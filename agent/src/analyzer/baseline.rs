// SPDX-License-Identifier: Apache-2.0
// analyzer/baseline.rs — Per-agent behavioral baseline + anomaly detection
//
// Replaces fixed thresholds in heuristics.rs with statistical deviations
// from a rolling 7-day learned baseline per named agent.
//
// Baseline profiles track:
//   - File access patterns: directories accessed, read/write ratio, frequency
//   - Network destinations: seen endpoints
//   - Process spawns: child process names
//   - Data volume: bytes read/written per session
//
// Anomaly score: 0..=100, where ≥60 = HIGH.
//
// Storage: in-memory (Mutex<HashMap>) with sled persistence.
// Fleet aggregation (Postgres) is future work.

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Mutex;

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};

use crate::analyzer::observer::{ActivityClass, ActivityRule, BaselineAction};
use crate::common::event::{EventKind, SecurityEvent};
use crate::policy::profile::{LayeredRule, PolicyLayer};

// ── Constants ─────────────────────────────────────────────────────────────────

const BASELINE_WINDOW_DAYS: i64 = 7;
const ANOMALY_HIGH_THRESHOLD: u8 = 60;
const ANOMALY_MEDIUM_THRESHOLD: u8 = 35;
/// Max events kept per agent in the rolling window
const MAX_EVENTS_PER_AGENT: usize = 10_000;

// ── Types ──────────────────────────────────────────────────────────────────────

/// A single observed data point for one event.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct EventRecord {
    kind: EventKind,
    target: String,
    timestamp: DateTime<Utc>,
}

/// Rolling baseline profile for one named agent.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentBaseline {
    pub agent_name: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    /// Number of sessions observed
    pub session_count: u64,

    // ── File access profile ──
    /// Directories seen in normal operation
    pub known_dirs: HashSet<String>,
    /// Total file reads observed (for ratio)
    pub file_reads: u64,
    /// Total file writes observed (for ratio)
    pub file_writes: u64,

    // ── Network profile ──
    /// Network destinations seen in normal operation (host:port or IP:port)
    pub known_destinations: HashSet<String>,

    // ── Process spawn profile ──
    /// Child process names seen in normal operation
    pub known_children: HashSet<String>,

    // ── Volume profile ──
    /// Rolling window of per-session event counts (proxy for volume)
    pub session_event_counts: VecDeque<u64>,

    // ── Raw event window (for incremental updates) ──
    #[serde(skip)]
    recent_events: VecDeque<EventRecord>,
}

impl AgentBaseline {
    fn new(agent_name: &str) -> Self {
        AgentBaseline {
            agent_name: agent_name.to_string(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
            session_count: 0,
            known_dirs: HashSet::new(),
            file_reads: 0,
            file_writes: 0,
            known_destinations: HashSet::new(),
            known_children: HashSet::new(),
            session_event_counts: VecDeque::with_capacity(1000),
            recent_events: VecDeque::new(),
        }
    }

    /// Ingest one event into the baseline (during learning phase).
    fn learn(&mut self, ev: &SecurityEvent) {
        self.updated_at = Utc::now();
        match ev.kind {
            EventKind::FileOpen => {
                self.file_reads += 1;
                if let Some(dir) = parent_dir(&ev.target) {
                    self.known_dirs.insert(dir);
                }
            }
            EventKind::FileWrite | EventKind::FileCreate => {
                self.file_writes += 1;
                if let Some(dir) = parent_dir(&ev.target) {
                    self.known_dirs.insert(dir);
                }
            }
            EventKind::NetworkConnect | EventKind::NetworkSend => {
                self.known_destinations.insert(normalize_dest(&ev.target));
            }
            EventKind::ProcessExec => {
                self.known_children.insert(basename(&ev.target));
            }
            _ => {}
        }

        let rec = EventRecord {
            kind: ev.kind.clone(),
            target: ev.target.clone(),
            timestamp: ev.timestamp,
        };
        self.recent_events.push_back(rec);
        if self.recent_events.len() > MAX_EVENTS_PER_AGENT {
            self.recent_events.pop_front();
        }

        // Prune events older than baseline window
        let cutoff = Utc::now() - Duration::days(BASELINE_WINDOW_DAYS);
        while self
            .recent_events
            .front()
            .map(|e| e.timestamp < cutoff)
            .unwrap_or(false)
        {
            self.recent_events.pop_front();
        }
    }

    /// Is the baseline mature enough to detect anomalies?
    pub fn is_mature(&self) -> bool {
        self.session_count >= 5
    }
}

// ── AnomalyFinding ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnomalyFinding {
    pub kind: AnomalyKind,
    pub description: String,
    pub score: u8,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AnomalyKind {
    NewDirectory,
    NewNetworkDestination,
    NewChildProcess,
    VolumeSpike,
    WriteRatioAnomaly,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnomalyReport {
    pub agent_name: String,
    pub session_id: String,
    pub total_score: u8,
    pub is_high: bool,
    pub is_medium: bool,
    pub findings: Vec<AnomalyFinding>,
    pub generated_at: DateTime<Utc>,
}

impl AnomalyReport {
    pub fn is_high(&self) -> bool {
        self.is_high
    }
}

// ── BaselineEngine ────────────────────────────────────────────────────────────

pub struct BaselineEngine {
    profiles: Mutex<HashMap<String, AgentBaseline>>,
}

impl BaselineEngine {
    pub fn new() -> Self {
        BaselineEngine {
            profiles: Mutex::new(HashMap::new()),
        }
    }

    /// Feed an event into the engine.
    /// - If the agent has a mature baseline, returns an anomaly report.
    /// - Otherwise, learn from the event and return None.
    pub fn process(&self, event: &SecurityEvent, session_id: &str) -> Option<AnomalyReport> {
        let agent = &event.process;
        let mut profiles = self.profiles.lock().unwrap();
        let profile = profiles
            .entry(agent.clone())
            .or_insert_with(|| AgentBaseline::new(agent));

        if profile.is_mature() {
            let report = detect_anomalies(profile, event, session_id);
            profile.learn(event);
            if report.total_score >= ANOMALY_MEDIUM_THRESHOLD {
                Some(report)
            } else {
                None
            }
        } else {
            profile.learn(event);
            None
        }
    }

    /// Called when a session ends — record session event count for volume baseline.
    #[allow(dead_code)]
    pub fn record_session_end(&self, agent: &str, event_count: u64) {
        let mut profiles = self.profiles.lock().unwrap();
        if let Some(profile) = profiles.get_mut(agent) {
            profile.session_count += 1;
            profile.session_event_counts.push_back(event_count);
            if profile.session_event_counts.len() > 200 {
                profile.session_event_counts.pop_front();
            }
        }
    }

    /// Return a snapshot of all agent profiles (for API/console).
    pub fn profiles(&self) -> Vec<AgentProfileSummary> {
        let profiles = self.profiles.lock().unwrap();
        profiles
            .values()
            .map(|p| AgentProfileSummary {
                agent_name: p.agent_name.clone(),
                session_count: p.session_count,
                known_dirs: p.known_dirs.len(),
                known_destinations: p.known_destinations.len(),
                known_children: p.known_children.len(),
                is_mature: p.is_mature(),
                created_at: p.created_at,
                updated_at: p.updated_at,
            })
            .collect()
    }

    /// Return the baseline for one agent.
    pub fn get_profile(&self, agent: &str) -> Option<AgentProfileSummary> {
        let profiles = self.profiles.lock().unwrap();
        profiles.get(agent).map(|p| AgentProfileSummary {
            agent_name: p.agent_name.clone(),
            session_count: p.session_count,
            known_dirs: p.known_dirs.len(),
            known_destinations: p.known_destinations.len(),
            known_children: p.known_children.len(),
            is_mature: p.is_mature(),
            created_at: p.created_at,
            updated_at: p.updated_at,
        })
    }

    /// Generate learned rules from baseline observations.
    ///
    /// Rules start as AUDIT (Warn) and promote to WARN enforcement after 10+ sessions.
    /// This feeds into Layer 4 of the layered policy evaluator.
    ///
    /// Returns empty if the baseline is not mature (< 5 sessions).
    pub fn generate_learned_rules(&self, agent: &str) -> Vec<LearnedRule> {
        let profiles = self.profiles.lock().unwrap();
        let profile = match profiles.get(agent) {
            Some(p) => p,
            None => return Vec::new(),
        };

        // Not mature enough — don't generate rules
        if !profile.is_mature() {
            return Vec::new();
        }

        let confidence = if profile.session_count >= 10 {
            LearnedConfidence::Warn
        } else {
            LearnedConfidence::Audit
        };

        let action = match confidence {
            LearnedConfidence::Audit => BaselineAction::Warn,
            LearnedConfidence::Warn => BaselineAction::Block,
        };

        let mut rules = Vec::new();

        // Generate AllowScoped rules for known directories
        if !profile.known_dirs.is_empty() {
            let patterns: Vec<String> = profile
                .known_dirs
                .iter()
                .map(|d| format!("{}/**", d))
                .collect();
            rules.push(LearnedRule {
                activity: ActivityClass::FileRead,
                action: BaselineAction::AllowScoped {
                    patterns: patterns.clone(),
                },
                description: format!(
                    "Learned: file access in {} known directories",
                    profile.known_dirs.len()
                ),
                confidence: confidence.clone(),
                session_count: profile.session_count,
            });
            rules.push(LearnedRule {
                activity: ActivityClass::FileWrite,
                action: BaselineAction::AllowScoped { patterns },
                description: format!(
                    "Learned: file writes in {} known directories",
                    profile.known_dirs.len()
                ),
                confidence: confidence.clone(),
                session_count: profile.session_count,
            });
        }

        // Generate AllowScoped rules for known network destinations
        if !profile.known_destinations.is_empty() {
            let patterns: Vec<String> = profile.known_destinations.iter().cloned().collect();
            rules.push(LearnedRule {
                activity: ActivityClass::NetworkConnect,
                action: BaselineAction::AllowScoped { patterns },
                description: format!(
                    "Learned: connections to {} known destinations",
                    profile.known_destinations.len()
                ),
                confidence: confidence.clone(),
                session_count: profile.session_count,
            });
        }

        // Generate AllowScoped rules for known child processes
        if !profile.known_children.is_empty() {
            let patterns: Vec<String> = profile.known_children.iter().cloned().collect();
            rules.push(LearnedRule {
                activity: ActivityClass::ProcessExec,
                action: BaselineAction::AllowScoped { patterns },
                description: format!(
                    "Learned: {} known child processes",
                    profile.known_children.len()
                ),
                confidence: confidence.clone(),
                session_count: profile.session_count,
            });
        }

        // For mature baselines (10+ sessions), add a blocking rule for
        // unknown network destinations (enforcement)
        if profile.session_count >= 10 {
            rules.push(LearnedRule {
                activity: ActivityClass::NetworkSend,
                action: action.clone(),
                description: format!(
                    "Learned: {} action for unknown network sends ({}+ sessions)",
                    match &action {
                        BaselineAction::Block => "block",
                        BaselineAction::Warn => "warn",
                        _ => "allow",
                    },
                    profile.session_count,
                ),
                confidence: confidence.clone(),
                session_count: profile.session_count,
            });
        }

        rules
    }

    /// Convert learned rules into LayeredRules for the policy evaluator.
    pub fn to_layered_rules(&self, agent: &str) -> Vec<LayeredRule> {
        self.generate_learned_rules(agent)
            .into_iter()
            .enumerate()
            .map(|(i, lr)| LayeredRule {
                rule: ActivityRule {
                    class: lr.activity,
                    action: lr.action,
                    description: lr.description,
                },
                layer: PolicyLayer::Learned,
                rule_id: format!("learned_{}_{}", agent, i),
                source: format!(
                    "learned:baseline:{}",
                    match lr.confidence {
                        LearnedConfidence::Audit => "audit",
                        LearnedConfidence::Warn => "warn",
                    }
                ),
            })
            .collect()
    }
}

// ── Learned rule types ────────────────────────────────────────────────────────

/// A rule generated from baseline observations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LearnedRule {
    pub activity: ActivityClass,
    pub action: BaselineAction,
    pub description: String,
    pub confidence: LearnedConfidence,
    pub session_count: u64,
}

/// Confidence level for learned rules.
/// Determines enforcement strength.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum LearnedConfidence {
    /// < 10 sessions observed — Warn action (audit mode)
    Audit,
    /// >= 10 sessions — promoted to enforcement
    Warn,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentProfileSummary {
    pub agent_name: String,
    pub session_count: u64,
    pub known_dirs: usize,
    pub known_destinations: usize,
    pub known_children: usize,
    pub is_mature: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

// ── Anomaly detection logic ───────────────────────────────────────────────────

fn detect_anomalies(
    profile: &AgentBaseline,
    event: &SecurityEvent,
    session_id: &str,
) -> AnomalyReport {
    let mut findings = Vec::new();
    let mut total: u32 = 0;

    match event.kind {
        // New directory access
        EventKind::FileOpen | EventKind::FileWrite | EventKind::FileCreate => {
            if let Some(dir) = parent_dir(&event.target) {
                if !profile.known_dirs.contains(&dir) && is_sensitive_dir(&dir) {
                    let score = if is_highly_sensitive(&dir) { 50u8 } else { 25 };
                    findings.push(AnomalyFinding {
                        kind: AnomalyKind::NewDirectory,
                        description: "File access in directory not seen in baseline".into(),
                        score,
                        detail: format!("dir={}", dir),
                    });
                    total += score as u32;
                }
            }
        }
        // New network destination
        EventKind::NetworkConnect | EventKind::NetworkSend => {
            let dest = normalize_dest(&event.target);
            if !dest.is_empty() && !profile.known_destinations.contains(&dest) {
                let score = if is_suspicious_dest(&dest) { 55u8 } else { 30 };
                findings.push(AnomalyFinding {
                    kind: AnomalyKind::NewNetworkDestination,
                    description: "Network connection to destination not seen in baseline".into(),
                    score,
                    detail: format!("dest={}", dest),
                });
                total += score as u32;
            }
        }
        // New child process
        EventKind::ProcessExec => {
            let child = basename(&event.target);
            if !profile.known_children.contains(&child) && is_suspicious_child(&child) {
                findings.push(AnomalyFinding {
                    kind: AnomalyKind::NewChildProcess,
                    description: "Spawned process not seen in baseline".into(),
                    score: 40,
                    detail: format!("process={}", child),
                });
                total += 40;
            }
        }
        _ => {}
    }

    let total_score = total.min(100) as u8;
    AnomalyReport {
        agent_name: event.process.clone(),
        session_id: session_id.to_string(),
        total_score,
        is_high: total_score >= ANOMALY_HIGH_THRESHOLD,
        is_medium: total_score >= ANOMALY_MEDIUM_THRESHOLD,
        findings,
        generated_at: Utc::now(),
    }
}

// ── helpers ───────────────────────────────────────────────────────────────────

fn parent_dir(path: &str) -> Option<String> {
    std::path::Path::new(path)
        .parent()
        .map(|p| p.to_string_lossy().into_owned())
}

fn basename(path: &str) -> String {
    std::path::Path::new(path)
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| path.to_string())
}

fn normalize_dest(target: &str) -> String {
    // Strip port for destination grouping
    if let Some(colon) = target.rfind(':') {
        target[..colon].to_string()
    } else {
        target.to_string()
    }
}

fn is_sensitive_dir(dir: &str) -> bool {
    const SENSITIVE: &[&str] = &[
        ".ssh",
        ".aws",
        ".gnupg",
        ".config",
        "keychain",
        "/etc",
        "/proc",
        "/sys",
        "/root",
        "passwords",
        "credentials",
        "secrets",
        "tokens",
    ];
    let lower = dir.to_lowercase();
    SENSITIVE.iter().any(|s| lower.contains(s))
}

fn is_highly_sensitive(dir: &str) -> bool {
    const HIGH: &[&str] = &[
        ".ssh",
        ".aws/credentials",
        "/etc/shadow",
        "/etc/passwd",
        "keychain",
        "/root",
    ];
    let lower = dir.to_lowercase();
    HIGH.iter().any(|s| lower.contains(s))
}

fn is_suspicious_dest(dest: &str) -> bool {
    const SUSPICIOUS: &[&str] = &[
        "ngrok",
        "burpcollaborator",
        "oastify",
        "interactsh",
        "requestbin",
        "webhook.site",
        "pipedream",
        "0.0.0.0",
        "127.0.0.1",
    ];
    let lower = dest.to_lowercase();
    SUSPICIOUS.iter().any(|s| lower.contains(s))
}

fn is_suspicious_child(name: &str) -> bool {
    const SUSPICIOUS: &[&str] = &[
        "bash", "sh", "zsh", "fish", "nc", "ncat", "socat", "curl", "wget", "python", "perl",
        "ruby", "node", "openssl", "ssh", "scp", "sftp", "rsync",
    ];
    let lower = name.to_lowercase();
    SUSPICIOUS
        .iter()
        .any(|s| lower == *s || lower.starts_with(s))
}

#[cfg(test)]
pub mod tests {
    use super::*;

    fn make_event(kind: EventKind, target: &str, process: &str) -> SecurityEvent {
        SecurityEvent {
            id: uuid::Uuid::new_v4().to_string(),
            kind,
            pid: 1000,
            uid: 1000,
            process: process.to_string(),
            target: target.to_string(),
            allowed: true,
            reason: None,
            timestamp: Utc::now(),
            ppid: None,
            parent_process: None,
            llm_context: None,
            extra: None,
        }
    }

    /// Seed a baseline with N sessions and some known patterns.
    fn seed_baseline(engine: &BaselineEngine, agent: &str, sessions: u64) {
        // Inject some events to build known patterns
        let events = vec![
            make_event(EventKind::FileOpen, "/home/user/project/src/main.rs", agent),
            make_event(EventKind::FileWrite, "/home/user/project/src/lib.rs", agent),
            make_event(EventKind::NetworkConnect, "api.github.com:443", agent),
            make_event(EventKind::ProcessExec, "/usr/bin/git", agent),
        ];

        for ev in &events {
            engine.process(ev, "seed-session");
        }

        // Record enough session endings to reach desired session_count
        for _ in 0..sessions {
            engine.record_session_end(agent, 50);
        }
    }

    #[test]
    fn test_generate_learned_rules_immature() {
        let engine = BaselineEngine::new();
        let agent = "test-agent-immature";

        // Seed with only 3 sessions (< 5 = immature)
        seed_baseline(&engine, agent, 3);

        let rules = engine.generate_learned_rules(agent);
        assert!(
            rules.is_empty(),
            "Immature baseline (< 5 sessions) should return no learned rules"
        );
    }

    #[test]
    fn test_generate_learned_rules_mature() {
        let engine = BaselineEngine::new();
        let agent = "test-agent-mature";

        // Seed with 7 sessions (>= 5 = mature, < 10 = audit confidence)
        seed_baseline(&engine, agent, 7);

        let rules = engine.generate_learned_rules(agent);
        assert!(
            !rules.is_empty(),
            "Mature baseline (7 sessions) should return learned rules"
        );

        // Should have rules for known dirs (FileRead, FileWrite),
        // known destinations (NetworkConnect), known children (ProcessExec)
        let activities: Vec<&ActivityClass> = rules.iter().map(|r| &r.activity).collect();
        assert!(
            activities.contains(&&ActivityClass::FileRead),
            "Should have FileRead rule from known_dirs"
        );
        assert!(
            activities.contains(&&ActivityClass::ProcessExec),
            "Should have ProcessExec rule from known_children"
        );
        assert!(
            activities.contains(&&ActivityClass::NetworkConnect),
            "Should have NetworkConnect rule from known_destinations"
        );

        // All rules should have Audit confidence (< 10 sessions)
        for rule in &rules {
            assert_eq!(
                rule.confidence,
                LearnedConfidence::Audit,
                "Rules with < 10 sessions should be Audit confidence"
            );
        }
    }

    #[test]
    fn test_learned_promotion() {
        let engine = BaselineEngine::new();
        let agent = "test-agent-promoted";

        // Seed with 12 sessions (>= 10 = promoted to Warn)
        seed_baseline(&engine, agent, 12);

        let rules = engine.generate_learned_rules(agent);
        assert!(!rules.is_empty());

        // All rules should have Warn confidence (>= 10 sessions)
        for rule in &rules {
            assert_eq!(
                rule.confidence,
                LearnedConfidence::Warn,
                "Rules with 10+ sessions should be promoted to Warn confidence"
            );
        }

        // Should have a NetworkSend enforcement rule at 10+ sessions
        let network_send_rules: Vec<&LearnedRule> = rules
            .iter()
            .filter(|r| r.activity == ActivityClass::NetworkSend)
            .collect();
        assert!(
            !network_send_rules.is_empty(),
            "Promoted baseline should include NetworkSend enforcement rule"
        );
        assert_eq!(
            network_send_rules[0].action,
            BaselineAction::Block,
            "NetworkSend enforcement rule should be Block at Warn confidence"
        );
    }

    #[test]
    fn test_to_layered_rules() {
        let engine = BaselineEngine::new();
        let agent = "test-agent-layered";

        seed_baseline(&engine, agent, 7);

        let layered = engine.to_layered_rules(agent);
        assert!(!layered.is_empty());

        for lr in &layered {
            assert_eq!(lr.layer, PolicyLayer::Learned);
            assert!(lr.rule_id.starts_with("learned_"));
            assert!(lr.source.starts_with("learned:baseline:"));
        }
    }
}
