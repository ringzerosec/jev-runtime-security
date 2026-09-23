// SPDX-License-Identifier: Apache-2.0
// analyzer/correlation.rs — Attack Pattern Correlation Engine (Behavior Graph)
//
// Detects multi-step attack chains that individual event monitoring misses.
// This is Ring Zero's core EDR advantage: correlating sequences of benign-looking
// events into recognized attack patterns mapped to MITRE ATT&CK.
//
// Design:
//   1. AttackPattern — multi-step signature with time window
//   2. CorrelationEngine — sliding window per session, pattern matching
//   3. AttackChain — detected chain with matched events and MITRE reference
//
// Integration:
//   - main.rs: call engine.evaluate() for every event (same as observer)
//   - API: expose detected chains and registered patterns
//   - UI: render attack chain timelines

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};
use tokio::sync::RwLock;

use crate::analyzer::observer::ActivityClass;
use crate::common::event::{EventKind, SecurityEvent};

// ── Severity ────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Severity::Critical => write!(f, "critical"),
            Severity::High => write!(f, "high"),
            Severity::Medium => write!(f, "medium"),
            Severity::Low => write!(f, "low"),
        }
    }
}

// ── Attack pattern definition ───────────────────────────────────────────────

/// A multi-step attack signature. Each step must match in order within the
/// time window for the pattern to fire.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackPattern {
    pub id: String,
    pub name: String,
    pub description: String,
    pub severity: Severity,
    pub steps: Vec<PatternStep>,
    /// Maximum seconds between first and last step for the chain to match.
    pub window_secs: u64,
    /// MITRE ATT&CK technique ID(s).
    pub mitre_id: Option<String>,
    /// Process names excluded from this pattern. AI coding agents like
    /// claude, cursor, copilot legitimately spawn shells + make network
    /// connections — that's not a reverse shell.
    #[serde(default)]
    pub excluded_processes: Vec<String>,
}

/// A single step in an attack pattern.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PatternStep {
    pub activity: ActivityClass,
    /// Optional glob/substring pattern for the event target field.
    /// If None, any target matches.
    pub target_pattern: Option<String>,
    /// Step ordering (0-based). Steps are matched in ascending order.
    pub order: u8,
    /// Minimum number of events matching this step required (default 1).
    /// Used for patterns like "5+ file_read on .env files".
    #[serde(default = "default_min_count")]
    pub min_count: u32,
    /// If true, this step's event must share a PID or PID/PPID relationship
    /// with the previous step's event (same process or direct child).
    /// Enables ancestry-aware chains: "file write BY process A → exec BY process A or child".
    #[serde(default)]
    pub require_ancestry: bool,
}

fn default_min_count() -> u32 {
    1
}

// ── Window event — lightweight copy for correlation ─────────────────────────

/// Compact event stored in the sliding window. We keep only the fields needed
/// for pattern matching to minimize memory.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WindowEvent {
    pub event_id: String,
    pub activity: ActivityClass,
    pub target: String,
    pub process: String,
    pub pid: u32,
    pub ppid: Option<u32>,
    pub timestamp: DateTime<Utc>,
}

impl WindowEvent {
    pub fn from_security_event(ev: &SecurityEvent) -> Self {
        Self {
            event_id: ev.id.clone(),
            activity: classify_event_kind(&ev.kind, &ev.target),
            target: ev.target.clone(),
            process: ev.process.clone(),
            pid: ev.pid,
            ppid: ev.ppid,
            timestamp: ev.timestamp,
        }
    }
}

/// Classify EventKind into ActivityClass for correlation purposes.
fn classify_event_kind(kind: &EventKind, target: &str) -> ActivityClass {
    match kind {
        // Captured terminal text is something the agent SAID, not something it
        // did. It is not a file write, a network request or an exec, and
        // classing it as any of those would put words into the correlation
        // engine as if they were actions.
        EventKind::AgentStdout | EventKind::AgentStdin => ActivityClass::AgentSpeech,
        EventKind::TranscriptWrite => ActivityClass::FileWrite,
        EventKind::FileOpen => {
            if is_credential_target(target) {
                ActivityClass::CredentialAccess
            } else {
                ActivityClass::FileRead
            }
        }
        EventKind::FileCreate | EventKind::FileWrite => ActivityClass::FileWrite,
        EventKind::FileDelete | EventKind::FileRename => ActivityClass::FileDelete,
        EventKind::ProcessExec => ActivityClass::ProcessExec,
        EventKind::ProcessFork | EventKind::ProcessExit => ActivityClass::ProcessFork,
        EventKind::NetworkConnect => ActivityClass::NetworkConnect,
        EventKind::NetworkSend | EventKind::NetworkRecv => ActivityClass::NetworkSend,
        EventKind::DnsQuery => ActivityClass::DnsQuery,
        // Containment/tamper events map to privilege escalation
        EventKind::TamperPtrace
        | EventKind::TamperSignal
        | EventKind::TamperMount
        | EventKind::TamperUmount => ActivityClass::PrivilegeEscalation,
        EventKind::ContainedExecBlocked => ActivityClass::ProcessExec,
        EventKind::ContainedFileBlocked => ActivityClass::CredentialAccess,
        // Offensive prompt → maps to credential access (intent to steal/exploit)
        EventKind::OffensivePrompt => ActivityClass::CredentialAccess,
        // mprotect W→X → privilege escalation (runtime code generation)
        EventKind::MprotectWx => ActivityClass::PrivilegeEscalation,
        // Attack chain meta-event — already correlated, treat as credential access
        EventKind::AttackChain => ActivityClass::CredentialAccess,
        // LLM/proxy/MCP events are not correlated as kernel activity
        EventKind::McpToolCall
        | EventKind::LlmRequest
        | EventKind::LlmResponse
        | EventKind::LlmToolCall
        | EventKind::ProxyBlock
        | EventKind::ProxyDetection
        | EventKind::DlpPii
        | EventKind::PromptInjection
        | EventKind::SkillFileChange
        | EventKind::SkillGitRepoDrop => ActivityClass::FileRead,
    }
}

/// Check if a target path indicates credential/sensitive file access.
fn is_credential_target(target: &str) -> bool {
    let t = target.to_lowercase();
    CREDENTIAL_INDICATORS.iter().any(|p| t.contains(p))
}

const CREDENTIAL_INDICATORS: &[&str] = &[
    ".ssh/",
    ".aws/credentials",
    ".aws/config",
    "id_rsa",
    "id_ed25519",
    "id_ecdsa",
    ".env",
    ".npmrc",
    ".pypirc",
    ".netrc",
    "credentials",
    "keychain",
    "vault",
    "passwd",
    "shadow",
    "private_key",
    "secret",
    "token",
    "api_key",
    ".kube/config",
    ".docker/config",
];

// ── Matched event in a chain ────────────────────────────────────────────────

/// An event that was matched as part of a detected attack chain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MatchedEvent {
    pub event_id: String,
    pub step_order: u8,
    pub activity: ActivityClass,
    pub target: String,
    pub process: String,
    pub pid: u32,
    pub timestamp: DateTime<Utc>,
}

// ── Attack chain (detected) ────────────────────────────────────────────────

/// A fully matched attack chain — all steps of an AttackPattern were observed
/// within the time window for a single session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackChain {
    pub id: String,
    pub pattern_id: String,
    pub pattern_name: String,
    pub description: String,
    pub session_id: String,
    pub severity: Severity,
    pub matched_events: Vec<MatchedEvent>,
    pub detected_at: DateTime<Utc>,
    pub mitre_id: Option<String>,
}

// ── Correlation Engine ──────────────────────────────────────────────────────

/// The correlation engine maintains sliding windows of recent events per session
/// and evaluates all registered attack patterns against each new event.
pub struct CorrelationEngine {
    /// Sliding window of recent events per session.
    event_windows: RwLock<HashMap<String, VecDeque<WindowEvent>>>,
    /// Detected attack chains (ring buffer, max 500).
    detected_chains: RwLock<Vec<AttackChain>>,
    /// All registered attack patterns.
    patterns: Vec<AttackPattern>,
    /// Dedup: (session_id, pattern_id) pairs that have already fired.
    /// Prevents the same pattern from firing repeatedly as new events arrive.
    fired_patterns: RwLock<HashSet<(String, String)>>,
}

/// Maximum events kept per session window.
const MAX_WINDOW_SIZE: usize = 1000;

/// Maximum detected chains kept in memory.
const MAX_CHAINS: usize = 500;

/// Global maximum window for pruning (matches the longest pattern window).
const MAX_WINDOW_SECS: i64 = 300;

impl CorrelationEngine {
    pub fn new() -> Self {
        Self {
            event_windows: RwLock::new(HashMap::new()),
            detected_chains: RwLock::new(Vec::new()),
            patterns: builtin_patterns(),
            fired_patterns: RwLock::new(HashSet::new()),
        }
    }

    /// Evaluate a new security event against all attack patterns.
    /// Call this for every event in the main processing loop.
    ///
    /// Returns `Some(AttackChain)` if a full pattern match was detected.
    pub async fn evaluate(&self, ev: &SecurityEvent, session_id: &str) -> Option<AttackChain> {
        let window_event = WindowEvent::from_security_event(ev);
        let now = ev.timestamp;

        // Add to session window
        {
            let mut windows = self.event_windows.write().await;
            let window = windows
                .entry(session_id.to_string())
                .or_insert_with(VecDeque::new);

            window.push_back(window_event);

            // Enforce max window size
            while window.len() > MAX_WINDOW_SIZE {
                window.pop_front();
            }

            // Prune events older than max window
            let cutoff = now - chrono::Duration::seconds(MAX_WINDOW_SECS);
            while let Some(front) = window.front() {
                if front.timestamp < cutoff {
                    window.pop_front();
                } else {
                    break;
                }
            }
        }

        // Check all patterns against the window
        let windows = self.event_windows.read().await;
        let window = windows.get(session_id)?;

        // Read fired patterns to skip already-detected chains
        let fired = self.fired_patterns.read().await;

        let mut new_chains: Vec<AttackChain> = Vec::new();

        for pattern in &self.patterns {
            // Skip patterns that already fired for this session
            let key = (session_id.to_string(), pattern.id.clone());
            if fired.contains(&key) {
                continue;
            }

            // Skip patterns if the session belongs to an excluded process.
            // Check both the current event's process AND the session ID (which
            // contains the agent name, e.g. "auto-claude-12345"). We also check
            // all processes in the window — child processes like "sh" or "node"
            // inherit the session's agent identity.
            if !pattern.excluded_processes.is_empty() {
                let session_lower = session_id.to_lowercase();
                let proc_lower = ev.process.to_lowercase();
                let is_excluded = pattern
                    .excluded_processes
                    .iter()
                    .any(|excl| session_lower.contains(excl) || proc_lower.contains(excl))
                    || window.iter().any(|w| {
                        let wp = w.process.to_lowercase();
                        pattern
                            .excluded_processes
                            .iter()
                            .any(|excl| wp.contains(excl))
                    });
                if is_excluded {
                    continue;
                }
            }

            if let Some(chain) = match_pattern(pattern, window, session_id, now) {
                tracing::warn!(
                    pattern = %pattern.name,
                    session = %session_id,
                    severity = %pattern.severity,
                    mitre = ?pattern.mitre_id,
                    matched_events = chain.matched_events.len(),
                    "ATTACK CHAIN DETECTED"
                );
                new_chains.push(chain);
            }
        }
        drop(fired);

        // Store all newly detected chains and mark patterns as fired
        if !new_chains.is_empty() {
            let mut fired = self.fired_patterns.write().await;
            let mut chains = self.detected_chains.write().await;
            for chain in &new_chains {
                fired.insert((session_id.to_string(), chain.pattern_id.clone()));
                chains.push(chain.clone());
            }
            while chains.len() > MAX_CHAINS {
                chains.remove(0);
            }
        }

        // Return highest-severity chain for caller (e.g., for logging)
        new_chains
            .into_iter()
            .max_by_key(|c| severity_rank(&c.severity))
    }

    /// Get recent detected attack chains (most recent first).
    pub async fn recent_chains(&self, limit: usize) -> Vec<AttackChain> {
        let chains = self.detected_chains.read().await;
        chains.iter().rev().take(limit).cloned().collect()
    }

    /// Get chains for a specific session (most recent first).
    pub async fn chains_for_session(&self, session_id: &str, limit: usize) -> Vec<AttackChain> {
        let chains = self.detected_chains.read().await;
        chains
            .iter()
            .rev()
            .filter(|c| c.session_id == session_id)
            .take(limit)
            .cloned()
            .collect()
    }

    /// List all registered attack patterns (for UI display).
    pub fn list_patterns(&self) -> &[AttackPattern] {
        &self.patterns
    }

    /// Remove a session's window (on session termination).
    pub async fn remove_session(&self, session_id: &str) {
        self.event_windows.write().await.remove(session_id);
        // Clean up fired patterns for this session
        let mut fired = self.fired_patterns.write().await;
        fired.retain(|(sid, _)| sid != session_id);
    }

    /// Get window size for diagnostics.
    pub async fn window_size(&self, session_id: &str) -> usize {
        self.event_windows
            .read()
            .await
            .get(session_id)
            .map_or(0, |w| w.len())
    }
}

fn severity_rank(s: &Severity) -> u8 {
    match s {
        Severity::Critical => 4,
        Severity::High => 3,
        Severity::Medium => 2,
        Severity::Low => 1,
    }
}

// ── Pattern matching ────────────────────────────────────────────────────────

/// Attempt to match a single attack pattern against the session's event window.
/// Returns an AttackChain if all steps are satisfied in order within the window.
fn match_pattern(
    pattern: &AttackPattern,
    window: &VecDeque<WindowEvent>,
    session_id: &str,
    now: DateTime<Utc>,
) -> Option<AttackChain> {
    if pattern.steps.is_empty() {
        return None;
    }

    // Sort steps by order
    let mut steps: Vec<&PatternStep> = pattern.steps.iter().collect();
    steps.sort_by_key(|s| s.order);

    // Find candidate events for each step
    let mut step_matches: Vec<Vec<&WindowEvent>> = Vec::with_capacity(steps.len());

    for step in &steps {
        let matching: Vec<&WindowEvent> = window
            .iter()
            .filter(|ev| {
                if ev.activity != step.activity {
                    return false;
                }
                if let Some(ref pat) = step.target_pattern {
                    if !target_matches(&ev.target, pat) {
                        return false;
                    }
                }
                true
            })
            .collect();

        // Check minimum count requirement
        if (matching.len() as u32) < step.min_count {
            return None;
        }

        step_matches.push(matching);
    }

    // Verify temporal ordering: find the earliest valid chain where
    // step[i] timestamp <= step[i+1] timestamp, all within window_secs.
    let chain_events = find_ordered_chain(&steps, &step_matches, pattern.window_secs, now)?;

    // Build the attack chain
    let chain_id = format!(
        "chain-{}-{}",
        pattern.id,
        now.timestamp_nanos_opt().unwrap_or(0)
    );

    Some(AttackChain {
        id: chain_id,
        pattern_id: pattern.id.clone(),
        pattern_name: pattern.name.clone(),
        description: pattern.description.clone(),
        session_id: session_id.to_string(),
        severity: pattern.severity.clone(),
        matched_events: chain_events,
        detected_at: now,
        mitre_id: pattern.mitre_id.clone(),
    })
}

/// Check if two events share a PID/PPID ancestry relationship.
/// Returns true if:
///   - Same PID (same process)
///   - ev's PPID == prev's PID (ev is child of prev)
///   - prev's PPID == ev's PID (prev is child of ev)
///   - Both share the same PPID (siblings)
fn is_related(prev: &WindowEvent, ev: &WindowEvent) -> bool {
    // Same process
    if prev.pid == ev.pid {
        return true;
    }
    // Direct parent-child
    if let Some(ppid) = ev.ppid {
        if ppid == prev.pid {
            return true;
        }
    }
    if let Some(ppid) = prev.ppid {
        if ppid == ev.pid {
            return true;
        }
    }
    // Siblings (same parent)
    if let (Some(p1), Some(p2)) = (prev.ppid, ev.ppid) {
        if p1 == p2 && p1 != 0 {
            return true;
        }
    }
    false
}

/// Find an ordered sequence of events that satisfy the chain constraints.
/// Uses a greedy forward scan: pick the earliest event for each step that
/// occurs after the previous step's match.
///
/// When `require_ancestry` is set on a step, the matched event must share
/// a PID/PPID relationship with the previous step's event.
fn find_ordered_chain(
    steps: &[&PatternStep],
    step_matches: &[Vec<&WindowEvent>],
    window_secs: u64,
    now: DateTime<Utc>,
) -> Option<Vec<MatchedEvent>> {
    let window_start = now - chrono::Duration::seconds(window_secs as i64);
    let mut result = Vec::with_capacity(steps.len());
    let mut last_ts: Option<DateTime<Utc>> = None;
    let mut last_event: Option<&WindowEvent> = None;

    for (i, step) in steps.iter().enumerate() {
        let candidates = &step_matches[i];

        // For steps with min_count > 1, we need that many events in the window
        if step.min_count > 1 {
            let in_window: Vec<&&WindowEvent> = candidates
                .iter()
                .filter(|ev| ev.timestamp >= window_start && ev.timestamp <= now)
                .filter(|ev| last_ts.map_or(true, |lt| ev.timestamp >= lt))
                .filter(|ev| {
                    if step.require_ancestry {
                        last_event.map_or(true, |prev| is_related(prev, ev))
                    } else {
                        true
                    }
                })
                .collect();

            if (in_window.len() as u32) < step.min_count {
                return None;
            }

            // Use the last matching event as the step's representative
            let representative = in_window.last()?;
            last_ts = Some(representative.timestamp);
            last_event = Some(representative);
            result.push(MatchedEvent {
                event_id: representative.event_id.clone(),
                step_order: step.order,
                activity: representative.activity.clone(),
                target: representative.target.clone(),
                process: representative.process.clone(),
                pid: representative.pid,
                timestamp: representative.timestamp,
            });
        } else {
            // Find earliest candidate after last_ts and within window
            let candidate = candidates
                .iter()
                .filter(|ev| ev.timestamp >= window_start && ev.timestamp <= now)
                .filter(|ev| last_ts.map_or(true, |lt| ev.timestamp >= lt))
                .filter(|ev| {
                    if step.require_ancestry {
                        last_event.map_or(true, |prev| is_related(prev, ev))
                    } else {
                        true
                    }
                })
                .next()?;

            last_ts = Some(candidate.timestamp);
            last_event = Some(candidate);
            result.push(MatchedEvent {
                event_id: candidate.event_id.clone(),
                step_order: step.order,
                activity: candidate.activity.clone(),
                target: candidate.target.clone(),
                process: candidate.process.clone(),
                pid: candidate.pid,
                timestamp: candidate.timestamp,
            });
        }
    }

    Some(result)
}

/// Match event target against a step's target pattern.
/// Supports:
///   - Simple substring match (e.g., ".ssh/")
///   - Glob-like prefix (e.g., "/tmp/*")
///   - Pipe-separated alternatives (e.g., "tar|zip|gzip")
fn target_matches(target: &str, pattern: &str) -> bool {
    let t = target.to_lowercase();
    let p = pattern.to_lowercase();

    // Pipe-separated alternatives
    if p.contains('|') {
        return p
            .split('|')
            .any(|alt| target_matches_single(&t, alt.trim()));
    }

    target_matches_single(&t, &p)
}

fn target_matches_single(target: &str, pattern: &str) -> bool {
    if pattern.ends_with('*') {
        let prefix = &pattern[..pattern.len() - 1];
        target.starts_with(prefix)
    } else {
        target.contains(pattern)
    }
}

// ── Built-in attack patterns ────────────────────────────────────────────────

fn builtin_patterns() -> Vec<AttackPattern> {
    vec![
        // 1. Credential Exfiltration
        // Read SSH keys or AWS creds → send data to non-provider IP
        AttackPattern {
            id: "credential_exfil".into(),
            name: "Credential Exfiltration".into(),
            description: "Sensitive credential file read followed by outbound network transfer — \
                          classic exfil pattern where stolen keys are sent to attacker infrastructure."
                .into(),
            severity: Severity::Critical,
            steps: vec![
                PatternStep {
                    activity: ActivityClass::CredentialAccess,
                    // Match both full paths (.ssh/id_rsa) and bare filenames (id_rsa)
                    // eBPF file_open only captures dentry name, not full path
                    target_pattern: Some(".ssh/|.aws/|id_rsa|id_ed25519|id_ecdsa|credentials|.env".into()),
                    order: 0,
                    min_count: 1,
                    require_ancestry: false,
                },
                PatternStep {
                    // NetworkConnect fires on socket_connect (always available);
                    // NetworkSend only fires when DLP is enabled
                    activity: ActivityClass::NetworkConnect,
                    target_pattern: None,
                    order: 1,
                    min_count: 1,
                    require_ancestry: false,
                },
            ],
            window_secs: 120,
            mitre_id: Some("T1552.001 + T1041".into()),
            // Canonical agent list — derived from agent_detect::known_agents() so
            // it can't drift. (It used to be a hand-maintained subset that omitted
            // gemini, chatgpt, cody, … → a Gemini CLI doing the normal "network +
            // spawn a shell for a tool" got flagged as a reverse shell and the
            // session was auto-KILLED. A coding agent doing network+shell is benign.)
            excluded_processes: crate::common::agent_detect::known_agents()
                .iter().map(|s| s.to_string()).collect(),
        },

        // 2. Staged Exfiltration
        // Read sensitive file → compress → network send
        AttackPattern {
            id: "staged_exfil".into(),
            name: "Staged Data Exfiltration".into(),
            description: "Sensitive file read, followed by compression/archiving, then outbound \
                          network transfer — staged exfil to evade size-based detection."
                .into(),
            severity: Severity::Critical,
            steps: vec![
                PatternStep {
                    // CredentialAccess, not FileRead: classify_event_kind promotes
                    // FileOpen on credential files (id_rsa, .env, etc.) to CredentialAccess
                    activity: ActivityClass::CredentialAccess,
                    target_pattern: Some(".ssh/|.aws/|.env|credentials|secret|token|api_key|id_rsa|id_ed25519".into()),
                    order: 0,
                    min_count: 1,
                    require_ancestry: false,
                },
                PatternStep {
                    activity: ActivityClass::ProcessExec,
                    target_pattern: Some("tar|zip|gzip|bzip2|xz|7z|rar".into()),
                    order: 1,
                    min_count: 1,
                    require_ancestry: false,
                },
                PatternStep {
                    activity: ActivityClass::NetworkConnect,
                    target_pattern: None,
                    order: 2,
                    min_count: 1,
                    require_ancestry: false,
                },
            ],
            window_secs: 180,
            mitre_id: Some("T1560.001 + T1041".into()),
            excluded_processes: vec![],
        },

        // 3. Payload Drop & Execute
        // Write file to /tmp or unusual path → execute that file
        AttackPattern {
            id: "payload_drop".into(),
            name: "Payload Drop & Execute".into(),
            description: "File written to temporary or unusual path, then immediately executed — \
                          classic dropper behavior (download → chmod → run)."
                .into(),
            severity: Severity::Critical,
            steps: vec![
                PatternStep {
                    activity: ActivityClass::FileWrite,
                    // Match full paths (/tmp/...) OR bare filenames from eBPF dentry.
                    // inode_create only captures the dentry name (e.g., "payload.sh"),
                    // not the full path, so we also match common dropper extensions/names.
                    target_pattern: Some("/tmp/|/var/tmp/|/dev/shm/|payload|dropper|.sh|.py|.elf|.bin".into()),
                    order: 0,
                    min_count: 1,
                    require_ancestry: false,
                },
                PatternStep {
                    activity: ActivityClass::ProcessExec,
                    // Process exec (bprm_check) gets full path from bprm->filename
                    target_pattern: Some("/tmp/|/var/tmp/|/dev/shm/".into()),
                    order: 1,
                    min_count: 1,
                    require_ancestry: true, // Exec must be same process tree as writer
                },
            ],
            window_secs: 60,
            mitre_id: Some("T1105 + T1059".into()),
            excluded_processes: vec![],
        },

        // 4. Lateral Movement (SSH)
        // Credential access → SSH connection
        AttackPattern {
            id: "lateral_movement".into(),
            name: "Lateral Movement (SSH)".into(),
            description: "Credential file access followed by outbound SSH connection — \
                          agent may be attempting to pivot to another host using stolen keys."
                .into(),
            severity: Severity::High,
            steps: vec![
                PatternStep {
                    activity: ActivityClass::CredentialAccess,
                    target_pattern: None,
                    order: 0,
                    min_count: 1,
                    require_ancestry: false,
                },
                PatternStep {
                    activity: ActivityClass::NetworkConnect,
                    target_pattern: Some(":22".into()),
                    order: 1,
                    min_count: 1,
                    require_ancestry: false,
                },
            ],
            window_secs: 300,
            mitre_id: Some("T1021.004".into()),
            excluded_processes: vec![],
        },

        // 5. Privilege Escalation Chain
        // Exec sudo/su/pkexec → credential access
        AttackPattern {
            id: "privilege_escalation_chain".into(),
            name: "Privilege Escalation Chain".into(),
            description: "Privilege escalation tool invoked, followed by credential file access — \
                          agent may be using elevated privileges to steal secrets."
                .into(),
            severity: Severity::High,
            steps: vec![
                PatternStep {
                    activity: ActivityClass::ProcessExec,
                    target_pattern: Some("sudo|su|pkexec|doas".into()),
                    order: 0,
                    min_count: 1,
                    require_ancestry: false,
                },
                PatternStep {
                    activity: ActivityClass::CredentialAccess,
                    target_pattern: None,
                    order: 1,
                    min_count: 1,
                    require_ancestry: false,
                },
            ],
            window_secs: 60,
            mitre_id: Some("T1548".into()),
            excluded_processes: vec![],
        },

        // 6. Data Staging
        // Multiple sensitive file reads → single archive write
        AttackPattern {
            id: "data_staging".into(),
            name: "Data Staging".into(),
            description: "Multiple sensitive files read in quick succession, then written to a \
                          single archive — data collection before exfiltration."
                .into(),
            severity: Severity::High,
            steps: vec![
                PatternStep {
                    // CredentialAccess, not FileRead: classify_event_kind promotes
                    // FileOpen on credential files to CredentialAccess
                    activity: ActivityClass::CredentialAccess,
                    target_pattern: Some(".ssh/|.aws/|.env|credentials|secret|token|passwd|shadow|id_rsa|id_ed25519|id_ecdsa".into()),
                    order: 0,
                    min_count: 3,
                    require_ancestry: false,
                },
                PatternStep {
                    activity: ActivityClass::FileWrite,
                    // Match archive extensions — both full paths and bare filenames from eBPF dentry
                    target_pattern: Some(".tar|.zip|.gz|.tgz|.bz2|.7z|.rar|exfil|staging|archive".into()),
                    order: 1,
                    min_count: 1,
                    require_ancestry: false,
                },
            ],
            window_secs: 120,
            mitre_id: Some("T1074".into()),
            excluded_processes: vec![],
        },

        // 7. Reverse Shell
        // Outbound network connection → shell exec within same session
        // Excludes known AI coding agents — they legitimately connect to
        // APIs and spawn shells as part of normal operation.
        AttackPattern {
            id: "reverse_shell".into(),
            name: "Reverse Shell".into(),
            description: "Outbound network connection immediately followed by interactive shell \
                          execution — classic reverse shell or bind shell callback."
                .into(),
            severity: Severity::Critical,
            steps: vec![
                PatternStep {
                    activity: ActivityClass::NetworkConnect,
                    target_pattern: None,
                    order: 0,
                    min_count: 1,
                    require_ancestry: false,
                },
                PatternStep {
                    activity: ActivityClass::ProcessExec,
                    target_pattern: Some("sh|bash|zsh|fish|dash|csh|tcsh|/bin/sh|/bin/bash".into()),
                    order: 1,
                    min_count: 1,
                    require_ancestry: false,
                },
            ],
            window_secs: 30,
            mitre_id: Some("T1059.004".into()),
            // Canonical agent list — derived from agent_detect::known_agents() so
            // it can't drift. (It used to be a hand-maintained subset that omitted
            // gemini, chatgpt, cody, … → a Gemini CLI doing the normal "network +
            // spawn a shell for a tool" got flagged as a reverse shell and the
            // session was auto-KILLED. A coding agent doing network+shell is benign.)
            excluded_processes: crate::common::agent_detect::known_agents()
                .iter().map(|s| s.to_string()).collect(),
        },

        // 8. LLM → File → Exec Attack Chain
        // Offensive prompt detected → file written → binary executed → network connect
        // This is the canonical "AI agent weaponization" chain:
        // an agent asks an LLM for offensive code, writes it to disk, and runs it.
        AttackPattern {
            id: "llm_exec_chain".into(),
            name: "LLM → File → Exec Attack Chain".into(),
            description: "Offensive prompt detected in LLM API call, followed by file write \
                          and binary execution — AI agent may be weaponizing LLM-generated code. \
                          This is the highest-confidence indicator of an AI-driven attack."
                .into(),
            severity: Severity::Critical,
            steps: vec![
                PatternStep {
                    activity: ActivityClass::CredentialAccess, // OffensivePrompt maps here
                    target_pattern: None,
                    order: 0,
                    min_count: 1,
                    require_ancestry: false,
                },
                PatternStep {
                    activity: ActivityClass::FileWrite,
                    target_pattern: None,
                    order: 1,
                    min_count: 1,
                    require_ancestry: false,
                },
                PatternStep {
                    activity: ActivityClass::ProcessExec,
                    target_pattern: None,
                    order: 2,
                    min_count: 1,
                    require_ancestry: true, // Exec must be same process tree as file writer
                },
            ],
            window_secs: 120,
            mitre_id: Some("T1059 + T1027".into()),
            excluded_processes: vec![],
        },

        // 9. mprotect W→X + Exec (Runtime Code Generation)
        // Write→Execute memory transition followed by outbound network activity
        // Indicates LLM-generated shellcode was JIT-compiled and is calling home.
        // Excludes AI agents — Node.js V8 JIT does mprotect W→X as part of
        // normal execution, and agents connect to APIs. Not shellcode.
        AttackPattern {
            id: "wx_exec_chain".into(),
            name: "Runtime Code Generation & Callback".into(),
            description: "Write→Execute memory transition (mprotect W→X) followed by outbound \
                          network connection — indicates runtime-generated code (possibly \
                          LLM-synthesized shellcode) is actively executing and calling home."
                .into(),
            severity: Severity::Critical,
            steps: vec![
                PatternStep {
                    activity: ActivityClass::PrivilegeEscalation, // MprotectWx maps here
                    target_pattern: None,
                    order: 0,
                    min_count: 1,
                    require_ancestry: false,
                },
                PatternStep {
                    activity: ActivityClass::NetworkConnect,
                    target_pattern: None,
                    order: 1,
                    min_count: 1,
                    require_ancestry: true, // Network connect must be same process tree as W→X
                },
            ],
            window_secs: 60,
            mitre_id: Some("T1055 + T1071".into()),
            excluded_processes: vec![
                "claude".into(),
                "cursor".into(),
                "copilot".into(),
                "codex".into(),
                "windsurf".into(),
                "devin".into(),
                "aider".into(),
                "cline".into(),
                "node".into(),
            ],
        },

        // 10. Environment Harvesting
        // 5+ reads on config/credential files within window
        AttackPattern {
            id: "env_harvesting".into(),
            name: "Environment Variable Harvesting".into(),
            description: "Burst of reads on environment and configuration files — agent is \
                          systematically collecting secrets and credentials across the system."
                .into(),
            severity: Severity::High,
            steps: vec![
                PatternStep {
                    activity: ActivityClass::CredentialAccess,
                    target_pattern: Some(".env|.credentials|.config|.npmrc|.pypirc|.netrc|.aws/|.kube/|.docker/|credentials|id_rsa|id_ed25519|secret|token".into()),
                    order: 0,
                    min_count: 5,
                    require_ancestry: false,
                },
            ],
            window_secs: 60,
            mitre_id: Some("T1552.001".into()),
            excluded_processes: vec![],
        },
    ]
}

// ── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;

    fn make_event(kind: EventKind, target: &str, secs_ago: i64) -> SecurityEvent {
        let ts = Utc::now() - Duration::seconds(secs_ago);
        SecurityEvent {
            id: format!("test-{}-{}", target, secs_ago),
            kind,
            pid: 1234,
            uid: 1000,
            // Not "test-agent": any process whose name contains a known agent
            // name ("agent" is Cursor's CLI binary) is excluded from correlation.
            process: "exfil-tool".to_string(),
            target: target.to_string(),
            allowed: true,
            reason: None,
            timestamp: ts,
            ppid: Some(1233),
            parent_process: Some("bash".to_string()),
            llm_context: None,
            extra: None,
        }
    }

    #[test]
    fn builtin_patterns_are_valid() {
        let patterns = builtin_patterns();
        assert!(
            patterns.len() >= 10,
            "Expected at least 10 built-in patterns"
        );

        for p in &patterns {
            assert!(!p.id.is_empty(), "Pattern ID must not be empty");
            assert!(!p.steps.is_empty(), "Pattern '{}' has no steps", p.id);
            assert!(p.window_secs > 0, "Pattern '{}' has zero window", p.id);
        }

        // Verify critical patterns exist
        let ids: Vec<&str> = patterns.iter().map(|p| p.id.as_str()).collect();
        assert!(ids.contains(&"credential_exfil"));
        assert!(ids.contains(&"staged_exfil"));
        assert!(ids.contains(&"payload_drop"));
        assert!(ids.contains(&"reverse_shell"));
        assert!(ids.contains(&"env_harvesting"));
    }

    #[test]
    fn target_matching() {
        // Pipe-separated alternatives
        assert!(target_matches("/usr/bin/tar", "tar|zip|gzip"));
        assert!(target_matches("/usr/bin/zip", "tar|zip|gzip"));
        assert!(!target_matches("/usr/bin/cat", "tar|zip|gzip"));

        // Substring match
        assert!(target_matches("/home/user/.ssh/id_rsa", ".ssh/"));
        assert!(!target_matches("/home/user/project/main.rs", ".ssh/"));

        // Glob prefix
        assert!(target_matches("/tmp/malware", "/tmp/*"));
        assert!(!target_matches("/var/log/syslog", "/tmp/*"));

        // Case insensitive
        assert!(target_matches("/home/user/.SSH/ID_RSA", ".ssh/"));
    }

    #[tokio::test]
    async fn detect_credential_exfil() {
        let engine = CorrelationEngine::new();
        let session = "test-session-1";

        // Step 1: credential file read (50 seconds ago)
        let ev1 = make_event(EventKind::FileOpen, "/home/user/.ssh/id_rsa", 50);
        let result1 = engine.evaluate(&ev1, session).await;
        assert!(result1.is_none(), "Single event should not trigger chain");

        // Step 2: network connect (10 seconds ago) — completes the chain
        let ev2 = make_event(EventKind::NetworkConnect, "192.168.1.100:4444", 0);
        let result2 = engine.evaluate(&ev2, session).await;
        assert!(
            result2.is_some(),
            "Credential read + network connect should trigger credential_exfil"
        );

        let chain = result2.unwrap();
        assert_eq!(chain.pattern_id, "credential_exfil");
        assert_eq!(chain.severity, Severity::Critical);
        assert_eq!(chain.session_id, session);
        assert!(chain.mitre_id.as_deref().unwrap().contains("T1552"));
        assert_eq!(chain.matched_events.len(), 2);
    }

    #[tokio::test]
    async fn detect_payload_drop() {
        let engine = CorrelationEngine::new();
        let session = "test-session-2";

        // Step 1: write to /tmp (30 seconds ago)
        let ev1 = make_event(EventKind::FileWrite, "/tmp/payload.sh", 30);
        let result1 = engine.evaluate(&ev1, session).await;
        assert!(result1.is_none());

        // Step 2: execute from /tmp (now) — completes the chain
        let ev2 = make_event(EventKind::ProcessExec, "/tmp/payload.sh", 0);
        let result2 = engine.evaluate(&ev2, session).await;
        assert!(
            result2.is_some(),
            "File write to /tmp + exec from /tmp should trigger payload_drop"
        );

        let chain = result2.unwrap();
        assert_eq!(chain.pattern_id, "payload_drop");
        assert_eq!(chain.severity, Severity::Critical);
        assert!(chain.mitre_id.as_deref().unwrap().contains("T1105"));
    }

    #[tokio::test]
    async fn detect_reverse_shell() {
        let engine = CorrelationEngine::new();
        let session = "test-session-3";

        // Step 1: outbound connection (15 seconds ago)
        let ev1 = make_event(EventKind::NetworkConnect, "10.0.0.1:9999", 15);
        let result1 = engine.evaluate(&ev1, session).await;
        assert!(result1.is_none());

        // Step 2: shell exec (now) — completes the chain
        let ev2 = make_event(EventKind::ProcessExec, "/bin/bash", 0);
        let result2 = engine.evaluate(&ev2, session).await;
        assert!(
            result2.is_some(),
            "Network connect + shell exec should trigger reverse_shell"
        );

        let chain = result2.unwrap();
        assert_eq!(chain.pattern_id, "reverse_shell");
        assert_eq!(chain.severity, Severity::Critical);
    }

    #[tokio::test]
    async fn reverse_shell_excludes_coding_agents() {
        // Regression: a Gemini CLI doing the normal "talk to its API, then spawn
        // a shell for a tool" must NOT be flagged as a reverse shell and have its
        // session auto-killed. The session id carries the agent identity
        // (auto-gemini-<pid>); the exclusion list is the canonical agent set.
        for agent in ["gemini", "claude", "chatgpt", "cody", "cline"] {
            let engine = CorrelationEngine::new();
            let session = format!("auto-{agent}-8005");
            let ev1 = make_event(EventKind::NetworkConnect, "216.239.32.223:443", 5);
            assert!(engine.evaluate(&ev1, &session).await.is_none());
            let ev2 = make_event(EventKind::ProcessExec, "/bin/sh", 0);
            let result = engine.evaluate(&ev2, &session).await;
            assert!(
                result.as_ref().map_or(true, |c| c.pattern_id != "reverse_shell"),
                "{agent}: network + shell must NOT trigger reverse_shell (would auto-kill the agent)"
            );
        }
    }

    #[tokio::test]
    async fn detect_env_harvesting() {
        let engine = CorrelationEngine::new();
        let session = "test-session-4";

        let env_files = [
            "/app/.env",
            "/home/user/.aws/credentials",
            "/home/user/.npmrc",
            "/home/user/.kube/config",
            "/home/user/.docker/config",
        ];

        // Read 4 env files — not enough for threshold (5)
        for (i, f) in env_files[..4].iter().enumerate() {
            let ev = make_event(EventKind::FileOpen, f, (40 - i * 5) as i64);
            let result = engine.evaluate(&ev, session).await;
            assert!(
                result.is_none(),
                "Only {} env reads — below threshold",
                i + 1
            );
        }

        // 5th read triggers the chain
        let ev5 = make_event(EventKind::FileOpen, env_files[4], 0);
        let result = engine.evaluate(&ev5, session).await;
        assert!(
            result.is_some(),
            "5 env file reads should trigger env_harvesting"
        );

        let chain = result.unwrap();
        assert_eq!(chain.pattern_id, "env_harvesting");
        assert_eq!(chain.severity, Severity::High);
    }

    #[tokio::test]
    async fn no_match_outside_window() {
        let engine = CorrelationEngine::new();
        let session = "test-session-5";

        // Step 1: credential read 200 seconds ago (outside reverse_shell's 30s window
        // but inside credential_exfil's 120s window)
        let ev1 = make_event(EventKind::NetworkConnect, "10.0.0.1:9999", 200);
        engine.evaluate(&ev1, session).await;

        // Step 2: shell exec now — too far from network connect for reverse_shell
        let ev2 = make_event(EventKind::ProcessExec, "/bin/bash", 0);
        let result = engine.evaluate(&ev2, session).await;

        // The reverse_shell pattern has a 30s window, so 200s gap should not match
        if let Some(ref chain) = result {
            assert_ne!(
                chain.pattern_id, "reverse_shell",
                "Events 200s apart should NOT trigger reverse_shell (30s window)"
            );
        }
    }

    #[tokio::test]
    async fn recent_chains_and_session_filter() {
        let engine = CorrelationEngine::new();
        let session_a = "session-a";
        let session_b = "session-b";

        // Trigger chain in session A
        engine
            .evaluate(
                &make_event(EventKind::FileOpen, "/home/.ssh/id_rsa", 50),
                session_a,
            )
            .await;
        engine
            .evaluate(
                &make_event(EventKind::NetworkConnect, "1.2.3.4:80", 0),
                session_a,
            )
            .await;

        // Trigger chain in session B
        engine
            .evaluate(
                &make_event(EventKind::FileWrite, "/tmp/dropper", 20),
                session_b,
            )
            .await;
        engine
            .evaluate(
                &make_event(EventKind::ProcessExec, "/tmp/dropper", 0),
                session_b,
            )
            .await;

        let all = engine.recent_chains(10).await;
        assert!(all.len() >= 2, "Should have at least 2 chains");

        let a_chains = engine.chains_for_session(session_a, 10).await;
        assert!(!a_chains.is_empty());
        assert!(a_chains.iter().all(|c| c.session_id == session_a));

        let b_chains = engine.chains_for_session(session_b, 10).await;
        assert!(!b_chains.is_empty());
        assert!(b_chains.iter().all(|c| c.session_id == session_b));
    }

    #[tokio::test]
    async fn window_pruning() {
        let engine = CorrelationEngine::new();
        let session = "test-prune";

        // Insert MAX_WINDOW_SIZE + 100 events
        for i in 0..(MAX_WINDOW_SIZE + 100) {
            let ev = make_event(EventKind::FileOpen, &format!("/file/{}", i), 0);
            engine.evaluate(&ev, session).await;
        }

        let size = engine.window_size(session).await;
        assert!(
            size <= MAX_WINDOW_SIZE,
            "Window should be capped at {}",
            MAX_WINDOW_SIZE
        );
    }

    #[tokio::test]
    async fn detect_lateral_movement() {
        let engine = CorrelationEngine::new();
        let session = "test-lateral";

        // Step 1: credential access
        let ev1 = make_event(EventKind::FileOpen, "/home/user/.ssh/id_rsa", 60);
        engine.evaluate(&ev1, session).await;

        // Step 2: SSH connection
        let ev2 = make_event(EventKind::NetworkConnect, "10.0.0.50:22", 0);
        let result = engine.evaluate(&ev2, session).await;
        assert!(
            result.is_some(),
            "Credential access + SSH should trigger lateral_movement"
        );

        let chain = result.unwrap();
        // Could match credential_exfil too (but lateral_movement is also valid)
        // The engine returns the highest severity match
        assert!(
            chain.pattern_id == "lateral_movement" || chain.pattern_id == "credential_exfil",
            "Expected lateral_movement or credential_exfil, got {}",
            chain.pattern_id
        );
    }

    #[tokio::test]
    async fn detect_staged_exfil() {
        let engine = CorrelationEngine::new();
        let session = "test-staged";

        // Step 1: read sensitive file
        let ev1 = make_event(EventKind::FileOpen, "/home/user/.aws/credentials", 100);
        engine.evaluate(&ev1, session).await;

        // Step 2: compress
        let ev2 = make_event(EventKind::ProcessExec, "/usr/bin/tar", 50);
        engine.evaluate(&ev2, session).await;

        // Step 3: network connect (curl outbound)
        let ev3 = make_event(EventKind::NetworkConnect, "evil.com:443", 0);
        let result = engine.evaluate(&ev3, session).await;
        assert!(
            result.is_some(),
            "Read + tar + connect should trigger staged_exfil"
        );

        let chain = result.unwrap();
        assert!(
            chain.pattern_id == "staged_exfil" || chain.pattern_id == "credential_exfil",
            "Expected staged_exfil or credential_exfil, got {}",
            chain.pattern_id
        );
    }
}
