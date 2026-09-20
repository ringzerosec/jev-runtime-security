// SPDX-License-Identifier: Apache-2.0
// analyzer/intent_diff.rs — Intent–Action correlation engine
//
// AgentSight-inspired: correlates the **Intent Stream** (LLM prompts,
// responses, tool calls captured by the TLS proxy) with the **Action Stream**
// (kernel-level syscalls captured by eBPF) to build causal traces and detect
// behavioral drift.
//
// Correlation axes:
//   1. Process tree — actions from the agent's PID or child PIDs
//   2. Time window — actions within N seconds of an LLM response
//   3. Argument matching — URLs/paths/commands mentioned in the LLM response
//      matched against actual syscall targets
//   4. Sequence analysis — multi-step attack patterns (cred read → exfil)

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::RwLock;
use uuid::Uuid;

use crate::common::event::{EventKind, LlmContext, SecurityEvent};

// ── Data structures ──────────────────────────────────────────────────────────

/// Intent record received from the MCP proxy (mirrors mcp-proxy's IntentRecord).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntentRecord {
    pub session_id: String,
    pub tool_name: String,
    pub intent: String,
    pub risk_level: String,
    pub timestamp: String,
    pub allowed: bool,
}

/// A causal trace linking an LLM response to subsequent kernel actions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CausalTrace {
    pub trace_id: String,
    /// Session owning this trace
    pub session_id: String,
    /// The LLM response that initiated this action sequence
    pub llm_event: Option<SecurityEvent>,
    /// Kernel actions correlated to this LLM response
    pub actions: Vec<CorrelatedAction>,
    /// Trace-level risk assessment
    pub risk_score: u8,
    pub risk_reasons: Vec<String>,
    pub started_at: DateTime<Utc>,
    pub ended_at: DateTime<Utc>,
}

/// A kernel action correlated to an LLM response with match evidence.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorrelatedAction {
    pub event: SecurityEvent,
    /// How this action was correlated to the intent
    pub correlation: CorrelationType,
    /// If argument matching found a link, what was matched
    pub matched_argument: Option<String>,
}

/// How an action was linked to an intent.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CorrelationType {
    /// Action from the same PID within the time window
    ProcessDirect,
    /// Action from a child process within the time window
    ProcessChild,
    /// Target (URL/path/command) appears in the LLM response text
    ArgumentMatch,
    /// Both process tree and argument match
    ProcessAndArgument,
    /// Time-window only (no stronger signal)
    TimeWindow,
}

/// A discrepancy between declared intent and observed behavior.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntentDiff {
    pub id: String,
    pub session_id: String,
    pub pid: u32,
    pub declared_intent: String,
    pub observed_behavior: String,
    pub severity: DiffSeverity,
    pub events: Vec<SecurityEvent>,
    pub detected_at: String,
    /// Trace ID linking this diff to a causal trace (if available)
    pub trace_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DiffSeverity {
    Low,
    Medium,
    High,
    Critical,
}

/// Recent LLM response tracked per session for context propagation.
#[derive(Debug, Clone)]
struct RecentLlmResponse {
    session_id: String,
    pid: u32,
    response_text: String,
    tool_calls: Vec<String>,
    timestamp: DateTime<Utc>,
    trace_id: String,
    /// Extracted targets from the response text (URLs, paths, commands)
    extracted_targets: Vec<String>,
}

/// Tracks multi-step sequences for a session (for sequence-aware drift).
#[derive(Debug, Clone, Default)]
struct SessionSequence {
    /// Recent event kinds in order (last N events)
    recent_kinds: Vec<EventKind>,
    /// Recent targets accessed
    recent_targets: Vec<String>,
    /// Has this session read a credential path recently?
    cred_read: bool,
    /// Timestamp of the credential read
    cred_read_ts: Option<DateTime<Utc>>,
    /// Has this session done DNS lookup after cred read?
    dns_after_cred: bool,
}

// ── Constants ────────────────────────────────────────────────────────────────

/// Time window for correlating kernel actions to LLM responses (seconds).
const CORRELATION_WINDOW_SECS: i64 = 30;

/// Max number of actions per causal trace before we stop linking.
const MAX_TRACE_ACTIONS: usize = 100;

/// Max recent LLM responses to keep per session.
const MAX_RECENT_LLM: usize = 20;

/// Max recent events to keep in session sequence tracker.
const MAX_SEQUENCE_LEN: usize = 50;

// ── Engine ───────────────────────────────────────────────────────────────────

/// Engine that holds recent intents and detected diffs.
pub struct IntentDiffEngine {
    /// Recent intent records from MCP proxy.
    intents: RwLock<Vec<IntentRecord>>,
    /// Detected diffs.
    diffs: RwLock<Vec<IntentDiff>>,
    /// Recent LLM responses per session for context propagation.
    recent_llm: RwLock<Vec<RecentLlmResponse>>,
    /// Active causal traces (trace_id → trace).
    traces: RwLock<HashMap<String, CausalTrace>>,
    /// Per-session sequence tracking for multi-step attack detection.
    sequences: RwLock<HashMap<String, SessionSequence>>,
}

impl IntentDiffEngine {
    pub fn new() -> Self {
        Self {
            intents: RwLock::new(Vec::new()),
            diffs: RwLock::new(Vec::new()),
            recent_llm: RwLock::new(Vec::new()),
            traces: RwLock::new(HashMap::new()),
            sequences: RwLock::new(HashMap::new()),
        }
    }

    /// Record a new intent from the MCP proxy.
    pub fn record_intent(&self, record: IntentRecord) {
        let mut intents = self.intents.write().expect("intents lock poisoned");
        intents.push(record);
        if intents.len() > 500 {
            let drain_count = intents.len() - 500;
            intents.drain(0..drain_count);
        }
    }

    /// Record an LLM response event for context propagation.
    /// Called when the TLS proxy reassembles a complete LLM response.
    /// Returns the trace_id assigned to this response.
    pub fn record_llm_response(&self, session_id: &str, pid: u32, event: &SecurityEvent) -> String {
        let trace_id = format!("trace-{}", Uuid::new_v4());
        let now = Utc::now();

        let (response_text, tool_calls) = if let Some(ref ctx) = event.llm_context {
            (
                ctx.response_text.clone().unwrap_or_default(),
                ctx.tool_call.iter().cloned().collect::<Vec<_>>(),
            )
        } else {
            (String::new(), Vec::new())
        };

        // Extract actionable targets from the response text
        let extracted_targets = extract_targets_from_text(&response_text);

        let llm_record = RecentLlmResponse {
            session_id: session_id.to_string(),
            pid,
            response_text,
            tool_calls,
            timestamp: now,
            trace_id: trace_id.clone(),
            extracted_targets,
        };

        // Create a new causal trace
        let trace = CausalTrace {
            trace_id: trace_id.clone(),
            session_id: session_id.to_string(),
            llm_event: Some(event.clone()),
            actions: Vec::new(),
            risk_score: 0,
            risk_reasons: Vec::new(),
            started_at: now,
            ended_at: now,
        };

        {
            let mut recent = self.recent_llm.write().expect("recent_llm lock poisoned");
            recent.push(llm_record);
            // Keep bounded
            if recent.len() > MAX_RECENT_LLM * 10 {
                let drain = recent.len() - MAX_RECENT_LLM * 10;
                recent.drain(0..drain);
            }
        }
        {
            let mut traces = self.traces.write().expect("traces lock poisoned");
            traces.insert(trace_id.clone(), trace);
            // Prune old traces (keep last 200)
            if traces.len() > 200 {
                let mut by_time: Vec<_> = traces.keys().cloned().collect();
                by_time.sort();
                for key in by_time.iter().take(traces.len() - 200) {
                    traces.remove(key);
                }
            }
        }

        trace_id
    }

    /// Get the most recent LLM context for a session+pid, for attaching to
    /// kernel events. Returns (LlmContext, trace_id) if available.
    pub fn get_llm_context_for_event(
        &self,
        session_id: &str,
        pid: u32,
        ppid: Option<u32>,
    ) -> Option<(LlmContext, String)> {
        let recent = self.recent_llm.read().expect("recent_llm lock poisoned");
        let now = Utc::now();

        // Find the most recent LLM response for this session within the window
        // Match on session_id, and either same PID or parent PID (child process)
        recent
            .iter()
            .rev()
            .find(|r| {
                let within_window =
                    (now - r.timestamp).num_seconds().abs() <= CORRELATION_WINDOW_SECS;
                let pid_match = r.pid == pid || ppid.map_or(false, |pp| r.pid == pp);
                let session_match = r.session_id == session_id;
                within_window && (session_match || pid_match)
            })
            .map(|r| {
                let ctx = LlmContext {
                    provider: "correlated".to_string(),
                    model: None,
                    response_text: if r.response_text.is_empty() {
                        None
                    } else {
                        // Truncate for attachment — keep last 2048 chars
                        let text = if r.response_text.len() > 2048 {
                            r.response_text[r.response_text.len() - 2048..].to_string()
                        } else {
                            r.response_text.clone()
                        };
                        Some(text)
                    },
                    tool_call: r.tool_calls.first().cloned(),
                    usage: None,
                    response_ts: r.timestamp,
                };
                (ctx, r.trace_id.clone())
            })
    }

    /// Correlate a kernel event against recent LLM responses.
    /// Returns the correlation type and trace_id if a match is found.
    pub fn correlate_action(
        &self,
        event: &SecurityEvent,
        session_id: &str,
    ) -> Option<(CorrelationType, String)> {
        let recent = self.recent_llm.read().expect("recent_llm lock poisoned");
        let now = Utc::now();

        // Find the best matching LLM response
        for r in recent.iter().rev() {
            let within_window = (now - r.timestamp).num_seconds().abs() <= CORRELATION_WINDOW_SECS;
            if !within_window {
                continue;
            }
            let session_match = r.session_id == session_id;
            if !session_match {
                continue;
            }

            // Determine correlation type
            let is_direct = r.pid == event.pid;
            let is_child = event.ppid.map_or(false, |pp| r.pid == pp);
            let arg_match =
                target_matches_response(&event.target, &r.response_text, &r.extracted_targets);

            let correlation = match (is_direct || is_child, arg_match.is_some()) {
                (true, true) => CorrelationType::ProcessAndArgument,
                (true, false) => CorrelationType::ProcessDirect,
                (false, true) => CorrelationType::ArgumentMatch,
                (false, false) => CorrelationType::TimeWindow,
            };

            // Clone what we need before dropping the read lock
            let trace_id = r.trace_id.clone();
            let arg_match_clone = arg_match.clone();
            drop(recent);

            // Add to the causal trace
            {
                let mut traces = self.traces.write().expect("traces lock poisoned");
                if let Some(trace) = traces.get_mut(&trace_id) {
                    if trace.actions.len() < MAX_TRACE_ACTIONS {
                        trace.actions.push(CorrelatedAction {
                            event: event.clone(),
                            correlation: correlation.clone(),
                            matched_argument: arg_match_clone,
                        });
                        trace.ended_at = now;
                    }
                }
            }

            return Some((correlation, trace_id));
        }

        None
    }

    /// Compare a new SecurityEvent against recent intents (MCP) and LLM responses.
    /// Returns Some(IntentDiff) if a discrepancy is detected.
    pub fn check_event(&self, event: &SecurityEvent, session_id: &str) -> Option<IntentDiff> {
        let behavior = event_to_behavior(&event.kind);
        if behavior == "other" {
            return None;
        }

        // An AI agent connecting to its own LLM provider — or to our loopback
        // inspection proxy, which is where its HTTPS is now routed — is its single
        // most expected behavior, not an intent mismatch. Without this, every API
        // call from an auto-created session (declared=none, no MCP intent) is
        // flagged as a Critical "network_request" threat (the Gemini FP storm).
        if behavior == "network_request"
            && crate::policy::network::is_whitelisted_destination(&event.target)
        {
            return None;
        }

        // Update per-session sequence tracking
        self.update_sequence(session_id, event);

        let now = Utc::now();

        // Check MCP intents first (explicit declared intent)
        let intents = self.intents.read().expect("intents lock poisoned");
        let matching_intent = intents.iter().rev().find(|r| {
            let record_time = DateTime::parse_from_rfc3339(&r.timestamp)
                .map(|dt| dt.with_timezone(&Utc))
                .ok();
            let within_window = record_time
                .map(|t| (now - t).num_seconds().abs() <= CORRELATION_WINDOW_SECS)
                .unwrap_or(false);
            within_window && intent_matches(&r.intent, behavior)
        });

        if matching_intent.is_some() {
            return None; // MCP intent covers this behavior
        }

        // Check LLM response correlation — if the action target appears in
        // a recent LLM response, that's an implicit intent (the model said
        // to do it, even if no explicit MCP intent was declared)
        {
            let recent = self.recent_llm.read().expect("recent_llm lock poisoned");
            let has_llm_cover = recent.iter().rev().any(|r| {
                let within_window =
                    (now - r.timestamp).num_seconds().abs() <= CORRELATION_WINDOW_SECS;
                let session_match = r.session_id == session_id;
                if !within_window || !session_match {
                    return false;
                }
                // If the target matches something in the LLM response, consider it covered
                target_matches_response(&event.target, &r.response_text, &r.extracted_targets)
                    .is_some()
            });
            if has_llm_cover {
                return None;
            }
        }

        // Check sequence-level drift
        let sequence_alert = self.check_sequence_drift(session_id, event);

        // No intent covers this behavior — generate a diff
        let declared_intent = intents
            .iter()
            .rev()
            .next()
            .map(|r| r.intent.clone())
            .unwrap_or_else(|| "none".to_string());

        let intent_session = intents
            .iter()
            .rev()
            .next()
            .map(|r| r.session_id.clone())
            .unwrap_or_else(|| session_id.to_string());

        drop(intents);

        let mut severity = mismatch_severity(&event.kind);

        // Escalate severity if sequence analysis found something
        if let Some(ref alert) = sequence_alert {
            severity = match alert.as_str() {
                s if s.contains("exfiltration") => DiffSeverity::Critical,
                s if s.contains("credential") => DiffSeverity::High,
                _ => severity,
            };
        }

        // Get trace_id from correlation if available
        let trace_id = {
            let recent = self.recent_llm.read().expect("recent_llm lock poisoned");
            recent
                .iter()
                .rev()
                .find(|r| {
                    let w = (now - r.timestamp).num_seconds().abs() <= CORRELATION_WINDOW_SECS;
                    w && r.session_id == session_id
                })
                .map(|r| r.trace_id.clone())
        };

        let observed = if let Some(ref alert) = sequence_alert {
            format!("{} [sequence: {}]", behavior, alert)
        } else {
            behavior.to_string()
        };

        let diff = IntentDiff {
            id: Uuid::new_v4().to_string(),
            session_id: intent_session,
            pid: event.pid,
            declared_intent,
            observed_behavior: observed,
            severity,
            events: vec![event.clone()],
            detected_at: now.to_rfc3339(),
            trace_id,
        };

        {
            let mut diffs = self.diffs.write().expect("diffs lock poisoned");
            diffs.push(diff.clone());
            if diffs.len() > 1000 {
                let drain_count = diffs.len() - 1000;
                diffs.drain(0..drain_count);
            }
        }

        Some(diff)
    }

    /// Get all detected diffs.
    pub fn diffs(&self) -> Vec<IntentDiff> {
        self.diffs.read().expect("diffs lock poisoned").clone()
    }

    /// Get a causal trace by ID.
    pub fn get_trace(&self, trace_id: &str) -> Option<CausalTrace> {
        self.traces
            .read()
            .expect("traces lock poisoned")
            .get(trace_id)
            .cloned()
    }

    /// Get all active causal traces.
    pub fn traces(&self) -> Vec<CausalTrace> {
        self.traces
            .read()
            .expect("traces lock poisoned")
            .values()
            .cloned()
            .collect()
    }

    // ── Sequence tracking (multi-step drift detection) ───────────────────────

    fn update_sequence(&self, session_id: &str, event: &SecurityEvent) {
        let mut seqs = self.sequences.write().expect("sequences lock poisoned");
        let seq = seqs.entry(session_id.to_string()).or_default();

        seq.recent_kinds.push(event.kind.clone());
        seq.recent_targets.push(event.target.clone());
        if seq.recent_kinds.len() > MAX_SEQUENCE_LEN {
            seq.recent_kinds.remove(0);
            seq.recent_targets.remove(0);
        }

        // Track credential reads
        if matches!(event.kind, EventKind::FileOpen | EventKind::FileCreate)
            && is_credential_path(&event.target)
        {
            seq.cred_read = true;
            seq.cred_read_ts = Some(event.timestamp);
        }

        // Track DNS after credential read
        if seq.cred_read && matches!(event.kind, EventKind::DnsQuery) {
            seq.dns_after_cred = true;
        }
    }

    fn check_sequence_drift(&self, session_id: &str, event: &SecurityEvent) -> Option<String> {
        let seqs = self.sequences.read().expect("sequences lock poisoned");
        let seq = seqs.get(session_id)?;

        // Pattern: credential read → DNS → network send = exfiltration sequence
        if seq.cred_read
            && seq.dns_after_cred
            && matches!(
                event.kind,
                EventKind::NetworkSend | EventKind::NetworkConnect
            )
        {
            // Check if the cred read was recent (within 60s)
            if let Some(cred_ts) = seq.cred_read_ts {
                if (event.timestamp - cred_ts).num_seconds().abs() <= 60 {
                    return Some(format!(
                        "credential exfiltration sequence: cred_read → dns → {}",
                        if event.kind == EventKind::NetworkSend {
                            "network_send"
                        } else {
                            "network_connect"
                        }
                    ));
                }
            }
        }

        // Pattern: credential read → network connect (no DNS, direct IP exfil)
        if seq.cred_read && !seq.dns_after_cred && matches!(event.kind, EventKind::NetworkConnect) {
            if let Some(cred_ts) = seq.cred_read_ts {
                if (event.timestamp - cred_ts).num_seconds().abs() <= 30 {
                    return Some(
                        "credential exfiltration (direct IP): cred_read → network_connect"
                            .to_string(),
                    );
                }
            }
        }

        // Pattern: multiple file deletes in rapid succession (destructive behavior)
        let recent_deletes = seq
            .recent_kinds
            .iter()
            .rev()
            .take(10)
            .filter(|k| matches!(k, EventKind::FileDelete))
            .count();
        if recent_deletes >= 5 && matches!(event.kind, EventKind::FileDelete) {
            return Some(format!(
                "mass file deletion: {} deletes in last {} events",
                recent_deletes + 1,
                seq.recent_kinds.len().min(10),
            ));
        }

        None
    }
}

impl Default for IntentDiffEngine {
    fn default() -> Self {
        Self::new()
    }
}

// ── Argument matching ────────────────────────────────────────────────────────

/// Extract actionable targets (URLs, file paths, commands) from LLM response text.
fn extract_targets_from_text(text: &str) -> Vec<String> {
    let mut targets = Vec::new();

    for word in text.split_whitespace() {
        let cleaned = word.trim_matches(|c: char| {
            c == '"' || c == '\'' || c == '`' || c == ',' || c == ';' || c == ')' || c == '('
        });
        // File paths (absolute)
        if cleaned.starts_with('/') && cleaned.len() > 2 {
            targets.push(cleaned.to_string());
        }
        // Home-relative paths
        if cleaned.starts_with("~/") && cleaned.len() > 2 {
            targets.push(cleaned.to_string());
        }
        // URLs
        if cleaned.starts_with("http://") || cleaned.starts_with("https://") {
            // Extract hostname from URL
            if let Some(host) = cleaned.split("//").nth(1).and_then(|s| s.split('/').next()) {
                let host = host.split(':').next().unwrap_or(host);
                targets.push(host.to_string());
            }
            targets.push(cleaned.to_string());
        }
        // Hostnames/domains (contains dots, no spaces, reasonable length)
        if cleaned.contains('.')
            && !cleaned.contains(' ')
            && cleaned.len() >= 4
            && cleaned.len() <= 253
            && cleaned
                .chars()
                .all(|c| c.is_alphanumeric() || c == '.' || c == '-' || c == ':')
            && !cleaned.starts_with('.')
        {
            let host = cleaned.split(':').next().unwrap_or(cleaned);
            targets.push(host.to_string());
        }
    }

    targets.sort();
    targets.dedup();
    targets
}

/// Check if a kernel event target matches something mentioned in the LLM response.
/// Returns the matched string if found.
fn target_matches_response(
    target: &str,
    response_text: &str,
    extracted_targets: &[String],
) -> Option<String> {
    if target.is_empty() || response_text.is_empty() {
        return None;
    }

    // Direct: target path/host appears verbatim in response
    if response_text.contains(target) {
        return Some(target.to_string());
    }

    // Check if any extracted target matches
    for extracted in extracted_targets {
        // Exact match
        if target == extracted {
            return Some(extracted.clone());
        }
        // Target contains the extracted value (e.g. target="evil.com:443", extracted="evil.com")
        if target.contains(extracted.as_str()) {
            return Some(extracted.clone());
        }
        // Extracted contains the target (e.g. extracted="/home/user/.ssh/id_rsa", target=".ssh/id_rsa")
        if extracted.contains(target) {
            return Some(extracted.clone());
        }
    }

    // Basename matching: check if the filename component of a path appears in the response
    if let Some(basename) = target.rsplit('/').next() {
        if basename.len() >= 3 && response_text.contains(basename) {
            return Some(basename.to_string());
        }
    }

    // IP:port matching — target might be "1.2.3.4:443", check for just the IP
    if let Some(ip) = target.split(':').next() {
        if !ip.is_empty() && ip.contains('.') && response_text.contains(ip) {
            return Some(ip.to_string());
        }
    }

    None
}

// ── Helpers ──────────────────────────────────────────────────────────────────

fn event_to_behavior(kind: &EventKind) -> &'static str {
    match kind {
        // What the agent said, not what it did. See the note in
        // analyzer/correlation.rs.
        EventKind::AgentStdout | EventKind::AgentStdin => "agent_output",
        EventKind::TranscriptWrite => "file_operation",
        EventKind::FileOpen
        | EventKind::FileCreate
        | EventKind::FileWrite
        | EventKind::FileDelete
        | EventKind::FileRename => "file_operation",
        EventKind::NetworkConnect | EventKind::NetworkSend => "network_request",
        EventKind::ProcessExec | EventKind::ProcessFork => "process_execution",
        EventKind::DnsQuery => "dns_query",
        EventKind::ProcessExit
        | EventKind::NetworkRecv
        | EventKind::McpToolCall
        | EventKind::LlmRequest
        | EventKind::LlmResponse
        | EventKind::LlmToolCall
        | EventKind::ProxyBlock
        | EventKind::ProxyDetection
        | EventKind::DlpPii
        | EventKind::TamperPtrace
        | EventKind::TamperSignal
        | EventKind::TamperMount
        | EventKind::TamperUmount
        | EventKind::ContainedExecBlocked
        | EventKind::ContainedFileBlocked
        | EventKind::OffensivePrompt
        | EventKind::PromptInjection
        | EventKind::MprotectWx
        | EventKind::AttackChain
        | EventKind::SkillFileChange
        | EventKind::SkillGitRepoDrop => "other",
    }
}

fn expected_intents(behavior: &str) -> &'static [&'static str] {
    match behavior {
        "network_request" => &["network_request", "tool_call:"],
        "file_operation" => &[
            "file_read",
            "file_write",
            "file_deletion",
            "file_search",
            "credential_read",
            "shell_execution",
            "package_operation",
            "tool_call:",
        ],
        "process_execution" => &["shell_execution", "package_operation", "tool_call:"],
        "dns_query" => &["network_request", "tool_call:"],
        _ => &[],
    }
}

fn intent_matches(intent: &str, behavior: &str) -> bool {
    let expected = expected_intents(behavior);
    for pat in expected {
        if pat.ends_with(':') {
            if intent.starts_with(pat) {
                return true;
            }
        } else if intent == *pat {
            return true;
        }
    }
    false
}

fn mismatch_severity(kind: &EventKind) -> DiffSeverity {
    match kind {
        EventKind::NetworkConnect | EventKind::NetworkSend => DiffSeverity::Critical,
        EventKind::FileDelete => DiffSeverity::High,
        EventKind::ProcessExec | EventKind::ProcessFork => DiffSeverity::Medium,
        _ => DiffSeverity::Low,
    }
}

fn is_credential_path(path: &str) -> bool {
    const CRED_PATHS: &[&str] = &[
        ".ssh/",
        ".aws/credentials",
        ".aws/config",
        ".config/gcloud",
        "keychain",
        "Keychain",
        ".gnupg/",
        ".netrc",
        ".npmrc",
        ".pypirc",
        "id_rsa",
        "id_ed25519",
        "id_ecdsa",
        "/etc/shadow",
        "/etc/passwd",
    ];
    CRED_PATHS.iter().any(|c| path.contains(c))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::event::SecurityEvent;
    use chrono::Utc;

    fn make_event(pid: u32, kind: EventKind, target: &str) -> SecurityEvent {
        SecurityEvent {
            id: format!("test-{}", Uuid::new_v4()),
            kind,
            pid,
            uid: 1000,
            process: "test-agent".to_string(),
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

    fn make_llm_event(pid: u32, response: &str, tool_call: Option<&str>) -> SecurityEvent {
        SecurityEvent {
            id: format!("llm-{}", Uuid::new_v4()),
            kind: if tool_call.is_some() {
                EventKind::LlmToolCall
            } else {
                EventKind::LlmResponse
            },
            pid,
            uid: 1000,
            process: "test-agent".to_string(),
            target: "anthropic:claude-sonnet-4-20250514".to_string(),
            allowed: true,
            reason: None,
            timestamp: Utc::now(),
            ppid: None,
            parent_process: None,
            llm_context: Some(LlmContext {
                provider: "anthropic".to_string(),
                model: Some("claude-sonnet-4-20250514".to_string()),
                response_text: Some(response.to_string()),
                tool_call: tool_call.map(|s| s.to_string()),
                usage: None,
                response_ts: Utc::now(),
            }),
            extra: None,
        }
    }

    #[test]
    fn extract_paths_from_text() {
        let text = "I'll read the file at /home/user/.ssh/id_rsa and then connect to evil.com";
        let targets = extract_targets_from_text(text);
        assert!(targets.contains(&"/home/user/.ssh/id_rsa".to_string()));
        assert!(targets.contains(&"evil.com".to_string()));
    }

    #[test]
    fn extract_urls_from_text() {
        let text = "Let me fetch https://api.example.com/data and save to ~/output.json";
        let targets = extract_targets_from_text(text);
        assert!(targets.contains(&"api.example.com".to_string()));
        assert!(targets.contains(&"~/output.json".to_string()));
    }

    #[test]
    fn argument_match_direct() {
        let result = target_matches_response(
            "/home/user/.ssh/id_rsa",
            "I'll read /home/user/.ssh/id_rsa for the SSH key",
            &["/home/user/.ssh/id_rsa".to_string()],
        );
        assert!(result.is_some());
    }

    #[test]
    fn argument_match_hostname() {
        let result = target_matches_response(
            "evil.com:443",
            "Let me connect to evil.com",
            &["evil.com".to_string()],
        );
        assert!(result.is_some());
    }

    #[test]
    fn argument_no_match() {
        let result = target_matches_response(
            "attacker.com:443",
            "I'll connect to api.example.com",
            &["api.example.com".to_string()],
        );
        assert!(result.is_none());
    }

    #[test]
    fn llm_context_propagation() {
        let engine = IntentDiffEngine::new();
        let llm_event = make_llm_event(100, "Reading /etc/passwd for user info", None);
        let trace_id = engine.record_llm_response("session-1", 100, &llm_event);
        assert!(!trace_id.is_empty());

        // Kernel event from same PID should get LLM context
        let ctx = engine.get_llm_context_for_event("session-1", 100, None);
        assert!(ctx.is_some());
        let (llm_ctx, tid) = ctx.unwrap();
        assert!(llm_ctx.response_text.unwrap().contains("/etc/passwd"));
        assert_eq!(tid, trace_id);
    }

    #[test]
    fn correlate_action_argument_match() {
        let engine = IntentDiffEngine::new();
        let llm_event =
            make_llm_event(100, "I'll read ~/.ssh/id_rsa and send it to evil.com", None);
        engine.record_llm_response("session-1", 100, &llm_event);

        // File read that matches the LLM response
        let file_event = make_event(100, EventKind::FileOpen, "/home/user/.ssh/id_rsa");
        let result = engine.correlate_action(&file_event, "session-1");
        assert!(result.is_some());
        let (corr, _tid) = result.unwrap();
        assert!(matches!(corr, CorrelationType::ProcessAndArgument));
    }

    #[test]
    fn sequence_exfil_detection() {
        let engine = IntentDiffEngine::new();

        // Step 1: credential read
        let cred_event = make_event(100, EventKind::FileOpen, "/home/user/.ssh/id_rsa");
        let _diff1 = engine.check_event(&cred_event, "session-1");
        // May or may not diff (no intents registered), but sequence should track

        // Step 2: DNS query
        let dns_event = make_event(100, EventKind::DnsQuery, "evil.com");
        let _diff2 = engine.check_event(&dns_event, "session-1");

        // Step 3: network send — should detect exfiltration sequence
        let send_event = make_event(100, EventKind::NetworkSend, "evil.com:443");
        let diff3 = engine.check_event(&send_event, "session-1");
        assert!(diff3.is_some());
        let d = diff3.unwrap();
        assert_eq!(d.severity, DiffSeverity::Critical);
        assert!(d.observed_behavior.contains("exfiltration"));
    }

    #[test]
    fn llm_response_covers_action() {
        let engine = IntentDiffEngine::new();

        // LLM says it will read a file
        let llm_event = make_llm_event(100, "I'll read /tmp/config.json for you", None);
        engine.record_llm_response("session-1", 100, &llm_event);

        // Kernel event for exactly that file — should NOT produce a diff
        let file_event = make_event(100, EventKind::FileOpen, "/tmp/config.json");
        let diff = engine.check_event(&file_event, "session-1");
        assert!(
            diff.is_none(),
            "LLM response should cover this action via argument match"
        );
    }

    #[test]
    fn uncovered_action_produces_diff() {
        let engine = IntentDiffEngine::new();

        // LLM says it will read one file
        let llm_event = make_llm_event(100, "I'll read /tmp/config.json", None);
        engine.record_llm_response("session-1", 100, &llm_event);

        // Kernel event for a DIFFERENT file — should produce a diff
        let file_event = make_event(100, EventKind::FileOpen, "/etc/shadow");
        let diff = engine.check_event(&file_event, "session-1");
        // /etc/shadow is not mentioned in the LLM response and no MCP intent covers it
        assert!(diff.is_some());
    }

    #[test]
    fn causal_trace_built() {
        let engine = IntentDiffEngine::new();

        let llm_event = make_llm_event(100, "I'll run git status and read README.md", None);
        let trace_id = engine.record_llm_response("session-1", 100, &llm_event);

        let action1 = make_event(100, EventKind::ProcessExec, "git");
        engine.correlate_action(&action1, "session-1");

        let action2 = make_event(100, EventKind::FileOpen, "README.md");
        engine.correlate_action(&action2, "session-1");

        let trace = engine.get_trace(&trace_id).unwrap();
        assert_eq!(trace.actions.len(), 2);
        assert!(matches!(
            trace.actions[0].correlation,
            CorrelationType::ProcessDirect | CorrelationType::ProcessAndArgument
        ));
    }

    #[test]
    fn mass_deletion_detection() {
        let engine = IntentDiffEngine::new();

        // Delete 6 files in succession
        for i in 0..6 {
            let ev = make_event(100, EventKind::FileDelete, &format!("/tmp/file_{}.txt", i));
            let diff = engine.check_event(&ev, "session-1");
            if i >= 5 {
                // Should trigger mass deletion alert on the 6th delete
                assert!(diff.is_some());
                let d = diff.unwrap();
                assert!(d.observed_behavior.contains("mass file deletion"));
            }
        }
    }
}
