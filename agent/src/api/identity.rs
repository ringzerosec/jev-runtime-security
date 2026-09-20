// SPDX-License-Identifier: Apache-2.0
// api/identity.rs — Agent Identity API (Phase 5)
//
// Unified endpoint that surfaces the full agent context for a session:
// agent detection, LLM context, process lineage, policy state, risk score,
// and data exfiltration metrics.
//
// This is the "category-defining" feature — Ring Zero is more than a syscall
// monitor; it provides a single pane of glass into what an AI agent is, what
// it's doing, and whether it's behaving.

use std::sync::Arc;

use chrono::{DateTime, Utc};
use serde::Serialize;

use crate::analyzer::observer::{ActivityClass, BaselineViolation, ObserverEngine};
use crate::common::event::EventKind;
use crate::config::PiiAction;
use crate::secrets::dlp::DlpEngine;
use crate::session::store::Session;
use crate::session::SessionStore;

// ── Response types ──────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize)]
pub struct AgentIdentity {
    pub session_id: String,
    pub agent: AgentInfo,
    pub context: AgentContext,
    pub lineage: ProcessLineage,
    pub policy: PolicyState,
    pub risk_score: u32,
    pub data_exfiltration: DataExfiltration,
}

#[derive(Debug, Clone, Serialize)]
pub struct AgentInfo {
    #[serde(rename = "type")]
    pub agent_type: String,
    pub provider: String,
    pub model: Option<String>,
    pub binary_path: Option<String>,
    pub version: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct AgentContext {
    pub current_prompt: Option<String>,
    pub task_description: Option<String>,
    pub tools_available: Vec<String>,
    pub last_tool_call: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ProcessLineage {
    pub pid: Option<u32>,
    pub ppid: Option<u32>,
    pub parent_process: Option<String>,
    pub process_tree: Vec<String>,
    pub cwd: Option<String>,
    pub started_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize)]
pub struct PolicyState {
    pub profile: String,
    pub active_rules: usize,
    pub violations: usize,
    pub declared_scope: Vec<String>,
    pub containment: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct DataExfiltration {
    pub pii_detected: usize,
    pub secrets_detected: usize,
    pub action_mode: String,
}

/// Summary view for the list endpoint.
#[derive(Debug, Clone, Serialize)]
pub struct AgentIdentitySummary {
    pub session_id: String,
    pub agent_type: String,
    pub provider: String,
    pub model: Option<String>,
    pub profile: String,
    pub risk_score: u32,
    pub violations: usize,
    pub pid: Option<u32>,
    pub started_at: DateTime<Utc>,
    pub state: String,
}

// ── Provider mapping ────────────────────────────────────────────────────────

/// Map agent type string to its cloud provider.
fn agent_provider(agent_type: &str) -> &'static str {
    match agent_type.to_lowercase().as_str() {
        "claude" => "anthropic",
        "chatgpt" => "openai",
        "codex" => "openai",
        "copilot" => "github",
        "gemini" => "google",
        "deepseek" => "deepseek",
        "cursor" => "cursor",
        "devin" => "cognition",
        "aider" => "community",
        "windsurf" => "codeium",
        "cody" => "sourcegraph",
        "tabnine" => "tabnine",
        _ => "unknown",
    }
}

// ── /proc helpers ────────────────────────────────────────────────────────────

/// Read the binary path for a PID via /proc/<pid>/exe symlink.
fn read_exe_path(pid: u32) -> Option<String> {
    std::fs::read_link(format!("/proc/{}/exe", pid))
        .ok()
        .map(|p| p.display().to_string())
}

/// Read the current working directory for a PID via /proc/<pid>/cwd.
fn read_cwd(pid: u32) -> Option<String> {
    std::fs::read_link(format!("/proc/{}/cwd", pid))
        .ok()
        .map(|p| p.display().to_string())
}

/// Read the parent PID from /proc/<pid>/status.
fn read_ppid(pid: u32) -> Option<u32> {
    let status = std::fs::read_to_string(format!("/proc/{}/status", pid)).ok()?;
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("PPid:") {
            return rest.trim().parse::<u32>().ok();
        }
    }
    None
}

/// Read the process name from /proc/<pid>/comm.
fn read_comm(pid: u32) -> Option<String> {
    std::fs::read_to_string(format!("/proc/{}/comm", pid))
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

/// Walk the process tree upward from a PID via /proc.
/// Returns names from root → leaf (e.g. ["systemd", "sshd", "bash", "claude"]).
/// Stops at PID 1 or after 32 hops to prevent infinite loops.
fn build_process_tree(pid: u32) -> Vec<String> {
    let mut tree = Vec::new();
    let mut current = pid;
    let max_depth = 32;

    for _ in 0..max_depth {
        if let Some(name) = read_comm(current) {
            tree.push(name);
        } else {
            break;
        }
        match read_ppid(current) {
            Some(ppid) if ppid > 0 && ppid != current => {
                current = ppid;
            }
            _ => break,
        }
    }

    tree.reverse(); // root → leaf order
    tree
}

// ── Risk score calculation ──────────────────────────────────────────────────

/// Calculate a 0–100 risk score based on violations and behavior.
///
/// Scoring:
///   - Base: 0
///   - +10 per baseline violation (warn)
///   - +20 per credential access violation
///   - +15 per blocked violation
///   - +30 if PII detected in block mode
///   - Capped at 100
fn calculate_risk_score(
    violations: &[BaselineViolation],
    pii_count: usize,
    secrets_count: usize,
    pii_action: &PiiAction,
) -> u32 {
    let mut score: u32 = 0;

    for v in violations {
        // Skip violations on whitelisted destinations — AI agents legitimately
        // connect to APIs and registries; these aren't risky behaviors.
        if crate::policy::network::is_whitelisted_destination(&v.target) {
            continue;
        }
        // Skip normal process exec violations (shells, common tools) for AI agents
        if v.activity_class == ActivityClass::ProcessExec {
            let proc_lower = v.process.to_lowercase();
            if [
                "claude", "cursor", "copilot", "codex", "windsurf", "devin", "aider", "cline",
            ]
            .iter()
            .any(|a| proc_lower.contains(a))
            {
                continue;
            }
        }

        if v.activity_class == ActivityClass::CredentialAccess {
            score = score.saturating_add(20);
        } else if v.action_taken == "blocked" {
            score = score.saturating_add(15);
        } else {
            // warned
            score = score.saturating_add(10);
        }
    }

    // PII in block mode is a serious indicator
    if pii_count > 0 && matches!(pii_action, PiiAction::Block) {
        score = score.saturating_add(30);
    } else if pii_count > 0 {
        score = score.saturating_add(10);
    }

    if secrets_count > 0 {
        score = score.saturating_add(25);
    }

    score.min(100)
}

// ── Builder ─────────────────────────────────────────────────────────────────

/// Build the full agent identity response for a single session.
pub async fn build_agent_identity(
    session: &Session,
    session_store: &Arc<SessionStore>,
    observer: &Arc<ObserverEngine>,
    dlp: &Arc<DlpEngine>,
) -> AgentIdentity {
    let session_id = &session.id;
    let agent_type_str = session.agent_type.to_string();

    // -- Agent info --
    let primary_pid = session.pids.first().copied();
    let binary_path = primary_pid.and_then(read_exe_path);

    // Try to find model from LLM events
    let events = session_store.get_events(session_id);
    let llm_events: Vec<_> = events
        .iter()
        .filter(|e| matches!(e.kind, EventKind::LlmRequest | EventKind::LlmResponse))
        .collect();

    let model = llm_events
        .iter()
        .rev()
        .find_map(|e| e.llm_context.as_ref().and_then(|ctx| ctx.model.clone()));

    let agent = AgentInfo {
        agent_type: agent_type_str.clone(),
        provider: agent_provider(&agent_type_str).to_string(),
        model,
        binary_path,
        version: None, // Not reliably detectable at runtime
    };

    // -- Context (from LLM events) --
    let current_prompt = llm_events.iter().rev().find_map(|e| {
        if e.kind == EventKind::LlmRequest {
            e.llm_context
                .as_ref()
                .and_then(|ctx| ctx.response_text.clone())
        } else {
            None
        }
    });

    let tool_call_events: Vec<_> = events
        .iter()
        .filter(|e| e.kind == EventKind::LlmToolCall)
        .collect();

    let tools_available: Vec<String> = tool_call_events
        .iter()
        .filter_map(|e| {
            e.llm_context
                .as_ref()
                .and_then(|ctx| ctx.tool_call.as_ref())
                .map(|tc| {
                    // Extract tool name (before first space): "Write /src/auth.rs" → "Write"
                    tc.split_whitespace().next().unwrap_or(tc).to_string()
                })
        })
        .collect::<std::collections::HashSet<_>>()
        .into_iter()
        .collect();

    let last_tool_call = tool_call_events
        .first() // events are newest-first
        .and_then(|e| e.llm_context.as_ref())
        .and_then(|ctx| ctx.tool_call.clone());

    let context = AgentContext {
        current_prompt,
        task_description: None, // Would require system prompt extraction
        tools_available,
        last_tool_call,
    };

    // -- Lineage --
    let ppid = primary_pid.and_then(read_ppid);
    let parent_process = ppid.and_then(read_comm);
    let process_tree = primary_pid.map(build_process_tree).unwrap_or_default();
    let cwd = primary_pid.and_then(read_cwd);

    let lineage = ProcessLineage {
        pid: primary_pid,
        ppid,
        parent_process,
        process_tree,
        cwd,
        started_at: session.start_time,
    };

    // -- Policy --
    let policy_data = observer.get_policy(session_id).await;
    let violations = observer.session_violations(session_id).await;
    let violation_count = violations.len();

    // Check if containment is supported (eBPF/ES active) by checking if policy exists
    let containment = if policy_data.is_some() {
        "active"
    } else {
        "inactive"
    };

    let policy = PolicyState {
        profile: policy_data
            .as_ref()
            .map(|p| p.profile_label.clone())
            .unwrap_or_else(|| "None".to_string()),
        active_rules: policy_data.as_ref().map(|p| p.rules.len()).unwrap_or(0),
        violations: violation_count,
        declared_scope: session.declared_scope.clone(),
        containment: containment.to_string(),
    };

    // -- Data exfiltration --
    let pii_action = dlp.get_pii_action();
    let action_mode_str = match &pii_action {
        PiiAction::Block => "block",
        PiiAction::Redact => "redact",
    };

    // Count PII and secret events from session history
    let pii_count = events
        .iter()
        .filter(|e| e.kind == EventKind::DlpPii)
        .count();
    let secrets_count = events
        .iter()
        .filter(|e| {
            e.kind == EventKind::ProxyBlock
                && e.reason
                    .as_deref()
                    .map(|r| r.contains("API key") || r.contains("secret"))
                    .unwrap_or(false)
        })
        .count();

    let data_exfiltration = DataExfiltration {
        pii_detected: pii_count,
        secrets_detected: secrets_count,
        action_mode: action_mode_str.to_string(),
    };

    // -- Risk score --
    let risk_score = calculate_risk_score(&violations, pii_count, secrets_count, &pii_action);

    tracing::debug!(
        session_id,
        agent_type = %agent_type_str,
        risk_score,
        violations = violation_count,
        pii = pii_count,
        "Built agent identity"
    );

    AgentIdentity {
        session_id: session_id.clone(),
        agent,
        context,
        lineage,
        policy,
        risk_score,
        data_exfiltration,
    }
}

/// Build summary views for all active agent sessions.
pub async fn build_all_identities(
    session_store: &Arc<SessionStore>,
    observer: &Arc<ObserverEngine>,
    dlp: &Arc<DlpEngine>,
) -> Vec<AgentIdentitySummary> {
    let sessions = session_store.list_active();
    let mut summaries = Vec::with_capacity(sessions.len());

    for session in &sessions {
        let agent_type_str = session.agent_type.to_string();
        let violations = observer.session_violations(&session.id).await;
        let policy_data = observer.get_policy(&session.id).await;

        let events = session_store.get_events(&session.id);
        let pii_count = events
            .iter()
            .filter(|e| e.kind == EventKind::DlpPii)
            .count();
        let secrets_count = events
            .iter()
            .filter(|e| {
                e.kind == EventKind::ProxyBlock
                    && e.reason
                        .as_deref()
                        .map(|r| r.contains("API key") || r.contains("secret"))
                        .unwrap_or(false)
            })
            .count();

        let pii_action = dlp.get_pii_action();
        let risk_score = calculate_risk_score(&violations, pii_count, secrets_count, &pii_action);

        // Find model from latest LLM event
        let model = events
            .iter()
            .filter(|e| matches!(e.kind, EventKind::LlmRequest | EventKind::LlmResponse))
            .find_map(|e| e.llm_context.as_ref().and_then(|ctx| ctx.model.clone()));

        let state_str = serde_json::to_string(&session.state)
            .unwrap_or_default()
            .trim_matches('"')
            .to_string();

        summaries.push(AgentIdentitySummary {
            session_id: session.id.clone(),
            agent_type: agent_type_str.clone(),
            provider: agent_provider(&agent_type_str).to_string(),
            model,
            profile: policy_data
                .as_ref()
                .map(|p| p.profile_label.clone())
                .unwrap_or_else(|| "None".to_string()),
            risk_score,
            violations: violations.len(),
            pid: session.pids.first().copied(),
            started_at: session.start_time,
            state: state_str,
        });
    }

    summaries
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzer::observer::BaselineViolation;

    #[test]
    fn risk_score_zero_for_clean_session() {
        let score = calculate_risk_score(&[], 0, 0, &PiiAction::Block);
        assert_eq!(score, 0);
    }

    #[test]
    fn risk_score_adds_up() {
        let violations = vec![BaselineViolation {
            session_id: "s1".into(),
            event_id: "e1".into(),
            activity_class: ActivityClass::FileWrite,
            action_taken: "warned".into(),
            rule_description: "test".into(),
            process: "claude".into(),
            target: "/tmp/test".into(),
            pid: 1234,
            timestamp: Utc::now(),
        }];
        let score = calculate_risk_score(&violations, 0, 0, &PiiAction::Block);
        assert_eq!(score, 10); // 1 warned violation = +10
    }

    #[test]
    fn risk_score_credential_access_higher() {
        let violations = vec![BaselineViolation {
            session_id: "s1".into(),
            event_id: "e1".into(),
            activity_class: ActivityClass::CredentialAccess,
            action_taken: "blocked".into(),
            rule_description: "test".into(),
            process: "claude".into(),
            target: "/home/.ssh/id_rsa".into(),
            pid: 1234,
            timestamp: Utc::now(),
        }];
        let score = calculate_risk_score(&violations, 0, 0, &PiiAction::Block);
        assert_eq!(score, 20); // credential access = +20
    }

    #[test]
    fn risk_score_pii_in_block_mode() {
        let score = calculate_risk_score(&[], 3, 0, &PiiAction::Block);
        assert_eq!(score, 30); // PII in block mode = +30
    }

    #[test]
    fn risk_score_capped_at_100() {
        let violations: Vec<BaselineViolation> = (0..20)
            .map(|i| BaselineViolation {
                session_id: "s1".into(),
                event_id: format!("e{}", i),
                activity_class: ActivityClass::CredentialAccess,
                action_taken: "blocked".into(),
                rule_description: "test".into(),
                process: "claude".into(),
                target: "/home/.ssh/id_rsa".into(),
                pid: 1234,
                timestamp: Utc::now(),
            })
            .collect();
        let score = calculate_risk_score(&violations, 5, 2, &PiiAction::Block);
        assert_eq!(score, 100);
    }

    #[test]
    fn provider_mapping() {
        assert_eq!(agent_provider("claude"), "anthropic");
        assert_eq!(agent_provider("chatgpt"), "openai");
        assert_eq!(agent_provider("codex"), "openai");
        assert_eq!(agent_provider("copilot"), "github");
        assert_eq!(agent_provider("gemini"), "google");
        assert_eq!(agent_provider("cursor"), "cursor");
        assert_eq!(agent_provider("devin"), "cognition");
        assert_eq!(agent_provider("unknown-thing"), "unknown");
    }
}
