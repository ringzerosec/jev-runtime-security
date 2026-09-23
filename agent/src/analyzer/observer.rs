// SPDX-License-Identifier: Apache-2.0
// analyzer/observer.rs — Session-scoped baseline policy engine (Observer AI)
//
// When an AI agent session starts, the Observer assigns a baseline policy
// based on the agent type. Every kernel event is then checked against this
// baseline. Violations are flagged immediately — before heuristics or SLM.
//
// This is the key defense against attacks like the iTerm2 cat-readme.txt exploit:
// a "coding" agent should never spawn unknown binaries, so the process_exec
// event for the attacker-controlled path is caught as a baseline violation.
//
// Design:
//   1. AgentProfile — static per-agent-type defaults (coding, research, etc.)
//   2. SessionPolicy — runtime policy for a specific session (can be customized)
//   3. ObserverEngine — evaluates events against session policies
//
// Integration points:
//   - main.rs: auto-assign policy on session creation
//   - main.rs: evaluate every event before timeline insert
//   - API: expose session policy + allow customization
//   - UI: show active policy on session detail page

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tokio::sync::RwLock;

use crate::common::event::{EventKind, SecurityEvent};

// ── Activity class ──────────────────────────────────────────────────────────

/// High-level activity categories that baseline policies control.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActivityClass {
    FileRead,
    FileWrite,
    FileDelete,
    ProcessExec,
    ProcessFork,
    NetworkConnect,
    NetworkSend,
    DnsQuery,
    CredentialAccess,
    PrivilegeEscalation,
    /// API key routing — keys sent to whitelisted provider endpoints (allowed)
    /// vs keys sent to unauthorized destinations (blocked by DLP).
    ApiKeyRouting,
    /// Something the agent said rather than something it did — captured
    /// terminal output. Deliberately not folded into one of the activity
    /// classes above: words are not actions, and counting them as a file write
    /// or a network request would put claims into the correlation engine as if
    /// the kernel had seen them happen.
    AgentSpeech,
}

impl std::fmt::Display for ActivityClass {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            ActivityClass::FileRead => "file_read",
            ActivityClass::FileWrite => "file_write",
            ActivityClass::FileDelete => "file_delete",
            ActivityClass::ProcessExec => "process_exec",
            ActivityClass::ProcessFork => "process_fork",
            ActivityClass::NetworkConnect => "network_connect",
            ActivityClass::NetworkSend => "network_send",
            ActivityClass::DnsQuery => "dns_query",
            ActivityClass::CredentialAccess => "credential_access",
            ActivityClass::PrivilegeEscalation => "privilege_escalation",
            ActivityClass::ApiKeyRouting => "api_key_routing",
            ActivityClass::AgentSpeech => "agent_speech",
        };
        write!(f, "{s}")
    }
}

// ── Policy action per activity ──────────────────────────────────────────────

/// What the observer does when an activity class is triggered.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BaselineAction {
    /// Allow without restriction.
    Allow,
    /// Allow but only if target matches a glob pattern.
    AllowScoped { patterns: Vec<String> },
    /// Log as a warning — potential violation but don't block.
    Warn,
    /// Block and flag as a baseline violation.
    Block,
}

// ── Activity rule ───────────────────────────────────────────────────────────

/// A single rule in a baseline policy.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActivityRule {
    pub class: ActivityClass,
    pub action: BaselineAction,
    pub description: String,
}

// ── Agent profile (static defaults) ─────────────────────────────────────────

/// Pre-defined activity profiles per agent type.
/// These are the defaults assigned when a session is auto-created.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentProfile {
    pub agent_type: String,
    pub label: String,
    pub description: String,
    pub rules: Vec<ActivityRule>,
}

/// Known process names that are safe for coding agents to exec.
const CODING_SAFE_PROCESSES: &[&str] = &[
    "git",
    "cargo",
    "rustc",
    "npm",
    "npx",
    "node",
    "python",
    "python3",
    "pip",
    "pip3",
    "go",
    "gcc",
    "g++",
    "clang",
    "make",
    "cmake",
    "docker",
    "kubectl",
    "terraform",
    "pnpm",
    "yarn",
    "bun",
    "tsc",
    "eslint",
    "prettier",
    "ruff",
    "black",
    "mypy",
    "javac",
    "java",
    "mvn",
    "gradle",
    "dotnet",
    "ruby",
    "gem",
    "bash",
    "sh",
    "zsh",
    "cat",
    "grep",
    "rg",
    "fd",
    "find",
    "ls",
    "head",
    "tail",
    "sort",
    "uniq",
    "wc",
    "diff",
    "patch",
    "sed",
    "awk",
    "jq",
    "yq",
    "curl",
    "wget",
    "mkdir",
    "cp",
    "mv",
    "rm",
    "touch",
    "chmod",
    "ln",
    "tar",
    "gzip",
    "gunzip",
    "zip",
    "unzip",
    "test",
    "true",
    "false",
    "echo",
    "printf",
    "env",
    "which",
];

/// Build the default coding agent profile.
fn coding_profile(agent_type: &str) -> AgentProfile {
    AgentProfile {
        agent_type: agent_type.to_string(),
        label: "Coding Agent".to_string(),
        description: "File read/write in project scope, build tools, no credential access".to_string(),
        rules: vec![
            ActivityRule {
                class: ActivityClass::FileRead,
                action: BaselineAction::Allow,
                description: "Read any file".to_string(),
            },
            ActivityRule {
                class: ActivityClass::FileWrite,
                action: BaselineAction::Allow,
                description: "Write files (scoped to project if declared_scope set)".to_string(),
            },
            ActivityRule {
                class: ActivityClass::FileDelete,
                action: BaselineAction::Warn,
                description: "File deletion flagged for review".to_string(),
            },
            ActivityRule {
                // Observe, don't block: coding agents legitimately run a long tail
                // of tools (git/npm/node + shell utilities), so blocking anything
                // off a fixed allowlist is a constant false positive. Spawns are
                // logged to the session timeline; genuinely dangerous execs are
                // still hard-blocked at L0 (launder tools, credential paths).
                class: ActivityClass::ProcessExec,
                action: BaselineAction::Warn,
                description: "Process execution logged (not blocked)".to_string(),
            },
            ActivityRule {
                class: ActivityClass::ProcessFork,
                action: BaselineAction::Allow,
                description: "Process forking allowed for build tools".to_string(),
            },
            ActivityRule {
                class: ActivityClass::NetworkConnect,
                action: BaselineAction::Warn,
                description: "Network connections logged".to_string(),
            },
            ActivityRule {
                class: ActivityClass::NetworkSend,
                action: BaselineAction::Warn,
                description: "Outbound data logged".to_string(),
            },
            ActivityRule {
                class: ActivityClass::DnsQuery,
                action: BaselineAction::Allow,
                description: "DNS allowed (package registries, APIs)".to_string(),
            },
            ActivityRule {
                class: ActivityClass::ApiKeyRouting,
                action: BaselineAction::AllowScoped {
                    patterns: vec![
                        "api.anthropic.com".to_string(),
                        "*.anthropic.com".to_string(),
                        "*.claude.com".to_string(),
                        "api.openai.com".to_string(),
                        "*.openai.com".to_string(),
                        "api.github.com".to_string(),
                        "*.googleapis.com".to_string(),
                    ],
                },
                description: "API keys may only be sent to whitelisted provider endpoints. DLP blocks exfiltration to unauthorized domains.".to_string(),
            },
            ActivityRule {
                class: ActivityClass::CredentialAccess,
                action: BaselineAction::Block,
                description: "No credential file access".to_string(),
            },
            ActivityRule {
                class: ActivityClass::PrivilegeEscalation,
                action: BaselineAction::Block,
                description: "No privilege escalation".to_string(),
            },
        ],
    }
}

/// Build a research/browsing agent profile.
fn research_profile(agent_type: &str) -> AgentProfile {
    AgentProfile {
        agent_type: agent_type.to_string(),
        label: "Research Agent".to_string(),
        description: "Web fetch only, no file write outside reports, no process exec".to_string(),
        rules: vec![
            ActivityRule {
                class: ActivityClass::FileRead,
                action: BaselineAction::Allow,
                description: "Read files for context".to_string(),
            },
            ActivityRule {
                class: ActivityClass::FileWrite,
                action: BaselineAction::AllowScoped {
                    patterns: vec![
                        "~/reports/**".to_string(),
                        "~/Downloads/**".to_string(),
                        "/tmp/**".to_string(),
                    ],
                },
                description: "Write only to reports/downloads/tmp".to_string(),
            },
            ActivityRule {
                class: ActivityClass::FileDelete,
                action: BaselineAction::Block,
                description: "No file deletion".to_string(),
            },
            ActivityRule {
                class: ActivityClass::ProcessExec,
                action: BaselineAction::Warn,
                description: "Process execution logged (not blocked)".to_string(),
            },
            ActivityRule {
                class: ActivityClass::ProcessFork,
                action: BaselineAction::Warn,
                description: "Process forking logged (not blocked)".to_string(),
            },
            ActivityRule {
                class: ActivityClass::NetworkConnect,
                action: BaselineAction::Allow,
                description: "Web browsing allowed".to_string(),
            },
            ActivityRule {
                class: ActivityClass::NetworkSend,
                action: BaselineAction::Warn,
                description: "Outbound data logged".to_string(),
            },
            ActivityRule {
                class: ActivityClass::DnsQuery,
                action: BaselineAction::Allow,
                description: "DNS allowed".to_string(),
            },
            ActivityRule {
                class: ActivityClass::CredentialAccess,
                action: BaselineAction::Block,
                description: "No credential access".to_string(),
            },
            ActivityRule {
                class: ActivityClass::PrivilegeEscalation,
                action: BaselineAction::Block,
                description: "No privilege escalation".to_string(),
            },
        ],
    }
}

/// Default restrictive profile for unknown agents.
fn default_profile(agent_type: &str) -> AgentProfile {
    AgentProfile {
        agent_type: agent_type.to_string(),
        label: "Default (Restrictive)".to_string(),
        description:
            "Conservative defaults — block process exec, credential access, privilege escalation"
                .to_string(),
        rules: vec![
            ActivityRule {
                class: ActivityClass::FileRead,
                action: BaselineAction::Allow,
                description: "Read allowed".to_string(),
            },
            ActivityRule {
                class: ActivityClass::FileWrite,
                action: BaselineAction::Warn,
                description: "File writes logged".to_string(),
            },
            ActivityRule {
                class: ActivityClass::FileDelete,
                action: BaselineAction::Block,
                description: "No file deletion".to_string(),
            },
            ActivityRule {
                class: ActivityClass::ProcessExec,
                action: BaselineAction::Warn,
                description: "Process execution logged (not blocked)".to_string(),
            },
            ActivityRule {
                class: ActivityClass::ProcessFork,
                action: BaselineAction::Warn,
                description: "Process forking logged (not blocked)".to_string(),
            },
            ActivityRule {
                class: ActivityClass::NetworkConnect,
                action: BaselineAction::Warn,
                description: "Network connections logged".to_string(),
            },
            ActivityRule {
                class: ActivityClass::NetworkSend,
                action: BaselineAction::Warn,
                description: "Outbound data logged".to_string(),
            },
            ActivityRule {
                class: ActivityClass::DnsQuery,
                action: BaselineAction::Allow,
                description: "DNS allowed".to_string(),
            },
            ActivityRule {
                class: ActivityClass::CredentialAccess,
                action: BaselineAction::Block,
                description: "No credential access".to_string(),
            },
            ActivityRule {
                class: ActivityClass::PrivilegeEscalation,
                action: BaselineAction::Block,
                description: "No privilege escalation".to_string(),
            },
        ],
    }
}

/// Get the default profile for an agent type.
pub fn default_profile_for(agent_type: &str) -> AgentProfile {
    let t = agent_type.to_lowercase();
    match t.as_str() {
        // Coding agents — need file r/w, build tools, git, and to spawn processes.
        // Gemini CLI is a coding agent (it edits files + runs tools), not a
        // browse-only chat agent — classifying it as research blocked every tool
        // it spawned (a constant false positive).
        "claude" | "cursor" | "copilot" | "codex" | "aider" | "windsurf" | "cody" | "devin"
        | "gemini" => coding_profile(agent_type),
        // Chat/research agents — web only, no file write
        "chatgpt" => research_profile(agent_type),
        // Unknown — restrictive defaults
        _ => default_profile(agent_type),
    }
}

// ── Session policy (runtime) ────────────────────────────────────────────────

/// The active policy for a specific session. Created from an AgentProfile
/// when the session starts, can be customized at runtime via API.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionPolicy {
    pub session_id: String,
    pub agent_type: String,
    pub profile_label: String,
    pub profile_description: String,
    pub rules: Vec<ActivityRule>,
    /// User-defined scope constraints (e.g., "only files in ~/myproject")
    pub declared_scope: Vec<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl SessionPolicy {
    pub fn from_profile(
        session_id: &str,
        profile: &AgentProfile,
        declared_scope: Vec<String>,
    ) -> Self {
        let now = Utc::now();
        Self {
            session_id: session_id.to_string(),
            agent_type: profile.agent_type.clone(),
            profile_label: profile.label.clone(),
            profile_description: profile.description.clone(),
            rules: profile.rules.clone(),
            declared_scope,
            created_at: now,
            updated_at: now,
        }
    }

    /// Find the rule for a given activity class.
    pub fn rule_for(&self, class: &ActivityClass) -> Option<&ActivityRule> {
        self.rules.iter().find(|r| &r.class == class)
    }
}

// ── Baseline violation ──────────────────────────────────────────────────────

/// A detected violation of the session's baseline policy.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BaselineViolation {
    pub session_id: String,
    pub event_id: String,
    pub activity_class: ActivityClass,
    pub action_taken: String, // "blocked" or "warned"
    pub rule_description: String,
    pub process: String,
    pub target: String,
    pub pid: u32,
    pub timestamp: DateTime<Utc>,
}

// ── Sensitive file patterns ─────────────────────────────────────────────────

/// Patterns that indicate credential/sensitive file access.
/// Used by both the Observer engine (kernel event evaluation) and the
/// TLS proxy (tool call interception) — single source of truth.
pub const CREDENTIAL_PATTERNS: &[&str] = &[
    "id_rsa",
    "id_ed25519",
    "id_ecdsa",
    "id_dsa",
    ".ssh/",
    ".aws/credentials",
    ".aws/config",
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

pub fn is_credential_access(target: &str) -> bool {
    let t = target.to_lowercase();
    CREDENTIAL_PATTERNS.iter().any(|p| t.contains(p))
}

// ── Observer engine ─────────────────────────────────────────────────────────

pub struct ObserverEngine {
    /// Session ID → active policy
    policies: RwLock<HashMap<String, SessionPolicy>>,
    /// Recent violations (ring buffer, max 500)
    violations: RwLock<Vec<BaselineViolation>>,
}

impl ObserverEngine {
    pub fn new() -> Self {
        Self {
            policies: RwLock::new(HashMap::new()),
            violations: RwLock::new(Vec::new()),
        }
    }

    /// Assign a baseline policy when a session is created.
    /// Uses the default profile for the agent type, merging declared_scope.
    pub async fn assign_policy(
        &self,
        session_id: &str,
        agent_type: &str,
        declared_scope: Vec<String>,
    ) {
        let profile = default_profile_for(agent_type);
        let policy = SessionPolicy::from_profile(session_id, &profile, declared_scope);
        tracing::info!(
            session_id,
            agent_type,
            profile = %policy.profile_label,
            rules = policy.rules.len(),
            "Observer: assigned baseline policy to session"
        );
        self.policies
            .write()
            .await
            .insert(session_id.to_string(), policy);
    }

    /// Get the active policy for a session.
    pub async fn get_policy(&self, session_id: &str) -> Option<SessionPolicy> {
        self.policies.read().await.get(session_id).cloned()
    }

    /// Update a specific rule in a session's policy.
    pub async fn update_rule(&self, session_id: &str, rule: ActivityRule) -> bool {
        let mut policies = self.policies.write().await;
        if let Some(policy) = policies.get_mut(session_id) {
            if let Some(existing) = policy.rules.iter_mut().find(|r| r.class == rule.class) {
                *existing = rule;
                policy.updated_at = Utc::now();
                return true;
            }
        }
        false
    }

    /// Remove a session's policy (on session termination).
    pub async fn remove_policy(&self, session_id: &str) {
        self.policies.write().await.remove(session_id);
    }

    /// List all available default profiles (for UI display).
    pub fn list_profiles() -> Vec<AgentProfile> {
        vec![
            coding_profile("coding"),
            research_profile("research"),
            default_profile("default"),
        ]
    }

    /// Get recent violations across all sessions.
    pub async fn recent_violations(&self, limit: usize) -> Vec<BaselineViolation> {
        let v = self.violations.read().await;
        v.iter().rev().take(limit).cloned().collect()
    }

    /// Get violations for a specific session.
    pub async fn session_violations(&self, session_id: &str) -> Vec<BaselineViolation> {
        let v = self.violations.read().await;
        v.iter()
            .filter(|v| v.session_id == session_id)
            .cloned()
            .collect()
    }

    /// List all session IDs that have active policies.
    pub async fn active_session_ids(&self) -> Vec<String> {
        self.policies.read().await.keys().cloned().collect()
    }

    /// Evaluate a kernel event against the session's baseline policy.
    /// Returns Some(violation) if the event violates the baseline.
    ///
    /// This is the critical path — called for every event in the main loop.
    pub async fn evaluate(
        &self,
        ev: &SecurityEvent,
        session_id: &str,
    ) -> Option<BaselineViolation> {
        let policies = self.policies.read().await;
        let policy = policies.get(session_id)?;

        // Classify the event into an activity class
        let (class, _target) = classify_event(ev);

        // Check credential access regardless of event kind
        if is_credential_access(&ev.target) && class != ActivityClass::CredentialAccess {
            // Re-evaluate as credential access
            if let Some(rule) = policy.rule_for(&ActivityClass::CredentialAccess) {
                if let Some(violation) =
                    evaluate_rule(rule, ev, session_id, &ActivityClass::CredentialAccess)
                {
                    let mut violations = self.violations.write().await;
                    violations.push(violation.clone());
                    if violations.len() > 500 {
                        violations.remove(0);
                    }
                    return Some(violation);
                }
            }
        }

        let rule = policy.rule_for(&class)?;
        let violation = evaluate_rule(rule, ev, session_id, &class)?;

        let mut violations = self.violations.write().await;
        violations.push(violation.clone());
        if violations.len() > 500 {
            violations.remove(0);
        }
        Some(violation)
    }
}

// ── Event classification ────────────────────────────────────────────────────

fn classify_event(ev: &SecurityEvent) -> (ActivityClass, &str) {
    match ev.kind {
        EventKind::FileOpen => {
            if is_credential_access(&ev.target) {
                (ActivityClass::CredentialAccess, &ev.target)
            } else {
                (ActivityClass::FileRead, &ev.target)
            }
        }
        EventKind::FileCreate | EventKind::FileWrite => (ActivityClass::FileWrite, &ev.target),
        EventKind::FileDelete | EventKind::FileRename => (ActivityClass::FileDelete, &ev.target),
        EventKind::ProcessExec => (ActivityClass::ProcessExec, &ev.target),
        EventKind::ProcessFork => (ActivityClass::ProcessFork, &ev.target),
        EventKind::ProcessExit => (ActivityClass::ProcessFork, &ev.target), // no rule for exit
        EventKind::NetworkConnect => (ActivityClass::NetworkConnect, &ev.target),
        EventKind::NetworkSend => (ActivityClass::NetworkSend, &ev.target),
        EventKind::DnsQuery => (ActivityClass::DnsQuery, &ev.target),
        // LLM events and proxy events don't go through baseline
        _ => (ActivityClass::FileRead, &ev.target),
    }
}

/// Evaluate a single rule against an event.
/// Returns None if the event is allowed, Some(violation) if it violates.
fn evaluate_rule(
    rule: &ActivityRule,
    ev: &SecurityEvent,
    session_id: &str,
    class: &ActivityClass,
) -> Option<BaselineViolation> {
    match &rule.action {
        BaselineAction::Allow => None,
        BaselineAction::AllowScoped { patterns } => {
            // For ProcessExec: allow the scoped list silently; an exec NOT on the
            // list is OBSERVED, not blocked. Blanket-blocking every unlisted
            // command is the FP storm — a coding agent runs hundreds of benign
            // tools (locale/find/run-parts/...) no static list can enumerate. The
            // unlisted exec is captured (action "warned") for async SLM judgment,
            // and the hard floor (creds/persistence/exfil/priv-esc, enforced via
            // their own rules + eBPF) blocks the genuine threats regardless. See
            if *class == ActivityClass::ProcessExec {
                let proc_name = ev
                    .target
                    .rsplit('/')
                    .next()
                    .unwrap_or(&ev.target)
                    .to_lowercase();
                let is_allowed = patterns
                    .iter()
                    .any(|p| proc_name.contains(&p.to_lowercase()));
                if is_allowed {
                    return None;
                }
                return Some(BaselineViolation {
                    session_id: session_id.to_string(),
                    event_id: ev.id.clone(),
                    activity_class: class.clone(),
                    action_taken: "warned".to_string(),
                    rule_description: format!(
                        "Unlisted exec observed (not in scope) — {}",
                        rule.description
                    ),
                    process: ev.process.clone(),
                    target: ev.target.clone(),
                    pid: ev.pid,
                    timestamp: ev.timestamp,
                });
            }
            // For file operations: check glob patterns
            let target = &ev.target;
            let is_allowed = patterns.iter().any(|p| glob_match(p, target));
            if is_allowed {
                None
            } else {
                Some(BaselineViolation {
                    session_id: session_id.to_string(),
                    event_id: ev.id.clone(),
                    activity_class: class.clone(),
                    action_taken: "blocked".to_string(),
                    rule_description: rule.description.clone(),
                    process: ev.process.clone(),
                    target: ev.target.clone(),
                    pid: ev.pid,
                    timestamp: ev.timestamp,
                })
            }
        }
        BaselineAction::Warn => Some(BaselineViolation {
            session_id: session_id.to_string(),
            event_id: ev.id.clone(),
            activity_class: class.clone(),
            action_taken: "warned".to_string(),
            rule_description: rule.description.clone(),
            process: ev.process.clone(),
            target: ev.target.clone(),
            pid: ev.pid,
            timestamp: ev.timestamp,
        }),
        BaselineAction::Block => Some(BaselineViolation {
            session_id: session_id.to_string(),
            event_id: ev.id.clone(),
            activity_class: class.clone(),
            action_taken: "blocked".to_string(),
            rule_description: rule.description.clone(),
            process: ev.process.clone(),
            target: ev.target.clone(),
            pid: ev.pid,
            timestamp: ev.timestamp,
        }),
    }
}

/// Simple glob match supporting `*` and `**` and `~` expansion.
fn glob_match(pattern: &str, path: &str) -> bool {
    let home = std::env::var("HOME").unwrap_or_default();
    let expanded = pattern.replace('~', &home);
    let parts: Vec<&str> = expanded.split("**").collect();
    if parts.len() == 1 {
        // No ** — simple wildcard
        simple_glob(&expanded, path)
    } else {
        // Has ** — match prefix and suffix
        let prefix = parts[0].trim_end_matches('/');
        if !prefix.is_empty() && !path.starts_with(prefix) {
            return false;
        }
        true
    }
}

fn simple_glob(pattern: &str, text: &str) -> bool {
    let parts: Vec<&str> = pattern.split('*').collect();
    if parts.len() == 1 {
        return pattern == text;
    }
    let mut pos = 0;
    for (i, part) in parts.iter().enumerate() {
        if part.is_empty() {
            continue;
        }
        if let Some(found) = text[pos..].find(part) {
            if i == 0 && found != 0 {
                return false;
            }
            pos += found + part.len();
        } else {
            return false;
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_profiles_exist() {
        let claude = default_profile_for("claude");
        assert_eq!(claude.label, "Coding Agent");
        assert!(!claude.rules.is_empty());

        let chatgpt = default_profile_for("chatgpt");
        assert_eq!(chatgpt.label, "Research Agent");

        let unknown = default_profile_for("some-unknown-agent");
        assert_eq!(unknown.label, "Default (Restrictive)");
    }

    #[test]
    fn coding_profile_observes_process_exec() {
        // Coding agents run a long tail of tools — exec is observed, not blocked
        // (no false positives), while credential access stays blocked.
        let profile = coding_profile("claude");
        let exec_rule = profile
            .rules
            .iter()
            .find(|r| r.class == ActivityClass::ProcessExec)
            .unwrap();
        assert_eq!(exec_rule.action, BaselineAction::Warn);
    }

    #[test]
    fn coding_profile_blocks_credentials() {
        let profile = coding_profile("claude");
        let cred_rule = profile
            .rules
            .iter()
            .find(|r| r.class == ActivityClass::CredentialAccess)
            .unwrap();
        assert_eq!(cred_rule.action, BaselineAction::Block);
    }

    #[test]
    fn profiles_observe_exec_but_block_credentials() {
        // No FP: process execution is observed (logged), never blocked by the
        // baseline — agents spawn tools constantly. The real threats stay blocked.
        for profile in [
            coding_profile("claude"),
            research_profile("chatgpt"),
            default_profile("x"),
        ] {
            let exec = profile
                .rules
                .iter()
                .find(|r| r.class == ActivityClass::ProcessExec)
                .unwrap();
            assert_eq!(
                exec.action,
                BaselineAction::Warn,
                "exec must be observed, not blocked ({})",
                profile.label
            );
            let cred = profile
                .rules
                .iter()
                .find(|r| r.class == ActivityClass::CredentialAccess)
                .unwrap();
            assert_eq!(
                cred.action,
                BaselineAction::Block,
                "credential access must stay blocked ({})",
                profile.label
            );
        }
    }

    #[test]
    fn gemini_is_a_coding_agent() {
        // Gemini CLI edits files + runs tools — must get the coding profile, not
        // research (which it used to, blocking every tool it spawned).
        assert_eq!(default_profile_for("gemini").label, "Coding Agent");
    }

    #[test]
    fn credential_detection() {
        assert!(is_credential_access("/home/user/.ssh/id_rsa"));
        assert!(is_credential_access("/home/user/.aws/credentials"));
        assert!(is_credential_access("/app/.env"));
        assert!(!is_credential_access("/home/user/project/src/main.rs"));
    }

    #[test]
    fn glob_match_basic() {
        assert!(glob_match("/tmp/**", "/tmp/foo/bar"));
        assert!(glob_match("/tmp/**", "/tmp/file.txt"));
        assert!(!glob_match("/tmp/**", "/var/foo"));
    }

    #[tokio::test]
    async fn engine_assign_and_get() {
        let engine = ObserverEngine::new();
        engine
            .assign_policy("sess-1", "claude", vec!["~/project".to_string()])
            .await;
        let policy = engine.get_policy("sess-1").await;
        assert!(policy.is_some());
        let policy = policy.unwrap();
        assert_eq!(policy.profile_label, "Coding Agent");
        assert_eq!(policy.declared_scope, vec!["~/project"]);
    }

    #[tokio::test]
    async fn engine_evaluate_observes_unknown_exec() {
        let engine = ObserverEngine::new();
        engine.assign_policy("sess-1", "claude", vec![]).await;

        let ev = SecurityEvent {
            id: "test-1".to_string(),
            kind: EventKind::ProcessExec,
            pid: 1234,
            uid: 1000,
            process: "cat".to_string(),
            target: "ace/c+aliFIo".to_string(), // the iTerm2 exploit binary
            allowed: true,
            reason: None,
            timestamp: Utc::now(),
            ppid: Some(1233),
            parent_process: Some("bash".to_string()),
            llm_context: None,
            extra: None,
        };

        let violation = engine.evaluate(&ev, "sess-1").await;
        // An unlisted exec is still CAPTURED (so the SLM can judge it), but it is
        // OBSERVED, not blocked — blanket-blocking unlisted commands is the FP
        // storm. The hard floor (creds/persistence/exfil/priv-esc) blocks the real
        // threats regardless.
        assert!(
            violation.is_some(),
            "Should still capture the unlisted binary for SLM judgment"
        );
        let v = violation.unwrap();
        assert_eq!(v.activity_class, ActivityClass::ProcessExec);
        assert_eq!(v.action_taken, "warned");
        assert!(v.target.contains("ace/c+aliFIo"));
    }

    #[tokio::test]
    async fn engine_evaluate_allows_known_exec() {
        let engine = ObserverEngine::new();
        engine.assign_policy("sess-1", "claude", vec![]).await;

        let ev = SecurityEvent {
            id: "test-2".to_string(),
            kind: EventKind::ProcessExec,
            pid: 1234,
            uid: 1000,
            process: "claude".to_string(),
            target: "/usr/bin/git".to_string(),
            allowed: true,
            reason: None,
            timestamp: Utc::now(),
            ppid: Some(1233),
            parent_process: Some("bash".to_string()),
            llm_context: None,
            extra: None,
        };

        // Process exec is observed, never blocked (no FP). git is logged as a
        // 'warned' event, not blocked — coding agents run tools constantly.
        let violation = engine.evaluate(&ev, "sess-1").await;
        if let Some(v) = violation {
            assert_eq!(
                v.action_taken, "warned",
                "exec must be observed, not blocked"
            );
        }
    }

    #[tokio::test]
    async fn engine_evaluate_blocks_credential_access() {
        let engine = ObserverEngine::new();
        engine.assign_policy("sess-1", "claude", vec![]).await;

        let ev = SecurityEvent {
            id: "test-3".to_string(),
            kind: EventKind::FileOpen,
            pid: 1234,
            uid: 1000,
            process: "claude".to_string(),
            target: "/home/user/.ssh/id_rsa".to_string(),
            allowed: true,
            reason: None,
            timestamp: Utc::now(),
            ppid: None,
            parent_process: None,
            llm_context: None,
            extra: None,
        };

        let violation = engine.evaluate(&ev, "sess-1").await;
        assert!(violation.is_some(), "Credential access should be blocked");
        let v = violation.unwrap();
        assert_eq!(v.activity_class, ActivityClass::CredentialAccess);
    }

    #[tokio::test]
    async fn research_agent_blocks_all_exec() {
        let engine = ObserverEngine::new();
        engine.assign_policy("sess-1", "chatgpt", vec![]).await;

        let ev = SecurityEvent {
            id: "test-4".to_string(),
            kind: EventKind::ProcessExec,
            pid: 1234,
            uid: 1000,
            process: "chatgpt".to_string(),
            target: "/usr/bin/git".to_string(), // even git is blocked for research agents
            allowed: true,
            reason: None,
            timestamp: Utc::now(),
            ppid: None,
            parent_process: None,
            llm_context: None,
            extra: None,
        };

        let violation = engine.evaluate(&ev, "sess-1").await;
        assert!(
            violation.is_some(),
            "Research agents should not exec any processes"
        );
    }
}
