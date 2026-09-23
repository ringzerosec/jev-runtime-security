// SPDX-License-Identifier: Apache-2.0
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Raw security event emitted by the kernel driver → daemon.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityEvent {
    pub id: String,
    pub kind: EventKind,
    pub pid: u32,
    pub uid: u32,
    pub process: String,
    pub target: String,
    pub allowed: bool,
    pub reason: Option<String>,
    pub timestamp: DateTime<Utc>,
    /// Parent PID — populated from /proc or kernel fork events.
    /// Enables process tree reconstruction (agent → child chains).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ppid: Option<u32>,
    /// Parent process name — resolved from ppid for display.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_process: Option<String>,
    /// LLM context — what the model said before this action happened.
    /// Populated by SSE stream reassembly in the TLS proxy.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub llm_context: Option<LlmContext>,
    /// Free-form, event-type-specific detail (tool inputs for hook events,
    /// appended lines for transcript events, …). Merged into `args` in the
    /// webhook payload. Absent for plain kernel events.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub extra: Option<serde_json::Value>,
}

/// Context extracted from intercepted LLM API responses (SSE streams).
/// Links "what the model said" to "what the agent did."
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LlmContext {
    /// Provider: openai, anthropic, google, etc.
    pub provider: String,
    /// Model ID (e.g. "gpt-4o", "claude-sonnet-4-20250514")
    pub model: Option<String>,
    /// Truncated response text (last N chars before action)
    pub response_text: Option<String>,
    /// Tool/function call the model requested
    pub tool_call: Option<String>,
    /// Token usage from the response
    pub usage: Option<TokenUsage>,
    /// Timestamp of the LLM response
    pub response_ts: DateTime<Utc>,
}

/// Token usage extracted from LLM API responses.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenUsage {
    pub input_tokens: Option<u64>,
    pub output_tokens: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EventKind {
    FileOpen,
    FileCreate,
    FileDelete,
    FileRename,
    FileWrite,
    ProcessExec,
    ProcessFork,
    ProcessExit,
    NetworkConnect,
    NetworkSend,
    NetworkRecv,
    DnsQuery,
    McpToolCall,
    // -- LLM / proxy events (AgentSight-inspired) --
    /// LLM API request intercepted by TLS proxy
    LlmRequest,
    /// LLM API response (or SSE stream) reassembled by TLS proxy
    LlmResponse,
    /// Tool/function call extracted from LLM response
    LlmToolCall,
    /// TLS proxy blocked a request (DLP, injection, etc.)
    ProxyBlock,
    /// TLS proxy detected something noteworthy but allowed it
    ProxyDetection,
    /// PII detected and redacted in outbound traffic
    DlpPii,
    /// Tamper protection: external process attempted to ptrace contained agent
    TamperPtrace,
    /// Tamper protection: external process attempted to signal contained agent
    TamperSignal,
    /// Tamper protection: contained process attempted mount (escape attempt)
    TamperMount,
    /// Tamper protection: contained process attempted umount
    TamperUmount,
    /// Contained process tried to exec unauthorized binary
    ContainedExecBlocked,
    /// Contained process tried to access credential file
    ContainedFileBlocked,
    /// Offensive code generation detected in LLM prompt
    OffensivePrompt,
    /// Prompt injection / jailbreak detected in LLM request
    PromptInjection,
    /// Write→Execute memory transition (mprotect W→X)
    MprotectWx,
    /// Attack chain correlation: LLM→file→exec sequence detected
    AttackChain,
    /// Skill file changed — SkillSpector pattern scan detected a threat
    SkillFileChange,
    /// New git repo detected in a skill directory
    SkillGitRepoDrop,
    /// Lines appended to an agent's transcript/session file (opt-in watcher)
    TranscriptWrite,

    // ── Terminal capture ───────────────────────────────────────────────────
    //
    // Text an agent read from or wrote to its terminal, captured below the
    // agent by the kernel. These were emitted as LlmRequest / LlmResponse,
    // which was simply wrong: stdout is not an API exchange with a model, and
    // anyone reading the stream had no way to tell the two apart. The old
    // kinds are still ACCEPTED when deserialising a persisted event, for one
    // release, so a timeline written before this change still loads.
    /// Text the agent wrote to its terminal (fd 1 or 2).
    #[serde(alias = "llm_response")]
    AgentStdout,
    /// Text the agent read from its terminal (fd 0).
    #[serde(alias = "llm_request")]
    AgentStdin,
}

impl SecurityEvent {
    /// Construct a proxy-originated event (pid=0, uid=0, process="proxy:{peer}").
    /// Reduces boilerplate in proxy/server.rs and ssl_sniff.rs.
    pub fn proxy_event(
        kind: EventKind,
        peer: &std::net::SocketAddr,
        sni: &str,
        allowed: bool,
        reason: Option<String>,
        llm_context: Option<LlmContext>,
    ) -> Self {
        SecurityEvent {
            id: format!(
                "proxy-{}-{}",
                match kind {
                    EventKind::ProxyBlock => "block",
                    EventKind::ProxyDetection => "detect",
                    EventKind::LlmRequest => "req",
                    EventKind::LlmResponse => "resp",
                    EventKind::LlmToolCall => "tool",
                    _ => "evt",
                },
                chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0)
            ),
            kind,
            pid: 0,
            uid: 0,
            process: format!("proxy:{}", peer),
            target: sni.to_string(),
            allowed,
            reason,
            timestamp: chrono::Utc::now(),
            ppid: None,
            parent_process: None,
            llm_context,
            extra: None,
        }
    }
}
