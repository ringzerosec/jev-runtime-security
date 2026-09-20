// SPDX-License-Identifier: Apache-2.0
// integrations/webhook.rs — detection webhooks.
//
// Two extension points let third-party detection systems (including ML
// backends) plug into the daemon without loading anything into the kernel:
//
//   * Event stream (async). Every agent event the daemon attributes to an AI
//     agent session — process exec, file access, network activity, plus the
//     daemon's own threat detections — is POSTed as JSON to each configured
//     endpoint. Delivery is best-effort through a bounded local queue and never
//     blocks the event pipeline. Payloads are HMAC-SHA256 signed when the
//     endpoint has a shared secret, and pass through the redaction config first.
//
//   * Verdict hooks (sync, opt-in per event type). For the configured kernel
//     event types the daemon calls the endpoint and waits (default 250 ms) for
//     an allow/deny verdict before releasing the event. Every hook must state
//     `fail_mode = "open"` or `"closed"`; a config without it refuses to load.
//
// Enforcement stays in the kernel component and the daemon: a deny verdict
// terminates the offending process and installs a kernel block rule for the
// target, it never hands control to the receiver. See docs/integrations.md.

use std::collections::HashSet;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{bail, Context, Result};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::Sha256;
use tokio::sync::mpsc;

use crate::common::event::{EventKind, SecurityEvent};
use crate::session::store::SessionStore;

/// Version of the JSON payload schema. Bumped only for incompatible changes;
/// additive fields keep the same version.
pub const SCHEMA_VERSION: u32 = 1;

/// Largest verdict response body we will read (bytes). Anything larger is
/// treated as a malformed response.
const MAX_VERDICT_BODY: usize = 64 * 1024;

/// Consecutive failures after which a verdict hook's circuit opens, and for
/// how long it stays open (the fail mode applies immediately meanwhile).
const BREAKER_THRESHOLD: u32 = 5;
const BREAKER_OPEN_SECS: u64 = 10;

/// Event types the sync verdict hooks may subscribe to (kernel-observed
/// events only — LLM/proxy events are async-stream only).
const VERDICT_EVENT_TYPES: &[&str] = &[
    "file_open",
    "file_create",
    "file_delete",
    "file_rename",
    "file_write",
    "process_exec",
    "process_fork",
    "process_exit",
    "network_connect",
    "network_send",
    "dns_query",
    "mprotect_wx",
];

/// Every event type the async stream can emit (`"*"` = all).
const STREAM_EVENT_TYPES: &[&str] = &[
    "file_open",
    "file_create",
    "file_delete",
    "file_rename",
    "file_write",
    "process_exec",
    "process_fork",
    "process_exit",
    "network_connect",
    "network_send",
    "network_recv",
    "dns_query",
    "mcp_tool_call",
    "llm_request",
    "llm_response",
    "llm_tool_call",
    "proxy_block",
    "proxy_detection",
    "dlp_pii",
    "tamper_ptrace",
    "tamper_signal",
    "tamper_mount",
    "tamper_umount",
    "contained_exec_blocked",
    "contained_file_blocked",
    "offensive_prompt",
    "prompt_injection",
    "mprotect_wx",
    "attack_chain",
    "skill_file_change",
    "skill_git_repo_drop",
    "transcript_write",
    "threat",
];

// ── Config ────────────────────────────────────────────────────────────────────

/// `[webhooks]` section of daemon.toml.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct WebhooksSection {
    /// Async event-stream receivers.
    pub endpoints: Vec<EndpointConfig>,
    /// Sync allow/deny hooks.
    pub verdict_hooks: Vec<VerdictHookConfig>,
    /// Redaction applied to every payload before it leaves the daemon.
    pub redaction: RedactionConfig,
    /// Per-endpoint queue depth. When the queue is full new events are dropped
    /// (counted in the stats), never blocked on.
    pub queue_size: usize,
}

impl Default for WebhooksSection {
    fn default() -> Self {
        WebhooksSection {
            endpoints: vec![],
            verdict_hooks: vec![],
            redaction: RedactionConfig::default(),
            queue_size: 10_000,
        }
    }
}

/// One async receiver (`[[webhooks.endpoints]]`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EndpointConfig {
    pub name: String,
    pub url: String,
    /// Shared secret for HMAC-SHA256 signing. Strongly recommended.
    #[serde(default)]
    pub secret: Option<String>,
    /// Event types to send. Empty or `["*"]` = everything.
    #[serde(default)]
    pub event_types: Vec<String>,
    /// Per-request timeout.
    #[serde(default = "default_stream_timeout_ms")]
    pub timeout_ms: u64,
    /// Retries after the first failed attempt (exponential backoff).
    #[serde(default = "default_retries")]
    pub retries: u32,
}

fn default_stream_timeout_ms() -> u64 {
    5_000
}
fn default_retries() -> u32 {
    3
}
fn default_verdict_timeout_ms() -> u64 {
    250
}

/// What to do when a verdict hook times out, errors, or returns garbage.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FailMode {
    /// Allow the event (log it).
    Open,
    /// Deny the event as if the hook had returned `deny`.
    Closed,
}

impl std::fmt::Display for FailMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FailMode::Open => write!(f, "fail_open"),
            FailMode::Closed => write!(f, "fail_closed"),
        }
    }
}

/// One sync hook (`[[webhooks.verdict_hooks]]`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerdictHookConfig {
    pub name: String,
    pub url: String,
    /// Kernel event types this hook decides on. Required, non-empty.
    pub event_types: Vec<String>,
    /// Required. There is deliberately no default: the operator must choose.
    pub fail_mode: FailMode,
    #[serde(default = "default_verdict_timeout_ms")]
    pub timeout_ms: u64,
    #[serde(default)]
    pub secret: Option<String>,
    /// Set this when the hook is backed by a hosted model rather than a local
    /// policy engine. It exists so the config can be REFUSED on high-frequency
    /// event types — see `validate`.
    #[serde(default)]
    pub model_backed: bool,
}

/// Kernel event types that fire far too often for a network round trip to sit
/// in front of them. One compile in the boundary demo produces dozens of these.
const HIGH_FREQUENCY_VERDICT_EVENTS: &[&str] = &["file_open", "process_exec", "socket_connect"];

/// `[webhooks.redaction]`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct RedactionConfig {
    pub enabled: bool,
    /// Apply the built-in secret patterns (API keys, tokens, private keys, …).
    pub builtin_patterns: bool,
    /// Extra regexes; every match in any string field is replaced.
    pub patterns: Vec<String>,
    /// Dotted JSON paths to remove entirely, e.g. `"args.cmdline"`.
    pub drop_fields: Vec<String>,
    pub replacement: String,
}

impl Default for RedactionConfig {
    fn default() -> Self {
        RedactionConfig {
            enabled: true,
            builtin_patterns: true,
            patterns: vec![],
            drop_fields: vec![],
            replacement: "[REDACTED]".into(),
        }
    }
}

/// Built-in redaction patterns. Conservative on purpose: they target things
/// that look like credentials, not ordinary paths or arguments.
const BUILTIN_PATTERNS: &[&str] = &[
    // key=value / key: value style secrets
    r#"(?i)\b(api[_-]?key|access[_-]?key|secret[_-]?key|client[_-]?secret|token|passwd|password|authorization|bearer)\b["']?\s*[=:]\s*["']?[^\s"'&,;]+"#,
    // Vendor key formats
    r"sk-[A-Za-z0-9_-]{16,}",
    r"AKIA[0-9A-Z]{16}",
    r"ghp_[A-Za-z0-9]{20,}",
    r"github_pat_[A-Za-z0-9_]{20,}",
    r"xox[abpr]-[A-Za-z0-9-]{10,}",
    r"AIza[0-9A-Za-z_-]{30,}",
    r"sk_(?:live|test)_[A-Za-z0-9]{16,}",
    // JWTs
    r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}",
    // PEM private keys
    r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----",
];

fn parse_url(raw: &str, what: &str, allow_file: bool) -> Result<reqwest::Url> {
    let url = reqwest::Url::parse(raw).with_context(|| format!("{what}: invalid url {raw:?}"))?;
    match url.scheme() {
        "http" | "https" => {
            if url.host_str().map(|h| h.is_empty()).unwrap_or(true) {
                bail!("{what}: url has no host");
            }
        }
        "file" if allow_file => {
            // The URL parser normalizes `..` away and ignores a trailing `/`;
            // refuse both in the raw text so the configured path is exactly
            // the path that gets written.
            if raw.split('/').any(|c| c == "..") || raw.ends_with('/') {
                bail!("{what}: file url must be an absolute file path without '..' (got {raw:?})");
            }
            file_sink_path(&url).with_context(|| format!("{what}: bad file url {raw:?}"))?;
        }
        "file" => bail!("{what}: file:// is only allowed for [[webhooks.endpoints]]"),
        s => bail!("{what}: url scheme must be http or https (got {s:?})"),
    }
    Ok(url)
}

/// The local path behind a `file://` sink URL: absolute, no host part, no
/// `..` components.
fn file_sink_path(url: &reqwest::Url) -> Result<std::path::PathBuf> {
    if url.host_str().map(|h| !h.is_empty()).unwrap_or(false) {
        bail!("file url must not have a host (use file:///absolute/path)");
    }
    let path = url
        .to_file_path()
        .map_err(|_| anyhow::anyhow!("file url is not an absolute local path"))?;
    if !path.is_absolute()
        || path
            .components()
            .any(|c| matches!(c, std::path::Component::ParentDir))
    {
        bail!("file url path must be absolute without '..'");
    }
    if path.file_name().is_none() {
        bail!("file url must name a file");
    }
    Ok(path)
}

/// True for loopback, RFC1918, link-local and ULA addresses, and for the
/// literal `localhost`. Used only to warn about sync hooks pointed elsewhere.
fn is_local_or_private_host(url: &reqwest::Url) -> bool {
    match url.host() {
        Some(url::Host::Domain(d)) => d.eq_ignore_ascii_case("localhost") || d.ends_with(".local"),
        Some(url::Host::Ipv4(ip)) => ip.is_loopback() || ip.is_private() || ip.is_link_local(),
        Some(url::Host::Ipv6(ip)) => {
            ip.is_loopback()
                || (ip.segments()[0] & 0xfe00) == 0xfc00
                || (ip.segments()[0] & 0xffc0) == 0xfe80
        }
        None => false,
    }
}

impl WebhooksSection {
    /// Any endpoint or hook configured?
    pub fn is_enabled(&self) -> bool {
        !self.endpoints.is_empty() || !self.verdict_hooks.is_empty()
    }

    /// Reject anything ambiguous. Called at startup and on reload; an error
    /// means the config is not applied.
    pub fn validate(&self) -> Result<()> {
        if self.queue_size == 0 {
            bail!("[webhooks] queue_size must be > 0");
        }
        let mut names = HashSet::new();
        for ep in &self.endpoints {
            let what = format!("[[webhooks.endpoints]] {:?}", ep.name);
            if ep.name.trim().is_empty() {
                bail!("[[webhooks.endpoints]] entry without a name");
            }
            if !names.insert(format!("endpoint:{}", ep.name)) {
                bail!("{what}: duplicate name");
            }
            parse_url(&ep.url, &what, true)?;
            if ep.timeout_ms == 0 || ep.timeout_ms > 60_000 {
                bail!("{what}: timeout_ms must be 1..=60000");
            }
            if ep.retries > 10 {
                bail!("{what}: retries must be <= 10");
            }
            for t in &ep.event_types {
                if t != "*" && !STREAM_EVENT_TYPES.contains(&t.as_str()) {
                    bail!("{what}: unknown event type {t:?}");
                }
            }
            if ep
                .secret
                .as_deref()
                .map(|s| s.trim().is_empty())
                .unwrap_or(false)
            {
                bail!("{what}: secret is set but empty");
            }
        }
        for h in &self.verdict_hooks {
            let what = format!("[[webhooks.verdict_hooks]] {:?}", h.name);
            if h.name.trim().is_empty() {
                bail!("[[webhooks.verdict_hooks]] entry without a name");
            }
            if !names.insert(format!("hook:{}", h.name)) {
                bail!("{what}: duplicate name");
            }
            parse_url(&h.url, &what, false)?;
            if h.event_types.is_empty() {
                bail!("{what}: event_types must list at least one kernel event type");
            }
            // A model-backed verdict hook on a high-frequency event type cannot
            // work, and the arithmetic is worth stating rather than letting
            // someone discover it in production. A hosted model answers in
            // roughly 1s; the default verdict budget is 250ms, so every call
            // times out and `fail_mode` decides instead of the model. Even with
            // a generous budget, dozens of events per compile at ~1s each turns
            // a build into hours.
            if h.model_backed {
                for t in &h.event_types {
                    if HIGH_FREQUENCY_VERDICT_EVENTS.contains(&t.as_str()) {
                        bail!(
                            "{what}: model_backed = true is refused on {t:?}. That event fires \
                             thousands of times a day at nanosecond-to-microsecond scale, and a \
                             hosted model answers in roughly a second: with the {}ms budget every \
                             call would time out and fail_mode would decide, not the model, and a \
                             single compile would take hours. Score files at scan time instead \
                             ([scanner.jev]) or score tool calls off the hot path ([checks]). \
                             The verdict hook stays available for a fast LOCAL policy engine, \
                             which is what it was designed for.",
                            h.timeout_ms
                        );
                    }
                }
            }
            for t in &h.event_types {
                if !VERDICT_EVENT_TYPES.contains(&t.as_str()) {
                    bail!(
                        "{what}: {t:?} is not a kernel event type a verdict hook can decide on \
                         (allowed: {})",
                        VERDICT_EVENT_TYPES.join(", ")
                    );
                }
            }
            if h.timeout_ms == 0 || h.timeout_ms > 10_000 {
                bail!("{what}: timeout_ms must be 1..=10000");
            }
            if h.secret
                .as_deref()
                .map(|s| s.trim().is_empty())
                .unwrap_or(false)
            {
                bail!("{what}: secret is set but empty");
            }
        }
        for p in &self.redaction.patterns {
            regex::Regex::new(p)
                .with_context(|| format!("[webhooks.redaction] bad pattern {p:?}"))?;
        }
        for f in &self.redaction.drop_fields {
            if f.trim().is_empty() || f.split('.').any(|seg| seg.is_empty()) {
                bail!("[webhooks.redaction] drop_fields entry {f:?} is not a dotted path");
            }
        }
        if self.redaction.replacement.is_empty() {
            bail!("[webhooks.redaction] replacement must not be empty");
        }
        Ok(())
    }
}

// ── Payload ──────────────────────────────────────────────────────────────────

/// Name of an event kind as it appears in payloads (`file_open`, …).
pub fn kind_name(kind: &EventKind) -> String {
    match serde_json::to_value(kind) {
        Ok(Value::String(s)) => s,
        _ => format!("{kind:?}").to_lowercase(),
    }
}

fn is_file_kind(kind: &EventKind) -> bool {
    matches!(
        kind,
        EventKind::FileOpen
            | EventKind::FileCreate
            | EventKind::FileDelete
            | EventKind::FileRename
            | EventKind::FileWrite
    )
}

fn is_network_kind(kind: &EventKind) -> bool {
    matches!(
        kind,
        EventKind::NetworkConnect
            | EventKind::NetworkSend
            | EventKind::NetworkRecv
            | EventKind::DnsQuery
    )
}

/// Split a `"ip:port"` target into its parts.
fn split_target(target: &str) -> (Option<String>, Option<u16>) {
    if let Some((ip, port)) = target.rsplit_once(':') {
        if let Ok(p) = port.parse::<u16>() {
            return (Some(ip.to_string()), Some(p));
        }
    }
    if target.is_empty() {
        (None, None)
    } else {
        (Some(target.to_string()), None)
    }
}

/// Build the schema-v1 JSON for a security event. `session` is the agent
/// session the daemon attributed the event to, if any.
pub fn event_payload(
    ev: &SecurityEvent,
    session_id: Option<&str>,
    agent_type: Option<&str>,
    host: &str,
) -> Value {
    let kind = kind_name(&ev.kind);
    let mut args = json!({ "target": ev.target });
    if is_file_kind(&ev.kind) {
        args["path"] = json!(ev.target);
    } else if is_network_kind(&ev.kind) {
        let (ip, port) = split_target(&ev.target);
        args["remote_ip"] = json!(ip);
        args["remote_port"] = json!(port);
    } else if ev.kind == EventKind::ProcessExec {
        args["cmdline"] = json!(ev.target);
    }
    if let Some(ctx) = &ev.llm_context {
        args["llm_context"] = serde_json::to_value(ctx).unwrap_or(Value::Null);
    }
    // Event-type-specific detail (tool inputs for hook events, appended lines
    // for transcript events, …) is merged into args; fixed keys win.
    if let Some(Value::Object(extra)) = &ev.extra {
        if let Value::Object(a) = &mut args {
            for (k, v) in extra {
                a.entry(k.clone()).or_insert_with(|| v.clone());
            }
        }
    }
    json!({
        "schema_version": SCHEMA_VERSION,
        "id": ev.id,
        "timestamp": ev.timestamp.to_rfc3339(),
        "host": host,
        "event_type": kind,
        "agent": {
            "session_id": session_id,
            "agent_type": agent_type,
            "process": ev.process,
            "pid": ev.pid,
            "ppid": ev.ppid,
            "parent_process": ev.parent_process,
            "uid": ev.uid,
        },
        "args": args,
        "verdict": {
            "allowed": ev.allowed,
            "reason": ev.reason,
        },
    })
}

/// Build the schema-v1 JSON for one of the daemon's own detections. The
/// detection payload is free-form and goes under `args`.
pub fn threat_payload(payload: &Value, host: &str) -> Value {
    let get_str = |k: &str| payload.get(k).and_then(|v| v.as_str()).map(String::from);
    let pid = payload.get("pid").and_then(|v| v.as_u64());
    json!({
        "schema_version": SCHEMA_VERSION,
        "id": get_str("id").or_else(|| get_str("event_id")).unwrap_or_else(|| {
            format!("threat-{}", chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0))
        }),
        "timestamp": get_str("timestamp").unwrap_or_else(|| chrono::Utc::now().to_rfc3339()),
        "host": host,
        "event_type": "threat",
        "agent": {
            "session_id": get_str("session_id"),
            "agent_type": get_str("agent"),
            "process": get_str("process"),
            "pid": pid,
            "ppid": Value::Null,
            "parent_process": Value::Null,
            "uid": Value::Null,
        },
        "args": payload,
        "verdict": {
            "allowed": Value::Null,
            "reason": get_str("description").or_else(|| get_str("type")),
        },
    })
}

// ── Redaction ────────────────────────────────────────────────────────────────

pub struct Redactor {
    enabled: bool,
    patterns: Vec<regex::Regex>,
    drop_fields: Vec<Vec<String>>,
    replacement: String,
}

impl Redactor {
    pub fn new(cfg: &RedactionConfig) -> Result<Self> {
        let mut patterns = Vec::new();
        if cfg.builtin_patterns {
            for p in BUILTIN_PATTERNS {
                patterns.push(regex::Regex::new(p).expect("builtin redaction pattern"));
            }
        }
        for p in &cfg.patterns {
            patterns.push(
                regex::Regex::new(p).with_context(|| format!("bad redaction pattern {p:?}"))?,
            );
        }
        Ok(Redactor {
            enabled: cfg.enabled,
            patterns,
            drop_fields: cfg
                .drop_fields
                .iter()
                .map(|f| f.split('.').map(String::from).collect())
                .collect(),
            replacement: cfg.replacement.clone(),
        })
    }

    /// Apply drop_fields and patterns in place.
    pub fn redact(&self, v: &mut Value) {
        if !self.enabled {
            return;
        }
        for path in &self.drop_fields {
            Self::drop_path(v, path);
        }
        self.redact_strings(v);
    }

    fn drop_path(v: &mut Value, path: &[String]) {
        let Some((last, parents)) = path.split_last() else {
            return;
        };
        let mut cur = v;
        for seg in parents {
            match cur.get_mut(seg) {
                Some(next) => cur = next,
                None => return,
            }
        }
        if let Some(obj) = cur.as_object_mut() {
            obj.remove(last);
        }
    }

    fn redact_strings(&self, v: &mut Value) {
        match v {
            Value::String(s) => {
                for re in &self.patterns {
                    if re.is_match(s) {
                        *s = re.replace_all(s, self.replacement.as_str()).into_owned();
                    }
                }
            }
            Value::Array(items) => items.iter_mut().for_each(|i| self.redact_strings(i)),
            Value::Object(map) => map.values_mut().for_each(|i| self.redact_strings(i)),
            _ => {}
        }
    }
}

// ── Signing ──────────────────────────────────────────────────────────────────

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// `HMAC-SHA256(secret, "<timestamp>.<body>")`, hex encoded. The timestamp is
/// bound into the signature so a captured delivery cannot be replayed later
/// without the receiver noticing the stale timestamp.
pub fn sign(secret: &[u8], timestamp: u64, body: &str) -> String {
    let mut mac = Hmac::<Sha256>::new_from_slice(secret).expect("HMAC accepts any key length");
    mac.update(timestamp.to_string().as_bytes());
    mac.update(b".");
    mac.update(body.as_bytes());
    hex(&mac.finalize().into_bytes())
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn apply_headers(
    req: reqwest::RequestBuilder,
    secret: Option<&str>,
    event_type: &str,
    delivery_id: &str,
    body: &str,
) -> reqwest::RequestBuilder {
    let ts = unix_now();
    let mut req = req
        .header("content-type", "application/json")
        .header(
            "user-agent",
            concat!("ringzero-daemon/", env!("CARGO_PKG_VERSION")),
        )
        .header("x-ringzero-schema", SCHEMA_VERSION.to_string())
        .header("x-ringzero-event", event_type)
        .header("x-ringzero-delivery", delivery_id)
        .header("x-ringzero-timestamp", ts.to_string());
    if let Some(secret) = secret {
        req = req.header(
            "x-ringzero-signature",
            format!("v1={}", sign(secret.as_bytes(), ts, body)),
        );
    }
    req.body(body.to_string())
}

/// Read a response body up to `max` bytes. `Ok(None)` = body exceeded the cap.
async fn read_bounded(mut resp: reqwest::Response, max: usize) -> reqwest::Result<Option<Vec<u8>>> {
    if resp
        .content_length()
        .map(|n| n as usize > max)
        .unwrap_or(false)
    {
        return Ok(None);
    }
    let mut buf: Vec<u8> = Vec::new();
    while let Some(chunk) = resp.chunk().await? {
        if buf.len() + chunk.len() > max {
            return Ok(None);
        }
        buf.extend_from_slice(&chunk);
    }
    Ok(Some(buf))
}

fn build_client(timeout: Duration) -> Result<reqwest::Client> {
    // Redirects are never followed: a receiver must not be able to bounce the
    // daemon to another host.
    reqwest::Client::builder()
        .timeout(timeout)
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .context("building webhook HTTP client")
}

// ── Stats ────────────────────────────────────────────────────────────────────

#[derive(Default)]
pub struct Stats {
    pub enqueued: AtomicU64,
    pub dropped_queue_full: AtomicU64,
    pub delivered: AtomicU64,
    pub delivery_failed: AtomicU64,
    pub verdict_allow: AtomicU64,
    pub verdict_deny: AtomicU64,
    pub verdict_failed: AtomicU64,
}

impl Stats {
    pub fn snapshot(&self) -> Value {
        json!({
            "enqueued": self.enqueued.load(Ordering::Relaxed),
            "dropped_queue_full": self.dropped_queue_full.load(Ordering::Relaxed),
            "delivered": self.delivered.load(Ordering::Relaxed),
            "delivery_failed": self.delivery_failed.load(Ordering::Relaxed),
            "verdict_allow": self.verdict_allow.load(Ordering::Relaxed),
            "verdict_deny": self.verdict_deny.load(Ordering::Relaxed),
            "verdict_failed": self.verdict_failed.load(Ordering::Relaxed),
        })
    }
}

// ── Async event stream ───────────────────────────────────────────────────────

struct Delivery {
    event_type: String,
    body: Arc<String>,
}

struct Endpoint {
    name: String,
    event_types: Option<HashSet<String>>, // None = all
    tx: mpsc::Sender<Arc<Delivery>>,
}

impl Endpoint {
    fn wants(&self, event_type: &str) -> bool {
        self.event_types
            .as_ref()
            .map(|s| s.contains(event_type))
            .unwrap_or(true)
    }
}

async fn run_sender(cfg: EndpointConfig, mut rx: mpsc::Receiver<Arc<Delivery>>, stats: Arc<Stats>) {
    if cfg.url.starts_with("file:") {
        run_file_sink(cfg, rx, stats).await;
        return;
    }
    let client = match build_client(Duration::from_millis(cfg.timeout_ms)) {
        Ok(c) => c,
        Err(e) => {
            tracing::error!(endpoint = %cfg.name, err = %e, "webhook sender disabled");
            return;
        }
    };
    while let Some(d) = rx.recv().await {
        let mut attempt: u32 = 0;
        loop {
            let delivery_id = uuid::Uuid::new_v4().to_string();
            let req = apply_headers(
                client.post(&cfg.url),
                cfg.secret.as_deref(),
                &d.event_type,
                &delivery_id,
                &d.body,
            );
            let outcome = req.send().await;
            let retryable = match &outcome {
                Ok(resp) if resp.status().is_success() => {
                    stats.delivered.fetch_add(1, Ordering::Relaxed);
                    tracing::debug!(endpoint = %cfg.name, event_type = %d.event_type, status = %resp.status(), "webhook delivered");
                    break;
                }
                Ok(resp) => {
                    let status = resp.status();
                    tracing::warn!(endpoint = %cfg.name, event_type = %d.event_type, %status, attempt, "webhook receiver rejected delivery");
                    status.is_server_error() || status.as_u16() == 429 || status.as_u16() == 408
                }
                Err(e) => {
                    tracing::warn!(endpoint = %cfg.name, event_type = %d.event_type, err = %e, attempt, "webhook delivery failed");
                    true
                }
            };
            if !retryable || attempt >= cfg.retries {
                stats.delivery_failed.fetch_add(1, Ordering::Relaxed);
                break;
            }
            attempt += 1;
            // 0.5s, 2s, 8s, … capped at 30s so a long retry budget can never
            // park the sender (and its queue) for hours on one event.
            let backoff = 500u64
                .saturating_mul(4u64.saturating_pow(attempt - 1))
                .min(30_000);
            tokio::time::sleep(Duration::from_millis(backoff)).await;
        }
    }
    tracing::info!(endpoint = %cfg.name, "webhook sender stopped");
}

/// `file://` sink: one JSON line per delivery, appended to a local file.
/// `{"delivery_id", "timestamp", "signature", "event"}` — `event` is the exact
/// redacted event object an HTTP receiver would get, and `signature` (when the
/// endpoint has a secret) is the same `v1=<hmac>` over `"<timestamp>.<event>"`.
/// The file is opened per write with create-0600 + append + O_NOFOLLOW, so a
/// pre-placed symlink cannot redirect the daemon's writes. No retries.
async fn run_file_sink(
    cfg: EndpointConfig,
    mut rx: mpsc::Receiver<Arc<Delivery>>,
    stats: Arc<Stats>,
) {
    let path = match reqwest::Url::parse(&cfg.url)
        .ok()
        .and_then(|u| file_sink_path(&u).ok())
    {
        Some(p) => p,
        None => {
            tracing::error!(endpoint = %cfg.name, url = %cfg.url, "file sink disabled — invalid path");
            return;
        }
    };
    let mut failures: u64 = 0;
    while let Some(d) = rx.recv().await {
        let ts = unix_now();
        let delivery_id = uuid::Uuid::new_v4().to_string();
        let signature = match cfg.secret.as_deref() {
            Some(secret) => format!("\"v1={}\"", sign(secret.as_bytes(), ts, &d.body)),
            None => "null".to_string(),
        };
        let line = format!(
            "{{\"delivery_id\":\"{delivery_id}\",\"timestamp\":{ts},\"signature\":{signature},\"event\":{}}}\n",
            d.body
        );
        match append_line(&path, line.as_bytes()) {
            Ok(()) => {
                stats.delivered.fetch_add(1, Ordering::Relaxed);
            }
            Err(e) => {
                failures += 1;
                stats.delivery_failed.fetch_add(1, Ordering::Relaxed);
                if failures == 1 || failures % 100 == 0 {
                    tracing::error!(endpoint = %cfg.name, path = %path.display(), err = %e, failures, "file sink write failed");
                }
            }
        }
    }
    tracing::info!(endpoint = %cfg.name, "file sink stopped");
}

fn append_line(path: &std::path::Path, line: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .custom_flags(nix::libc::O_NOFOLLOW)
        .open(path)?;
    f.write_all(line)
}

// ── Sync verdict hooks ───────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    Allow,
    Deny,
}

/// What the receiver answered, or what the fail mode decided for it.
#[derive(Debug, Clone)]
pub struct VerdictResult {
    pub hook: String,
    pub verdict: Verdict,
    /// `receiver`, `fail_open`, or `fail_closed`.
    pub source: &'static str,
    pub reason: Option<String>,
    pub latency_ms: u128,
}

#[derive(Deserialize)]
struct VerdictResponse {
    verdict: String,
    #[serde(default)]
    reason: Option<String>,
}

struct Breaker {
    consecutive_failures: u32,
    open_until: Option<Instant>,
}

pub struct VerdictHook {
    cfg: VerdictHookConfig,
    client: reqwest::Client,
    breaker: Mutex<Breaker>,
    stats: Arc<Stats>,
}

impl VerdictHook {
    fn new(cfg: VerdictHookConfig, stats: Arc<Stats>) -> Result<Self> {
        let client = build_client(Duration::from_millis(cfg.timeout_ms))?;
        Ok(VerdictHook {
            cfg,
            client,
            breaker: Mutex::new(Breaker {
                consecutive_failures: 0,
                open_until: None,
            }),
            stats,
        })
    }

    pub fn name(&self) -> &str {
        &self.cfg.name
    }

    fn wants(&self, event_type: &str) -> bool {
        self.cfg.event_types.iter().any(|t| t == event_type)
    }

    fn fail_result(&self, detail: String, started: Instant) -> VerdictResult {
        self.stats.verdict_failed.fetch_add(1, Ordering::Relaxed);
        let (verdict, source) = match self.cfg.fail_mode {
            FailMode::Open => (Verdict::Allow, "fail_open"),
            FailMode::Closed => (Verdict::Deny, "fail_closed"),
        };
        VerdictResult {
            hook: self.cfg.name.clone(),
            verdict,
            source,
            reason: Some(detail),
            latency_ms: started.elapsed().as_millis(),
        }
    }

    fn breaker_is_open(&self) -> bool {
        let mut b = self.breaker.lock().unwrap_or_else(|e| e.into_inner());
        match b.open_until {
            Some(t) if Instant::now() < t => true,
            Some(_) => {
                b.open_until = None;
                b.consecutive_failures = 0;
                tracing::info!(hook = %self.cfg.name, "verdict hook circuit closed again");
                false
            }
            None => false,
        }
    }

    fn record(&self, ok: bool) {
        let mut b = self.breaker.lock().unwrap_or_else(|e| e.into_inner());
        if ok {
            b.consecutive_failures = 0;
        } else {
            b.consecutive_failures += 1;
            if b.consecutive_failures >= BREAKER_THRESHOLD && b.open_until.is_none() {
                b.open_until = Some(Instant::now() + Duration::from_secs(BREAKER_OPEN_SECS));
                tracing::warn!(
                    hook = %self.cfg.name,
                    failures = b.consecutive_failures,
                    fail_mode = %self.cfg.fail_mode,
                    "verdict hook circuit opened for {BREAKER_OPEN_SECS}s — fail mode applies without calling the receiver"
                );
            }
        }
    }

    /// Ask the receiver. Never panics, never takes longer than `timeout_ms`
    /// (plus scheduling jitter); every outcome is logged.
    pub async fn evaluate(&self, event_type: &str, body: &str) -> VerdictResult {
        let started = Instant::now();
        if self.breaker_is_open() {
            let r = self.fail_result("circuit open".into(), started);
            tracing::warn!(hook = %self.cfg.name, event_type, verdict = ?r.verdict, source = r.source, "verdict hook skipped");
            return r;
        }
        let delivery_id = uuid::Uuid::new_v4().to_string();
        let req = apply_headers(
            self.client.post(&self.cfg.url),
            self.cfg.secret.as_deref(),
            event_type,
            &delivery_id,
            body,
        );
        let result = match req.send().await {
            Ok(resp) if resp.status().is_success() => {
                // Bound the body we are willing to parse — stop reading as soon
                // as the cap is exceeded rather than buffering whatever the
                // receiver sends within the timeout.
                let bytes = match read_bounded(resp, MAX_VERDICT_BODY).await {
                    Ok(Some(b)) => b,
                    Ok(None) => {
                        self.record(false);
                        let r = self.fail_result(
                            format!("response larger than {MAX_VERDICT_BODY} bytes"),
                            started,
                        );
                        tracing::warn!(hook = %self.cfg.name, event_type, verdict = ?r.verdict, source = r.source, "verdict hook returned an oversized body");
                        return r;
                    }
                    Err(e) => {
                        self.record(false);
                        let r = self.fail_result(format!("read error: {e}"), started);
                        tracing::warn!(hook = %self.cfg.name, event_type, verdict = ?r.verdict, source = r.source, err = %e, "verdict hook body read failed");
                        return r;
                    }
                };
                match serde_json::from_slice::<VerdictResponse>(&bytes) {
                    Ok(v) => match v.verdict.as_str() {
                        "allow" => Ok((Verdict::Allow, v.reason)),
                        "deny" => Ok((Verdict::Deny, v.reason)),
                        other => Err(format!("unknown verdict {other:?}")),
                    },
                    Err(e) => Err(format!("malformed verdict response: {e}")),
                }
            }
            Ok(resp) => Err(format!("http {}", resp.status())),
            Err(e) if e.is_timeout() => Err(format!("timeout after {} ms", self.cfg.timeout_ms)),
            Err(e) => Err(format!("request failed: {e}")),
        };
        match result {
            Ok((verdict, reason)) => {
                self.record(true);
                match verdict {
                    Verdict::Allow => self.stats.verdict_allow.fetch_add(1, Ordering::Relaxed),
                    Verdict::Deny => self.stats.verdict_deny.fetch_add(1, Ordering::Relaxed),
                };
                let r = VerdictResult {
                    hook: self.cfg.name.clone(),
                    verdict,
                    source: "receiver",
                    reason,
                    latency_ms: started.elapsed().as_millis(),
                };
                tracing::info!(hook = %self.cfg.name, event_type, verdict = ?r.verdict, latency_ms = r.latency_ms, reason = ?r.reason, "verdict hook");
                r
            }
            Err(detail) => {
                self.record(false);
                let r = self.fail_result(detail.clone(), started);
                tracing::warn!(
                    hook = %self.cfg.name,
                    event_type,
                    verdict = ?r.verdict,
                    source = r.source,
                    latency_ms = r.latency_ms,
                    detail = %detail,
                    "verdict hook failed — fail mode applied"
                );
                r
            }
        }
    }
}

// ── Dispatcher ───────────────────────────────────────────────────────────────

/// Owns the sender tasks and the verdict hooks for one loaded config.
pub struct WebhookDispatcher {
    endpoints: Vec<Endpoint>,
    hooks: Vec<Arc<VerdictHook>>,
    redactor: Redactor,
    sessions: Option<Arc<SessionStore>>,
    host: String,
    stats: Arc<Stats>,
}

impl WebhookDispatcher {
    /// A dispatcher with nothing configured: every publish is a no-op.
    pub fn disabled() -> Self {
        WebhookDispatcher {
            endpoints: vec![],
            hooks: vec![],
            redactor: Redactor::new(&RedactionConfig::default()).expect("default redaction"),
            sessions: None,
            host: crate::platform::hostname(),
            stats: Arc::new(Stats::default()),
        }
    }

    /// Validate `cfg`, spawn one sender task per endpoint, build the hooks.
    pub fn start(cfg: &WebhooksSection, sessions: Option<Arc<SessionStore>>) -> Result<Self> {
        cfg.validate()?;
        let stats = Arc::new(Stats::default());
        let mut endpoints = Vec::new();
        for ep in &cfg.endpoints {
            if ep.secret.is_none() {
                tracing::warn!(endpoint = %ep.name, "webhook endpoint has no secret — deliveries will be unsigned");
            }
            let (tx, rx) = mpsc::channel::<Arc<Delivery>>(cfg.queue_size);
            tokio::spawn(run_sender(ep.clone(), rx, Arc::clone(&stats)));
            let event_types =
                if ep.event_types.is_empty() || ep.event_types.iter().any(|t| t == "*") {
                    None
                } else {
                    Some(ep.event_types.iter().cloned().collect())
                };
            endpoints.push(Endpoint {
                name: ep.name.clone(),
                event_types,
                tx,
            });
            tracing::info!(endpoint = %ep.name, url = %ep.url, "webhook event stream enabled");
        }
        let mut hooks = Vec::new();
        for h in &cfg.verdict_hooks {
            let url = parse_url(&h.url, "verdict hook", false)?;
            if !is_local_or_private_host(&url) {
                tracing::warn!(
                    hook = %h.name,
                    url = %h.url,
                    "verdict hook points at a non-local host — sync hooks are meant for localhost or the local network; remote systems should consume the async stream"
                );
            }
            tracing::info!(hook = %h.name, url = %h.url, event_types = ?h.event_types, timeout_ms = h.timeout_ms, fail_mode = %h.fail_mode, "verdict hook enabled");
            hooks.push(Arc::new(VerdictHook::new(h.clone(), Arc::clone(&stats))?));
        }
        Ok(WebhookDispatcher {
            endpoints,
            hooks,
            redactor: Redactor::new(&cfg.redaction)?,
            sessions,
            host: crate::platform::hostname(),
            stats,
        })
    }

    pub fn is_enabled(&self) -> bool {
        !self.endpoints.is_empty() || !self.hooks.is_empty()
    }

    pub fn stats(&self) -> Value {
        let mut v = self.stats.snapshot();
        v["endpoints"] = json!(self
            .endpoints
            .iter()
            .map(|e| e.name.clone())
            .collect::<Vec<_>>());
        v["verdict_hooks"] = json!(self
            .hooks
            .iter()
            .map(|h| h.name().to_string())
            .collect::<Vec<_>>());
        v
    }

    fn session_for(&self, pid: u32) -> (Option<String>, Option<String>) {
        match self.sessions.as_ref().and_then(|s| s.find_by_pid(pid)) {
            Some(s) => (Some(s.id), Some(s.agent_type.to_string())),
            None => (None, None),
        }
    }

    /// Redacted, serialized event body — shared by the stream and the hooks so
    /// both see exactly the same bytes.
    fn render_event(&self, ev: &SecurityEvent) -> (String, String) {
        let (sid, agent) = self.session_for(ev.pid);
        let mut payload = event_payload(ev, sid.as_deref(), agent.as_deref(), &self.host);
        self.redactor.redact(&mut payload);
        (kind_name(&ev.kind), payload.to_string())
    }

    fn enqueue(&self, event_type: String, body: String) {
        if self.endpoints.is_empty() {
            return;
        }
        let d = Arc::new(Delivery {
            event_type,
            body: Arc::new(body),
        });
        for ep in &self.endpoints {
            if !ep.wants(&d.event_type) {
                continue;
            }
            match ep.tx.try_send(Arc::clone(&d)) {
                Ok(()) => {
                    self.stats.enqueued.fetch_add(1, Ordering::Relaxed);
                }
                Err(_) => {
                    let n = self
                        .stats
                        .dropped_queue_full
                        .fetch_add(1, Ordering::Relaxed)
                        + 1;
                    if n == 1 || n % 1000 == 0 {
                        tracing::warn!(endpoint = %ep.name, dropped = n, "webhook queue full — dropping events (receiver too slow or down)");
                    }
                }
            }
        }
    }

    /// Async stream: queue a security event for every endpoint that wants it.
    pub fn publish_event(&self, ev: &SecurityEvent) {
        if self.endpoints.is_empty() {
            return;
        }
        let (event_type, body) = self.render_event(ev);
        self.enqueue(event_type, body);
    }

    /// Async stream: queue one of the daemon's own detections.
    pub fn publish_threat(&self, payload: &Value) {
        if self.endpoints.is_empty() {
            return;
        }
        let mut p = threat_payload(payload, &self.host);
        self.redactor.redact(&mut p);
        self.enqueue("threat".into(), p.to_string());
    }

    /// Sync hooks: ask every hook subscribed to this event's type, in config
    /// order. The first deny wins; `None` means every hook allowed (or none
    /// is configured for this type).
    pub async fn verdict(&self, ev: &SecurityEvent) -> Option<VerdictResult> {
        let event_type = kind_name(&ev.kind);
        let hooks: Vec<&Arc<VerdictHook>> =
            self.hooks.iter().filter(|h| h.wants(&event_type)).collect();
        if hooks.is_empty() {
            return None;
        }
        let (_, body) = self.render_event(ev);
        for h in hooks {
            let r = h.evaluate(&event_type, &body).await;
            if r.verdict == Verdict::Deny {
                return Some(r);
            }
        }
        None
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn hook(fail_mode: FailMode) -> VerdictHookConfig {
        VerdictHookConfig {
            name: "h".into(),
            url: "http://127.0.0.1:9/verdict".into(),
            event_types: vec!["file_open".into()],
            fail_mode,
            timeout_ms: 50,
            secret: None,
            model_backed: false,
        }
    }

    #[test]
    fn fail_mode_is_required() {
        let toml_src = r#"
            [[verdict_hooks]]
            name = "x"
            url = "http://127.0.0.1:8081/verdict"
            event_types = ["file_open"]
        "#;
        let err = toml::from_str::<WebhooksSection>(toml_src).unwrap_err();
        assert!(err.to_string().contains("fail_mode"), "{err}");

        let ok = toml::from_str::<WebhooksSection>(&format!("{toml_src}\nfail_mode = \"closed\""))
            .unwrap();
        assert_eq!(ok.verdict_hooks[0].fail_mode, FailMode::Closed);
        assert_eq!(ok.verdict_hooks[0].timeout_ms, 250);
        ok.validate().unwrap();
    }

    #[test]
    fn model_backed_verdict_hook_is_refused_on_high_frequency_events() {
        for ev in ["file_open", "process_exec", "socket_connect"] {
            let mut cfg = WebhooksSection::default();
            cfg.verdict_hooks.push(VerdictHookConfig {
                name: "model".into(),
                url: "http://127.0.0.1:9/verdict".into(),
                event_types: vec![ev.to_string()],
                fail_mode: FailMode::Closed,
                timeout_ms: 250,
                secret: None,
                model_backed: true,
            });
            let err = cfg.validate().expect_err("must be refused");
            let msg = err.to_string();
            assert!(msg.contains("model_backed = true is refused"), "got: {msg}");
            assert!(
                msg.contains("fail_mode would decide"),
                "explains the arithmetic: {msg}"
            );
        }
    }

    #[test]
    fn a_local_verdict_hook_on_the_same_events_is_still_allowed() {
        // The verdict hook exists for a fast local policy engine; only the
        // model-backed case is refused.
        let mut cfg = WebhooksSection::default();
        cfg.verdict_hooks.push(VerdictHookConfig {
            name: "local-engine".into(),
            url: "http://127.0.0.1:8081/verdict".into(),
            event_types: vec!["file_open".into()],
            fail_mode: FailMode::Closed,
            timeout_ms: 250,
            secret: None,
            model_backed: false,
        });
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn validate_rejects_bad_config() {
        let mut cfg = WebhooksSection::default();
        cfg.endpoints.push(EndpointConfig {
            name: "a".into(),
            url: "ftp://example.com/x".into(),
            secret: None,
            event_types: vec![],
            timeout_ms: 1000,
            retries: 1,
        });
        assert!(cfg.validate().unwrap_err().to_string().contains("scheme"));
        cfg.endpoints[0].url = "http://example.com/x".into();
        cfg.endpoints[0].event_types = vec!["nope".into()];
        assert!(cfg
            .validate()
            .unwrap_err()
            .to_string()
            .contains("unknown event type"));
        cfg.endpoints[0].event_types = vec!["*".into()];
        cfg.validate().unwrap();

        let mut h = hook(FailMode::Open);
        h.event_types = vec!["llm_request".into()];
        cfg.verdict_hooks.push(h);
        assert!(cfg
            .validate()
            .unwrap_err()
            .to_string()
            .contains("not a kernel event type"));
        cfg.verdict_hooks[0].event_types = vec![];
        assert!(cfg
            .validate()
            .unwrap_err()
            .to_string()
            .contains("at least one"));
        cfg.verdict_hooks[0].event_types = vec!["file_open".into()];
        cfg.verdict_hooks[0].timeout_ms = 0;
        assert!(cfg.validate().is_err());
        cfg.verdict_hooks[0].timeout_ms = 250;
        cfg.redaction.patterns = vec!["(".into()];
        assert!(cfg
            .validate()
            .unwrap_err()
            .to_string()
            .contains("bad pattern"));
        cfg.redaction.patterns = vec![];
        cfg.validate().unwrap();
    }

    #[test]
    fn hmac_matches_reference_vector() {
        // RFC 4231 test case 2: key "Jefe", data "what do ya want for nothing?"
        let mut mac = Hmac::<Sha256>::new_from_slice(b"Jefe").unwrap();
        mac.update(b"what do ya want for nothing?");
        assert_eq!(
            hex(&mac.finalize().into_bytes()),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
        // Our envelope: HMAC(secret, "<ts>.<body>")
        let s = sign(b"secret", 1700000000, r#"{"a":1}"#);
        let mut mac = Hmac::<Sha256>::new_from_slice(b"secret").unwrap();
        mac.update(b"1700000000.{\"a\":1}");
        assert_eq!(s, hex(&mac.finalize().into_bytes()));
        assert_eq!(s.len(), 64);
    }

    #[test]
    fn redaction_masks_secrets_and_drops_fields() {
        let cfg = RedactionConfig {
            drop_fields: vec!["args.cmdline".into(), "agent.uid".into()],
            patterns: vec![r"CUSTOM-[0-9]+".into()],
            ..RedactionConfig::default()
        };
        let r = Redactor::new(&cfg).unwrap();
        let mut v = json!({
            "args": {
                "cmdline": "curl -H 'Authorization: Bearer abc'",
                "target": "/home/u/.env OPENAI_API_KEY=sk-abcdefghijklmnopqrstuvwxyz0123 done",
                "nested": ["AKIAABCDEFGHIJKLMNOP", "CUSTOM-42", "plain"],
                "pem": "-----BEGIN RSA PRIVATE KEY-----\nMIIE...\n-----END RSA PRIVATE KEY-----",
            },
            "agent": {"uid": 1000, "process": "cat"},
        });
        r.redact(&mut v);
        assert!(v["args"].get("cmdline").is_none());
        assert!(v["agent"].get("uid").is_none());
        let target = v["args"]["target"].as_str().unwrap();
        assert!(!target.contains("sk-abc"), "{target}");
        assert!(target.starts_with("/home/u/.env "), "{target}");
        assert_eq!(v["args"]["nested"][0], "[REDACTED]");
        assert_eq!(v["args"]["nested"][1], "[REDACTED]");
        assert_eq!(v["args"]["nested"][2], "plain");
        assert_eq!(v["args"]["pem"], "[REDACTED]");
        assert_eq!(v["agent"]["process"], "cat");
    }

    #[test]
    fn redaction_can_be_disabled() {
        let cfg = RedactionConfig {
            enabled: false,
            ..RedactionConfig::default()
        };
        let r = Redactor::new(&cfg).unwrap();
        let mut v = json!({"k": "AKIAABCDEFGHIJKLMNOP"});
        r.redact(&mut v);
        assert_eq!(v["k"], "AKIAABCDEFGHIJKLMNOP");
    }

    #[test]
    fn event_payload_has_stable_shape() {
        let ev = SecurityEvent {
            id: "1-2".into(),
            kind: EventKind::NetworkConnect,
            pid: 42,
            uid: 1000,
            process: "curl".into(),
            target: "203.0.113.5:443".into(),
            allowed: true,
            reason: None,
            timestamp: chrono::Utc::now(),
            ppid: Some(41),
            parent_process: Some("claude".into()),
            llm_context: None,
            extra: None,
        };
        let p = event_payload(&ev, Some("auto-claude-41"), Some("claude"), "host1");
        assert_eq!(p["schema_version"], SCHEMA_VERSION);
        assert_eq!(p["event_type"], "network_connect");
        assert_eq!(p["agent"]["session_id"], "auto-claude-41");
        assert_eq!(p["agent"]["pid"], 42);
        assert_eq!(p["args"]["remote_ip"], "203.0.113.5");
        assert_eq!(p["args"]["remote_port"], 443);
        assert_eq!(p["verdict"]["allowed"], true);

        let t = threat_payload(
            &json!({"type": "config_tamper", "pid": 7, "process": "bash", "session_id": "s"}),
            "h",
        );
        assert_eq!(t["event_type"], "threat");
        assert_eq!(t["agent"]["pid"], 7);
        assert_eq!(t["args"]["type"], "config_tamper");
    }

    #[tokio::test]
    async fn unreachable_hook_applies_fail_mode_and_opens_breaker() {
        let stats = Arc::new(Stats::default());
        let closed = VerdictHook::new(hook(FailMode::Closed), Arc::clone(&stats)).unwrap();
        let r = closed.evaluate("file_open", "{}").await;
        assert_eq!(r.verdict, Verdict::Deny);
        assert_eq!(r.source, "fail_closed");

        let open = VerdictHook::new(hook(FailMode::Open), Arc::clone(&stats)).unwrap();
        let r = open.evaluate("file_open", "{}").await;
        assert_eq!(r.verdict, Verdict::Allow);
        assert_eq!(r.source, "fail_open");

        // After BREAKER_THRESHOLD failures the circuit opens and the hook is
        // skipped without a network call.
        for _ in 0..BREAKER_THRESHOLD {
            let _ = open.evaluate("file_open", "{}").await;
        }
        assert!(open.breaker_is_open());
        let r = open.evaluate("file_open", "{}").await;
        assert_eq!(r.reason.as_deref(), Some("circuit open"));
        assert!(stats.verdict_failed.load(Ordering::Relaxed) >= 7);
    }

    #[test]
    fn file_sink_urls_are_endpoint_only() {
        let mut cfg = WebhooksSection::default();
        cfg.endpoints.push(EndpointConfig {
            name: "audit".into(),
            url: "file:///var/log/ringzero/events.jsonl".into(),
            secret: None,
            event_types: vec![],
            timeout_ms: 1000,
            retries: 0,
        });
        cfg.validate().unwrap();
        for bad in [
            "file://relative/x.jsonl",
            "file:///var/../etc/x",
            "file:///var/log/",
            "file://host/x",
        ] {
            cfg.endpoints[0].url = bad.into();
            assert!(cfg.validate().is_err(), "{bad} should be rejected");
        }
        cfg.endpoints[0].url = "file:///tmp/ok.jsonl".into();
        cfg.validate().unwrap();

        let mut h = hook(FailMode::Open);
        h.url = "file:///tmp/verdict.jsonl".into();
        cfg.verdict_hooks.push(h);
        let err = cfg.validate().unwrap_err().to_string();
        assert!(
            err.contains("only allowed for [[webhooks.endpoints]]"),
            "{err}"
        );
    }

    #[tokio::test]
    async fn file_sink_appends_signed_json_lines() {
        let dir = std::env::temp_dir().join(format!("rz-sink-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("events.jsonl");
        let _ = std::fs::remove_file(&file);
        let mut cfg = WebhooksSection::default();
        cfg.endpoints.push(EndpointConfig {
            name: "audit".into(),
            url: format!("file://{}", file.display()),
            secret: Some("s3cret".into()),
            event_types: vec![],
            timeout_ms: 1000,
            retries: 0,
        });
        let d = WebhookDispatcher::start(&cfg, None).unwrap();
        let ev = SecurityEvent {
            id: "e-1".into(),
            kind: EventKind::ProcessExec,
            pid: 7,
            uid: 1000,
            process: "bash".into(),
            target: "/usr/bin/curl".into(),
            allowed: true,
            reason: None,
            timestamp: chrono::Utc::now(),
            ppid: Some(1),
            parent_process: Some("claude".into()),
            llm_context: None,
            extra: None,
        };
        d.publish_event(&ev);
        let mut content = String::new();
        for _ in 0..40 {
            tokio::time::sleep(Duration::from_millis(50)).await;
            content = std::fs::read_to_string(&file).unwrap_or_default();
            if content.ends_with('\n') {
                break;
            }
        }
        let lines: Vec<&str> = content.lines().collect();
        assert_eq!(lines.len(), 1, "one line expected: {content:?}");
        let v: Value = serde_json::from_str(lines[0]).unwrap();
        assert!(v["delivery_id"]
            .as_str()
            .map(|s| s.len() == 36)
            .unwrap_or(false));
        let ts = v["timestamp"].as_u64().unwrap();
        assert_eq!(v["event"]["event_type"], "process_exec");
        assert_eq!(v["event"]["agent"]["pid"], 7);
        // The signature covers "<timestamp>.<event JSON exactly as written>".
        let raw = lines[0];
        let idx = raw.find("\"event\":").unwrap() + "\"event\":".len();
        let event_json = &raw[idx..raw.len() - 1];
        assert_eq!(
            v["signature"].as_str().unwrap(),
            format!("v1={}", sign(b"s3cret", ts, event_json))
        );
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&file).unwrap().permissions().mode() & 0o777,
            0o600
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn local_host_detection() {
        for u in [
            "http://127.0.0.1:8080/",
            "http://localhost/x",
            "http://10.1.2.3/",
            "http://192.168.1.9:1/",
            "http://[::1]:5/",
            "http://[fd00::1]/",
        ] {
            assert!(
                is_local_or_private_host(&reqwest::Url::parse(u).unwrap()),
                "{u}"
            );
        }
        for u in ["https://example.com/", "http://203.0.113.9/"] {
            assert!(
                !is_local_or_private_host(&reqwest::Url::parse(u).unwrap()),
                "{u}"
            );
        }
    }
}

// ── Handle ───────────────────────────────────────────────────────────────────

/// Shared, hot-swappable dispatcher. The event pipeline and the IPC broadcast
/// hold this; a config reload replaces the inner dispatcher atomically.
pub struct WebhookHandle {
    inner: std::sync::RwLock<Arc<WebhookDispatcher>>,
}

impl WebhookHandle {
    pub fn new(dispatcher: WebhookDispatcher) -> Arc<Self> {
        Arc::new(WebhookHandle {
            inner: std::sync::RwLock::new(Arc::new(dispatcher)),
        })
    }

    pub fn get(&self) -> Arc<WebhookDispatcher> {
        Arc::clone(&self.inner.read().unwrap_or_else(|e| e.into_inner()))
    }

    /// Swap in a freshly built dispatcher. The old one's sender tasks finish
    /// draining their queues and exit once the last reference drops.
    pub fn replace(&self, dispatcher: WebhookDispatcher) {
        let mut guard = self.inner.write().unwrap_or_else(|e| e.into_inner());
        *guard = Arc::new(dispatcher);
    }

    pub fn publish_event(&self, ev: &SecurityEvent) {
        let d = self.get();
        if d.is_enabled() {
            d.publish_event(ev);
        }
    }

    pub fn publish_threat(&self, payload: &Value) {
        let d = self.get();
        if d.is_enabled() {
            d.publish_threat(payload);
        }
    }

    pub fn stats(&self) -> Value {
        self.get().stats()
    }
}
