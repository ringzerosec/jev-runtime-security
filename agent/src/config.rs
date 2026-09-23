// SPDX-License-Identifier: Apache-2.0
// daemon/src/config.rs — Daemon configuration file
//
// Loaded from (first found):
//   1. $RINGZERO_CONFIG env var
//   2. /etc/ringzero/daemon.toml (root) or ~/.config/ringzero/daemon.toml (dev)
//
// Hot-reload: daemon re-reads on SIGHUP.

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

use crate::siem::forwarder::{SiemConfig, SiemTarget};

// ── PII action mode ──────────────────────────────────────────────────────────

/// What to do when PII is detected in outbound LLM traffic.
/// - `Redact`: mask PII in the event log but allow the connection (legacy)
/// - `Block`: record the send as a blocked event and add the (pid, destination)
///   pair to the kernel block cache. Process termination on kernel-captured send
///   payloads is disabled in this release (the capture is unverified on 6.x kernels).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum PiiAction {
    Redact,
    Block,
}

impl Default for PiiAction {
    fn default() -> Self {
        PiiAction::Block
    }
}

// ── Config schema ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct DaemonConfig {
    pub daemon: DaemonSection,
    pub http_api: HttpApiSection,
    pub siem: SiemSection,
    pub policy: PolicySection,
    pub dlp: DlpSection,
    pub slm: crate::analyzer::slm::SlmConfig,
    pub model_armor: crate::scanner::model_armor::ModelArmorConfig,
    pub enforcement: EnforcementSection,
    pub osv: OsvSection,
    pub webhooks: crate::integrations::webhook::WebhooksSection,
    pub checks: ChecksSection,
    pub scanner: ScannerSection,
    pub stdio_capture: StdioCaptureSection,
    pub egress: EgressSection,
    pub transcript_watch: TranscriptWatchSection,
}

// ── OSV.dev vulnerability lookups ───────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct OsvSection {
    /// Query https://api.osv.dev for known vulnerabilities when an agent runs a
    /// package install (npm/pip/cargo/...). Opt-in: this sends the package name
    /// and version to OSV.dev, so it is off by default.
    pub enabled: bool,
}

impl Default for OsvSection {
    fn default() -> Self {
        OsvSection { enabled: false }
    }
}

// ── Transcript forwarding ────────────────────────────────────────────────────

// ── LLM Gateway (OpenAI-compatible proxy) ───────────────────────────────────

// ── Enforcement (per-category policy) ────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct EnforcementSection {
    /// Default action for all categories: observe | alert | block
    pub default_action: String,
    /// Per-category overrides
    pub categories: EnforcementCategories,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct EnforcementCategories {
    pub credential_access: String,     // PE3, E2
    pub data_exfiltration: String,     // E1, E3, E4
    pub privilege_escalation: String,  // PE1, PE2
    pub prompt_injection: String,      // P1-P5
    pub supply_chain: String,          // SC1-SC6
    pub excessive_agency: String,      // EA1-EA4
    pub output_handling: String,       // OH1-OH3
    pub memory_poisoning: String,      // MP1-MP3
    pub tool_misuse: String,           // TM1-TM3
    pub rogue_agent: String,           // RA1, RA2
    pub system_prompt_leakage: String, // P6-P8
    pub mcp_tool_poisoning: String,    // TP1-TP3
    pub harmful_content: String,       // P5
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct DaemonSection {
    /// debug | info | warn | error
    pub log_level: String,
    /// observe | enforce
    pub mode: String,
    pub socket_path: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct HttpApiSection {
    pub enabled: bool,
    pub bind: String,
    pub tls_cert: Option<String>,
    pub tls_key: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct SiemSection {
    pub splunk_url: Option<String>,
    pub splunk_token: Option<String>,
    pub splunk_index: Option<String>,
    pub sentinel_workspace_id: Option<String>,
    pub sentinel_key: Option<String>,
    pub elasticsearch_url: Option<String>,
    pub elasticsearch_index: Option<String>,
    pub elasticsearch_api_key: Option<String>,
    pub syslog_host: Option<String>,
    pub syslog_port: Option<u16>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct PolicySection {
    pub bundle_dir: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct DlpSection {
    /// Enable context-aware DLP key routing (default: true when TLS proxy enabled)
    pub enabled: bool,
    /// Block keys going to unauthorized providers (false = warn only)
    pub enforce: bool,
    /// Custom key→destination routes loaded from environment variables
    pub key_routes: Vec<DlpKeyRouteEntry>,
    /// PII detection/redaction settings
    pub pii: PiiSection,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct PiiSection {
    pub ssn: bool,
    pub credit_card: bool,
    pub email: bool,
    pub phone: bool,
    pub ip_address: bool,
    /// What to do when PII is detected: block the connection or just redact in logs.
    pub action: PiiAction,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DlpKeyRouteEntry {
    /// Environment variable holding the key value, e.g. "OPENAI_API_KEY"
    pub env_var: String,
    /// Allowed destination domain, e.g. "api.openai.com"
    pub destination: String,
}

// ── Defaults ──────────────────────────────────────────────────────────────────

impl Default for DaemonConfig {
    fn default() -> Self {
        DaemonConfig {
            daemon: DaemonSection::default(),
            http_api: HttpApiSection::default(),
            siem: SiemSection::default(),
            policy: PolicySection::default(),
            dlp: DlpSection::default(),
            slm: crate::analyzer::slm::SlmConfig::default(),
            model_armor: crate::scanner::model_armor::ModelArmorConfig::default(),
            enforcement: EnforcementSection::default(),
            osv: OsvSection::default(),
            webhooks: crate::integrations::webhook::WebhooksSection::default(),
            checks: ChecksSection::default(),
            scanner: ScannerSection::default(),
            stdio_capture: StdioCaptureSection::default(),
            egress: EgressSection::default(),
            transcript_watch: TranscriptWatchSection::default(),
        }
    }
}

impl Default for EnforcementSection {
    fn default() -> Self {
        EnforcementSection {
            default_action: "observe".into(),
            categories: EnforcementCategories::default(),
        }
    }
}

impl Default for EnforcementCategories {
    fn default() -> Self {
        let o = || "observe".to_string();
        EnforcementCategories {
            credential_access: o(),
            data_exfiltration: o(),
            privilege_escalation: o(),
            prompt_injection: o(),
            supply_chain: o(),
            excessive_agency: o(),
            output_handling: o(),
            memory_poisoning: o(),
            tool_misuse: o(),
            rogue_agent: o(),
            system_prompt_leakage: o(),
            mcp_tool_poisoning: o(),
            harmful_content: o(),
        }
    }
}

impl Default for DaemonSection {
    fn default() -> Self {
        DaemonSection {
            log_level: "info".into(),
            mode: "enforce".into(),
            socket_path: None,
        }
    }
}

impl Default for HttpApiSection {
    fn default() -> Self {
        HttpApiSection {
            enabled: true,
            bind: "127.0.0.1:7700".into(),
            tls_cert: None,
            tls_key: None,
        }
    }
}

impl Default for SiemSection {
    fn default() -> Self {
        SiemSection {
            splunk_url: None,
            splunk_token: None,
            splunk_index: None,
            sentinel_workspace_id: None,
            sentinel_key: None,
            elasticsearch_url: None,
            elasticsearch_index: None,
            elasticsearch_api_key: None,
            syslog_host: None,
            syslog_port: None,
        }
    }
}

impl Default for PolicySection {
    fn default() -> Self {
        PolicySection { bundle_dir: None }
    }
}

impl Default for PiiSection {
    fn default() -> Self {
        PiiSection {
            ssn: true,
            credit_card: true,
            email: true,
            phone: true,
            ip_address: false,
            action: PiiAction::default(), // Block
        }
    }
}

impl Default for DlpSection {
    fn default() -> Self {
        DlpSection {
            enabled: true,
            enforce: true,
            key_routes: vec![],
            pii: PiiSection::default(),
        }
    }
}

// ── Load / save ───────────────────────────────────────────────────────────────

impl DaemonConfig {
    /// Load config from disk. Returns defaults if file not found.
    pub fn load() -> Self {
        let path = config_path();
        match std::fs::read_to_string(&path) {
            Ok(content) => match toml::from_str(&content) {
                Ok(cfg) => {
                    tracing::info!(path = %path.display(), "Config loaded");
                    cfg
                }
                Err(e) => {
                    tracing::warn!(path = %path.display(), err = %e, "Config parse error — using defaults");
                    DaemonConfig::default()
                }
            },
            Err(_) => {
                tracing::info!(path = %path.display(), "Config not found — using defaults");
                DaemonConfig::default()
            }
        }
    }

    /// Load config from disk, refusing to fall back to defaults when the file
    /// exists but is invalid. Used at startup (a security daemon should not
    /// silently run with default policy because of a typo) and on reload
    /// (keep the previous config instead). A missing file still yields defaults.
    pub fn load_strict() -> Result<Self> {
        let path = config_path();
        match std::fs::read_to_string(&path) {
            Ok(content) => {
                let cfg: DaemonConfig = toml::from_str(&content)
                    .map_err(|e| anyhow::anyhow!("{}: {}", path.display(), e))?;
                cfg.webhooks
                    .validate()
                    .map_err(|e| anyhow::anyhow!("{}: [webhooks] {}", path.display(), e))?;
                tracing::info!(path = %path.display(), "Config loaded");
                Ok(cfg)
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                tracing::info!(path = %path.display(), "Config not found — using defaults");
                Ok(DaemonConfig::default())
            }
            Err(e) => Err(anyhow::anyhow!("{}: {}", path.display(), e)),
        }
    }

    /// Convert the [siem] section into a SiemConfig for the forwarder.
    pub fn to_siem_config(&self) -> SiemConfig {
        let mut targets = Vec::new();

        if let (Some(url), Some(token)) = (&self.siem.splunk_url, &self.siem.splunk_token) {
            targets.push(SiemTarget::SplunkHec {
                url: url.clone(),
                token: token.clone(),
                index: self.siem.splunk_index.clone(),
            });
        }

        if let (Some(url), Some(index)) =
            (&self.siem.elasticsearch_url, &self.siem.elasticsearch_index)
        {
            targets.push(SiemTarget::Elasticsearch {
                url: url.clone(),
                index: index.clone(),
                api_key: self.siem.elasticsearch_api_key.clone(),
            });
        }

        if let (Some(host), Some(port)) = (&self.siem.syslog_host, self.siem.syslog_port) {
            targets.push(SiemTarget::Syslog {
                host: host.clone(),
                port,
                facility: 16, // local0
            });
        }

        // Microsoft Sentinel — registered separately via SiemTarget::Sentinel
        if let (Some(workspace_id), Some(key)) =
            (&self.siem.sentinel_workspace_id, &self.siem.sentinel_key)
        {
            targets.push(SiemTarget::Sentinel {
                workspace_id: workspace_id.clone(),
                shared_key: key.clone(),
                log_type: "RingZeroEvents".into(),
            });
        }

        SiemConfig {
            enabled: !targets.is_empty(),
            targets,
        }
    }

    /// Returns true if daemon is in enforce mode.
    pub fn is_enforce(&self) -> bool {
        self.daemon.mode.eq_ignore_ascii_case("enforce")
    }
}

/// Config file path: `$RINGZERO_CONFIG`, else `/etc/ringzero/daemon.toml`
/// when running as root, else `~/.config/ringzero/daemon.toml` (dev runs).
pub fn config_path() -> PathBuf {
    if let Ok(p) = std::env::var("RINGZERO_CONFIG") {
        return PathBuf::from(p);
    }

    if crate::platform::is_elevated() {
        PathBuf::from("/etc/ringzero/daemon.toml")
    } else {
        dirs_next::config_dir()
            .unwrap_or_else(|| PathBuf::from("/tmp"))
            .join("ringzero/daemon.toml")
    }
}

/// Write a default config template to the config path (first-run).
#[allow(dead_code)]
pub fn write_default_template() -> Result<()> {
    let path = config_path();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let template = r#"# Ring Zero Security — Daemon Configuration
# Reload: sudo kill -HUP $(pidof ringzero-daemon)

[daemon]
log_level   = "info"    # debug | info | warn | error
mode        = "enforce" # observe | enforce
# socket_path = "/var/run/ringzero/daemon.sock"

[http_api]
enabled = true
bind    = "127.0.0.1:7700"
# tls_cert = "/etc/ringzero/certs/daemon.crt"
# tls_key  = "/etc/ringzero/certs/daemon.key"

[console]
# url                = "https://console.ringzerosecurity.com"
# registration_token = "rz_reg_..."

[siem]
# Splunk HTTP Event Collector
# splunk_url   = "https://splunk.example.com:8088/services/collector/event"
# splunk_token = "rz_splunk_..."
# splunk_index = "ringzero"

# Microsoft Sentinel (Log Analytics)
# sentinel_workspace_id = "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
# sentinel_key          = "base64encodedkey=="

# Elasticsearch
# elasticsearch_url       = "https://es.example.com:9200"
# elasticsearch_index     = "ringzero-events"
# elasticsearch_api_key   = "..."

# Syslog / CEF
# syslog_host = "siem.example.com"
# syslog_port = 514

[policy]
# bundle_dir = "/etc/ringzero/policy"

[dlp]
enabled = true
enforce = true
# Custom key routes: reads env var at startup, blocks if sent to wrong host
# key_routes = [{ env_var = "CUSTOM_API_KEY", destination = "api.mycorp.com" }]
key_routes = []

[dlp.pii]
ssn         = true
credit_card = true
email       = true
phone       = true
ip_address  = false
action      = "block"   # block | redact — block records a blocked event, redact masks in logs

[pattern_reload]
enabled             = false
url                 = "https://patterns.ringzerosecurity.com/v1/patterns.json"
check_interval_secs = 3600
# public_key_hex    = "hex-encoded Ed25519 public key"

[updater]
enabled             = false
manifest_url        = "https://updates.ringzerosecurity.com/v1/manifest.json"
check_interval_secs = 21600

[crash_report]
# Opt-in: sends minimal crash data (no user data, no file paths)
enabled = false
# endpoint = "https://telemetry.ringzerosecurity.com/v1/crash"

[cloud_sync]
# Sync security events to the Ring Zero cloud console
enabled = false
sync_interval_secs = 60

[slm]
# Security analyzer using Graph RAG + LLM inference
# Modes: off | local | cloud
#   local — Ollama (any model at 127.0.0.1:11434)
#   cloud — Google Gemini API (gemma-4-27b-it by default)
mode = "off"
# model_path = "gemma3:4b"         # Ollama model name for local mode
# cloud_model = "gemma-4-27b-it"   # Gemini model ID for cloud mode
# gemini_api_key = ""               # or set GEMINI_API_KEY env var
context_window = 20
score_threshold = 40

[model_armor]
# Prompt injection detection — local heuristic patterns, runs offline.
enabled            = true
mode               = "heuristic"
scan_live_traffic  = false
enforce            = false

[osv]
# Opt-in: look up packages an agent installs (npm/pip/cargo/...) against
# https://api.osv.dev. Sends the package name + version to OSV.dev.
enabled = false

# ── Detection webhooks (off until you add an endpoint or a hook) ─────────────
# Reference and an example receiver: docs/integrations.md
# Async event stream: every agent event is POSTed as JSON, HMAC-SHA256 signed,
# after redaction. Sync verdict hooks wait up to timeout_ms for
# {"verdict": "allow"|"deny"}; fail_mode ("open" | "closed") is REQUIRED.
[webhooks]
queue_size = 10000

# [[webhooks.endpoints]]
# name        = "ml-scorer"
# url         = "https://scoring.example.com/ringzero/events"
# secret      = "replace-with-a-long-random-string"
# event_types = ["*"]
# timeout_ms  = 5000
# retries     = 3

# A local file sink: one JSON line per event, appended (created 0600).
# [[webhooks.endpoints]]
# name        = "audit-file"
# url         = "file:///var/log/ringzero/events.jsonl"
# secret      = "replace-with-a-long-random-string"   # optional; signs each line
# event_types = ["*"]

# [[webhooks.verdict_hooks]]
# name        = "policy-engine"
# url         = "http://127.0.0.1:8081/verdict"
# event_types = ["process_exec", "file_open", "network_connect"]
# timeout_ms  = 250
# fail_mode   = "open"
# secret      = "replace-with-a-long-random-string"

[webhooks.redaction]
enabled          = true
builtin_patterns = true
patterns         = []
drop_fields      = []
replacement      = "[REDACTED]"

# ── Transcript forwarding (off by default) ───────────────────────────────────
# Forwards every line appended to the agents' transcript files (Claude Code
# ~/.claude/projects, Codex ~/.codex/sessions, Gemini CLI ~/.gemini/tmp) as
# transcript_write events to your webhook endpoints. That is the agent's whole
# conversation — enable only with endpoints you trust. Nothing is stored by
# the daemon.
[transcripts]
enabled         = false
max_event_bytes = 16384
extra_dirs      = []

# ── Enforcement (per-category policy) ────────────────────────────────────────
# Maps to SkillSpector's threat categories.
# Actions: observe (log only) | alert (log + UI alert) | block
[enforcement]
default_action = "observe"

[enforcement.categories]
credential_access     = "observe"
data_exfiltration     = "observe"
privilege_escalation  = "observe"
prompt_injection      = "observe"
supply_chain          = "observe"
excessive_agency      = "observe"
output_handling       = "observe"
memory_poisoning      = "observe"
tool_misuse           = "observe"
rogue_agent           = "observe"
system_prompt_leakage = "observe"
mcp_tool_poisoning    = "observe"
harmful_content       = "observe"
"#;
    std::fs::write(&path, template)?;
    tracing::info!(path = %path.display(), "Default config template written");
    Ok(())
}

// ── Checks (deterministic scorers, off the syscall path) ────────────────────

/// Checks label what an agent is ABOUT TO DO. They never allow or deny
/// anything: a result is an observation written into the trace and joined to
/// the kernel's real decision by session id. Off by default.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ChecksSection {
    /// Run the checks layer on agent hook events. OFF by default: with the
    /// default provider, turning this on calls a third-party API.
    pub enabled: bool,
    /// Which scorer decides. "jev" (default) uses TypeSafe's hosted model;
    /// "deterministic" keeps everything on the machine.
    pub provider: String,
    /// Settings for the hosted provider.
    #[serde(default)]
    pub jev: JevSection,
    /// The numbers this layer judges by. Defaults are the values the layer
    /// shipped with; see checks/src/thresholds.rs for what each one changes.
    #[serde(default)]
    pub thresholds: ringzero_checks::thresholds::Thresholds,
    /// The directory the agent is expected to work in. A write outside it is
    /// scored by check 3. Empty means the check cannot judge and stays quiet.
    pub workspace: Option<String>,
    /// Hosts the operator has approved for outbound tool calls.
    pub approved_hosts: Vec<String>,

    /// Let the agent's tool-call hook DENY a call, instead of only recording it.
    ///
    /// Off by default. With this off the hook is fire-and-forget exactly as
    /// before and adds no latency. With it on, the hook waits for a decision,
    /// so `fail_mode` becomes required: there is no safe default for "what
    /// happens when the scorer cannot answer".
    ///
    /// This layer is app-level and bypassable — an agent can write and run its
    /// own binary, which `examples/boundary-demo.sh` demonstrates. The kernel
    /// remains the only boundary that holds.
    pub blocking: bool,

    /// Required when `blocking = true`: "open" lets the call through when no
    /// decision arrives, "closed" denies it. No default, deliberately.
    pub fail_mode: Option<String>,

    /// How long the hook may wait for a decision.
    pub timeout_ms: u64,

    /// Seconds to remember a decision for an identical tool call, so a loop
    /// over one path does not pay per call.
    pub cache_ttl_secs: u64,
}

impl Default for ChecksSection {
    fn default() -> Self {
        ChecksSection {
            enabled: false,
            provider: "jev".to_string(),
            jev: JevSection::default(),
            thresholds: ringzero_checks::thresholds::Thresholds::default(),
            workspace: None,
            approved_hosts: Vec::new(),
            blocking: false,
            fail_mode: None,
            timeout_ms: 1500,
            cache_ttl_secs: 30,
        }
    }
}

// ── Optional hosted scoring provider (TypeSafe Jev) ─────────────────────────

/// Turning this on sends agent tool-call context to a third-party API, so it
/// is off by default and inert without a key. The key is never in this file:
/// it is read from `api_key_file`, which must be 0600 and owned by root.
///
/// The provider can only ever RAISE a deterministic score. It cannot clear a
/// deny or downgrade a flag, and the kernel never waits on it.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct JevSection {
    pub enabled: bool,
    /// Path to a file containing only the API key. 0600, root-owned.
    pub api_key_file: String,
    pub model: String,
    /// Origin of the scoring service. The path is always `/v1/systemone`.
    /// Point this at your own endpoint when you have one — a self-hosted or
    /// fine-tuned model serving the same contract drops in with no code change.
    pub base_url: String,
    pub timeout_ms: u64,
}

impl Default for JevSection {
    fn default() -> Self {
        JevSection {
            enabled: false,
            api_key_file: "/etc/ringzero/typesafe.key".to_string(),
            model: "jev-latest".to_string(),
            base_url: "https://api.typesafe.ai".to_string(),
            timeout_ms: 1500,
        }
    }
}

impl ChecksSection {
    /// Reject a blocking configuration that has not said what to do when the
    /// scorer cannot answer. Guessing here means guessing whether a developer
    /// gets blocked or goes unprotected during an outage.
    /// Refuse a threshold set that cannot mean anything sensible.
    ///
    /// Clamping quietly would leave an operator believing a band was where
    /// they put it. Every problem is reported at once so a config is fixed in
    /// one pass rather than one restart at a time.
    pub fn validate_thresholds(&self) -> Result<(), String> {
        self.thresholds.validate().map_err(|errs| errs.join("\n"))
    }

    pub fn validate_blocking(&self) -> Result<(), String> {
        if !self.blocking {
            return Ok(());
        }
        match self.fail_mode.as_deref() {
            Some("open") | Some("closed") => Ok(()),
            Some(other) => Err(format!(
                "[checks] fail_mode = {other:?} is not valid; use \"open\" or \"closed\""
            )),
            None => Err(
                "[checks] blocking = true requires fail_mode = \"open\" or \"closed\". \
                 There is no default: with a network-backed scorer an outage either blocks \
                 your developers (closed) or leaves that path unprotected (open), and that \
                 is your decision to make."
                    .to_string(),
            ),
        }
    }

    /// True when a failure to decide should deny the call.
    pub fn fail_closed(&self) -> bool {
        self.fail_mode.as_deref() == Some("closed")
    }
}

impl JevSection {
    /// Read the key. An operator who selected the hosted provider must get it
    /// or be told plainly — a silent downgrade to the local scorer would mean
    /// they think a model is running when none is. The error text names the
    /// path so the fix is obvious.
    pub fn load_key(&self) -> Result<String, String> {
        let path = std::path::Path::new(&self.api_key_file);
        let meta =
            std::fs::metadata(path).map_err(|e| format!("cannot read {}: {e}", path.display()))?;

        use std::os::unix::fs::PermissionsExt;
        let mode = meta.permissions().mode();
        if mode & 0o077 != 0 {
            return Err(format!(
                "{} is mode {:o}; it must not be readable by group or others (chmod 600)",
                path.display(),
                mode & 0o777
            ));
        }
        let key = std::fs::read_to_string(path)
            .map_err(|e| format!("cannot read {}: {e}", path.display()))?;
        if key.trim().is_empty() {
            return Err(format!("{} is empty", path.display()));
        }
        Ok(key.trim().to_string())
    }
}

// ── Scanning what an agent writes ───────────────────────────────────────────

/// Scan a file an agent wrote, the moment the write finishes.
///
/// Detection is fanotify CLOSE_WRITE, mount-wide, with the writing pid. Only
/// files written from inside a tracked agent tree are read at all.
///
/// ENFORCEMENT IS OFF BY DEFAULT. With `enforce = false` a flagged file is
/// recorded and still runs. With it on, the kernel refuses to open or exec a
/// file that a DETERMINISTIC pattern flagged at or above `enforce_severity`. A
/// model verdict can never cause a refusal; see `write_scan::decide`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct WriteScanSection {
    /// Watch for finished writes by agents and scan them.
    pub enabled: bool,
    /// Let the kernel refuse a quarantined file. OFF by default.
    pub enforce: bool,
    /// The worst deterministic severity that still runs. "critical", "high",
    /// "medium" or "low"; anything at or above it is refused when `enforce` is
    /// on.
    pub enforce_severity: String,
    /// Mounts to watch. One entry per filesystem an agent writes to.
    pub mounts: Vec<String>,
    /// File extensions worth reading when nothing else about the file says so.
    pub extensions: Vec<String>,
    /// Largest file read, in bytes. Anything bigger is recorded and skipped.
    pub max_file_bytes: usize,
    /// Cap on scans per minute. Reaching it is logged, never silent.
    pub max_scans_per_minute: usize,
    /// Hold an agent-written file unusable until it has been scanned.
    ///
    /// There is a window between the write closing and the verdict being
    /// stored, during which the file is usable. Default false: the window is
    /// short and measured, and a pause on every agent-written file is a real
    /// cost. See README for the measured number.
    pub fail_closed: bool,
}

impl Default for WriteScanSection {
    fn default() -> Self {
        WriteScanSection {
            enabled: true,
            // OFF. Refusing to run a file is a sharper thing than anything else
            // this daemon does by default.
            enforce: false,
            enforce_severity: "high".to_string(),
            mounts: vec!["/home".to_string(), "/tmp".to_string()],
            extensions: crate::write_scan::default_extensions(),
            max_file_bytes: 1024 * 1024,
            max_scans_per_minute: 120,
            fail_closed: false,
        }
    }
}

impl WriteScanSection {
    /// The severity bar, parsed. An unrecognised value is treated as the
    /// strictest reading rather than as "off", and `validate` refuses it
    /// before the daemon starts.
    pub fn enforce_severity(&self) -> crate::scanner::patterns::models::Severity {
        use crate::scanner::patterns::models::Severity;
        match self.enforce_severity.trim().to_ascii_lowercase().as_str() {
            "low" => Severity::Low,
            "medium" => Severity::Medium,
            "high" => Severity::High,
            _ => Severity::Critical,
        }
    }

    pub fn validate(&self) -> Result<(), String> {
        let allowed = ["low", "medium", "high", "critical"];
        let v = self.enforce_severity.trim().to_ascii_lowercase();
        if !allowed.contains(&v.as_str()) {
            return Err(format!(
                "[scanner.write_scan] enforce_severity = {:?} is not one of low, medium, high,                  critical",
                self.enforce_severity
            ));
        }
        if self.max_file_bytes == 0 {
            return Err("[scanner.write_scan] max_file_bytes = 0 would scan nothing".to_string());
        }
        if self.max_scans_per_minute == 0 {
            return Err(
                "[scanner.write_scan] max_scans_per_minute = 0 would scan nothing; set enabled =                  false instead"
                    .to_string(),
            );
        }
        if self.enabled && self.mounts.is_empty() {
            return Err(
                "[scanner.write_scan] enabled with no mounts to watch; add at least one"
                    .to_string(),
            );
        }
        Ok(())
    }
}

// ── Egress narrowing on taint ────────────────────────────────────────────────

/// Whether the kernel refuses off-allowlist connections from a process that
/// ingested external content, and where the allowlist comes from.
///
/// ENFORCEMENT IS OFF BY DEFAULT. With `enforce = false` a tainted process's
/// off-allowlist connect is recorded and allowed. With it on, socket_connect
/// returns -EACCES. Loopback and the resolved LLM API endpoints are always
/// allowed so the agent keeps working; `allow` is the operator's additions.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct EgressSection {
    /// Let the kernel refuse off-allowlist egress from a tainted process.
    pub enforce: bool,
    /// Extra destinations a tainted process may still reach. Host or IP; a host
    /// is resolved once at startup. Loopback and the LLM endpoints are allowed
    /// without being listed here.
    ///
    /// Prefer `allow_names` for anything behind a CDN: resolving a name once at
    /// startup gives addresses the agent may never use.
    pub allow: Vec<String>,
    /// Hostnames allowed by NAME, admitted from observed DNS answers with the
    /// record's TTL. A leading dot means the name and any subdomain of it.
    ///
    /// This is what a CDN-fronted endpoint needs. A static address list cannot
    /// work for one: the daemon resolved api.anthropic.com at boot and held 42
    /// addresses, the agent resolved it later and used 160.79.104.10, which was
    /// not among them, so the agent's own model calls read as external.
    pub allow_names: Vec<String>,
    /// Raise taint in the kernel when an agent-tree process connects off the
    /// allowlist. This is the PRIMARY signal that external content arrived.
    ///
    /// WHY IT IS HERE AND NOT IN THE TRANSCRIPT WATCHER. A real agent reaches
    /// the network with whatever is to hand. Asked to read a web page, Claude
    /// Code ran `curl` through Bash rather than calling a fetch tool, so a
    /// watcher matching tool names in the transcript saw nothing and the agent
    /// kept full egress authority. Every one of those routes still has to call
    /// `connect(2)`, which the kernel already sees, so the fact is structural
    /// and there is nothing to evade.
    ///
    /// Separate from `enforce` on purpose: this only records a bit, so an
    /// operator can turn it on and measure how often a normal session taints
    /// before deciding to refuse anything on the strength of it.
    pub taint_on_egress: bool,
}

impl Default for EgressSection {
    fn default() -> Self {
        EgressSection {
            enforce: false,
            allow: Vec::new(),
            // The model endpoints, by name, so a CDN cannot desynchronise the
            // allowlist from what the agent actually resolves.
            allow_names: vec![
                ".anthropic.com".to_string(),
                ".openai.com".to_string(),
                ".githubcopilot.com".to_string(),
                ".googleapis.com".to_string(),
            ],
            taint_on_egress: false,
        }
    }
}

// ── Transcript taint watcher ─────────────────────────────────────────────────

/// Watching agent transcripts to raise taint when external content is ingested.
///
/// READ THIS. The watcher reads each agent's JSONL transcript incrementally and
/// raises taint on that agent's process tree when a record shows a web fetch, a
/// web search or an MCP tool result — a deterministic provenance fact, never a
/// judgment about the content. It reads no file content off the machine and
/// stores nothing: it acts on the tool NAME in the transcript and sets one bit
/// in the kernel. It has its own switch so an operator can run egress
/// enforcement seeded some other way without it.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct TranscriptWatchSection {
    /// Watch transcripts and raise taint on external ingestion.
    pub enabled: bool,
}

impl Default for TranscriptWatchSection {
    fn default() -> Self {
        TranscriptWatchSection { enabled: true }
    }
}

// ── Terminal capture ────────────────────────────────────────────────────────

/// Reading what an agent prints to its terminal.
///
/// READ THIS BEFORE TURNING IT ON OR LEAVING IT ON. This captures the text an
/// agent writes to, and reads from, its terminal. That text is whatever the
/// agent happened to print, which can include secrets it was legitimately
/// working with. It is captured in the kernel, below the agent, so it does not
/// depend on the agent cooperating and cannot be turned off from inside the
/// agent.
///
/// Every captured fragment goes through the same redactor the webhook and
/// checks paths use before it is stored or scored. Nothing captured is written
/// anywhere unredacted, and captured text only leaves the machine if the checks
/// layer is enabled with a hosted provider AND the deterministic scorer already
/// flagged that fragment.
///
/// It is its own switch so that an operator can have kernel enforcement with no
/// terminal capture at all.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct StdioCaptureSection {
    /// Capture agent terminal I/O. On by default: with agent hooks opt-in,
    /// this and the kernel event stream are what the checks layer has to work
    /// with. Set to false for kernel enforcement with no capture.
    pub enabled: bool,
    /// Longest captured fragment stored on one event, in bytes, after
    /// redaction. A fragment longer than this is truncated; the event says so.
    pub max_event_bytes: usize,
    /// Score captured output with the checks layer. Requires [checks] enabled.
    /// Turning this off keeps capture in the timeline without scoring it.
    pub score: bool,
}

impl Default for StdioCaptureSection {
    fn default() -> Self {
        StdioCaptureSection {
            enabled: true,
            max_event_bytes: 4096,
            score: true,
        }
    }
}

// ── Scanner ─────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ScannerSection {
    pub jev: ScannerJevSection,
    /// Scanning files an agent wrote. Read as `[scanner.write_scan]`.
    ///
    /// It lives here rather than at the top level because that is the section
    /// name the docs and the config use. Wired at the top level it parsed as an
    /// unknown key under [scanner], silently fell back to defaults, and
    /// `enforce = true` never reached the kernel.
    #[serde(default)]
    pub write_scan: WriteScanSection,
}

impl Default for ScannerSection {
    fn default() -> Self {
        ScannerSection {
            jev: ScannerJevSection::default(),
            write_scan: WriteScanSection::default(),
        }
    }
}

/// Optional model layer over the pattern scanner.
///
/// Its own switch, separate from `[checks.jev]`, because the disclosure is
/// bigger: this sends file CONTENT to a third party, where the checks send
/// structured tool-call fields. Someone may want model-scored tool calls
/// without shipping their skill files off the machine.
///
/// Monotonic: it may raise a finding's severity or add one the patterns missed.
/// It can never clear, downgrade or suppress a pattern finding.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ScannerJevSection {
    pub enabled: bool,
    /// 0600, root-owned. Shared with [checks.jev] by default.
    pub api_key_file: String,
    pub model: String,
    /// Origin of the service; the path is always /v1/systemone. Point this at
    /// your own endpoint when you have one.
    pub base_url: String,
    pub timeout_ms: u64,
    /// Cap on model calls per scan. Reaching it is reported in the scan output,
    /// never silently scanned less.
    pub max_calls_per_scan: usize,
    /// Bytes of file content sent per file, after redaction.
    pub max_bytes_per_file: usize,
}

impl Default for ScannerJevSection {
    fn default() -> Self {
        ScannerJevSection {
            enabled: false,
            api_key_file: "/etc/ringzero/typesafe.key".to_string(),
            model: "jev-latest".to_string(),
            base_url: "https://api.typesafe.ai".to_string(),
            timeout_ms: 4000,
            max_calls_per_scan: 40,
            max_bytes_per_file: 8 * 1024,
        }
    }
}

impl ScannerJevSection {
    /// Read the key, refusing a group- or world-readable file. Returns the
    /// reason on failure so the scan report can state it.
    pub fn load_key(&self) -> Result<String, String> {
        let path = std::path::Path::new(&self.api_key_file);
        let meta =
            std::fs::metadata(path).map_err(|e| format!("cannot read {}: {e}", path.display()))?;
        use std::os::unix::fs::PermissionsExt;
        let mode = meta.permissions().mode();
        if mode & 0o077 != 0 {
            return Err(format!(
                "{} is mode {:o}; it must not be readable by group or others (chmod 600)",
                path.display(),
                mode & 0o777
            ));
        }
        let key = std::fs::read_to_string(path)
            .map_err(|e| format!("cannot read {}: {e}", path.display()))?;
        if key.trim().is_empty() {
            return Err(format!("{} is empty", path.display()));
        }
        Ok(key.trim().to_string())
    }
}

#[cfg(test)]
mod blocking_tests {
    use super::*;

    #[test]
    fn blocking_without_a_fail_mode_is_refused() {
        let mut c = ChecksSection::default();
        c.blocking = true;
        c.fail_mode = None;
        let err = c.validate_blocking().expect_err("must refuse");
        assert!(err.contains("requires fail_mode"), "got: {err}");
        assert!(err.contains("your decision to make"), "says why: {err}");
    }

    #[test]
    fn blocking_accepts_only_open_or_closed() {
        let mut c = ChecksSection::default();
        c.blocking = true;
        for good in ["open", "closed"] {
            c.fail_mode = Some(good.to_string());
            assert!(c.validate_blocking().is_ok(), "{good} should be valid");
        }
        c.fail_mode = Some("maybe".to_string());
        assert!(c.validate_blocking().is_err());
    }

    #[test]
    fn fail_closed_is_only_true_for_closed() {
        let mut c = ChecksSection::default();
        c.fail_mode = Some("closed".into());
        assert!(c.fail_closed());
        c.fail_mode = Some("open".into());
        assert!(!c.fail_closed());
        c.fail_mode = None;
        assert!(!c.fail_closed(), "absent must not mean closed");
    }

    #[test]
    fn not_blocking_needs_no_fail_mode() {
        let c = ChecksSection::default();
        assert!(!c.blocking);
        assert!(c.validate_blocking().is_ok());
    }
}
