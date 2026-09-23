// SPDX-License-Identifier: Apache-2.0
// ringzero-daemon — main entry point
// Ring Zero Security (ringzerosecurity.com)

mod analyzer;
mod api;
mod audit;
mod checks_provider;
mod common;
mod config;
mod dns_allow;
mod ebpf_loader;
mod enforcement;
mod fscache;
mod health;
mod integrations;
mod ipc;
mod platform;
mod policy;
mod review;
mod scanner;
mod secrets;
mod session;
mod siem;
mod skill_correlation;
mod stdio_capture;
mod transcript_taint;
mod write_scan;

use anyhow::Result;
use chrono::Utc;
use nix::libc;
use std::{collections::HashMap, path::PathBuf, sync::Arc};
use tokio::sync::{mpsc, RwLock};
use tracing_subscriber::EnvFilter;

use analyzer::{
    baseline::BaselineEngine, correlation::CorrelationEngine, heuristics, observer::ObserverEngine,
};
use audit::AuditLog;
use common::event::{EventKind, SecurityEvent};
use common::protocol::{DaemonMessage, DriverMessage};
use ipc::server::IpcServer;
use policy::intent_policy::IntentAwarePolicy;
use policy::{
    acl::{AclEngine, Decision},
    network::NetworkPolicy,
};
use scanner::{
    model_armor::{scan_file_for_injection, InjectionVerdict, ModelArmorConfig},
    supply_chain,
    verified_registry::VerifiedRegistry,
    watcher,
};
use secrets::dlp::DlpEngine;
use secrets::rotation::RotationStore;
use session::jwt::JwtIssuer;
use session::store::{AgentType, PrivEscEvent, Session, SessionState};
use session::SessionStore;
use siem::forwarder::SiemForwarder;

// ── socket paths ─────────────────────────────────────────────────────────────

fn daemon_sock() -> PathBuf {
    PathBuf::from("/var/run/ringzero/daemon.sock")
}

fn dev_sock() -> PathBuf {
    let xdg = std::env::var("XDG_RUNTIME_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| std::env::temp_dir());
    xdg.join("ringzero").join("daemon.sock")
}

fn event_type_to_kind(t: u32) -> EventKind {
    // Must match the C enum values in drivers/linux/ebpf/ringzero.bpf.c
    match t {
        1 => EventKind::FileOpen,
        2 => EventKind::FileCreate,
        3 => EventKind::FileDelete,
        4 => EventKind::FileRename,
        5 => EventKind::FileWrite,
        10 => EventKind::ProcessExec,
        11 => EventKind::ProcessFork,
        12 => EventKind::ProcessExit,
        20 => EventKind::NetworkConnect,
        25 => EventKind::MprotectWx,
        30 => EventKind::NetworkSend,
        31 => EventKind::DlpPii,
        40 => EventKind::DnsQuery,
        _ => {
            tracing::warn!(event_type = t, "Unknown eBPF event type");
            EventKind::FileOpen
        }
    }
}

// ── AI agent auto-detection ──────────────────────────────────────────────────

fn detect_agent_type(process: &str) -> Option<AgentType> {
    if !common::agent_detect::is_ai_agent(process) {
        return None;
    }
    let class = common::agent_detect::classify_agent(process);
    match class {
        "claude" => Some(AgentType::Claude),
        "cursor" => Some(AgentType::Cursor),
        "copilot" => Some(AgentType::Copilot),
        "codex" => Some(AgentType::Codex),
        "chatgpt" => Some(AgentType::ChatGpt),
        "gemini" => Some(AgentType::Gemini),
        "devin" => Some(AgentType::Devin),
        "aider" => Some(AgentType::Custom("aider".to_string())),
        "windsurf" => Some(AgentType::Custom("windsurf".to_string())),
        "agy" | "antigravity" => Some(AgentType::Custom("antigravity".to_string())),
        "custom" => None, // Don't create sessions for unrecognized processes
        other => Some(AgentType::Custom(other.to_string())),
    }
}

// ── process tree helpers ─────────────────────────────────────────────────────
//
// PID metadata is queried per kernel event (in the hot loop), so we cache it
// with a small TTL so recycled PIDs don't surface stale metadata for long.

use std::sync::Mutex as StdMutex;
use std::time::{Duration, Instant};

#[derive(Clone)]
struct ProcMetaEntry {
    ppid: Option<u32>,
    comm: Option<String>,
    fetched_at: Instant,
}

const PROC_META_TTL: Duration = Duration::from_secs(5);
const PROC_META_MAX_ENTRIES: usize = 4096;

static PROC_META_CACHE: once_cell::sync::Lazy<
    StdMutex<std::collections::HashMap<u32, ProcMetaEntry>>,
> = once_cell::sync::Lazy::new(|| StdMutex::new(std::collections::HashMap::new()));

/// Pull both ppid + comm from /proc in a single shot (two reads, no forks).
/// The result is cached for 5 s; busy hot-paths see HashMap lookups instead
/// of syscalls.
fn fetch_proc_meta(pid: u32) -> ProcMetaEntry {
    let comm = std::fs::read_to_string(format!("/proc/{}/comm", pid))
        .ok()
        .map(|s| s.trim().to_string());
    let ppid = std::fs::read_to_string(format!("/proc/{}/status", pid))
        .ok()
        .and_then(|status| {
            status.lines().find_map(|line| {
                line.strip_prefix("PPid:")
                    .and_then(|rest| rest.trim().parse().ok())
            })
        });
    ProcMetaEntry {
        ppid,
        comm,
        fetched_at: Instant::now(),
    }
}

/// Look up cached metadata or refresh it from the OS.
fn proc_meta(pid: u32) -> ProcMetaEntry {
    let now = Instant::now();
    {
        let guard = PROC_META_CACHE.lock();
        if let Ok(cache) = guard {
            if let Some(entry) = cache.get(&pid) {
                if now.duration_since(entry.fetched_at) < PROC_META_TTL {
                    return entry.clone();
                }
            }
        }
    }
    let fresh = fetch_proc_meta(pid);
    if let Ok(mut cache) = PROC_META_CACHE.lock() {
        if cache.len() > PROC_META_MAX_ENTRIES {
            // Cheap eviction: drop expired entries. Avoids a full LRU but
            // keeps the cache bounded under high churn.
            cache.retain(|_, e| now.duration_since(e.fetched_at) < PROC_META_TTL);
        }
        cache.insert(pid, fresh.clone());
    }
    fresh
}

/// Resolve parent PID from cache (refreshes from /proc if cold).
fn resolve_ppid(pid: u32) -> Option<u32> {
    proc_meta(pid).ppid
}

/// Resolve process name from PID (cached).
fn resolve_comm(pid: u32) -> Option<String> {
    proc_meta(pid).comm
}

/// Kill a process with a TOCTOU re-check: confirm the live `comm` still
/// matches `expected_process` (or at least is non-empty) before sending the
/// signal. Without this, a PID recycled between event arrival and our kill
/// decision would let us hit an unrelated, possibly-critical, system process.
///
/// `kill_group` controls whether we signal the whole process group (-pgid)
/// or just the PID. Group kill is correct for terminal-launched agents but
/// Parent pid of `pid` from /proc/<pid>/status (PPid line). None if unreadable.
fn parent_pid_of(pid: u32) -> Option<u32> {
    let s = std::fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
    s.lines().find_map(|l| {
        l.strip_prefix("PPid:")
            .and_then(|r| r.trim().parse::<u32>().ok())
    })
}

/// Find the session an event belongs to by walking the process ancestry. The
/// agent's real activity (file opens/creates, spawned processes) happens in
/// CHILD processes (gemini → node → cat/touch), whose pid/name don't match the
/// session directly — but an ancestor pid does. Registers the descendant pid to
/// the session so future events from it match by pid. Bounded walk.
fn session_by_ancestry(sessions: &session::store::SessionStore, pid: u32) -> Option<String> {
    let mut cur = parent_pid_of(pid);
    let mut hops = 0;
    while let Some(p) = cur {
        if p <= 1 || hops >= 16 {
            break;
        }
        if let Some(s) = sessions.find_by_pid(p) {
            sessions.register_pid(&s.id, pid);
            return Some(s.id.clone());
        }
        cur = parent_pid_of(p);
        hops += 1;
    }
    None
}

/// can take down a parent shell — call sites decide.
///
/// Returns true if a signal was sent. Logs and returns false on mismatch.
fn verified_kill(pid: u32, expected_process: Option<&str>, signal: i32, kill_group: bool) -> bool {
    use nix::libc;
    // PID safety: never signal kernel/init or pid <= 0.
    if pid <= 1 {
        tracing::warn!(pid, "Refusing to signal pid <= 1");
        return false;
    }
    // Re-check liveness + identity. If the process is already gone, treat the
    // mismatch as a no-op (success-equivalent), since signal(2) would just
    // return ESRCH anyway.
    let live_comm = resolve_comm(pid);
    match (&live_comm, expected_process) {
        (None, _) => {
            tracing::debug!(pid, "Skipping kill: process already exited");
            return false;
        }
        (Some(actual), Some(expected)) => {
            // Exact match, the agent's display name (events carry e.g. "Claude
            // Code" for comm "claude"), or a known agent runtime — all OK.
            let agent_runtimes = ["node", "python3", "python", "ruby", "deno", "bun"];
            if actual != expected
                && ebpf_loader::agent_display_name(actual, &[]) != expected
                && !agent_runtimes.contains(&actual.as_str())
            {
                tracing::warn!(
                    pid,
                    actual = %actual,
                    expected = %expected,
                    "TOCTOU guard: live comm does not match — PID likely recycled, refusing to kill"
                );
                return false;
            }
        }
        (Some(_), None) => { /* No expectation — allow */ }
    }
    unsafe {
        if kill_group {
            let pgid = libc::getpgid(pid as libc::pid_t);
            if pgid > 1 {
                libc::kill(-pgid, signal);
                return true;
            }
        }
        libc::kill(pid as libc::pid_t, signal);
    }
    true
}

// ── entry point ───────────────────────────────────────────────────────────────

/// Is one of our agent hooks actually configured anywhere on this machine?
///
/// The hook is opt-in: the installer only writes it when asked. Several
/// settings depend on it, and a setting that cannot work must say so rather
/// than sit quietly enabled — the same class of bug as a file-access rule that
/// displayed as BLOCK and enforced nothing.
///
/// Best effort by design: it looks for our hook command in the config files the
/// installer writes. A hook configured somewhere else will be missed, which is
/// why this only ever produces a warning.
fn agent_hook_configured() -> bool {
    let mut homes: Vec<std::path::PathBuf> = vec![std::path::PathBuf::from("/root")];
    if let Ok(entries) = std::fs::read_dir("/home") {
        for e in entries.flatten() {
            homes.push(e.path());
        }
    }
    let candidates = [
        ".claude/settings.json",
        ".claude/settings.local.json",
        ".codex/config.toml",
    ];
    for home in &homes {
        for rel in &candidates {
            if let Ok(text) = std::fs::read_to_string(home.join(rel)) {
                if text.contains("rz-hook") {
                    return true;
                }
            }
        }
    }
    false
}

fn main() -> Result<()> {
    // Build tokio runtime with thread names starting with "ringzero-" so the eBPF
    // cgroup/connect hook recognizes them as daemon threads and doesn't redirect
    // their outbound connections. Without this, the proxy's upstream connect() to
    // port 443 gets redirected back to itself → infinite loop → ECONNREFUSED.
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .thread_name("ringzero-wk")
        .build()
        .expect("Failed to build tokio runtime");
    rt.block_on(async_main())
}

async fn async_main() -> Result<()> {
    // Init tracing
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    tracing::info!("Ring Zero Security daemon starting");

    // Install rustls crypto provider (ring) — required before any TLS operations
    let _ = ::rustls::crypto::ring::default_provider().install_default();

    // Load config file. A file that exists but does not parse or validate
    // (e.g. a verdict hook without fail_mode) refuses to start the daemon
    // rather than silently running with default policy.
    let cfg = match config::DaemonConfig::load_strict() {
        Ok(c) => c,
        Err(e) => {
            tracing::error!(err = %e, "Config rejected — refusing to start");
            return Err(e);
        }
    };
    let enforce_mode = cfg.is_enforce();

    // Determine socket path
    let sock = if let Some(ref p) = cfg.daemon.socket_path {
        std::path::PathBuf::from(p)
    } else if platform::is_elevated() {
        daemon_sock()
    } else {
        tracing::warn!("Running as non-root — using dev socket path");
        dev_sock()
    };

    let http_bind = cfg.http_api.bind.clone();

    // Initialise subsystems
    let acl = Arc::new(RwLock::new(AclEngine::new(enforce_mode)));
    let network = Arc::new(NetworkPolicy::new());
    let dlp = Arc::new(DlpEngine::new());

    // Load DLP key routes from config (reads env vars for actual key values)
    if cfg.dlp.enabled {
        let dlp_routes: Vec<secrets::dlp::DlpRouteConfig> = cfg
            .dlp
            .key_routes
            .iter()
            .map(|r| secrets::dlp::DlpRouteConfig {
                key_env_var: r.env_var.clone(),
                destination: r.destination.clone(),
            })
            .collect();
        dlp.load_from_config(&dlp_routes).await;
        dlp.load_pii_config(&cfg.dlp.pii);
        tracing::info!(
            routes = dlp_routes.len(),
            enforce = cfg.dlp.enforce,
            "DLP context-aware key routing enabled"
        );
    }

    // Session store — sled-backed, survives daemon restarts
    let sessions_path = if nix::unistd::Uid::effective().is_root() {
        PathBuf::from("/var/lib/ringzero/sessions")
    } else {
        std::env::temp_dir().join("ringzero-sessions")
    };
    let sessions = Arc::new(SessionStore::open(&sessions_path).unwrap_or_else(|e| {
        tracing::warn!(err = %e, "Failed to open persistent session store, using temporary");
        SessionStore::new()
    }));
    let jwt_issuer = Arc::new(JwtIssuer::new());
    let intent_policy = IntentAwarePolicy::new();
    let rotation_store = Arc::new(RotationStore::new());
    let verified_registry = Arc::new(VerifiedRegistry::new());
    let baseline_engine = Arc::new(BaselineEngine::new());
    let observer_engine = Arc::new(ObserverEngine::new());
    let correlation_engine = Arc::new(CorrelationEngine::new());
    let skill_correlation = Arc::new(skill_correlation::SkillCorrelationEngine::new());

    // Review queue — every kernel denial and check flag waits here for a human
    // label. This is how labelled data gets collected; no model reads it yet.
    let review_path = if platform::is_elevated() {
        PathBuf::from("/var/lib/ringzero/review")
    } else {
        std::env::temp_dir().join("ringzero-review")
    };
    let review = match review::ReviewQueue::open(&review_path) {
        Ok(q) => q,
        Err(e) => {
            tracing::error!(err = %e, path = %review_path.display(), "Review queue unavailable");
            return Err(e);
        }
    };

    // Immutable audit log — persistent per run
    let audit_path = if platform::is_elevated() {
        PathBuf::from("/var/lib/ringzero/audit")
    } else {
        std::env::temp_dir().join("ringzero-audit")
    };
    let audit = match AuditLog::open(&audit_path) {
        Ok(a) => {
            tracing::info!(path = %audit_path.display(), "Audit log opened");
            Arc::new(a)
        }
        Err(e) => {
            tracing::warn!(err = %e, "Audit log open failed — using temp");
            Arc::new(AuditLog::open_temp().expect("temp audit log"))
        }
    };

    // SIEM forwarder — loaded from config, or disabled by default
    let siem_config = cfg.to_siem_config();
    if siem_config.enabled {
        tracing::info!(
            targets = siem_config.targets.len(),
            "SIEM forwarding enabled"
        );
    }
    // SiemForwarder::new now spawns its own drain task and returns Arc<Self>.
    let siem = SiemForwarder::new(siem_config);

    // Detection webhooks — async event stream + sync verdict hooks. Off unless
    // [webhooks] lists an endpoint or a hook; validated strictly (see
    // integrations/webhook.rs). Sessions are used to attribute events.
    let webhooks = integrations::webhook::WebhookHandle::new(
        integrations::webhook::WebhookDispatcher::start(&cfg.webhooks, Some(Arc::clone(&sessions)))
            .map_err(|e| anyhow::anyhow!("[webhooks] config rejected: {e}"))?,
    );

    // ── Checks layer ────────────────────────────────────────────────────────
    // Scorers that label what an agent is about to do. Off by default. With
    // the default provider this calls a third-party API, so an untouched
    // install still sends nothing off the machine.
    //
    // The outbound state goes through the SAME redactor the webhook path uses,
    // so a secret is not shipped to a third party.
    // Refuse to start in blocking mode without a fail_mode. Guessing means
    // guessing whether an outage blocks developers or leaves a path unprotected.
    if let Err(e) = cfg.checks.validate_blocking() {
        return Err(anyhow::anyhow!("{e}"));
    }

    // Refuse to start on a threshold set that cannot mean anything, rather than
    // clamping it and leaving the operator believing a band is where they put
    // it. Installed once, before anything scores.
    if let Err(e) = cfg.checks.validate_thresholds() {
        return Err(anyhow::anyhow!("{e}"));
    }
    if ringzero_checks::thresholds::install(cfg.checks.thresholds).is_err() {
        tracing::warn!("checks thresholds were already installed; keeping the first set");
    } else if cfg.checks.thresholds != ringzero_checks::thresholds::Thresholds::default() {
        tracing::info!("checks thresholds: using the operator's values from [checks.thresholds]");
    }

    let checks_provider: Option<Arc<checks_provider::ScoringProvider>> = if cfg.checks.enabled {
        let redaction = cfg.webhooks.redaction.clone();
        let redactor = integrations::webhook::Redactor::new(&redaction)
            .map_err(|e| anyhow::anyhow!("[webhooks.redaction] config rejected: {e}"))?;
        let redact: Arc<dyn Fn(&mut serde_json::Value) + Send + Sync> =
            Arc::new(move |v: &mut serde_json::Value| redactor.redact(v));

        match checks_provider::ScoringProvider::from_config(&cfg.checks, redact) {
            Ok(p) => {
                tracing::info!(provider = p.name(), "Checks layer enabled");
                if p.name() == "jev" {
                    tracing::warn!(
                        endpoint = %cfg.checks.jev.base_url,
                        "Checks are scored by a third-party API: redacted tool-call fields \
                         and hashes leave this machine. Raw prompt text is never sent."
                    );
                }
                Some(Arc::new(p))
            }
            Err(e) => {
                // The operator asked for a model and is not getting one. Say so
                // once, clearly, and leave the rest of the daemon running.
                tracing::error!(
                    provider = %cfg.checks.provider,
                    error = %e,
                    "Checks layer DISABLED: the configured provider is unavailable. \
                     Fix the configuration or set [checks] provider = \"deterministic\" \
                     to score locally."
                );
                None
            }
        }
    } else {
        None
    };

    // Bind IPC server (Unix socket)
    let ipc = IpcServer::bind(
        &sock,
        Arc::clone(&network),
        Arc::clone(&dlp),
        Arc::clone(&webhooks),
    )?;

    // Share timeline and intent_diff from IPC server across the daemon
    let timeline = Arc::clone(&ipc.timeline);
    let intent_diff = Arc::clone(&ipc.intent_diff);

    // Spawn skill-install watcher
    let ipc_watcher = Arc::clone(&ipc);
    let siem_watcher = Arc::clone(&siem);
    let registry_watcher = Arc::clone(&verified_registry);
    let model_armor_cfg = ModelArmorConfig::resolve(&cfg.model_armor);
    tokio::spawn(async move {
        match watcher::start(64) {
            Ok((mut rx, _guard)) => {
                tracing::info!("Skill install watcher active");
                while let Some(path) = rx.recv().await {
                    tracing::debug!(path = %path.display(), "New file detected");

                    // Supply chain scan (entropy + secret detection)
                    let report = supply_chain::scan_file(&path);
                    if let Ok(r) = report {
                        if r.risk_level >= scanner::supply_chain::RiskLevel::Medium {
                            tracing::warn!(
                                path = %path.display(),
                                risk = ?r.risk_level,
                                findings = r.findings.len(),
                                "Supply chain risk detected"
                            );
                            if let Ok(payload) = serde_json::to_value(&r) {
                                ipc_watcher.broadcast(DaemonMessage::Threat {
                                    payload: payload.clone(),
                                });
                                siem_watcher.try_enqueue_threat(payload.clone());
                            }
                        }

                        // Prompt injection scan — heuristic detector
                        let injection_report =
                            scan_file_for_injection(&path, model_armor_cfg.as_ref()).await;
                        let injection_found = !injection_report.clean;
                        if injection_found {
                            let has_high = injection_report.findings.iter().any(|f| {
                                matches!(
                                    f.verdict,
                                    InjectionVerdict::InjectionDetected
                                        | InjectionVerdict::Jailbreak
                                )
                            });
                            tracing::warn!(
                                path = %path.display(),
                                findings = injection_report.findings.len(),
                                high = has_high,
                                "Prompt injection detected in new skill file"
                            );
                            if let Ok(payload) = serde_json::to_value(&injection_report) {
                                ipc_watcher.broadcast(DaemonMessage::Threat {
                                    payload: payload.clone(),
                                });
                                siem_watcher.try_enqueue_threat(payload.clone());
                            }
                        }

                        // Register in verified registry
                        let entry = registry_watcher.ingest_scan(&path, &r, injection_found);
                        tracing::warn!(
                            id = %entry.id,
                            status = ?entry.status,
                            risk = ?entry.risk_level,
                            "Package registered in verified registry"
                        );
                    }
                }
            }
            Err(e) => tracing::warn!(err = %e, "Skill watcher failed to start"),
        }
    });

    // Privileged path patterns — any event touching these triggers session auto-flag
    let sensitive_patterns: Arc<Vec<&'static str>> = Arc::new(vec![
        "id_rsa",
        "id_ed25519",
        ".pem",
        ".p12",
        ".pfx",
        ".env",
        "credentials",
        "secrets",
        "token",
        "api_key",
        "passwd",
        "shadow",
        "/etc/sudoers",
        ".aws/",
        "id_token",
        "access_token",
        "refresh_token",
        "keychain",
        "Keychain",
        ".ssh/",
    ]);

    // Privilege escalation patterns — processes/targets that indicate priv-esc
    let priv_esc_patterns: Arc<Vec<(&'static str, &'static str)>> = Arc::new(vec![
        // (process_name_substring, escalation_kind)
        ("sudo", "sudo"),
        ("su", "su"),
        ("doas", "doas"),
        ("pkexec", "pkexec"),
        ("newgrp", "newgrp"),
        ("passwd", "credential_store"),
        ("chpasswd", "credential_store"),
        ("gpasswd", "credential_store"),
    ]);
    // Shell escape patterns — target process spawns indicating escape
    let shell_escape_patterns: Arc<Vec<&'static str>> = Arc::new(vec![
        "bash -i",
        "bash --norc",
        "bash --noprofile",
        "sh -i",
        "/bin/sh -i",
        "python -c",
        "python3 -c",
        "perl -e",
        "ruby -e",
        "pty.spawn",
        "os.system",
        "subprocess.Popen",
        "nc -e",
        "nc.traditional",
        "ncat",
        "socat",
    ]);

    // SLM analyzer — secondary LLM for trace classification
    let slm_analyzer = Arc::new(analyzer::slm::SlmAnalyzer::new(cfg.slm.clone()));
    {
        let slm_init = Arc::clone(&slm_analyzer);
        tokio::spawn(async move {
            let _ = slm_init.init().await;
        });
    }

    // Create event channel — eBPF loader (or external driver) sends DriverMessage into this
    let (_driver_tx, mut driver_rx) = mpsc::channel::<DriverMessage>(65536);

    // eBPF command channel — daemon sends policy/DLP updates to eBPF maps at runtime
    let ebpf_cmd_tx: Arc<RwLock<Option<mpsc::Sender<ebpf_loader::EbpfCommand>>>> =
        Arc::new(RwLock::new(None));

    // Shared flag: is the eBPF kernel subsystem active?
    let ebpf_active = Arc::new(std::sync::atomic::AtomicBool::new(false));

    // Monotonic event counters — fast status endpoint (avoids full timeline scan)
    let events_total: Arc<std::sync::atomic::AtomicU64> =
        Arc::new(std::sync::atomic::AtomicU64::new(0));
    let threats_blocked: Arc<std::sync::atomic::AtomicU64> =
        Arc::new(std::sync::atomic::AtomicU64::new(0));

    // On Linux: start the embedded eBPF loader
    {
        let tx = _driver_tx.clone();
        let cmd_holder = Arc::clone(&ebpf_cmd_tx);
        let slm_l0 = Arc::clone(&slm_analyzer);
        let ebpf_flag = Arc::clone(&ebpf_active);
        let dlp_enabled = cfg.dlp.enabled;
        // The kernel's global enforce switch follows [daemon] mode. (DLP has its
        // own flag; it must not be able to turn every file block off.)
        let kernel_enforce = enforce_mode;
        let dlp_for_ebpf = if cfg.dlp.enabled {
            Some(Arc::clone(&dlp))
        } else {
            None
        };
        // TLS MITM proxy removed — session enforcement via SSL uprobes instead.
        // No need to redirect port 443 traffic to a local proxy.
        let proxy_port: Option<u16> = None;
        tokio::spawn(async move {
            match ebpf_loader::start(tx, proxy_port, dlp_for_ebpf).await {
                Ok(cmd_tx) => {
                    tracing::info!("eBPF subsystem started");
                    ebpf_flag.store(true, std::sync::atomic::Ordering::Relaxed);

                    // Push DLP config into eBPF
                    let _ = cmd_tx
                        .send(ebpf_loader::EbpfCommand::SetDlpEnabled(dlp_enabled))
                        .await;
                    let _ = cmd_tx
                        .send(ebpf_loader::EbpfCommand::SetEnforce(kernel_enforce))
                        .await;

                    // Let the SLM compile judgments straight into L0 reflexes
                    // (the keystone loop): the brain now programs the spinal cord.
                    slm_l0.attach_l0(cmd_tx.clone()).await;

                    // Store sender so daemon event loop can push DLP block decisions
                    *cmd_holder.write().await = Some(cmd_tx);

                    std::future::pending::<()>().await;
                }
                Err(e) => {
                    tracing::warn!(err = %e, "eBPF loader failed — kernel telemetry disabled")
                }
            }
        });
    }

    // Spawn driver event processor — receives DriverMessage from channel
    {
        let acl_d = Arc::clone(&acl);
        let timeline_d = Arc::clone(&timeline);
        let ipc_d = Arc::clone(&ipc);
        let intent_diff_d = Arc::clone(&intent_diff);
        let siem_d = Arc::clone(&siem);
        let sessions_d = Arc::clone(&sessions);
        let audit_d = Arc::clone(&audit);
        let sensitive_d = Arc::clone(&sensitive_patterns);
        let priv_esc_d = Arc::clone(&priv_esc_patterns);
        let shell_escape_d = Arc::clone(&shell_escape_patterns);
        let network_d = Arc::clone(&network);
        let baseline_d = Arc::clone(&baseline_engine);
        let observer_d = Arc::clone(&observer_engine);
        let correlation_d = Arc::clone(&correlation_engine);
        let dlp_d = Arc::clone(&dlp);
        let ebpf_cmd_d = Arc::clone(&ebpf_cmd_tx);
        let slm_d = Arc::clone(&slm_analyzer);
        let dlp_enabled_d = cfg.dlp.enabled;
        let osv_enabled_d = cfg.osv.enabled;
        let webhooks_d = Arc::clone(&webhooks);
        let review_d = Arc::clone(&review);
        let enforce_mode_d = enforce_mode;
        let events_total_d = Arc::clone(&events_total);
        let threats_blocked_d = Arc::clone(&threats_blocked);

        tokio::spawn(async move {
            let acl_c = acl_d;
            let timeline_c = timeline_d;
            let ipc_c = ipc_d;
            let intent_diff_c = intent_diff_d;
            let siem_c = siem_d;
            let sessions_c = sessions_d;
            let audit_c = audit_d;
            let sensitive_c = sensitive_d;
            let priv_esc_c = priv_esc_d;
            let shell_esc_c = shell_escape_d;
            let network_c = network_d;
            let baseline_c = baseline_d;
            let observer_c = observer_d;
            let correlation_c = correlation_d;
            let dlp_c = dlp_d;
            let ebpf_cmd_c = ebpf_cmd_d;
            let webhooks_c = webhooks_d;
            let review_c = review_d;
            let enforce_mode_c = enforce_mode_d;
            let slm_c = slm_d;

            // Dedup cache: (pid, kind, target) -> last_seen epoch second
            let mut dedup: HashMap<(u32, String, String), i64> = HashMap::new();

            while let Some(DriverMessage::Event {
                event_type,
                pid,
                uid,
                comm,
                path,
                remote_ip,
                remote_port,
                blocked,
                args: _args,
            }) = driver_rx.recv().await
            {
                let kind = event_type_to_kind(event_type);
                let target = path.filter(|p| !p.is_empty()).unwrap_or_else(|| {
                    match (&remote_ip, remote_port) {
                        (Some(ip), Some(port)) if !ip.is_empty() => format!("{}:{}", ip, port),
                        (Some(ip), None) if !ip.is_empty() => ip.clone(),
                        _ => String::new(),
                    }
                });

                // Resolve parent PID from /proc
                let ppid = resolve_ppid(pid);
                let parent_process = ppid.and_then(|p| resolve_comm(p));

                let mut ev = SecurityEvent {
                    id: format!("{}-{}", pid, Utc::now().timestamp_nanos_opt().unwrap_or(0)),
                    kind: kind.clone(),
                    pid,
                    uid,
                    process: comm,
                    target: target.clone(),
                    allowed: blocked == 0,
                    reason: None,
                    timestamp: Utc::now(),
                    ppid,
                    parent_process,
                    llm_context: None,
                    extra: None,
                };

                // Dedup: skip if same (pid, kind, target) seen within 1 second
                let dedup_key = (ev.pid, format!("{:?}", ev.kind), ev.target.clone());
                let now_sec = ev.timestamp.timestamp();
                if let Some(&last) = dedup.get(&dedup_key) {
                    if now_sec - last < 1 {
                        continue;
                    }
                }
                dedup.insert(dedup_key, now_sec);
                // Prune dedup cache every ~1000 entries
                if dedup.len() > 1000 {
                    dedup.retain(|_, &mut t| now_sec - t < 5);
                }

                // Auto-detect AI agents by destination — any process connecting
                // to an LLM API endpoint is an agent, regardless of its name.
                let is_agent = common::agent_detect::is_ai_agent(&ev.process)
                    || (ev.kind == EventKind::NetworkConnect
                        && common::agent_detect::is_llm_destination(&ev.target))
                    || (ev.kind == EventKind::NetworkConnect
                        && ev.target.ends_with(":443")
                        && common::agent_detect::is_agent_by_binary(pid));

                // If detected by destination or binary path, try dynamic SSL uprobe attachment
                if !common::agent_detect::is_ai_agent(&ev.process)
                    && ev.kind == EventKind::NetworkConnect
                    && (common::agent_detect::is_llm_destination(&ev.target)
                        || (ev.target.ends_with(":443")
                            && common::agent_detect::is_agent_by_binary(pid)))
                {
                    tracing::info!(
                        pid, process = %ev.process, target = %ev.target,
                        "Auto-detected AI agent"
                    );
                }
                let acl_decision = acl_c.read().await.evaluate(&ev);
                if let Decision::Block { ref reason } = acl_decision {
                    // Observe-only: the ACL verdict is recorded as the event's
                    // reason; kernel-side blocking is handled by the eBPF policy
                    // maps. `allowed` already carries the kernel's decision — do
                    // not overwrite it, or a real denial is logged as an allow.
                    ev.reason = Some(reason.clone());
                    tracing::info!(
                    pid, process = %ev.process, target = %target,
                    reason, "ACL would-block (observe-only)"
                    );
                }

                // Network policy evaluation
                if ev.allowed
                    && matches!(
                        ev.kind,
                        EventKind::NetworkConnect | EventKind::NetworkSend | EventKind::DnsQuery
                    )
                {
                    let net_decision = network_c.evaluate(&ev).await;
                    if let Decision::Block { ref reason } = net_decision {
                        // Observe-only: the network-policy verdict is recorded as
                        // the event's reason; kernel-side blocking is handled by the
                        // eBPF maps. `allowed` already carries the kernel's decision.
                        ev.reason = Some(reason.clone());
                        tracing::info!(
                        pid, process = %ev.process, target = %target,
                        reason, "Network policy would-block (observe-only)"
                        );
                    }
                }

                // Session approval gate — kill agent processes that connect to
                // port 443 (HTTPS/LLM APIs) without an approved session.
                // This enforces "approve before use" for all AI agents.
                // Skip for whitelisted destinations (AI APIs, registries) —
                // agents legitimately connect to these before session approval.
                if ev.allowed
                    && ev.kind == EventKind::NetworkConnect
                    && is_agent
                    && !policy::network::is_whitelisted_destination(&ev.target)
                {
                    let port = ev
                        .target
                        .rsplit(':')
                        .next()
                        .and_then(|p| p.parse::<u16>().ok())
                        .unwrap_or(0);
                    if port == 443
                        && sessions_c.has_unapproved_sessions()
                        && !sessions_c.has_approved_session()
                    {
                        // Observe-only: record the gate decision, do not block or
                        // kill. `allowed` already carries the kernel's decision.
                        ev.reason = Some(
                                "[Ring Zero] Session not approved — HTTPS would be blocked. Approve the session first.".to_string()
                            );
                        tracing::warn!(
                            pid, process = %ev.process, target = %target,
                            "SESSION GATE: unapproved session detected (observe-only, not killing)"
                        );
                    }
                }

                // DLP content inspection is handled by ssl_sniff where
                // actual plaintext HTTP data is available. eBPF network
                // events only carry IP:port, not payload.

                // Log every event at trace level for diagnostics
                tracing::trace!(
                    pid, process = %ev.process, target = %target, kind = ?ev.kind,
                    allowed = ev.allowed, "Kernel event received"
                );

                // Kernel → session wiring:
                // Find the session for this event by PID or process name,
                // register the PID, and increment event counter.
                let matched_session_id: Option<String> =
                    {
                        // Try PID lookup first
                        if let Some(s) = sessions_c.find_by_pid(pid) {
                            Some(s.id.clone())
                        } else if let Some(s) = sessions_c.list_active().into_iter().find(|s| {
                            s.actor.contains(&ev.process) || ev.process.contains(&s.actor)
                        }) {
                            // Process-name match
                            sessions_c.register_pid(&s.id, pid);
                            Some(s.id.clone())
                        } else {
                            // Ancestry walk: attribute a descendant's syscall/exec to the
                            // agent session it belongs to (the agent spawns the children
                            // that actually open files / run processes).
                            session_by_ancestry(&sessions_c, pid)
                        }
                    };

                // Auto-detect AI agent sessions from kernel events
                let matched_session_id = if matched_session_id.is_some() {
                    matched_session_id
                } else if let Some(agent_type) = detect_agent_type(&ev.process) {
                    // Known agent binary — create a new session.
                    // Sanitize ev.process before embedding it in a session
                    // id: `comm` can contain chars that would later fail the
                    // containment is_safe_session_id allowlist (and would
                    // also be terrible as a cgroup directory name).
                    let agent_label_str = agent_type.to_string();
                    let sid_proc: String = ev
                        .process
                        .chars()
                        .map(|c| {
                            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                                c
                            } else {
                                '_'
                            }
                        })
                        .collect();
                    // Trim leading/trailing underscores to avoid awkward `auto-__...`
                    let sid_proc_trimmed = sid_proc.trim_matches('_');
                    // Cap length so we never collide with the
                    // is_safe_session_id 128-char limit including "auto-"
                    // prefix and the PID suffix.
                    let sid_proc_capped: String = sid_proc_trimmed.chars().take(80).collect();
                    // Fallback for fully non-ASCII process names (emoji
                    // binary, exotic locale): use the agent_type label so
                    // the session id stays distinguishable rather than
                    // collapsing to "auto--{pid}" for every such process.
                    let sid_proc: String = if sid_proc_capped.is_empty() {
                        agent_label_str.replace(|c: char| !c.is_ascii_alphanumeric(), "_")
                    } else {
                        sid_proc_capped
                    };
                    let sid = format!("auto-{}-{}", sid_proc, pid);
                    let agent_label = agent_label_str;
                    let mut session =
                        Session::new(sid.clone(), agent_type, ev.process.clone(), vec![], None);
                    session.state = SessionState::Active;
                    session.pids.push(pid);
                    sessions_c.create(session);
                    // Assign baseline policy from Observer engine
                    observer_c.assign_policy(&sid, &agent_label, vec![]).await;
                    // Register with network policy so this PID's traffic is allowed
                    network_c.register_agent(pid).await;
                    tracing::info!(
                        session_id = %sid,
                        process = %ev.process,
                        pid,
                        "Auto-created session for detected AI agent"
                    );
                    // YOLO flag check: read cmdline of agent + parent process.
                    // Node.js agents (claude) overwrite their cmdline to just
                    // the process name, so we also check the parent shell.
                    let read_cmdline = |p: u32| -> Option<String> {
                        std::fs::read(format!("/proc/{}/cmdline", p))
                            .ok()
                            .and_then(|data| {
                                if data.is_empty() {
                                    return None;
                                }
                                let s: String = data
                                    .iter()
                                    .map(|&b| if b == 0 { ' ' } else { b as char })
                                    .collect();
                                let s = s.trim().to_string();
                                if s.is_empty() {
                                    None
                                } else {
                                    Some(s)
                                }
                            })
                    };
                    let self_cmdline = read_cmdline(pid).unwrap_or_default();
                    let parent_cmdline = ev.ppid.and_then(read_cmdline).unwrap_or_default();
                    // Combine both for matching
                    let combined = format!("{} {}", self_cmdline, parent_cmdline);
                    let cmdline = combined.trim().to_string();
                    tracing::debug!(pid, ppid = ?ev.ppid,
                            self_cmd = %self_cmdline, parent_cmd = %parent_cmdline,
                            "YOLO check: cmdline inspection");
                    {
                        let cmdline_lower = cmdline.to_lowercase();
                        let yolo_flags: &[(&str, &str)] = &[
                            ("--dangerously-skip-permissions", "Claude Code"),
                            ("--yolo", "Gemini CLI"),
                            ("--trust-all-tools", "Amazon Q"),
                        ];
                        // Also check for short -y flag (word boundary)
                        let has_short_y = cmdline_lower.split_whitespace().any(|w| w == "-y");
                        for (flag, flag_agent) in yolo_flags {
                            if cmdline_lower.contains(flag) {
                                tracing::error!(
                                    pid, process = %ev.process, flag = %flag,
                                    agent = %flag_agent, cmdline = %cmdline,
                                    "YOLO FLAG DETECTED — AI agent launched with safety bypass"
                                );
                                // Observe-only: record the finding and broadcast a
                                // threat. `allowed` carries the kernel's decision.
                                ev.reason = Some(format!(
                                        "[Ring Zero] CRITICAL: {} flag detected — safety bypass detected (observe-only)",
                                        flag
                                    ));
                                // Broadcast threat
                                let threat_payload = serde_json::json!({
                                    "type": "yolo_flag_detected",
                                    "severity": "critical",
                                    "flag": flag,
                                    "agent": flag_agent,
                                    "process": &ev.process,
                                    "cmdline": &cmdline,
                                    "pid": pid,
                                    "session_id": &sid,
                                    "timestamp": ev.timestamp,
                                    "description": format!(
                                        "AI agent '{}' launched with '{}' — all safety guardrails bypassed.",
                                        ev.process, flag
                                    ),
                                });
                                ipc_c.broadcast(DaemonMessage::Threat {
                                    payload: threat_payload.clone(),
                                });
                                let siem_ref = Arc::clone(&siem_c);
                                tokio::spawn(async move {
                                    siem_ref.forward_threat(&threat_payload).await;
                                });
                                audit_c.try_append(
                                    audit::AuditEntryType::SecurityEvent,
                                    serde_json::json!({
                                        "event": "yolo_flag_detected",
                                        "flag": flag,
                                        "process": &ev.process,
                                        "pid": pid,
                                        "session_id": &sid,
                                        "cmdline": &cmdline,
                                    }),
                                );
                                break;
                            }
                        }
                        if has_short_y && ev.process.contains("claude") {
                            tracing::error!(
                                pid, process = %ev.process, cmdline = %cmdline,
                                "YOLO FLAG DETECTED — Claude launched with -y (short safety bypass, observe-only)"
                            );
                            let threat_payload = serde_json::json!({
                                "type": "yolo_flag_detected",
                                "severity": "critical",
                                "flag": "-y",
                                "agent": "Claude Code",
                                "process": &ev.process,
                                "pid": pid,
                                "session_id": &sid,
                                "timestamp": ev.timestamp,
                            });
                            ipc_c.broadcast(DaemonMessage::Threat {
                                payload: threat_payload.clone(),
                            });
                            let siem_ref = Arc::clone(&siem_c);
                            tokio::spawn(async move {
                                siem_ref.forward_threat(&threat_payload).await;
                            });
                        }
                    } // yolo check block
                    Some(sid)
                } else {
                    // Unknown process name but the eBPF let it through —
                    // it's a child of an AI agent (node, python, etc.)
                    // First try to find the session by PPID (most accurate)
                    let found = if let Some(ppid) = ev.ppid {
                        sessions_c.find_by_pid(ppid).map(|s| s.id.clone())
                    } else {
                        None
                    }
                    .or_else(|| {
                        // Fall back to the most recent active session only
                        // if there's exactly one (avoid cross-session leakage)
                        let active = sessions_c.list_active();
                        if active.len() == 1 {
                            Some(active[0].id.clone())
                        } else {
                            None
                        }
                    });
                    if let Some(ref sid) = found {
                        sessions_c.register_pid(sid, pid);
                        // Also register child PID with network policy
                        network_c.register_agent(pid).await;
                        network_c.register_fork(ev.ppid.unwrap_or(0), pid).await;
                        tracing::warn!(
                            session = %sid, process = %ev.process, pid,
                            "Assigned child process to active agent session"
                        );
                    }
                    found
                };

                // Observer baseline policy evaluation — catch violations before
                // other analysis. Blocks set ev.allowed=false, warns get logged.
                // Skip network events to our own inspection proxy / loopback:
                // the agent's HTTPS is routed through 127.0.0.1, so otherwise
                // every request spams network_connect/network_send warnings (a
                // notification per prompt). The proxy inspects the real target.
                let to_loopback =
                    matches!(ev.kind, EventKind::NetworkConnect | EventKind::NetworkSend)
                        && policy::network::is_whitelisted_destination(&ev.target)
                        && ev
                            .target
                            .split(':')
                            .next()
                            .map(|h| h.starts_with("127.") || h == "::1" || h == "localhost")
                            .unwrap_or(false);
                if let Some(ref sid) = matched_session_id {
                    if to_loopback {
                        // no-op: don't run baseline checks against our own proxy
                    } else if let Some(violation) = observer_c.evaluate(&ev, sid).await {
                        match violation.action_taken.as_str() {
                            "blocked" => {
                                // Observe-only: record the violation as the
                                // event's reason. Never touch `allowed` — that
                                // field carries the KERNEL's decision, and an
                                // advisory baseline verdict must not overwrite
                                // a real denial with an allow.
                                ev.reason = Some(format!(
                                    "Baseline violation: {} — {}",
                                    violation.activity_class, violation.rule_description
                                ));
                                tracing::warn!(
                                    session = %sid,
                                    pid,
                                    process = %ev.process,
                                    target = %ev.target,
                                    class = %violation.activity_class,
                                    "Observer: baseline violation detected (observe-only)"
                                );
                                // Broadcast as threat
                                if let Ok(payload) = serde_json::to_value(&violation) {
                                    ipc_c.broadcast(DaemonMessage::Threat {
                                        payload: payload.clone(),
                                    });
                                    siem_c.try_enqueue_threat(payload.clone());
                                }
                                // SLM analysis on critical baseline violations (Graph RAG)
                                {
                                    // Session/tree-scoped: gather events across ALL pids in the
                                    // agent session so the graph is a real multi-node provenance
                                    // graph (claude→bash→curl), not a single ephemeral-pid exec.
                                    let mut session_pids = sessions_c
                                        .find_by_pid(pid)
                                        .map(|s| s.pids)
                                        .unwrap_or_default();
                                    if !session_pids.contains(&pid) {
                                        session_pids.push(pid);
                                    }
                                    let mut slm_events = timeline_c
                                        .recent_for_pids(&session_pids, 60)
                                        .unwrap_or_default();
                                    if !slm_events.iter().any(|e| e.id == ev.id) {
                                        slm_events.push(ev.clone());
                                    }
                                    let graph = analyzer::graph::ProvenanceGraph::from_events(
                                        &slm_events,
                                        40,
                                    );
                                    let slm_ref = Arc::clone(&slm_c);
                                    let ipc_slm = ipc_c.clone();
                                    let siem_slm = Arc::clone(&siem_c);
                                    tokio::spawn(async move {
                                        if let Some(verdict) =
                                            slm_ref.analyze_graph(&graph, None, 80).await
                                        {
                                            tracing::info!(
                                                risk = verdict.risk_score,
                                                action = ?verdict.action,
                                                model = %verdict.model,
                                                latency_ms = verdict.latency_ms,
                                                "SLM baseline violation analysis"
                                            );
                                            if let Ok(payload) = serde_json::to_value(&verdict) {
                                                ipc_slm.broadcast(DaemonMessage::Threat {
                                                    payload: payload.clone(),
                                                });
                                                siem_slm.forward_threat(&payload).await;
                                            }
                                        }
                                    });
                                }
                            }
                            "warned" => {
                                tracing::info!(
                                    session = %sid,
                                    pid,
                                    process = %ev.process,
                                    target = %ev.target,
                                    class = %violation.activity_class,
                                    "Observer: baseline warning"
                                );
                            }
                            _ => {}
                        }
                    }
                }

                // Privileged session auto-detection: sensitive path access
                if !target.is_empty() {
                    if let Some(pat) = sensitive_c.iter().find(|&&p| target.contains(p)) {
                        let reason =
                            format!("accessed sensitive path: {} (pattern: {})", target, pat);
                        let affected: Vec<_> = if let Some(ref sid) = matched_session_id {
                            vec![sid.clone()]
                        } else {
                            sessions_c
                                .list_active()
                                .into_iter()
                                .filter(|s| {
                                    s.actor.contains(&ev.process) || ev.process.contains(&s.actor)
                                })
                                .map(|s| s.id.clone())
                                .collect()
                        };
                        for sid in &affected {
                            sessions_c.set_privileged(sid, &reason);
                            audit_c.try_append(
                                audit::AuditEntryType::SecurityEvent,
                                serde_json::json!({
                                "event": "privileged_session_detected",
                                "session_id": sid,
                                "reason": &reason,
                                }),
                            );
                        }
                    }
                }

                // Privilege escalation detection
                // Detect sudo/su/doas/shell-escapes
                {
                    let is_proc_exec =
                        matches!(ev.kind, EventKind::ProcessExec | EventKind::ProcessFork);
                    let mut priv_esc_kind: Option<&str> = None;

                    if is_proc_exec {
                        // Check process name for escalation binaries
                        for (pattern, kind) in priv_esc_c.iter() {
                            if ev.process.contains(pattern) || target.contains(pattern) {
                                priv_esc_kind = Some(kind);
                                break;
                            }
                        }
                        // Check for shell escape patterns in target
                        if priv_esc_kind.is_none() {
                            for pat in shell_esc_c.iter() {
                                if target.contains(pat) {
                                    priv_esc_kind = Some("shell_escape");
                                    break;
                                }
                            }
                        }
                    }

                    if let Some(kind) = priv_esc_kind {
                        tracing::warn!(
                        pid, process = %ev.process, target = %target,
                        kind, "Privilege escalation detected"
                        );
                        let esc_ev = PrivEscEvent {
                            kind: kind.to_string(),
                            process: ev.process.clone(),
                            target: target.clone(),
                            pid,
                            blocked: !ev.allowed,
                            timestamp: ev.timestamp,
                        };
                        let affected: Vec<_> = if let Some(ref sid) = matched_session_id {
                            vec![sid.clone()]
                        } else {
                            sessions_c
                                .list_active()
                                .into_iter()
                                .filter(|s| {
                                    s.actor.contains(&ev.process) || ev.process.contains(&s.actor)
                                })
                                .map(|s| s.id.clone())
                                .collect()
                        };
                        for sid in &affected {
                            sessions_c.record_priv_esc(sid, esc_ev.clone());
                            audit_c.try_append(
                                audit::AuditEntryType::SecurityEvent,
                                serde_json::json!({
                                "event": "privilege_escalation",
                                "session_id": sid,
                                "kind": kind,
                                "process": &ev.process,
                                "target": &target,
                                "pid": pid,
                                "blocked": !ev.allowed,
                                }),
                            );
                        }
                        // Broadcast as threat
                        let threat_payload = serde_json::json!({
                        "type": "privilege_escalation",
                        "kind": kind,
                        "process": &ev.process,
                        "target": &target,
                        "pid": pid,
                        "timestamp": ev.timestamp,
                        });
                        ipc_c.broadcast(DaemonMessage::Threat {
                            payload: threat_payload.clone(),
                        });
                        siem_c.try_enqueue_threat(threat_payload.clone());
                    }
                }

                // ── Config tamper detection (NX P2) ────────────────────────
                // Detect AI agents writing to shell config files (.bashrc,
                // .zshrc, etc). NX attack appends shutdown commands to bashrc.
                if matches!(ev.kind, EventKind::FileWrite | EventKind::FileCreate) {
                    const SHELL_CONFIGS: &[&str] = &[
                        ".bashrc",
                        ".bash_profile",
                        ".bash_login",
                        ".profile",
                        ".zshrc",
                        ".zprofile",
                        ".zshenv",
                        ".config/fish/config.fish",
                        "crontab",
                        ".crontab",
                    ];
                    if SHELL_CONFIGS.iter().any(|c| target.contains(c)) {
                        tracing::error!(
                            pid, process = %ev.process, target = %target,
                            "CONFIG TAMPER: AI agent writing to shell config"
                        );
                        // Observe-only: record the finding and broadcast a threat.
                        // `allowed` already carries the kernel's decision.
                        ev.reason = Some(format!(
                            "[Ring Zero] Shell config tamper detected: {} → {} (observe-only)",
                            ev.process, target
                        ));
                        let threat_payload = serde_json::json!({
                            "type": "config_tamper",
                            "severity": "critical",
                            "process": &ev.process,
                            "target": &target,
                            "pid": pid,
                            "session_id": matched_session_id,
                            "timestamp": ev.timestamp,
                            "description": format!(
                                "AI agent '{}' attempted to modify shell config '{}'. \
                                 This matches the NX attack pattern where malware appends \
                                 shutdown/persistence commands to .bashrc.",
                                ev.process, target
                            ),
                        });
                        ipc_c.broadcast(DaemonMessage::Threat {
                            payload: threat_payload.clone(),
                        });
                        siem_c.try_enqueue_threat(threat_payload.clone());
                        audit_c.try_append(
                            audit::AuditEntryType::SecurityEvent,
                            serde_json::json!({
                                "event": "config_tamper_blocked",
                                "process": &ev.process,
                                "target": &target,
                                "pid": pid,
                            }),
                        );
                    }
                }

                // ── Behavioral exfiltration indicator tracking ──────────────
                // Feed events into the DLP exfil tracker so it can detect
                // multi-step exfil patterns: read sensitive → compress → send.
                if dlp_enabled_d {
                    // Sensitive file reads → record_sensitive_read
                    if matches!(ev.kind, EventKind::FileOpen) && !target.is_empty() {
                        if sensitive_c.iter().any(|&p| target.contains(p)) {
                            dlp_c.exfil.record_sensitive_read(pid).await;
                        }
                    }

                    // Archive tool execution → record_archive_op
                    if matches!(ev.kind, EventKind::ProcessExec | EventKind::ProcessFork) {
                        if secrets::dlp::is_archive_tool(&ev.process)
                            || secrets::dlp::is_archive_tool(&target)
                        {
                            dlp_c.exfil.record_archive_op(pid).await;
                        }
                    }

                    // Network sends → record_network_send with entropy
                    if matches!(ev.kind, EventKind::NetworkSend) {
                        // eBPF events don't carry payload data, so we use a
                        // default entropy of 0.0 here. The ssl_sniff path
                        // provides real entropy from intercepted plaintext.
                        dlp_c.exfil.record_network_send(pid, 0.0).await;
                    }
                }

                // Only persist and analyze events from detected agent sessions
                // (skip system noise to avoid 100% CPU and log spam)
                if matched_session_id.is_none() {
                    // Log the process name at debug level so we can diagnose detection
                    tracing::warn!(
                        pid, process = %ev.process, target = %target, kind = ?ev.kind,
                        "Kernel event from non-agent process — skipping"
                    );
                    continue;
                }

                // Never escalate (or treat as blocked) connections to our own
                // inspection proxy / loopback — the agent's HTTPS is routed
                // there, and a spurious "blocked access to 127.0.0.1:7710"
                // escalation fires a notification per prompt even though the
                // connection succeeds and the prompt is captured.
                if !ev.allowed
                    && ev
                        .target
                        .split(':')
                        .next()
                        .map(|h| h.starts_with("127.") || h == "::1" || h == "localhost")
                        .unwrap_or(false)
                {
                    // Loopback traffic is uninteresting, but never turn a denial
                    // into an allow.
                    if ev.allowed {
                        ev.allowed = true;
                    }
                }

                // Detection webhooks — sync verdict hooks (opt-in per event type).
                // The kernel has already decided this syscall from its policy maps;
                // the hook gates the daemon's release of the event and everything
                // downstream. A deny marks the event blocked and, in enforce mode,
                // terminates the process and installs a kernel block rule for the
                // target so the next attempt is refused in-kernel. Every verdict,
                // timeout and fail-mode outcome is logged inside `verdict()`.
                if let Some(v) = webhooks_c.get().verdict(&ev).await {
                    let reason = format!(
                        "[verdict hook {}] deny via {}{}",
                        v.hook,
                        v.source,
                        v.reason
                            .as_deref()
                            .map(|r| format!(": {r}"))
                            .unwrap_or_default()
                    );
                    ev.allowed = false;
                    ev.reason = Some(reason.clone());
                    let mut killed = false;
                    let mut kernel_rule: Option<String> = None;
                    if enforce_mode_c {
                        killed = verified_kill(pid, Some(&ev.process), libc::SIGKILL, false);
                        let cmd = match ev.kind {
                            EventKind::FileOpen
                            | EventKind::FileCreate
                            | EventKind::FileDelete
                            | EventKind::FileRename
                            | EventKind::FileWrite
                                if !target.is_empty() =>
                            {
                                Some(ebpf_loader::EbpfCommand::BlockFile(target.clone()))
                            }
                            EventKind::NetworkConnect
                            | EventKind::NetworkSend
                            | EventKind::DnsQuery => target
                                .rsplit_once(':')
                                .map(|(ip, _)| ip.to_string())
                                .or_else(|| (!target.is_empty()).then(|| target.clone()))
                                .map(ebpf_loader::EbpfCommand::BlockIp),
                            _ => None,
                        };
                        if let Some(cmd) = cmd {
                            kernel_rule = Some(format!("{cmd:?}"));
                            if let Some(tx) = ebpf_cmd_c.read().await.as_ref() {
                                let _ = tx.try_send(cmd);
                            }
                        }
                    }
                    tracing::warn!(
                        pid, process = %ev.process, target = %target, hook = %v.hook,
                        source = v.source, latency_ms = v.latency_ms, killed,
                        kernel_rule = ?kernel_rule, enforce = enforce_mode_c,
                        "Verdict hook denied event"
                    );
                    audit_c.try_append(
                        audit::AuditEntryType::AccessDenied,
                        serde_json::json!({
                            "event": "verdict_hook_deny",
                            "hook": v.hook,
                            "source": v.source,
                            "session_id": matched_session_id,
                            "process": &ev.process,
                            "target": &target,
                            "pid": pid,
                            "killed": killed,
                            "kernel_rule": kernel_rule,
                            "reason": &reason,
                        }),
                    );
                    let threat_payload = serde_json::json!({
                        "type": "verdict_hook_deny",
                        "severity": "high",
                        "hook": v.hook,
                        "source": v.source,
                        "process": &ev.process,
                        "target": &target,
                        "pid": pid,
                        "session_id": matched_session_id,
                        "killed": killed,
                        "kernel_rule": kernel_rule,
                        "timestamp": ev.timestamp,
                        "description": reason,
                    });
                    ipc_c.broadcast(DaemonMessage::Threat {
                        payload: threat_payload.clone(),
                    });
                    siem_c.try_enqueue_threat(threat_payload);
                }

                // Auto-escalate: when a blocked event hits an active session,
                // create an escalation request so the admin can approve via console
                if !ev.allowed {
                    if let Some(ref sid) = matched_session_id {
                        let reason = format!(
                            "Blocked access to '{}' by {} (pid {})",
                            target, ev.process, pid
                        );
                        if let Some(esc_id) = sessions_c.escalate(sid, &target, &reason) {
                            tracing::warn!(
                                session = %sid,
                                target = %target,
                                escalation_id = %esc_id,
                                "Auto-escalation created for blocked access"
                            );
                            audit_c.try_append(
                                audit::AuditEntryType::EscalationRequested,
                                serde_json::json!({
                                    "session_id": sid,
                                    "escalation_id": esc_id,
                                    "target": &target,
                                    "process": &ev.process,
                                    "reason": &reason,
                                }),
                            );
                        }
                    }

                    // Observe-only: log critical violations; no process is killed.
                    if ev.reason.as_deref().map_or(false, |r| {
                        r.contains("DLP")
                            || r.contains("credential")
                            || r.contains("exfiltrat")
                            || r.contains("key sent to")
                    }) {
                        tracing::warn!(
                            pid, process = %ev.process,
                            reason = ?ev.reason,
                            "Critical policy violation detected (observe-only, not terminating)"
                        );
                    }
                }

                // Persist to timeline + per-session event log + update counters
                let _ = timeline_c.insert(&ev);
                if let Some(ref sid) = matched_session_id {
                    sessions_c.append_event(sid, ev.clone());
                }
                events_total_d.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                if !ev.allowed {
                    threats_blocked_d.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    // Every denial goes to the review queue with its trace, so a
                    // human can label it. That label is the training row we do
                    // not have yet — see review.rs.
                    let sid = matched_session_id.as_deref().unwrap_or("unknown");
                    let summary = format!(
                        "kernel denied {} on '{}' by {} (pid {})",
                        format!("{:?}", ev.kind),
                        target,
                        ev.process,
                        pid
                    );
                    if let Err(e) = review_c.push(
                        crate::review::Source::KernelDeny,
                        sid,
                        summary,
                        serde_json::to_value(&ev).unwrap_or(serde_json::Value::Null),
                    ) {
                        tracing::warn!(err = %e, "Could not queue denial for review");
                    }
                }

                // ── LLM context propagation ──────────────────────────────
                // Attach recent LLM response context to kernel events so
                // traces link "what the model said" → "what actually happened"
                let session_id_str = matched_session_id.as_deref().unwrap_or("unknown");
                if ev.llm_context.is_none() {
                    if let Some((llm_ctx, _trace_id)) =
                        intent_diff_c.get_llm_context_for_event(session_id_str, pid, ev.ppid)
                    {
                        ev.llm_context = Some(llm_ctx);
                    }
                }

                // ── Causal trace correlation ────────────────────────────────
                // Link this kernel action to the most recent LLM response
                // via process tree + argument matching
                let _correlation = intent_diff_c.correlate_action(&ev, session_id_str);

                // ── Record LLM response events into the correlation engine ──
                if matches!(ev.kind, EventKind::LlmResponse | EventKind::LlmToolCall) {
                    intent_diff_c.record_llm_response(session_id_str, pid, &ev);
                }

                // ── OSV vulnerability check on package installs ──────────────
                // Opt-in ([osv] enabled = true): when an agent runs `npm install`,
                // `pip install`, etc., parse the command and query OSV.dev.
                if osv_enabled_d && matches!(ev.kind, EventKind::ProcessExec) {
                    if let Some(install) = scanner::osv::parse_install_command(&ev.process, &target)
                    {
                        let pkg_name = install.name.clone();
                        let pkg_ver = install.version.clone();
                        let eco = install.ecosystem.osv_name().to_string();
                        let ev_id = ev.id.clone();
                        let ipc_osv = ipc_c.clone();
                        let siem_osv = Arc::clone(&siem_c);
                        let audit_osv = audit_c.clone();
                        tracing::info!(
                            package = %pkg_name,
                            version = ?pkg_ver,
                            ecosystem = %eco,
                            pid,
                            "OSV: checking package install for vulnerabilities"
                        );
                        tokio::spawn(async move {
                            if let Some(result) = scanner::osv::check_package(&install).await {
                                if result.is_vulnerable() {
                                    let summary = result.summary();
                                    tracing::warn!(
                                        package = %pkg_name,
                                        vulns = result.vuln_count(),
                                        cvss = ?result.highest_severity(),
                                        "OSV: vulnerable package install detected!"
                                    );
                                    let payload = serde_json::json!({
                                        "event": "vulnerable_package_install",
                                        "package": pkg_name,
                                        "version": pkg_ver,
                                        "ecosystem": eco,
                                        "vuln_count": result.vuln_count(),
                                        "cve_ids": result.cve_ids(),
                                        "highest_cvss": result.highest_severity(),
                                        "summary": summary,
                                        "event_id": ev_id,
                                    });
                                    ipc_osv.broadcast(DaemonMessage::Threat {
                                        payload: payload.clone(),
                                    });
                                    siem_osv.forward_threat(&payload).await;
                                    let _ = audit_osv
                                        .append(audit::AuditEntryType::ThreatDetected, payload);
                                }
                            }
                        });
                    }
                }

                // ── Intent vs behavior diff audit ────────────────────────────
                {
                    if let Some(diff) = intent_diff_c.check_event(&ev, session_id_str) {
                        tracing::warn!(
                        session = %diff.session_id,
                        declared = %diff.declared_intent,
                        observed = %diff.observed_behavior,
                        severity = ?diff.severity,
                        "Intent vs behavior mismatch detected"
                        );
                        if let Ok(payload) = serde_json::to_value(&diff) {
                            ipc_c.broadcast(DaemonMessage::Threat {
                                payload: payload.clone(),
                            });
                            siem_c.try_enqueue_threat(payload.clone());
                        }
                    }
                }

                // Heuristic scoring over last 60s for this PID
                let recent = timeline_c.recent(pid, 60).unwrap_or_default();
                let score = heuristics::score(&recent);
                if score.is_high() {
                    tracing::warn!(
                    pid, process = %ev.process, score = score.total,
                    reasons = ?score.reasons, "High-risk behavior detected"
                    );
                    if let Ok(payload) = serde_json::to_value(&ev) {
                        ipc_c.broadcast(DaemonMessage::Threat {
                            payload: payload.clone(),
                        });
                        siem_c.try_enqueue_threat(payload.clone());
                    }

                    // SLM analysis — build provenance graph and classify (Graph RAG)
                    let h_score = score.total as u32;
                    {
                        // Session/tree-scoped events for a real provenance graph
                        // (heuristic scoring above stays per-PID by design).
                        let mut session_pids = sessions_c
                            .find_by_pid(pid)
                            .map(|s| s.pids)
                            .unwrap_or_default();
                        if !session_pids.contains(&pid) {
                            session_pids.push(pid);
                        }
                        let graph_events = timeline_c
                            .recent_for_pids(&session_pids, 60)
                            .unwrap_or_default();
                        let graph_events = if graph_events.is_empty() {
                            recent.clone()
                        } else {
                            graph_events
                        };
                        let mut graph =
                            analyzer::graph::ProvenanceGraph::from_events(&graph_events, 40);

                        // Enrich with causal trace if available
                        if let Some((_, ref trace_id)) = _correlation {
                            if let Some(trace) = intent_diff_c.get_trace(trace_id) {
                                graph.add_causal_trace(&trace);
                            }
                        }

                        let slm_ref = Arc::clone(&slm_c);
                        let ipc_slm = ipc_c.clone();
                        let siem_slm = Arc::clone(&siem_c);
                        tokio::spawn(async move {
                            if let Some(verdict) =
                                slm_ref.analyze_graph(&graph, None, h_score).await
                            {
                                tracing::info!(
                                    risk = verdict.risk_score,
                                    action = ?verdict.action,
                                    model = %verdict.model,
                                    latency_ms = verdict.latency_ms,
                                    nodes = graph.node_count(),
                                    edges = graph.edge_count(),
                                    "SLM graph analysis complete"
                                );
                                if let Ok(payload) = serde_json::to_value(&verdict) {
                                    ipc_slm.broadcast(DaemonMessage::Threat {
                                        payload: payload.clone(),
                                    });
                                    siem_slm.forward_threat(&payload).await;
                                }
                            }
                        });
                    }
                }

                // Attack pattern correlation (Phase 6) — multi-step chain detection
                if let Some(ref sid) = matched_session_id {
                    if let Some(chain) = correlation_c.evaluate(&ev, sid).await {
                        tracing::warn!(
                            session = %sid,
                            pattern = %chain.pattern_name,
                            severity = %chain.severity,
                            mitre = ?chain.mitre_id,
                            events = chain.matched_events.len(),
                            "Attack chain detected — multi-step correlation"
                        );
                        // Observe-only: log critical attack chains; the session is not killed.
                        if matches!(chain.severity, analyzer::correlation::Severity::Critical) {
                            tracing::error!(
                                session = %sid, pattern = %chain.pattern_name,
                                "CRITICAL attack chain detected (observe-only, not killing session)"
                            );
                            // Observe-only: `allowed` carries the kernel's (or a
                            // verdict hook's) decision and must not be relaxed here.
                            ev.reason = Some(format!(
                                "[Ring Zero] Attack chain '{}' detected (observe-only)",
                                chain.pattern_name
                            ));
                        }
                        if let Ok(payload) = serde_json::to_value(&chain) {
                            ipc_c.broadcast(DaemonMessage::Threat {
                                payload: payload.clone(),
                            });
                            siem_c.try_enqueue_threat(payload.clone());
                        }
                        audit_c.try_append(
                            audit::AuditEntryType::SecurityEvent,
                            serde_json::json!({
                                "event": "attack_chain_detected",
                                "session_id": sid,
                                "pattern": chain.pattern_name,
                                "severity": chain.severity.to_string(),
                                "mitre": chain.mitre_id,
                                "auto_killed": false,
                            }),
                        );

                        // SLM analysis on attack chain — build graph with chain context
                        let mut chain_events: Vec<SecurityEvent> = Vec::new();
                        for me in &chain.matched_events {
                            if let Ok(mut events) = timeline_c.recent(me.pid, 120) {
                                chain_events.append(&mut events);
                            }
                        }
                        chain_events.sort_by_key(|e| e.timestamp);
                        chain_events.dedup_by(|a, b| a.id == b.id);
                        if !chain_events.is_empty() {
                            let mut graph =
                                analyzer::graph::ProvenanceGraph::from_events(&chain_events, 30);
                            graph.add_attack_chain(&chain);
                            let slm_ref = Arc::clone(&slm_c);
                            let ipc_slm = ipc_c.clone();
                            let siem_slm = Arc::clone(&siem_c);
                            tokio::spawn(async move {
                                if let Some(verdict) = slm_ref.analyze_graph(&graph, None, 90).await
                                {
                                    tracing::info!(
                                        risk = verdict.risk_score,
                                        action = ?verdict.action,
                                        model = %verdict.model,
                                        latency_ms = verdict.latency_ms,
                                        nodes = graph.node_count(),
                                        edges = graph.edge_count(),
                                        "SLM attack chain graph analysis complete"
                                    );
                                    if let Ok(payload) = serde_json::to_value(&verdict) {
                                        ipc_slm.broadcast(DaemonMessage::Threat {
                                            payload: payload.clone(),
                                        });
                                        siem_slm.forward_threat(&payload).await;
                                    }
                                }
                            });
                        }
                    }
                }

                // ML baseline anomaly detection
                let session_id_for_baseline = matched_session_id.as_deref().unwrap_or("unknown");
                if let Some(anomaly) = baseline_c.process(&ev, session_id_for_baseline) {
                    if anomaly.is_high() {
                        tracing::warn!(
                        agent  = %ev.process,
                        score  = anomaly.total_score,
                        findings = anomaly.findings.len(),
                        "Baseline anomaly detected"
                        );
                        if let Ok(payload) = serde_json::to_value(&anomaly) {
                            ipc_c.broadcast(DaemonMessage::Threat {
                                payload: payload.clone(),
                            });
                            siem_c.try_enqueue_threat(payload.clone());
                        }
                    }
                }

                // Always broadcast the event to IPC subscribers and forward to SIEM
                {
                    let siem_ref = Arc::clone(&siem_c);
                    let ev_clone = ev.clone();
                    tokio::spawn(async move {
                        siem_ref.forward_event(&ev_clone).await;
                    });
                }
                ipc_c.broadcast(DaemonMessage::Event { payload: ev });
            } // end while let
        }); // end tokio::spawn
    } // end block

    // Session reaper — periodically terminate sessions whose PIDs are all dead.
    // Prevents ghost sessions from showing up in the UI after an agent exits.
    // Also releases containment (cgroup + nftables) for dead sessions.
    {
        let reaper_sessions = Arc::clone(&sessions);
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                for session in reaper_sessions.list_active() {
                    if session.pids.is_empty() {
                        continue;
                    }
                    // Grace period: don't reap sessions younger than 30 seconds.
                    // Avoids race where session is created but process hasn't
                    // fully initialized yet.
                    let age_secs = (chrono::Utc::now() - session.start_time).num_seconds();
                    if age_secs < 30 {
                        continue;
                    }
                    // Check if ANY pid in the session is still alive
                    let any_alive = session.pids.iter().any(|&p| {
                        let ret = unsafe { libc::kill(p as libc::pid_t, 0) };
                        ret == 0
                    });
                    if !any_alive {
                        tracing::info!(
                            session_id = %session.id,
                            pids = ?session.pids,
                            age_secs,
                            "Session reaper: all PIDs dead, terminating session"
                        );
                        reaper_sessions.terminate(&session.id);
                    }
                }
            }
        });
    }

    // Periodic exfiltration confidence checker — every 10 seconds, scan tracked
    // PIDs for behavioral exfil patterns and emit alerts + prune stale entries.
    // ── Periodic session-scoped graph capture ──────────────────────────────
    // Build each active agent session's provenance graph on a timer and run it
    // through the analyzer, so the distillation corpus captures REAL multi-node
    // session graphs (claude→bash→curl) — independent of enforce/observe mode
    // and of whether any single event was blocked. Without this, capture only
    // fires on per-PID hard-blocks / high heuristics, which misses the chain.
    {
        let cap_timeline = Arc::clone(&timeline);
        let cap_sessions = Arc::clone(&sessions);
        let cap_slm = Arc::clone(&slm_analyzer);
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(30));
            loop {
                interval.tick().await;
                for session in cap_sessions.list_active() {
                    if session.pids.is_empty() {
                        continue;
                    }
                    let events = cap_timeline
                        .recent_for_pids(&session.pids, 120)
                        .unwrap_or_default();
                    if events.len() < 2 {
                        continue;
                    }
                    let graph = analyzer::graph::ProvenanceGraph::from_events(&events, 60);
                    if graph.node_count() < 2 {
                        continue; // skip trivial single-node windows
                    }
                    let score = analyzer::heuristics::score(&events).total as u32;
                    // analyze_graph's capture path records the sample to the
                    // distillation corpus whenever capture is enabled.
                    let _ = cap_slm.analyze_graph(&graph, None, score).await;
                }
            }
        });
    }

    if cfg.dlp.enabled {
        let exfil_dlp = Arc::clone(&dlp);
        let exfil_ipc = Arc::clone(&ipc);
        let exfil_siem = Arc::clone(&siem);
        let exfil_sessions = Arc::clone(&sessions);
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(10));
            loop {
                interval.tick().await;

                // Prune stale entries (older than 5 minutes)
                exfil_dlp.exfil.prune_stale().await;

                // Check confidence for all tracked PIDs
                let pids = exfil_dlp.exfil.tracked_pids().await;
                for pid in pids {
                    let process_name = resolve_comm(pid).unwrap_or_else(|| format!("pid:{}", pid));
                    if let Some(alert) = exfil_dlp
                        .exfil
                        .check_exfil_confidence(pid, &process_name)
                        .await
                    {
                        tracing::warn!(
                            pid = alert.pid,
                            process = %alert.process_name,
                            confidence = format!("{:.2}", alert.confidence),
                            indicators = %alert.indicators,
                            action = %alert.recommended_action,
                            "Data exfiltration behavior detected"
                        );

                        // Find the session for this PID
                        let session_id = exfil_sessions
                            .find_by_pid(pid)
                            .map(|s| s.id.clone())
                            .unwrap_or_else(|| "unknown".to_string());

                        // Broadcast as threat
                        if let Ok(payload) = serde_json::to_value(&serde_json::json!({
                            "type": "data_exfiltration",
                            "pid": alert.pid,
                            "process": &alert.process_name,
                            "confidence": alert.confidence,
                            "indicators": &alert.indicators,
                            "recommended_action": &alert.recommended_action,
                            "session_id": &session_id,
                        })) {
                            exfil_ipc.broadcast(common::protocol::DaemonMessage::Threat {
                                payload: payload.clone(),
                            });
                            exfil_siem.try_enqueue_threat(payload.clone());
                        }
                    }
                }
            }
        });
    }

    // Register the resolved injection-scan config so `rz scan skills` / the
    // app's "Scan Skills" honour the [model_armor] section.
    scanner::model_armor::init_skill_scan_config(scanner::model_armor::ModelArmorConfig::resolve(
        &cfg.model_armor,
    ));

    // Spawn HTTP management API on localhost:7700
    {
        let timeline_api = Arc::clone(&timeline);
        let acl_api = Arc::clone(&acl);
        let ipc_api = Arc::clone(&ipc);
        let intent_diff_api = Arc::clone(&intent_diff);
        let sessions_api = Arc::clone(&sessions);
        let audit_api = Arc::clone(&audit);
        let network_api = Arc::clone(&network);
        let jwt_issuer_api = Arc::clone(&jwt_issuer);
        let intent_policy_api = Arc::clone(&intent_policy);
        let rotation_store_api = Arc::clone(&rotation_store);
        let verified_registry_api = Arc::clone(&verified_registry);
        let baseline_engine_api = Arc::clone(&baseline_engine);
        let observer_engine_api = Arc::clone(&observer_engine);
        let correlation_engine_api = Arc::clone(&correlation_engine);
        let skill_correlation_api = Arc::clone(&skill_correlation);
        let dlp_api = Arc::clone(&dlp);
        let ebpf_active_api = Arc::clone(&ebpf_active);
        let webhooks_api = Arc::clone(&webhooks);
        let review_api = Arc::clone(&review);
        let checks_cfg_api = cfg.checks.clone();
        let checks_provider_api = checks_provider.clone();
        let events_total_api = Arc::clone(&events_total);
        let threats_blocked_api = Arc::clone(&threats_blocked);
        // L0 enforcement hook: API block_file pushes to the kernel eBPF map
        // (type-erased so the API layer never names EbpfCommand).
        let ebpf_block_api: Option<Arc<dyn Fn(String, bool) + Send + Sync>> = {
            {
                let cmd_arc = Arc::clone(&ebpf_cmd_tx);
                Some(Arc::new(move |path: String, block: bool| {
                    if let Ok(guard) = cmd_arc.try_read() {
                        if let Some(tx) = guard.as_ref() {
                            let cmd = if block {
                                ebpf_loader::EbpfCommand::BlockFile(path)
                            } else {
                                ebpf_loader::EbpfCommand::UnblockFile(path)
                            };
                            let _ = tx.try_send(cmd);
                        }
                    }
                })
                    as Arc<dyn Fn(String, bool) + Send + Sync>)
            }
        };
        // Directory restriction hook: pushes allowed dir inodes to eBPF
        let ebpf_dir_api: Option<Arc<dyn Fn(String) + Send + Sync>> = {
            {
                let cmd_arc = Arc::clone(&ebpf_cmd_tx);
                Some(Arc::new(move |path: String| {
                    if let Ok(guard) = cmd_arc.try_read() {
                        if let Some(tx) = guard.as_ref() {
                            let cmd = if path.is_empty() {
                                ebpf_loader::EbpfCommand::ClearAllowedDirs
                            } else {
                                ebpf_loader::EbpfCommand::SetAllowedDir(path)
                            };
                            let _ = tx.try_send(cmd);
                        }
                    }
                }) as Arc<dyn Fn(String) + Send + Sync>)
            }
        };
        // Blocked directory hook: pushes blocked dir inodes to eBPF
        let ebpf_block_dir_api: Option<Arc<dyn Fn(String) + Send + Sync>> = {
            {
                let cmd_arc = Arc::clone(&ebpf_cmd_tx);
                Some(Arc::new(move |path: String| {
                    if let Ok(guard) = cmd_arc.try_read() {
                        if let Some(tx) = guard.as_ref() {
                            let cmd = if path.is_empty() {
                                ebpf_loader::EbpfCommand::ClearBlockedDirs
                            } else {
                                ebpf_loader::EbpfCommand::BlockDir(path)
                            };
                            let _ = tx.try_send(cmd);
                        }
                    }
                }) as Arc<dyn Fn(String) + Send + Sync>)
            }
        };
        tokio::spawn(async move {
            if let Err(e) = api::server::start(
                timeline_api,
                acl_api,
                ipc_api,
                intent_diff_api,
                sessions_api,
                audit_api,
                network_api,
                jwt_issuer_api,
                intent_policy_api,
                rotation_store_api,
                verified_registry_api,
                baseline_engine_api,
                observer_engine_api,
                correlation_engine_api,
                dlp_api,
                ebpf_active_api,
                events_total_api,
                threats_blocked_api,
                skill_correlation_api,
                ebpf_block_api,
                ebpf_dir_api,
                ebpf_block_dir_api,
                webhooks_api,
                review_api,
                checks_cfg_api,
                checks_provider_api,
                &http_bind,
            )
            .await
            {
                tracing::error!(err = %e, "HTTP API server error");
            }
        });
    }

    // Proxy events channel — bridges SSL-uprobe / gateway / forward-proxy
    // SecurityEvents into the IPC broadcast pipeline.
    let (proxy_event_tx, mut proxy_event_rx) = mpsc::channel::<common::event::SecurityEvent>(256);

    // Stdio capture: read/write tracepoints on the terminal of any process whose
    // comm looks like an agent. Deliberately independent of the harness having a
    // hook configured — a hook is configuration owned by the thing being
    // watched, and it can be absent, wrong, or edited by the agent itself.
    //
    // Captured text is redacted before it is stored or scored. The switch is
    // [stdio_capture] enabled, so an operator can run kernel enforcement with
    // no terminal capture at all.
    // WHAT THE CHECKS LAYER ACTUALLY HAS TO WORK WITH.
    //
    // Agent hooks are opt-in, so on a default install there is no hook and the
    // layer's inputs are captured terminal output and the kernel event stream.
    // A layer that is enabled with nothing feeding it should say so at startup
    // rather than look healthy and score nothing.
    if cfg.checks.enabled {
        let hook = agent_hook_configured();
        let capture = cfg.stdio_capture.enabled && cfg.stdio_capture.score;
        if !hook && !capture {
            tracing::warn!(
                "The checks layer is enabled but has no input: no agent hook is configured and                  terminal capture is off (or not scored). It will score nothing. Turn on                  [stdio_capture] enabled and score, or install the optional agent hook with                  RZ_INSTALL_AGENT_HOOKS=1."
            );
        } else if !hook {
            tracing::info!(
                "No agent hook configured — the checks layer is scoring captured terminal                  output. The hook is optional and adds pre-execution tool arguments."
            );
        }

        // blocking only means anything where a call can be declined BEFORE it
        // runs, and the hook is the only place that happens.
        if cfg.checks.blocking && !hook {
            tracing::warn!(
                "[checks] blocking = true has NO EFFECT here: declining a tool call before it                  runs happens in the agent hook, and no hook is configured. Nothing will be                  blocked by this setting. Install the optional hook with                  RZ_INSTALL_AGENT_HOOKS=1, or set blocking = false. Kernel enforcement is                  unaffected and continues either way."
            );
        }
    }

    // ── Hostname allowlisting, learned from observed DNS answers ──────────
    //
    // Fed by the DNS capture that rides in the stdio object. A static address
    // list cannot track a CDN-fronted endpoint, so this is what makes
    // [egress] allow_names mean anything.
    let dns_allow = if cfg.egress.allow_names.is_empty() {
        None
    } else {
        Some(Arc::new(tokio::sync::Mutex::new(
            dns_allow::DnsAllowManager::new(
                dns_allow::NameAllowlist::new(cfg.egress.allow_names.clone()),
                Arc::clone(&ebpf_cmd_tx),
            ),
        )))
    };

    let stdio_exec_tx = if cfg.stdio_capture.enabled {
        let redaction = cfg.webhooks.redaction.clone();
        match integrations::webhook::Redactor::new(&redaction) {
            Ok(r) => {
                let redact: Arc<dyn Fn(&mut serde_json::Value) + Send + Sync> =
                    Arc::new(move |v: &mut serde_json::Value| r.redact(v));
                let scorer = if cfg.stdio_capture.score {
                    checks_provider.clone()
                } else {
                    None
                };
                if cfg.stdio_capture.score && scorer.is_none() {
                    tracing::info!(
                        "[stdio_capture] score = true but the checks layer is off, so captured                          output is recorded and not scored. Enable [checks] to score it."
                    );
                }
                let ctx = stdio_capture::CaptureContext {
                    redact,
                    scorer,
                    max_event_bytes: cfg.stdio_capture.max_event_bytes,
                    review: Some(review.clone()),
                    dns: dns_allow.clone(),
                };
                tracing::info!(
                    score = cfg.stdio_capture.score,
                    max_event_bytes = cfg.stdio_capture.max_event_bytes,
                    "Terminal capture enabled — captured text is redacted before it is stored"
                );
                Some(stdio_capture::spawn_auto(proxy_event_tx.clone(), ctx))
            }
            Err(e) => {
                // Capture without redaction would write raw terminal text,
                // including whatever secrets it contained, into the timeline.
                // Refuse rather than capture unredacted.
                tracing::error!(
                    err = %e,
                    "[webhooks.redaction] is unusable, so terminal capture is OFF: capturing                      without redaction would store raw output"
                );
                None
            }
        }
    } else {
        tracing::info!("Terminal capture is off ([stdio_capture] enabled = false)");
        None
    };
    let _ = &stdio_exec_tx;

    // The DNS answer capture only exists while terminal capture is running:
    // it is attached from the stdio object. With capture off (by config, or
    // because redaction was unusable), allow_names can never learn anything,
    // so say so now and name the real cause rather than wait five minutes and
    // blame encrypted DNS.
    let dns_feed = stdio_exec_tx.is_some();
    if dns_allow.is_some() && !dns_feed {
        tracing::warn!(
            allow_names = cfg.egress.allow_names.len(),
            "HOSTNAME ALLOWLISTING IS OFF: [egress] allow_names is set, but the DNS answer \
             capture it learns from is attached with terminal capture, which is not running \
             ([stdio_capture] enabled = false, or redaction is unusable). No name will ever be \
             allowed. Turn [stdio_capture] enabled on, or list literal addresses in [egress] allow."
        );
    }

    // TTL expiry, and the loud failure when nothing is ever learned.
    if let Some(mgr) = dns_allow.clone().filter(|_| dns_feed) {
        let taint_on = cfg.egress.taint_on_egress;
        let names = cfg.egress.allow_names.len();
        tokio::spawn(async move {
            let started = std::time::Instant::now();
            let mut warned = false;
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(30)).await;
                mgr.lock().await.expire_now().await;

                // A FEATURE THAT QUIETLY DOES NOTHING IS THE FAILURE MODE TO
                // AVOID. If no answer for any allowlisted name has been seen a
                // few minutes in, hostname allowlisting is not working on this
                // host, and we can name the likely cause in advance.
                if !warned
                    && taint_on
                    && started.elapsed() >= std::time::Duration::from_secs(300)
                    && mgr.lock().await.learned_count() == 0
                {
                    warned = true;
                    tracing::warn!(
                        allow_names = names,
                        "HOSTNAME ALLOWLISTING IS NOT WORKING ON THIS HOST. Five minutes in, no \
                         DNS answer has been observed for any name in [egress] allow_names, so \
                         the egress allowlist is empty. The usual cause is encrypted DNS: with \
                         DNS over HTTPS or TLS there is no plaintext answer to read, and \
                         systemd-resolved can be configured that way. A connected UDP socket \
                         that reports no source address has the same effect. With \
                         taint_on_egress on, every session will be tainted, and with enforce on \
                         everything off-allowlist will be refused. Fix it by listing literal \
                         addresses in [egress] allow, or turn taint_on_egress off."
                    );
                }
            }
        });
    }

    // ── Scan what an agent writes, when the write finishes ────────────────
    //
    // fanotify CLOSE_WRITE, mount-wide, with the writing pid. Only files
    // written from inside a tracked agent tree are read. The verdict is stored
    // as one bit per (dev, ino) that the kernel reads later; the scan itself is
    // never on a syscall path.
    //
    // ENFORCEMENT IS OFF UNLESS ASKED FOR. Refusing to run a file is sharper
    // than anything else this daemon does by default.
    if cfg.scanner.write_scan.enabled {
        if let Err(e) = cfg.scanner.write_scan.validate() {
            return Err(anyhow::anyhow!("{e}"));
        }
        let redaction = cfg.webhooks.redaction.clone();
        match integrations::webhook::Redactor::new(&redaction) {
            Ok(r) => {
                let redact: Arc<dyn Fn(&mut serde_json::Value) + Send + Sync> =
                    Arc::new(move |v: &mut serde_json::Value| r.redact(v));
                if cfg.scanner.write_scan.enforce {
                    tracing::warn!(
                        severity = %cfg.scanner.write_scan.enforce_severity,
                        "Write-scan QUARANTINE ENFORCEMENT IS ON: the kernel will refuse to open                          or exec an agent-written file that a deterministic pattern flagged at                          or above this severity"
                    );
                } else {
                    tracing::info!(
                        "Write scan enabled, enforcement OFF: agent-written files are scanned                          and recorded, and still run. Set [scanner.write_scan] enforce = true to                          quarantine them."
                    );
                }
                if cfg.scanner.write_scan.fail_closed {
                    tracing::warn!(
                        "[scanner.write_scan] fail_closed = true pauses every agent-written file                          until it has been scanned"
                    );
                }
                write_scan::spawn(write_scan::ScanContext {
                    cfg: cfg.scanner.write_scan.clone(),
                    // The handle, not a snapshot: this runs before the eBPF
                    // subsystem starts.
                    ebpf: Arc::clone(&ebpf_cmd_tx),
                    events: proxy_event_tx.clone(),
                    review: Some(review.clone()),
                    redact,
                });
            }
            Err(e) => {
                tracing::error!(
                    err = %e,
                    "[webhooks.redaction] is unusable, so write scanning is OFF: findings would                      be stored unredacted"
                );
            }
        }
    }

    // ── Egress narrowing on taint ─────────────────────────────────────────
    //
    // Seed the allowlist and set the enforce flag once the eBPF subsystem is
    // up. Loopback is handled in the kernel inline; the LLM endpoints and the
    // operator's own entries are pushed here. OFF by default: flipping
    // socket_connect to enforce is an operator's deliberate choice.
    {
        let handle = Arc::clone(&ebpf_cmd_tx);
        let egress = cfg.egress.clone();
        tokio::spawn(async move {
            // Wait for the sender to exist.
            let mut tx = None;
            for _ in 0..60 {
                if let Some(t) = handle.read().await.clone() {
                    tx = Some(t);
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(500)).await;
            }
            let Some(tx) = tx else {
                if egress.enforce {
                    tracing::warn!("egress: eBPF subsystem never came up; enforcement NOT active");
                }
                return;
            };

            // The LLM endpoints, so a tainted agent keeps reaching its model.
            let llm = crate::policy::network::resolved_llm_ipv4s();
            for ip in &llm {
                let _ = tx
                    .send(ebpf_loader::EbpfCommand::AllowEgressIp(ip.to_string()))
                    .await;
            }
            // The operator's additions, hosts resolved once.
            let mut extra = 0usize;
            for entry in &egress.allow {
                let ips: Vec<String> = if entry.parse::<std::net::Ipv4Addr>().is_ok() {
                    vec![entry.clone()]
                } else {
                    std::net::ToSocketAddrs::to_socket_addrs(&format!("{entry}:443"))
                        .map(|it| {
                            it.filter_map(|a| match a.ip() {
                                std::net::IpAddr::V4(v4) => Some(v4.to_string()),
                                _ => None,
                            })
                            .collect()
                        })
                        .unwrap_or_default()
                };
                for ip in ips {
                    let _ = tx.send(ebpf_loader::EbpfCommand::AllowEgressIp(ip)).await;
                    extra += 1;
                }
            }

            let _ = tx
                .send(ebpf_loader::EbpfCommand::SetTaintOnEgress(
                    egress.taint_on_egress,
                ))
                .await;
            if egress.taint_on_egress {
                tracing::info!(
                    "Taint on external egress ON: an agent-tree process that connects off the \
                     allowlist is marked as having ingested external content. DNS and the \
                     allowlisted model endpoints are excluded, or a normal session would be \
                     tainted within a second of starting."
                );
            } else if egress.enforce {
                tracing::warn!(
                    "EGRESS ENFORCEMENT IS ON but [egress] taint_on_egress is off, so the kernel \
                     never marks a process as having ingested external content. Unless something \
                     else raises taint, nothing will be refused."
                );
            }

            let _ = tx
                .send(ebpf_loader::EbpfCommand::SetEgressEnforce(egress.enforce))
                .await;
            if egress.enforce {
                tracing::warn!(
                    llm_endpoints = llm.len(),
                    operator_allow = extra,
                    "EGRESS ENFORCEMENT IS ON: a process that ingested external content is \
                     refused any connection off the allowlist (loopback + LLM + operator allow)"
                );
            } else {
                tracing::info!(
                    "Egress enforcement OFF: off-allowlist connects from a tainted process are \
                     recorded, not refused. Set [egress] enforce = true to refuse them."
                );
            }
        });
    }

    // ── Transcript taint watcher ──────────────────────────────────────────
    //
    // Raises taint when a transcript record shows external content was ingested
    // (web fetch, web search, MCP). Deterministic provenance, not a content
    // judgment. Its own switch, so egress can be seeded another way without it.
    if cfg.transcript_watch.enabled {
        tracing::info!("Transcript taint watcher enabled");
        transcript_taint::spawn(transcript_taint::WatchContext {
            cfg: cfg.transcript_watch.clone(),
            ebpf: Arc::clone(&ebpf_cmd_tx),
            started_at: std::time::SystemTime::now(),
        });
    } else {
        tracing::info!("Transcript taint watcher off ([transcript_watch] enabled = false)");
    }

    // Start SSL uprobe interceptor (captures LLM API plaintext at library level)
    // Uses uprobes on SSL_read/SSL_write — no proxy config needed.
    // Passes SessionStore so the interceptor can enforce session approval.
    // Running-agent discovery: register a session for every live AI-agent process
    // by scanning /proc (cmdline-aware), so agents show up in Sessions the moment
    // they run — not only when they make a recognized LLM API call. This is what
    // makes Node/Python CLIs (Gemini CLI runs as `node`/`MainThread`, not
    // `gemini`) appear at all.
    {
        let scan_sessions = Arc::clone(&sessions);
        let scan_observer = Arc::clone(&observer_engine);
        let scan_cmd = Arc::clone(&ebpf_cmd_tx);
        tokio::spawn(async move {
            // Tell the kernel to capture events for a cmdline-detected agent pid.
            let track = move |pid: u32| {
                if let Ok(guard) = scan_cmd.try_read() {
                    if let Some(tx) = guard.as_ref() {
                        let _ = tx.try_send(ebpf_loader::EbpfCommand::TrackAgentPid(pid));
                    }
                }
            };
            let mut tick = tokio::time::interval(std::time::Duration::from_secs(4));
            loop {
                tick.tick().await;
                session::scan::reconcile(&scan_sessions, &scan_observer, &track).await;
            }
        });
    }

    // Bridge proxy events → IPC broadcast + timeline persistence
    // This connects the TLS proxy, SSL uprobes, and other SecurityEvent producers
    // into the main event pipeline so UI/SIEM see all events.
    {
        let ipc_proxy = Arc::clone(&ipc);
        let timeline_proxy = Arc::clone(&timeline);
        let siem_proxy = Arc::clone(&siem);
        let events_total_proxy = Arc::clone(&events_total);
        let threats_blocked_proxy = Arc::clone(&threats_blocked);
        tokio::spawn(async move {
            while let Some(ev) = proxy_event_rx.recv().await {
                tracing::warn!(
                    kind = ?ev.kind,
                    target = %ev.target,
                    "Proxy event → pipeline"
                );
                // Persist to timeline + update counters
                let _ = timeline_proxy.insert(&ev);
                events_total_proxy.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                if !ev.allowed {
                    threats_blocked_proxy.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                }
                // Forward to SIEM
                let siem_ref = Arc::clone(&siem_proxy);
                let ev_siem = ev.clone();
                tokio::spawn(async move {
                    siem_ref.forward_event(&ev_siem).await;
                });
                // Broadcast to IPC subscribers (Tauri app, CLI)
                ipc_proxy.broadcast(common::protocol::DaemonMessage::Event { payload: ev });
            }
        });
    }

    // Periodic sled pruning — 7-day retention + 100MB cap
    // Runs on startup and every 5 minutes
    {
        let timeline_prune = Arc::clone(&timeline);
        const RETENTION_SECS: i64 = 7 * 24 * 3600; // 7 days
        const MAX_DB_BYTES: u64 = 100 * 1024 * 1024; // 100 MB

        // Prune on startup
        if let Err(e) = timeline_prune.prune(RETENTION_SECS, MAX_DB_BYTES) {
            tracing::warn!(err = %e, "Startup sled prune failed");
        }

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(5 * 60));
            interval.tick().await; // first tick is immediate, skip it
            loop {
                interval.tick().await;
                if let Err(e) = timeline_prune.prune(RETENTION_SECS, MAX_DB_BYTES) {
                    tracing::warn!(err = %e, "Periodic sled prune failed");
                }
            }
        });
    }

    tracing::info!("Ring Zero Security daemon ready");

    // SIGHUP hot-reload — re-read config and update SIEM + DLP
    {
        let siem_reload = Arc::clone(&siem);
        let dlp_reload = Arc::clone(&dlp);
        let ebpf_cmd_reload = Arc::clone(&ebpf_cmd_tx);
        let webhooks_reload = Arc::clone(&webhooks);
        let sessions_reload = Arc::clone(&sessions);
        tokio::spawn(async move {
            {
                use tokio::signal::unix::{signal, SignalKind};
                if let Ok(mut sig) = signal(SignalKind::hangup()) {
                    loop {
                        sig.recv().await;
                        tracing::info!("SIGHUP received — reloading config");
                        // A config that fails to parse or validate keeps the
                        // running config; a security daemon must not fall back
                        // to defaults because of a typo.
                        let new_cfg = match config::DaemonConfig::load_strict() {
                            Ok(c) => c,
                            Err(e) => {
                                tracing::error!(err = %e, "Config reload rejected — keeping the previous config");
                                continue;
                            }
                        };
                        siem_reload.update_config(new_cfg.to_siem_config()).await;

                        // Rebuild the webhook dispatcher (endpoints, hooks, redaction)
                        match integrations::webhook::WebhookDispatcher::start(
                            &new_cfg.webhooks,
                            Some(Arc::clone(&sessions_reload)),
                        ) {
                            Ok(d) => {
                                webhooks_reload.replace(d);
                                tracing::info!("Webhook config reloaded");
                            }
                            Err(e) => {
                                tracing::error!(err = %e, "Webhook reload failed — keeping the previous webhook config")
                            }
                        }

                        // Reload DLP key routes from config
                        if new_cfg.dlp.enabled {
                            let dlp_routes: Vec<secrets::dlp::DlpRouteConfig> = new_cfg
                                .dlp
                                .key_routes
                                .iter()
                                .map(|r| secrets::dlp::DlpRouteConfig {
                                    key_env_var: r.env_var.clone(),
                                    destination: r.destination.clone(),
                                })
                                .collect();
                            dlp_reload.load_from_config(&dlp_routes).await;
                            dlp_reload.load_pii_config(&new_cfg.dlp.pii);
                            tracing::info!(
                                routes = dlp_routes.len(),
                                "DLP routes + PII config reloaded"
                            );
                        }

                        // Push DLP enabled/enforce state to eBPF
                        {
                            if let Some(ref cmd_tx) = *ebpf_cmd_reload.read().await {
                                let _ = cmd_tx.try_send(ebpf_loader::EbpfCommand::SetDlpEnabled(
                                    new_cfg.dlp.enabled,
                                ));
                                let _ = cmd_tx.try_send(ebpf_loader::EbpfCommand::SetEnforce(
                                    new_cfg.is_enforce(),
                                ));
                            }
                        }

                        tracing::info!("Config reloaded");
                    }
                }
            }
        });
    }

    // Block forever — tokio tasks handle everything
    tokio::signal::ctrl_c().await?;
    tracing::info!("Shutting down");
    Ok(())
}
