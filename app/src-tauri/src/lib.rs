// SPDX-License-Identifier: Apache-2.0
// Ring Zero Security desktop app — Tauri backend.
//
// The webview never talks to the daemon directly: every call goes through the
// commands below, which run in the Rust backend (not subject to browser CORS)
// and attach the operator's local API token. Two transports are used:
//   - the daemon's HTTP management API on 127.0.0.1:7700 (bearer token)
//   - the daemon's Unix socket (newline-delimited JSON, peer-credential checked)

mod privileged;

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tauri::tray::TrayIconBuilder;
use tauri::Manager;

// ── Socket path ──────────────────────────────────────────────────────────────

fn socket_path() -> String {
    // Production daemon (root) listens here; the peer-credential check inside
    // the daemon decides whether this user may connect, so probe with a real
    // connect rather than a bare exists() check.
    let root = "/var/run/ringzero/daemon.sock";
    if std::path::Path::new(root).exists() && UnixStream::connect(root).is_ok() {
        return root.to_string();
    }
    // Dev daemon (non-root `cargo run -p daemon`) uses the XDG runtime dir.
    let xdg = std::env::var("XDG_RUNTIME_DIR").unwrap_or_else(|_| "/tmp".into());
    format!("{}/ringzero/daemon.sock", xdg)
}

// ── Daemon wire types ─────────────────────────────────────────────────────────

/// Mirrors the daemon's EventKind enum (snake_case tags from protocol.rs).
#[derive(Debug, Serialize, Deserialize, Clone)]
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
    LlmRequest,
    LlmResponse,
    LlmToolCall,
    ProxyBlock,
    ProxyDetection,
    DlpPii,
    TamperPtrace,
    TamperSignal,
    TamperMount,
    TamperUmount,
    ContainedExecBlocked,
    ContainedFileBlocked,
    OffensivePrompt,
    PromptInjection,
    MprotectWx,
    AttackChain,
    SkillFileChange,
    SkillGitRepoDrop,
    TranscriptWrite,
    /// Text the agent wrote to its terminal, captured by the kernel.
    #[serde(alias = "llm_response")]
    AgentStdout,
    /// Text the agent read from its terminal.
    #[serde(alias = "llm_request")]
    AgentStdin,
}

impl std::fmt::Display for EventKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            EventKind::FileOpen => "file_open",
            EventKind::FileCreate => "file_create",
            EventKind::FileDelete => "file_delete",
            EventKind::FileRename => "file_rename",
            EventKind::FileWrite => "file_write",
            EventKind::ProcessExec => "process_exec",
            EventKind::ProcessFork => "process_fork",
            EventKind::ProcessExit => "process_exit",
            EventKind::NetworkConnect => "network_connect",
            EventKind::NetworkSend => "network_send",
            EventKind::NetworkRecv => "network_recv",
            EventKind::DnsQuery => "dns_query",
            EventKind::McpToolCall => "mcp_tool_call",
            EventKind::LlmRequest => "llm_request",
            EventKind::LlmResponse => "llm_response",
            EventKind::LlmToolCall => "llm_tool_call",
            EventKind::ProxyBlock => "proxy_block",
            EventKind::ProxyDetection => "proxy_detection",
            EventKind::DlpPii => "dlp_pii",
            EventKind::TamperPtrace => "tamper_ptrace",
            EventKind::TamperSignal => "tamper_signal",
            EventKind::TamperMount => "tamper_mount",
            EventKind::TamperUmount => "tamper_umount",
            EventKind::ContainedExecBlocked => "contained_exec_blocked",
            EventKind::ContainedFileBlocked => "contained_file_blocked",
            EventKind::OffensivePrompt => "offensive_prompt",
            EventKind::PromptInjection => "prompt_injection",
            EventKind::MprotectWx => "mprotect_wx",
            EventKind::AttackChain => "attack_chain",
            EventKind::SkillFileChange => "skill_file_change",
            EventKind::SkillGitRepoDrop => "skill_git_repo_drop",
            EventKind::TranscriptWrite => "transcript_write",
            EventKind::AgentStdout => "agent_stdout",
            EventKind::AgentStdin => "agent_stdin",
        };
        write!(f, "{}", s)
    }
}

/// Mirrors the daemon's SecurityEvent struct (from event.rs).
/// `timestamp` is an ISO-8601 string.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct DaemonSecurityEvent {
    pub id: String,
    pub kind: EventKind,
    pub pid: u32,
    pub uid: u32,
    pub process: String,
    pub target: String,
    pub allowed: bool,
    pub reason: Option<String>,
    pub timestamp: String,
    #[serde(default)]
    pub ppid: Option<u32>,
    #[serde(default)]
    pub parent_process: Option<String>,
    #[serde(default)]
    pub llm_context: Option<serde_json::Value>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "snake_case")]
pub struct DaemonStatus {
    pub connected: bool,
    pub driver_connected: Option<bool>,
    pub version: Option<String>,
    pub uptime: Option<u64>,
    pub threats_blocked: Option<u64>,
    pub skills_monitored: Option<u64>,
    pub ebpf_active: Option<bool>,
    pub kernel_monitoring: Option<String>,
    pub enforce_mode: Option<bool>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Skill {
    pub id: String,
    pub name: String,
    pub author: String,
    pub path: String,
    pub is_verified: bool,
    pub last_scan: String,
    pub threat_level: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Event {
    pub id: String,
    pub r#type: String,
    pub skill_name: String,
    pub target: String,
    pub allowed: bool,
    pub timestamp: String,
    pub reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ppid: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_process: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub llm_context: Option<serde_json::Value>,
}

// ── Daemon IPC client (Unix socket) ───────────────────────────────────────────

fn daemon_request(payload: serde_json::Value) -> anyhow::Result<serde_json::Value> {
    let mut stream = UnixStream::connect(socket_path())?;
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;

    let msg = serde_json::to_string(&payload)? + "\n";
    stream.write_all(msg.as_bytes())?;

    let mut reader = BufReader::new(stream);
    let mut response = String::new();
    reader.read_line(&mut response)?;

    Ok(serde_json::from_str(&response)?)
}

// ── Daemon HTTP client ────────────────────────────────────────────────────────

const DAEMON_HTTP: &str = "http://127.0.0.1:7700";

/// Resolve the daemon API token a local client can read. The daemon writes the
/// full token 0600; on this host the operator user's copy lives at
/// ~/.config/ringzero/api-token (the app runs as that user).
fn api_token() -> Option<String> {
    if let Ok(t) = std::env::var("RZ_API_TOKEN") {
        if !t.trim().is_empty() {
            return Some(t.trim().to_string());
        }
    }
    let mut cands: Vec<String> = Vec::new();
    if let Ok(h) = std::env::var("HOME") {
        cands.push(format!("{h}/.config/ringzero/api-token"));
    }
    cands.push("/var/lib/ringzero/api-token".into());
    cands.push("/root/.config/ringzero/api-token".into());
    for p in cands {
        if let Ok(s) = std::fs::read_to_string(&p) {
            let s = s.trim().to_string();
            if !s.is_empty() {
                return Some(s);
            }
        }
    }
    None
}

/// Only these methods may be forwarded to the daemon from the webview.
fn validate_method(method: &str) -> Result<&'static str, String> {
    match method.to_ascii_uppercase().as_str() {
        "GET" => Ok("GET"),
        "POST" => Ok("POST"),
        "PUT" => Ok("PUT"),
        "DELETE" => Ok("DELETE"),
        other => Err(format!("method not allowed: {other}")),
    }
}

/// The webview may only address the daemon's versioned API, by relative path.
/// Anything that could escape it (absolute URL, scheme, traversal, CR/LF,
/// whitespace, or a `//` that would be read as an authority) is rejected.
fn validate_api_path(path: &str) -> Result<(), String> {
    if !path.starts_with("/api/v1/") {
        return Err("path must start with /api/v1/".into());
    }
    if path.contains("..")
        || path.contains("://")
        || path.contains("//")
        || path.contains('\\')
        || path.chars().any(|c| c.is_control() || c.is_whitespace())
        || path.len() > 2048
    {
        return Err("invalid path".into());
    }
    Ok(())
}

/// Call the daemon's HTTP API from the Rust backend (NOT the webview), so it's
/// not subject to browser CORS and carries the bearer token.
fn http_json(
    method: &str,
    path: &str,
    body: Option<serde_json::Value>,
) -> anyhow::Result<serde_json::Value> {
    let method = validate_method(method).map_err(|e| anyhow::anyhow!(e))?;
    validate_api_path(path).map_err(|e| anyhow::anyhow!(e))?;
    tokio::task::block_in_place(|| {
        let url = format!("{DAEMON_HTTP}{path}");
        // Most calls answer immediately. A skill scan does not: with the model
        // layer on it makes one call per instruction-bearing file, so a single
        // scan of a real agent directory runs for tens of seconds. An 8s
        // timeout turned that into "Scan failed" while the daemon was still
        // working, which is a lie the user has no way to see through.
        let timeout = if path.starts_with("/api/v1/skill-scan") {
            Duration::from_secs(300)
        } else {
            Duration::from_secs(8)
        };
        let client = reqwest::blocking::Client::builder()
            .timeout(timeout)
            .redirect(reqwest::redirect::Policy::none())
            .build()?;
        let mut rb = match method {
            "POST" => client.post(&url),
            "PUT" => client.put(&url),
            "DELETE" => client.delete(&url),
            _ => client.get(&url),
        };
        if let Some(t) = api_token() {
            rb = rb.bearer_auth(t);
        }
        if let Some(b) = body {
            rb = rb.json(&b);
        }
        let resp = rb.send()?;
        if !resp.status().is_success() {
            anyhow::bail!("daemon {method} {path} -> {}", resp.status());
        }
        Ok(resp
            .json::<serde_json::Value>()
            .unwrap_or(serde_json::Value::Null))
    })
}

/// Fetch + parse the event timeline over HTTP. `kind` is an optional
/// comma-separated filter the HTTP endpoint understands.
fn http_events(limit: u32, kind: Option<&str>) -> Vec<DaemonSecurityEvent> {
    let mut path = format!("/api/v1/events?limit={}", limit.min(1000));
    if let Some(k) = kind {
        // Event kinds are snake_case identifiers; refuse anything else so the
        // filter can't smuggle extra query parameters.
        if !k.is_empty()
            && k.chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == ',')
        {
            path.push_str(&format!("&kind={k}"));
        }
    }
    match http_json("GET", &path, None) {
        Ok(v) => v
            .as_array()
            .map(|arr| {
                arr.iter()
                    .filter_map(|e| serde_json::from_value::<DaemonSecurityEvent>(e.clone()).ok())
                    .collect()
            })
            .unwrap_or_default(),
        Err(_) => Vec::new(),
    }
}

/// Convert a DaemonSecurityEvent into the Tauri-facing Event struct.
fn to_tauri_event(se: DaemonSecurityEvent) -> Event {
    Event {
        id: se.id,
        r#type: se.kind.to_string(),
        skill_name: se.process,
        target: se.target,
        allowed: se.allowed,
        timestamp: se.timestamp,
        reason: se.reason,
        ppid: se.ppid,
        parent_process: se.parent_process,
        llm_context: se.llm_context,
    }
}

// ── Privileged writes ─────────────────────────────────────────────────────────

/// Run one allow-listed `rz` command as root through polkit, and say plainly
/// what happened.
///
/// This app keeps the read-only token for everything it reads; the full-scope
/// token stays root-only and never enters this process. A write goes through
/// `pkexec`, so the privilege boundary is an interactive administrator
/// authentication that an agent running as the developer cannot satisfy.
#[tauri::command]
async fn privileged_rz(args: Vec<String>) -> Result<serde_json::Value, String> {
    let display = crate::privileged::display_command(&args);
    let outcome = tokio::task::spawn_blocking(move || crate::privileged::run(&args))
        .await
        .map_err(|e| e.to_string())?;

    let message = match &outcome {
        crate::privileged::Outcome::Ok { stdout } => {
            if stdout.is_empty() {
                "Applied.".to_string()
            } else {
                stdout.clone()
            }
        }
        crate::privileged::Outcome::Cancelled => {
            "Authentication was cancelled, so nothing was changed.".to_string()
        }
        crate::privileged::Outcome::Unavailable { message } => message.clone(),
        crate::privileged::Outcome::Failed { code, stderr } => {
            if stderr.is_empty() {
                format!("rz exited {code}")
            } else {
                stderr.clone()
            }
        }
    };

    Ok(serde_json::json!({
        "ok": matches!(outcome, crate::privileged::Outcome::Ok { .. }),
        "status": outcome.status(),
        "message": message,
        "command": display,
    }))
}

// ── Tauri commands ────────────────────────────────────────────────────────────

/// Generic daemon HTTP passthrough for UI components. Restricted to
/// GET/POST/PUT/DELETE against relative `/api/v1/...` paths on the local daemon.
#[tauri::command]
async fn daemon_api(
    method: String,
    path: String,
    body: Option<serde_json::Value>,
) -> Result<serde_json::Value, String> {
    validate_method(&method)?;
    validate_api_path(&path)?;
    http_json(&method, &path, body).map_err(|e| e.to_string())
}

#[tauri::command]
async fn get_status() -> Result<DaemonStatus, String> {
    match http_json("GET", "/api/v1/status", None) {
        Ok(s) => Ok(DaemonStatus {
            connected: true,
            driver_connected: s["driver_connected"].as_bool(),
            version: s["version"]
                .as_str()
                .map(|v| v.to_string())
                .or_else(|| Some("0.1.0".to_string())),
            uptime: s["uptime"].as_u64(),
            threats_blocked: s["threats_blocked"].as_u64(),
            skills_monitored: s["skills_monitored"].as_u64(),
            ebpf_active: s["ebpf_active"].as_bool(),
            kernel_monitoring: s["kernel_monitoring"].as_str().map(|v| v.to_string()),
            enforce_mode: s["enforce_mode"].as_bool(),
        }),
        Err(_) => Ok(DaemonStatus {
            connected: false,
            driver_connected: None,
            version: None,
            uptime: None,
            threats_blocked: None,
            skills_monitored: None,
            ebpf_active: None,
            kernel_monitoring: None,
            enforce_mode: None,
        }),
    }
}

/// What this app is allowed to do, from the daemon's point of view.
///
/// The installer leaves the operator a READ-ONLY token on purpose: an AI agent
/// runs as that same user, so a full token in their home would hand the agent
/// the ability to turn enforcement off. The app therefore renders as a viewer
/// and names the command a human runs instead. Launched by root it holds the
/// full token and the controls work normally.
#[tauri::command]
async fn get_token_scope() -> Result<serde_json::Value, String> {
    match http_json("GET", "/api/v1/auth/scope", None) {
        Ok(v) => Ok(v),
        // Unreachable daemon: assume the safe answer rather than enabling
        // controls that would fail with a 403 later.
        Err(_) => Ok(serde_json::json!({
            "scope": "readonly",
            "mutating_requires": "root (sudo rz ...)",
            "unreachable": true
        })),
    }
}

#[tauri::command]
async fn get_skills() -> Result<Vec<Skill>, String> {
    // The daemon has no GetSkills command yet — the skill inventory comes from
    // `scan_skills_auto` instead.
    Ok(vec![])
}

/// Auto-discover every installed agent's skill surface and scan it. Returns the
/// daemon's SkillScanAutoResult JSON verbatim for the UI to render.
#[tauri::command]
async fn scan_skills_auto() -> Result<serde_json::Value, String> {
    daemon_request(serde_json::json!({"type": "scan_skills_auto"}))
        .map(|r| r["payload"].clone())
        .map_err(|e| e.to_string())
}

/// Subsystem health for the UI banner. Returns the daemon's /health/components
/// JSON (an unauthenticated liveness endpoint).
#[tauri::command]
async fn daemon_health() -> Result<serde_json::Value, String> {
    tokio::task::block_in_place(|| {
        let client = reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(4))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|e| e.to_string())?;
        client
            .get(format!("{DAEMON_HTTP}/api/v1/health/components"))
            .send()
            .map_err(|e| e.to_string())?
            .json::<serde_json::Value>()
            .map_err(|e| e.to_string())
    })
}

#[tauri::command]
async fn get_events(limit: Option<u32>, kind: Option<String>) -> Result<Vec<Event>, String> {
    let limit = limit.unwrap_or(100);
    let events = http_events(limit, kind.as_deref());
    Ok(events.into_iter().map(to_tauri_event).collect())
}

/// Policy update over the daemon socket. Only a fixed set of actions is
/// accepted, and the value must be a plain string or boolean.
#[tauri::command]
async fn update_policy(policy: serde_json::Value) -> Result<bool, String> {
    const ACTIONS: &[&str] = &[
        "block_file",
        "unblock_file",
        "block_domain",
        "unblock_domain",
        "block_process",
        "unblock_process",
        "set_enforce",
    ];
    let action = policy["action"].as_str().ok_or("missing action")?;
    if !ACTIONS.contains(&action) {
        return Err(format!("unknown policy action: {action}"));
    }
    // Frontend sends { action, value } for toggles and { action, name } for block/unblock.
    let value = if !policy["value"].is_null() {
        policy["value"].clone()
    } else {
        policy["name"].clone()
    };
    match &value {
        serde_json::Value::Bool(_) => {}
        serde_json::Value::String(s)
            if !s.is_empty() && s.len() <= 4096 && !s.chars().any(|c| c.is_control()) => {}
        _ => return Err("policy value must be a non-empty string or boolean".into()),
    }
    daemon_request(serde_json::json!({"type": "update_policy", "action": action, "value": value}))
        .map(|_| true)
        .map_err(|e| e.to_string())
}

// ── App entry ─────────────────────────────────────────────────────────────────

pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_single_instance::init(|app, _args, _cwd| {
            // Second instance launched — focus the existing window
            if let Some(window) = app.get_webview_window("main") {
                let _ = window.show();
                let _ = window.unminimize();
                let _ = window.set_focus();
            }
        }))
        .setup(|app| {
            // WINDOW ICON, set here rather than left to the bundler.
            //
            // tauri's codegen does embed a default window icon, but it takes
            // the FIRST entry in bundle.icon, which is icons/32x32.png — a
            // 32x32 image stretched into every place a window icon appears.
            // Setting it explicitly from the 256x256 asset gives X11 sessions
            // something that survives being scaled up.
            //
            // Under Wayland this call does nothing: the compositor takes a
            // window's icon from the .desktop file matched by app id, not from
            // the process. That is why the package ships
            // ringzero-app.desktop with Icon=ringzero-app and installs
            // ringzero-app.png into hicolor, and why the binary, the launcher,
            // the WM class and the icon all carry the one name.
            if let Some(window) = app.get_webview_window("main") {
                match tauri::image::Image::from_bytes(include_bytes!("../icons/128x128@2x.png")) {
                    Ok(img) => {
                        if let Err(e) = window.set_icon(img) {
                            eprintln!("could not set the window icon: {e}");
                        }
                    }
                    // Not fatal: a window with the wrong icon still works.
                    Err(e) => eprintln!("could not decode the window icon: {e}"),
                }
            }

            // Create tray icon using the Ring Zero logo (embedded at compile time)
            let icon = tauri::image::Image::from_bytes(include_bytes!("../icons/tray.png"))
                .expect("failed to load tray icon");
            TrayIconBuilder::new()
                .icon(icon)
                .tooltip("Ring Zero Security")
                .on_tray_icon_event(|tray, event| {
                    if let tauri::tray::TrayIconEvent::Click { .. } = event {
                        if let Some(window) = tray.app_handle().get_webview_window("main") {
                            let _ = window.show();
                            let _ = window.set_focus();
                        }
                    }
                })
                .build(app)?;
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            daemon_api,
            get_status,
            get_token_scope,
            get_skills,
            scan_skills_auto,
            daemon_health,
            get_events,
            update_policy,
            privileged_rz,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
