// SPDX-License-Identifier: Apache-2.0
// rz — Ring Zero Security CLI
// Ring Zero Security (ringzerosecurity.com)

mod build_info;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use std::path::PathBuf;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;

// ── Sandbox config (shared between setup and sandbox commands) ─────────────

/// Default files/globs to deny read access inside the sandbox.
const DEFAULT_DENY_READ: &[&str] = &[
    "id_rsa",
    "id_ed25519",
    "id_ecdsa",
    "id_dsa",
    ".env",
    "credentials",
    "passwd",
    "shadow",
    ".aws/credentials",
    ".aws/config",
    ".ssh/id_rsa",
    ".ssh/id_ed25519",
    "*.pem",
    "*.key",
    "*.p12",
];

/// Path to the sandbox config file.
fn sandbox_config_path() -> PathBuf {
    PathBuf::from("/etc/ringzero/sandbox.toml")
}

/// Path of the DENY marker — a zero-byte file bind-mounted over sensitive files.
fn deny_marker_path() -> PathBuf {
    PathBuf::from("/tmp/.ringzero-denied")
}

// ── Sandbox runner ────────────────────────────────────────────

fn run_sandboxed(real_binary: &str, args: &[String], deny_read: &[String]) -> Result<()> {
    use std::os::unix::process::CommandExt;
    use std::process::Command;

    // Ensure deny marker exists
    let marker = deny_marker_path();
    if !marker.exists() {
        std::fs::write(&marker, b"")
            .with_context(|| format!("Cannot create deny marker at {}", marker.display()))?;
    }

    // Build the inner script that applies bind mounts then execs the real binary
    // We use a shell wrapper so bind-mounts happen inside the new mount namespace
    // before exec'ing the actual target.
    let mut bind_args = String::new();
    let home = std::env::var("HOME").unwrap_or_default();

    for pattern in deny_read {
        // Resolve simple paths — no glob expansion here, just direct paths
        let candidates = if pattern.starts_with('/') {
            vec![PathBuf::from(pattern)]
        } else {
            let mut c = vec![
                PathBuf::from(format!("/etc/{pattern}")),
                PathBuf::from(format!("/root/{pattern}")),
            ];
            if !home.is_empty() {
                c.push(PathBuf::from(format!("{home}/{pattern}")));
            }
            c
        };
        for path in candidates {
            if path.exists() {
                bind_args.push_str(&format!(
                    "mount --bind {} {} 2>/dev/null || true\n",
                    marker.display(),
                    path.display()
                ));
            }
        }
    }

    let args_escaped: Vec<String> = args.iter().map(|a| shell_escape(a)).collect();
    let inner_script = format!(
        "#!/bin/sh\nset -e\n{bind_args}exec {real_binary} {}\n",
        args_escaped.join(" ")
    );

    // Write inner script to a temp file
    let script_path = format!("/tmp/.ringzero-sandbox-{}.sh", std::process::id());
    std::fs::write(&script_path, inner_script.as_bytes())
        .with_context(|| format!("Cannot write sandbox script to {script_path}"))?;
    std::fs::set_permissions(
        &script_path,
        std::os::unix::fs::PermissionsExt::from_mode(0o700),
    )
    .ok();

    // Launch with unshare: new mount + pid namespace, fork so pid 1 in namespace is our script
    // --map-root-user only works when caller is non-root; skip it when already root
    let already_root = unsafe { libc::geteuid() } == 0;
    let mut unshare_args: Vec<&str> = vec!["--mount", "--pid", "--fork"];
    if !already_root {
        unshare_args.push("--map-root-user");
    }
    unshare_args.extend_from_slice(&["sh", &script_path]);

    let err = Command::new("unshare").args(&unshare_args).exec(); // replaces current process

    // cleanup on exec failure
    let _ = std::fs::remove_file(&script_path);
    Err(anyhow::anyhow!("unshare exec failed: {err}"))
}

fn shell_escape(s: &str) -> String {
    if s.chars()
        .all(|c| c.is_alphanumeric() || "-_./=@:,".contains(c))
    {
        s.to_string()
    } else {
        format!("'{}'", s.replace('\'', "'\\''"))
    }
}

// ── Wire types (inline — avoids depending on daemon crate) ──────────────────

#[derive(Debug, serde::Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum ClientRequest {
    GetStatus,
    GetEvents {
        limit: Option<usize>,
    },
    Subscribe,
    UpdatePolicy {
        action: String,
        value: Option<serde_json::Value>,
    },
}

// ── Socket + API path helpers ─────────────────────────────────────────────────

fn default_sock() -> PathBuf {
    let sys = PathBuf::from("/var/run/ringzero/daemon.sock");
    if sys.exists() {
        return sys;
    }
    if let Ok(xdg) = std::env::var("XDG_RUNTIME_DIR") {
        let p = PathBuf::from(xdg).join("ringzero/daemon.sock");
        if p.exists() {
            return p;
        }
    }
    std::env::temp_dir().join("ringzero/daemon.sock")
}

fn default_api() -> String {
    std::env::var("RZ_API").unwrap_or_else(|_| "http://127.0.0.1:7700".to_string())
}

// ── IPC helpers ───────────────────────────────────────────────────────────────

async fn send_request(sock: &PathBuf, req: &ClientRequest) -> Result<serde_json::Value> {
    let stream = UnixStream::connect(sock)
        .await
        .with_context(|| format!("Cannot connect to daemon at {}", sock.display()))?;
    let (read_half, mut write_half) = stream.into_split();
    let mut line = serde_json::to_string(req)?;
    line.push('\n');
    write_half.write_all(line.as_bytes()).await?;
    let mut reader = BufReader::new(read_half).lines();
    let resp = reader.next_line().await?.unwrap_or_default();
    let val: serde_json::Value =
        serde_json::from_str(&resp).with_context(|| format!("Invalid daemon response: {resp}"))?;
    Ok(val)
}

async fn subscribe_stream(sock: &PathBuf, limit: Option<usize>) -> Result<()> {
    let stream = UnixStream::connect(sock)
        .await
        .with_context(|| format!("Cannot connect to daemon at {}", sock.display()))?;
    let (read_half, mut write_half) = stream.into_split();
    let mut line = serde_json::to_string(&ClientRequest::Subscribe)?;
    line.push('\n');
    write_half.write_all(line.as_bytes()).await?;
    let mut reader = BufReader::new(read_half).lines();
    let mut count = 0usize;
    while let Ok(Some(line)) = reader.next_line().await {
        if line.is_empty() {
            continue;
        }
        let val: serde_json::Value = match serde_json::from_str(&line) {
            Ok(v) => v,
            Err(_) => continue,
        };
        match val["type"].as_str().unwrap_or("") {
            "subscribed" => eprintln!("Subscribed to daemon event stream. Ctrl+C to stop.\n"),
            "event" => {
                if let Some(ev) = val.get("payload") {
                    print_event(ev);
                    count += 1;
                    if let Some(lim) = limit {
                        if count >= lim {
                            break;
                        }
                    }
                }
            }
            "threat" => {
                if let Some(p) = val.get("payload") {
                    println!("[THREAT] {}", serde_json::to_string_pretty(p)?);
                }
            }
            _ => {}
        }
    }
    Ok(())
}

fn print_event(ev: &serde_json::Value) {
    let ts = ev["timestamp"].as_str().unwrap_or("?");
    let kind = ev["kind"]
        .as_str()
        .unwrap_or(ev["event_type"].as_str().unwrap_or("?"));
    let proc = ev["process"].as_str().unwrap_or("?");
    let pid = ev["pid"].as_u64().unwrap_or(0);
    let target = ev["target"].as_str().unwrap_or("?");
    let allowed = ev["allowed"].as_bool().unwrap_or(true);
    let verdict = if allowed {
        "\x1b[32mALLOW\x1b[0m"
    } else {
        "\x1b[31mBLOCK\x1b[0m"
    };
    let reason = ev["reason"].as_str().unwrap_or("");
    let rsuffix = if reason.is_empty() {
        String::new()
    } else {
        format!(" ({})", reason)
    };
    println!("{ts}  {verdict}  {kind:<20}  {proc}[{pid}]  →  {target}{rsuffix}");
}

// ── HTTP helper ───────────────────────────────────────────────────────────────

/// Where the CLI caches its raw API bearer token. The daemon only persists a
/// blake3 *hash* of the token and the desktop app keeps the raw token in the OS
/// keyring, so a headless CLI install has no other way to recover it — we keep
/// our own copy here, mode 0600. Override with $RZ_API_TOKEN_FILE.
/// The root-only token the installer places for the daemon's own use. Readable
/// only by uid 0, so it is tried only when this process is effectively root.
const ROOT_TOKEN_PATH: &str = "/var/lib/ringzero/api-token";

fn effectively_root() -> bool {
    (unsafe { libc::geteuid() }) == 0
}

/// Every place a cached API token may live, in the order they are tried:
/// `$RZ_API_TOKEN_FILE` (an explicit operator override), then this user's
/// config dir, then the root-only path — that last one only when we are root,
/// because reading it as anyone else would fail anyway.
///
/// This changes nothing about scope: the token at `ROOT_TOKEN_PATH` is the
/// full-scope one and stays root-only, and the CLI never writes to it.
fn token_candidates() -> Vec<PathBuf> {
    let mut out = Vec::new();
    if let Ok(p) = std::env::var("RZ_API_TOKEN_FILE") {
        if !p.is_empty() {
            out.push(PathBuf::from(p));
        }
    }
    if let Ok(home) = std::env::var("HOME") {
        if !home.is_empty() {
            out.push(PathBuf::from(home).join(".config/ringzero/api-token"));
        }
    }
    if effectively_root() {
        out.push(PathBuf::from(ROOT_TOKEN_PATH));
    }
    if out.is_empty() {
        out.push(std::env::temp_dir().join("ringzero-cli-api-token"));
    }
    out
}

/// Where a token this CLI registers itself is cached. Never `ROOT_TOKEN_PATH`:
/// that file belongs to the daemon and the CLI must not overwrite it.
fn token_cache_path() -> PathBuf {
    if let Ok(p) = std::env::var("RZ_API_TOKEN_FILE") {
        if !p.is_empty() {
            return PathBuf::from(p);
        }
    }
    if let Ok(home) = std::env::var("HOME") {
        if !home.is_empty() {
            return PathBuf::from(home).join(".config/ringzero/api-token");
        }
    }
    std::env::temp_dir().join("ringzero-cli-api-token")
}

/// Read a token from `path`, requiring it to look like one.
fn read_token_file(path: &std::path::Path) -> Option<String> {
    let t = std::fs::read_to_string(path).ok()?;
    let t = t.trim().to_string();
    (t.len() >= 32).then_some(t)
}

/// A token this process can already use, without registering a new one.
///
/// This is what a command calls when the daemon is useful but not required: no
/// token means fall back to doing the work locally, not fail.
fn existing_api_token() -> Option<String> {
    if let Ok(t) = std::env::var("RZ_API_TOKEN") {
        if t.len() >= 32 {
            return Some(t);
        }
    }
    token_candidates().iter().find_map(|p| read_token_file(p))
}

/// One line per place we looked, saying what was there. Used in the error the
/// operator actually reads, so it never has to guess what the CLI tried.
fn token_search_report() -> String {
    let mut lines = Vec::new();
    match std::env::var("RZ_API_TOKEN") {
        Ok(t) if t.len() >= 32 => lines.push("  $RZ_API_TOKEN  set".to_string()),
        Ok(t) if !t.is_empty() => lines.push(format!(
            "  $RZ_API_TOKEN  set but only {} chars long, ignored",
            t.len()
        )),
        _ => lines.push("  $RZ_API_TOKEN  not set".to_string()),
    }
    let candidates = token_candidates();
    let width = candidates
        .iter()
        .map(|p| p.display().to_string().chars().count())
        .chain(std::iter::once(31))
        .max()
        .unwrap_or(31);
    for p in &candidates {
        let what = match std::fs::metadata(p) {
            Ok(_) if read_token_file(p).is_some() => "readable".to_string(),
            Ok(_) => "present but does not hold a token".to_string(),
            Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
                format!("exists, not readable by uid {}", unsafe { libc::geteuid() })
            }
            Err(_) => "not found".to_string(),
        };
        lines.push(format!("  {:<width$}  {}", p.display().to_string(), what));
    }
    // Re-pad the first line now that the column width is known.
    if let Some(first) = lines.first_mut() {
        let (label, state) = first.trim_start().split_once("  ").unwrap_or(("", ""));
        *first = format!("  {:<width$}  {}", label, state.trim_start());
    }
    lines.join("\n")
}

/// Whether the root-only token path is out of this process's reach.
///
/// `/var/lib/ringzero` is root-owned and not world-readable, so as a normal
/// user the stat itself is refused — which is also why this cannot say whether
/// the file is there, only that we cannot look. The message built from this
/// claims no more than that.
fn root_token_out_of_reach() -> bool {
    if effectively_root() {
        return false;
    }
    match std::fs::metadata(ROOT_TOKEN_PATH) {
        Ok(_) => true,
        Err(e) => e.kind() == std::io::ErrorKind::PermissionDenied,
    }
}

/// Generate a fresh 64-hex-char token from the system CSPRNG.
fn generate_token() -> Result<String> {
    use std::io::Read;
    let mut bytes = [0u8; 32];
    std::fs::File::open("/dev/urandom")
        .context("open /dev/urandom")?
        .read_exact(&mut bytes)
        .context("read /dev/urandom")?;
    Ok(bytes.iter().map(|b| format!("{b:02x}")).collect())
}

/// Split a full `http://host:port/path` URL into (host:port, /path).
fn split_url(url: &str) -> (String, String) {
    let rest = url.strip_prefix("http://").unwrap_or(url);
    match rest.split_once('/') {
        Some((h, p)) => (h.to_string(), format!("/{p}")),
        None => (rest.to_string(), "/".to_string()),
    }
}

/// Derive the `http://host:port` base from a full URL.
fn api_base(url: &str) -> String {
    let (host, _) = split_url(url);
    format!("http://{host}")
}

/// Low-level HTTP/1.1 request over a raw TCP socket. Returns (status_code, body).
async fn http_request(
    method: &str,
    url: &str,
    body: Option<&str>,
    token: Option<&str>,
) -> Result<(u16, String)> {
    use tokio::net::TcpStream;
    let (addr, path) = split_url(url);
    let mut stream = TcpStream::connect(&addr)
        .await
        .with_context(|| format!("Cannot connect to daemon HTTP API at {addr}"))?;
    let mut req = format!("{method} {path} HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n");
    if let Some(t) = token {
        req.push_str(&format!("Authorization: Bearer {t}\r\n"));
    }
    if let Some(b) = body {
        req.push_str(&format!(
            "Content-Type: application/json\r\nContent-Length: {}\r\n",
            b.len()
        ));
    }
    req.push_str("\r\n");
    if let Some(b) = body {
        req.push_str(b);
    }
    stream.write_all(req.as_bytes()).await?;
    let mut buf = Vec::new();
    stream.read_to_end(&mut buf).await?;
    let resp = String::from_utf8_lossy(&buf);
    let status = resp
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|c| c.parse::<u16>().ok())
        .unwrap_or(0);
    let body_resp = resp
        .split("\r\n\r\n")
        .nth(1)
        .unwrap_or("")
        .trim()
        .to_string();
    Ok((status, body_resp))
}

/// Obtain the API bearer token, provisioning one on first use.
///
/// The HTTP management API (port 7700) refuses every call until a token has been
/// registered. On a headless Linux box nothing else does this, so the CLI
/// self-registers over the loopback-exempt `/auth/register` path and caches the
/// raw token locally. Subsequent runs reuse the cached token (it still validates
/// against the hash the daemon rehydrates across restarts). $RZ_API_TOKEN
/// overrides everything for the case where the desktop app owns the token.
async fn api_token(api: &str) -> Result<String> {
    if let Some(t) = existing_api_token() {
        return Ok(t);
    }
    let path = token_cache_path();
    // No cached token — generate one and register it with the daemon.
    let token = generate_token()?;
    let body = serde_json::json!({ "token": token }).to_string();
    let (status, resp_body) = http_request(
        "POST",
        &format!("{api}/api/v1/auth/register"),
        Some(&body),
        None,
    )
    .await?;
    match status {
        200..=299 => {
            if let Some(dir) = path.parent() {
                let _ = std::fs::create_dir_all(dir);
            }
            std::fs::write(&path, &token)
                .with_context(|| format!("Failed to cache API token at {}", path.display()))?;
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
            }
            Ok(token)
        }
        409 => {
            // A token is registered and this process does not hold it. Say
            // where we looked rather than guessing who owns it.
            let mut msg = format!(
                "The daemon's HTTP API already has a token registered, and this process does \
                 not have it.\nLooked in:\n{}",
                token_search_report()
            );
            if root_token_out_of_reach() {
                msg.push_str(&format!(
                    "\n\nThe root-only token path {ROOT_TOKEN_PATH} is out of this process's \
                     reach. If that is where the daemon's token is, re-run the same command \
                     with sudo."
                ));
            } else {
                msg.push_str(
                    "\n\nIf the desktop app or another client registered it, pass that token: \
                     RZ_API_TOKEN=<token> rz ...",
                );
            }
            anyhow::bail!(msg)
        }
        _ => anyhow::bail!("API token registration failed (HTTP {status}): {resp_body}"),
    }
}

/// Parse a daemon API response, surfacing the real status + body on error
/// instead of a misleading "Invalid JSON".
fn parse_api_response(url: &str, status: u16, body: String) -> Result<serde_json::Value> {
    // 403 = the token we resolved is the read-only one the installer places in
    // the operator's home. Changing policy or enforcement is an operator action
    // that needs the root-only token, so the agent (running as the operator)
    // cannot do it. Tell a human how to escalate; the agent has no sudo.
    if status == 403 {
        // Two different things return 403 now, and the daemon says which.
        //
        // The old assumption was that a 403 always meant "you are holding the
        // read-only token", so this printed "sudo rz ..." over whatever the
        // daemon said. It now also means "the caller could not be shown to be a
        // human operator", and telling someone to re-run with sudo in that case
        // is advice that cannot work: sudo does not change who your parent
        // process is. Pass the daemon's own words through whenever it sent any.
        let explained = body.trim();
        if !explained.is_empty() && !explained.starts_with('{') {
            // Where the daemon says sudo would help, spell out the command.
            // Where it says the caller itself is the problem, it does not, and
            // we must not invent advice that cannot work.
            let argv: Vec<String> = std::env::args().skip(1).collect();
            if explained.contains("sudo") && !argv.is_empty() {
                anyhow::bail!("{explained}\n  Try:  sudo rz {}", argv.join(" "));
            }
            anyhow::bail!("{explained}");
        }
        let argv: Vec<String> = std::env::args().skip(1).collect();
        anyhow::bail!(
            "this requires root: sudo rz {}",
            if argv.is_empty() {
                "<command>".to_string()
            } else {
                argv.join(" ")
            }
        );
    }
    if !(200..=299).contains(&status) {
        let msg = if body.is_empty() {
            "(empty response)".into()
        } else {
            body
        };
        anyhow::bail!("Daemon API {url} returned HTTP {status}: {msg}");
    }
    if body.is_empty() {
        return Ok(serde_json::Value::Null);
    }
    serde_json::from_str(&body).with_context(|| format!("Invalid JSON from {url}: {body}"))
}

async fn fetch_json(url: &str) -> Result<serde_json::Value> {
    let token = api_token(&api_base(url)).await?;
    let (status, body) = http_request("GET", url, None, Some(&token)).await?;
    parse_api_response(url, status, body)
}

async fn post_json(url: &str, body: serde_json::Value) -> Result<serde_json::Value> {
    let token = api_token(&api_base(url)).await?;
    let body_str = body.to_string();
    let (status, resp) = http_request("POST", url, Some(&body_str), Some(&token)).await?;
    parse_api_response(url, status, resp)
}

async fn delete_json(url: &str) -> Result<serde_json::Value> {
    let token = api_token(&api_base(url)).await?;
    let (status, resp) = http_request("DELETE", url, None, Some(&token)).await?;
    parse_api_response(url, status, resp)
}

// ── CLI definition ────────────────────────────────────────────────────────────

#[derive(Parser)]
#[command(
    name = "rz",
    about = "Ring Zero Security — Agentic Access Management",
    // The packaged build, not just the crate version: a tester needs to be
    // able to confirm which build they are running.
    // The packaged build, not just the crate version: a tester needs to be
    // able to confirm which build they are running. Leaked deliberately —
    // clap wants a 'static str and this is read once at startup.
    version = Box::leak(build_info::version_string(env!("CARGO_PKG_VERSION")).into_boxed_str()) as &'static str,
)]
struct Cli {
    /// Daemon socket path (default: /var/run/ringzero/daemon.sock)
    #[arg(long, global = true)]
    socket: Option<PathBuf>,

    /// Daemon HTTP API base URL (default: http://127.0.0.1:7700 or $RZ_API)
    #[arg(long, global = true)]
    api: Option<String>,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Show daemon status
    Status,

    /// List and stream security events
    Events {
        #[arg(short, long, default_value = "50")]
        limit: usize,
        /// Stream live events (Ctrl+C to stop)
        #[arg(short, long)]
        follow: bool,
    },

    /// Policy management
    Policy {
        #[command(subcommand)]
        action: PolicyCommands,
    },

    /// Show recent threats
    Threats,

    /// Intent vs. behavior diff audit
    Diffs,

    /// Session management (AAM)
    Sessions {
        #[command(subcommand)]
        action: SessionCommands,
    },

    /// Escalation queue management
    Escalations {
        #[command(subcommand)]
        action: EscalationCommands,
    },

    /// Immutable audit log
    Audit {
        #[command(subcommand)]
        action: AuditCommands,
    },

    /// Network policy management
    Network {
        #[command(subcommand)]
        action: NetworkCommands,
    },

    /// Checks layer — provider key, status and a live connectivity test
    Checks {
        #[command(subcommand)]
        action: ChecksCommands,
    },

    /// Review queue — kernel denials and check flags waiting for a human label
    Review {
        #[command(subcommand)]
        action: ReviewCommands,
    },

    /// Enforcement posture — per-category threat response (observe/alert/block)
    Enforcement {
        #[command(subcommand)]
        action: EnforcementCommands,
    },

    /// File access control — block/allow files at the kernel (eBPF)
    FileAccess {
        #[command(subcommand)]
        action: FileAccessCommands,
    },

    /// Non-Human Identity inventory
    Nhi,

    /// Shadow AI discovery — detect unauthorized AI API usage
    ShadowAi,

    /// On-demand security scans
    Scan {
        #[command(subcommand)]
        action: ScanCommands,
    },

    /// Session kernel event timeline
    SessionEvents {
        /// Session ID
        id: String,
    },

    /// Install the capture+sandbox shim for AI agent binaries (Linux)
    Setup {
        /// Path to the real agent binary (e.g. ~/.local/bin/claude)
        #[arg(long)]
        binary: Option<String>,
        /// Name for the shim (default: basename of --binary, or "claude")
        #[arg(long)]
        name: Option<String>,
        /// Discover and shim every installed AI agent (claude, gemini, cursor,
        /// codex, aider, …) in one step.
        #[arg(long)]
        all: bool,
    },

    /// Run a command inside a Ring Zero mount+pid namespace sandbox (Linux)
    ///
    /// Typically called by the installed shim, not directly by users.
    /// Example: rz sandbox -- /path/to/claude --arg1 --arg2
    #[command(hide = true)]
    Sandbox {
        /// Command and arguments to run
        #[arg(last = true, required = true)]
        cmd: Vec<String>,
    },

    /// Run an AI agent with Ring Zero prompt capture enabled.
    ///
    /// Points the agent's HTTPS traffic at the local inspection proxy and trusts
    /// Ring Zero's CA, so the daemon can see prompts even from agents (Claude
    /// Code, Gemini CLI) that statically link their own TLS and are invisible to
    /// the kernel SSL uprobe. Example: `rz run claude` or `rz run gemini`.
    Run {
        /// The agent command and its arguments.
        #[arg(trailing_var_arg = true, required = true)]
        command: Vec<String>,
    },
}

#[derive(Subcommand)]
enum ScanCommands {
    /// Discover and scan every installed AI agent's skill surface
    /// (Claude/Cursor/Windsurf/… skills, plugins, rules, MCP configs) for
    /// prompt injection + supply-chain risk (entropy/secrets).
    ///
    /// Reports only findings that are NEW since the accepted baseline, if one
    /// has been accepted. Use --all to see everything.
    Skills {
        /// Show every finding, including ones already accepted.
        #[arg(long)]
        all: bool,
    },
    /// Accepted-findings baseline, so scans report only what changed
    Baseline {
        #[command(subcommand)]
        action: BaselineCommands,
    },
}

#[derive(Subcommand)]
enum BaselineCommands {
    /// Show what has been accepted, and by whom
    Show,
    /// Snapshot the current findings as expected (needs root)
    Accept,
    /// Forget the snapshot — every finding becomes new again (needs root)
    Clear,
}

#[derive(Subcommand)]
enum PolicyCommands {
    /// Show current policy
    Show,
    /// Block a domain
    BlockDomain { domain: String },
    /// Set enforcement mode (observe|enforce)
    SetMode { mode: String },
}

#[derive(Subcommand)]
enum SessionCommands {
    /// List all sessions
    List {
        /// Filter: all | live | ended
        #[arg(short, long, default_value = "live")]
        filter: String,
    },
    /// Create a new session
    Create {
        /// Actor/process name
        #[arg(short, long)]
        actor: String,
        /// Agent type (claude|chatgpt|gemini|custom|…)
        #[arg(short = 't', long, default_value = "custom")]
        agent_type: String,
    },
    /// Show session detail
    Get { id: String },
    /// Terminate a session
    Terminate { id: String },
    /// Approve a waiting session
    Approve { id: String },
}

#[derive(Subcommand)]
enum EscalationCommands {
    /// List pending escalations
    List,
    /// Approve an escalation
    Approve {
        id: String,
        #[arg(short, long, default_value = "admin")]
        reviewer: String,
    },
    /// Deny an escalation
    Deny {
        id: String,
        #[arg(short, long, default_value = "admin")]
        reviewer: String,
    },
}

#[derive(Subcommand)]
enum NetworkCommands {
    /// Show current network policy
    Show,
    /// Set network mode: low | medium | high
    SetMode { mode: String },
    /// Set enforce mode: enforce | observe
    SetEnforce { mode: String },
}

#[derive(Subcommand)]
enum ChecksCommands {
    /// Show whether checks are on, which provider, and the key's state
    Status,
    /// Install the provider API key, read from STDIN only (needs root)
    ///
    /// With a terminal it prompts without echoing. It also accepts a pipe:
    ///   cat key.txt | sudo rz checks set-key
    /// The key is never taken as an argument, so it cannot reach your shell
    /// history or another user's `ps` output.
    SetKey {
        /// Also set [checks] enabled = true in the config after the key verifies
        #[arg(long)]
        enable: bool,
    },
    /// Make one live request against the provider and report the round trip
    Test,
}

#[derive(Subcommand)]
enum ReviewCommands {
    /// List items waiting for a label (newest first)
    List {
        #[arg(short, long, default_value = "20")]
        limit: usize,
        /// Include items that already have a label
        #[arg(long)]
        all: bool,
    },
    /// Show one item in full, including its trace
    Show { id: String },
    /// Label an item: benign | real-threat | false-positive  (needs root)
    Label { id: String, label: String },
    /// Counts: how much is waiting, and how labelled items came out
    Stats,
}

#[derive(Subcommand)]
enum EnforcementCommands {
    /// Show enforcement posture (default + per-category)
    Show,
    /// Set the default action for all categories: observe | alert | block
    SetDefault { action: String },
    /// Set one category's action, e.g. `rz enforcement set-category credential_access block`
    SetCategory { category: String, action: String },
}

#[derive(Subcommand)]
enum FileAccessCommands {
    /// List file access rules
    Show,
    /// Add a rule, e.g. `rz file-access add '*id_rsa' block`
    Add {
        /// File pattern (glob or basename), e.g. '*id_rsa' or '/home/u/.env'
        pattern: String,
        /// block | allow
        #[arg(default_value = "block")]
        action: String,
        #[arg(short, long)]
        description: Option<String>,
        /// Block the whole directory and everything under it. Implied by a
        /// trailing /* , so `add '~/projects/*' block` already does this.
        #[arg(long, conflicts_with = "file")]
        dir: bool,
        /// Treat the pattern as a file or a basename, even with a trailing /*.
        #[arg(long, conflicts_with = "dir")]
        file: bool,
    },
    /// Remove a rule by id, or every rule covering a pattern with --all
    Remove {
        /// A rule id, or a pattern such as '~/projects/*'
        id: String,
        /// Remove every rule that covers this pattern, not just one
        #[arg(long)]
        all: bool,
    },
}

#[derive(Subcommand)]
enum AuditCommands {
    /// Show recent audit entries
    Recent {
        #[arg(short, long, default_value = "50")]
        limit: usize,
    },
    /// Verify chain integrity
    Verify,
    /// Export full audit log to JSON file
    Export {
        #[arg(short, long, default_value = "ringzero-audit.json")]
        output: String,
    },
}

// ── Command handlers ──────────────────────────────────────────────────────────

async fn cmd_status(sock: &PathBuf, api: &str) -> Result<()> {
    // Try HTTP API first, fall back to IPC
    match fetch_json(&format!("{api}/api/v1/status")).await {
        Ok(v) => {
            // The kernel driver's state is `ebpf_active`, not `connected`
            // (which only reports whether anything is subscribed to the IPC
            // event stream). Use ebpf_active so the line reflects reality.
            let ebpf_active = v["ebpf_active"].as_bool().unwrap_or(false);
            let version = v["version"].as_str().unwrap_or("?");
            let threats = v["threats_blocked"].as_u64().unwrap_or(0);
            let sessions = v["active_sessions"].as_u64().unwrap_or(0);
            let waiting = v["waiting_approval"].as_u64().unwrap_or(0);
            println!("Ring Zero Security daemon  v{version}");
            println!(
                "  rz build:          {}",
                build_info::version_string(env!("CARGO_PKG_VERSION"))
            );
            println!(
                "  Kernel driver:     {}",
                if ebpf_active {
                    "\x1b[32mactive (eBPF)\x1b[0m"
                } else {
                    "\x1b[33mnot active — reboot may be required\x1b[0m"
                }
            );
            println!("  Active sessions:   {sessions}");
            if waiting > 0 {
                println!("  Awaiting approval: \x1b[33m{waiting}\x1b[0m");
            }
            println!("  Threats blocked:   {threats}  (last 1h)");
        }
        Err(_) => {
            let resp = send_request(sock, &ClientRequest::GetStatus).await?;
            if let Some(p) = resp.get("payload") {
                println!("{}", serde_json::to_string_pretty(p)?);
            }
        }
    }
    Ok(())
}

async fn cmd_events(sock: &PathBuf, limit: usize, follow: bool) -> Result<()> {
    if follow {
        subscribe_stream(sock, None).await
    } else {
        let resp = send_request(sock, &ClientRequest::GetEvents { limit: Some(limit) }).await?;
        if let Some(events) = resp.get("payload").and_then(|p| p.as_array()) {
            if events.is_empty() {
                println!("No events in last hour.");
                return Ok(());
            }
            println!(
                "{:<26} {:<7} {:<22} {:<24} {}",
                "TIME", "VERDICT", "KIND", "PROCESS[PID]", "TARGET"
            );
            println!("{}", "─".repeat(100));
            for ev in events {
                print_event(ev);
            }
            println!("\n{} events shown.", events.len());
        } else {
            println!("{}", serde_json::to_string_pretty(&resp)?);
        }
        Ok(())
    }
}

async fn cmd_policy_show(api: &str) -> Result<()> {
    let v = fetch_json(&format!("{api}/api/v1/policy")).await?;
    println!("{}", serde_json::to_string_pretty(&v)?);
    Ok(())
}

async fn cmd_policy_block_domain(sock: &PathBuf, api: &str, domain: &str) -> Result<()> {
    match post_json(
        &format!("{api}/api/v1/policy"),
        serde_json::json!({"action":"block_domain","value":domain}),
    )
    .await
    {
        Ok(v) => println!("{}", serde_json::to_string_pretty(&v)?),
        Err(_) => {
            let req = ClientRequest::UpdatePolicy {
                action: "block_domain".into(),
                value: Some(serde_json::Value::String(domain.to_string())),
            };
            let resp = send_request(sock, &req).await?;
            println!("{}", serde_json::to_string_pretty(&resp)?);
        }
    }
    Ok(())
}

async fn cmd_threats(api: &str) -> Result<()> {
    let v = fetch_json(&format!("{api}/api/v1/threats")).await?;
    let arr = v.as_array().cloned().unwrap_or_default();
    if arr.is_empty() {
        println!("No threats in last hour.");
        return Ok(());
    }
    println!("{} threats in last hour:\n", arr.len());
    for t in &arr {
        let ts = t["timestamp"].as_str().unwrap_or("?");
        let proc = t["process"].as_str().unwrap_or("?");
        let target = t["target"].as_str().unwrap_or("?");
        let kind = t["kind"].as_str().unwrap_or("threat");
        println!("  [{ts}] \x1b[31m{kind}\x1b[0m  {proc}  →  {target}");
    }
    Ok(())
}

async fn cmd_diffs(api: &str) -> Result<()> {
    let v = fetch_json(&format!("{api}/api/v1/intent-diffs")).await?;
    let arr = v.as_array().cloned().unwrap_or_default();
    if arr.is_empty() {
        println!("No intent vs. behavior mismatches detected.");
        return Ok(());
    }
    println!("{} mismatch(es):\n", arr.len());
    for d in &arr {
        println!("{}\n---", serde_json::to_string_pretty(d)?);
    }
    Ok(())
}

// ── Session handlers ──────────────────────────────────────────────────────────

fn state_color(state: &str) -> &'static str {
    match state {
        "ACTIVE" => "\x1b[32m",
        "WAITING_APPROVAL" => "\x1b[33m",
        "PENDING" => "\x1b[34m",
        "TERMINATED" => "\x1b[31m",
        _ => "\x1b[90m",
    }
}

async fn cmd_sessions_list(api: &str, filter: &str) -> Result<()> {
    let sessions: Vec<serde_json::Value> = fetch_json(&format!("{api}/api/v1/sessions"))
        .await?
        .as_array()
        .cloned()
        .unwrap_or_default();

    let filtered: Vec<_> = sessions
        .iter()
        .filter(|s| {
            let state = s["state"].as_str().unwrap_or("");
            match filter {
                "live" => matches!(state, "PENDING" | "ACTIVE" | "WAITING_APPROVAL"),
                "ended" => matches!(state, "EXPIRED" | "TERMINATED"),
                _ => true,
            }
        })
        .collect();

    if filtered.is_empty() {
        println!("No sessions.");
        return Ok(());
    }

    println!(
        "{:<38} {:<12} {:<20} {:<18} {:<6} {:<6}",
        "ID", "STATE", "ACTOR", "AGENT", "JIT", "EVENTS"
    );
    println!("{}", "─".repeat(105));
    for s in &filtered {
        let id = s["id"].as_str().unwrap_or("?");
        let state = s["state"].as_str().unwrap_or("?");
        let actor = s["actor"].as_str().unwrap_or("?");
        let agent = s["agent_type"].as_str().unwrap_or("?");
        let events = s["event_count"].as_u64().unwrap_or(0);
        let priv_flag = if s["privileged"].as_bool().unwrap_or(false) {
            "\x1b[33m⚑\x1b[0m"
        } else {
            " "
        };
        let jit = s["jit_identities"]
            .as_array()
            .map(|a| {
                a.iter()
                    .filter(|j| !j["revoked"].as_bool().unwrap_or(false))
                    .count()
            })
            .unwrap_or(0);
        let col = state_color(state);
        println!(
            "{id:<38} {col}{state:<12}\x1b[0m {priv_flag}{actor:<19} {agent:<18} {jit:<6} {events}"
        );
    }
    println!("\n{} session(s) shown.", filtered.len());
    Ok(())
}

async fn cmd_sessions_create(api: &str, actor: &str, agent_type: &str) -> Result<()> {
    let v = post_json(
        &format!("{api}/api/v1/sessions"),
        serde_json::json!({"actor": actor, "agent_type": agent_type}),
    )
    .await?;
    println!("Created: {}", serde_json::to_string_pretty(&v)?);
    Ok(())
}

async fn cmd_sessions_get(api: &str, id: &str) -> Result<()> {
    let v = fetch_json(&format!("{api}/api/v1/sessions/{id}")).await?;
    println!("{}", serde_json::to_string_pretty(&v)?);
    Ok(())
}

async fn cmd_sessions_terminate(api: &str, id: &str) -> Result<()> {
    let v = delete_json(&format!("{api}/api/v1/sessions/{id}")).await?;
    println!("{}", serde_json::to_string_pretty(&v)?);
    Ok(())
}

async fn cmd_sessions_approve(api: &str, id: &str) -> Result<()> {
    let v = post_json(
        &format!("{api}/api/v1/sessions/{id}/approve"),
        serde_json::json!({}),
    )
    .await?;
    println!("{}", serde_json::to_string_pretty(&v)?);
    Ok(())
}

// ── Escalation handlers ───────────────────────────────────────────────────────

async fn cmd_escalations_list(api: &str) -> Result<()> {
    let arr: Vec<serde_json::Value> = fetch_json(&format!("{api}/api/v1/escalations"))
        .await?
        .as_array()
        .cloned()
        .unwrap_or_default();
    if arr.is_empty() {
        println!("\x1b[32m✓\x1b[0m No pending escalations.");
        return Ok(());
    }
    println!("{} pending escalation(s):\n", arr.len());
    for e in &arr {
        let esc_id = e["escalation_id"].as_str().unwrap_or("?");
        let sess_id = e["session_id"].as_str().unwrap_or("?");
        let actor = e["actor"].as_str().unwrap_or("?");
        let tool = e["tool_name"].as_str().unwrap_or("?");
        let reason = e["reason"].as_str().unwrap_or("?");
        let ts = e["requested_at"].as_str().unwrap_or("?");
        let priv_flag = if e["privileged"].as_bool().unwrap_or(false) {
            " \x1b[33m[PRIVILEGED]\x1b[0m"
        } else {
            ""
        };
        println!("  \x1b[33m{esc_id}\x1b[0m{priv_flag}");
        println!("    Session: {sess_id}  Actor: {actor}");
        println!("    Tool:    \x1b[36m{tool}\x1b[0m");
        println!("    Reason:  {reason}");
        println!("    At:      {ts}");
        println!("    → rz escalations approve {esc_id}");
        println!("    → rz escalations deny    {esc_id}");
        println!();
    }
    Ok(())
}

async fn cmd_escalations_resolve(
    api: &str,
    esc_id: &str,
    approved: bool,
    reviewer: &str,
) -> Result<()> {
    let v = post_json(
        &format!("{api}/api/v1/escalations/{esc_id}/resolve"),
        serde_json::json!({"approved": approved, "reviewer": reviewer}),
    )
    .await?;
    let msg = v["message"]
        .as_str()
        .unwrap_or(if approved { "Approved" } else { "Denied" });
    let col = if approved { "\x1b[32m" } else { "\x1b[31m" };
    println!("{col}{msg}\x1b[0m");
    Ok(())
}

// ── Audit handlers ────────────────────────────────────────────────────────────

async fn cmd_audit_recent(api: &str, limit: usize) -> Result<()> {
    let entries: Vec<serde_json::Value> = fetch_json(&format!("{api}/api/v1/audit?limit={limit}"))
        .await?
        .as_array()
        .cloned()
        .unwrap_or_default();
    if entries.is_empty() {
        println!("No audit entries.");
        return Ok(());
    }
    println!("{:<6} {:<26} {:<26} SUMMARY", "SEQ", "TIME", "TYPE");
    println!("{}", "─".repeat(100));
    for e in &entries {
        let seq = e["seq"].as_u64().unwrap_or(0);
        let ts = e["timestamp"].as_str().unwrap_or("?");
        let etype = e["entry_type"].as_str().unwrap_or("?");
        let summary = serde_json::to_string(&e["payload"]).unwrap_or_default();
        let summary = if summary.len() > 60 {
            format!("{}…", &summary[..60])
        } else {
            summary
        };
        println!("{seq:<6} {ts:<26} {etype:<26} {summary}");
    }
    println!("\n{} entries shown.", entries.len());
    Ok(())
}

async fn cmd_audit_verify(api: &str) -> Result<()> {
    let v = fetch_json(&format!("{api}/api/v1/audit/verify")).await?;
    let valid = v["valid"].as_bool().unwrap_or(false);
    let msg = v["message"].as_str().unwrap_or("");
    if valid {
        println!("\x1b[32m✓ {msg}\x1b[0m");
    } else {
        let seq = v["first_invalid"].as_u64();
        println!("\x1b[31m✗ {msg}\x1b[0m");
        if let Some(s) = seq {
            println!("  First invalid sequence: {s}");
        }
    }
    Ok(())
}

async fn cmd_audit_export(api: &str, output: &str) -> Result<()> {
    use tokio::net::TcpStream;
    let addr = "127.0.0.1:7700";
    let path = "/api/v1/audit/export";
    let mut stream = TcpStream::connect(addr)
        .await
        .with_context(|| format!("Cannot connect to {addr}"))?;
    let request = format!("GET {path} HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n\r\n");
    stream.write_all(request.as_bytes()).await?;
    let mut buf = Vec::new();
    stream.read_to_end(&mut buf).await?;
    let resp = String::from_utf8_lossy(&buf);
    let body = resp.split("\r\n\r\n").nth(1).unwrap_or(&resp);
    tokio::fs::write(output, body.as_bytes())
        .await
        .with_context(|| format!("Failed to write {output}"))?;
    println!("Audit log exported to: {output}");
    let _ = api; // suppress unused warning
    Ok(())
}

// ── Network handlers ─────────────────────────────────────────────────────

async fn cmd_network_show(api: &str) -> Result<()> {
    let v = fetch_json(&format!("{api}/api/v1/network")).await?;
    let mode = v["mode"].as_str().unwrap_or("?");
    let enforce = v["enforce"].as_str().unwrap_or("?");
    let mode_desc = match mode {
        "low" => "Only agent PID allowed",
        "medium" => "Agent PID + child tree allowed",
        "high" => "All outbound + consent for new destinations",
        _ => "",
    };
    println!("Network Policy:");
    println!("  Mode:    \x1b[36m{mode}\x1b[0m  — {mode_desc}");
    println!(
        "  Enforce: {}",
        if enforce == "enforce" {
            "\x1b[31menforce\x1b[0m (violations blocked)"
        } else {
            "\x1b[33mobserve\x1b[0m (violations logged)"
        }
    );
    Ok(())
}

async fn cmd_network_set(api: &str, mode: Option<&str>, enforce: Option<&str>) -> Result<()> {
    let body = match (mode, enforce) {
        (Some(m), Some(e)) => serde_json::json!({"mode": m, "enforce": e}),
        (Some(m), None) => serde_json::json!({"mode": m}),
        (None, Some(e)) => serde_json::json!({"enforce": e}),
        (None, None) => serde_json::json!({}),
    };
    let v = post_json(&format!("{api}/api/v1/network"), body).await?;
    println!("Network policy updated:");
    println!(
        "  mode: {}  enforce: {}",
        v["mode"].as_str().unwrap_or("?"),
        v["enforce"].as_str().unwrap_or("?")
    );
    Ok(())
}

// ── Enforcement posture handlers ──────────────────────────────────────────────

const ENF_CATEGORIES: &[&str] = &[
    "credential_access",
    "data_exfiltration",
    "privilege_escalation",
    "prompt_injection",
    "supply_chain",
    "excessive_agency",
    "output_handling",
    "memory_poisoning",
    "tool_misuse",
    "rogue_agent",
    "system_prompt_leakage",
    "mcp_tool_poisoning",
    "harmful_content",
];

fn color_action(a: &str) -> String {
    match a {
        "block" => format!("\x1b[31m{a}\x1b[0m"),
        "alert" => format!("\x1b[33m{a}\x1b[0m"),
        "observe" => format!("\x1b[36m{a}\x1b[0m"),
        _ => a.to_string(),
    }
}

// ── Checks layer administration ─────────────────────────────────────────────

fn require_root(what: &str) -> Result<()> {
    if unsafe { libc::geteuid() } != 0 {
        anyhow::bail!("this requires root: sudo rz {what}");
    }
    Ok(())
}

/// Read a secret from stdin without echoing it.
///
/// With a terminal, echo is turned off for the read and restored afterwards, so
/// the key never appears on screen. With a pipe, the bytes are simply read.
/// Either way the key is never an argument, so it cannot land in shell history
/// or in another user's view of the process table.
fn read_secret_from_stdin() -> Result<String> {
    use std::io::{BufRead, IsTerminal, Write};

    let stdin = std::io::stdin();
    let interactive = stdin.is_terminal();

    if interactive {
        print!("Provider API key (not echoed): ");
        std::io::stdout().flush().ok();
        // `stty` is in coreutils on every target we support, and shelling out
        // avoids a terminal crate for one prompt.
        let _ = std::process::Command::new("stty").arg("-echo").status();
    }

    let mut key = String::new();
    let read = stdin.lock().read_line(&mut key);

    if interactive {
        let _ = std::process::Command::new("stty").arg("echo").status();
        println!();
    }
    read.context("reading the key from stdin")?;

    // Trim trailing newlines and surrounding whitespace only.
    let key = key.trim().to_string();
    if key.is_empty() {
        anyhow::bail!("no key on stdin — nothing was written");
    }
    Ok(key)
}

/// Write the key 0600 root-owned, refusing to follow a symlink.
fn write_key_file(path: &std::path::Path, key: &str) -> Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;

    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating {}", parent.display()))?;
        let _ =
            std::fs::set_permissions(parent, std::os::unix::fs::PermissionsExt::from_mode(0o750));
    }
    // A pre-placed symlink must not redirect a root-owned write.
    if let Ok(meta) = std::fs::symlink_metadata(path) {
        if meta.file_type().is_symlink() {
            anyhow::bail!(
                "{} is a symlink — refusing to write a credential through it",
                path.display()
            );
        }
    }
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .custom_flags(libc::O_NOFOLLOW)
        .mode(0o600)
        .open(path)
        .with_context(|| format!("writing {}", path.display()))?;
    f.write_all(key.as_bytes())?;
    f.write_all(b"\n")?;
    Ok(())
}

// ── Local view of the daemon config ─────────────────────────────────────────
//
// `rz checks set-key` and `rz checks status` are local operations: one writes a
// file and asks the provider whether the key works, the other reports what the
// config says. Neither needs the daemon's HTTP API, so neither may fail on
// resolving a token for it. Anything the daemon alone knows — whether a
// provider is actually running right now — is reported as unknown when we
// cannot ask it.

/// The slice of the daemon config these commands need.
///
/// Field names and defaults mirror `ChecksSection` and `JevSection` in
/// `agent/src/config.rs`. The test at the bottom of this file parses the
/// shipped `packaging/daemon.toml` and fails if the two drift apart. Unknown
/// keys are ignored: the rest of the daemon's config is not the CLI's business.
#[derive(serde::Deserialize, Default)]
struct LocalConfigFile {
    #[serde(default)]
    checks: LocalChecks,
}

#[derive(serde::Deserialize)]
#[serde(default)]
struct LocalChecks {
    enabled: bool,
    provider: String,
    blocking: bool,
    fail_mode: Option<String>,
    jev: LocalJev,
}

impl Default for LocalChecks {
    fn default() -> Self {
        LocalChecks {
            enabled: false,
            provider: "jev".to_string(),
            blocking: false,
            fail_mode: None,
            jev: LocalJev::default(),
        }
    }
}

#[derive(serde::Deserialize)]
#[serde(default)]
struct LocalJev {
    api_key_file: String,
    model: String,
    base_url: String,
    timeout_ms: u64,
}

impl Default for LocalJev {
    fn default() -> Self {
        LocalJev {
            api_key_file: "/etc/ringzero/typesafe.key".to_string(),
            model: "jev-latest".to_string(),
            base_url: "https://api.typesafe.ai".to_string(),
            timeout_ms: 1500,
        }
    }
}

impl LocalJev {
    fn endpoint(&self) -> String {
        format!("{}/v1/systemone", self.base_url.trim_end_matches('/'))
    }

    /// Read the key from its file, refusing one any other account can read.
    /// Same rules as the daemon applies in `JevSection::load_key`.
    fn load_key(&self) -> Result<String, String> {
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

fn config_path() -> String {
    std::env::var("RINGZERO_CONFIG").unwrap_or_else(|_| "/etc/ringzero/daemon.toml".to_string())
}

/// Read `[checks]` out of the config file.
///
/// A file that is there but malformed is an error: guessing would report
/// settings the daemon is not using. A file that is absent or unreadable falls
/// back to the built-in defaults and says so, because those are the same
/// defaults the daemon would use.
fn load_local_checks() -> Result<(LocalChecks, String, Option<String>)> {
    let path = config_path();
    match std::fs::read_to_string(&path) {
        Ok(text) => {
            let parsed: LocalConfigFile =
                toml::from_str(&text).with_context(|| format!("parsing [checks] out of {path}"))?;
            Ok((parsed.checks, path, None))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            let note = format!("{path} does not exist — showing built-in defaults");
            Ok((LocalChecks::default(), path, Some(note)))
        }
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
            let note = format!(
                "{path} is not readable by this user — showing built-in defaults. \
                 Re-run with sudo to read the real config."
            );
            Ok((LocalChecks::default(), path, Some(note)))
        }
        Err(e) => Err(anyhow::anyhow!("reading {path}: {e}")),
    }
}

// ── Talking to the provider without the daemon ──────────────────────────────

/// What one probe request found. Mirrors the stages the daemon's
/// `/api/v1/checks/verify-key` reports, so the two read the same way.
enum Probe {
    Ok {
        elapsed_ms: u64,
        model: Option<String>,
    },
    Rejected {
        elapsed_ms: u64,
    },
    Failed {
        stage: &'static str,
        error: String,
        elapsed_ms: u64,
    },
}

/// One live request to the configured endpoint, using the transport the daemon
/// uses. Cheap enough to run whenever someone asks, and enough to prove that
/// the key and the contract both work.
async fn probe_provider(jev: &LocalJev, key: String) -> Probe {
    use ringzero_checks::jev::{HttpTransport, JevError, Transport};

    let endpoint = jev.endpoint();
    let model = jev.model.clone();
    let timeout = std::time::Duration::from_millis(jev.timeout_ms.max(1000));
    let body = serde_json::json!({
        "state": {"probe": "ringzero key verification"},
        "model": model,
        "questions": {
            "probe": {
                "type": "noul",
                "instructions": "Answer 0.5. This is a connectivity probe.",
                "criteria": {}
            }
        }
    })
    .to_string();

    let started = std::time::Instant::now();
    let joined =
        tokio::task::spawn_blocking(move || HttpTransport.post(&endpoint, &key, body, timeout))
            .await;
    let elapsed_ms = started.elapsed().as_millis() as u64;

    match joined {
        Ok(Ok((200, text))) => {
            let model = serde_json::from_str::<serde_json::Value>(&text)
                .ok()
                .and_then(|v| v["model"].as_str().map(|m| m.to_string()));
            Probe::Ok { elapsed_ms, model }
        }
        Ok(Ok((401, _))) => Probe::Rejected { elapsed_ms },
        Ok(Ok((code, _))) => Probe::Failed {
            stage: "http",
            error: format!("provider returned HTTP {code}"),
            elapsed_ms,
        },
        Ok(Err(JevError::Timeout)) => Probe::Failed {
            stage: "transport",
            error: format!("timed out after {} ms", timeout.as_millis()),
            elapsed_ms,
        },
        Ok(Err(e)) => Probe::Failed {
            stage: "transport",
            error: e.to_string(),
            elapsed_ms,
        },
        Err(e) => Probe::Failed {
            stage: "task",
            error: e.to_string(),
            elapsed_ms,
        },
    }
}

/// Whether a scoring provider is live right now. Only the daemon knows, so
/// "unknown" is a real answer and is reported as one rather than guessed at.
enum Running {
    Named(String),
    NotRunning,
    /// No daemon token here, so the daemon was never asked.
    NotAsked,
    Unreachable(String),
}

/// `rz checks status` — what the checks layer is configured to do.
///
/// Reads the config file directly. The daemon is asked one extra question, and
/// only when a token for it is already at hand: whether a provider is running
/// right now. Without a token that one line reads `unknown`; nothing fails.
async fn cmd_checks_status(api: &str) -> Result<()> {
    let (cfg, cfg_path, note) = load_local_checks()?;

    // Ask the daemon only for what only it knows, and only when a token for it
    // is already at hand. Every other line comes from the config file.
    let running = match existing_api_token() {
        None => Running::NotAsked,
        Some(_) => match fetch_json(&format!("{api}/api/v1/checks/status")).await {
            Ok(v) => match v["running_provider"].as_str() {
                Some(p) => Running::Named(p.to_string()),
                None => Running::NotRunning,
            },
            Err(e) => Running::Unreachable(e.to_string()),
        },
    };

    let key_path = std::path::Path::new(&cfg.jev.api_key_file);
    let (key_present, key_mode, key_mode_ok) = match std::fs::metadata(key_path) {
        Ok(m) => {
            use std::os::unix::fs::PermissionsExt;
            let bits = m.permissions().mode() & 0o777;
            (true, format!("{bits:o}"), bits & 0o077 == 0)
        }
        Err(_) => (false, String::new(), false),
    };

    match &note {
        None => println!("Checks layer:  (from {cfg_path})"),
        // Saying "from <path>" would be a lie when we could not read it.
        Some(_) => println!("Checks layer:  (built-in defaults — see the note below)"),
    }
    println!(
        "  enabled           {}",
        if cfg.enabled {
            "\x1b[32myes\x1b[0m"
        } else {
            "\x1b[33mno\x1b[0m"
        }
    );
    println!("  provider          {}", cfg.provider);
    match &running {
        Running::Named(p) => println!("  running           {p}"),
        Running::NotRunning => println!("  running           \x1b[33mnot running\x1b[0m"),
        Running::NotAsked => println!(
            "  running           \x1b[33munknown\x1b[0m — no daemon token here, so the \
             daemon was not asked"
        ),
        Running::Unreachable(_) => {
            println!("  running           \x1b[33munknown\x1b[0m — the daemon did not answer")
        }
    }
    println!("  endpoint          {}", cfg.jev.endpoint());
    println!("  model             {}", cfg.jev.model);
    println!("  timeout           {} ms", cfg.jev.timeout_ms);
    println!("  blocking          {}", cfg.blocking);
    if cfg.blocking {
        println!(
            "  fail_mode         {}",
            cfg.fail_mode
                .as_deref()
                .unwrap_or("(unset — daemon refuses to start)")
        );
    }
    println!("  key file          {}", cfg.jev.api_key_file);
    if key_present {
        if key_mode_ok {
            println!("  key               present, mode {key_mode}");
        } else {
            println!(
                "  key               \x1b[31mpresent but mode {key_mode}\x1b[0m — must not be \
                 group- or world-readable (chmod 600)"
            );
        }
    } else {
        // As a normal user the key file is deliberately out of reach, so
        // "not installed" would be a claim we cannot make.
        if effectively_root() {
            println!("  key               \x1b[33mnot installed\x1b[0m");
        } else {
            println!(
                "  key               \x1b[33munknown\x1b[0m — not readable by this user, \
                 which is how it should be"
            );
        }
        println!("\n  Install one with:  sudo rz checks set-key");
    }
    if let Some(n) = note {
        println!("\n\x1b[33mNote:\x1b[0m {n}");
    }
    if let Running::Unreachable(e) = &running {
        println!("\n\x1b[33mNote:\x1b[0m could not ask the daemon what is running: {e}");
    }
    if cfg.enabled && matches!(running, Running::NotRunning) {
        println!(
            "\n\x1b[33mChecks are enabled but no provider is running.\x1b[0m \
             See: journalctl -u ringzero-daemon | grep 'Checks layer'"
        );
    }
    Ok(())
}

/// `rz checks test` — one live request to the configured provider.
///
/// Prefers the daemon, because the daemon uses the key and endpoint it is
/// actually running with. With no token for it, the same request goes out from
/// here against the config on disk, and the output says which path was taken.
async fn cmd_checks_test(api: &str) -> Result<()> {
    if existing_api_token().is_some() {
        println!("Asking the daemon to make one live request to its configured provider…");
        match post_json(
            &format!("{api}/api/v1/checks/verify-key"),
            serde_json::json!({}),
        )
        .await
        {
            Ok(v) => {
                let ms = v["elapsed_ms"].as_u64().unwrap_or(0);
                if v["ok"].as_bool().unwrap_or(false) {
                    let model = v["model"]
                        .as_str()
                        .unwrap_or("(model not named in the response)");
                    println!("\x1b[32m✓\x1b[0m The provider answered in {ms} ms. Model: {model}");
                    return Ok(());
                }
                let stage = v["stage"].as_str().unwrap_or("?");
                let err = v["error"].as_str().unwrap_or("unknown error");
                anyhow::bail!("provider check failed at the {stage} stage after {ms} ms: {err}")
            }
            Err(e) => {
                println!("\x1b[33m!\x1b[0m Could not use the daemon ({e}).");
                println!("   Making the request from here instead, against the config on disk.");
            }
        }
    } else {
        println!(
            "Making one live request to the configured provider from here \
             (no daemon token, so the daemon was not used)…"
        );
    }

    let (cfg, cfg_path, note) = load_local_checks()?;
    if let Some(n) = note {
        println!("\x1b[33mNote:\x1b[0m {n}");
    }
    let key = cfg
        .jev
        .load_key()
        .map_err(|e| anyhow::anyhow!("{e}\nConfig read from {cfg_path}."))?;
    match probe_provider(&cfg.jev, key).await {
        Probe::Ok { elapsed_ms, model } => {
            let model = model.unwrap_or_else(|| "(model not named in the response)".to_string());
            println!("\x1b[32m✓\x1b[0m The provider answered in {elapsed_ms} ms. Model: {model}");
            Ok(())
        }
        Probe::Rejected { elapsed_ms } => {
            anyhow::bail!("the provider rejected this key (401) after {elapsed_ms} ms")
        }
        Probe::Failed {
            stage,
            error,
            elapsed_ms,
        } => anyhow::bail!(
            "provider check failed at the {stage} stage after {elapsed_ms} ms: {error}"
        ),
    }
}

/// `rz checks set-key` — install a provider key and prove it works.
///
/// Entirely local: read the config, write the file, ask the provider. The
/// daemon is not involved and no token for it is resolved, so this works on a
/// box where another client owns the daemon's API token.
async fn cmd_checks_set_key(enable: bool) -> Result<()> {
    require_root("checks set-key")?;

    let (cfg, cfg_path, note) = load_local_checks()?;
    if let Some(n) = note {
        println!("\x1b[33mNote:\x1b[0m {n}");
    }
    let key_file = cfg.jev.api_key_file.clone();
    let path = std::path::Path::new(&key_file);
    let previous = std::fs::read_to_string(path).ok();

    let key = read_secret_from_stdin()?;
    write_key_file(path, &key)?;
    println!("Wrote {key_file} (0600, root).");

    // Verify before claiming success. The key goes straight from this process
    // to the provider: it is never an argument, and never a request body sent
    // to anything else.
    println!("Verifying against {}…", cfg.jev.endpoint());
    let outcome = probe_provider(&cfg.jev, key).await;

    match outcome {
        Probe::Ok { elapsed_ms, model } => {
            let model = model.unwrap_or_else(|| "(model not named)".to_string());
            println!("\x1b[32m✓\x1b[0m The key works. {model} answered in {elapsed_ms} ms.");
        }
        Probe::Rejected { .. } => {
            // A rejected key must not be left in place pretending to work.
            match &previous {
                Some(old) => {
                    write_key_file(path, old.trim())?;
                    println!("\x1b[31m✗\x1b[0m The provider rejected that key (401).");
                    println!("   The previous key has been restored.");
                }
                None => {
                    let _ = std::fs::remove_file(path);
                    println!("\x1b[31m✗\x1b[0m The provider rejected that key (401).");
                    println!("   Removed {key_file}; there was no key there before.");
                }
            }
            anyhow::bail!("key not installed");
        }
        Probe::Failed { error, .. } => {
            println!("\x1b[33m!\x1b[0m The key was saved but could not be verified: {error}");
            println!("   Re-run the check when the provider is reachable:  sudo rz checks test");
        }
    }

    // Next step, spelled out.
    if cfg.enabled {
        println!("\nChecks are already enabled. Reload to pick up the key:");
        println!("  sudo systemctl reload ringzero-daemon");
    } else if enable {
        match enable_checks_in_config() {
            Ok(p) => {
                println!("\nSet [checks] enabled = true in {p}.");
                println!("Reload to apply:  sudo systemctl reload ringzero-daemon");
            }
            Err(e) => {
                println!("\n[!] Could not edit the config automatically: {e}");
                println!("Set [checks] enabled = true by hand, then reload the daemon.");
            }
        }
    } else {
        println!("\nNext: turn the checks layer on.");
        println!("  sudo rz checks set-key --enable      # edits the config for you");
        println!("or set [checks] enabled = true in {cfg_path}, then:");
        println!("  sudo systemctl reload ringzero-daemon");
    }
    Ok(())
}

/// Flip `enabled = false` to `true` inside the `[checks]` section only.
fn enable_checks_in_config() -> Result<String> {
    let path = std::env::var("RINGZERO_CONFIG")
        .unwrap_or_else(|_| "/etc/ringzero/daemon.toml".to_string());
    let text = std::fs::read_to_string(&path).with_context(|| format!("reading {path}"))?;

    let mut out = String::with_capacity(text.len());
    let mut in_checks = false;
    let mut done = false;
    for line in text.lines() {
        let t = line.trim_start();
        if t.starts_with('[') {
            // `[checks.jev]` is a different table; only `[checks]` counts.
            in_checks = t.starts_with("[checks]");
        }
        if in_checks && !done && t.starts_with("enabled") && t.contains("false") {
            out.push_str(&line.replacen("false", "true", 1));
            out.push('\n');
            done = true;
            continue;
        }
        out.push_str(line);
        out.push('\n');
    }
    if !done {
        anyhow::bail!("could not find `enabled = false` under [checks] in {path}");
    }
    std::fs::write(&path, out).with_context(|| format!("writing {path}"))?;
    Ok(path)
}

// ── Scan baseline ───────────────────────────────────────────────────────────

async fn cmd_baseline_show(api: &str) -> Result<()> {
    let v = fetch_json(&format!("{api}/api/v1/scan/baseline")).await?;
    if !v["accepted"].as_bool().unwrap_or(false) {
        println!("No scan baseline accepted. Every finding is reported as new.");
        println!("Accept the current state with:  sudo rz scan baseline accept");
        return Ok(());
    }
    println!("Scan baseline:");
    println!(
        "  accepted by       {}",
        v["accepted_by"].as_str().unwrap_or("?")
    );
    println!(
        "  accepted at       {}",
        v["accepted_at"].as_str().unwrap_or("?")
    );
    println!(
        "  findings accepted {}",
        v["findings_accepted"].as_u64().unwrap_or(0)
    );
    println!(
        "  surfaces          {}",
        v["surfaces"].as_u64().unwrap_or(0)
    );
    println!("  file              {}", v["path"].as_str().unwrap_or("?"));
    println!("\n`rz scan skills` reports only what is new. `--all` shows everything.");
    Ok(())
}

async fn cmd_baseline_accept(api: &str) -> Result<()> {
    println!("Scanning, then accepting the current findings as expected…");
    let v = post_json(
        &format!("{api}/api/v1/scan/baseline"),
        serde_json::json!({}),
    )
    .await?;
    println!(
        "\x1b[32m✓\x1b[0m Accepted {} finding(s) across {} surface(s) as {}.",
        v["findings_accepted"].as_u64().unwrap_or(0),
        v["surfaces"].as_u64().unwrap_or(0),
        v["accepted_by"].as_str().unwrap_or("root")
    );
    println!("Later scans report only what is new. `rz scan skills --all` still shows everything.");
    println!("\nA baseline hides known noise. It does not make a real finding go away.");
    Ok(())
}

async fn cmd_baseline_clear(api: &str) -> Result<()> {
    delete_json(&format!("{api}/api/v1/scan/baseline")).await?;
    println!("Scan baseline cleared. Every finding is reported as new again.");
    Ok(())
}

// ── Review queue ─────────────────────────────────────────────────────────────

/// Shorten a queue id for display; the full id is what `show`/`label` take.
fn short_id(id: &str) -> String {
    id.rsplit('-').next().unwrap_or(id).to_string()
}

fn label_colour(label: Option<&str>) -> String {
    match label {
        None => "\x1b[33munlabelled\x1b[0m".to_string(),
        Some("real-threat") => "\x1b[31mreal-threat\x1b[0m".to_string(),
        Some("false-positive") => "\x1b[32mfalse-positive\x1b[0m".to_string(),
        Some(other) => other.to_string(),
    }
}

async fn cmd_review_list(api: &str, limit: usize, all: bool) -> Result<()> {
    let url = format!(
        "{api}/api/v1/review?limit={limit}&unlabeled_only={}",
        if all { "false" } else { "true" }
    );
    let v = fetch_json(&url).await?;
    let items = v["items"].as_array().cloned().unwrap_or_default();
    if items.is_empty() {
        if all {
            println!("\x1b[32m✓\x1b[0m The review queue is empty.");
        } else {
            println!(
                "\x1b[32m✓\x1b[0m Nothing waiting for a label. (`--all` shows labelled items.)"
            );
        }
        return Ok(());
    }
    println!("{} item(s):\n", items.len());
    for i in &items {
        let id = i["id"].as_str().unwrap_or("?");
        let source = i["source"].as_str().unwrap_or("?");
        let created = i["created"].as_str().unwrap_or("?");
        let summary = i["summary"].as_str().unwrap_or("");
        let session = i["session_id"].as_str().unwrap_or("?");
        let label = i["label"].as_str();
        let src_tag = match source {
            "kernel_deny" => "\x1b[31mDENY\x1b[0m ",
            "check_flag" => "\x1b[33mFLAG\x1b[0m ",
            _ => "?    ",
        };
        println!("  {src_tag} {}  {}", short_id(id), summary);
        println!(
            "         session {session} · {created} · {}",
            label_colour(label)
        );
    }
    println!("\nLabel one with:  sudo rz review label <id> real-threat");
    Ok(())
}

async fn cmd_review_show(api: &str, id: &str) -> Result<()> {
    // The list endpoint is the only reader, so pull a page and find the id.
    // Accepts either the full id or the short suffix shown by `list`.
    let v = fetch_json(&format!(
        "{api}/api/v1/review?limit=1000&unlabeled_only=false"
    ))
    .await?;
    let items = v["items"].as_array().cloned().unwrap_or_default();
    let found = items.iter().find(|i| {
        let full = i["id"].as_str().unwrap_or("");
        full == id || short_id(full) == id
    });
    match found {
        None => anyhow::bail!("no review item matching '{id}'"),
        Some(i) => {
            println!("id       {}", i["id"].as_str().unwrap_or("?"));
            println!("source   {}", i["source"].as_str().unwrap_or("?"));
            println!("created  {}", i["created"].as_str().unwrap_or("?"));
            println!("session  {}", i["session_id"].as_str().unwrap_or("?"));
            println!("label    {}", label_colour(i["label"].as_str()));
            println!("summary  {}", i["summary"].as_str().unwrap_or(""));
            println!("\ntrace:");
            println!(
                "{}",
                serde_json::to_string_pretty(&i["trace"]).unwrap_or_default()
            );
            Ok(())
        }
    }
}

async fn cmd_review_label(api: &str, id: &str, label: &str) -> Result<()> {
    if !matches!(label, "benign" | "real-threat" | "false-positive") {
        anyhow::bail!("label must be one of: benign | real-threat | false-positive");
    }
    // Resolve a short id to the full one the API expects.
    let full = {
        let v = fetch_json(&format!(
            "{api}/api/v1/review?limit=1000&unlabeled_only=false"
        ))
        .await?;
        let items = v["items"].as_array().cloned().unwrap_or_default();
        items
            .iter()
            .find_map(|i| {
                let f = i["id"].as_str().unwrap_or("");
                (f == id || short_id(f) == id).then(|| f.to_string())
            })
            .ok_or_else(|| anyhow::anyhow!("no review item matching '{id}'"))?
    };
    post_json(
        &format!("{api}/api/v1/review/{full}/label"),
        serde_json::json!({ "label": label }),
    )
    .await?;
    println!(
        "Labelled {} as {}",
        short_id(&full),
        label_colour(Some(label))
    );
    Ok(())
}

async fn cmd_review_stats(api: &str) -> Result<()> {
    let v = fetch_json(&format!("{api}/api/v1/review/stats")).await?;
    let g = |k: &str| v[k].as_u64().unwrap_or(0);
    println!("Review queue:");
    println!("  total           {}", g("total"));
    println!("  unlabelled      \x1b[33m{}\x1b[0m", g("unlabeled"));
    println!("  benign          {}", g("benign"));
    println!("  real-threat     \x1b[31m{}\x1b[0m", g("real_threat"));
    println!("  false-positive  \x1b[32m{}\x1b[0m", g("false_positive"));
    let labelled = g("benign") + g("real_threat") + g("false_positive");
    if labelled == 0 {
        println!("\nNothing labelled yet. Labels are the training rows future models need.");
    }
    Ok(())
}

async fn cmd_enforcement_show(api: &str) -> Result<()> {
    let v = fetch_json(&format!("{api}/api/v1/enforcement")).await?;
    println!("Enforcement posture:");
    println!(
        "  default: {}",
        color_action(v["default_action"].as_str().unwrap_or("?"))
    );
    if let Some(cats) = v["categories"].as_object() {
        println!("  categories:");
        for cat in ENF_CATEGORIES {
            if let Some(action) = cats.get(*cat).and_then(|x| x.as_str()) {
                println!("    {cat:24} {}", color_action(action));
            }
        }
    }
    Ok(())
}

async fn cmd_enforcement_set(api: &str, category: Option<&str>, action: &str) -> Result<()> {
    if !matches!(action, "observe" | "alert" | "block") {
        anyhow::bail!("action must be observe | alert | block (got '{action}')");
    }
    // The endpoint takes the full section, so GET → mutate → POST.
    let mut cfg = fetch_json(&format!("{api}/api/v1/enforcement")).await?;
    match category {
        None => cfg["default_action"] = serde_json::json!(action),
        Some(cat) => {
            if !ENF_CATEGORIES.contains(&cat) {
                anyhow::bail!(
                    "unknown category '{cat}'.\nValid categories: {}",
                    ENF_CATEGORIES.join(", ")
                );
            }
            if !cfg["categories"].is_object() {
                cfg["categories"] = serde_json::json!({});
            }
            cfg["categories"][cat] = serde_json::json!(action);
        }
    }
    post_json(&format!("{api}/api/v1/enforcement"), cfg).await?;
    match category {
        None => println!("Enforcement default → {}", color_action(action)),
        Some(cat) => println!("Enforcement {cat} → {}", color_action(action)),
    }
    println!("  saved to daemon.toml — reload to apply: sudo systemctl reload ringzero-daemon");
    Ok(())
}

// ── File access control handlers ──────────────────────────────────────────────

async fn cmd_file_access_show(api: &str) -> Result<()> {
    let v = fetch_json(&format!("{api}/api/v1/file-access-rules")).await?;
    let rules = v["rules"].as_array().cloned().unwrap_or_default();
    if rules.is_empty() {
        println!("No file access rules.");
        return Ok(());
    }
    println!("File access rules ({}):", rules.len());
    let mut unresolved = 0usize;
    for r in &rules {
        let action = r["action"].as_str().unwrap_or("?");
        let mark = if action == "block" {
            "\x1b[31mBLOCK\x1b[0m"
        } else {
            "\x1b[32mALLOW\x1b[0m"
        };
        // What the rule is, and whether the kernel is actually holding it.
        // A rule that reads BLOCK while enforcing nothing is the exact thing
        // this column exists to stop, so it is never printed on its own.
        let kind = r["kind"].as_str().unwrap_or("file");
        let live = r["status"].as_str().unwrap_or("enforced") == "enforced";
        let state = if live {
            String::new()
        } else {
            unresolved += 1;
            "  \x1b[33m← NOT ENFORCING\x1b[0m".to_string()
        };
        println!(
            "  [{}] {mark} {:<6} {}  ({}){}",
            r["id"].as_str().unwrap_or("?"),
            kind,
            r["pattern"].as_str().unwrap_or("?"),
            r["source"].as_str().unwrap_or("custom"),
            state
        );
        if !live {
            if let Some(why) = r["status_reason"].as_str() {
                println!("        {why}");
            }
        }
        if r["kind_from_legacy_marker"].as_bool() == Some(true) {
            println!("        kind came from the old [dir-block] note — re-save this rule");
        }
    }
    if unresolved > 0 {
        println!(
            "\n\x1b[33m{unresolved} rule(s) are stored but the kernel is holding nothing for \
             them.\x1b[0m They will start enforcing when the path exists."
        );
    }
    Ok(())
}

/// What a pattern actually points at, for deciding whether two rules are the
/// same rule.
///
/// `~` is expanded the way the daemon expands it, so `~/projects/*` and
/// `/home/dev/projects/*` compare equal. This mirrors
/// `policy::file_rule::identity` in the daemon, which is the authority; the
/// copy here exists so the CLI can report "already exists" instead of posting a
/// set and watching it come back shorter.
fn resolved_target(pattern: &str, kind: &str) -> String {
    let p = pattern.trim();
    let p = if kind == "dir" {
        p.trim_end_matches("/*").trim_end_matches('/')
    } else {
        p
    };
    let expanded = match p.strip_prefix('~') {
        Some(rest) => format!("{}{rest}", operator_home()),
        None => p.to_string(),
    };
    // Follow symlinks, so /home/alice.linux and /home/alice.guest are one
    // directory rather than two rules. A path that does not exist yet keeps
    // its lexical form, which is what the daemon does too.
    std::fs::canonicalize(&expanded)
        .map(|p| p.to_string_lossy().to_string())
        .unwrap_or(expanded)
}

/// The home `~` means in a rule: the OPERATOR's, not the one this process
/// happens to be running with.
///
/// Under `sudo rz`, `$HOME` is usually /root, so expanding `~` with it points
/// at the wrong directory and two spellings of one rule stop matching.
/// `$SUDO_USER` names the person who ran the command, and their home comes from
/// /etc/passwd.
fn operator_home() -> String {
    if let Ok(user) = std::env::var("SUDO_USER") {
        if !user.is_empty() {
            if let Ok(passwd) = std::fs::read_to_string("/etc/passwd") {
                for line in passwd.lines() {
                    let mut f = line.split(':');
                    if f.next() == Some(user.as_str()) {
                        if let Some(home) = f.nth(4) {
                            if !home.is_empty() {
                                return home.to_string();
                            }
                        }
                    }
                }
            }
        }
    }
    std::env::var("HOME").unwrap_or_else(|_| "/root".to_string())
}

/// `rz file-access add` — add one rule.
///
/// The daemon refuses a rule nothing can enforce, so a pattern that would be
/// stored and then quietly do nothing fails here with the reason instead. A
/// trailing `/*` means the directory and everything under it; `--dir` and
/// `--file` say it outright.
async fn cmd_file_access_add(
    api: &str,
    pattern: &str,
    action: &str,
    description: Option<&str>,
    kind: Option<&str>,
) -> Result<()> {
    if !matches!(action, "block" | "allow") {
        anyhow::bail!("action must be block | allow (got '{action}')");
    }
    // Say what it is. With neither flag the daemon infers it, and a trailing
    // /* infers a directory — so the obvious thing works without a flag.
    let kind = kind.map(|k| k.to_string()).unwrap_or_else(|| {
        if pattern.trim().ends_with("/*") {
            "dir".to_string()
        } else {
            "file".to_string()
        }
    });

    let v = fetch_json(&format!("{api}/api/v1/file-access-rules")).await?;
    let mut rules = v["rules"].as_array().cloned().unwrap_or_default();
    // The GET decorates each rule with read-only fields. Send back only what
    // the daemon stores, or they come straight back at us as unknown input.
    for r in &mut rules {
        if let Some(obj) = r.as_object_mut() {
            obj.remove("status");
            obj.remove("status_reason");
            obj.remove("kind_from_legacy_marker");
        }
    }
    // ADDING THE SAME RULE TWICE IS NOT AN ERROR, AND DOES NOT ADD A ROW.
    //
    // Repeating an add used to append another row, so a list could end up with
    // four rules blocking one path — and then removing one left the path
    // blocked, which reads as "remove is broken". The daemon resolves patterns
    // and collapses duplicates; this does the same check first so the CLI can
    // say what it did rather than silently posting a set that comes back
    // shorter.
    let target = resolved_target(pattern, &kind);
    let existing = rules.iter().position(|r| {
        let r_kind = r["kind"].as_str().unwrap_or("file").to_string();
        r["action"].as_str() == Some(action)
            && r_kind == kind
            && resolved_target(r["pattern"].as_str().unwrap_or(""), &r_kind) == target
    });

    if let Some(idx) = existing {
        let existing_id = rules[idx]["id"].as_str().unwrap_or("?").to_string();
        let old_description = rules[idx]["description"].as_str().map(|d| d.to_string());
        let new_description = description.map(|d| d.to_string());

        if new_description.is_some() && new_description != old_description {
            rules[idx]["description"] = serde_json::json!(new_description);
            post_json(
                &format!("{api}/api/v1/file-access-rules"),
                serde_json::json!({ "rules": rules }),
            )
            .await?;
            println!(
                "That rule already exists (id {existing_id}) — updated its description. \
                 No second rule was added."
            );
        } else {
            println!("That rule already exists (id {existing_id}). No change.");
        }
        return Ok(());
    }

    let id = format!(
        "cli-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis())
            .unwrap_or(0)
    );
    rules.push(serde_json::json!({
        "id": id,
        "pattern": pattern,
        "action": action,
        "source": "custom",
        "kind": kind,
        "description": description,
    }));
    post_json(
        &format!("{api}/api/v1/file-access-rules"),
        serde_json::json!({ "rules": rules }),
    )
    .await?;

    // The daemon is the authority on whether two patterns are the same rule:
    // it expands `~` against the real homes and resolves symlinks, which this
    // process cannot do reliably (under sudo, $HOME is usually /root). If our
    // id is not in the set that comes back, the daemon folded this into an
    // existing rule, and saying "Added" would be a lie.
    let after = fetch_json(&format!("{api}/api/v1/file-access-rules")).await?;
    let added = after["rules"]
        .as_array()
        .and_then(|rs| rs.iter().find(|r| r["id"].as_str() == Some(id.as_str())));

    let Some(added) = added else {
        println!("That rule already exists. No second rule was added.");
        if let Some(covering) = after["rules"].as_array().and_then(|rs| {
            rs.iter()
                .find(|r| r["action"].as_str() == Some(action) && r["kind"].as_str() == Some(&kind))
        }) {
            println!(
                "  It is [{}] {} {}",
                covering["id"].as_str().unwrap_or("?"),
                covering["kind"].as_str().unwrap_or("?"),
                covering["pattern"].as_str().unwrap_or("?")
            );
        }
        return Ok(());
    };

    println!(
        "Added {} rule for '{pattern}' as a {kind} rule (id {id})",
        color_action(action)
    );

    // Say whether it is actually live, rather than leaving the operator to
    // assume. A rule for a directory that does not exist yet is legitimate,
    // and it is not enforcing anything until it does.
    {
        if added["status"].as_str() == Some("unresolved") {
            println!(
                "\x1b[33m! Not enforcing yet:\x1b[0m {}",
                added["status_reason"]
                    .as_str()
                    .unwrap_or("path does not resolve")
            );
        } else {
            println!("  The kernel is holding this rule.");
        }
    }
    Ok(())
}

/// `rz file-access remove` — take a rule out, by id or by pattern.
///
/// The warning at the end is the point. Removing one of several rules that
/// cover the same path used to look like a no-op: the rule was gone from the
/// list and the path was still blocked. Now it says so.
async fn cmd_file_access_remove(api: &str, target: &str, all: bool) -> Result<()> {
    let v = fetch_json(&format!("{api}/api/v1/file-access-rules")).await?;
    let rules = v["rules"].as_array().cloned().unwrap_or_default();
    if rules.is_empty() {
        anyhow::bail!("there are no file access rules to remove");
    }

    // Match by id first; if nothing matches, treat the argument as a pattern.
    let by_id: Vec<usize> = rules
        .iter()
        .enumerate()
        .filter(|(_, r)| r["id"].as_str() == Some(target))
        .map(|(i, _)| i)
        .collect();

    let matched: Vec<usize> = if !by_id.is_empty() {
        by_id
    } else {
        let wanted_kind = if target.trim().ends_with("/*") {
            "dir"
        } else {
            "file"
        };
        let wanted = resolved_target(target, wanted_kind);
        let hits: Vec<usize> = rules
            .iter()
            .enumerate()
            .filter(|(_, r)| {
                let k = r["kind"].as_str().unwrap_or("file");
                resolved_target(r["pattern"].as_str().unwrap_or(""), k) == wanted
            })
            .map(|(i, _)| i)
            .collect();
        if hits.is_empty() {
            anyhow::bail!(
                "no rule with id or pattern '{target}' (list them with: rz file-access show)"
            );
        }
        if hits.len() > 1 && !all {
            println!("{} rules cover '{target}':", hits.len());
            for i in &hits {
                println!(
                    "  [{}] {} {}",
                    rules[*i]["id"].as_str().unwrap_or("?"),
                    rules[*i]["action"].as_str().unwrap_or("?"),
                    rules[*i]["pattern"].as_str().unwrap_or("?")
                );
            }
            anyhow::bail!(
                "refusing to guess which one you meant. Remove one by id, or remove them \
                 all with:  rz file-access remove --all '{target}'"
            );
        }
        hits
    };

    // What is being removed, kept for the check afterwards.
    let removed: Vec<(String, String, String)> = matched
        .iter()
        .map(|i| {
            let k = rules[*i]["kind"].as_str().unwrap_or("file").to_string();
            (
                rules[*i]["id"].as_str().unwrap_or("?").to_string(),
                rules[*i]["pattern"].as_str().unwrap_or("").to_string(),
                k,
            )
        })
        .collect();

    let kept: Vec<serde_json::Value> = rules
        .iter()
        .enumerate()
        .filter(|(i, _)| !matched.contains(i))
        .map(|(_, r)| {
            let mut r = r.clone();
            // The GET decorates each rule with read-only fields; send back only
            // what the daemon stores.
            if let Some(obj) = r.as_object_mut() {
                obj.remove("status");
                obj.remove("status_reason");
                obj.remove("kind_from_legacy_marker");
            }
            r
        })
        .collect();

    post_json(
        &format!("{api}/api/v1/file-access-rules"),
        serde_json::json!({ "rules": kept }),
    )
    .await?;

    for (id, pattern, _) in &removed {
        println!("Removed rule {id} ({pattern})");
    }

    // STILL COVERED? Say so. "I removed it and it is still blocked" is the
    // confusion this exists to prevent.
    //
    // Read the set back rather than reasoning about the one we posted: the
    // daemon resolves `~` against the real homes and follows symlinks, and it
    // collapses rules that turn out to be the same. Warning from the local view
    // would name rules that the same save had just folded away.
    let after = fetch_json(&format!("{api}/api/v1/file-access-rules")).await?;
    let remaining = after["rules"].as_array().cloned().unwrap_or_default();

    for (_, pattern, kind) in &removed {
        let resolved = resolved_target(pattern, kind);
        let still: Vec<&serde_json::Value> = remaining
            .iter()
            .filter(|r| {
                r["action"].as_str() == Some("block")
                    && resolved_target(
                        r["pattern"].as_str().unwrap_or(""),
                        r["kind"].as_str().unwrap_or("file"),
                    ) == resolved
            })
            .collect();
        if !still.is_empty() {
            println!(
                "\n\x1b[33m{} other rule(s) still block '{pattern}'.\x1b[0m \
                 Removing this one did not unblock it:",
                still.len()
            );
            for r in still {
                println!(
                    "  [{}] {} {}",
                    r["id"].as_str().unwrap_or("?"),
                    r["kind"].as_str().unwrap_or("file"),
                    r["pattern"].as_str().unwrap_or("?")
                );
            }
            println!("  Remove them all with:  rz file-access remove --all '{pattern}'");
        }
    }
    Ok(())
}

async fn cmd_scan_skills(api: &str, all: bool) -> Result<()> {
    println!("Scanning AI agent skill surfaces…");
    let v = post_json(
        &format!(
            "{api}/api/v1/skill-scan/auto{}",
            if all { "?all=true" } else { "" }
        ),
        serde_json::json!({}),
    )
    .await?;

    let roots = v["roots_found"].as_u64().unwrap_or(0);
    let files = v["files_scanned"].as_u64().unwrap_or(0);
    let overall = v["overall_risk"].as_str().unwrap_or("unknown");
    let suppressed = v["baseline_suppressed"].as_u64().unwrap_or(0);
    let baselined = v["baseline"]["accepted"].as_bool().unwrap_or(false);

    if roots == 0 {
        println!("\x1b[33mNo AI agent skill surfaces found on this host.\x1b[0m");
        return Ok(());
    }

    // Colour the overall verdict.
    let (col, mark) = match overall {
        "clean" => ("\x1b[32m", "✓"),
        "low" | "medium" => ("\x1b[33m", "⚑"),
        _ => ("\x1b[31m", "✗"),
    };
    println!(
        "{col}{mark} Scanned {roots} skill surface(s), {files} file(s) — overall risk: {overall}\x1b[0m"
    );
    if baselined {
        if all {
            println!("Showing ALL findings (baseline ignored).\n");
        } else {
            println!(
                "Showing findings NEW since the accepted baseline; {suppressed} already accepted. \
                 Use --all to see everything.\n"
            );
        }
    } else {
        println!();
    }

    if let Some(results) = v["results"].as_array() {
        for r in results {
            let agent = r["agent"].as_str().unwrap_or("?");
            let kind = r["kind"].as_str().unwrap_or("?");
            let owner = r["owner"].as_str().unwrap_or("?");
            let path = r["path"].as_str().unwrap_or("?");
            let risk = r["risk"].as_str().unwrap_or("?");
            let inj = r["injection_reports"]
                .as_array()
                .map(|a| a.len())
                .unwrap_or(0);
            let sup = r["supply_findings"]
                .as_array()
                .map(|a| a.len())
                .unwrap_or(0);

            // Only spell out surfaces that aren't clean; list clean ones tersely.
            if risk == "clean" {
                println!("  \x1b[32m✓\x1b[0m {agent}/{kind} ({owner})  {path}");
                continue;
            }
            let rc = if risk == "critical" || risk == "high" {
                "\x1b[31m"
            } else {
                "\x1b[33m"
            };
            println!("  {rc}● {agent}/{kind}\x1b[0m ({owner})  {path}");
            println!("    risk: {rc}{risk}\x1b[0m   injection findings: {inj}   supply-chain findings: {sup}");
            if let Some(injs) = r["injection_reports"].as_array() {
                for ir in injs.iter().take(5) {
                    let f = ir["path"].as_str().unwrap_or("?");
                    let signals = ir["findings"]
                        .as_array()
                        .map(|fs| {
                            fs.iter()
                                .flat_map(|fi| {
                                    fi["signals"].as_array().cloned().unwrap_or_default()
                                })
                                .filter_map(|s| s.as_str().map(String::from))
                                .collect::<Vec<_>>()
                                .join("; ")
                        })
                        .unwrap_or_default();
                    println!("      ↳ injection: {f}  {signals}");
                }
            }
            if let Some(sups) = r["supply_findings"].as_array() {
                for sr in sups.iter().take(5) {
                    let f = sr["path"].as_str().unwrap_or("?");
                    let lvl = sr["risk_level"].as_str().unwrap_or("?");
                    println!("      ↳ supply-chain [{lvl}]: {f}");
                }
            }
            println!();
        }
    }
    Ok(())
}

async fn cmd_nhi(api: &str) -> Result<()> {
    let v = fetch_json(&format!("{api}/api/v1/nhi")).await?;
    let count = v["nhi_count"].as_u64().unwrap_or(0);
    if count == 0 {
        println!("\x1b[32m✓\x1b[0m No privileged NHI detected.");
        return Ok(());
    }
    println!(
        "\x1b[33m⚑ {} privileged Non-Human Identities detected\x1b[0m\n",
        count
    );
    if let Some(ids) = v["identities"].as_array() {
        for nhi in ids {
            let actor = nhi["actor"].as_str().unwrap_or("?");
            let atype = nhi["agent_type"].as_str().unwrap_or("?");
            let reason = nhi["reason"].as_str().unwrap_or("?");
            let creds = nhi["credentials_accessed"]
                .as_array()
                .map(|a| {
                    a.iter()
                        .filter_map(|v| v.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                })
                .unwrap_or_default();
            println!("  Actor: {actor}  Type: {atype}");
            println!("  Reason: {reason}");
            if !creds.is_empty() {
                println!("  Credentials: {creds}");
            }
            println!();
        }
    }
    Ok(())
}

// ── Shadow AI handler ───────────────────────────────────────────────────

async fn cmd_shadow_ai(api: &str) -> Result<()> {
    let v = fetch_json(&format!("{api}/api/v1/shadow-ai")).await?;
    let monitored = v["monitored_endpoints"].as_u64().unwrap_or(0);
    let count = v["unauthorized_count"].as_u64().unwrap_or(0);
    println!("Shadow AI Scan — monitoring {} AI endpoints", monitored);
    if count == 0 {
        println!("\x1b[32m✓\x1b[0m No unauthorized AI API usage detected.");
        return Ok(());
    }
    println!(
        "\x1b[31m✗ {} unauthorized AI API call(s) detected\x1b[0m\n",
        count
    );
    if let Some(detections) = v["detections"].as_array() {
        for d in detections {
            let provider = d["provider"].as_str().unwrap_or("?");
            let process = d["process"].as_str().unwrap_or("?");
            let pid = d["pid"].as_u64().unwrap_or(0);
            let target = d["target"].as_str().unwrap_or("?");
            let ts = d["timestamp"].as_str().unwrap_or("?");
            println!("  \x1b[31m[SHADOW AI]\x1b[0m  {provider}");
            println!("    Process: {process}[{pid}]  Target: {target}");
            println!("    At: {ts}");
            println!();
        }
    }
    Ok(())
}

// ── Session events handler ────────────────────────────────────

async fn cmd_session_events(api: &str, id: &str) -> Result<()> {
    let v = fetch_json(&format!("{api}/api/v1/sessions/{id}/events")).await?;
    let count = v["event_count"].as_u64().unwrap_or(0);
    println!("Session {id} — {count} kernel event(s)\n");
    if let Some(events) = v["events"].as_array() {
        println!(
            "{:<26} {:<7} {:<22} {:<24} {}",
            "TIME", "VERDICT", "KIND", "PROCESS[PID]", "TARGET"
        );
        println!("{}", "─".repeat(100));
        for ev in events {
            print_event(ev);
        }
    }
    Ok(())
}

// ── Setup handler ─────────────────────────────────────────────────────────────

async fn cmd_setup(binary: Option<String>, name: Option<String>, all: bool) -> Result<()> {
    if all {
        return cmd_setup_all().await;
    }
    cmd_setup_linux(binary, name).await
}

async fn cmd_setup_linux(binary: Option<String>, name: Option<String>) -> Result<()> {
    // Resolve binary path
    let real_bin = match binary {
        Some(b) => {
            // Expand ~
            if b.starts_with("~/") {
                let home = std::env::var("HOME").unwrap_or_default();
                format!("{home}/{}", &b[2..])
            } else {
                b
            }
        }
        None => {
            // Auto-detect claude
            let candidates = [
                std::env::var("HOME")
                    .map(|h| format!("{h}/.local/bin/claude"))
                    .ok(),
                std::env::var("HOME")
                    .map(|h| format!("{h}/.local/share/claude/claude"))
                    .ok(),
                Some("/usr/local/bin/claude.real".to_string()),
            ];
            candidates
                .into_iter()
                .flatten()
                .find(|p| std::path::Path::new(p).exists())
                .ok_or_else(|| {
                    anyhow::anyhow!(
                        "Cannot auto-detect claude binary. Use --binary /path/to/real/claude"
                    )
                })?
        }
    };

    let shim_name = name.unwrap_or_else(|| {
        std::path::Path::new(&real_bin)
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_else(|| "claude".to_string())
    });

    // Verify real binary exists
    if !std::path::Path::new(&real_bin).exists() {
        anyhow::bail!("Binary not found: {real_bin}");
    }

    // Determine rz binary location
    let rz_bin = std::env::current_exe().unwrap_or_else(|_| PathBuf::from("/usr/bin/rz"));
    let rz_bin_str = rz_bin.display();

    // Write shim script
    let shim_path = format!("/usr/local/bin/{shim_name}");
    // The shim makes prompt capture transparent: the user still runs `claude`,
    // but it routes the agent's HTTPS through the local inspection proxy and
    // trusts Ring Zero's CA, so prompts AND responses are captured even though
    // the agent statically links its own TLS (invisible to the SSL uprobe). The
    // env is set inline so it is inherited through the sandbox into the real
    // binary. CA path is the root-daemon location.
    const CAP_PROXY: &str = "http://127.0.0.1:7710";
    const CAP_CA: &str = "/var/lib/ringzero/spiffe-ca/spiffe-ca.pem";
    let shim_content = format!(
        "#!/bin/sh\n\
         # Ring Zero Security capture+sandbox shim for {shim_name}\n\
         # Real binary: {real_bin}\n\
         export HTTPS_PROXY={CAP_PROXY} https_proxy={CAP_PROXY} HTTP_PROXY={CAP_PROXY} http_proxy={CAP_PROXY}\n\
         export NODE_EXTRA_CA_CERTS={CAP_CA} SSL_CERT_FILE={CAP_CA} REQUESTS_CA_BUNDLE={CAP_CA} CURL_CA_BUNDLE={CAP_CA}\n\
         exec {rz_bin_str} sandbox -- {real_bin} \"$@\"\n"
    );

    // Create deny marker
    let marker = deny_marker_path();
    tokio::fs::write(&marker, b"")
        .await
        .with_context(|| format!("Cannot create deny marker at {}", marker.display()))?;

    // Write sandbox config
    let cfg_dir = PathBuf::from("/etc/ringzero");
    tokio::fs::create_dir_all(&cfg_dir)
        .await
        .with_context(|| "Cannot create /etc/ringzero -- run as root")?;

    let deny_list: Vec<String> = DEFAULT_DENY_READ
        .iter()
        .map(|s| format!("  \"{s}\""))
        .collect();
    let cfg_content = format!(
        "# Ring Zero sandbox config\n# Generated by: rz setup\n\n[sandbox]\ndeny_read = [\n{}\n]\n",
        deny_list.join(",\n")
    );
    let cfg_path = sandbox_config_path();
    tokio::fs::write(&cfg_path, cfg_content.as_bytes())
        .await
        .with_context(|| format!("Cannot write {}", cfg_path.display()))?;

    // Write shim
    tokio::fs::write(&shim_path, shim_content.as_bytes())
        .await
        .with_context(|| format!("Cannot write shim to {shim_path} -- run as root"))?;

    // Make executable
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&shim_path, std::fs::Permissions::from_mode(0o755))
            .with_context(|| format!("Cannot chmod {shim_path}"))?;
    }

    println!("\x1b[32mOK\x1b[0m Ring Zero sandbox shim installed:");
    println!("  Shim:        {shim_path}");
    println!("  Real binary: {real_bin}");
    println!("  Config:      {}", cfg_path.display());
    println!("  Deny marker: {}", marker.display());
    println!();
    println!("Users can now run \x1b[36m{shim_name}\x1b[0m normally -- it will be transparently sandboxed.");
    println!("eBPF kernel telemetry continues inside the sandbox for full session visibility.");

    Ok(())
}

// ── Multi-agent setup (rz setup --all) ──────────────────────────────────────

/// Canonical AI-agent binary names to discover + shim. Mirrors the daemon's
/// agent_detect::known_agents() so capture covers every agent the analyzer knows.
fn known_agent_names() -> &'static [&'static str] {
    &[
        "claude", "cursor", "copilot", "codex", "chatgpt", "gemini", "devin", "aider", "windsurf",
        "cody", "tabnine", "continue", "cline", "openclaw",
    ]
}

/// The capture shim script for one agent: set the proxy + CA-trust env, then
/// exec the preserved original launcher. Kept capture-only (no sandbox wrapper)
/// for reliability — the sandbox can be layered back once capture is solid.
fn capture_shim_content(real_bin: &str, shim_name: &str, _rz_bin: &str) -> String {
    const CAP_CA: &str = "/var/lib/ringzero/spiffe-ca/spiffe-ca.pem";
    // Encode the agent PID ($$, which becomes the exec'd agent's pid) in the
    // proxy URL userinfo so the proxy can attribute capture to the right session
    // (the agent sends it as Proxy-Authorization on CONNECT).
    format!(
        "#!/bin/sh\n\
         # Ring Zero Security capture shim for {shim_name}\n\
         # Real binary: {real_bin}\n\
         RZ_PROXY=\"http://rzpid-$$:rz@127.0.0.1:7710\"\n\
         export HTTPS_PROXY=\"$RZ_PROXY\" https_proxy=\"$RZ_PROXY\" HTTP_PROXY=\"$RZ_PROXY\" http_proxy=\"$RZ_PROXY\"\n\
         export NODE_EXTRA_CA_CERTS={CAP_CA} SSL_CERT_FILE={CAP_CA} REQUESTS_CA_BUNDLE={CAP_CA} CURL_CA_BUNDLE={CAP_CA}\n\
         exec \"{real_bin}\" \"$@\"\n"
    )
}

/// The directories on the operator's *login* PATH, in order (root's PATH differs,
/// and agents live under the operator's home — so a shim in /usr/local/bin loses
/// to ~/.local/bin which comes first). Resolved via the operator's login shell.
fn operator_path_dirs() -> Vec<String> {
    let operator = std::env::var("SUDO_USER").ok();
    let path = match &operator {
        Some(user) => std::process::Command::new("runuser")
            .args(["-l", user, "-c", "printf %s \"$PATH\""])
            .output()
            .ok()
            .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| std::env::var("PATH").unwrap_or_default()),
        None => std::env::var("PATH").unwrap_or_default(),
    };
    path.split(':')
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
        .collect()
}

/// Is this file one of our own capture shims (so we don't shim a shim)?
fn is_our_shim(path: &std::path::Path) -> bool {
    std::fs::read_to_string(path)
        .map(|s| s.contains("Ring Zero Security capture"))
        .unwrap_or(false)
}

/// Discover every installed AI agent on the OPERATOR's PATH → (name, launcher
/// path). We scan the operator's login PATH in order and take the first hit per
/// name — that is exactly the binary the shell runs when the user types the
/// name, so installing the shim there guarantees it wins (a shim in
/// /usr/local/bin loses to ~/.local/bin, which comes first). Catches name
/// variants too (cursor-agent, gemini-cli).
fn discover_all_agents() -> Vec<(String, String)> {
    use std::collections::BTreeMap;
    let mut found: BTreeMap<String, String> = BTreeMap::new(); // name -> launcher path

    for dir in operator_path_dirs() {
        let entries = match std::fs::read_dir(&dir) {
            Ok(e) => e,
            Err(_) => continue,
        };
        for e in entries.flatten() {
            let fname = e.file_name().to_string_lossy().to_string();
            if fname.ends_with(".real") {
                continue;
            }
            let lower = fname.to_lowercase();
            if !known_agent_names().iter().any(|a| lower.contains(a)) {
                continue;
            }
            let path = e.path();
            // If this path is ALREADY our shim, re-shim THIS path (the launcher) so
            // a re-run updates the shim content; the real binary is preserved as
            // <name>.real. (Returning the .real here would wrongly shim the .real.)
            if is_our_shim(&path) {
                let real = format!("{}.real", path.display());
                if std::path::Path::new(&real).exists() {
                    found
                        .entry(fname)
                        .or_insert_with(|| path.to_string_lossy().to_string());
                }
                continue;
            }
            // First PATH dir wins (don't override a higher-priority entry).
            found
                .entry(fname)
                .or_insert_with(|| path.to_string_lossy().to_string());
        }
    }
    found.into_iter().collect()
}

/// Install the capture shim AT the launcher's own path (so it wins on PATH),
/// preserving the original launcher as `<launcher>.real`. Idempotent.
fn install_capture_shim(launcher: &str, shim_name: &str, rz_bin: &str) -> Result<String> {
    use std::os::unix::fs::PermissionsExt;
    let preserved = format!("{launcher}.real");
    // Preserve the real launcher once.
    if !std::path::Path::new(&preserved).exists() {
        std::fs::rename(launcher, &preserved)
            .with_context(|| format!("preserve launcher {launcher} -> {preserved}"))?;
    }
    let content = capture_shim_content(&preserved, shim_name, rz_bin);
    std::fs::write(launcher, content.as_bytes())
        .with_context(|| format!("write shim {launcher} (run as root?)"))?;
    std::fs::set_permissions(launcher, std::fs::Permissions::from_mode(0o755))
        .with_context(|| format!("chmod {launcher}"))?;
    Ok(launcher.to_string())
}

/// Discover and shim every installed AI agent in one step.
async fn cmd_setup_all() -> Result<()> {
    let rz_bin = std::env::current_exe().unwrap_or_else(|_| PathBuf::from("/usr/bin/rz"));
    let rz_bin_str = rz_bin.display().to_string();

    // Sandbox scaffold (deny marker + config) once.
    let _ = tokio::fs::write(deny_marker_path(), b"").await;
    let _ = tokio::fs::create_dir_all("/etc/ringzero").await;
    let deny_list: Vec<String> = DEFAULT_DENY_READ
        .iter()
        .map(|s| format!("  \"{s}\""))
        .collect();
    let cfg = format!(
        "# Ring Zero sandbox config\n# Generated by: rz setup --all\n\n[sandbox]\ndeny_read = [\n{}\n]\n",
        deny_list.join(",\n")
    );
    let _ = tokio::fs::write(sandbox_config_path(), cfg.as_bytes()).await;

    let mut installed = Vec::new();
    for (shim_name, real) in discover_all_agents() {
        match install_capture_shim(&real, &shim_name, &rz_bin_str) {
            Ok(shim) => installed.push((shim_name, real, shim)),
            Err(e) => eprintln!("  \x1b[33mskip\x1b[0m {shim_name}: {e}"),
        }
    }

    if installed.is_empty() {
        println!("No AI agents found to shim. Install an agent (claude, gemini, …) then re-run \x1b[36mrz setup --all\x1b[0m.");
        return Ok(());
    }
    println!(
        "\x1b[32mOK\x1b[0m Capture shims installed for {} agent(s):",
        installed.len()
    );
    for (name, real, shim) in &installed {
        println!("  \x1b[36m{name:10}\x1b[0m {shim}  ->  {real}");
    }
    println!();
    println!("Run any of them normally (e.g. \x1b[36mclaude\x1b[0m, \x1b[36mgemini\x1b[0m) — prompts + responses are now captured.");
    println!("The original binaries are preserved as <name>.real; re-run to pick up new agents.");
    Ok(())
}

// ── Sandbox runner handler ─────────────────────────────────────────────────────

fn cmd_sandbox(cmd: Vec<String>) -> Result<()> {
    if cmd.is_empty() {
        anyhow::bail!("Usage: rz sandbox -- <binary> [args...]");
    }

    let real_binary = &cmd[0];
    let args = &cmd[1..];

    // Load deny list from config, fall back to defaults
    let deny_read: Vec<String> = load_sandbox_deny_read();

    eprintln!("[ringzero] sandbox active — {real_binary}");
    if !deny_read.is_empty() {
        eprintln!("[ringzero] deny_read: {} path(s)", deny_read.len());
    }

    run_sandboxed(real_binary, args, &deny_read)
}

fn load_sandbox_deny_read() -> Vec<String> {
    let cfg_path = sandbox_config_path();
    // Simple TOML-free parser: find lines inside deny_read = [ ... ]
    if let Ok(content) = std::fs::read_to_string(&cfg_path) {
        let mut in_list = false;
        let mut items = Vec::new();
        for line in content.lines() {
            let trimmed = line.trim();
            if trimmed.starts_with("deny_read") && trimmed.contains('[') {
                in_list = true;
                continue;
            }
            if in_list {
                if trimmed == "]" {
                    break;
                }
                // Extract quoted string
                if let Some(start) = trimmed.find('"') {
                    if let Some(end) = trimmed[start + 1..].find('"') {
                        items.push(trimmed[start + 1..start + 1 + end].to_string());
                    }
                }
            }
        }
        if !items.is_empty() {
            return items;
        }
    }
    DEFAULT_DENY_READ.iter().map(|s| s.to_string()).collect()
}

// ── Entry point ───────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let sock = cli.socket.unwrap_or_else(default_sock);
    let api = cli.api.unwrap_or_else(default_api);

    match cli.command {
        Commands::Status => cmd_status(&sock, &api).await,

        Commands::Events { limit, follow } => cmd_events(&sock, limit, follow).await,

        Commands::Policy { action } => match action {
            PolicyCommands::Show => cmd_policy_show(&api).await,
            PolicyCommands::BlockDomain { domain } => {
                cmd_policy_block_domain(&sock, &api, &domain).await
            }
            PolicyCommands::SetMode { mode } => {
                println!("set-mode {mode} — use: POST {api}/api/v1/policy");
                Ok(())
            }
        },

        Commands::Threats => cmd_threats(&api).await,
        Commands::Diffs => cmd_diffs(&api).await,

        Commands::Sessions { action } => match action {
            SessionCommands::List { filter } => cmd_sessions_list(&api, &filter).await,
            SessionCommands::Create { actor, agent_type } => {
                cmd_sessions_create(&api, &actor, &agent_type).await
            }
            SessionCommands::Get { id } => cmd_sessions_get(&api, &id).await,
            SessionCommands::Terminate { id } => cmd_sessions_terminate(&api, &id).await,
            SessionCommands::Approve { id } => cmd_sessions_approve(&api, &id).await,
        },

        Commands::Escalations { action } => match action {
            EscalationCommands::List => cmd_escalations_list(&api).await,
            EscalationCommands::Approve { id, reviewer } => {
                cmd_escalations_resolve(&api, &id, true, &reviewer).await
            }
            EscalationCommands::Deny { id, reviewer } => {
                cmd_escalations_resolve(&api, &id, false, &reviewer).await
            }
        },

        Commands::Audit { action } => match action {
            AuditCommands::Recent { limit } => cmd_audit_recent(&api, limit).await,
            AuditCommands::Verify => cmd_audit_verify(&api).await,
            AuditCommands::Export { output } => cmd_audit_export(&api, &output).await,
        },

        Commands::Network { action } => match action {
            NetworkCommands::Show => cmd_network_show(&api).await,
            NetworkCommands::SetMode { mode } => cmd_network_set(&api, Some(&mode), None).await,
            NetworkCommands::SetEnforce { mode } => cmd_network_set(&api, None, Some(&mode)).await,
        },

        Commands::Checks { action } => match action {
            ChecksCommands::Status => cmd_checks_status(&api).await,
            ChecksCommands::SetKey { enable } => cmd_checks_set_key(enable).await,
            ChecksCommands::Test => cmd_checks_test(&api).await,
        },

        Commands::Review { action } => match action {
            ReviewCommands::List { limit, all } => cmd_review_list(&api, limit, all).await,
            ReviewCommands::Show { id } => cmd_review_show(&api, &id).await,
            ReviewCommands::Label { id, label } => cmd_review_label(&api, &id, &label).await,
            ReviewCommands::Stats => cmd_review_stats(&api).await,
        },

        Commands::Enforcement { action } => match action {
            EnforcementCommands::Show => cmd_enforcement_show(&api).await,
            EnforcementCommands::SetDefault { action: a } => {
                cmd_enforcement_set(&api, None, &a).await
            }
            EnforcementCommands::SetCategory {
                category,
                action: a,
            } => cmd_enforcement_set(&api, Some(&category), &a).await,
        },

        Commands::FileAccess { action } => match action {
            FileAccessCommands::Show => cmd_file_access_show(&api).await,
            FileAccessCommands::Add {
                pattern,
                action: a,
                description,
                dir,
                file,
            } => {
                let kind = if dir {
                    Some("dir")
                } else if file {
                    Some("file")
                } else {
                    None
                };
                cmd_file_access_add(&api, &pattern, &a, description.as_deref(), kind).await
            }
            FileAccessCommands::Remove { id, all } => cmd_file_access_remove(&api, &id, all).await,
        },

        Commands::Nhi => cmd_nhi(&api).await,
        Commands::ShadowAi => cmd_shadow_ai(&api).await,

        Commands::Scan { action } => match action {
            ScanCommands::Skills { all } => cmd_scan_skills(&api, all).await,
            ScanCommands::Baseline { action } => match action {
                BaselineCommands::Show => cmd_baseline_show(&api).await,
                BaselineCommands::Accept => cmd_baseline_accept(&api).await,
                BaselineCommands::Clear => cmd_baseline_clear(&api).await,
            },
        },
        Commands::SessionEvents { id } => cmd_session_events(&api, &id).await,

        Commands::Setup { binary, name, all } => cmd_setup(binary, name, all).await,

        Commands::Sandbox { cmd } => {
            // Sandbox runs synchronously (exec replaces process)
            cmd_sandbox(cmd)
        }

        Commands::Run { command } => cmd_run(command),
    }
}

/// `rz run <agent...>` — launch an AI agent with prompt capture enabled.
///
/// Sets HTTPS_PROXY to the daemon's local inspection proxy and trusts Ring Zero's
/// CA across the common TLS stacks (Node/Bun via NODE_EXTRA_CA_CERTS, OpenSSL via
/// SSL_CERT_FILE, curl/requests via their bundles), then execs the agent so its
/// HTTPS traffic is MITM-inspected and prompts are captured — even when the agent
/// statically links its own TLS (Claude Code/Bun, Gemini CLI/Node). We do NOT set
/// NODE_TLS_REJECT_UNAUTHORIZED=0: the agent validates against our CA, which is
/// the whole point (no blanket TLS bypass).
fn cmd_run(command: Vec<String>) -> Result<()> {
    use std::os::unix::process::CommandExt;

    // Encode our PID (which becomes the exec'd agent's pid) in the proxy URL
    // userinfo so the proxy attributes capture to the right session (sent as
    // Proxy-Authorization on CONNECT).
    let proxy = format!("http://rzpid-{}:rz@127.0.0.1:7710", std::process::id());
    let proxy = proxy.as_str();
    // CA cert path: daemon (root) writes it here; falls back to the user config dir.
    let user_ca = std::env::var("HOME")
        .map(|h| std::path::PathBuf::from(h).join(".config/ringzero/spiffe-ca/spiffe-ca.pem"))
        .unwrap_or_else(|_| std::path::PathBuf::from("/tmp/ringzero/spiffe-ca/spiffe-ca.pem"));
    let ca_candidates = [
        std::path::PathBuf::from("/var/lib/ringzero/spiffe-ca/spiffe-ca.pem"),
        user_ca,
    ];
    let ca_path = ca_candidates.iter().find(|p| p.exists()).cloned();
    let ca = match &ca_path {
        Some(p) => p.to_string_lossy().to_string(),
        None => {
            eprintln!("rz run: Ring Zero CA not found (is the daemon running?). Looked in:");
            for p in &ca_candidates {
                eprintln!("  {}", p.display());
            }
            std::process::exit(1);
        }
    };

    let (prog, args) = command.split_first().expect("clap requires >=1 arg");
    println!(
        "rz run: launching '{prog}' with Ring Zero prompt capture (proxy 127.0.0.1:7710, CA {ca})"
    );

    let err = std::process::Command::new(prog)
        .args(args)
        .env("HTTPS_PROXY", proxy)
        .env("https_proxy", proxy)
        .env("HTTP_PROXY", proxy)
        .env("http_proxy", proxy)
        .env("NODE_EXTRA_CA_CERTS", &ca) // Node + Bun
        .env("SSL_CERT_FILE", &ca) // OpenSSL-based
        .env("REQUESTS_CA_BUNDLE", &ca) // python requests
        .env("CURL_CA_BUNDLE", &ca) // curl
        .exec(); // replaces this process on success
    Err(anyhow::anyhow!("failed to exec '{prog}': {err}"))
}

#[cfg(test)]
mod local_config_tests {
    use super::*;

    /// The CLI reads a slice of the daemon's config with its own structs. If
    /// the shipped config renames or moves one of those keys, this fails
    /// rather than the CLI silently reporting a default.
    #[test]
    fn the_packaged_daemon_toml_parses() {
        let text = include_str!("../../packaging/daemon.toml");
        let parsed: LocalConfigFile = toml::from_str(text).expect("packaged config must parse");
        let c = parsed.checks;
        assert!(
            c.jev.api_key_file.starts_with('/'),
            "api_key_file should be absolute, got {:?}",
            c.jev.api_key_file
        );
        assert!(
            c.jev.base_url.starts_with("https://"),
            "base_url should be https, got {:?}",
            c.jev.base_url
        );
        assert!(c.jev.timeout_ms > 0, "timeout_ms must be set");
        assert!(!c.jev.model.is_empty(), "model must be set");
    }

    /// Defaults must match the daemon's, since they are what the CLI reports
    /// when the config file is not there.
    #[test]
    fn defaults_match_the_daemon() {
        let c = LocalChecks::default();
        assert!(!c.enabled);
        assert_eq!(c.provider, "jev");
        assert!(!c.blocking);
        assert_eq!(c.fail_mode, None);
        assert_eq!(c.jev.api_key_file, "/etc/ringzero/typesafe.key");
        assert_eq!(c.jev.model, "jev-latest");
        assert_eq!(c.jev.base_url, "https://api.typesafe.ai");
        assert_eq!(c.jev.timeout_ms, 1500);
        assert_eq!(c.jev.endpoint(), "https://api.typesafe.ai/v1/systemone");
    }

    /// The root-only token is searched only when we could actually read it, is
    /// never the file a self-registered token is written to, and an explicit
    /// override is honoured for both reading and caching.
    ///
    /// One test, not two: both halves touch the same process-wide environment
    /// variable, and tests in a binary run in parallel.
    #[test]
    fn the_token_search_order_holds() {
        std::env::remove_var("RZ_API_TOKEN_FILE");
        let cands = token_candidates();
        let has_root = cands.iter().any(|p| p.as_os_str() == ROOT_TOKEN_PATH);
        assert_eq!(
            has_root,
            effectively_root(),
            "the root-only path belongs in the search exactly when we are root"
        );
        if has_root {
            assert_eq!(
                cands.last().unwrap().as_os_str(),
                ROOT_TOKEN_PATH,
                "the root-only path is tried last, after the home path"
            );
        }
        assert_ne!(
            token_cache_path().as_os_str(),
            ROOT_TOKEN_PATH,
            "the CLI must never overwrite the daemon's token"
        );

        std::env::set_var("RZ_API_TOKEN_FILE", "/tmp/rz-test-token");
        assert_eq!(
            token_candidates().first().unwrap().as_os_str(),
            "/tmp/rz-test-token"
        );
        assert_eq!(token_cache_path().as_os_str(), "/tmp/rz-test-token");
        std::env::remove_var("RZ_API_TOKEN_FILE");
    }
}
