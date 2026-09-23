// SPDX-License-Identifier: Apache-2.0
// Ring Zero — Linux eBPF loader (merged into daemon)
//
// Runs as a tokio task inside ringzero-daemon when on Linux.
// Loads ringzero.bpf.o, attaches LSM/tracepoint/cgroup hooks,
// and forwards raw kernel events directly via an mpsc channel
// — no socket, no separate process.
//
// Only compiled on Linux.

use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, Result};
use aya::{
    maps::{Array, HashMap as AyaHashMap, Map, MapData, PerCpuArray, RingBuf},
    programs::{Lsm, TracePoint},
    Bpf, BpfLoader, Btf,
};
use tokio::sync::mpsc;
use tracing::{info, warn};

use crate::common::protocol::DriverMessage;
use crate::config::PiiAction;
use crate::secrets::dlp::DlpEngine;
use std::sync::Arc;

// ── BPF map struct definitions (must match ringzero.bpf.c) ───────────────────

const MAX_PATH_LEN: usize = 128;
const MAX_COMM_LEN: usize = 16;
const MAX_SEND_DATA: usize = 4096;
const MAX_ARGS_LEN: usize = 256;

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct Config {
    enabled: u8,
    monitor_all: u8,
    enforce_blocks: u8,
    dlp_enabled: u8,
    /// Refuse to open or exec a file an agent wrote that a deterministic scan
    /// flagged. Separate from `enforce_blocks` and OFF by default: it is newer,
    /// it is sharper, and an operator must be able to run every other kind of
    /// enforcement without it. Mirrors `quarantine_enforce` in
    /// GPL/bpf/ringzero.bpf.c; the struct size is unchanged.
    quarantine_enforce: u8,
    /// Egress narrowing on taint: socket_connect refuses a tainted process
    /// connecting off the egress allowlist. Mirrors `egress_enforce` in the
    /// C config; struct size unchanged.
    egress_enforce: u8,
    /// Raise taint when an agent-tree process connects off the allowlist. This
    /// is the primary provenance signal for external ingestion: a real agent
    /// reaches the network through whatever is to hand, and all of it goes
    /// through `connect(2)`, so the kernel sees what a transcript tool name
    /// does not. Separate from `egress_enforce` so an operator can measure how
    /// often a normal session taints before enforcing on it. Mirrors
    /// `taint_on_egress` in the C config; struct size unchanged.
    taint_on_egress: u8,
    _reserved: [u8; 1],
}

/// Mirrors `struct write_verdict` in GPL/bpf/ringzero.bpf.c.
///
/// `enforce` is the only field the kernel acts on, and only a deterministic
/// pattern match may set it. `review` and `severity` are for humans.
#[repr(C)]
#[derive(Clone, Copy, Default, Debug, PartialEq, Eq)]
pub struct WriteVerdict {
    pub enforce: u8,
    pub review: u8,
    pub severity: u8,
    pub _pad: u8,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct TaintInfo {
    tainted: u8,
    has_keys: u8,
    _pad: u16,
    taint_time: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct ProxyConfig {
    proxy_ip4: u32,
    proxy_port: u16,
    enabled: u8,
    _pad: u8,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct BlockKey {
    pid: u32,
    ip: u32,
}

/// Identity key for `blocked_inodes` — must match `struct ino_key` in
/// ringzero.bpf.c exactly. `dev` is the KERNEL-encoded device (MKDEV:
/// (major<<20)|minor), which differs from the glibc st_dev encoding userspace
/// stat returns — `resolve_inode_key` does the conversion.
#[repr(C)]
#[derive(Clone, Copy, Default, PartialEq, Eq, Hash, Debug)]
struct InoKey {
    ino: u64,
    dev: u32,
    _pad: u32,
}

unsafe impl aya::Pod for Config {}
unsafe impl aya::Pod for TaintInfo {}
unsafe impl aya::Pod for ProxyConfig {}
unsafe impl aya::Pod for BlockKey {}
unsafe impl aya::Pod for InoKey {}
/// Mirrors `struct write_origin` in GPL/bpf/ringzero.bpf.c.
#[repr(C)]
#[derive(Clone, Copy, Default, Debug)]
pub struct WriteOrigin {
    /// The process that opened the file: often a helper such as `cp`.
    pub pid: u32,
    /// The agent the write belongs to.
    pub agent_pid: u32,
    pub opened_ns: u64,
    pub comm: [u8; 16],
    pub agent_comm: [u8; 16],
}

unsafe impl aya::Pod for WriteVerdict {}
unsafe impl aya::Pod for WriteOrigin {}

/// The kernel's (dev, ino) key for a file that exists on disk.
///
/// THE ENCODING TRAP. glibc's `st_dev` packs major and minor differently from
/// the kernel's `s_dev`, which is `(major << 20) | minor`. Get this wrong and
/// the `dev` half never matches, the lookup silently returns nothing, and the
/// feature looks like it is running and finding nothing. One conversion, shared
/// with `resolve_inode_key`, so there is no second copy to drift.
pub fn kernel_ino_key(dev: u64, ino: u64) -> (u32, u64) {
    // SAFETY: libc major/minor are pure bit-twiddles on the value.
    let major = unsafe { libc::major(dev) } as u32;
    let minor = unsafe { libc::minor(dev) } as u32;
    ((major << 20) | (minor & 0xf_ffff), ino)
}

/// Who opened this file for writing, if the kernel recorded it.
///
/// Reads the snapshot the loader refreshes, for the same reason
/// `AGENT_DESCENDANTS` exists: the answer has to be available after the writing
/// process has gone.
/// Who opened a file for writing, and which agent it was for.
#[derive(Debug, Clone)]
pub struct WriteAttribution {
    /// The agent the write belongs to. This is what a person reads.
    pub agent_pid: u32,
    pub agent_comm: String,
    /// The process that actually performed it: `cp`, `tee`, the agent itself.
    pub writer_pid: u32,
    pub writer_comm: String,
}

pub static WRITE_ORIGINS: once_cell::sync::Lazy<
    std::sync::RwLock<std::collections::HashMap<(u32, u64), WriteAttribution>>,
> = once_cell::sync::Lazy::new(|| std::sync::RwLock::new(std::collections::HashMap::new()));

/// The agent name last seen for a pid, so an exec cannot erase it.
///
/// A shell running a single command execs over itself: `claude -c "cp a b"`
/// becomes a process named `cp` with the SAME pid. The kernel's root walk then
/// finds only `cp`, because nothing in the ancestry is named like an agent any
/// more, and attribution silently degrades to naming a coreutil. A finding that
/// says `cp` tells a reviewer nothing.
///
/// The pid is unchanged across exec, so what the process was called when it was
/// still the agent is the right answer. This remembers it.
pub static AGENT_NAME_BY_PID: once_cell::sync::Lazy<
    std::sync::RwLock<std::collections::HashMap<u32, String>>,
> = once_cell::sync::Lazy::new(|| std::sync::RwLock::new(std::collections::HashMap::new()));

/// Record that this pid was, at some point, a named agent.
pub fn remember_agent_name(pid: u32, name: &str) {
    if !crate::common::agent_detect::is_ai_agent(name) {
        return;
    }
    if let Ok(mut m) = AGENT_NAME_BY_PID.write() {
        if m.len() > 8192 {
            m.clear();
        }
        m.insert(pid, name.to_string());
    }
}

/// What this pid was called when it was still an agent, if we ever saw it.
pub fn agent_name_for_pid(pid: u32) -> Option<String> {
    AGENT_NAME_BY_PID.read().ok()?.get(&pid).cloned()
}

/// Look up and consume an attribution for a file.
///
/// Consuming it keeps the userspace copy from growing and means a second write
/// to the same path is attributed by its own open, not by a stale one.
pub fn take_write_origin(st_dev: u64, ino: u64) -> Option<WriteAttribution> {
    let key = kernel_ino_key(st_dev, ino);
    WRITE_ORIGINS.write().ok()?.remove(&key)
}

/// A snapshot of the kernel's `agent_descendants` set, refreshed periodically.
///
/// WHY THIS EXISTS. Attributing a finished write to an agent has to work for a
/// process that has already exited — `cat > file` lives for a few milliseconds
/// and is gone before the close-write event is read, so `/proc` cannot answer
/// and fanotify hands back FAN_NOPIDFD. The kernel tags every agent descendant
/// at fork and keeps the entry, so it can still answer. This is a read-only
/// copy so the answer costs a lock and not a map round trip.
pub static AGENT_DESCENDANTS: once_cell::sync::Lazy<
    std::sync::RwLock<std::collections::HashSet<u32>>,
> = once_cell::sync::Lazy::new(|| std::sync::RwLock::new(std::collections::HashSet::new()));

/// Was this pid an agent, or a descendant of one, when the kernel last looked?
pub fn was_agent_pid(pid: u32) -> bool {
    AGENT_DESCENDANTS
        .read()
        .map(|s| s.contains(&pid))
        .unwrap_or(false)
}

// ── Kernel event layout (matches ringzero.bpf.c) ─────────────────────────────

#[repr(C)]
#[derive(Clone, Copy)]
struct KernelEvent {
    event_type: u32,
    pid: u32,
    ppid: u32,
    uid: u32,
    timestamp: u64,
    comm: [u8; MAX_COMM_LEN],
    path: [u8; MAX_PATH_LEN],
    parent_comm: [u8; MAX_COMM_LEN],
    remote_ip: u32,
    remote_port: u16,
    local_port: u16,
    protocol: u8,
    blocked: u8,
    args: [u8; MAX_ARGS_LEN],
}

#[repr(C)]
#[derive(Clone, Copy)]
struct SendEvent {
    event_type: u32,
    pid: u32,
    uid: u32,
    remote_ip: u32,
    remote_port: u16,
    data_len: u16,
    total_len: u32,
    blocked: u8,
    _pad: [u8; 3],
    comm: [u8; MAX_COMM_LEN],
    data: [u8; MAX_SEND_DATA],
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn cstr(bytes: &[u8]) -> String {
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..end]).to_string()
}

fn ip_to_str(ip_net: u32) -> String {
    Ipv4Addr::from(u32::from_be(ip_net)).to_string()
}

fn parse_ip(s: &str) -> Option<u32> {
    s.parse::<Ipv4Addr>().ok().map(|ip| {
        let o = ip.octets();
        u32::from_be_bytes(o)
    })
}

/// Map raw kernel comm names to user-friendly agent display names.
/// Processes like MainThread, agent, node etc. are confusing in the UI —
/// show the actual agent product name instead.
pub(crate) fn agent_display_name(comm: &str, parent_comm: &[u8]) -> String {
    match comm {
        "MainThread" => {
            // Could be Codex (Python) or Cursor (node). Check parent_comm hint.
            let pc = cstr(parent_comm);
            if pc.contains("codex") || pc == "MainThread" {
                "Codex".into()
            } else if pc.contains("cursor") || pc == "agent" {
                "Cursor".into()
            } else {
                "Codex".into()
            }
        }
        "agent" => "Cursor".into(),
        c if c.starts_with("claude") => "Claude Code".into(),
        c if c.starts_with("cursor") => "Cursor".into(),
        c if c.starts_with("codex") => "Codex".into(),
        c if c.starts_with("copilot") => "Copilot".into(),
        "devin" => "Devin".into(),
        "aider" => "Aider".into(),
        c if c.starts_with("winds") => "Windsurf".into(),
        "agy" | "antigravity" => "Gemini CLI".into(),
        c if c.starts_with("gemini") => "Gemini CLI".into(),
        c if c.starts_with("opencode") => "OpenCode".into(),
        c if c.contains("claw") => format!("{} (claw agent)", c),
        // Child processes (cat, bash, node, etc.) — keep raw name, the session
        // view already shows which agent owns this process tree.
        _ => comm.into(),
    }
}

fn kernel_event_to_driver_msg(e: &KernelEvent) -> DriverMessage {
    let raw_comm = cstr(&e.comm);
    let comm = agent_display_name(&raw_comm, &e.parent_comm);
    let path = cstr(&e.path);

    // Extract args for exec events (event_type 10)
    let args = if e.event_type == 10 {
        let a = cstr(&e.args);
        if a.is_empty() {
            None
        } else {
            Some(a)
        }
    } else {
        None
    };

    // mprotect W→X event — include path info (contains "mprotect:W->X")
    if e.event_type == 25 {
        return DriverMessage::Event {
            event_type: e.event_type,
            pid: e.pid,
            uid: e.uid,
            comm,
            path: Some(path),
            remote_ip: None,
            remote_port: None,
            blocked: e.blocked as u32,
            args: None,
        };
    }

    if e.event_type == 20 {
        DriverMessage::Event {
            event_type: e.event_type,
            pid: e.pid,
            uid: e.uid,
            comm,
            path: Some(path),
            remote_ip: Some(ip_to_str(e.remote_ip)),
            remote_port: Some(e.remote_port),
            blocked: e.blocked as u32,
            args: None,
        }
    } else {
        DriverMessage::Event {
            event_type: e.event_type,
            pid: e.pid,
            uid: e.uid,
            comm,
            path: Some(path),
            remote_ip: None,
            remote_port: None,
            blocked: e.blocked as u32,
            args,
        }
    }
}

fn send_event_to_driver_msg(se: &SendEvent) -> DriverMessage {
    DriverMessage::Event {
        event_type: 30,
        pid: se.pid,
        uid: se.uid,
        comm: cstr(&se.comm),
        path: None,
        args: None,
        remote_ip: Some(ip_to_str(se.remote_ip)),
        remote_port: Some(se.remote_port),
        blocked: 0,
    }
}

// ── Default sensitive file blocks ─────────────────────────────────────────────

/// The kernel `blocked_files` map is keyed by **basename**: `ringzero_file_open`
/// looks up `d_name.name` (the final path component), never the full path. So a
/// full-path key like "/etc/shadow" silently never matches and the block is a
/// no-op — every userspace insert MUST reduce to the basename first. (This is the
/// bug that made SLM-compiled BlockFile rules, which carry full paths, do
/// nothing.) Note the match is agent-scoped: the file_open hook only fires for
/// AI-agent processes and their cat/head/tail/ssh children, so blocking a
/// basename affects those, not the whole host.
fn blocked_file_key(name: &str) -> &str {
    let trimmed = name.trim_end_matches('/');
    trimmed.rsplit('/').next().unwrap_or(trimmed)
}

/// Write a basename into a fixed 128-byte map key (NUL-padded), as the kernel
/// expects. Truncates over-long names defensively.
fn make_file_key(name: &str) -> [u8; MAX_PATH_LEN] {
    let base = blocked_file_key(name);
    let mut key = [0u8; MAX_PATH_LEN];
    let b = base.as_bytes();
    let n = b.len().min(MAX_PATH_LEN - 1);
    key[..n].copy_from_slice(&b[..n]);
    key
}

/// The unconditional L0 block set: basenames an AI agent should NEVER open.
/// Single source of truth for the deterministic "always-block" layer — each
/// entry mapped to its MITRE technique so coverage is auditable. Enforcement is agent-scoped and
/// basename-keyed (see `blocked_file_key`); these are things never legitimate
/// for a monitored agent to read or write, so a blanket open-block is correct.
const UNCONDITIONAL_BLOCK_FILES: &[(&str, &str)] = &[
    // ── Credential access (T1552 Unsecured Credentials) ──
    ("id_rsa", "T1552.004"),
    ("id_ed25519", "T1552.004"),
    ("id_ecdsa", "T1552.004"),
    ("id_dsa", "T1552.004"),
    ("credentials", "T1552.001"),
    (".env", "T1552.001"),
    // ── Persistence / code injection (never legitimate for an agent) ──
    ("ld.so.preload", "T1574.006"), // preload hijack — inject a .so into every process
    ("authorized_keys", "T1098.004"), // SSH authorized_keys — remote-access persistence
];

/// Resolve a concrete filesystem path to the kernel-space `(dev, ino)` identity
/// the eBPF `blocked_inodes` map is keyed on. Returns None if the path doesn't
/// exist (nothing to pin) or isn't a regular file.
///
/// The encoding gotcha: glibc's `st_dev` (what `metadata().dev()` returns) packs
/// major/minor differently than the kernel's `s_dev`. The kernel stores
/// `s_dev = MKDEV(major, minor) = (major << 20) | minor`. So we extract the
/// canonical major/minor via libc and re-encode to the kernel form. Without this
/// the `dev` half never matches and the inode block silently no-ops.
fn resolve_inode_key(path: &std::path::Path) -> Option<InoKey> {
    use std::os::unix::fs::MetadataExt;
    // Never follow symlinks: the default seeding walks every user's home, and a
    // user-planted `~/.ssh/id_rsa -> /some/other/file` symlink would otherwise
    // make the root daemon pin an arbitrary inode into the kernel block map
    // (denying every monitored agent process access to that file).
    let md = std::fs::symlink_metadata(path).ok()?;
    if !md.is_file() {
        return None;
    }
    let st_dev = md.dev();
    // SAFETY: libc major/minor are pure bit-twiddles on the value.
    let major = unsafe { libc::major(st_dev) } as u32;
    let minor = unsafe { libc::minor(st_dev) } as u32;
    let kdev = (major << 20) | (minor & 0xf_ffff);
    Some(InoKey {
        ino: md.ino(),
        dev: kdev,
        _pad: 0,
    })
}

/// Insert one resolved file identity into `blocked_inodes`. Best-effort: a
/// missing file or absent map is a no-op (we still have the basename block).
fn block_inode_path(bpf: &mut Bpf, path: &std::path::Path) -> bool {
    let Some(key) = resolve_inode_key(path) else {
        return false;
    };
    if let Some(m) = bpf.map_mut("blocked_inodes") {
        if let Ok(mut map) = AyaHashMap::<_, InoKey, u8>::try_from(m) {
            if map.insert(key, 1u8, 0).is_ok() {
                info!(
                    "eBPF: blocked inode dev={} ino={} ({}) — rename/hardlink-proof",
                    key.dev,
                    key.ino,
                    path.display()
                );
                return true;
            }
        }
    }
    false
}

/// Seed `blocked_inodes` from the concrete credential files that actually exist
/// on this host, so the rename/hardlink bypass is closed for the real secrets
/// (not just for files that happen to keep the sensitive basename). Scans the
/// standard SSH/credential locations across every home plus root.
fn block_default_inodes(bpf: &mut Bpf) {
    // The credential filenames worth pinning by identity (a copy/hardlink of one
    // of these is still the same secret). Persistence files (ld.so.preload,
    // authorized_keys) are basename-blocked for *write*, not identity-read, so
    // they're intentionally not here.
    const CRED_NAMES: &[&str] = &[
        "id_rsa",
        "id_ed25519",
        "id_ecdsa",
        "id_dsa",
        "credentials",
        ".env",
    ];

    let mut home_dirs: Vec<PathBuf> = vec![PathBuf::from("/root")];
    if let Ok(entries) = std::fs::read_dir("/home") {
        for e in entries.flatten() {
            if e.path().is_dir() {
                home_dirs.push(e.path());
            }
        }
    }

    let mut pinned = 0usize;
    for home in &home_dirs {
        for name in CRED_NAMES {
            // SSH keys live under ~/.ssh; .env/credentials at the home root.
            for candidate in [home.join(".ssh").join(name), home.join(name)] {
                if block_inode_path(bpf, &candidate) {
                    pinned += 1;
                }
            }
        }
    }
    info!(
        "Seeded {} credential-file inode blocks across {} home(s) (rename/hardlink-proof)",
        pinned,
        home_dirs.len()
    );
}

fn block_default_files(bpf: &mut Bpf) {
    if let Some(m) = bpf.map_mut("blocked_files") {
        if let Ok(mut map) = AyaHashMap::<_, [u8; MAX_PATH_LEN], u8>::try_from(m) {
            for (name, _mitre) in UNCONDITIONAL_BLOCK_FILES {
                let _ = map.insert(make_file_key(name), 1u8, 0);
            }
            info!(
                "Seeded {} unconditional file blocks (credential access + persistence/injection)",
                UNCONDITIONAL_BLOCK_FILES.len()
            );
        }
    }
}

/// Load user-configured file access rules from /etc/ringzero/file-access-rules.json
/// and push "block" entries into the eBPF blocked_files map at startup.
/// Expand `~` in a path to the first real user's home directory.
/// The daemon runs as root, so $HOME=/root — but user file-access rules
/// refer to operator home directories. We scan /home/* for the first match.
fn expand_tilde(path: &str) -> String {
    if !path.starts_with('~') {
        return path.to_string();
    }
    // Try /home/* entries first (the user who configured rules)
    if let Ok(entries) = std::fs::read_dir("/home") {
        for entry in entries.flatten() {
            if entry.path().is_dir() {
                let candidate = path.replacen("~", &entry.path().to_string_lossy(), 1);
                if std::path::Path::new(&candidate).exists() {
                    return candidate;
                }
            }
        }
    }
    // Fallback: try /root
    let fallback = path.replacen("~", "/root", 1);
    if std::path::Path::new(&fallback).exists() {
        return fallback;
    }
    // Last resort: first /home/* regardless of existence
    if let Ok(entries) = std::fs::read_dir("/home") {
        for entry in entries.flatten() {
            if entry.path().is_dir() {
                return path.replacen("~", &entry.path().to_string_lossy(), 1);
            }
        }
    }
    path.replacen("~", "/root", 1)
}

fn load_file_access_rules(bpf: &mut Bpf) {
    let path = "/etc/ringzero/file-access-rules.json";
    let data = match std::fs::read_to_string(path) {
        Ok(d) => d,
        Err(_) => return, // no rules file — nothing to load
    };
    let rules: Vec<serde_json::Value> = match serde_json::from_str(&data) {
        Ok(r) => r,
        Err(e) => {
            warn!("Failed to parse file access rules: {}", e);
            return;
        }
    };

    // ── Basename blocks ──────────────────────────────────────────────────
    let map = match bpf.map_mut("blocked_files") {
        Some(m) => m,
        None => return,
    };
    let mut map = match AyaHashMap::<_, [u8; MAX_PATH_LEN], u8>::try_from(map) {
        Ok(m) => m,
        Err(_) => return,
    };

    let mut count = 0usize;
    for rule in &rules {
        if rule["action"].as_str() != Some("block") {
            continue;
        }
        let pattern = match rule["pattern"].as_str() {
            Some(p) => p,
            None => continue,
        };
        let basenames = crate::api::routes::pattern_to_basenames(pattern);
        for name in &basenames {
            let _ = map.insert(make_file_key(name), 1u8, 0);
            count += 1;
        }
    }
    if count > 0 {
        info!("Loaded {} file access block rules from {}", count, path);
    }
    drop(map);

    // Concrete absolute-path rules also pin the file identity (dev, ino), so a
    // hardlink or rename under another basename cannot dodge the block.
    for rule in &rules {
        if rule["action"].as_str() != Some("block") {
            continue;
        }
        let Some(pattern) = rule["pattern"].as_str() else {
            continue;
        };
        let expanded = expand_tilde(pattern.trim());
        if expanded.starts_with('/') && !expanded.contains(['*', '?', '[']) {
            block_inode_path(bpf, std::path::Path::new(&expanded));
        }
    }

    // ── Blocked directory rules ──────────────────────────────────────────
    // Decided by the rule's `kind` field. This used to key off the literal
    // string "[dir-block]" appearing in the human-readable description, which
    // meant a rule enforced or did not depending on a note someone typed, and
    // any save path that dropped the note disarmed it silently. The old marker
    // is still READ, for one release, so an install written before the field
    // existed keeps enforcing what it always did.
    let mut legacy_marker_seen = false;
    let blocked_dirs: Vec<String> = rules
        .iter()
        .filter(|r| {
            if r["action"].as_str() != Some("block") {
                return false;
            }
            let mut legacy = false;
            let kind = crate::policy::file_rule::infer_kind(
                r["pattern"].as_str().unwrap_or(""),
                r["kind"].as_str(),
                r["description"].as_str(),
                &mut legacy,
            );
            legacy_marker_seen |= legacy;
            kind == crate::policy::file_rule::Kind::Dir
        })
        .filter_map(|r| {
            r["pattern"]
                .as_str()
                .map(crate::policy::file_rule::dir_target)
        })
        .collect();

    if legacy_marker_seen {
        warn!(
            "file-access rules: a rule still uses the legacy \"[dir-block]\" description marker \
             to mean a directory. Re-save it (or run `rz file-access add ... --dir`) so it \
             carries kind = \"dir\"; support for the marker will be removed."
        );
    }

    if !blocked_dirs.is_empty() {
        if let Some(m) = bpf.map_mut("blocked_dir_inodes") {
            if let Ok(mut dir_map) = AyaHashMap::<_, InoKey, u8>::try_from(m) {
                let sentinel = InoKey {
                    ino: 0,
                    dev: 0,
                    _pad: 0,
                };
                let _ = dir_map.insert(sentinel, 1u8, 0);
                for dir_path in &blocked_dirs {
                    let p = std::path::PathBuf::from(dir_path);
                    if let Some(key) = resolve_dir_inode_key(&p) {
                        let _ = dir_map.insert(key, 1u8, 0);
                        info!(
                            "Loaded blocked directory: {} (dev={}, ino={})",
                            dir_path, key.dev, key.ino
                        );
                    } else {
                        warn!("Cannot resolve blocked directory inode: {}", dir_path);
                    }
                }
            }
        }
    }

    // ── Allowed directory rules (Project Directory Only) ─────────────────
    let allowed_dirs: Vec<String> = rules
        .iter()
        .filter(|r| {
            r["action"].as_str() == Some("allow") && !r["pattern"].as_str().unwrap_or("").is_empty()
        })
        .filter_map(|r| {
            r["pattern"]
                .as_str()
                .map(|s| expand_tilde(s.trim_end_matches("/*").trim_end_matches('/')))
        })
        .filter(|s| s != "/**" && s != "/*" && s != "*")
        .collect();

    if !allowed_dirs.is_empty() {
        if let Some(m) = bpf.map_mut("allowed_dir_inodes") {
            if let Ok(mut dir_map) = AyaHashMap::<_, InoKey, u8>::try_from(m) {
                let sentinel = InoKey {
                    ino: 0,
                    dev: 0,
                    _pad: 0,
                };
                let _ = dir_map.insert(sentinel, 1u8, 0);
                for dir_path in &allowed_dirs {
                    let p = std::path::PathBuf::from(dir_path);
                    if let Some(key) = resolve_dir_inode_key(&p) {
                        let _ = dir_map.insert(key, 1u8, 0);
                        info!(
                            "Loaded allowed directory: {} (dev={}, ino={})",
                            dir_path, key.dev, key.ino
                        );
                    } else {
                        warn!("Cannot resolve allowed directory inode: {}", dir_path);
                    }
                }
            }
        }
    }
}

// ── BPF command handler (called from daemon policy updates) ──────────────────

pub fn apply_command(bpf: &mut Bpf, cmd: &EbpfCommand) {
    match cmd {
        EbpfCommand::BlockFile(name) => {
            if let Some(m) = bpf.map_mut("blocked_files") {
                if let Ok(mut map) = AyaHashMap::<_, [u8; MAX_PATH_LEN], u8>::try_from(m) {
                    // Key by basename so it matches the kernel's d_name.name lookup.
                    let _ = map.insert(make_file_key(name), 1u8, 0);
                    info!(
                        "eBPF: blocked file {} (key={})",
                        name,
                        blocked_file_key(name)
                    );
                }
            }
            // If the caller gave a concrete absolute path that exists, ALSO pin
            // its (dev,ino) so a rename/hardlink to a new basename can't dodge it.
            // Bare basenames have no resolvable path here — they stay basename-only.
            if name.starts_with('/') {
                let p = PathBuf::from(name);
                if p.exists() {
                    block_inode_path(bpf, &p);
                } else {
                    // Note: under the shipped unit the daemon has PrivateTmp, so
                    // paths under /tmp are invisible here and get a basename block only.
                    warn!(
                        "eBPF: {} not visible from the daemon — basename block only, inode not pinned",
                        name
                    );
                }
            }
        }
        EbpfCommand::UnblockFile(name) => {
            if let Some(m) = bpf.map_mut("blocked_files") {
                if let Ok(mut map) = AyaHashMap::<_, [u8; MAX_PATH_LEN], u8>::try_from(m) {
                    let _ = map.remove(&make_file_key(name));
                }
            }
        }
        EbpfCommand::BlockIp(ip_str) => {
            if let Some(ip) = parse_ip(ip_str) {
                if let Some(m) = bpf.map_mut("blocked_ips") {
                    if let Ok(mut map) = AyaHashMap::<_, u32, u8>::try_from(m) {
                        let _ = map.insert(ip, 1u8, 0);
                        info!("eBPF: blocked IP {}", ip_str);
                    }
                }
            }
        }
        EbpfCommand::UnblockIp(ip_str) => {
            if let Some(ip) = parse_ip(ip_str) {
                if let Some(m) = bpf.map_mut("blocked_ips") {
                    if let Ok(mut map) = AyaHashMap::<_, u32, u8>::try_from(m) {
                        let _ = map.remove(&ip);
                        info!("eBPF: unblocked IP {}", ip_str);
                    }
                }
            }
        }
        EbpfCommand::SetEnforce(enabled) => {
            if let Some(m) = bpf.map_mut("config_map") {
                if let Ok(mut map) = Array::<_, Config>::try_from(m) {
                    if let Ok(mut cfg) = map.get(&0, 0) {
                        cfg.enforce_blocks = *enabled as u8;
                        let _ = map.set(0, cfg, 0);
                        info!("eBPF: enforce_blocks = {}", enabled);
                    }
                }
            }
        }
        EbpfCommand::SetDlpEnabled(enabled) => {
            if let Some(m) = bpf.map_mut("config_map") {
                if let Ok(mut map) = Array::<_, Config>::try_from(m) {
                    if let Ok(mut cfg) = map.get(&0, 0) {
                        cfg.dlp_enabled = *enabled as u8;
                        let _ = map.set(0, cfg, 0);
                        info!("eBPF: dlp_enabled = {}", enabled);
                    }
                }
            }
        }
        EbpfCommand::AllowKeyIp(ip_str) => {
            if let Some(ip) = parse_ip(ip_str) {
                if let Some(m) = bpf.map_mut("key_allowed_ips") {
                    if let Ok(mut map) = AyaHashMap::<_, u32, u8>::try_from(m) {
                        let _ = map.insert(ip, 1u8, 0);
                        info!("eBPF: allowed key destination IP {}", ip_str);
                    }
                }
            }
        }
        EbpfCommand::BlockSend { pid, ip_str } => {
            if let Some(ip) = parse_ip(ip_str) {
                if let Some(m) = bpf.map_mut("blocked_sends") {
                    if let Ok(mut map) = AyaHashMap::<_, BlockKey, u8>::try_from(m) {
                        let key = BlockKey { pid: *pid, ip };
                        let _ = map.insert(key, 1u8, 0);
                        info!("eBPF: blocked sends from pid {} to {}", pid, ip_str);
                    }
                }
            }
        }
        EbpfCommand::TrackAgentPid(pid) => {
            if let Some(m) = bpf.map_mut("agent_descendants") {
                if let Ok(mut map) = AyaHashMap::<_, u32, u8>::try_from(m) {
                    let _ = map.insert(*pid, 1u8, 0);
                    info!(
                        "eBPF: tracking agent PID {} (cmdline-detected) — kernel events captured",
                        pid
                    );
                }
            }
        }
        EbpfCommand::ContainPid(pid) => {
            if let Some(m) = bpf.map_mut("contained_pids") {
                if let Ok(mut map) = AyaHashMap::<_, u32, u8>::try_from(m) {
                    let _ = map.insert(*pid, 1u8, 0);
                    info!("eBPF: contained PID {} — tamper protection active", pid);
                }
            }
        }
        EbpfCommand::ReleasePid(pid) => {
            if let Some(m) = bpf.map_mut("contained_pids") {
                if let Ok(mut map) = AyaHashMap::<_, u32, u8>::try_from(m) {
                    let _ = map.remove(pid);
                    info!("eBPF: released PID {} from containment", pid);
                }
            }
        }
        EbpfCommand::SetWriteVerdict { dev, ino, verdict } => {
            if let Some(m) = bpf.map_mut("agent_write_verdicts") {
                if let Ok(mut map) = AyaHashMap::<_, InoKey, WriteVerdict>::try_from(m) {
                    let key = InoKey {
                        ino: *ino,
                        dev: *dev,
                        _pad: 0,
                    };
                    match map.insert(key, *verdict, 0) {
                        Ok(()) => info!(
                            dev,
                            ino,
                            enforce = verdict.enforce,
                            review = verdict.review,
                            severity = verdict.severity,
                            "eBPF: quarantine verdict recorded"
                        ),
                        // A full map is a real condition, not something to
                        // swallow: from here on, new verdicts are not held.
                        Err(e) => warn!(
                            dev, ino, err = %e,
                            "eBPF: could not record a quarantine verdict — the map is full or \
                             unavailable, so this file is NOT quarantined"
                        ),
                    }
                }
            }
        }
        EbpfCommand::ClearWriteVerdict { dev, ino } => {
            if let Some(m) = bpf.map_mut("agent_write_verdicts") {
                if let Ok(mut map) = AyaHashMap::<_, InoKey, WriteVerdict>::try_from(m) {
                    let key = InoKey {
                        ino: *ino,
                        dev: *dev,
                        _pad: 0,
                    };
                    let _ = map.remove(&key);
                }
            }
        }
        EbpfCommand::SetQuarantineEnforce(on) => {
            if let Some(m) = bpf.map_mut("config_map") {
                if let Ok(mut map) = Array::<_, Config>::try_from(m) {
                    if let Ok(mut cfg) = map.get(&0, 0) {
                        cfg.quarantine_enforce = *on as u8;
                        let _ = map.set(0, cfg, 0);
                        info!(enabled = *on, "eBPF: quarantine_enforce set");
                    }
                }
            }
        }
        EbpfCommand::SetEgressEnforce(on) => {
            if let Some(m) = bpf.map_mut("config_map") {
                if let Ok(mut map) = Array::<_, Config>::try_from(m) {
                    if let Ok(mut cfg) = map.get(&0, 0) {
                        cfg.egress_enforce = *on as u8;
                        let _ = map.set(0, cfg, 0);
                        info!(enabled = *on, "eBPF: egress_enforce set");
                    }
                }
            }
        }
        EbpfCommand::SetTaintOnEgress(on) => {
            if let Some(m) = bpf.map_mut("config_map") {
                if let Ok(mut map) = Array::<_, Config>::try_from(m) {
                    if let Ok(mut cfg) = map.get(&0, 0) {
                        cfg.taint_on_egress = *on as u8;
                        let _ = map.set(0, cfg, 0);
                        info!(enabled = *on, "eBPF: taint_on_egress set");
                    }
                }
            }
        }
        EbpfCommand::RevokeEgressIp(ip_str) => {
            if let Some(ip) = parse_ip(ip_str) {
                if let Some(m) = bpf.map_mut("egress_allowed_ips") {
                    if let Ok(mut map) = AyaHashMap::<_, u32, u8>::try_from(m) {
                        let _ = map.remove(&ip);
                    }
                }
            }
        }
        EbpfCommand::AllowEgressIp(ip_str) => {
            if let Some(ip) = parse_ip(ip_str) {
                if let Some(m) = bpf.map_mut("egress_allowed_ips") {
                    if let Ok(mut map) = AyaHashMap::<_, u32, u8>::try_from(m) {
                        let _ = map.insert(ip, 1u8, 0);
                        info!("eBPF: egress allowlist += {}", ip_str);
                    }
                }
            }
        }
        EbpfCommand::SetTaint { pid, has_keys } => {
            if let Some(m) = bpf.map_mut("tainted_pids") {
                if let Ok(mut map) = AyaHashMap::<_, u32, TaintInfo>::try_from(m) {
                    // Raise only. If the pid is already tainted, keep the
                    // higher has_keys — taint never steps down.
                    let existing = map.get(pid, 0).ok();
                    let prior_keys = existing.map(|t| t.has_keys).unwrap_or(0);
                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map(|d| d.as_secs() as u32)
                        .unwrap_or(0);
                    let ti = TaintInfo {
                        tainted: 1,
                        has_keys: prior_keys | (*has_keys as u8),
                        _pad: 0,
                        taint_time: existing
                            .map(|t| t.taint_time)
                            .filter(|&x| x != 0)
                            .unwrap_or(now),
                    };
                    let _ = map.insert(*pid, ti, 0);
                }
            }
        }
        EbpfCommand::SetDaemonPid(pid) => {
            if let Some(m) = bpf.map_mut("daemon_pid_map") {
                if let Ok(mut map) = Array::<_, u32>::try_from(m) {
                    let _ = map.set(0, *pid, 0);
                    info!(
                        "eBPF: daemon PID set to {} (exempt from tamper protection)",
                        pid
                    );
                }
            }
        }
        EbpfCommand::AllowContainedExec(name) => {
            if let Some(m) = bpf.map_mut("contained_allowed_exec") {
                if let Ok(mut map) = AyaHashMap::<_, [u8; MAX_COMM_LEN], u8>::try_from(m) {
                    let mut key = [0u8; MAX_COMM_LEN];
                    let b = name.as_bytes();
                    key[..b.len().min(MAX_COMM_LEN - 1)]
                        .copy_from_slice(&b[..b.len().min(MAX_COMM_LEN - 1)]);
                    let _ = map.insert(key, 1u8, 0);
                    info!("eBPF: allowed exec '{}' for contained processes", name);
                }
            }
        }
        EbpfCommand::DenyContainedExec(name) => {
            if let Some(m) = bpf.map_mut("contained_allowed_exec") {
                if let Ok(mut map) = AyaHashMap::<_, [u8; MAX_COMM_LEN], u8>::try_from(m) {
                    let mut key = [0u8; MAX_COMM_LEN];
                    let b = name.as_bytes();
                    key[..b.len().min(MAX_COMM_LEN - 1)]
                        .copy_from_slice(&b[..b.len().min(MAX_COMM_LEN - 1)]);
                    let _ = map.remove(&key);
                }
            }
        }
        EbpfCommand::SetAllowedDir(path_str) => {
            let p = PathBuf::from(path_str);
            if p.is_dir() {
                if let Some(key) = resolve_dir_inode_key(&p) {
                    if let Some(m) = bpf.map_mut("allowed_dir_inodes") {
                        if let Ok(mut map) = AyaHashMap::<_, InoKey, u8>::try_from(m) {
                            // Insert sentinel (ino=0) to signal "dir restriction active"
                            let sentinel = InoKey {
                                ino: 0,
                                dev: 0,
                                _pad: 0,
                            };
                            let _ = map.insert(sentinel, 1u8, 0);
                            // Insert the actual directory inode
                            let _ = map.insert(key, 1u8, 0);
                            info!(
                                "eBPF: allowed directory dev={} ino={} ({}) — files outside blocked for agents",
                                key.dev, key.ino, path_str
                            );
                        }
                    }
                } else {
                    warn!(
                        "eBPF: SetAllowedDir — cannot resolve inode for {}",
                        path_str
                    );
                }
            } else {
                warn!("eBPF: SetAllowedDir — not a directory: {}", path_str);
            }
        }
        EbpfCommand::ClearAllowedDirs => {
            if let Some(m) = bpf.map_mut("allowed_dir_inodes") {
                if let Ok(mut map) = AyaHashMap::<_, InoKey, u8>::try_from(m) {
                    let sentinel = InoKey {
                        ino: 0,
                        dev: 0,
                        _pad: 0,
                    };
                    let _ = map.remove(&sentinel);
                    info!("eBPF: cleared allowed directory restrictions");
                }
            }
        }
        EbpfCommand::BlockDir(path_str) => {
            let p = PathBuf::from(path_str);
            if p.is_dir() {
                if let Some(key) = resolve_dir_inode_key(&p) {
                    if let Some(m) = bpf.map_mut("blocked_dir_inodes") {
                        if let Ok(mut map) = AyaHashMap::<_, InoKey, u8>::try_from(m) {
                            // Insert sentinel (ino=0) to signal "blocked-dir restriction active"
                            let sentinel = InoKey {
                                ino: 0,
                                dev: 0,
                                _pad: 0,
                            };
                            let _ = map.insert(sentinel, 1u8, 0);
                            let _ = map.insert(key, 1u8, 0);
                            info!(
                                "eBPF: blocked directory dev={} ino={} ({}) — all files inside blocked for agents",
                                key.dev, key.ino, path_str
                            );
                        }
                    }
                } else {
                    warn!("eBPF: BlockDir — cannot resolve inode for {}", path_str);
                }
            } else {
                warn!("eBPF: BlockDir — not a directory: {}", path_str);
            }
        }
        EbpfCommand::ClearBlockedDirs => {
            if let Some(m) = bpf.map_mut("blocked_dir_inodes") {
                if let Ok(mut map) = AyaHashMap::<_, InoKey, u8>::try_from(m) {
                    let sentinel = InoKey {
                        ino: 0,
                        dev: 0,
                        _pad: 0,
                    };
                    let _ = map.remove(&sentinel);
                    info!("eBPF: cleared blocked directory restrictions");
                }
            }
        }
    }
}

/// Resolve a directory path to its kernel-space (dev, ino) identity.
fn resolve_dir_inode_key(path: &std::path::Path) -> Option<InoKey> {
    use std::os::unix::fs::MetadataExt;
    let md = std::fs::metadata(path).ok()?;
    if !md.is_dir() {
        return None;
    }
    let st_dev = md.dev();
    let major = unsafe { libc::major(st_dev) } as u32;
    let minor = unsafe { libc::minor(st_dev) } as u32;
    let kdev = (major << 20) | (minor & 0xf_ffff);
    Some(InoKey {
        ino: md.ino(),
        dev: kdev,
        _pad: 0,
    })
}

/// Commands the daemon can push into the eBPF subsystem at runtime.
#[derive(Debug, Clone)]
pub enum EbpfCommand {
    BlockFile(String),
    UnblockFile(String),
    BlockIp(String),
    UnblockIp(String),
    SetEnforce(bool),
    SetDlpEnabled(bool),
    /// Allow a specific IP for tainted (key-holding) processes
    AllowKeyIp(String),
    /// Block a specific (pid, ip) pair in the send cache
    BlockSend {
        pid: u32,
        ip_str: String,
    },
    /// Set allowed directory (for "Project Directory Only" restriction).
    /// Resolves path to inode and inserts into allowed_dir_inodes BPF map.
    SetAllowedDir(String),
    /// Clear all allowed directory restrictions.
    ClearAllowedDirs,
    /// Block all files inside a directory. Resolves path to inode and inserts
    /// into blocked_dir_inodes BPF map.
    BlockDir(String),
    /// Clear all blocked directory restrictions.
    ClearBlockedDirs,
    /// Mark a PID as an AI-agent (taint it into agent_descendants) so the kernel
    /// captures its file/network/exec events. Used for Node/Python CLIs whose
    /// `comm` isn't the agent name (Gemini CLI runs as `node`/`MainThread`), so
    /// the in-kernel comm check misses them — userspace detects them by cmdline
    /// and tells the kernel to track the pid.
    TrackAgentPid(u32),
    /// Containment: register a PID as contained (tamper-protected)
    ContainPid(u32),
    /// Containment: unregister a PID from containment
    ReleasePid(u32),
    /// Set daemon PID (exempt from tamper protection checks)
    SetDaemonPid(u32),
    /// Record what a scan of an agent-written file concluded, keyed on the
    /// file's identity so a rename or hardlink cannot shake it off.
    ///
    /// The `enforce` field must only ever be set from a deterministic pattern
    /// match. `SetWriteVerdict` does not check that — the caller does, in
    /// `write_scan.rs`, where the two scorers are visible side by side.
    SetWriteVerdict {
        dev: u32,
        ino: u64,
        verdict: WriteVerdict,
    },
    /// Forget a verdict: the file was deleted, or replaced by different
    /// content that scanned clean.
    ClearWriteVerdict {
        dev: u32,
        ino: u64,
    },
    /// Turn quarantine enforcement on or off at runtime.
    SetQuarantineEnforce(bool),
    /// Turn egress narrowing on or off at runtime.
    SetEgressEnforce(bool),
    /// Turn the kernel's taint-on-external-egress signal on or off at runtime.
    SetTaintOnEgress(bool),
    /// Add a destination to the egress allowlist for tainted processes.
    AllowEgressIp(String),
    /// Remove one, when a learned DNS record's TTL has run out.
    RevokeEgressIp(String),
    /// Set or raise taint on a pid. `has_keys` only ever goes 0 -> 1, never
    /// back: taint may be raised, never cleared, which is THE ONE RULE. The
    /// kernel drops it on process exit, which is not a downgrade of authority.
    SetTaint {
        pid: u32,
        has_keys: bool,
    },
    /// Allow a binary name for contained processes to exec
    AllowContainedExec(String),
    /// Remove a binary from the contained exec allowlist
    DenyContainedExec(String),
}

// ── Main entry point ──────────────────────────────────────────────────────────

/// Start the eBPF loader and forward kernel events into `tx`.
/// Also returns a `cmd_tx` sender the daemon can use to push `EbpfCommand`s.
///
/// Must be called as root (EUID 0).
pub async fn start(
    tx: mpsc::Sender<DriverMessage>,
    proxy_port: Option<u16>,
    dlp_engine: Option<Arc<DlpEngine>>,
) -> Result<mpsc::Sender<EbpfCommand>> {
    if unsafe { libc::geteuid() } != 0 {
        anyhow::bail!("eBPF loader must run as root — skipping kernel telemetry");
    }

    let bpf_path = std::env::var("RINGZERO_BPF_PATH")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("/usr/lib/ringzero/ringzero.bpf.o"));

    info!("Loading BPF object: {}", bpf_path.display());

    let btf = Btf::from_sys_fs()
        .context("Failed to load BTF — ensure kernel has CONFIG_DEBUG_INFO_BTF=y")?;

    let mut bpf = BpfLoader::new()
        .btf(Some(&btf))
        .load_file(&bpf_path)
        .context("Failed to load BPF object — ensure BPF LSM is enabled")?;

    // Attach LSM hooks
    let lsm_programs = [
        ("ringzero_file_open", "file_open"),
        ("ringzero_inode_create", "inode_create"),
        ("ringzero_inode_unlink", "inode_unlink"),
        ("ringzero_inode_rename", "inode_rename"),
        ("ringzero_bprm_check", "bprm_check_security"),
        ("ringzero_socket_connect", "socket_connect"),
        ("ringzero_socket_sendmsg", "socket_sendmsg"),
        // mprotect W→X detection (shellcode/JIT)
        ("ringzero_file_mprotect", "file_mprotect"),
        // Tamper protection (Phase 3)
        ("ringzero_ptrace_access_check", "ptrace_access_check"),
        ("ringzero_task_kill", "task_kill"),
        ("ringzero_sb_mount", "sb_mount"),
        ("ringzero_sb_umount", "sb_umount"),
        // Enhanced containment enforcement (Phase 4)
        ("ringzero_bprm_check_contained", "bprm_check_security"),
        ("ringzero_file_open_contained", "file_open"),
    ];
    let mut _links: Vec<Box<dyn std::any::Any + Send>> = vec![];
    let mut lsm_attached = 0u32;
    let mut lsm_failed = 0u32;
    for (prog_name, hook_name) in &lsm_programs {
        // Per-hook attach. A single failure (incompatible kernel, hook absent,
        // duplicate-hook rejection) must NOT drop every prior link via `?`,
        // which would silently disable all eBPF telemetry while the daemon
        // keeps running. Warn and continue instead — partial coverage is
        // better than zero coverage.
        match bpf.program_mut(prog_name) {
            Some(prog) => {
                let lsm = match TryInto::<&mut Lsm>::try_into(prog) {
                    Ok(l) => l,
                    Err(e) => {
                        warn!(prog = prog_name, hook = hook_name, err = %e,
                              "LSM program type mismatch — skipping");
                        lsm_failed += 1;
                        continue;
                    }
                };
                if let Err(e) = lsm.load(hook_name, &btf) {
                    warn!(prog = prog_name, hook = hook_name, err = %e,
                          "LSM load failed — skipping (kernel may lack this hook)");
                    lsm_failed += 1;
                    continue;
                }
                match lsm.attach() {
                    Ok(link) => {
                        _links.push(Box::new(link));
                        info!("Attached LSM: {}", prog_name);
                        lsm_attached += 1;
                    }
                    Err(e) => {
                        warn!(prog = prog_name, hook = hook_name, err = %e,
                              "LSM attach failed — skipping");
                        lsm_failed += 1;
                    }
                }
            }
            None => {
                warn!("LSM program not found: {}", prog_name);
                lsm_failed += 1;
            }
        }
    }
    if lsm_attached == 0 {
        warn!(
            failed = lsm_failed,
            "ALL LSM hooks failed to attach — kernel telemetry is DEGRADED. \
             Check CONFIG_BPF_LSM=y and that 'bpf' is in /sys/kernel/security/lsm"
        );
    } else if lsm_failed > 0 {
        warn!(
            attached = lsm_attached,
            failed = lsm_failed,
            "eBPF telemetry partially degraded — some LSM hooks failed to attach"
        );
    } else {
        info!(attached = lsm_attached, "All LSM hooks attached cleanly");
    }

    // Attach tracepoints — mirror the LSM continue+warn pattern. A failure to
    // load/attach a tracepoint must not bring down the whole loader because
    // that would silently disable every previously-attached LSM/cgroup hook.
    for (name, category, tracepoint) in &[
        ("handle_fork", "sched", "sched_process_fork"),
        ("handle_exit", "sched", "sched_process_exit"),
    ] {
        let Some(prog) = bpf.program_mut(name) else {
            warn!("Tracepoint program not found: {}", name);
            continue;
        };
        let tp = match TryInto::<&mut TracePoint>::try_into(prog) {
            Ok(t) => t,
            Err(e) => {
                warn!(prog = name, err = %e, "Tracepoint program type mismatch — skipping");
                continue;
            }
        };
        if let Err(e) = tp.load() {
            warn!(prog = name, err = %e, "Tracepoint load failed — skipping");
            continue;
        }
        match tp.attach(category, tracepoint) {
            Ok(link) => _links.push(Box::new(link)),
            Err(e) => warn!(prog = name, err = %e, "Tracepoint attach failed — skipping"),
        }
    }

    // Attach cgroup programs (TLS proxy redirect, optional)
    if std::path::Path::new("/sys/fs/cgroup").exists() {
        use std::fs::File;
        if let Ok(cgroup_file) = File::open("/sys/fs/cgroup") {
            for prog_name in &["ringzero_connect4", "ringzero_connect6"] {
                if let Some(prog) = bpf.program_mut(prog_name) {
                    use aya::programs::CgroupSockAddr;
                    if let Ok(cg) = TryInto::<&mut CgroupSockAddr>::try_into(prog) {
                        cg.load().ok();
                        if let Ok(link) = cg.attach(&cgroup_file) {
                            _links.push(Box::new(link));
                            info!("Attached cgroup: {}", prog_name);
                        }
                    }
                }
            }
        }
    }

    // Default config. A missing config_map shouldn't drop every previously
    // attached LSM/tracepoint hook via `?` — warn and continue with kernel
    // defaults instead. Same for the proxy_config_map below.
    match bpf.map_mut("config_map") {
        Some(m) => match Array::<_, Config>::try_from(m) {
            Ok(mut config_map) => {
                if let Err(e) = config_map.set(
                    0,
                    Config {
                        enabled: 1,
                        monitor_all: 0,
                        enforce_blocks: 1,
                        dlp_enabled: 1,
                        // Quarantine enforcement starts OFF. The daemon turns
                        // it on only if the operator asked for it.
                        quarantine_enforce: 0,
                        // Egress enforcement starts OFF, same reasoning.
                        egress_enforce: 0,
                        // Taint-on-egress starts OFF too. It only records a
                        // bit, but it changes what every other rule sees, so
                        // it is the operator's choice to turn on.
                        taint_on_egress: 0,
                        _reserved: [0; 1],
                    },
                    0,
                ) {
                    warn!(err = %e, "Failed to write default config to config_map — kernel will use embedded defaults");
                } else {
                    info!("eBPF config: enabled=1 monitor_all=0 enforce=1 dlp=1");
                }
            }
            Err(e) => warn!(err = %e, "config_map type mismatch — skipping"),
        },
        None => warn!("config_map not found — daemon-side feature toggles disabled"),
    }

    // TLS proxy redirect config — tells kernel to redirect port 443 to the local proxy
    if let Some(port) = proxy_port {
        match bpf.map_mut("proxy_config_map") {
            Some(map) => match Array::<_, ProxyConfig>::try_from(map) {
                Ok(mut proxy_map) => {
                    // The kernel reads this raw u32 and writes it into
                    // ctx->user_ip4 (a network-order field). To get the bytes
                    // [7F,00,00,01] in memory we write them via from_ne_bytes,
                    // so the on-wire representation is correct on both LE and
                    // BE hosts without further byteswaps.
                    let ip_netorder = u32::from_ne_bytes([127, 0, 0, 1]);
                    if let Err(e) = proxy_map.set(
                        0,
                        ProxyConfig {
                            proxy_ip4: ip_netorder,
                            proxy_port: port,
                            enabled: 1,
                            _pad: 0,
                        },
                        0,
                    ) {
                        warn!(err = %e, "Failed to set proxy_config — TLS redirect disabled");
                    } else {
                        info!(
                            port,
                            "eBPF proxy redirect enabled: 443 → 127.0.0.1:{}", port
                        );
                    }
                }
                Err(e) => warn!(err = %e, "proxy_config_map type mismatch — TLS redirect disabled"),
            },
            None => warn!("proxy_config_map not found — TLS redirect disabled"),
        }
    }

    block_default_files(&mut bpf);
    block_default_inodes(&mut bpf);
    load_file_access_rules(&mut bpf);

    // Register daemon PID so tamper protection exempts us
    {
        let daemon_pid = std::process::id();
        if let Some(m) = bpf.map_mut("daemon_pid_map") {
            if let Ok(mut map) = Array::<_, u32>::try_from(m) {
                let _ = map.set(0, daemon_pid, 0);
                info!(
                    "eBPF: registered daemon PID {} (exempt from tamper protection)",
                    daemon_pid
                );
            }
        }
    }

    // Populate default allowed exec list for contained processes
    // Matches CODING_SAFE_PROCESSES from observer.rs
    {
        let safe_binaries = [
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
        if let Some(m) = bpf.map_mut("contained_allowed_exec") {
            if let Ok(mut map) = AyaHashMap::<_, [u8; MAX_COMM_LEN], u8>::try_from(m) {
                for name in &safe_binaries {
                    let mut key = [0u8; MAX_COMM_LEN];
                    let b = name.as_bytes();
                    key[..b.len().min(MAX_COMM_LEN - 1)]
                        .copy_from_slice(&b[..b.len().min(MAX_COMM_LEN - 1)]);
                    let _ = map.insert(key, 1u8, 0);
                }
                info!(
                    "eBPF: loaded {} allowed exec binaries for contained processes",
                    safe_binaries.len()
                );
            }
        }
    }

    info!("Ring Zero eBPF subsystem loaded — forwarding events to daemon pipeline");

    // Command channel — daemon → eBPF maps
    let (cmd_tx, mut cmd_rx) = mpsc::channel::<EbpfCommand>(64);

    // Take ownership of the ring-buffer maps out of `bpf` BEFORE the event loop.
    // This avoids forging `&'static mut aya::maps::MapData` from an `&mut Map`
    // (which is unsound because the lifetime is laundered) and matches the
    // proven pattern used in ssl_sniff.rs for persistent consumers.
    //
    // The persistent consumer is critical: recreating RingBuf each iteration
    // resets the internal producer position cache (pos_cache=0), causing
    // data_available() to think there is unconsumed data even though the
    // consumer has caught up — re-reading the same events millions of times.
    let events_map = bpf.take_map("events");
    let send_events_map = bpf.take_map("send_events");
    let drop_counters_map = bpf.take_map("drop_counters");

    if events_map.is_none() {
        warn!("Events ring buffer map NOT found — kernel events will NOT be received");
    } else {
        info!("Events ring buffer map taken (persistent consumer)");
    }

    // Spawn the event loop
    tokio::spawn(async move {
        // Keep _links alive to maintain hook attachments
        let _keep = _links;
        let mut event_count: u64 = 0;
        let mut loop_count: u64 = 0;

        let mut events_ring: Option<RingBuf<aya::maps::MapData>> =
            events_map.and_then(|m| match RingBuf::try_from(m) {
                Ok(rb) => {
                    tracing::info!("Events ring buffer consumer created");
                    Some(rb)
                }
                Err(e) => {
                    tracing::error!(err = %e, "Failed to create events ring buffer consumer");
                    None
                }
            });

        let mut send_events_ring: Option<RingBuf<aya::maps::MapData>> =
            send_events_map.and_then(|m| match RingBuf::try_from(m) {
                Ok(rb) => {
                    tracing::info!("Send events ring buffer consumer created");
                    Some(rb)
                }
                Err(e) => {
                    tracing::warn!(err = %e, "Failed to create send events ring buffer");
                    None
                }
            });

        // Persistent drop-counter accessor — created once instead of per-iteration.
        let drop_counters: Option<PerCpuArray<aya::maps::MapData, u64>> =
            drop_counters_map.and_then(|m| PerCpuArray::<_, u64>::try_from(m).ok());

        loop {
            loop_count += 1;

            if loop_count == 1 {
                tracing::info!("eBPF event polling loop started");
            }

            // Refresh the agent-descendant snapshot about twice a second. The
            // write scanner reads it to attribute a finished write whose author
            // has already exited.
            // Often enough that the write scanner's bounded retry catches it.
            if loop_count % 10 == 1 {
                // Who opened what for writing. Read here because the map lives
                // with the Bpf handle this task owns.
                if let Some(m) = bpf.map_mut("agent_write_origin") {
                    // NOTE, for whoever picks this up: aya's HashMap does
                    // accept BPF_MAP_TYPE_LRU_HASH, so the map type is not why
                    // the snapshot comes back empty. Ruled out by trying
                    // LruHashMap, which does not exist in aya 0.12.
                    if let Ok(map) = AyaHashMap::<_, InoKey, WriteOrigin>::try_from(m) {
                        let mut snapshot = std::collections::HashMap::new();
                        for (k, v) in map.iter().flatten() {
                            let name = |raw: &[u8; 16]| {
                                String::from_utf8_lossy(raw)
                                    .trim_end_matches('\0')
                                    .trim()
                                    .to_string()
                            };
                            let agent_name = name(&v.agent_comm);
                            // Remember the name before an exec can erase it.
                            remember_agent_name(v.agent_pid, &agent_name);
                            remember_agent_name(v.pid, &name(&v.comm));
                            snapshot.insert(
                                (k.dev, k.ino),
                                WriteAttribution {
                                    agent_pid: v.agent_pid,
                                    agent_comm: agent_name,
                                    writer_pid: v.pid,
                                    writer_comm: name(&v.comm),
                                },
                            );
                        }
                        if let Ok(mut shared) = WRITE_ORIGINS.write() {
                            // Keep anything the scanner has not consumed yet.
                            for (k, v) in snapshot {
                                shared.entry(k).or_insert(v);
                            }
                            // The kernel map is LRU and bounded; this one is
                            // not, so bound it here too.
                            if shared.len() > 32_768 {
                                shared.clear();
                            }
                        }
                    }
                }
            }

            // Drain kernel events ring buffer (persistent consumer — no re-creation)
            let mut got_events = false;
            if let Some(ref mut ring_buf) = events_ring {
                while let Some(item) = ring_buf.next() {
                    got_events = true;
                    let data: &[u8] = item.as_ref();
                    if data.len() >= std::mem::size_of::<KernelEvent>() {
                        let e = unsafe { &*(data.as_ptr() as *const KernelEvent) };
                        let msg = kernel_event_to_driver_msg(e);
                        event_count += 1;
                        if event_count <= 5 || event_count % 100_000 == 0 {
                            tracing::info!(
                                count = event_count,
                                pid = e.pid,
                                event_type = e.event_type,
                                comm = %cstr(&e.comm),
                                "eBPF kernel event milestone"
                            );
                        }
                        match tx.try_send(msg) {
                            Ok(()) => {}
                            Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {}
                            Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {
                                return; // daemon shut down
                            }
                        }
                    }
                }
            }

            // Log periodically if no events are being received
            if loop_count == 100 && event_count == 0 {
                tracing::warn!(
                    "No eBPF events received after 100 poll cycles — BPF programs may not be firing for monitored processes"
                );
            }

            // Drain DLP send events ring buffer (persistent consumer)
            // Inspect outbound payloads for PII — if detected and action=Block,
            // immediately SIGKILL the process to tear down the socket before
            // the kernel finishes transmitting, then block future sends from
            // any child/respawn via the (pid, ip) block map.
            if let Some(ref mut ring) = send_events_ring {
                while let Some(item) = ring.next() {
                    let data: &[u8] = item.as_ref();
                    if data.len() >= std::mem::size_of::<SendEvent>() {
                        let se = unsafe { &*(data.as_ptr() as *const SendEvent) };

                        // Check payload for PII before forwarding
                        if let Some(ref dlp) = dlp_engine {
                            let payload_len = (se.data_len as usize).min(MAX_SEND_DATA);
                            let payload_text = String::from_utf8_lossy(&se.data[..payload_len]);
                            let result = dlp.redact(&payload_text);

                            if result.count > 0 {
                                let ip_str = ip_to_str(se.remote_ip);
                                let comm = cstr(&se.comm);
                                let action = dlp.get_pii_action();

                                warn!(
                                    pid = se.pid,
                                    comm = %comm,
                                    dest = %ip_str,
                                    pii_count = result.count,
                                    details = ?result.details,
                                    action = ?action,
                                    "DLP: PII detected in outbound send"
                                );

                                if matches!(action, PiiAction::Block) {
                                    // 1. SIGKILL the process immediately — tears down
                                    //    the socket and prevents kernel from finishing
                                    //    the TCP transmit of the buffered data.
                                    //    Guard against pid reuse between the kernel event
                                    //    and this signal: never signal pid <= 1, and only
                                    //    signal if the live comm still matches the event's.
                                    let live_comm =
                                        std::fs::read_to_string(format!("/proc/{}/comm", se.pid))
                                            .map(|c| c.trim().to_string())
                                            .unwrap_or_default();
                                    // Process termination from this path is DISABLED: the
                                    // socket_sendmsg capture reads the iov_iter's `__iov`
                                    // member, which on 6.x kernels is the ITER_UBUF user
                                    // pointer, so the copied payload is not the real send
                                    // buffer (verified on 6.8: a send carrying an SSN and an
                                    // email produced no detection). Killing on that data
                                    // would hit the wrong process. The event, the audit
                                    // trail and the (observe-only) block-cache entry stay;
                                    // re-enable the kill once the kernel-side read is fixed.
                                    if se.pid <= 1 || live_comm != comm {
                                        warn!(
                                            pid = se.pid,
                                            comm = %comm,
                                            live_comm = %live_comm,
                                            "DLP: process identity changed since the event (pid reuse guard)"
                                        );
                                    } else {
                                        warn!(
                                            pid = se.pid,
                                            comm = %comm,
                                            "DLP: PII in outbound send recorded (termination disabled — kernel send capture unverified)"
                                        );
                                    }

                                    // 2. Also block in eBPF map — catches respawns
                                    //    or child processes reusing the same destination
                                    apply_command(
                                        &mut bpf,
                                        &EbpfCommand::BlockSend {
                                            pid: se.pid,
                                            ip_str: ip_str.clone(),
                                        },
                                    );

                                    // 3. Emit a security event for the DLP kill
                                    let block_msg = DriverMessage::Event {
                                        event_type: 31, // DLP block event
                                        pid: se.pid,
                                        uid: se.uid,
                                        comm: comm.clone(),
                                        path: Some(format!(
                                            "PII exfil killed: {}",
                                            result.details.join(", ")
                                        )),
                                        remote_ip: Some(ip_str),
                                        remote_port: Some(se.remote_port),
                                        blocked: 1,
                                        args: None,
                                    };
                                    let _ = tx.try_send(block_msg);
                                }
                            }
                        }

                        let msg = send_event_to_driver_msg(se);
                        match tx.try_send(msg) {
                            Ok(()) => {}
                            Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {}
                            Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {
                                return;
                            }
                        }
                    }
                }
            }

            // Process any pending eBPF commands from the daemon
            while let Ok(cmd) = cmd_rx.try_recv() {
                apply_command(&mut bpf, &cmd);
            }

            // Every ~30s (600 loops * 50ms), report ring buffer drop counters
            if loop_count % 600 == 0 {
                if let Some(ref drop_map) = drop_counters {
                    for (idx, label) in [(0u32, "events"), (1u32, "send_events")] {
                        if let Ok(values) = drop_map.get(&idx, 0) {
                            let total: u64 = values.iter().sum();
                            if total > 0 {
                                tracing::warn!(
                                    ring = label,
                                    drops = total,
                                    "eBPF ring buffer overflow — events lost"
                                );
                            }
                        }
                    }
                    // Slot 2 is not a ring buffer: it counts taint the kernel
                    // could not record because tainted_pids is full.
                    if let Ok(values) = drop_map.get(&2u32, 0) {
                        let total: u64 = values.iter().sum();
                        if total > 0 {
                            tracing::warn!(
                                refused = total,
                                "tainted_pids map is full — new taint is being lost, so \
                                 processes that ingested untrusted input may not be marked"
                            );
                        }
                    }
                }
            }

            // Only sleep when no events were received — drain backlog without delay.
            // Keep the idle sleep short: the kernel ring buffer holds ~575 file/exec
            // events, and `ringzero_file_open` allows an open it cannot reserve a
            // slot for, so the consumer must never let the ring fill during a burst.
            if !got_events {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        }
    });

    Ok(cmd_tx)
}

#[cfg(test)]
mod tests {
    use super::{blocked_file_key, UNCONDITIONAL_BLOCK_FILES};

    #[test]
    fn unconditional_block_set_covers_persistence_and_credentials() {
        let names: Vec<&str> = UNCONDITIONAL_BLOCK_FILES.iter().map(|(n, _)| *n).collect();
        // credential access (T1552)
        assert!(names.contains(&"id_rsa"));
        assert!(names.contains(&".env"));
        // persistence / injection — the gap this closes
        assert!(
            names.contains(&"ld.so.preload"),
            "ld.so.preload must be blocked (T1574.006)"
        );
        assert!(
            names.contains(&"authorized_keys"),
            "authorized_keys must be blocked (T1098.004)"
        );
        // every entry carries a MITRE technique id
        assert!(UNCONDITIONAL_BLOCK_FILES
            .iter()
            .all(|(_, m)| m.starts_with('T')));
    }

    #[test]
    fn blocked_file_key_reduces_to_basename() {
        // The kernel matches d_name.name (basename) — full paths must reduce or
        // the block silently no-ops (the bug this fixes).
        assert_eq!(blocked_file_key("/home/u/.ssh/id_rsa"), "id_rsa");
        assert_eq!(blocked_file_key("/etc/shadow"), "shadow");
        assert_eq!(blocked_file_key("/root/.aws/credentials"), "credentials");
        // Already-basename inputs (the default-blocks path) pass through unchanged.
        assert_eq!(blocked_file_key("id_rsa"), "id_rsa");
        assert_eq!(blocked_file_key(".env"), ".env");
        // Trailing slash + empty are handled without panicking.
        assert_eq!(blocked_file_key("/etc/"), "etc");
        assert_eq!(blocked_file_key(""), "");
    }
}

#[cfg(test)]
mod taint_signal_tests {
    use super::*;

    const BPF: &str = include_str!("../../GPL/bpf/ringzero.bpf.c");

    /// The Rust mirror and the C struct must stay the same size, or every
    /// config field the daemon writes lands in the wrong place. The flags were
    /// added by consuming reserved bytes precisely so this stays true.
    #[test]
    fn the_config_mirror_is_the_size_the_kernel_expects() {
        assert_eq!(
            std::mem::size_of::<Config>(),
            8,
            "4 flag bytes + 4 reserved"
        );
        for field in [
            "u8 enabled;",
            "u8 monitor_all;",
            "u8 enforce_blocks;",
            "u8 dlp_enabled;",
            "u8 quarantine_enforce;",
            "u8 taint_on_egress;",
        ] {
            assert!(BPF.contains(field), "the C config lost {field:?}");
        }
    }

    /// THE MEASUREMENT THAT CONDEMNED THE CURRENT ALLOWLIST. A clean session
    /// produced 18 tainted processes, because the model API is CDN-fronted and
    /// the addresses the daemon resolves at boot are not the ones the agent
    /// later uses. Until allowlisting is DNS-aware this must stay off, or
    /// every session is tainted and the signal means nothing.
    #[test]
    fn taint_on_egress_is_off_by_default() {
        let cfg = crate::config::EgressSection::default();
        assert!(
            !cfg.taint_on_egress,
            "a static IP allowlist cannot track a CDN-fronted model endpoint, so this \
             must not ship on"
        );
        assert!(!cfg.enforce, "and nothing is refused by default either");
    }

    /// Taint must land on the AGENT ROOT, not only on the process that made the
    /// connection. Measured, not assumed: asked to read a web page, the agent
    /// ran `curl` through a shell; curl connected, was tainted, and exited in
    /// the same breath, so the exit tracepoint dropped the entry before
    /// anything could act on it. The helper is not the thing whose authority
    /// should narrow.
    #[test]
    fn the_taint_lands_on_the_agent_root_not_just_the_connecting_process() {
        let block = BPF
            .split("EXTERNAL INGESTION RAISES TAINT")
            .nth(1)
            .expect("the taint block must exist in socket_connect");
        // It taints the connecting process...
        assert!(
            block.contains("raise_taint(ipid"),
            "the connecting pid is tainted"
        );
        // ...and walks to the agent root and taints that too.
        assert!(
            block.contains("find_agent_root(&root_pid"),
            "the agent root must be resolved"
        );
        assert!(
            block.contains("raise_taint(root_pid"),
            "the agent root must be tainted, or a short-lived helper takes the taint to \
             the grave with it"
        );
    }

    /// Both carve-outs, without which the rule taints everything immediately
    /// and therefore says nothing.
    #[test]
    fn dns_and_allowlisted_destinations_never_raise_taint() {
        let block = BPF
            .split("EXTERNAL INGESTION RAISES TAINT")
            .nth(1)
            .expect("taint block");
        assert!(block.contains("port != 53"), "a name lookup must not taint");
        assert!(
            block.contains("key_allowed_ips") && block.contains("egress_allowed_ips"),
            "an allowlisted destination must not taint"
        );
        assert!(
            block.contains("(ip & 0xff) == 127"),
            "loopback must not taint"
        );
    }

    /// Taint narrows authority, so it may be raised and never lowered. The
    /// kernel helper must not clear `has_keys` or unset `tainted`.
    #[test]
    fn raising_taint_never_downgrades_an_existing_entry() {
        let helper = BPF
            .split("static __always_inline void raise_taint")
            .nth(1)
            .expect("raise_taint must exist")
            .split("\n}")
            .next()
            .unwrap();
        assert!(
            !helper.contains("tainted = 0") && !helper.contains("has_keys = 0"),
            "raise_taint must never clear a bit: {helper}"
        );
        assert!(
            helper.contains("if (!ex)") && helper.contains("else if (!ex->tainted)"),
            "an existing entry is preserved rather than overwritten wholesale"
        );
    }

    /// The taint signal is placed AFTER the narrowing decision so the very
    /// connection that ingests still completes. If it moved above, the first
    /// off-allowlist fetch would be refused and the agent could never ingest
    /// anything at all.
    #[test]
    fn the_taint_is_raised_after_the_narrowing_decision() {
        let hook = BPF
            .split("int BPF_PROG(ringzero_socket_connect")
            .nth(1)
            .expect("socket_connect hook");
        let narrow = hook
            .find("EGRESS NARROWING ON TAINT")
            .expect("narrowing block");
        let taint = hook
            .find("EXTERNAL INGESTION RAISES TAINT")
            .expect("taint block");
        assert!(
            narrow < taint,
            "narrowing must be decided before this connection raises taint"
        );
    }
}
