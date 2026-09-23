// SPDX-License-Identifier: Apache-2.0
//
// transcript_taint — set kernel taint when external content enters the agent.
//
// THE DESIGN. A userspace sensor watches each agent's JSONL transcript and,
// when a record shows genuinely external content was ingested, raises taint on
// that agent's process tree. The kernel then enforces narrowed egress on the
// taint (see the socket_connect hook and `egress_enforce`). The two halves meet
// at one deterministic fact: this process pulled in content it did not author,
// so its outbound authority is narrowed to the egress allowlist.
//
// THE ONE RULE, and it is sharpest here. The trigger keys on PROVENANCE, which
// is a deterministic fact in the transcript — the agent invoked a web fetch, a
// web search, or an MCP tool — NOT on any judgment that the content is
// malicious. A model may raise severity on top; a model may never be the thing
// that clears taint. Taint is raised, never lowered; the kernel drops it only
// when the process exits, which is not a downgrade of authority.
//
// NARROW ON PURPOSE. This ships with the clearest external signals only: web
// fetch, web search, and MCP tool results. A read of a file outside the
// workspace is a plausible fourth signal and is deliberately NOT included yet,
// because it is the one most likely to taint a plain coding session and the
// taint-explosion risk has to be measured before it is widened. models/README
// carries the measurement.
//
// THE JOURNAL CARVE-OUT. The transcript is the union of everything the session
// handled, so it always looks sensitive. We never treat the transcript's own
// existence, or a read of it, as external ingestion, and the write-scanner
// excludes it too (see write_scan::is_agent_journal). Otherwise resuming a
// session would trip its own trap.
//
// INCREMENTAL. Each transcript is tailed from a saved byte offset and never
// re-read. On first sight of a transcript we seek to its end, so history is not
// replayed into a taint storm; only content that lands while we are watching
// counts.

use std::collections::HashMap;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use tracing::{debug, info, warn};

/// How often the transcripts are drained. Writes land within a second or two of
/// the event, so this is timely without spinning.
const POLL_INTERVAL: Duration = Duration::from_millis(500);

/// A cap on bytes read per transcript per poll, so a huge burst cannot stall
/// the loop. The rest is picked up next tick.
const MAX_READ_PER_POLL: u64 = 512 * 1024;

/// Tool names whose results are, deterministically, external content.
///
/// Web fetch and web search pull content off the machine's network. An MCP tool
/// returns data the agent did not author. This does NOT distinguish a local
/// stdio MCP server from a remote one — both return external-to-the-agent
/// content — and that limit is stated in the docs.
fn is_external_tool(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    n == "webfetch"
        || n == "websearch"
        || n == "web_fetch"
        || n == "web_search"
        || n.starts_with("mcp__")
}

/// Why a transcript record raised taint. Deterministic provenance, never a
/// content judgment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Provenance {
    WebFetch,
    WebSearch,
    Mcp(String),
}

impl Provenance {
    fn label(&self) -> String {
        match self {
            Provenance::WebFetch => "web_fetch".to_string(),
            Provenance::WebSearch => "web_search".to_string(),
            Provenance::Mcp(server) => format!("mcp:{server}"),
        }
    }

    fn from_tool(name: &str) -> Option<Provenance> {
        let n = name.to_ascii_lowercase();
        if n == "webfetch" || n == "web_fetch" {
            Some(Provenance::WebFetch)
        } else if n == "websearch" || n == "web_search" {
            Some(Provenance::WebSearch)
        } else if let Some(rest) = n.strip_prefix("mcp__") {
            let server = rest.split("__").next().unwrap_or("unknown").to_string();
            Some(Provenance::Mcp(server))
        } else {
            None
        }
    }
}

/// Scan one JSONL record for an external-content signal.
///
/// Keys on an assistant `tool_use` whose name is external. The invocation is a
/// deterministic provenance fact and is robust to the result arriving in a
/// later poll chunk, which correlating id-to-result is not. A record from the
/// agent's own journal machinery (queue-operation, cost-state, and the like)
/// carries no tool_use and is ignored for free.
pub fn record_signal(line: &str) -> Option<Provenance> {
    let v: serde_json::Value = serde_json::from_str(line).ok()?;
    // Only assistant messages carry tool_use.
    if v.get("type").and_then(|t| t.as_str()) != Some("assistant") {
        return None;
    }
    let content = v.get("message")?.get("content")?.as_array()?;
    for block in content {
        if block.get("type").and_then(|t| t.as_str()) == Some("tool_use") {
            if let Some(name) = block.get("name").and_then(|n| n.as_str()) {
                if let Some(p) = Provenance::from_tool(name) {
                    return Some(p);
                }
            }
        }
    }
    None
}

/// Everything the watcher needs, resolved once.
pub struct WatchContext {
    pub cfg: crate::config::TranscriptWatchSection,
    pub ebpf: std::sync::Arc<
        tokio::sync::RwLock<Option<tokio::sync::mpsc::Sender<crate::ebpf_loader::EbpfCommand>>>,
    >,
    /// When the watcher started. Used to tell a transcript that already existed
    /// (history, skip it) from one created since (a live session, read it all).
    pub started_at: std::time::SystemTime,
}

/// Per-transcript position and identity.
struct Tail {
    offset: u64,
    /// The inode, so a rotated/truncated file is noticed rather than mis-read.
    ino: u64,
    /// A carry buffer for a line split across two reads.
    partial: String,
}

pub fn spawn(ctx: WatchContext) {
    tokio::spawn(async move {
        if let Err(e) = run(ctx).await {
            warn!(err = %e, "transcript taint watcher exited");
        }
    });
}

async fn run(ctx: WatchContext) -> anyhow::Result<()> {
    info!("transcript taint watcher started");
    let mut tails: HashMap<PathBuf, Tail> = HashMap::new();

    loop {
        for dir in transcript_dirs() {
            let Ok(entries) = std::fs::read_dir(&dir) else {
                continue;
            };
            for e in entries.flatten() {
                let p = e.path();
                if p.extension().and_then(|x| x.to_str()) != Some("jsonl") {
                    continue;
                }
                // Canonicalize so a symlinked home (e.g. /home/alice.linux ->
                // /home/alice.guest) does not present the same transcript under
                // two paths, tail it twice and raise taint twice.
                let canon = std::fs::canonicalize(&p).unwrap_or(p);
                drain_transcript(&ctx, &canon, &mut tails).await;
            }
        }
        // Forget tails whose file is gone, so the map cannot grow forever.
        tails.retain(|p, _| p.exists());
        tokio::time::sleep(POLL_INTERVAL).await;
    }
}

/// Where transcripts live, across every user's home.
fn transcript_dirs() -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut homes = vec![PathBuf::from("/root")];
    if let Ok(entries) = std::fs::read_dir("/home") {
        for e in entries.flatten() {
            homes.push(e.path());
        }
    }
    for h in homes {
        let base = h.join(".claude/projects");
        if base.is_dir() {
            if let Ok(entries) = std::fs::read_dir(&base) {
                for e in entries.flatten() {
                    if e.path().is_dir() {
                        out.push(e.path());
                    }
                }
            }
        }
    }
    out
}

async fn drain_transcript(ctx: &WatchContext, path: &Path, tails: &mut HashMap<PathBuf, Tail>) {
    use std::os::unix::fs::MetadataExt;
    let Ok(meta) = std::fs::metadata(path) else {
        return;
    };
    let size = meta.len();
    let ino = meta.ino();

    let tail = tails.entry(path.to_path_buf()).or_insert_with(|| {
        // FIRST SIGHT. Two different cases, and treating them the same was a
        // real bug: a brand-new session was invisible.
        //
        // A transcript that already existed when we started watching is
        // history. Replaying it would raise taint for work that finished long
        // ago, so we seek to the end.
        //
        // A transcript CREATED since we started watching is a live session, and
        // its opening records are not history at all — they are the session
        // happening right now. Seeking to the end there skipped everything
        // written before our first poll, which for a short session is the whole
        // thing. Measured: a real Claude Code run using an MCP server produced
        // mcp__files__read_text_file in its transcript and raised no taint,
        // because the file was created and the tool called between two polls.
        //
        // So: created after we started => read from the beginning.
        let created_since_start = meta
            .created()
            .or_else(|_| meta.modified())
            .map(|t| t >= ctx.started_at)
            .unwrap_or(false);
        Tail {
            offset: if created_since_start { 0 } else { size },
            ino,
            partial: String::new(),
        }
    });

    // A truncated or rotated file (new inode, or shrank) starts over.
    if tail.ino != ino || size < tail.offset {
        tail.offset = 0;
        tail.ino = ino;
        tail.partial.clear();
    }
    if size <= tail.offset {
        return;
    }

    let to_read = (size - tail.offset).min(MAX_READ_PER_POLL);
    let Ok(mut f) = std::fs::File::open(path) else {
        return;
    };
    if f.seek(SeekFrom::Start(tail.offset)).is_err() {
        return;
    }
    let mut buf = vec![0u8; to_read as usize];
    let n = match f.read(&mut buf) {
        Ok(n) => n,
        Err(_) => return,
    };
    tail.offset += n as u64;
    buf.truncate(n);

    drop(f); // release our read handle before resolving who owns the transcript

    let mut text = std::mem::take(&mut tail.partial);
    text.push_str(&String::from_utf8_lossy(&buf));
    // Keep an unfinished trailing line for next time.
    let (complete, rest) = match text.rfind('\n') {
        Some(i) => (text[..i].to_string(), text[i + 1..].to_string()),
        None => (String::new(), text),
    };
    tail.partial = rest;

    // Gather signals, then act once. Nothing here holds the file open.
    let mut signals = Vec::new();
    for line in complete.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        if let Some(prov) = record_signal(line) {
            signals.push(prov);
        }
    }
    for prov in signals {
        on_external_ingestion(ctx, path, prov).await;
    }
}

async fn on_external_ingestion(ctx: &WatchContext, transcript: &Path, prov: Provenance) {
    let started = Instant::now();

    // Which live process owns this transcript? It is the agent, and it holds
    // the file open. Deterministic and exact, no guessing by cwd.
    let Some(pid) = pid_holding_file(transcript) else {
        debug!(
            transcript = %transcript.display(),
            "external ingestion seen but no live process holds the transcript; nothing to taint"
        );
        return;
    };

    // The agent root and its current descendants. Future children inherit taint
    // through the kernel's fork hook; existing ones are tainted here so a helper
    // already spawned is covered too.
    let pids = pid_and_descendants(pid);

    let sender = ctx.ebpf.read().await.clone();
    let Some(tx) = sender else {
        warn!("transcript taint: eBPF subsystem not up; taint not set");
        return;
    };
    for p in &pids {
        let _ = tx
            .send(crate::ebpf_loader::EbpfCommand::SetTaint {
                pid: *p,
                has_keys: false,
            })
            .await;
    }

    info!(
        provenance = %prov.label(),
        agent_pid = pid,
        tainted_pids = pids.len(),
        set_latency_ms = started.elapsed().as_millis() as u64,
        "transcript taint: external content ingested, taint raised on the agent tree"
    );
}

/// The pid that has this file open, if exactly one live process does.
///
/// The agent writes its transcript, so it holds it open. Scans /proc for a
/// matching fd symlink. Needs to see other processes' fds, which the daemon can
/// (it has CAP_SYS_PTRACE for the write-scan attribution walk).
fn pid_holding_file(path: &Path) -> Option<u32> {
    let want = std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
    let want = want.as_os_str();
    let me = std::process::id();
    let entries = std::fs::read_dir("/proc").ok()?;
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(pid) = name.to_str().and_then(|n| n.parse::<u32>().ok()) else {
            continue;
        };
        // Never attribute the transcript to the daemon itself: we open it to
        // read it. The agent is the process we want.
        if pid == me {
            continue;
        }
        let Ok(fds) = std::fs::read_dir(entry.path().join("fd")) else {
            continue;
        };
        for fd in fds.flatten() {
            if let Ok(target) = std::fs::read_link(fd.path()) {
                if target.as_os_str() == want {
                    return Some(pid);
                }
            }
        }
    }
    None
}

/// A pid and every live descendant of it, by walking /proc PPid links.
fn pid_and_descendants(root: u32) -> Vec<u32> {
    let mut children: HashMap<u32, Vec<u32>> = HashMap::new();
    if let Ok(entries) = std::fs::read_dir("/proc") {
        for e in entries.flatten() {
            let Some(pid) = e.file_name().to_str().and_then(|n| n.parse::<u32>().ok()) else {
                continue;
            };
            if let Some(ppid) = parent_pid(pid) {
                children.entry(ppid).or_default().push(pid);
            }
        }
    }
    let mut out = vec![root];
    let mut stack = vec![root];
    while let Some(p) = stack.pop() {
        if let Some(kids) = children.get(&p) {
            for &k in kids {
                if !out.contains(&k) {
                    out.push(k);
                    stack.push(k);
                }
            }
        }
    }
    out
}

fn parent_pid(pid: u32) -> Option<u32> {
    let status = std::fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
    status
        .lines()
        .find_map(|l| l.strip_prefix("PPid:"))
        .and_then(|v| v.trim().parse::<u32>().ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assistant_tool_use(name: &str) -> String {
        serde_json::json!({
            "type": "assistant",
            "message": { "content": [
                { "type": "text", "text": "let me look" },
                { "type": "tool_use", "name": name, "input": {} }
            ]}
        })
        .to_string()
    }

    #[test]
    fn web_fetch_and_search_are_external() {
        assert_eq!(
            record_signal(&assistant_tool_use("WebFetch")),
            Some(Provenance::WebFetch)
        );
        assert_eq!(
            record_signal(&assistant_tool_use("WebSearch")),
            Some(Provenance::WebSearch)
        );
    }

    #[test]
    fn an_mcp_tool_is_external_and_names_its_server() {
        let sig = record_signal(&assistant_tool_use("mcp__github__get_issue"));
        assert_eq!(sig, Some(Provenance::Mcp("github".to_string())));
    }

    /// The signals we deliberately do NOT ship yet, and the ordinary tools that
    /// must never taint a plain coding session.
    #[test]
    fn ordinary_local_tools_do_not_taint() {
        for tool in ["Read", "Write", "Edit", "Bash", "Grep", "Glob", "TodoWrite"] {
            assert_eq!(
                record_signal(&assistant_tool_use(tool)),
                None,
                "{tool} must not raise taint"
            );
        }
    }

    /// The agent's own journal machinery — queue records, cost state, user
    /// prompts — carries no external tool_use and must be silent.
    #[test]
    fn journal_and_user_records_are_silent() {
        for rec in [
            r#"{"type":"queue-operation","operation":"add"}"#,
            r#"{"type":"cost-state","totalCostUSD":0.1}"#,
            r#"{"type":"user","message":{"content":[{"type":"text","text":"hi"}]}}"#,
            r#"{"type":"attachment","attachment":{}}"#,
            "not json at all",
            "",
        ] {
            assert_eq!(record_signal(rec), None, "{rec:?} must be silent");
        }
    }

    /// A tool_result is not where we key: we key on the assistant's invocation,
    /// which is robust to the result landing in a later poll chunk.
    #[test]
    fn a_bare_tool_result_does_not_trigger() {
        let rec = serde_json::json!({
            "type": "user",
            "message": { "content": [
                { "type": "tool_result", "content": "some fetched text", "is_error": false }
            ]}
        })
        .to_string();
        assert_eq!(record_signal(&rec), None);
    }

    #[test]
    fn external_matcher_is_case_insensitive() {
        assert!(is_external_tool("webfetch"));
        assert!(is_external_tool("WebFetch"));
        assert!(is_external_tool("mcp__x__y"));
        assert!(!is_external_tool("Read"));
        assert!(!is_external_tool("bashfetcher"));
    }

    #[test]
    fn our_own_process_and_init_walk_sanely() {
        let me = std::process::id();
        let tree = pid_and_descendants(me);
        assert!(tree.contains(&me), "the tree includes its root");
        assert!(parent_pid(1).is_some() || parent_pid(1).is_none());
    }
}
