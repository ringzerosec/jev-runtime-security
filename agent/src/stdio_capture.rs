// SPDX-License-Identifier: Apache-2.0
//
// Stdio capture — reads stdin/stdout/stderr from AI agent processes via eBPF.
//
// WHAT THIS READS, AND WHY THAT MATTERS. Terminal output is whatever the agent
// printed, which can include secrets it was legitimately working with: a token
// it echoed, a config file it cat'd, a key in an error message. Capture happens
// in the kernel, below the agent, so it does not depend on the agent
// cooperating — and for the same reason it sees things the agent never meant
// to show anyone.
//
// So: every fragment goes through the operator's redactor BEFORE it is stored
// on an event or scored, and the raw text is dropped at that point. Captured
// text only leaves the machine when the checks layer is enabled with a hosted
// provider AND the deterministic scorer has already flagged that fragment; see
// `JevProvider::score_agent_output`. It has its own config switch,
// `[stdio_capture] enabled`, so an operator can run kernel enforcement with no
// capture at all.
//
// WHAT IT CANNOT SEE. Matching is on the process name (`comm`), so an agent
// whose binary has been renamed is not tracked. That is a real limit and it is
// written down in README rather than implied away.
//
// For agents using stripped Rust binaries (like Codex) where SSL uprobes can't
// work, we hook sys_read/sys_write tracepoints filtered to fd 0/1/2 and capture
// the terminal I/O directly. Prompts arrive as stdin reads, responses as stdout writes.
//
// Architecture:
//   1. Load stdiocap.bpf.o (separate BPF program)
//   2. Attach tracepoints: sys_enter_read/write, sys_exit_read/write
//   3. Accept tracked PIDs via channel (from ebpf_loader agent detection)
//   4. Poll stdio_events ring buffer for captured I/O
//   5. Accumulate text per (pid, fd), flush after 500ms idle -> SecurityEvents

use std::collections::HashMap;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use aya::maps::{HashMap as AyaHashMap, RingBuf};
use aya::programs::TracePoint;
use aya::{BpfLoader, Btf};
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

use crate::common::event::{EventKind, SecurityEvent};

// ── Constants matching stdiocap.bpf.c ────────────────────────────────────────

const MAX_BUF_SIZE: usize = 8192;
const TASK_COMM_LEN: usize = 16;

/// Minimum captured bytes to emit an event (filters terminal noise).
const MIN_CAPTURE_LEN: usize = 10;

/// Flush accumulated text after this idle duration.
const FLUSH_TIMEOUT: Duration = Duration::from_millis(500);

/// Poll interval when ring buffer is empty.
const POLL_INTERVAL: Duration = Duration::from_millis(50);

/// How often the backstop sweep of /proc runs. It is a backstop: exec events
/// are what track a new agent promptly, and a short-lived process that starts
/// and exits inside one interval is exactly what the poll alone used to miss.
const POLL_BACKSTOP_INTERVAL: Duration = Duration::from_secs(4);

/// Max events to drain per poll cycle.
const MAX_DRAIN: u32 = 256;

// ── Event struct (must match struct stdio_event in stdiocap.bpf.c) ───────────

#[repr(C)]
#[derive(Clone, Copy)]
struct StdioCaptureEvent {
    timestamp_ns: u64,
    pid: u32,
    tid: u32,
    uid: u32,
    fd: i32,
    len: u32,
    buf_size: u32,
    is_read: u8,
    comm: [u8; TASK_COMM_LEN],
    buf: [u8; MAX_BUF_SIZE],
}

// ── Accumulation buffer per (pid, fd) ────────────────────────────────────────

struct AccumBuffer {
    text: String,
    pid: u32,
    uid: u32,
    comm: String,
    is_read: bool,
    last_active: Instant,
}

// ── ANSI escape filter ──────────────────────────────────────────────────────

/// Returns true if the text is predominantly ANSI control sequences / noise.
fn is_control_noise(s: &str) -> bool {
    if s.is_empty() {
        return true;
    }
    let control_bytes = s
        .bytes()
        .filter(|&b| b == 0x1b || b < 0x20 && b != b'\n' && b != b'\t')
        .count();
    // If more than 50% is control chars, treat as noise
    control_bytes * 2 > s.len()
}

/// Strip ANSI escape sequences from text.
fn strip_ansi(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\x1b' {
            // Skip CSI sequences: ESC [ ... final_byte
            if chars.peek() == Some(&'[') {
                chars.next();
                while let Some(&nc) = chars.peek() {
                    chars.next();
                    if nc.is_ascii_alphabetic() || nc == '~' {
                        break;
                    }
                }
            }
            // Skip OSC: ESC ] ... ST
            else if chars.peek() == Some(&']') {
                chars.next();
                while let Some(&nc) = chars.peek() {
                    chars.next();
                    if nc == '\x07' || nc == '\\' {
                        break;
                    }
                }
            }
        } else {
            out.push(c);
        }
    }
    out
}

// ── Public API ──────────────────────────────────────────────────────────────

/// Spawn the stdio capture subsystem as a background task.
///
/// `event_tx` — channel for emitting SecurityEvents to the main event loop.
/// `pid_rx`   — receives tracked agent PIDs from ebpf_loader / process scanner.
// ── Score cache ─────────────────────────────────────────────────────────────
//
// Terminal output repeats: a progress line, a prompt redrawn, the same error
// twice. Keyed on the hash of the redacted text, so identical output is scored
// once. Bounded and swept, because an agent can print unbounded distinct text.

const SCORE_CACHE_TTL: Duration = Duration::from_secs(300);
const SCORE_CACHE_MAX: usize = 512;

static SCORE_CACHE: std::sync::OnceLock<
    std::sync::Mutex<HashMap<String, (Instant, ringzero_checks::CheckResult)>>,
> = std::sync::OnceLock::new();

fn score_cache(
) -> &'static std::sync::Mutex<HashMap<String, (Instant, ringzero_checks::CheckResult)>> {
    SCORE_CACHE.get_or_init(|| std::sync::Mutex::new(HashMap::new()))
}

fn score_cached(hash: &str) -> Option<ringzero_checks::CheckResult> {
    let cache = score_cache().lock().ok()?;
    let (at, result) = cache.get(hash)?;
    (at.elapsed() < SCORE_CACHE_TTL).then(|| result.clone())
}

fn remember_score(hash: &str, result: &ringzero_checks::CheckResult) {
    let Ok(mut cache) = score_cache().lock() else {
        return;
    };
    if cache.len() >= SCORE_CACHE_MAX {
        cache.retain(|_, (at, _)| at.elapsed() < SCORE_CACHE_TTL);
        if cache.len() >= SCORE_CACHE_MAX {
            cache.clear();
        }
    }
    cache.insert(hash.to_string(), (Instant::now(), result.clone()));
}

/// What the capture does with a fragment once it has one.
#[derive(Clone)]
pub struct CaptureContext {
    /// The operator's redactor. Runs over every fragment before anything is
    /// stored or scored; there is no path that skips it.
    pub redact: std::sync::Arc<dyn Fn(&mut serde_json::Value) + Send + Sync>,
    /// The checks layer, when it is enabled and asked to score capture.
    pub scorer: Option<std::sync::Arc<crate::checks_provider::ScoringProvider>>,
    /// Longest stored fragment, after redaction.
    pub max_event_bytes: usize,
    /// Where a flagged fragment goes for a human to label.
    pub review: Option<std::sync::Arc<crate::review::ReviewQueue>>,
    /// The hostname allowlist, fed from observed DNS answers.
    pub dns: Option<std::sync::Arc<tokio::sync::Mutex<crate::dns_allow::DnsAllowManager>>>,
}

pub fn spawn(
    event_tx: mpsc::Sender<SecurityEvent>,
    pid_rx: mpsc::Receiver<u32>,
    ctx: CaptureContext,
) {
    tokio::spawn(async move {
        if let Err(e) = run(event_tx, pid_rx, ctx).await {
            warn!(err = %e, "stdio capture exited");
        }
    });
}

async fn run(
    event_tx: mpsc::Sender<SecurityEvent>,
    mut pid_rx: mpsc::Receiver<u32>,
    ctx: CaptureContext,
) -> Result<()> {
    if unsafe { libc::geteuid() } != 0 {
        anyhow::bail!("stdio capture requires root");
    }

    let bpf_path = std::env::var("RINGZERO_STDIOCAP_PATH")
        .unwrap_or_else(|_| "/usr/lib/ringzero/stdiocap.bpf.o".to_string());

    info!(path = %bpf_path, "Loading stdiocap BPF program");

    let btf = Btf::from_sys_fs().context("Failed to load BTF for stdiocap")?;

    let mut bpf = BpfLoader::new()
        .btf(Some(&btf))
        .load_file(&bpf_path)
        .context("Failed to load stdiocap.bpf.o")?;

    // ── Attach tracepoints ──────────────────────────────────────────────────

    let tracepoints = [
        ("trace_enter_read", "syscalls", "sys_enter_read"),
        ("trace_exit_read", "syscalls", "sys_exit_read"),
        ("trace_enter_write", "syscalls", "sys_enter_write"),
        ("trace_exit_write", "syscalls", "sys_exit_write"),
        // DNS answer capture rides in the same object: it needs the same
        // enter/exit tracepoint machinery and the same tracked-pid set.
        ("trace_enter_recvfrom", "syscalls", "sys_enter_recvfrom"),
        ("trace_exit_recvfrom", "syscalls", "sys_exit_recvfrom"),
    ];

    let mut attached = 0u32;
    // Keep links alive for the lifetime of the program
    let mut _links: Vec<aya::programs::trace_point::TracePointLinkId> = Vec::new();

    for (name, category, tp_name) in &tracepoints {
        let prog = bpf
            .program_mut(name)
            .with_context(|| format!("BPF program '{}' not found", name))?;
        let tp: &mut TracePoint = prog
            .try_into()
            .with_context(|| format!("'{}' is not a TracePoint program", name))?;
        tp.load()?;
        let link = tp
            .attach(category, tp_name)
            .with_context(|| format!("Failed to attach tracepoint {}/{}", category, tp_name))?;
        _links.push(link);
        attached += 1;
    }

    info!(count = attached, "stdio capture tracepoints attached");

    // ── Take ownership of maps ──────────────────────────────────────────────

    let tracked_pids_map = bpf
        .take_map("tracked_pids")
        .context("tracked_pids map not found in stdiocap.bpf.o")?;
    let mut tracked_pids = AyaHashMap::<_, u32, u8>::try_from(tracked_pids_map)
        .context("Failed to create HashMap from tracked_pids")?;

    let events_map = bpf
        .take_map("stdio_events")
        .context("stdio_events ring buffer not found in stdiocap.bpf.o")?;
    let mut ring_buf =
        RingBuf::try_from(events_map).context("Failed to create RingBuf from stdio_events")?;

    let mut dns_ring = bpf
        .take_map("dns_events")
        .and_then(|m| RingBuf::try_from(m).ok());
    if dns_ring.is_some() {
        info!("DNS answer capture attached (source port 53, tracked agents only)");
    } else {
        warn!("dns_events ring buffer unavailable — hostname allowlisting will not learn");
    }

    info!("stdio capture polling started");

    // ── Event loop ──────────────────────────────────────────────────────────

    let mut accum: HashMap<(u32, i32), AccumBuffer> = HashMap::new();

    loop {
        // Accept any new tracked PIDs (non-blocking drain)
        while let Ok(pid) = pid_rx.try_recv() {
            if tracked_pids.insert(pid, 1u8, 0).is_ok() {
                debug!(pid, "stdio: tracking agent PID");
            }
        }

        // Drain DNS answers. Each is fed to the name allowlist, which admits
        // the addresses that answered for an allowlisted name.
        if let Some(rb) = dns_ring.as_mut() {
            let mut n = 0u32;
            while n < 64 {
                let Some(item) = rb.next() else { break };
                n += 1;
                let data: &[u8] = item.as_ref();
                // timestamp_ns(8) + pid(4) + len(4) then the payload.
                if data.len() < 16 {
                    continue;
                }
                let len = u32::from_ne_bytes([data[12], data[13], data[14], data[15]]) as usize;
                let end = 16 + len.min(data.len().saturating_sub(16));
                if len == 0 || end <= 16 {
                    continue;
                }
                if let Some(dns) = ctx.dns.as_ref() {
                    dns.lock().await.observe_response(&data[16..end]).await;
                }
            }
        }

        // Drain ring buffer
        let mut drained = 0u32;
        while drained < MAX_DRAIN {
            let item = match ring_buf.next() {
                Some(item) => item,
                None => break,
            };

            drained += 1;
            let data: &[u8] = item.as_ref();

            if data.len() < std::mem::size_of::<StdioCaptureEvent>() {
                continue;
            }

            let event: &StdioCaptureEvent =
                unsafe { &*(data.as_ptr() as *const StdioCaptureEvent) };

            let buf_size = (event.buf_size as usize).min(MAX_BUF_SIZE);
            if buf_size < MIN_CAPTURE_LEN {
                continue;
            }

            // Only process valid UTF-8 text
            let raw = &event.buf[..buf_size];
            let text = match std::str::from_utf8(raw) {
                Ok(s) => s,
                Err(_) => continue,
            };

            let cleaned = strip_ansi(text);
            if is_control_noise(&cleaned) || cleaned.trim().len() < MIN_CAPTURE_LEN {
                continue;
            }

            let comm = std::str::from_utf8(&event.comm)
                .unwrap_or("")
                .trim_end_matches('\0')
                .to_string();

            let key = (event.pid, event.fd);
            let entry = accum.entry(key).or_insert_with(|| AccumBuffer {
                text: String::new(),
                pid: event.pid,
                uid: event.uid,
                comm: comm.clone(),
                is_read: event.is_read != 0,
                last_active: Instant::now(),
            });

            entry.text.push_str(&cleaned);
            entry.last_active = Instant::now();
        }

        // Flush stale buffers
        let now = Instant::now();
        let mut to_flush = Vec::new();
        for (&key, buf) in &accum {
            if now.duration_since(buf.last_active) >= FLUSH_TIMEOUT && !buf.text.is_empty() {
                to_flush.push(key);
            }
        }

        for key in to_flush {
            if let Some(buf) = accum.remove(&key) {
                let raw = buf.text.trim().to_string();
                if raw.len() < MIN_CAPTURE_LEN {
                    continue;
                }

                // REDACT FIRST. Everything below this line works on the
                // redacted text; `raw` is dropped at the end of this block and
                // is never stored, logged or sent.
                let mut as_json = serde_json::Value::String(raw);
                (ctx.redact)(&mut as_json);
                let mut trimmed = match as_json {
                    serde_json::Value::String(s) => s,
                    // A redactor that returned something else has changed the
                    // shape out from under us; drop the fragment rather than
                    // guess what it meant.
                    _ => {
                        warn!("stdio capture: redactor did not return text; fragment dropped");
                        continue;
                    }
                };
                let truncated = trimmed.len() > ctx.max_event_bytes;
                if truncated {
                    // Cut on a character boundary.
                    let mut end = ctx.max_event_bytes;
                    while end > 0 && !trimmed.is_char_boundary(end) {
                        end -= 1;
                    }
                    trimmed.truncate(end);
                    trimmed.push_str(" …[truncated]");
                }

                // Score it, off the hot path: this is a flush boundary, well
                // after the write happened, and nothing waits on the answer.
                // One score per flush, not per fragment, and repeated identical
                // output is answered from the cache.
                let verdict = match (&ctx.scorer, buf.is_read) {
                    // Only output is scored. What the agent READ from the
                    // terminal is the operator typing, not the agent speaking.
                    (Some(scorer), false) => {
                        let scorer = scorer.clone();
                        let text = trimmed.clone();
                        let hash = blake3::hash(text.as_bytes()).to_hex().to_string();
                        match score_cached(&hash) {
                            Some(cached) => Some(cached),
                            None => {
                                let r = tokio::task::spawn_blocking(move || {
                                    scorer.score_agent_output(&text)
                                })
                                .await
                                .ok();
                                if let Some(ref r) = r {
                                    remember_score(&hash, r);
                                }
                                r
                            }
                        }
                    }
                    _ => None,
                };

                // Terminal text, not an LLM API exchange. Emitting LlmRequest /
                // LlmResponse here made the stream unreadable: a captured
                // stdout line looked exactly like a model response.
                let kind = if buf.is_read {
                    EventKind::AgentStdin
                } else {
                    EventKind::AgentStdout
                };

                let fd_label = match key.1 {
                    0 => "stdin",
                    1 => "stdout",
                    2 => "stderr",
                    _ => "unknown",
                };

                let event = SecurityEvent {
                    id: format!(
                        "stdio-{}-{}-{}",
                        if buf.is_read { "in" } else { "out" },
                        buf.pid,
                        chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0),
                    ),
                    kind,
                    pid: buf.pid,
                    uid: buf.uid,
                    process: buf.comm.clone(),
                    target: format!("fd:{} ({})", key.1, fd_label),
                    allowed: true,
                    reason: Some(trimmed),
                    timestamp: chrono::Utc::now(),
                    ppid: None,
                    parent_process: None,
                    llm_context: None,
                    extra: verdict.as_ref().and_then(|v| {
                        serde_json::to_value(v)
                            .ok()
                            .map(|v| serde_json::json!({ "check": v, "truncated": truncated }))
                    }),
                };

                // A flagged fragment is a lead for a human, not a verdict.
                if let (Some(v), Some(review)) = (&verdict, &ctx.review) {
                    if ringzero_checks::thresholds::current()
                        .worth_queueing(&v.option, v.probability)
                    {
                        let _ = review.push(
                            crate::review::Source::CheckFlag,
                            "",
                            format!(
                                "Agent {} output scored {} (p={:.2}, {})",
                                buf.comm, v.option, v.probability, v.provider
                            ),
                            serde_json::json!({
                                "source": "stdio_capture",
                                "pid": buf.pid,
                                "process": buf.comm,
                                "check": v,
                            }),
                        );
                    }
                }

                if event_tx.send(event).await.is_err() {
                    warn!("stdio capture: event channel closed, exiting");
                    return Ok(());
                }
            }
        }

        tokio::time::sleep(POLL_INTERVAL).await;
    }
}

/// Spawn stdio capture with automatic agent discovery.
///
/// TWO WAYS A PID GETS TRACKED, and the first one is why this is not just a
/// poll:
///
///   exec  — `exec_tx` carries pids the kernel told us about as they exec.
///           An agent is tracked the moment it starts, so its first output is
///           captured. The four-second poll alone missed anything that started
///           and finished inside one interval, which is most short commands.
///   poll  — every few seconds, for processes that were already running when
///           the daemon started, and as a backstop if an exec event is missed.
///
/// MATCHING IS ON THE PROCESS NAME. A renamed binary is not tracked. This is
/// stated in README rather than papered over; it is the same limit the kernel's
/// own comm-based agent detection has.
pub fn spawn_auto(event_tx: mpsc::Sender<SecurityEvent>, ctx: CaptureContext) -> mpsc::Sender<u32> {
    let (pid_tx, pid_rx) = mpsc::channel::<u32>(256);

    // The caller hands this back to whatever sees exec events, so a new agent
    // is tracked immediately instead of up to one poll interval later.
    let exec_tx = pid_tx.clone();

    tokio::spawn(async move {
        let mut seen: std::collections::HashSet<u32> = std::collections::HashSet::new();
        loop {
            if let Ok(proc_dir) = std::fs::read_dir("/proc") {
                for entry in proc_dir.flatten() {
                    let name = entry.file_name();
                    let Ok(pid) = name.to_string_lossy().parse::<u32>() else {
                        continue;
                    };
                    if seen.contains(&pid) {
                        continue;
                    }
                    let comm =
                        std::fs::read_to_string(format!("/proc/{}/comm", pid)).unwrap_or_default();
                    let comm = comm.trim();
                    if comm.is_empty() {
                        continue;
                    }
                    // One list of agent names for the whole daemon, so this
                    // cannot drift from what the rest of it calls an agent.
                    if crate::common::agent_detect::is_ai_agent(comm) {
                        seen.insert(pid);
                        let _ = pid_tx.try_send(pid);
                        debug!(pid, comm, "stdio capture: tracking agent PID (poll)");
                    }
                }
            }
            // Keep the set from growing without bound on a long-lived daemon.
            if seen.len() > 4096 {
                seen.retain(|pid| std::path::Path::new(&format!("/proc/{pid}")).exists());
            }
            tokio::time::sleep(POLL_BACKSTOP_INTERVAL).await;
        }
    });

    spawn(event_tx, pid_rx, ctx);
    exec_tx
}

/// Offer a freshly exec'd pid to the capture, if it looks like an agent.
///
/// Called from the kernel event path, which sees an exec as it happens. Cheap
/// and non-blocking: a full channel drops the pid rather than stalling the
/// event loop, and the poll will pick it up if it is still running.
pub fn offer_exec_pid(tx: &mpsc::Sender<u32>, pid: u32, comm: &str) {
    if !crate::common::agent_detect::is_ai_agent(comm) {
        return;
    }
    if tx.try_send(pid).is_ok() {
        debug!(pid, comm, "stdio capture: tracking agent PID (exec)");
    }
}
