// SPDX-License-Identifier: Apache-2.0
// narrator.rs — live commentary on what agents are doing, in plain sentences.
//
// Every event the daemon records passes through `observe` (from
// Timeline::insert), and every new transcript line through
// `observe_transcript`. Most produce nothing. The ones a person would want to
// hear about become one short line: what the agent was asked, what it is
// thinking, which files it reads and writes, what it runs, and above all what
// Ring Zero Security refused.
//
// The app reads the lines over GET /api/v1/commentary, shows them as captions
// and speaks them. Each line has a level so the speaker can choose: an `Alert`
// (something was refused) cuts in; `Info` may be skipped when the agent is
// busier than anyone can listen to.
//
// Deterministic on purpose: the words come from templates over facts the
// daemon already has, so a line can never claim something that did not
// happen. Every line passes through the secret detector before it is stored,
// so a key in a prompt or a message is never read aloud.

use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use serde::Serialize;

use crate::common::event::{EventKind, SecurityEvent};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, PartialOrd, Ord)]
#[serde(rename_all = "lowercase")]
pub enum Level {
    /// Routine progress. May be dropped by the speaker when lines pile up.
    Info,
    /// Worth hearing: a sensitive read, something outside the agent's limits.
    Notice,
    /// Ring Zero Security refused something. Always spoken, interrupts.
    Alert,
}

#[derive(Debug, Clone, Serialize)]
pub struct Line {
    pub seq: u64,
    pub at: chrono::DateTime<chrono::Utc>,
    pub level: Level,
    /// The agent this is about, as people name it ("Claude Code").
    pub agent: String,
    /// What kind of moment: task, thinking, read, write, run, web, tool,
    /// done, blocked, sensitive, watching.
    pub kind: &'static str,
    pub text: String,
}

const KEEP: usize = 200;
/// Programs too routine to mention: shells and text plumbing an agent runs
/// constantly. Saying them would drown out everything else.
const QUIET_PROGRAMS: &[&str] = &[
    "sh", "bash", "dash", "zsh", "fish", "env", "which", "uname", "cat", "ls", "head", "tail", "sed",
    "awk", "gawk", "grep", "rg", "find", "fd", "wc", "sort", "uniq", "tr", "cut", "dirname", "basename",
    "readlink", "realpath", "stat", "date", "id", "whoami", "true", "false", "test", "[", "printf",
    "echo", "tee", "xargs", "mkdir", "touch", "file", "less", "more", "tput", "stty", "locale", "ps",
    "pgrep", "sleep", "nproc", "getconf", "hostname", "pwd", "diff", "cmp", "sha256sum", "md5sum",
];
/// The same sentence is not repeated within this window.
const REPEAT_WINDOW: Duration = Duration::from_secs(20);
/// Reads are gathered and told as one line after this much quiet.
const READ_FLUSH: Duration = Duration::from_millis(2500);
/// Thinking is narrated at most this often per agent.
const THINKING_GAP: Duration = Duration::from_secs(8);

struct PendingReads {
    agent: String,
    files: Vec<String>,
    since: Instant,
}

struct State {
    seq: u64,
    lines: VecDeque<Line>,
    recent_text: HashMap<String, Instant>,
    reads: Option<PendingReads>,
    last_thinking: HashMap<String, Instant>,
    sessions_seen: HashMap<String, Instant>,
    /// Rebuilding a session's commentary from stored events: no repeat
    /// suppression, and each line takes its event's time.
    replay: bool,
    stamp: Option<chrono::DateTime<chrono::Utc>>,
}

pub struct Narrator {
    state: Mutex<State>,
    notify: tokio::sync::Notify,
}

pub static NARRATOR: once_cell::sync::Lazy<Narrator> = once_cell::sync::Lazy::new(|| Narrator {
    state: Mutex::new(State {
        seq: 0,
        lines: VecDeque::with_capacity(KEEP),
        recent_text: HashMap::new(),
        reads: None,
        last_thinking: HashMap::new(),
        sessions_seen: HashMap::new(),
        replay: false,
        stamp: None,
    }),
    notify: tokio::sync::Notify::new(),
});

impl Narrator {
    /// Lines after `after`, oldest first, and the newest sequence number.
    pub fn since(&self, after: u64) -> (Vec<Line>, u64) {
        self.flush_due_reads();
        let st = self.state.lock().unwrap_or_else(|e| e.into_inner());
        let lines = st.lines.iter().filter(|l| l.seq > after).cloned().collect();
        (lines, st.seq)
    }

    /// Wait until a line newer than `after` exists, or the timeout passes.
    pub async fn wait(&self, after: u64, timeout: Duration) -> (Vec<Line>, u64) {
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            let (lines, last) = self.since(after);
            if !lines.is_empty() {
                return (lines, last);
            }
            let notified = self.notify.notified();
            // Wake at least every READ_FLUSH so gathered reads are told on time.
            let step = std::cmp::min(deadline, tokio::time::Instant::now() + READ_FLUSH);
            if tokio::time::timeout_at(step, notified).await.is_err() && tokio::time::Instant::now() >= deadline {
                return self.since(after);
            }
        }
    }

    fn push(&self, st: &mut State, level: Level, agent: &str, kind: &'static str, text: String) {
        let text = speakable(&text);
        if text.is_empty() {
            return;
        }
        let now = Instant::now();
        if !st.replay {
            st.recent_text.retain(|_, t| now.duration_since(*t) < REPEAT_WINDOW);
            if st.recent_text.contains_key(&text) {
                return;
            }
            st.recent_text.insert(text.clone(), now);
        } else if st.lines.back().is_some_and(|l| l.text == text) {
            return; // the same sentence twice in a row says nothing new
        }
        st.seq += 1;
        let at = st.stamp.unwrap_or_else(chrono::Utc::now);
        let line = Line { seq: st.seq, at, level, agent: agent.to_string(), kind, text };
        if !st.replay && st.lines.len() >= KEEP {
            st.lines.pop_front();
        }
        st.lines.push_back(line);
        self.notify.notify_waiters();
    }

    /// Tell gathered reads as one line.
    fn flush_reads(&self, st: &mut State) {
        if let Some(r) = st.reads.take() {
            let text = match r.files.len() {
                0 => return,
                1 => format!("It's reading {}.", r.files[0]),
                2 => format!("It's reading {} and {}.", r.files[0], r.files[1]),
                n => format!("It's reading {}, {} and {} more.", r.files[0], r.files[1], n - 2),
            };
            self.push(st, Level::Info, &r.agent, "read", text);
        }
    }

    fn flush_due_reads(&self) {
        let mut st = self.state.lock().unwrap_or_else(|e| e.into_inner());
        if st.reads.as_ref().is_some_and(|r| r.since.elapsed() >= READ_FLUSH) {
            self.flush_reads(&mut st);
        }
    }

    /// Rebuild the commentary for a set of stored events, oldest first.
    pub fn replay(events: &[SecurityEvent]) -> Vec<Line> {
        let n = Narrator {
            state: Mutex::new(State {
                seq: 0,
                lines: VecDeque::new(),
                recent_text: HashMap::new(),
                reads: None,
                last_thinking: HashMap::new(),
                sessions_seen: HashMap::new(),
                replay: true,
                stamp: None,
            }),
            notify: tokio::sync::Notify::new(),
        };
        let mut sorted: Vec<&SecurityEvent> = events.iter().collect();
        sorted.sort_by_key(|e| e.timestamp);
        for e in sorted {
            n.observe(e);
        }
        let mut st = n.state.lock().unwrap_or_else(|e| e.into_inner());
        n.flush_reads(&mut st);
        st.lines.iter().cloned().collect()
    }

    /// Every recorded event comes through here.
    pub fn observe(&self, ev: &SecurityEvent) {
        let mut st = self.state.lock().unwrap_or_else(|e| e.into_inner());
        if st.replay {
            st.stamp = Some(ev.timestamp);
        }
        let agent = agent_name(&ev.process);
        let extra = ev.extra.as_ref();

        // A new agent session: say where it started.
        if let Some(sid) = extra.and_then(|x| x.get("agent_session_id")).and_then(|v| v.as_str()) {
            let now = Instant::now();
            st.sessions_seen.retain(|_, t| now.duration_since(*t) < Duration::from_secs(6 * 3600));
            if !st.sessions_seen.contains_key(sid) {
                st.sessions_seen.insert(sid.to_string(), now);
                let place = extra
                    .and_then(|x| x.get("cwd"))
                    .and_then(|v| v.as_str())
                    .map(|c| base_name(c))
                    .filter(|c| !c.is_empty());
                let text = match place {
                    Some(p) => format!("{agent} is at work in {p}."),
                    None => format!("{agent} is at work."),
                };
                self.push(&mut st, Level::Info, &agent, "start", text);
            }
        }

        match ev.kind {
            EventKind::LlmRequest => {
                self.flush_reads(&mut st);
                if ev.target.ends_with(":prompt-secret") {
                    let (level, text) = if ev.allowed {
                        (Level::Notice, "There's a secret in that prompt. Ring Zero Security masked it in the record.".to_string())
                    } else {
                        (Level::Alert, "That prompt had a secret in it. Ring Zero Security stopped it before it left this machine.".to_string())
                    };
                    self.push(&mut st, level, &agent, "blocked", text);
                    return;
                }
                if let Some(p) = ev.llm_context.as_ref().and_then(|c| c.response_text.as_deref()) {
                    let gist = first_sentence(p, 16);
                    if !gist.is_empty() {
                        self.push(&mut st, Level::Info, &agent, "task", format!("New task: {gist}"));
                    }
                }
            }
            EventKind::LlmToolCall => {
                let phase = extra.and_then(|x| x.get("phase")).and_then(|v| v.as_str()).unwrap_or("");
                let denied = extra
                    .and_then(|x| x.get("hook_decision"))
                    .and_then(|d| d.get("blocked"))
                    .and_then(|b| b.as_bool())
                    .unwrap_or(false);
                if denied {
                    self.flush_reads(&mut st);
                    let rule = extra
                        .and_then(|x| x.get("hook_decision"))
                        .and_then(|d| d.get("rule"))
                        .and_then(|r| r.as_str())
                        .unwrap_or("it broke a rule");
                    self.push(&mut st, Level::Alert, &agent, "blocked", format!("Ring Zero Security refused that {} call: {}.", ev.target, rule));
                    return;
                }
                // Narrate the intent, not the result: PreToolUse only.
                if phase == "result" || extra.and_then(|x| x.get("hook")).and_then(|v| v.as_str()) == Some("PostToolUse") {
                    return;
                }
                let input = extra.and_then(|x| x.get("tool_input"));
                self.narrate_tool(&mut st, &agent, &ev.target, input);
            }
            EventKind::LlmResponse => {
                self.flush_reads(&mut st);
                if let Some(t) = ev.llm_context.as_ref().and_then(|c| c.response_text.as_deref()) {
                    let gist = first_sentence(t, 18);
                    if !gist.is_empty() {
                        self.push(&mut st, Level::Info, &agent, "done", format!("Finished. {gist}"));
                    }
                }
            }
            _ => self.narrate_kernel(&mut st, &agent, ev),
        }
    }

    fn narrate_tool(&self, st: &mut State, agent: &str, tool: &str, input: Option<&serde_json::Value>) {
        let s = |k: &str| input.and_then(|i| i.get(k)).and_then(|v| v.as_str()).unwrap_or("");
        match tool {
            "Read" | "Glob" | "Grep" | "LS" | "NotebookRead" => {
                let what = match tool {
                    "Read" | "NotebookRead" => base_name(if s("file_path").is_empty() { s("notebook_path") } else { s("file_path") }),
                    "Grep" => format!("code mentioning {}", trim_words(s("pattern"), 4)),
                    _ => {
                        let p = if s("pattern").is_empty() { s("path") } else { s("pattern") };
                        if p.is_empty() { "the project files".into() } else { p.to_string() }
                    }
                };
                let pending = st.reads.get_or_insert_with(|| PendingReads { agent: agent.to_string(), files: Vec::new(), since: Instant::now() });
                if !pending.files.contains(&what) {
                    pending.files.push(what);
                }
                pending.since = Instant::now();
                return;
            }
            _ => {}
        }
        self.flush_reads(st);
        let (kind, text) = match tool {
            "Write" => ("write", format!("It's writing a new file, {}.", base_name(s("file_path")))),
            "Edit" | "MultiEdit" | "NotebookEdit" => {
                let f = if s("file_path").is_empty() { s("notebook_path") } else { s("file_path") };
                ("write", format!("It's changing {}.", base_name(f)))
            }
            "Bash" => ("run", describe_command(s("command"))),
            "WebFetch" => ("web", format!("It's fetching a page from {}.", host_of(s("url")))),
            "WebSearch" => ("web", format!("It's searching the web for {}.", trim_words(s("query"), 8))),
            "Task" | "Agent" => ("tool", "It's handing part of the work to a helper agent.".into()),
            "TodoWrite" => ("tool", "It's updating its plan.".into()),
            t if t.starts_with("mcp__") => {
                let mut parts = t.splitn(3, "__").skip(1);
                let server = parts.next().unwrap_or("an MCP");
                let action = parts.next().unwrap_or("a tool").replace('_', " ");
                ("tool", format!("It's asking the {server} server to {action}."))
            }
            other => ("tool", format!("It's using its {other} tool.")),
        };
        self.push(st, Level::Info, agent, kind, text);
    }

    fn narrate_kernel(&self, st: &mut State, agent: &str, ev: &SecurityEvent) {
        // A kernel event names the process that made the call (cat, curl).
        // Speak about the agent it belongs to instead.
        let owned;
        let agent = if is_known_agent(agent) {
            agent
        } else {
            owned = ev
                .parent_process
                .as_deref()
                .map(agent_name)
                .filter(|a| is_known_agent(a))
                .unwrap_or_else(|| "The agent".to_string());
            owned.as_str()
        };
        let name = base_name(&ev.target);
        let lower = name.to_ascii_lowercase();

        if ev.target.starts_with("TAMPER:") {
            self.flush_reads(st);
            self.push(st, Level::Alert, "Ring Zero Security", "blocked", "Something tried to stop or inspect Ring Zero Security itself. Refused.".into());
            return;
        }

        // First word from an agent without hooks: say it is working.
        if is_known_agent(agent) && agent != "Claude Code" {
            let key = format!("kernel:{agent}");
            let now = Instant::now();
            if !st.sessions_seen.get(&key).is_some_and(|t| now.duration_since(*t) < Duration::from_secs(1800)) {
                st.sessions_seen.insert(key, now);
                self.push(st, Level::Info, agent, "start", format!("{agent} is at work."));
            }
        }

        if !ev.allowed {
            self.flush_reads(st);
            let text = match ev.kind {
                EventKind::ProcessExec => {
                    let prog = lower.split_whitespace().next().unwrap_or("").to_string();
                    match prog.as_str() {
                        "sudo" | "su" | "pkexec" | "doas" | "run0" => format!("{agent} just tried to become an administrator with {prog}. Ring Zero Security refused."),
                        "systemd-run" | "at" | "batch" | "crontab" => format!("{agent} tried to slip work out of its own process with {prog}. Ring Zero Security refused."),
                        _ => format!("{agent} tried to run {prog}, which isn't on its approved list. Blocked."),
                    }
                }
                EventKind::NetworkConnect | EventKind::NetworkSend | EventKind::DnsQuery => {
                    let host = ev.target.rsplit_once(':').map(|(h, _)| h).unwrap_or(&ev.target);
                    format!("{agent} tried to connect to {host}, which isn't approved. Blocked.")
                }
                _ => match describe_protected(&lower, &ev.kind) {
                    Some(t) => format!("{agent} just tried to {t}. Blocked by Ring Zero Security."),
                    None => {
                        let verb = match ev.kind {
                            EventKind::FileCreate => "create",
                            EventKind::FileDelete => "delete",
                            EventKind::FileRename => "move",
                            EventKind::FileWrite => "change",
                            _ => "read",
                        };
                        format!("{agent} tried to {verb} {name}, which is protected. Blocked.")
                    }
                },
            };
            self.push(st, Level::Alert, agent, "blocked", text);
            return;
        }

        // Any agent, from what the kernel saw: first say it is working, then
        // the programs it runs and the files it saves. This is what makes the
        // commentary work for agents without hooks or a transcript we read.
        // Claude Code reports its own commands and edits through hooks, which
        // say more; the kernel lines would only repeat them.
        if is_known_agent(agent) && agent != "Claude Code" {
            match ev.kind {
                EventKind::ProcessExec => {
                    let prog = lower.split_whitespace().next().unwrap_or("").to_string();
                    if !prog.is_empty() && !QUIET_PROGRAMS.contains(&prog.as_str()) && !is_known_agent(&agent_name(&prog)) {
                        self.flush_reads(st);
                        self.push(st, Level::Info, agent, "run", format!("{agent} is running {prog}."));
                    }
                }
                EventKind::FileWrite if ev.reason.as_deref().is_some_and(|r| r.starts_with("agent-written file")) => {
                    self.flush_reads(st);
                    self.push(st, Level::Info, agent, "write", format!("{agent} saved {name}."));
                }
                _ => {}
            }
        }

        // Allowed, but worth hearing.
        if let Some(r) = ev.reason.as_deref() {
            if let Some(rest) = r.strip_prefix("Outside limits (watching) — ") {
                let what = rest.split_once(": ").map(|(_, d)| d).unwrap_or(rest);
                self.push(st, Level::Notice, agent, "watching", format!("Heads up: it {what}. Ring Zero Security is only watching this one, so it went through."));
                return;
            }
        }
        if matches!(ev.kind, EventKind::FileOpen) && crate::enforcement::classify(ev) == Some("credential_access") {
            self.flush_reads(st);
            self.push(st, Level::Notice, agent, "sensitive", format!("It opened {name}, which looks like a credential."));
        }
    }

    /// One new line of an agent's transcript (JSONL). Thinking and running
    /// text become a short "thinking" line, at most every few seconds.
    pub fn observe_transcript(&self, agent: &str, v: &serde_json::Value) {
        if v.get("type").and_then(|t| t.as_str()) != Some("assistant") {
            return;
        }
        let Some(blocks) = v.pointer("/message/content").and_then(|c| c.as_array()) else { return };
        let text = blocks.iter().find_map(|b| match b.get("type").and_then(|t| t.as_str()) {
            Some("thinking") => b.get("thinking").and_then(|t| t.as_str()).filter(|t| !t.trim().is_empty()),
            Some("text") => b.get("text").and_then(|t| t.as_str()).filter(|t| !t.trim().is_empty()),
            _ => None,
        });
        let Some(text) = text else { return };
        let agent = agent_name(agent);
        let mut st = self.state.lock().unwrap_or_else(|e| e.into_inner());
        let now = Instant::now();
        if st.last_thinking.get(&agent).is_some_and(|t| now.duration_since(*t) < THINKING_GAP) {
            return;
        }
        let gist = first_sentence(text, 16);
        if gist.is_empty() {
            return;
        }
        st.last_thinking.insert(agent.clone(), now);
        self.flush_reads(&mut st);
        self.push(&mut st, Level::Info, &agent, "thinking", format!("Thinking: {gist}"));
    }
}

/// What a refused file action means, in words a person uses.
fn describe_protected(name: &str, kind: &EventKind) -> Option<String> {
    let verb = match kind {
        EventKind::FileCreate => "create",
        EventKind::FileDelete => "delete",
        EventKind::FileRename => "move",
        EventKind::FileWrite => "change",
        _ => "read",
    };
    let thing = if name.starts_with("id_rsa") || name.starts_with("id_ed25519") || name.starts_with("id_ecdsa") || name == "authorized_keys" {
        "your SSH key"
    } else if name.starts_with(".env") {
        "a .env file full of secrets"
    } else if name == "credentials" || name == ".git-credentials" || name == ".netrc" || name == ".npmrc" || name == ".pypirc" {
        "your saved credentials"
    } else if name == "api-token" || name == "daemon.toml" || name == "profiles.json" || name.starts_with("ringzero") || name == "settings.json" {
        return Some(format!("{verb} Ring Zero Security's own settings. That's tampering"));
    } else if matches!(name, "claude.md" | "agents.md" | "gemini.md" | ".cursorrules" | ".windsurfrules" | "skill.md" | ".mcp.json" | "claude.local.md") {
        return Some(format!("{verb} its own instructions in {name}"));
    } else {
        return None;
    };
    Some(format!("{verb} {thing}"))
}

/// What a shell command is doing, in a few words.
fn describe_command(cmd: &str) -> String {
    let c = cmd.trim();
    let first = c.split_whitespace().next().unwrap_or("");
    let has = |s: &str| c.contains(s);
    let text = if has("npm test") || has("pytest") || has("cargo test") || has("go test") || has("yarn test") || has("pnpm test") {
        "Running the tests.".to_string()
    } else if has("git commit") {
        "Committing the changes.".to_string()
    } else if has("git push") {
        "Pushing the code to the remote.".to_string()
    } else if has("npm install") || has("pip install") || has("yarn add") || has("cargo add") || has("pnpm add") {
        "Installing packages.".to_string()
    } else if has("build") || first == "make" || first == "tsc" {
        "Building the project.".to_string()
    } else if first == "curl" || first == "wget" {
        format!("Running {first} to fetch something from {}.", host_of(c))
    } else if first.is_empty() {
        return String::new();
    } else {
        format!("Running {}.", base_name(first))
    };
    text
}

/// The name people use for an agent.
pub fn agent_label(process: &str) -> String {
    agent_name(process)
}

fn agent_name(process: &str) -> String {
    let p = process.to_ascii_lowercase();
    let n = if p.starts_with("claude") {
        "Claude Code"
    } else if p.starts_with("codex") {
        "Codex"
    } else if p.starts_with("gemini") {
        "Gemini"
    } else if p.starts_with("cursor") || p == "agent" {
        "Cursor"
    } else if p.starts_with("copilot") {
        "Copilot"
    } else if p.starts_with("opencode") {
        "opencode"
    } else if p.starts_with("aider") {
        "Aider"
    } else if p.starts_with("windsurf") {
        "Windsurf"
    } else if p.starts_with("devin") {
        "Devin"
    } else if p.starts_with("chatgpt") {
        "ChatGPT"
    } else if p.is_empty() || p == "unknown" {
        "The agent"
    } else {
        return process.to_string();
    };
    n.to_string()
}

fn is_known_agent(name: &str) -> bool {
    matches!(
        name,
        "Claude Code" | "Codex" | "Gemini" | "Cursor" | "Copilot" | "opencode" | "Aider" | "Windsurf" | "Devin" | "ChatGPT"
    )
}

fn base_name(path: &str) -> String {
    let p = path.trim().trim_end_matches('/');
    p.rsplit('/').next().unwrap_or(p).to_string()
}

fn host_of(s: &str) -> String {
    for tok in s.split_whitespace() {
        if let Some(rest) = tok.split("://").nth(1) {
            let h = rest.split(['/', ':', '?', '"', '\'']).next().unwrap_or("");
            if !h.is_empty() {
                return h.to_string();
            }
        }
    }
    "the internet".into()
}

fn trim_words(s: &str, n: usize) -> String {
    s.split_whitespace().take(n).collect::<Vec<_>>().join(" ")
}

/// The first sentence of some text, at most `max_words` words, without
/// markdown or code.
fn first_sentence(text: &str, max_words: usize) -> String {
    let mut t = String::new();
    let mut in_code = false;
    for line in text.lines() {
        let l = line.trim();
        if l.starts_with("```") {
            in_code = !in_code;
            continue;
        }
        if l.starts_with('#') {
            continue; // a heading is a label, not something the agent said
        }
        if in_code || l.is_empty() {
            if !t.is_empty() {
                break;
            }
            continue;
        }
        t.push_str(l.trim_start_matches(['#', '-', '*', '>', ' ']));
        t.push(' ');
    }
    let t = t.replace(['`', '*', '_'], "");
    let end = t.find(|c| c == '.' || c == '?' || c == '!').map(|i| i + 1).unwrap_or(t.len());
    let sentence = &t[..end];
    let words: Vec<&str> = sentence.split_whitespace().collect();
    if words.is_empty() {
        return String::new();
    }
    let mut out = words.iter().take(max_words).copied().collect::<Vec<_>>().join(" ");
    if words.len() > max_words {
        out = out.trim_end_matches([',', ';', ':']).to_string();
        out.push('.');
    } else if !out.ends_with(['.', '?', '!']) {
        out.push('.');
    }
    out
}

/// Mask secrets and squeeze whitespace, so nothing sensitive is spoken.
fn speakable(text: &str) -> String {
    let masked = crate::secrets::prompt_guard::check(text, crate::secrets::prompt_guard::PromptGuardMode::Warn);
    let mut out = masked.redacted;
    if !masked.findings.is_empty() {
        // A masked secret reads badly aloud; say what it was instead.
        out = out
            .split_whitespace()
            .map(|w| if w.contains("***") || w.contains('…') { "[a secret]" } else { w })
            .collect::<Vec<_>>()
            .join(" ");
    }
    out.split_whitespace().collect::<Vec<_>>().join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ev(kind: EventKind, process: &str, target: &str, allowed: bool) -> SecurityEvent {
        SecurityEvent {
            id: "t".into(),
            kind,
            pid: 1,
            uid: 1000,
            process: process.into(),
            target: target.into(),
            allowed,
            reason: None,
            timestamp: chrono::Utc::now(),
            ppid: None,
            parent_process: None,
            llm_context: None,
            extra: None,
        }
    }

    fn fresh() -> Narrator {
        Narrator {
            state: Mutex::new(State {
                seq: 0,
                lines: VecDeque::new(),
                recent_text: HashMap::new(),
                reads: None,
                last_thinking: HashMap::new(),
                sessions_seen: HashMap::new(),
                replay: false,
                stamp: None,
            }),
            notify: tokio::sync::Notify::new(),
        }
    }

    fn texts(n: &Narrator) -> Vec<(Level, String)> {
        n.since(0).0.into_iter().map(|l| (l.level, l.text)).collect()
    }

    #[test]
    fn blocked_secret_read_is_an_alert() {
        let n = fresh();
        n.observe(&ev(EventKind::FileOpen, "Claude Code", "id_rsa", false));
        assert_eq!(texts(&n), vec![(Level::Alert, "Claude Code just tried to read your SSH key. Blocked by Ring Zero Security.".into())]);
    }

    #[test]
    fn refused_sudo_and_program_and_host() {
        let n = fresh();
        n.observe(&ev(EventKind::ProcessExec, "Claude Code", "sudo", false));
        n.observe(&ev(EventKind::ProcessExec, "Claude Code", "curl", false));
        n.observe(&ev(EventKind::NetworkConnect, "python3", "93.184.215.14:443", false));
        let t = texts(&n);
        assert!(t[0].1.contains("become an administrator with sudo"));
        assert!(t[1].1.contains("run curl, which isn't on its approved list"));
        assert!(t[2].1.contains("connect to 93.184.215.14"));
        assert!(t.iter().all(|(l, _)| *l == Level::Alert));
    }

    #[test]
    fn ordinary_kernel_activity_is_silent() {
        let n = fresh();
        n.observe(&ev(EventKind::ProcessExec, "Claude Code", "/usr/bin/git", true));
        n.observe(&ev(EventKind::NetworkConnect, "node", "160.79.104.10:443", true));
        assert!(texts(&n).is_empty());
    }

    #[test]
    fn tool_calls_read_like_a_story() {
        let n = fresh();
        let tool = |name: &str, input: serde_json::Value| {
            let mut e = ev(EventKind::LlmToolCall, "claude", name, true);
            e.extra = Some(serde_json::json!({"hook": "PreToolUse", "phase": "call", "tool_input": input}));
            e
        };
        n.observe(&tool("Read", serde_json::json!({"file_path": "/repo/src/auth/login.ts"})));
        n.observe(&tool("Read", serde_json::json!({"file_path": "/repo/src/auth/session.ts"})));
        n.observe(&tool("Read", serde_json::json!({"file_path": "/repo/src/db.ts"})));
        n.observe(&tool("Edit", serde_json::json!({"file_path": "/repo/src/auth/login.ts"})));
        n.observe(&tool("Bash", serde_json::json!({"command": "npm test -- auth"})));
        let t: Vec<String> = texts(&n).into_iter().map(|x| x.1).collect();
        assert_eq!(
            t,
            vec![
                "It's reading login.ts, session.ts and 1 more.",
                "It's changing login.ts.",
                "Running the tests.",
            ]
        );
    }

    #[test]
    fn post_tool_use_is_not_repeated() {
        let n = fresh();
        let mut e = ev(EventKind::LlmToolCall, "claude", "Bash", true);
        e.extra = Some(serde_json::json!({"hook": "PostToolUse", "phase": "result", "tool_input": {"command": "ls"}}));
        n.observe(&e);
        assert!(texts(&n).is_empty());
    }

    #[test]
    fn prompt_with_secret_is_never_spoken() {
        let n = fresh();
        let mut e = ev(EventKind::LlmRequest, "claude", "claude:prompt-secret", false);
        e.llm_context = Some(crate::common::event::LlmContext {
            provider: "claude".into(),
            model: None,
            response_text: Some("deploy with key sk-ant-api03-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".into()),
            tool_call: None,
            usage: None,
            response_ts: chrono::Utc::now(),
        });
        n.observe(&e);
        let t = texts(&n);
        assert_eq!(t.len(), 1);
        assert_eq!(t[0].0, Level::Alert);
        assert!(!t[0].1.contains("sk-ant"));
    }

    #[test]
    fn thinking_is_one_sentence_and_rate_limited() {
        let n = fresh();
        let line = |s: &str| serde_json::json!({"type": "assistant", "message": {"content": [{"type": "thinking", "thinking": s}]}});
        n.observe_transcript("claude", &line("The login bug is probably in the session refresh. Let me check the token expiry first and then the cookie handling."));
        n.observe_transcript("claude", &line("Another thought right after."));
        let t = texts(&n);
        assert_eq!(t.len(), 1);
        assert_eq!(t[0].1, "Thinking: The login bug is probably in the session refresh.");
    }

    #[test]
    fn helper_programs_are_spoken_as_the_agent() {
        let n = fresh();
        n.observe(&ev(EventKind::FileOpen, "cat", ".env", false));
        let mut e = ev(EventKind::FileOpen, "head", "id_rsa", false);
        e.parent_process = Some("claude".into());
        n.observe(&e);
        let t = texts(&n);
        assert!(t[0].1.starts_with("The agent just tried to read a .env file"), "{}", t[0].1);
        assert!(t[1].1.starts_with("Claude Code just tried to read your SSH key"), "{}", t[1].1);
        assert!(t.iter().all(|(_, x)| x.contains("Ring Zero Security")));
    }

    #[test]
    fn any_agent_is_narrated_from_the_kernel() {
        let n = fresh();
        let mut e = ev(EventKind::ProcessExec, "opencode.exe", "/usr/bin/git", true);
        n.observe(&e);
        e.target = "/usr/bin/ls".into();
        n.observe(&e);
        let mut w = ev(EventKind::FileWrite, "opencode", "/home/u/app/login.ts", true);
        w.reason = Some("agent-written file scanned at close: Clean".into());
        n.observe(&w);
        let t: Vec<String> = texts(&n).into_iter().map(|x| x.1).collect();
        assert_eq!(t, vec!["opencode is at work.", "opencode is running git.", "opencode saved login.ts."]);
    }

    #[test]
    fn replay_keeps_event_times_and_repeats_minutes_apart() {
        let mut a = ev(EventKind::FileOpen, "opencode", "id_rsa", false);
        a.timestamp = chrono::Utc::now() - chrono::Duration::minutes(10);
        let mut b = a.clone();
        b.timestamp = chrono::Utc::now() - chrono::Duration::minutes(2);
        let mut g = ev(EventKind::ProcessExec, "opencode", "/usr/bin/git", true);
        g.timestamp = chrono::Utc::now() - chrono::Duration::minutes(5);
        let lines = Narrator::replay(&[b.clone(), a.clone(), g]);
        let t: Vec<&str> = lines.iter().map(|l| l.text.as_str()).collect();
        assert_eq!(t[0], "opencode is at work.");
        assert!(t[1].contains("SSH key"));
        assert_eq!(t[2], "opencode is running git.");
        assert!(t[3].contains("SSH key"), "a repeat minutes later is told again");
        assert_eq!(lines[1].at, a.timestamp);
    }

    #[test]
    fn same_sentence_not_repeated() {
        let n = fresh();
        n.observe(&ev(EventKind::FileOpen, "Claude Code", "id_rsa", false));
        n.observe(&ev(EventKind::FileOpen, "Claude Code", "id_rsa", false));
        assert_eq!(texts(&n).len(), 1);
    }

    #[test]
    fn first_sentence_strips_markdown() {
        assert_eq!(first_sentence("## Plan\n\n**Fix** the `auth` flow. Then test.", 10), "Fix the auth flow.");
        assert_eq!(first_sentence("```rust\nfn x(){}\n```\nDone now", 10), "Done now.");
    }
}
