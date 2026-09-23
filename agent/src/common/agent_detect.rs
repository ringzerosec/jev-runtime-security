// SPDX-License-Identifier: Apache-2.0
// AI agent process detection — canonical agent list for all platforms.
//
// Used by daemon event loop (auto-session creation) and proxy (agent traffic identification).

/// Names that mean "this is an AI coding agent".
///
/// MATCHED AS WHOLE TOKENS, NOT AS SUBSTRINGS, and that is not a style choice.
/// This list used to contain a bare `"agent"` matched with `contains`, so every
/// process whose name held those five letters was classified as an AI agent. On
/// a stock Ubuntu GNOME desktop that is `ptyxis-agent`, the terminal helper,
/// which meant every command a person typed was agent activity and the caller
/// check refused their policy changes outright. It also caught `ssh-agent`,
/// `gpg-agent` and `polkit-agent-helper-1` — the last of which sits in the
/// authentication path the desktop app depends on.
///
/// Classification by process name is a heuristic. A bad heuristic here does not
/// degrade the product, it disables it on an ordinary desktop, so the matching
/// rule is deliberately narrow and the negative cases are pinned by tests.
///
/// `"agent"` is gone and is not coming back: Cursor's CLI is `cursor-agent`,
/// which matches on `cursor` already.
const AGENT_NAMES: &[&str] = &[
    "claude",
    "cursor",
    "copilot",
    "codex",
    "chatgpt",
    "gemini",
    "devin",
    "aider",
    "windsurf",
    "cody",
    "tabnine",
    "continue", // continue.dev
    "cline",    // Cline / Claude Dev (VS Code agent)
    "hermes",   // Hermes agent
    "agy",      // Antigravity CLI (Google)
    "antigravity",
    "opencode", // OpenCode CLI
];

/// Entries that are genuinely several words, where a token match cannot work.
/// Kept on `contains` because a space is already a strong enough boundary.
const AGENT_PHRASES: &[&str] = &["code helper", "cursor helper"];

/// Entries matched on a token SUFFIX, for families named `*claw`.
const AGENT_SUFFIXES: &[&str] = &["claw"];

/// Split a process name the way a human reads it: on anything that is not a
/// letter or a digit. `claude-code` is two tokens, `ptyxis-agent` is two, and
/// neither `agent` nor `ssh` can be mistaken for a whole name.
fn tokens(name: &str) -> Vec<&str> {
    name.split(|c: char| !c.is_ascii_alphanumeric())
        .filter(|t| !t.is_empty())
        .collect()
}

/// Returns true if the given process name matches a known AI agent.
pub fn is_ai_agent(process_name: &str) -> bool {
    let p = process_name.to_lowercase();
    if AGENT_PHRASES.iter().any(|name| p.contains(name)) {
        return true;
    }
    tokens(&p)
        .iter()
        .any(|t| AGENT_NAMES.contains(t) || AGENT_SUFFIXES.iter().any(|suf| t.ends_with(suf)))
}

/// Check if a process should be tracked as an AI agent based on its network destination.
pub fn is_llm_destination(target: &str) -> bool {
    crate::policy::network::is_llm_api_destination(target)
}

/// Check if a PID belongs to an AI agent by examining its binary path.
/// Covers agents installed in known locations regardless of process name.
pub fn is_agent_by_binary(pid: u32) -> bool {
    let exe = format!("/proc/{}/exe", pid);
    let path = match std::fs::read_link(&exe) {
        Ok(p) => p.to_string_lossy().to_string(),
        Err(_) => {
            // Try TGID
            if let Ok(status) = std::fs::read_to_string(format!("/proc/{}/status", pid)) {
                if let Some(tgid) = status
                    .lines()
                    .find(|l| l.starts_with("Tgid:"))
                    .and_then(|l| l.split_whitespace().nth(1))
                    .and_then(|v| v.parse::<u32>().ok())
                {
                    match std::fs::read_link(format!("/proc/{}/exe", tgid)) {
                        Ok(p) => p.to_string_lossy().to_string(),
                        Err(_) => return false,
                    }
                } else {
                    return false;
                }
            } else {
                return false;
            }
        }
    };
    let path_lower = path.to_lowercase();
    // Known agent install paths
    path_lower.contains("cursor-agent")
        || path_lower.contains(".cursor/")
        || path_lower.contains(".codex/")
        || path_lower.contains("claude-code")
        || path_lower.contains(".claude/")
        || path_lower.contains("antigravity")
        || path_lower.contains("gemini-cli")
        || path_lower.contains("copilot")
        || path_lower.contains("windsurf")
        || path_lower.contains("aider")
}
/// Resolve the agent identity for a LIVE pid, falling back to the command line
/// when `comm` doesn't match. This is essential for Node/Python CLIs: Gemini CLI
/// runs as `node …/gemini` and its `comm` is "node" or even "MainThread" (Node
/// names the main thread), so a comm-only check misses it entirely. The agent's
/// real identity lives in argv (a token whose basename is `gemini`). We match on
/// the basename of each argv token, not a loose substring, to avoid false hits.
///
/// Returns the agent class (e.g. "gemini") or None.
pub fn detect_agent_for_pid(pid: u32, comm: &str) -> Option<&'static str> {
    if is_ai_agent(comm) {
        return Some(classify_agent(comm));
    }
    {
        // /proc/<pid>/cmdline is NUL-separated argv.
        if let Ok(data) = std::fs::read(format!("/proc/{pid}/cmdline")) {
            for tok in data.split(|&b| b == 0) {
                if tok.is_empty() {
                    continue;
                }
                let s = String::from_utf8_lossy(tok);
                // Match the basename of the token (e.g. ".../bin/gemini" → "gemini"),
                // so we catch the agent script/binary without matching stray paths.
                let base = s.rsplit(['/', '\\']).next().unwrap_or(&s);
                if is_ai_agent(base) {
                    return Some(classify_agent(base));
                }
            }
        }
    }
    None
}

/// Classify the agent type for session registration.
/// Returns a short identifier suitable for the session `agent_type` field.
pub fn classify_agent(process_name: &str) -> &'static str {
    let p = process_name.to_lowercase();
    if p.contains("claude") {
        "claude"
    } else if p.contains("cursor") {
        "cursor"
    } else if p.contains("copilot") {
        "copilot"
    } else if p.contains("codex") {
        "codex"
    } else if p.contains("chatgpt") {
        "chatgpt"
    } else if p.contains("gemini") {
        "gemini"
    } else if p.contains("devin") {
        "devin"
    } else if p.contains("aider") {
        "aider"
    } else if p.contains("windsurf") {
        "windsurf"
    } else if p.contains("cody") {
        "cody"
    } else if p.contains("tabnine") {
        "tabnine"
    } else if p.contains("claw") {
        "claw"
    } else if p.contains("hermes") {
        "hermes"
    } else {
        "custom"
    }
}

/// All known agent names (for UI display in the agent list).
#[allow(dead_code)]
pub fn known_agents() -> &'static [&'static str] {
    AGENT_NAMES
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detect_known_agents() {
        assert!(is_ai_agent("claude"));
        assert!(is_ai_agent("Claude Code"));
        assert!(is_ai_agent("cursor"));
        assert!(is_ai_agent("Cursor Helper (GPU)"));
        assert!(is_ai_agent("GitHub Copilot Host"));
        assert!(is_ai_agent("codex-agent"));
        assert!(is_ai_agent("aider"));
        assert!(is_ai_agent("windsurf"));
        assert!(is_ai_agent("chatgpt"));
        assert!(is_ai_agent("gemini"));
        assert!(is_ai_agent("hermes"));
        // any *claw* agent
        assert!(is_ai_agent("openclaw"));
        assert!(is_ai_agent("nanoclaw"));
        assert!(is_ai_agent("nemoclaw"));
        assert_eq!(classify_agent("nanoclaw"), "claw");
        assert_eq!(classify_agent("hermes-cli"), "hermes");
    }

    #[test]
    fn ignore_non_agents() {
        assert!(!is_ai_agent("explorer"));
        assert!(!is_ai_agent("notepad"));
        assert!(!is_ai_agent("svchost"));
        assert!(!is_ai_agent("chrome"));
        assert!(!is_ai_agent("node"));
    }

    #[test]
    fn classify_agents() {
        assert_eq!(classify_agent("claude"), "claude");
        assert_eq!(classify_agent("Cursor"), "cursor");
        assert_eq!(classify_agent("GitHub Copilot Host"), "copilot");
        assert_eq!(classify_agent("ChatGPT Desktop"), "chatgpt");
        assert_eq!(classify_agent("Gemini"), "gemini");
        assert_eq!(classify_agent("unknown-tool"), "custom");
    }
}

#[cfg(test)]
mod name_tests {
    use super::*;

    /// Real process names from an ordinary Linux desktop. Every one of these
    /// was, or could have been, classified as an AI agent by the old
    /// substring rule. A false positive here does not degrade the product, it
    /// stops a person changing policy on their own machine.
    #[test]
    fn ordinary_system_processes_are_never_agents() {
        for name in [
            "ptyxis-agent",
            "ssh-agent",
            "gpg-agent",
            "polkit-agent-helper-1",
            "gnome-keyring-daemon",
            "dbus-daemon",
            "systemd",
            "systemd-journald",
            "NetworkManager",
            "pipewire",
            "Xwayland",
            "bash",
            "sshd",
            "agetty",
            // Short entries that are substrings of unrelated words.
            "agenda",
            "codyssey",
            "discontinued",
            "clawback",
            "telemetry-agent",
        ] {
            assert!(
                !is_ai_agent(name),
                "{name:?} must not be classified as an AI agent"
            );
        }
    }

    #[test]
    fn the_agents_we_mean_still_match() {
        for name in [
            "claude",
            "claude-code",
            "Claude Code",
            "cursor",
            "cursor-agent",
            "codex",
            "gemini",
            "aider",
            "windsurf",
            "copilot",
            "cline",
            "opencode",
            "antigravity",
            "agy",
            "openclaw",
            "nanoclaw",
            "Code Helper (Renderer)",
        ] {
            assert!(is_ai_agent(name), "{name:?} must be classified as an agent");
        }
    }

    /// The bare entry that caused it. Its absence is the fix, so assert it.
    #[test]
    fn the_word_agent_alone_is_not_in_the_list() {
        assert!(
            !AGENT_NAMES.contains(&"agent"),
            "a bare \"agent\" entry matches ptyxis-agent, ssh-agent and \
             polkit-agent-helper-1"
        );
        assert!(!is_ai_agent("agent"));
    }

    /// The kernel has its own copy of this idea in GPL/bpf/ringzero.bpf.c, and
    /// it matches name PREFIXES rather than tokens. The two are deliberately
    /// not identical: the kernel version runs in a hot path with no allocation
    /// and cannot tokenise. What must hold is that neither is looser than the
    /// other on the names that matter, which is what this pins from the
    /// userspace side.
    #[test]
    fn the_kernel_list_has_no_bare_agent_entry_either() {
        let bpf = include_str!("../../../GPL/bpf/ringzero.bpf.c");
        assert!(
            !bpf.contains("\"agent\0\""),
            "the kernel list must not gain a bare agent entry either"
        );
    }
}
