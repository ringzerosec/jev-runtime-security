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

/// Package managers. Never an agent by their own name or arguments: npm sets
/// its process name and command line to "npm i openclaw@", so the package being
/// installed would otherwise make npm look like the agent it installs. A package
/// manager an agent starts is still in that agent's tree (the kernel inherits
/// the tag at fork), so agent controls still apply to it.
const PACKAGE_MANAGERS: &[&str] = &[
    "npm",
    "npx",
    "pnpm",
    "pnpx",
    "yarn",
    "bun",
    "bunx",
    "pip",
    "pip3",
    "pipx",
    "uv",
    "uvx",
    "poetry",
    "cargo",
    "gem",
    // The scripts a node interpreter runs for them (argv[1] of `node …`).
    "npm-cli.js",
    "npx-cli.js",
    "yarn.js",
    "pnpm.cjs",
    "pnpm.mjs",
];

/// The program a process name or argv token names: its first word, without a
/// directory. "npm i openclaw@" → "npm", "/usr/bin/pip3" → "pip3".
fn program_word(name: &str) -> String {
    let first = name.split_whitespace().next().unwrap_or("");
    first
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or(first)
        .to_lowercase()
}

/// Is this process name (or argv[0]) a package manager?
pub fn is_package_manager(process_name: &str) -> bool {
    PACKAGE_MANAGERS.contains(&program_word(process_name).as_str())
}

/// Returns true if the given process name matches a known AI agent.
pub fn is_ai_agent(process_name: &str) -> bool {
    let p = process_name.to_lowercase();
    if AGENT_PHRASES.iter().any(|name| p.contains(name)) {
        return true;
    }
    if is_package_manager(&p) {
        return false;
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
    is_agent_path(&path)
}

/// True if an executable path is a known agent install location. The path test
/// behind `is_agent_by_binary`, usable without a live pid (inventory).
pub fn is_agent_path(path: &str) -> bool {
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
            // A package manager is never an agent by its arguments: in
            // `node /usr/bin/npm install openclaw@latest`, "openclaw" is the
            // package, not the program. Look at the program, which is argv[0],
            // or argv[1] when argv[0] is the interpreter running it.
            let argv: Vec<String> = data
                .split(|&b| b == 0)
                .filter(|t| !t.is_empty())
                .map(|t| String::from_utf8_lossy(t).into_owned())
                .collect();
            if argv.iter().take(2).any(|a| is_package_manager(a)) {
                return None;
            }
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
    } else if p.starts_with("opencode") {
        "opencode"
    } else if p.starts_with("agy") || p.contains("antigravity") {
        "antigravity"
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

    /// npm puts its command line in its process name. The package it installs
    /// is not who it is: `npm i openclaw` is npm, not OpenClaw.
    #[test]
    fn a_package_manager_is_never_the_agent_it_installs() {
        for name in [
            "npm i openclaw@",
            "npm install --g",
            "npm install --global openclaw@latest",
            "npx nanoclaw",
            "pnpm add openclaw",
            "pip install claude-agent-sdk",
            "pip3",
            "uv tool install hermes",
            "bunx openclaw",
            "/usr/bin/npm",
        ] {
            assert!(
                !is_ai_agent(name),
                "{name:?} is a package manager, not an agent"
            );
            assert!(
                is_package_manager(name),
                "{name:?} must be recognised as a package manager"
            );
        }
        assert!(is_package_manager(
            "/usr/lib/node_modules/npm/bin/npm-cli.js"
        ));
        assert!(!is_package_manager("openclaw"));
        assert!(!is_package_manager("claude"));
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
