// SPDX-License-Identifier: Apache-2.0
// scanner/inventory.rs — what AI is on this machine.
//
// Answers the question a security team asks before any other: which AI agents,
// IDE AI extensions, MCP servers and local model runtimes are installed here,
// for which user, and does our enforcement cover each one.
//
// READ-ONLY BY CONSTRUCTION. Discovery reads directory listings and config
// files. It never executes a binary it finds (a discovered binary is untrusted
// by definition), never reads file contents beyond the config files named
// below, and never returns a secret: MCP environment variables are reported by
// name only, and arguments that look like credentials are redacted before they
// leave this module.
//
// `skill_surface.rs` answers the companion question — what instructions those
// agents load — and scans them. This module is the inventory; that one is the
// audit.

use std::path::{Path, PathBuf};

use serde::Serialize;

/// One installed AI agent.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct AgentInstall {
    /// Stable id, e.g. "claude".
    pub id: String,
    /// Human name, e.g. "Claude Code".
    pub name: String,
    /// The user whose home this install was found in.
    pub owner: String,
    /// Where the executable is, if one was found.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub binary: Option<String>,
    /// The agent's config directory, if present.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub config_dir: Option<String>,
    /// Whether Ring Zero recognises this agent's process, so the kernel policy
    /// and session tracking apply to it. False means: discovered, not covered.
    pub enforcement_covered: bool,
}

/// One AI extension installed in an editor.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct IdeExtension {
    pub id: String,
    pub name: String,
    /// "VS Code", "Cursor", "Windsurf", "VS Code Server".
    pub editor: String,
    pub version: String,
    pub owner: String,
    pub path: String,
}

/// One configured MCP server.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct McpServer {
    pub name: String,
    /// Which agent's config declares it.
    pub agent: String,
    pub owner: String,
    /// The config file it was read from.
    pub source: String,
    /// "user", or "project:<path>" for a project-scoped server.
    pub scope: String,
    /// "stdio" | "http" | "sse".
    pub transport: String,
    /// Command and leading arguments for stdio servers, secrets redacted.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub command: Option<String>,
    /// URL for remote servers (query string dropped).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    /// Names (never values) of environment variables passed to the server.
    pub env_keys: Vec<String>,
    /// Plain-language risk notes, e.g. "remote", "secrets in env".
    pub flags: Vec<String>,
}

/// One local model runtime.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct ModelRuntime {
    pub id: String,
    pub name: String,
    pub owner: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub binary: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub models_dir: Option<String>,
    /// Count of models found on disk, when the runtime's layout makes that
    /// cheap to read. None when unknown.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub model_count: Option<usize>,
}

/// The whole inventory.
#[derive(Debug, Clone, Serialize, Default)]
pub struct Inventory {
    pub agents: Vec<AgentInstall>,
    pub ide_extensions: Vec<IdeExtension>,
    pub mcp_servers: Vec<McpServer>,
    pub model_runtimes: Vec<ModelRuntime>,
    /// "observe" | "enforce" — the daemon's current mode.
    pub enforcement_mode: String,
}

// ── Catalogues ────────────────────────────────────────────────────────────────

/// (id, name, executable names, config dirs relative to home)
const AGENTS: &[(&str, &str, &[&str], &[&str])] = &[
    ("claude", "Claude Code", &["claude"], &[".claude"]),
    ("codex", "Codex CLI", &["codex"], &[".codex"]),
    ("gemini", "Gemini CLI", &["gemini"], &[".gemini"]),
    ("cursor", "Cursor", &["cursor", "cursor-agent"], &[".cursor"]),
    ("copilot", "GitHub Copilot CLI", &["copilot"], &[".copilot"]),
    ("opencode", "opencode", &["opencode"], &[".config/opencode"]),
    ("windsurf", "Windsurf", &["windsurf"], &[".windsurf", ".codeium/windsurf"]),
    ("aider", "Aider", &["aider"], &[]),
    ("goose", "Goose", &["goose"], &[".config/goose"]),
    ("amp", "Amp", &["amp"], &[".config/amp"]),
    ("qwen", "Qwen Code", &["qwen"], &[".qwen"]),
    ("claude-desktop", "Claude Desktop", &["claude-desktop"], &[".config/Claude"]),
    ("hermes", "Hermes Agent", &["hermes"], &[".hermes"]),
    ("openclaw", "OpenClaw", &["openclaw"], &[".openclaw"]),
];

/// (extension id prefix, display name)
const AI_EXTENSIONS: &[(&str, &str)] = &[
    ("anthropic.claude-code", "Claude Code"),
    ("github.copilot-chat", "GitHub Copilot Chat"),
    ("github.copilot", "GitHub Copilot"),
    ("continue.continue", "Continue"),
    ("saoudrizwan.claude-dev", "Cline"),
    ("rooveterinaryinc.roo-cline", "Roo Code"),
    ("kilocode.kilo-code", "Kilo Code"),
    ("codeium.codeium", "Windsurf (Codeium)"),
    ("google.geminicodeassist", "Gemini Code Assist"),
    ("openai.chatgpt", "ChatGPT / Codex"),
    ("sourcegraph.cody-ai", "Cody"),
    ("tabnine.tabnine-vscode", "Tabnine"),
    ("amazonwebservices.amazon-q-vscode", "Amazon Q"),
];

/// (editor name, extensions dir relative to home)
const EDITORS: &[(&str, &str)] = &[
    ("VS Code", ".vscode/extensions"),
    ("VS Code Server", ".vscode-server/extensions"),
    ("Cursor", ".cursor/extensions"),
    ("Windsurf", ".windsurf/extensions"),
];

/// System-wide executable directories, checked for every user.
const SYSTEM_BIN_DIRS: &[&str] = &["/usr/local/bin", "/usr/bin", "/opt/bin", "/snap/bin"];

/// Per-user executable directories, relative to home.
const USER_BIN_DIRS: &[&str] = &[
    ".local/bin",
    ".npm-global/bin",
    ".bun/bin",
    ".cargo/bin",
    "bin",
    ".claude/local",
];

// ── Entry points ──────────────────────────────────────────────────────────────

/// Inventory every home on the host. The daemon runs as root, so this covers
/// every user.
pub fn collect() -> Inventory {
    let mut inv = Inventory {
        enforcement_mode: crate::config::DaemonConfig::load().daemon.mode,
        ..Default::default()
    };
    for (owner, home) in crate::scanner::skill_surface::home_dirs() {
        collect_home(&owner, &home, &mut inv);
    }
    dedup(&mut inv);
    inv
}

/// Inventory one home directory. Public to the crate so tests can point it at
/// a fixture tree.
pub(crate) fn collect_home(owner: &str, home: &Path, inv: &mut Inventory) {
    let bin_dirs = bin_dirs_for(home);
    collect_agents(owner, home, &bin_dirs, inv);
    collect_extensions(owner, home, inv);
    collect_mcp(owner, home, inv);
    collect_runtimes(owner, home, &bin_dirs, inv);
}

fn bin_dirs_for(home: &Path) -> Vec<PathBuf> {
    let mut dirs: Vec<PathBuf> = USER_BIN_DIRS.iter().map(|d| home.join(d)).collect();
    // nvm keeps one bin dir per installed node version.
    if let Ok(rd) = std::fs::read_dir(home.join(".nvm/versions/node")) {
        for e in rd.flatten() {
            dirs.push(e.path().join("bin"));
        }
    }
    dirs.extend(SYSTEM_BIN_DIRS.iter().map(PathBuf::from));
    dirs
}

fn find_binary(names: &[&str], bin_dirs: &[PathBuf]) -> Option<PathBuf> {
    for dir in bin_dirs {
        for n in names {
            let p = dir.join(n);
            // A file or a symlink to one; never executed, only stat'ed.
            if p.is_file() {
                return Some(p);
            }
        }
    }
    None
}

// ── Agents ────────────────────────────────────────────────────────────────────

fn collect_agents(owner: &str, home: &Path, bin_dirs: &[PathBuf], inv: &mut Inventory) {
    for (id, name, bins, cfgs) in AGENTS {
        let binary = find_binary(bins, bin_dirs);
        let config_dir = cfgs.iter().map(|c| home.join(c)).find(|p| p.is_dir());
        if binary.is_none() && config_dir.is_none() {
            continue;
        }
        let covered = bins.iter().any(|b| crate::common::agent_detect::is_ai_agent(b))
            || binary
                .as_ref()
                .is_some_and(|b| crate::common::agent_detect::is_agent_path(&b.to_string_lossy()));
        inv.agents.push(AgentInstall {
            id: (*id).to_string(),
            name: (*name).to_string(),
            owner: owner.to_string(),
            binary: binary.map(|p| p.to_string_lossy().into_owned()),
            config_dir: config_dir.map(|p| p.to_string_lossy().into_owned()),
            enforcement_covered: covered,
        });
    }
}

// ── IDE extensions ────────────────────────────────────────────────────────────

fn collect_extensions(owner: &str, home: &Path, inv: &mut Inventory) {
    for (editor, rel) in EDITORS {
        let dir = home.join(rel);
        let Ok(rd) = std::fs::read_dir(&dir) else { continue };
        for e in rd.flatten() {
            let folder = e.file_name().to_string_lossy().to_lowercase();
            // Folder names are "<publisher>.<name>-<version>[-<platform>]".
            // Longest prefix wins so copilot-chat isn't reported as copilot.
            let hit = AI_EXTENSIONS
                .iter()
                .filter(|(prefix, _)| {
                    folder == *prefix || folder.starts_with(&format!("{prefix}-"))
                })
                .max_by_key(|(prefix, _)| prefix.len());
            let Some((prefix, name)) = hit else { continue };
            let version = folder
                .strip_prefix(prefix)
                .and_then(|s| s.strip_prefix('-'))
                .map(|s| s.split('-').next().unwrap_or("").to_string())
                .unwrap_or_default();
            inv.ide_extensions.push(IdeExtension {
                id: (*prefix).to_string(),
                name: (*name).to_string(),
                editor: (*editor).to_string(),
                version,
                owner: owner.to_string(),
                path: e.path().to_string_lossy().into_owned(),
            });
        }
    }
}

// ── MCP servers ───────────────────────────────────────────────────────────────

/// (agent, config path relative to home, JSON pointer to the servers object)
const MCP_JSON_SOURCES: &[(&str, &str, &str)] = &[
    ("claude", ".claude.json", "/mcpServers"),
    ("claude", ".mcp.json", "/mcpServers"),
    ("cursor", ".cursor/mcp.json", "/mcpServers"),
    ("windsurf", ".codeium/windsurf/mcp_config.json", "/mcpServers"),
    ("gemini", ".gemini/settings.json", "/mcpServers"),
    ("claude-desktop", ".config/Claude/claude_desktop_config.json", "/mcpServers"),
    ("vscode", ".config/Code/User/mcp.json", "/servers"),
    ("vscode", ".config/Code/User/settings.json", "/mcp/servers"),
    ("opencode", ".config/opencode/opencode.json", "/mcp"),
];

fn collect_mcp(owner: &str, home: &Path, inv: &mut Inventory) {
    for (agent, rel, pointer) in MCP_JSON_SOURCES {
        let path = home.join(rel);
        let Some(json) = read_json(&path) else { continue };
        if let Some(servers) = json.pointer(pointer).and_then(|v| v.as_object()) {
            for (name, spec) in servers {
                inv.mcp_servers
                    .push(mcp_from_json(name, spec, agent, owner, &path, "user"));
            }
        }
        // Claude Code also keeps project-scoped servers under "projects".
        if *rel == ".claude.json" {
            if let Some(projects) = json.get("projects").and_then(|v| v.as_object()) {
                for (proj, pv) in projects {
                    if let Some(servers) = pv.get("mcpServers").and_then(|v| v.as_object()) {
                        for (name, spec) in servers {
                            inv.mcp_servers.push(mcp_from_json(
                                name,
                                spec,
                                agent,
                                owner,
                                &path,
                                &format!("project:{proj}"),
                            ));
                        }
                    }
                    // And the project's own .mcp.json, if it is under this home.
                    let proj_path = Path::new(proj);
                    if proj_path.starts_with(home) {
                        let pm = proj_path.join(".mcp.json");
                        if let Some(pj) = read_json(&pm) {
                            if let Some(servers) = pj.get("mcpServers").and_then(|v| v.as_object()) {
                                for (name, spec) in servers {
                                    inv.mcp_servers.push(mcp_from_json(
                                        name,
                                        spec,
                                        agent,
                                        owner,
                                        &pm,
                                        &format!("project:{proj}"),
                                    ));
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    collect_codex_mcp(owner, home, inv);
}

/// Codex keeps MCP servers in TOML: `[mcp_servers.<name>] command = …`.
fn collect_codex_mcp(owner: &str, home: &Path, inv: &mut Inventory) {
    let path = home.join(".codex/config.toml");
    let Ok(text) = std::fs::read_to_string(&path) else { return };
    let Ok(doc) = text.parse::<toml::Value>() else { return };
    let Some(servers) = doc.get("mcp_servers").and_then(|v| v.as_table()) else { return };
    for (name, spec) in servers {
        // Re-shape into the JSON form so one code path describes every server.
        let json = serde_json::to_value(spec).unwrap_or(serde_json::Value::Null);
        inv.mcp_servers
            .push(mcp_from_json(name, &json, "codex", owner, &path, "user"));
    }
}

fn mcp_from_json(
    name: &str,
    spec: &serde_json::Value,
    agent: &str,
    owner: &str,
    source: &Path,
    scope: &str,
) -> McpServer {
    let url = spec
        .get("url")
        .or_else(|| spec.get("httpUrl"))
        .or_else(|| spec.get("serverUrl"))
        .and_then(|v| v.as_str())
        .map(strip_query);
    // `command` is a string in most configs and an array in opencode's.
    let (cmd, mut args): (Option<String>, Vec<String>) = match spec.get("command") {
        Some(serde_json::Value::String(s)) => (Some(s.clone()), Vec::new()),
        Some(serde_json::Value::Array(a)) => {
            let mut it = a.iter().filter_map(|v| v.as_str().map(str::to_string));
            (it.next(), it.collect())
        }
        _ => (None, Vec::new()),
    };
    if let Some(a) = spec.get("args").and_then(|v| v.as_array()) {
        args.extend(a.iter().filter_map(|v| v.as_str().map(str::to_string)));
    }
    let transport = match spec.get("type").or_else(|| spec.get("transport")).and_then(|v| v.as_str()) {
        Some(t) if t.contains("sse") => "sse",
        Some(t) if t.contains("http") || t == "remote" => "http",
        _ if url.is_some() && cmd.is_none() => "http",
        _ => "stdio",
    }
    .to_string();
    let command = cmd.map(|c| {
        let mut parts = vec![redact_arg(&c)];
        parts.extend(args.iter().take(3).map(|a| redact_arg(a)));
        if args.len() > 3 {
            parts.push(format!("(+{} args)", args.len() - 3));
        }
        parts.join(" ")
    });
    let env_keys: Vec<String> = spec
        .get("env")
        .or_else(|| spec.get("environment"))
        .and_then(|v| v.as_object())
        .map(|o| o.keys().cloned().collect())
        .unwrap_or_default();
    let headers_present = spec.get("headers").and_then(|v| v.as_object()).is_some_and(|o| !o.is_empty());

    let mut flags = Vec::new();
    if let Some(u) = &url {
        if !is_local_url(u) {
            flags.push("remote".to_string());
        }
    }
    if env_keys.iter().any(|k| looks_secret_name(k)) || headers_present {
        flags.push("credentials in config".to_string());
    }
    if let Some(c) = &command {
        let first = c.split_whitespace().next().unwrap_or("");
        let base = first.rsplit('/').next().unwrap_or(first);
        if matches!(base, "npx" | "uvx" | "bunx" | "pnpx") && !args.iter().any(|a| has_pinned_version(a)) {
            flags.push("unpinned package".to_string());
        }
    }

    McpServer {
        name: name.to_string(),
        agent: agent.to_string(),
        owner: owner.to_string(),
        source: source.to_string_lossy().into_owned(),
        scope: scope.to_string(),
        transport,
        command,
        url,
        env_keys,
        flags,
    }
}

// ── Model runtimes ────────────────────────────────────────────────────────────

fn collect_runtimes(owner: &str, home: &Path, bin_dirs: &[PathBuf], inv: &mut Inventory) {
    // Ollama: binary and/or the per-user model store.
    let ollama_bin = find_binary(&["ollama"], bin_dirs);
    let ollama_models = home.join(".ollama/models");
    if ollama_bin.is_some() || ollama_models.is_dir() {
        let count = count_dirs(&ollama_models.join("manifests/registry.ollama.ai/library"));
        inv.model_runtimes.push(ModelRuntime {
            id: "ollama".into(),
            name: "Ollama".into(),
            owner: owner.to_string(),
            binary: ollama_bin.map(|p| p.to_string_lossy().into_owned()),
            models_dir: ollama_models.is_dir().then(|| ollama_models.to_string_lossy().into_owned()),
            model_count: count,
        });
    }
    // LM Studio.
    for rel in [".lmstudio", ".cache/lm-studio"] {
        let d = home.join(rel);
        if d.is_dir() {
            inv.model_runtimes.push(ModelRuntime {
                id: "lmstudio".into(),
                name: "LM Studio".into(),
                owner: owner.to_string(),
                binary: None,
                models_dir: Some(d.join("models").to_string_lossy().into_owned()),
                model_count: None,
            });
            break;
        }
    }
    // llama.cpp.
    if let Some(b) = find_binary(&["llama-server", "llama-cli"], bin_dirs) {
        inv.model_runtimes.push(ModelRuntime {
            id: "llama.cpp".into(),
            name: "llama.cpp".into(),
            owner: owner.to_string(),
            binary: Some(b.to_string_lossy().into_owned()),
            models_dir: None,
            model_count: None,
        });
    }
    // Hugging Face cache: models downloaded for local inference or training.
    let hf = home.join(".cache/huggingface/hub");
    if hf.is_dir() {
        let count = std::fs::read_dir(&hf).ok().map(|rd| {
            rd.flatten()
                .filter(|e| e.file_name().to_string_lossy().starts_with("models--"))
                .count()
        });
        inv.model_runtimes.push(ModelRuntime {
            id: "huggingface".into(),
            name: "Hugging Face model cache".into(),
            owner: owner.to_string(),
            binary: None,
            models_dir: Some(hf.to_string_lossy().into_owned()),
            model_count: count,
        });
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Config files are small; anything over 4 MiB is not a config we want to parse.
fn read_json(path: &Path) -> Option<serde_json::Value> {
    let meta = std::fs::metadata(path).ok()?;
    if !meta.is_file() || meta.len() > 4 * 1024 * 1024 {
        return None;
    }
    let text = std::fs::read_to_string(path).ok()?;
    serde_json::from_str(&text).ok()
}

fn count_dirs(dir: &Path) -> Option<usize> {
    std::fs::read_dir(dir)
        .ok()
        .map(|rd| rd.flatten().filter(|e| e.path().is_dir()).count())
}

fn strip_query(u: &str) -> String {
    u.split(['?', '#']).next().unwrap_or(u).to_string()
}

fn is_local_url(u: &str) -> bool {
    let host = u
        .split("://")
        .nth(1)
        .unwrap_or(u)
        .split(['/', ':'])
        .next()
        .unwrap_or("");
    matches!(host, "localhost" | "127.0.0.1" | "::1" | "[::1]") || host.ends_with(".localhost")
}

/// Does an environment variable NAME suggest it holds a credential? Matched on
/// whole words of the name, so `GITHUB_PAT` and `API_KEY` count but `PATH`,
/// `KEYBOARD_LAYOUT` and `AUTHOR` do not.
fn looks_secret_name(k: &str) -> bool {
    const WORDS: &[&str] = &[
        "token", "key", "apikey", "secret", "password", "passwd", "pwd", "pat",
        "auth", "credential", "credentials", "bearer", "cookie", "session",
    ];
    k.to_ascii_lowercase()
        .split(|c: char| !c.is_ascii_alphanumeric())
        .any(|w| WORDS.contains(&w))
}

/// `pkg@1.2.3` or `pkg==1.2.3` counts as pinned.
fn has_pinned_version(a: &str) -> bool {
    if a.contains("==") {
        return true;
    }
    // Ignore a leading scope "@org/…" when looking for "@version".
    let body = a.strip_prefix('@').unwrap_or(a);
    body.rsplit_once('@')
        .map(|(_, v)| v.chars().next().is_some_and(|c| c.is_ascii_digit()))
        .unwrap_or(false)
}

/// Keep an argument readable unless it could be a credential.
fn redact_arg(a: &str) -> String {
    if let Some((k, _)) = a.split_once('=') {
        if looks_secret_name(k) || a.len() > 40 {
            return format!("{k}=[redacted]");
        }
    }
    let alnum = a.chars().filter(|c| c.is_ascii_alphanumeric()).count();
    let long_opaque = a.len() >= 32 && alnum * 10 >= a.len() * 9 && !a.contains('/');
    let known_prefix = ["sk-", "ghp_", "gho_", "github_pat_", "xox", "AKIA", "AIza"]
        .iter()
        .any(|p| a.starts_with(p));
    if long_opaque || known_prefix {
        "[redacted]".to_string()
    } else {
        a.to_string()
    }
}

/// The same agent can be reachable from several homes via $HOME fallbacks, and
/// a server can be declared twice in one file under two keys we read. One row
/// each in the report.
fn dedup(inv: &mut Inventory) {
    let mut seen = std::collections::HashSet::new();
    inv.agents.retain(|a| seen.insert(format!("{}\0{}", a.id, a.owner)));
    let mut seen = std::collections::HashSet::new();
    inv.ide_extensions.retain(|e| seen.insert(e.path.clone()));
    let mut seen = std::collections::HashSet::new();
    inv.mcp_servers
        .retain(|m| seen.insert(format!("{}\0{}\0{}\0{}", m.agent, m.owner, m.scope, m.name)));
    let mut seen = std::collections::HashSet::new();
    inv.model_runtimes.retain(|r| seen.insert(format!("{}\0{}", r.id, r.owner)));
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> PathBuf {
        let d = std::env::temp_dir().join(format!(
            "rz-inventory-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn write(p: &Path, s: &str) {
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(p, s).unwrap();
    }

    #[test]
    fn finds_agents_by_binary_or_config_dir() {
        let h = fixture();
        write(&h.join(".local/bin/claude"), "");
        std::fs::create_dir_all(h.join(".gemini")).unwrap();
        let mut inv = Inventory::default();
        collect_home("dev", &h, &mut inv);
        let ids: Vec<_> = inv.agents.iter().map(|a| a.id.as_str()).collect();
        assert!(ids.contains(&"claude"));
        assert!(ids.contains(&"gemini"));
        let claude = inv.agents.iter().find(|a| a.id == "claude").unwrap();
        assert!(claude.binary.as_deref().unwrap().ends_with(".local/bin/claude"));
        assert!(claude.enforcement_covered);
    }

    #[test]
    fn finds_general_purpose_agents_too() {
        let h = fixture();
        write(&h.join(".local/bin/hermes"), "");
        std::fs::create_dir_all(h.join(".openclaw")).unwrap();
        let mut inv = Inventory::default();
        collect_home("dev", &h, &mut inv);
        for id in ["hermes", "openclaw"] {
            let a = inv.agents.iter().find(|a| a.id == id).unwrap_or_else(|| panic!("{id} not found"));
            assert!(a.enforcement_covered, "{id} is in agent_detect, so it is enforced");
        }
    }

    #[test]
    fn unrecognised_agent_is_reported_as_not_covered() {
        let h = fixture();
        write(&h.join(".local/bin/goose"), "");
        let mut inv = Inventory::default();
        collect_home("dev", &h, &mut inv);
        let goose = inv.agents.iter().find(|a| a.id == "goose").unwrap();
        assert!(!goose.enforcement_covered, "goose is not in agent_detect; the screen must say so");
    }

    #[test]
    fn extensions_longest_prefix_wins() {
        let h = fixture();
        std::fs::create_dir_all(h.join(".vscode/extensions/github.copilot-chat-0.30.1")).unwrap();
        std::fs::create_dir_all(h.join(".vscode/extensions/github.copilot-1.300.0")).unwrap();
        std::fs::create_dir_all(h.join(".vscode/extensions/ms-python.python-2026.1.0")).unwrap();
        let mut inv = Inventory::default();
        collect_home("dev", &h, &mut inv);
        let mut names: Vec<_> = inv.ide_extensions.iter().map(|e| (e.name.as_str(), e.version.as_str())).collect();
        names.sort();
        assert_eq!(names, vec![("GitHub Copilot", "1.300.0"), ("GitHub Copilot Chat", "0.30.1")]);
    }

    #[test]
    fn mcp_servers_from_claude_user_and_project_scope() {
        let h = fixture();
        let proj = h.join("projects/app");
        write(
            &h.join(".claude.json"),
            &format!(
                r#"{{"mcpServers":{{"fs":{{"command":"npx","args":["-y","@modelcontextprotocol/server-filesystem","/home"]}}}},
                   "projects":{{"{}":{{"mcpServers":{{"remote":{{"type":"http","url":"https://mcp.example.com/v1?token=abc","headers":{{"Authorization":"x"}}}}}}}}}}}}"#,
                proj.display()
            ),
        );
        write(&proj.join(".mcp.json"), r#"{"mcpServers":{"db":{"command":"uvx","args":["db-mcp==1.2.0"],"env":{"DB_PASSWORD":"x"}}}}"#);
        let mut inv = Inventory::default();
        collect_home("dev", &h, &mut inv);

        let fs = inv.mcp_servers.iter().find(|m| m.name == "fs").unwrap();
        assert_eq!(fs.transport, "stdio");
        assert_eq!(fs.scope, "user");
        assert!(fs.flags.contains(&"unpinned package".to_string()));

        let remote = inv.mcp_servers.iter().find(|m| m.name == "remote").unwrap();
        assert_eq!(remote.transport, "http");
        assert_eq!(remote.url.as_deref(), Some("https://mcp.example.com/v1"), "query string must be dropped");
        assert!(remote.flags.contains(&"remote".to_string()));
        assert!(remote.flags.contains(&"credentials in config".to_string()));

        let db = inv.mcp_servers.iter().find(|m| m.name == "db").unwrap();
        assert_eq!(db.env_keys, vec!["DB_PASSWORD".to_string()]);
        assert!(!db.flags.contains(&"unpinned package".to_string()), "==1.2.0 is pinned");
        assert!(db.scope.starts_with("project:"));
    }

    #[test]
    fn codex_toml_mcp() {
        let h = fixture();
        write(&h.join(".codex/config.toml"), "[mcp_servers.docs]\ncommand = \"docs-mcp\"\nargs = [\"--port\", \"0\"]\n");
        let mut inv = Inventory::default();
        collect_home("dev", &h, &mut inv);
        let d = inv.mcp_servers.iter().find(|m| m.name == "docs").unwrap();
        assert_eq!(d.agent, "codex");
        assert_eq!(d.command.as_deref(), Some("docs-mcp --port 0"));
    }

    #[test]
    fn secrets_never_leave_the_module() {
        assert_eq!(redact_arg("GITHUB_TOKEN=ghp_abcdef"), "GITHUB_TOKEN=[redacted]");
        assert_eq!(redact_arg("ghp_0123456789abcdef0123456789abcdef0123"), "[redacted]");
        assert_eq!(redact_arg("sk-live-xyz"), "[redacted]");
        assert_eq!(redact_arg("0123456789abcdef0123456789abcdef"), "[redacted]");
        assert_eq!(redact_arg("@modelcontextprotocol/server-filesystem"), "@modelcontextprotocol/server-filesystem");
        assert_eq!(redact_arg("--port"), "--port");
    }

    #[test]
    fn secret_names_are_whole_words() {
        for yes in ["GITHUB_TOKEN", "API_KEY", "GITHUB_PAT", "DB_PASSWORD", "x-auth", "OPENAI_APIKEY"] {
            assert!(looks_secret_name(yes), "{yes}");
        }
        for no in ["PATH", "NODE_PATH", "CODEX_CLI_PATH", "KEYBOARD_LAYOUT", "AUTHOR", "MONKEY", "HOME"] {
            assert!(!looks_secret_name(no), "{no}");
        }
    }

    #[test]
    fn local_url_and_pinning() {
        assert!(is_local_url("http://localhost:3000/mcp"));
        assert!(is_local_url("http://127.0.0.1:8080"));
        assert!(!is_local_url("https://mcp.example.com"));
        assert!(has_pinned_version("@scope/pkg@1.0.0"));
        assert!(!has_pinned_version("@scope/pkg"));
        assert!(!has_pinned_version("pkg@latest"));
    }

    #[test]
    fn runtimes() {
        let h = fixture();
        std::fs::create_dir_all(h.join(".ollama/models/manifests/registry.ollama.ai/library/llama3")).unwrap();
        std::fs::create_dir_all(h.join(".ollama/models/manifests/registry.ollama.ai/library/qwen3")).unwrap();
        std::fs::create_dir_all(h.join(".cache/huggingface/hub/models--org--m")).unwrap();
        let mut inv = Inventory::default();
        collect_home("dev", &h, &mut inv);
        let o = inv.model_runtimes.iter().find(|r| r.id == "ollama").unwrap();
        assert_eq!(o.model_count, Some(2));
        let hf = inv.model_runtimes.iter().find(|r| r.id == "huggingface").unwrap();
        assert_eq!(hf.model_count, Some(1));
    }

    #[test]
    fn empty_home_is_empty() {
        let h = fixture();
        let mut inv = Inventory::default();
        collect_home("dev", &h, &mut inv);
        assert!(inv.agents.is_empty() && inv.mcp_servers.is_empty() && inv.ide_extensions.is_empty());
    }
}
