// SPDX-License-Identifier: Apache-2.0
//! MCP gateway: Ring Zero sits between agents and their remote MCP servers.
//!
//! `rz mcp adopt` points each agent's remote MCP servers at
//! `http://127.0.0.1:7700/mcp/<id>` and registers the real server here. The
//! agent then speaks MCP to the gateway in the clear, on loopback, so the
//! gateway can see every request and apply the administrator's choices:
//!
//! - a switched-off tool is removed from `tools/list`, so the agent never sees it;
//! - a `tools/call` to a switched-off tool is answered with an error and never
//!   reaches the server;
//! - every tool call, allowed or refused, is recorded (commentary, Security
//!   history).
//!
//! The kernel makes the gateway the only way through: agents are refused direct
//! connections to an adopted server's addresses (`ebpf_loader`, mcp upstreams),
//! so an agent that edits its config back cannot route around it. The daemon
//! itself is not an agent, so it can reach the server.
//!
//! The agent's own request headers (including any Authorization it was
//! configured with) are passed through to the server; the gateway stores no
//! credentials.
//!
//! The registry lives at /etc/ringzero/mcp-gateway.json and changes only
//! through the full-scope API, which the app reaches through `rz` under
//! polkit, so every change asks for the administrator password.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::RwLock;

use serde::{Deserialize, Serialize};

pub const REGISTRY_PATH: &str = "/etc/ringzero/mcp-gateway.json";
/// What a refused event's target starts with, like "TAMPER:" and "PKG_INSTALL:".
pub const TARGET_PREFIX: &str = "MCP_TOOL:";

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ManagedServer {
    /// The path segment agents use: /mcp/<id>.
    pub id: String,
    /// The server's name in the agent's config ("deepwiki").
    pub name: String,
    /// Which agent's config it came from ("opencode", "claude", ...).
    pub agent: String,
    /// The real server's URL.
    pub upstream: String,
    /// The config file it was adopted from, and the owner of that file.
    #[serde(default)]
    pub source: String,
    #[serde(default)]
    pub owner: String,
    /// Tools the administrator switched off.
    #[serde(default)]
    pub disabled_tools: BTreeSet<String>,
    /// Tools the server listed the last time an agent asked, with their
    /// one-line descriptions, so Discovery can show switches for them.
    #[serde(default)]
    pub seen_tools: BTreeMap<String, String>,
}

/// A remote MCP server that appeared in an agent's config after Ring Zero
/// started managing MCP. Agents may not reach it until an administrator
/// approves it (which routes it through the gateway) .
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct HeldServer {
    pub id: String,
    pub name: String,
    pub agent: String,
    pub owner: String,
    pub upstream: String,
    pub source: String,
    /// RFC 3339.
    pub first_seen: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Registry {
    #[serde(default)]
    pub servers: BTreeMap<String, ManagedServer>,
    /// New remote servers waiting for approval, by id.
    #[serde(default)]
    pub held: BTreeMap<String, HeldServer>,
}

static REGISTRY: once_cell::sync::Lazy<RwLock<Registry>> =
    once_cell::sync::Lazy::new(|| RwLock::new(load()));

fn load() -> Registry {
    std::fs::read_to_string(REGISTRY_PATH)
        .ok()
        .and_then(|t| serde_json::from_str(&t).ok())
        .unwrap_or_default()
}

fn save(r: &Registry) -> Result<(), String> {
    let path = std::path::Path::new(REGISTRY_PATH);
    if let Some(dir) = path.parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    let tmp = path.with_extension("json.tmp");
    let text = serde_json::to_string_pretty(r).map_err(|e| e.to_string())?;
    std::fs::write(&tmp, text).map_err(|e| e.to_string())?;
    std::fs::rename(&tmp, path).map_err(|e| e.to_string())
}

pub fn snapshot() -> Registry {
    REGISTRY.read().map(|r| r.clone()).unwrap_or_default()
}

fn valid_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 64
        && id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
}

fn valid_upstream(u: &str) -> bool {
    u.starts_with("https://") || u.starts_with("http://")
}

/// Register (or update) a server. Keeps the switches already set for it.
pub fn upsert(mut s: ManagedServer) -> Result<ManagedServer, String> {
    if !valid_id(&s.id) {
        return Err("id may only hold letters, digits, - and _".into());
    }
    if !valid_upstream(&s.upstream) {
        return Err("upstream must be an http(s) URL".into());
    }
    if s.upstream.contains("127.0.0.1:7700/mcp/") || s.upstream.contains("localhost:7700/mcp/") {
        return Err("upstream points at the gateway itself".into());
    }
    let mut r = REGISTRY.write().map_err(|_| "registry lock poisoned")?;
    if let Some(old) = r.servers.get(&s.id) {
        s.disabled_tools.extend(old.disabled_tools.iter().cloned());
        for (k, v) in &old.seen_tools {
            s.seen_tools.entry(k.clone()).or_insert_with(|| v.clone());
        }
    }
    r.held.remove(&s.id);
    r.servers.insert(s.id.clone(), s.clone());
    save(&r)?;
    Ok(s)
}

pub fn remove(id: &str) -> Result<(), String> {
    let mut r = REGISTRY.write().map_err(|_| "registry lock poisoned")?;
    if r.servers.remove(id).is_none() {
        return Err(format!("no managed MCP server called {id}"));
    }
    save(&r)
}

/// Switch one tool on or off.
pub fn set_tool(id: &str, tool: &str, enabled: bool) -> Result<ManagedServer, String> {
    if tool.is_empty() || tool.len() > 128 || tool.chars().any(|c| c.is_control()) {
        return Err("not a tool name".into());
    }
    let mut r = REGISTRY.write().map_err(|_| "registry lock poisoned")?;
    let s = r
        .servers
        .get_mut(id)
        .ok_or_else(|| format!("no managed MCP server called {id}"))?;
    if enabled {
        s.disabled_tools.remove(tool);
    } else {
        s.disabled_tools.insert(tool.to_string());
    }
    let out = s.clone();
    save(&r)?;
    Ok(out)
}

fn remember_tools(id: &str, tools: &[serde_json::Value]) {
    let mut seen = BTreeMap::new();
    for t in tools {
        if let Some(name) = t.get("name").and_then(|v| v.as_str()) {
            let d = t
                .get("description")
                .and_then(|v| v.as_str())
                .map(first_sentence)
                .unwrap_or_default();
            seen.insert(name.to_string(), d);
        }
    }
    if seen.is_empty() {
        return;
    }
    if let Ok(mut r) = REGISTRY.write() {
        if let Some(s) = r.servers.get_mut(id) {
            if s.seen_tools != seen {
                s.seen_tools = seen;
                let _ = save(&r);
            }
        }
    }
}

/// Fill a newly managed server's tool list by asking it, so its switches show
/// before any agent has connected. Only works for servers that need no sign-in;
/// the others fill in when an agent first lists their tools.
pub async fn seed_tools(id: &str, upstream: &str) {
    if let Ok(tools) = crate::scanner::mcp_tools::tools_for(upstream).await {
        let as_json: Vec<serde_json::Value> = tools
            .iter()
            .map(|t| serde_json::json!({"name": t.name, "description": t.description}))
            .collect();
        remember_tools(id, &as_json);
    }
}

fn first_sentence(s: &str) -> String {
    // First paragraph only, on one line.
    let para = s.trim().split("\n\n").next().unwrap_or("");
    let flat = para.split_whitespace().collect::<Vec<_>>().join(" ");
    let s = flat.as_str();
    let end = s.find(". ").map(|i| i + 1).unwrap_or(s.len()).min(160);
    let mut cut = end;
    while !s.is_char_boundary(cut) {
        cut -= 1;
    }
    s[..cut].trim().to_string()
}

// ── Kernel ───────────────────────────────────────────────────────────────────

/// Resolve every managed server's host and hand the addresses to the kernel,
/// which refuses agent trees a direct connection to them.
pub async fn sync_kernel() {
    let reg = snapshot();
    let upstreams: Vec<String> = reg
        .servers
        .values()
        .map(|s| s.upstream.clone())
        .chain(reg.held.values().map(|h| h.upstream.clone()))
        .collect();
    let hosts: BTreeSet<String> = upstreams
        .iter()
        .filter_map(|u| reqwest::Url::parse(u).ok())
        .filter_map(|u| {
            u.host_str()
                .map(|h| (h.to_string(), u.port_or_known_default().unwrap_or(443)))
        })
        .map(|(h, p)| format!("{h}:{p}"))
        .collect();
    let mut ips = Vec::new();
    for hp in hosts {
        if let Ok(addrs) = tokio::net::lookup_host(hp.as_str()).await {
            ips.extend(addrs.map(|a| a.ip()));
        }
    }
    ips.retain(|ip| !ip.is_loopback() && !ip.is_unspecified());
    ips.sort();
    ips.dedup();
    if let Some(tx) = crate::ebpf_loader::CMD_TX.get() {
        let _ = tx
            .send(crate::ebpf_loader::EbpfCommand::SetMcpUpstreams(ips))
            .await;
    }
}

/// Keep the kernel's address set current: CDNs move servers between addresses.
pub fn spawn_refresh() {
    tokio::spawn(async {
        loop {
            sync_kernel().await;
            tokio::time::sleep(std::time::Duration::from_secs(60)).await;
        }
    });
}

// ── Watching agents' configs ─────────────────────────────────────────────────

/// The id `rz mcp adopt` gives a server: name, agent and owner, path-safe.
pub fn server_id(name: &str, agent: &str, owner: &str) -> String {
    format!("{name}-{agent}-{owner}")
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .take(64)
        .collect()
}

fn is_gateway_url(u: &str) -> bool {
    u.starts_with("http://127.0.0.1:7700/mcp/") || u.starts_with("http://localhost:7700/mcp/")
}

/// One pass over every agent's MCP config. Once Ring Zero manages MCP (at
/// least one server adopted), a remote server that is neither managed nor
/// already held is held: its addresses join the set agents may not reach, and
/// the record says so. A managed server whose address in the config changed is
/// held again under its new address.
pub async fn watch_once(record: &(dyn Fn(crate::common::event::SecurityEvent) + Send + Sync)) {
    if snapshot().servers.is_empty() {
        return;
    }
    let inv = match tokio::task::spawn_blocking(crate::scanner::inventory::collect).await {
        Ok(i) => i,
        Err(_) => return,
    };
    let mut newly_held = Vec::new();
    let mut dropped_any = false;
    {
        let Ok(mut r) = REGISTRY.write() else { return };
        for m in &inv.mcp_servers {
            let Some(url) = m.url.as_deref() else {
                continue;
            };
            if m.transport != "http"
                || is_gateway_url(url)
                || !m.flags.iter().any(|f| f == "remote")
            {
                continue;
            }
            let id = server_id(&m.name, &m.agent, &m.owner);
            if r.servers.get(&id).is_some_and(|s| s.upstream == url) {
                // The config was pointed back at a managed server. The kernel
                // already refuses that path; nothing new to hold.
                continue;
            }
            if r.held.get(&id).is_some_and(|h| h.upstream == url) {
                continue;
            }
            let h = HeldServer {
                id: id.clone(),
                name: m.name.clone(),
                agent: m.agent.clone(),
                owner: m.owner.clone(),
                upstream: url.to_string(),
                source: m.source.clone(),
                first_seen: chrono::Utc::now().to_rfc3339(),
            };
            r.held.insert(id, h.clone());
            newly_held.push(h);
        }
        // A held server that left every config is no longer waiting for
        // anything: drop it, and its addresses leave the refused set.
        let present: BTreeSet<String> = inv
            .mcp_servers
            .iter()
            .filter(|m| m.url.as_deref().is_some_and(|u| !is_gateway_url(u)))
            .map(|m| server_id(&m.name, &m.agent, &m.owner))
            .collect();
        let before = r.held.len();
        r.held.retain(|id, _| present.contains(id));
        let dropped = before != r.held.len();
        if !newly_held.is_empty() || dropped {
            let _ = save(&r);
        }
        dropped_any = dropped;
    }
    if newly_held.is_empty() {
        if dropped_any {
            sync_kernel().await;
        }
        return;
    }
    sync_kernel().await;
    for h in newly_held {
        tracing::warn!(server = %h.name, agent = %h.agent, upstream = %h.upstream, "New MCP server held until an administrator approves it");
        let host = reqwest::Url::parse(&h.upstream)
            .ok()
            .and_then(|u| u.host_str().map(String::from))
            .unwrap_or_default();
        let now = chrono::Utc::now();
        record(crate::common::event::SecurityEvent {
            id: format!(
                "mcp-held-{}-{}",
                now.timestamp_nanos_opt().unwrap_or_default(),
                h.id
            ),
            kind: crate::common::event::EventKind::McpToolCall,
            pid: 0,
            uid: 0,
            process: h.agent.clone(),
            target: format!("{HELD_PREFIX}{}", h.name),
            allowed: false,
            reason: Some("New MCP server: held until an administrator approves it".into()),
            timestamp: now,
            ppid: None,
            parent_process: None,
            llm_context: None,
            extra: Some(
                serde_json::json!({"mcp_server": h.name, "host": host, "source": h.source, "held": true}),
            ),
        });
    }
}

/// Watch agents' MCP configs for new servers, every ten seconds.
pub fn spawn_watch(record: Box<dyn Fn(crate::common::event::SecurityEvent) + Send + Sync>) {
    tokio::spawn(async move {
        loop {
            watch_once(record.as_ref()).await;
            tokio::time::sleep(std::time::Duration::from_secs(10)).await;
        }
    });
}

/// What a held server's record target starts with.
pub const HELD_PREFIX: &str = "MCP_HELD:";

// ── Messages ─────────────────────────────────────────────────────────────────

/// The JSON-RPC messages in a request body: one object, or a batch.
fn messages(body: &serde_json::Value) -> Vec<&serde_json::Value> {
    match body {
        serde_json::Value::Array(a) => a.iter().collect(),
        v @ serde_json::Value::Object(_) => vec![v],
        _ => Vec::new(),
    }
}

/// Tool calls in a request: (JSON-RPC id, tool name, arguments).
fn tool_calls(body: &serde_json::Value) -> Vec<(serde_json::Value, String, serde_json::Value)> {
    messages(body)
        .into_iter()
        .filter(|m| m.get("method").and_then(|v| v.as_str()) == Some("tools/call"))
        .filter_map(|m| {
            let name = m.pointer("/params/name")?.as_str()?.to_string();
            let id = m.get("id").cloned().unwrap_or(serde_json::Value::Null);
            let args = m
                .pointer("/params/arguments")
                .cloned()
                .unwrap_or(serde_json::Value::Null);
            Some((id, name, args))
        })
        .collect()
}

fn asks_for_tools(body: &serde_json::Value) -> bool {
    messages(body)
        .iter()
        .any(|m| m.get("method").and_then(|v| v.as_str()) == Some("tools/list"))
}

fn refusal(id: serde_json::Value, server: &str, tool: &str) -> serde_json::Value {
    serde_json::json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": {
            "code": -32001,
            "message": format!(
                "Ring Zero Security refused this call: the {tool} tool of the {server} MCP server is switched off on this machine. \
                 Ask the person you are working for if you need it."
            )
        }
    })
}

/// Remove switched-off tools from a tools/list result, in place. Returns the
/// full list the server offered (before filtering), for Discovery.
fn filter_tool_list(
    v: &mut serde_json::Value,
    disabled: &BTreeSet<String>,
) -> Option<Vec<serde_json::Value>> {
    let tools = v.pointer_mut("/result/tools")?.as_array_mut()?;
    let all = tools.clone();
    tools.retain(|t| {
        t.get("name")
            .and_then(|n| n.as_str())
            .map(|n| !disabled.contains(n))
            .unwrap_or(true)
    });
    Some(all)
}

/// Apply `filter_tool_list` to a response body that is plain JSON (one object
/// or a batch) or an SSE stream of `data:` lines.
fn filter_body(
    body: &str,
    disabled: &BTreeSet<String>,
) -> (String, Option<Vec<serde_json::Value>>) {
    let mut offered = None;
    let mut fix = |v: &mut serde_json::Value| {
        let found = match v {
            serde_json::Value::Array(a) => a.iter_mut().find_map(|m| filter_tool_list(m, disabled)),
            _ => filter_tool_list(v, disabled),
        };
        if found.is_some() {
            offered = found;
        }
    };
    if let Ok(mut v) = serde_json::from_str::<serde_json::Value>(body) {
        fix(&mut v);
        return (v.to_string(), offered);
    }
    let mut out = String::with_capacity(body.len());
    for line in body.split_inclusive('\n') {
        let (content, nl) = match line.strip_suffix('\n') {
            Some(c) => (c.strip_suffix('\r').unwrap_or(c), "\n"),
            None => (line, ""),
        };
        if let Some(data) = content.strip_prefix("data:") {
            if let Ok(mut v) = serde_json::from_str::<serde_json::Value>(data.trim()) {
                fix(&mut v);
                out.push_str("data: ");
                out.push_str(&v.to_string());
                out.push_str(nl);
                continue;
            }
        }
        out.push_str(line);
    }
    (out, offered)
}

// ── Recording ────────────────────────────────────────────────────────────────

/// Which agent is on the other end of this connection, and its pid.
fn caller(peer: std::net::SocketAddr) -> (u32, String) {
    match crate::api::caller::pid_for_peer(peer) {
        Ok(pid) => match crate::api::caller::agent_in_lineage(pid) {
            Some((apid, comm)) => (apid, comm),
            None => (
                pid,
                std::fs::read_to_string(format!("/proc/{pid}/comm"))
                    .map(|c| c.trim().to_string())
                    .unwrap_or_default(),
            ),
        },
        Err(_) => (0, String::new()),
    }
}

fn event(
    pid: u32,
    process: &str,
    server: &str,
    tool: &str,
    args: &serde_json::Value,
    allowed: bool,
) -> crate::common::event::SecurityEvent {
    let now = chrono::Utc::now();
    let mut shown = args.to_string();
    if shown.len() > 400 {
        let mut cut = 400;
        while !shown.is_char_boundary(cut) {
            cut -= 1;
        }
        shown.truncate(cut);
        shown.push('…');
    }
    crate::common::event::SecurityEvent {
        id: format!(
            "mcp-{}-{}",
            now.timestamp_nanos_opt().unwrap_or_default(),
            pid
        ),
        kind: crate::common::event::EventKind::McpToolCall,
        pid,
        uid: 0,
        process: if process.is_empty() {
            "agent".into()
        } else {
            process.into()
        },
        target: format!("{TARGET_PREFIX}{server}/{tool}"),
        allowed,
        reason: (!allowed).then(|| format!("The {tool} tool of {server} is switched off")),
        timestamp: now,
        ppid: None,
        parent_process: None,
        llm_context: None,
        extra: Some(serde_json::json!({ "mcp_server": server, "tool": tool, "arguments": shown })),
    }
}

// ── The proxy ────────────────────────────────────────────────────────────────

use axum::body::Bytes;
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode};
use axum::response::{IntoResponse, Response};

/// Request headers passed through to the server.
const PASS_UP: &[&str] = &[
    "content-type",
    "accept",
    "authorization",
    "mcp-session-id",
    "mcp-protocol-version",
    "last-event-id",
    "user-agent",
];
/// Response headers passed back to the agent.
const PASS_DOWN: &[&str] = &["content-type", "mcp-session-id", "www-authenticate"];

static CLIENT: once_cell::sync::Lazy<reqwest::Client> = once_cell::sync::Lazy::new(|| {
    reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(120))
        .build()
        .unwrap_or_default()
});

fn json_response(v: &serde_json::Value) -> Response {
    let mut r = (StatusCode::OK, v.to_string()).into_response();
    r.headers_mut()
        .insert("content-type", HeaderValue::from_static("application/json"));
    r
}

pub async fn handle(
    id: String,
    peer: std::net::SocketAddr,
    method: Method,
    headers: HeaderMap,
    body: Bytes,
    record: impl Fn(crate::common::event::SecurityEvent),
) -> Response {
    // Agents reach this on loopback only.
    if !peer.ip().is_loopback() {
        return (
            StatusCode::FORBIDDEN,
            "the MCP gateway is reachable from this machine only",
        )
            .into_response();
    }
    let Some(server) = snapshot().servers.get(&id).cloned() else {
        return (
            StatusCode::NOT_FOUND,
            format!("no MCP server called {id} is managed by Ring Zero Security"),
        )
            .into_response();
    };
    // The optional server-to-client stream (GET) is not offered; MCP clients
    // then use POST only, which is all the gateway needs to see.
    if method == Method::GET {
        return (StatusCode::METHOD_NOT_ALLOWED, "").into_response();
    }

    let parsed: Option<serde_json::Value> = serde_json::from_slice(&body).ok();
    let (pid, process) = caller(peer);

    if let Some(v) = &parsed {
        let calls = tool_calls(v);
        let refused: Vec<_> = calls
            .iter()
            .filter(|(_, name, _)| server.disabled_tools.contains(name))
            .collect();
        if !refused.is_empty() {
            for (_, name, args) in &refused {
                record(event(pid, &process, &server.name, name, args, false));
            }
            // A single call, or a batch holding a refused call, is answered
            // here: one error per refused call, and nothing goes upstream.
            let errors: Vec<_> = refused
                .iter()
                .map(|(rid, name, _)| refusal(rid.clone(), &server.name, name))
                .collect();
            return if v.is_array() {
                json_response(&serde_json::Value::Array(errors))
            } else {
                json_response(&errors[0])
            };
        }
        for (_, name, args) in &calls {
            record(event(pid, &process, &server.name, name, args, true));
        }
    }

    let mut req = CLIENT
        .request(method.clone(), &server.upstream)
        .body(body.to_vec());
    for (k, v) in headers.iter() {
        if PASS_UP.contains(&k.as_str()) {
            req = req.header(k.as_str(), v.as_bytes());
        }
    }
    let up = match req.send().await {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!(server = %server.name, err = %e, "MCP gateway could not reach the server");
            return (
                StatusCode::BAD_GATEWAY,
                format!(
                    "Ring Zero Security could not reach the {} MCP server",
                    server.name
                ),
            )
                .into_response();
        }
    };
    let status = StatusCode::from_u16(up.status().as_u16()).unwrap_or(StatusCode::BAD_GATEWAY);
    let mut down = HeaderMap::new();
    for (k, v) in up.headers().iter() {
        if PASS_DOWN.contains(&k.as_str()) {
            if let (Ok(name), Ok(val)) = (
                axum::http::HeaderName::from_bytes(k.as_str().as_bytes()),
                HeaderValue::from_bytes(v.as_bytes()),
            ) {
                down.insert(name, val);
            }
        }
    }
    let text = up.text().await.unwrap_or_default();
    let text = if parsed.as_ref().is_some_and(asks_for_tools) {
        let (filtered, offered) = filter_body(&text, &server.disabled_tools);
        if let Some(all) = offered {
            remember_tools(&id, &all);
        }
        filtered
    } else {
        text
    };
    let mut r = (status, text).into_response();
    r.headers_mut().extend(down);
    r
}

#[cfg(test)]
mod tests {
    use super::*;

    fn disabled(names: &[&str]) -> BTreeSet<String> {
        names.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn switched_off_tools_vanish_from_the_list() {
        let body = r#"{"jsonrpc":"2.0","id":2,"result":{"tools":[{"name":"ask_question"},{"name":"read_wiki_contents"}]}}"#;
        let (out, offered) = filter_body(body, &disabled(&["read_wiki_contents"]));
        let v: serde_json::Value = serde_json::from_str(&out).unwrap();
        let names: Vec<_> = v
            .pointer("/result/tools")
            .unwrap()
            .as_array()
            .unwrap()
            .iter()
            .map(|t| t["name"].as_str().unwrap())
            .collect();
        assert_eq!(names, vec!["ask_question"]);
        assert_eq!(
            offered.unwrap().len(),
            2,
            "Discovery still learns every tool the server offers"
        );
    }

    #[test]
    fn sse_answers_are_filtered_too() {
        let body = "event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":2,\"result\":{\"tools\":[{\"name\":\"a\"},{\"name\":\"b\"}]}}\n\n";
        let (out, _) = filter_body(body, &disabled(&["b"]));
        assert!(out.contains("\"a\"") && !out.contains("\"b\""), "{out}");
        assert!(out.starts_with("event: message\n"));
    }

    #[test]
    fn tool_calls_are_found_in_single_and_batch_requests() {
        let one: serde_json::Value = serde_json::from_str(r#"{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"ask_question","arguments":{"q":"x"}}}"#).unwrap();
        assert_eq!(tool_calls(&one)[0].1, "ask_question");
        let batch: serde_json::Value = serde_json::from_str(r#"[{"jsonrpc":"2.0","id":1,"method":"tools/list"},{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"b"}}]"#).unwrap();
        assert_eq!(tool_calls(&batch).len(), 1);
        assert!(asks_for_tools(&batch));
    }

    #[test]
    fn a_refusal_is_a_json_rpc_error_for_the_same_id() {
        let r = refusal(serde_json::json!(7), "deepwiki", "ask_question");
        assert_eq!(r["id"], 7);
        assert!(r["error"]["message"]
            .as_str()
            .unwrap()
            .contains("switched off"));
    }

    #[test]
    fn server_ids_match_what_adopt_makes() {
        assert_eq!(
            server_id("deepwiki", "opencode", "vboxuser"),
            "deepwiki-opencode-vboxuser"
        );
        assert_eq!(
            server_id("My Server", "claude", "a.b"),
            "my-server-claude-a-b"
        );
        assert!(is_gateway_url("http://127.0.0.1:7700/mcp/x"));
        assert!(!is_gateway_url("https://mcp.deepwiki.com/mcp"));
    }

    #[test]
    fn ids_and_upstreams_are_checked() {
        assert!(valid_id("deepwiki-opencode"));
        assert!(!valid_id("../etc"));
        assert!(valid_upstream("https://mcp.deepwiki.com/mcp"));
        assert!(!valid_upstream("file:///etc/passwd"));
    }
}
