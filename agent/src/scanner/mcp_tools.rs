// SPDX-License-Identifier: Apache-2.0
//! The tools a remote MCP server offers, for Discovery.
//!
//! Asked of the server itself with the standard MCP handshake (initialize, then
//! tools/list) over streamable HTTP. Only for remote servers whose config holds
//! no credentials: the daemon never sends anyone's tokens anywhere, so a server
//! that needs sign-in is listed without its tools. Local (stdio) servers are
//! never started to ask: discovery does not run what it finds.
//!
//! Answers are cached for ten minutes, and each server gets a few seconds.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use serde::Serialize;

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct McpTool {
    pub name: String,
    /// First sentence of the server's own description, if it gave one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

const TTL: Duration = Duration::from_secs(600);
const TIMEOUT: Duration = Duration::from_secs(6);

type Cached = (Instant, Result<Vec<McpTool>, String>);
static CACHE: once_cell::sync::Lazy<Mutex<HashMap<String, Cached>>> =
    once_cell::sync::Lazy::new(|| Mutex::new(HashMap::new()));

/// Tools for one remote server, from cache or the server.
pub async fn tools_for(url: &str) -> Result<Vec<McpTool>, String> {
    if let Some((at, r)) = CACHE.lock().ok().and_then(|c| c.get(url).cloned()) {
        if at.elapsed() < TTL {
            return r;
        }
    }
    let r = match tokio::time::timeout(TIMEOUT, fetch(url)).await {
        Ok(r) => r,
        Err(_) => Err("the server did not answer in time".into()),
    };
    if let Ok(mut c) = CACHE.lock() {
        c.insert(url.to_string(), (Instant::now(), r.clone()));
    }
    r
}

/// A JSON-RPC answer from a streamable-HTTP server: plain JSON, or an SSE
/// stream whose `data:` lines carry it.
fn parse_body(body: &str) -> Option<serde_json::Value> {
    if let Ok(v) = serde_json::from_str::<serde_json::Value>(body) {
        return Some(v);
    }
    body.lines()
        .filter_map(|l| l.strip_prefix("data:"))
        .filter_map(|d| serde_json::from_str::<serde_json::Value>(d.trim()).ok())
        .find(|v| v.get("result").is_some() || v.get("error").is_some())
}

async fn fetch(url: &str) -> Result<Vec<McpTool>, String> {
    let client = reqwest::Client::builder()
        .timeout(TIMEOUT)
        .user_agent("ring-zero-discovery")
        .build()
        .map_err(|e| e.to_string())?;
    let post = |body: serde_json::Value, session: Option<String>| {
        let mut req = client
            .post(url)
            .header("Content-Type", "application/json")
            .header("Accept", "application/json, text/event-stream")
            .header("MCP-Protocol-Version", "2025-03-26");
        if let Some(s) = session {
            req = req.header("Mcp-Session-Id", s);
        }
        req.json(&body).send()
    };

    let init = post(
        serde_json::json!({
            "jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": {
                "protocolVersion": "2025-03-26",
                "capabilities": {},
                "clientInfo": {"name": "ring-zero-discovery", "version": env!("CARGO_PKG_VERSION")}
            }
        }),
        None,
    )
    .await
    .map_err(|_| "could not reach the server".to_string())?;
    if init.status() == reqwest::StatusCode::UNAUTHORIZED
        || init.status() == reqwest::StatusCode::FORBIDDEN
    {
        return Err("the server needs sign-in".into());
    }
    if !init.status().is_success() {
        return Err(format!("the server answered {}", init.status().as_u16()));
    }
    let session = init
        .headers()
        .get("mcp-session-id")
        .and_then(|v| v.to_str().ok())
        .map(String::from);
    let _ = init.text().await;

    let _ = post(
        serde_json::json!({"jsonrpc": "2.0", "method": "notifications/initialized"}),
        session.clone(),
    )
    .await;

    let list = post(
        serde_json::json!({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}),
        session,
    )
    .await
    .map_err(|_| "could not reach the server".to_string())?;
    let body = list.text().await.map_err(|e| e.to_string())?;
    let v = parse_body(&body).ok_or("the server's answer was not MCP")?;
    let tools = v
        .pointer("/result/tools")
        .and_then(|t| t.as_array())
        .ok_or("the server listed no tools")?;
    Ok(tools
        .iter()
        .filter_map(|t| {
            let name = t.get("name")?.as_str()?.to_string();
            let description = t
                .get("description")
                .and_then(|d| d.as_str())
                .map(first_sentence)
                .filter(|d| !d.is_empty());
            Some(McpTool { name, description })
        })
        .collect())
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_plain_json_and_sse_answers() {
        let plain = r#"{"jsonrpc":"2.0","id":2,"result":{"tools":[{"name":"a"}]}}"#;
        assert!(parse_body(plain)
            .unwrap()
            .pointer("/result/tools")
            .is_some());
        let sse =
            "event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":2,\"result\":{\"tools\":[]}}\n\n";
        assert!(parse_body(sse).unwrap().pointer("/result/tools").is_some());
        assert!(parse_body("<html>").is_none());
    }

    #[test]
    fn descriptions_are_cut_to_one_sentence() {
        assert_eq!(
            first_sentence("Ask a question. It answers."),
            "Ask a question."
        );
        assert_eq!(first_sentence("  Lists files  "), "Lists files");
        assert_eq!(
            first_sentence("Fetches docs\nfor any library\n\nYou must call x first."),
            "Fetches docs for any library"
        );
    }
}
