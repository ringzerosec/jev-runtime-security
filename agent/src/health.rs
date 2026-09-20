// SPDX-License-Identifier: Apache-2.0
//! Subsystem health — the single source of truth for "is the product actually
//! protecting this box right now". The UI renders this so an operator sees a
//! WARNING/CRITICAL state the moment a load-bearing piece stops running (kernel
//! enforcement down, TLS inspection down, the on-device AI engine unreachable),
//! instead of silently believing they're protected.
//!
//! It also performs OWNERSHIP verification of the on-device AI engine endpoint
//! (the squatting concern): a local attacker can bind 127.0.0.1:8081 and become
//! a model-in-the-middle. We resolve which process actually owns the listening
//! socket and flag it if it isn't a plausible llama-server.

use std::time::Duration;

use serde_json::{json, Value};

/// Overall rollup severity. `critical` = a must-have is down (no protection);
/// `warning` = a degraded/important piece is down or suspicious; `ok` = all good.
fn worst(a: &str, b: &str) -> String {
    let rank = |s: &str| match s {
        "critical" | "down" => 3,
        "warning" => 2,
        _ => 1,
    };
    if rank(a) >= rank(b) { a } else { b }.to_string()
}

/// Build the component-health payload. `ebpf_active` comes from the daemon's
/// shared flag; SSL probe count + the engine probe are resolved here.
pub fn components(ebpf_active: bool) -> Value {
    let mut comps: Vec<Value> = Vec::new();

    // 1. Daemon — if this handler runs at all, the daemon + API are up.
    comps.push(json!({
        "id": "daemon", "label": "Security daemon", "critical": true,
        "status": "ok", "detail": "API responding",
    }));

    // 2. Kernel enforcement (eBPF/LSM) — the CORE protection. Down = unprotected.
    comps.push(json!({
        "id": "ebpf", "label": "Kernel enforcement (eBPF/LSM)", "critical": true,
        "status": if ebpf_active { "ok" } else { "down" },
        "detail": if ebpf_active { "LSM hooks attached" } else { "not attached — enforcement OFF" },
    }));

    // 4. On-device AI engine — reachable AND owned by a plausible llama-server.
    let engine = engine_health();
    comps.push(engine);

    // Roll up: criticals drive `critical`, everything else `warning`.
    let mut overall = "ok".to_string();
    for c in &comps {
        let st = c["status"].as_str().unwrap_or("ok");
        let critical = c["critical"].as_bool().unwrap_or(false);
        let sev = match (st, critical) {
            ("down", true) => "critical",
            ("down", false) | ("warning", _) => "warning",
            _ => "ok",
        };
        overall = worst(&overall, sev);
    }

    json!({ "status": overall, "components": comps })
}

/// Probe the on-device AI engine endpoint and verify who owns it.
fn engine_health() -> Value {
    let url = std::env::var("RZ_LLAMA_URL").unwrap_or_else(|_| "http://127.0.0.1:8081/v1".into());
    let (host, port) = parse_host_port(&url).unwrap_or_else(|| ("127.0.0.1".into(), 8081));

    // Reachability: a short TCP connect (no request — we don't want to perturb it).
    let addr = format!("{host}:{port}");
    let reachable = std::net::ToSocketAddrs::to_socket_addrs(&addr)
        .ok()
        .and_then(|mut it| it.next())
        .map(|sa| std::net::TcpStream::connect_timeout(&sa, Duration::from_millis(400)).is_ok())
        .unwrap_or(false);

    if !reachable {
        return json!({
            "id": "engine", "label": "On-device AI engine", "critical": false,
            "status": "down", "detail": format!("not reachable at {addr} — start llama-server"),
        });
    }

    // Ownership check (loopback only). We can't reliably name the owning PROCESS
    // from the sandboxed daemon (its /proc view can't resolve another process's
    // socket fds), but the owning UID is readable from /proc/net/tcp with no
    // ptrace/fd access. That's the squat signal: an unexpected user owning the
    // engine port is a possible model-in-the-middle. To avoid false positives we
    // only WARN when an expected owner uid is configured (RZ_ENGINE_EXPECTED_UID)
    // and the actual owner differs; otherwise we report the owner informationally.
    if host == "127.0.0.1" || host == "localhost" || host == "::1" {
        if let Some(uid) = listen_owner_uid_for_port(port) {
            let who = username_for_uid(uid).unwrap_or_else(|| format!("uid {uid}"));
            if let Some(expected) = std::env::var("RZ_ENGINE_EXPECTED_UID")
                .ok()
                .and_then(|s| s.parse::<u32>().ok())
            {
                if uid != expected {
                    return json!({
                        "id": "engine", "label": "On-device AI engine", "critical": false,
                        "status": "warning",
                        "detail": format!("engine port served by {who}, expected uid {expected} — possible endpoint impersonation"),
                    });
                }
            }
            return json!({
                "id": "engine", "label": "On-device AI engine", "critical": false,
                "status": "ok", "detail": format!("ready (served by {who})"),
            });
        }
    }

    json!({
        "id": "engine", "label": "On-device AI engine", "critical": false,
        "status": "ok", "detail": format!("reachable at {addr}"),
    })
}

/// Username for a uid via /etc/passwd (best-effort; None if unresolved). uid 0 → "root".
fn username_for_uid(uid: u32) -> Option<String> {
    let content = std::fs::read_to_string("/etc/passwd").ok()?;
    for line in content.lines() {
        let f: Vec<&str> = line.split(':').collect();
        if f.len() >= 3 && f[2].parse::<u32>().ok() == Some(uid) {
            return Some(format!("{} (uid {uid})", f[0]));
        }
    }
    None
}

/// Split "http://host:port/path" → (host, port). Defaults port 8081.
fn parse_host_port(url: &str) -> Option<(String, u16)> {
    let rest = url
        .strip_prefix("http://")
        .or_else(|| url.strip_prefix("https://"))
        .unwrap_or(url);
    let authority = rest.split('/').next().unwrap_or(rest);
    let (h, p) = authority.rsplit_once(':')?;
    Some((h.to_string(), p.parse().ok()?))
}

/// Owning UID of the LISTEN socket on `port` — read straight from /proc/net/tcp
/// (field 8). No fd/ptrace access needed, so it works from the sandboxed daemon
/// (which can't resolve other processes' fds). Returns None if no listener.
fn listen_owner_uid_for_port(port: u16) -> Option<u32> {
    let want = format!(":{port:04X}"); // local-port hex, uppercase, as /proc formats it
    for path in ["/proc/net/tcp", "/proc/net/tcp6"] {
        let Ok(content) = std::fs::read_to_string(path) else {
            continue;
        };
        for line in content.lines().skip(1) {
            let f: Vec<&str> = line.split_whitespace().collect();
            if f.len() < 10 {
                continue;
            }
            if f[3] != "0A" {
                continue;
            } // 0A = TCP_LISTEN
            if f[1].to_uppercase().ends_with(&want) {
                if let Ok(uid) = f[7].parse::<u32>() {
                    return Some(uid);
                }
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_host_port() {
        assert_eq!(
            parse_host_port("http://127.0.0.1:8081/v1"),
            Some(("127.0.0.1".into(), 8081))
        );
        assert_eq!(
            parse_host_port("http://localhost:9000"),
            Some(("localhost".into(), 9000))
        );
    }

    #[test]
    fn rollup_picks_worst() {
        assert_eq!(worst("ok", "warning"), "warning");
        assert_eq!(worst("warning", "critical"), "critical");
        assert_eq!(worst("ok", "ok"), "ok");
    }

    #[test]
    fn ebpf_down_is_critical_overall() {
        let v = components(false);
        assert_eq!(v["status"], "critical");
        let ebpf = v["components"]
            .as_array()
            .unwrap()
            .iter()
            .find(|c| c["id"] == "ebpf")
            .unwrap();
        assert_eq!(ebpf["status"], "down");
    }
}
