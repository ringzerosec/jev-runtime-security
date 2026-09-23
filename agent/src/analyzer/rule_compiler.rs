// SPDX-License-Identifier: Apache-2.0
// analyzer/rule_compiler.rs — the judgment→rule compiler (the keystone).
//
// The slow on-device SLM (L2) reasons over a provenance graph and emits exactly
// ONE structured `SecurityToolCall`. This module turns that *judgment* into
// concrete L0 eBPF reflexes (`EbpfCommand`) the kernel enforces at line rate —
// so the slow brain programs the fast spinal cord: the SLM doesn't need to be
// fast — it needs to be right; it is a slow oracle that programs the reflexes.
//
// SECURITY: the SLM's string fields
// (`target` — a file the agent touched, a host it contacted) are
// attacker-influenced. A compiler that blindly trusted them could be talked
// into a self-DoS: `BlockFile("/")`, blocking loopback, containing pid 1. So
// every candidate rule is validated and destructive ones are REFUSED with a
// recorded reason — we fail closed toward *not* installing a kernel rule. The
// SLM may widen what's watched; it may not brick the host.

use std::net::IpAddr;

use serde::{Deserialize, Serialize};

use crate::analyzer::tool_call::SecurityToolCall;

/// A platform-neutral L0 enforcement rule the compiler emits. Deliberately
/// decoupled from `ebpf_loader::EbpfCommand` (which is Linux-only and a runtime
/// channel handle, not wire data): keeping the compiler independent of the
/// loader avoids a layering inversion and lets every platform + the SIEM carry
/// the rule. The Linux daemon translates each into an `EbpfCommand` when it
/// programs the kernel maps.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "rule", rename_all = "snake_case")]
pub enum L0Rule {
    BlockFile(String),
    BlockIp(String),
    ContainPid(u32),
}

/// Outcome of compiling one SLM judgment into L0 policy.
#[derive(Debug, Default, Clone)]
pub struct CompiledPolicy {
    /// Executable rules to install at L0.
    pub commands: Vec<L0Rule>,
    /// Audit trail: what was installed, and what was refused and why. Surfaced
    /// on the verdict for the SIEM/operator so every L0 change is explainable.
    pub notes: Vec<String>,
}

impl CompiledPolicy {
    fn install(&mut self, cmd: L0Rule, desc: impl Into<String>) {
        self.notes.push(format!("install {}", desc.into()));
        self.commands.push(cmd);
    }
    fn refuse(&mut self, what: impl Into<String>, why: impl Into<String>) {
        self.notes
            .push(format!("refuse {} — {}", what.into(), why.into()));
    }
}

/// How a `Block` target string maps onto L0 enforcement.
#[derive(Debug, PartialEq, Eq)]
enum Target {
    File(String),
    Ip(String),
    /// A domain name — eBPF enforces on IPs, not names; the inspection proxy
    /// handles hostnames, not L0. We don't resolve here (racy + poisonable).
    Hostname,
    /// Empty or unrecognisable.
    Invalid,
}

fn classify_target(raw: &str) -> Target {
    let t = raw.trim();
    if t.is_empty() {
        return Target::Invalid;
    }
    // A bare IP (v4/v6) enforces directly. A "host:port" or CIDR is NOT a bare
    // IP and falls through to the hostname/invalid arms on purpose — L0 blocks
    // single addresses, and we won't guess a range from model text.
    if let Ok(ip) = t.parse::<IpAddr>() {
        return Target::Ip(ip.to_string());
    }
    // Absolute filesystem path.
    if t.starts_with('/') {
        return Target::File(t.to_string());
    }
    // Looks like a domain: has a dot, no path separator, no whitespace.
    if t.contains('.') && !t.contains('/') && !t.split_whitespace().nth(1).is_some() {
        return Target::Hostname;
    }
    Target::Invalid
}

/// Reject filesystem paths whose blocking would brick the host or the monitored
/// agent. The target is untrusted SLM output. Returns `Some(reason)` when too
/// dangerous to install.
///
/// NOTE on enforcement model: the kernel `blocked_files` map matches by
/// **basename** (`d_name.name`), agent-scoped. So blocking "/usr/bin/python3"
/// actually denies the agent every "python3" open — which would brick it. We
/// therefore refuse basenames the agent needs to *run* (shells, interpreters,
/// the loader, core libs), in addition to bare critical directories. Blocking a
/// specific *credential* basename (id_rsa, credentials) is intended and allowed.
pub fn dangerous_path(raw: &str) -> Option<&'static str> {
    let p = raw.trim().trim_end_matches('/');
    if p.is_empty() {
        return Some("filesystem root");
    }
    let base = p.rsplit('/').next().unwrap_or(p);
    const BRICKS_AGENT: &[&str] = &[
        // shells + interpreters the agent executes
        "bash",
        "sh",
        "zsh",
        "dash",
        "fish",
        "python",
        "python3",
        "node",
        "ruby",
        "perl",
        // dynamic loader + core libs — block these and nothing runs at all
        "ld.so.cache",
        "ld-linux-x86-64.so.2",
        "ld-linux.so.2",
        "libc.so.6",
        "libc.so",
        "libm.so.6",
        "libpthread.so.0",
    ];
    if BRICKS_AGENT.contains(&base) {
        return Some("basename the monitored agent needs to run (would brick it)");
    }
    const CRITICAL: &[&str] = &[
        "/bin",
        "/sbin",
        "/usr",
        "/usr/bin",
        "/usr/sbin",
        "/usr/lib",
        "/lib",
        "/lib64",
        "/libx32",
        "/etc",
        "/boot",
        "/dev",
        "/proc",
        "/sys",
        "/var",
        "/run",
        "/opt",
        "/home",
        "/root",
    ];
    if CRITICAL.iter().any(|c| *c == p) {
        return Some("critical system path");
    }
    None
}

/// Reject IPs whose blocking would cut the host off from itself or match
/// everything. Private/LAN ranges are intentionally allowed — lateral movement
/// and LAN exfil are real threats worth blocking.
fn dangerous_ip(ip: &IpAddr) -> Option<&'static str> {
    if ip.is_unspecified() {
        return Some("unspecified address (0.0.0.0/::) — would match all traffic");
    }
    if ip.is_loopback() {
        return Some("loopback — blocking it breaks local IPC");
    }
    if let IpAddr::V4(v4) = ip {
        if v4.is_broadcast() {
            return Some("broadcast address");
        }
    }
    None
}

fn truncate(s: &str, max: usize) -> String {
    let s = s.trim();
    if s.chars().count() <= max {
        s.to_string()
    } else {
        format!("{}…", s.chars().take(max).collect::<String>())
    }
}

/// Compile one SLM judgment into the set of L0 eBPF rules that enforce it.
///
/// `allow`/`alert`/`escalate` install nothing — allow is advisory, alert is
/// detection-only, escalate waits for a human/L3. Only `block` (→ BlockFile /
/// BlockIp) and `quarantine` (→ ContainPid) program the kernel, and only after
/// the target passes the safety checks above.
pub fn compile(call: &SecurityToolCall) -> CompiledPolicy {
    let mut out = CompiledPolicy::default();
    match call {
        SecurityToolCall::Allow { .. } => {
            out.notes
                .push("allow — advisory, no L0 rule installed".into());
        }
        SecurityToolCall::Alert { .. } => {
            out.notes
                .push("alert — detection-only, no L0 enforcement".into());
        }
        SecurityToolCall::Block { target, .. } => match classify_target(target) {
            Target::File(p) => match dangerous_path(&p) {
                Some(why) => out.refuse(format!("BlockFile({p})"), why),
                None => out.install(L0Rule::BlockFile(p.clone()), format!("BlockFile({p})")),
            },
            Target::Ip(ip) => {
                let parsed: IpAddr = ip.parse().expect("classify_target validated this is an IP");
                match dangerous_ip(&parsed) {
                    Some(why) => out.refuse(format!("BlockIp({ip})"), why),
                    None => out.install(L0Rule::BlockIp(ip.clone()), format!("BlockIp({ip})")),
                }
            }
            Target::Hostname => out.refuse(
                format!("Block hostname '{}'", truncate(target, 40)),
                "eBPF enforces on IPs; hostnames are handled by the inspection proxy, not L0",
            ),
            Target::Invalid => out.refuse(
                format!("Block target '{}'", truncate(target, 40)),
                "empty or unrecognised target",
            ),
        },
        SecurityToolCall::Quarantine { pid, .. } => {
            // pid 0 is the schema's "session-wide containment" sentinel — that
            // needs the session→pids expansion the caller holds, not a single
            // ContainPid(0) (which would be meaningless/dangerous). pid 1 is init.
            if *pid <= 1 {
                let why = if *pid == 0 {
                    "session-wide sentinel — expand to session pids upstream, not a single ContainPid"
                } else {
                    "refusing to contain pid 1 (init)"
                };
                out.refuse(format!("ContainPid({pid})"), why);
            } else {
                out.install(L0Rule::ContainPid(*pid), format!("ContainPid({pid})"));
            }
        }
        SecurityToolCall::Escalate { .. } => {
            out.notes
                .push("escalate — awaiting human/L3, no autonomous L0 rule".into());
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzer::tool_call::{SecurityToolCall, Severity};

    fn block(target: &str) -> SecurityToolCall {
        SecurityToolCall::Block {
            severity: Severity::High,
            category: "exfiltration".into(),
            mitre_id: "T1041".into(),
            target: target.into(),
            rationale: "test".into(),
        }
    }

    #[test]
    fn block_file_path_compiles_to_blockfile() {
        let p = compile(&block("/home/u/.ssh/id_rsa"));
        assert_eq!(p.commands.len(), 1);
        match &p.commands[0] {
            L0Rule::BlockFile(f) => assert_eq!(f, "/home/u/.ssh/id_rsa"),
            other => panic!("expected BlockFile, got {other:?}"),
        }
    }

    #[test]
    fn block_ip_compiles_to_blockip() {
        let p = compile(&block("203.0.113.7"));
        assert_eq!(p.commands.len(), 1);
        assert!(matches!(&p.commands[0], L0Rule::BlockIp(ip) if ip == "203.0.113.7"));
    }

    #[test]
    fn private_lan_ip_is_allowed() {
        // Lateral movement / LAN exfil is a real threat — don't refuse private IPs.
        let p = compile(&block("192.168.1.50"));
        assert_eq!(
            p.commands.len(),
            1,
            "private IP should compile: {:?}",
            p.notes
        );
    }

    #[test]
    fn refuses_root_and_critical_paths() {
        for bad in [
            "/", "", "   ", "/etc", "/usr/bin", "/bin/", "/home", "/proc",
        ] {
            let p = compile(&block(bad));
            assert!(
                p.commands.is_empty(),
                "must refuse blocking '{bad}': {:?}",
                p.notes
            );
            assert!(
                p.notes.iter().any(|n| n.starts_with("refuse")),
                "should note refusal for '{bad}'"
            );
        }
    }

    #[test]
    fn refuses_basenames_that_brick_the_agent() {
        // Enforcement is basename-scoped, so blocking these denies the agent
        // every open of that name — bricking it. Must refuse.
        for bad in [
            "/bin/bash",
            "/usr/bin/python3",
            "/usr/bin/node",
            "/lib/x86_64-linux-gnu/libc.so.6",
            "/usr/bin/sh",
        ] {
            let p = compile(&block(bad));
            assert!(
                p.commands.is_empty(),
                "must refuse blocking '{bad}' (bricks agent): {:?}",
                p.notes
            );
        }
    }

    #[test]
    fn allows_specific_credential_file() {
        // A real credential the agent shouldn't exfiltrate — should compile.
        // (Enforced by basename, which is the intended credential-protection.)
        for ok in ["/home/u/.ssh/id_rsa", "/root/.aws/credentials", "/app/.env"] {
            let p = compile(&block(ok));
            assert_eq!(p.commands.len(), 1, "'{ok}' should compile: {:?}", p.notes);
        }
    }

    #[test]
    fn refuses_self_dos_ips() {
        for bad in ["127.0.0.1", "0.0.0.0", "::1", "::", "255.255.255.255"] {
            let p = compile(&block(bad));
            assert!(
                p.commands.is_empty(),
                "must refuse blocking '{bad}': {:?}",
                p.notes
            );
        }
    }

    #[test]
    fn hostname_target_is_not_an_l0_rule() {
        // eBPF can't enforce on a name; the proxy owns hostnames.
        let p = compile(&block("evil.example.com"));
        assert!(p.commands.is_empty());
        assert!(p.notes.iter().any(|n| n.contains("proxy")), "{:?}", p.notes);
    }

    #[test]
    fn quarantine_compiles_to_containpid() {
        let call = SecurityToolCall::Quarantine {
            pid: 4242,
            category: "c".into(),
            rationale: "r".into(),
        };
        let p = compile(&call);
        assert!(matches!(p.commands.as_slice(), [L0Rule::ContainPid(4242)]));
    }

    #[test]
    fn quarantine_refuses_init_and_session_sentinel() {
        for pid in [0u32, 1u32] {
            let call = SecurityToolCall::Quarantine {
                pid,
                category: "c".into(),
                rationale: "r".into(),
            };
            let p = compile(&call);
            assert!(
                p.commands.is_empty(),
                "must refuse ContainPid({pid}): {:?}",
                p.notes
            );
        }
    }

    #[test]
    fn allow_alert_escalate_install_nothing() {
        let calls = [
            SecurityToolCall::Allow {
                rationale: "ok".into(),
            },
            SecurityToolCall::Alert {
                severity: Severity::Low,
                category: "c".into(),
                mitre_id: "T1".into(),
                rationale: "r".into(),
            },
            SecurityToolCall::Escalate {
                action_requested: "x".into(),
                category: "c".into(),
                rationale: "r".into(),
            },
        ];
        for call in calls {
            let p = compile(&call);
            assert!(
                p.commands.is_empty(),
                "{} should install no rule",
                call.name()
            );
            assert_eq!(
                p.notes.len(),
                1,
                "{} should leave one explanatory note",
                call.name()
            );
        }
    }
}
