// SPDX-License-Identifier: Apache-2.0
//
// caller.rs — who is on the other end of a local API call.
//
// THE HOLE THIS EXISTS TO NARROW. The full-scope token is root-only, so the
// story was "an agent running as your developer cannot change enforcement".
// That story has a gap, and it is sudo's, not ours:
//
//     $ sudo -v                                  a human authenticates once
//     $ sudo -n cat /var/lib/ringzero/api-token  prints the full-scope token
//
// sudo caches credentials per tty for about fifteen minutes. An agent running
// in a terminal where the operator recently used sudo inherits that cache,
// reads the token with no prompt, and can then call the API as if it were the
// operator. Being in the `sudo` group is the normal case on a developer
// laptop, so this is not an exotic configuration.
//
// WHAT WE DO ABOUT IT. A valid token stops being sufficient for a mutating
// call. The caller's pid is resolved and, if that process or any of its
// ancestors is an AI agent, the call is refused however good the token is. The
// token proves what you have; this asks who you are.
//
// WHAT IT CANNOT DO, stated here so nobody reads more into it:
//
//   - An agent that writes a file some other privileged process later reads,
//     or that persuades a human to run something, is untouched by this.
//   - An agent that launches a helper outside its own process tree — a systemd
//     unit, an at job, a detached daemon reparented to init — breaks the
//     ancestry chain this walks, and would resolve as an ordinary caller.
//   - An agent process that EXEC-REPLACES ITSELF is not caught. Measured, not
//     assumed: `claude -c "rz enforcement set-default alert"` is optimised by
//     the shell into an exec, so the agent's own pid becomes `rz` and nothing
//     in the ancestry looks like an agent any more. The same command written
//     `claude -c "rz enforcement set-default alert; true"` keeps the agent
//     alive as the parent and IS refused. Real agents spawn tool processes as
//     children rather than exec-replacing themselves, which is the case this
//     catches, but the gap is real and this is not a boundary.
//   - Process names are evidence, not proof. A determined agent can exec a
//     binary named something else. This raises the cost of the easy path; it
//     is not a boundary in the sense the kernel enforcement is.
//
// The actual fix for the sudo window is on the operator's side, and SUPPORT.md
// gives it: do not run agents in a terminal that has authenticated sudo, or set
// `timestamp_timeout=0`. This module makes the common accident fail loudly.

use std::net::SocketAddr;

/// What we could work out about the caller.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Caller {
    /// Resolved to a pid with no agent anywhere in its ancestry.
    Trusted { pid: u32 },
    /// The caller is an AI agent, or a descendant of one.
    Agent {
        pid: u32,
        /// The ancestor that matched, and what it looked like.
        agent_pid: u32,
        agent_name: String,
    },
    /// We could not work out which process this is.
    ///
    /// For a mutating call this is treated exactly like `Agent`: the point of
    /// the check is to prove the caller is NOT an agent, and an unproven
    /// caller has not cleared that bar. It is never a reason to refuse a read.
    Unresolved { reason: String },
}

impl Caller {
    /// May this caller change policy?
    pub fn may_mutate(&self) -> bool {
        matches!(self, Caller::Trusted { .. })
    }

    /// One line for the operator, and for the security event.
    pub fn refusal_message(&self) -> String {
        match self {
            Caller::Trusted { .. } => String::new(),
            Caller::Agent {
                agent_name,
                agent_pid,
                ..
            } => format!(
                "This request came from an AI agent process ({agent_name}, pid {agent_pid}) or \
                 one of its children. Changing policy from inside an agent is refused whatever \
                 token is presented. If you are a human operator, run the command from a shell \
                 that is not a child of an agent."
            ),
            Caller::Unresolved { reason } => format!(
                "This request could not be traced back to a local process ({reason}), so it \
                 cannot be shown not to be an AI agent. Mutating calls require that. Reads are \
                 unaffected."
            ),
        }
    }
}

/// Walk a process's ancestry looking for an AI agent.
///
/// Returns the first agent found, starting from `pid` itself. The walk stops at
/// pid 1, at a pid that no longer exists, and after `MAX_DEPTH` steps so a
/// malformed or looping chain cannot spin.
pub fn agent_in_lineage(pid: u32) -> Option<(u32, String)> {
    const MAX_DEPTH: usize = 64;
    let mut current = pid;
    for _ in 0..MAX_DEPTH {
        if current <= 1 {
            return None;
        }
        let comm = std::fs::read_to_string(format!("/proc/{current}/comm"))
            .ok()
            .map(|c| c.trim().to_string())
            .unwrap_or_default();

        if !comm.is_empty() && crate::common::agent_detect::is_ai_agent(&comm) {
            return Some((current, comm));
        }
        // The name is not always the agent: Gemini CLI runs as `node`, Cursor
        // as an Electron helper. The binary path catches those.
        if crate::common::agent_detect::is_agent_by_binary(current) {
            let name = if comm.is_empty() {
                "agent".to_string()
            } else {
                comm
            };
            return Some((current, name));
        }

        match parent_pid(current) {
            Some(ppid) => current = ppid,
            None => return None,
        }
    }
    None
}

/// PPid from /proc/<pid>/status. `stat` would also work but its comm field can
/// contain spaces and parentheses, which is a parsing trap.
fn parent_pid(pid: u32) -> Option<u32> {
    let status = std::fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
    status
        .lines()
        .find_map(|l| l.strip_prefix("PPid:"))
        .and_then(|v| v.trim().parse::<u32>().ok())
}

/// Find the pid on the other end of a loopback TCP connection.
///
/// The listener is loopback-only, so the peer is a process on this machine:
/// its source port appears in /proc/net/tcp (or tcp6) against a socket inode,
/// and that inode appears as a /proc/<pid>/fd entry. Both steps can fail
/// benignly — a short-lived client may be gone by the time we look — and a
/// failure is reported rather than guessed at.
pub fn pid_for_peer(peer: SocketAddr) -> Result<u32, String> {
    let candidates = socket_inodes_for_peer(peer);
    if candidates.is_empty() {
        return Err(format!("no established /proc/net/tcp entry for {}", peer));
    }
    // More than one row can carry the same local port — a closed connection
    // whose inode nobody holds any more, or a socket on another address. Take
    // the first that resolves to a live process rather than the first row.
    for inode in &candidates {
        if let Some(pid) = pid_holding_socket(*inode) {
            return Ok(pid);
        }
    }
    Err(format!(
        "no process holds any of the {} socket(s) for {}",
        candidates.len(),
        peer
    ))
}

/// Socket inodes whose LOCAL end is `peer` and which are ESTABLISHED.
///
/// From this process's point of view the client's address is the remote end of
/// our accepted socket; the same tuple is the client's own local address in its
/// row. Matching the whole address rather than just the port keeps a socket on
/// another interface out, and requiring ESTABLISHED keeps TIME_WAIT rows — which
/// no process holds — from being picked up.
fn socket_inodes_for_peer(peer: SocketAddr) -> Vec<u64> {
    const TCP_ESTABLISHED: &str = "01";
    let mut exact = Vec::new();
    let mut port_only = Vec::new();

    for path in ["/proc/net/tcp", "/proc/net/tcp6"] {
        let Ok(text) = std::fs::read_to_string(path) else {
            continue;
        };
        for line in text.lines().skip(1) {
            let f: Vec<&str> = line.split_whitespace().collect();
            // 1 = local_address, 3 = connection state, 9 = inode.
            if f.len() < 10 {
                continue;
            }
            if f[3] != TCP_ESTABLISHED {
                continue;
            }
            let Some((ip_hex, port_hex)) = f[1].rsplit_once(':') else {
                continue;
            };
            let Ok(port) = u16::from_str_radix(port_hex, 16) else {
                continue;
            };
            if port != peer.port() {
                continue;
            }
            let Ok(inode) = f[9].parse::<u64>() else {
                continue;
            };
            if inode == 0 {
                continue;
            }
            // Prefer a row whose address also matches; keep the rest as a
            // fallback so an address format we did not anticipate cannot make
            // every caller unidentifiable.
            match parse_proc_ip(ip_hex) {
                Some(ip) if ip == peer.ip() => exact.push(inode),
                _ => port_only.push(inode),
            }
        }
    }
    exact.extend(port_only);
    exact
}

/// The hex address in /proc/net/tcp: little-endian 32-bit for IPv4, four
/// little-endian 32-bit words for IPv6.
fn parse_proc_ip(hex: &str) -> Option<std::net::IpAddr> {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    match hex.len() {
        8 => {
            let v = u32::from_str_radix(hex, 16).ok()?;
            Some(IpAddr::V4(Ipv4Addr::from(v.swap_bytes())))
        }
        32 => {
            let mut octets = [0u8; 16];
            for word in 0..4 {
                let v = u32::from_str_radix(&hex[word * 8..word * 8 + 8], 16).ok()?;
                octets[word * 4..word * 4 + 4].copy_from_slice(&v.swap_bytes().to_be_bytes());
            }
            let v6 = Ipv6Addr::from(octets);
            // ::ffff:127.0.0.1 and 127.0.0.1 are the same caller.
            Some(match v6.to_ipv4_mapped() {
                Some(v4) => IpAddr::V4(v4),
                None => IpAddr::V6(v6),
            })
        }
        _ => None,
    }
}

/// Which process has this socket inode open.
fn pid_holding_socket(inode: u64) -> Option<u32> {
    let want = format!("socket:[{inode}]");
    let mut scanned = 0usize;
    let mut denied = 0usize;
    let entries = std::fs::read_dir("/proc").ok()?;
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(pid) = name.to_str().and_then(|n| n.parse::<u32>().ok()) else {
            continue;
        };
        scanned += 1;
        let fds = match std::fs::read_dir(entry.path().join("fd")) {
            Ok(fds) => fds,
            Err(_) => {
                // Another user's process, or it exited between the readdir and
                // here. Counted so a systematic loss of visibility shows up as
                // a number rather than as silence.
                denied += 1;
                continue;
            }
        };
        for fd in fds.flatten() {
            if let Ok(target) = std::fs::read_link(fd.path()) {
                if target.to_string_lossy() == want {
                    return Some(pid);
                }
            }
        }
    }
    tracing::debug!(
        inode,
        scanned,
        denied,
        "caller lookup: no process holds this socket"
    );
    None
}

/// Classify the caller of an HTTP request from its peer address.
pub fn classify_http(peer: SocketAddr) -> Caller {
    match pid_for_peer(peer) {
        Ok(pid) => classify_pid(pid),
        Err(reason) => Caller::Unresolved { reason },
    }
}

/// Classify a caller we already have a pid for, such as an IPC peer whose
/// credentials came from SO_PEERCRED.
pub fn classify_pid(pid: u32) -> Caller {
    match agent_in_lineage(pid) {
        Some((agent_pid, agent_name)) => Caller::Agent {
            pid,
            agent_pid,
            agent_name,
        },
        None => Caller::Trusted { pid },
    }
}

/// Everything the mutation gate needs to refuse a call and say so durably.
///
/// Carried in request extensions so the auth middleware can record a refusal
/// without the whole `ApiState` being threaded through it.
#[derive(Clone)]
pub struct MutationGuard {
    pub audit: std::sync::Arc<crate::audit::AuditLog>,
    pub review: std::sync::Arc<crate::review::ReviewQueue>,
}

impl MutationGuard {
    /// An agent reaching for the policy API is a security event, not a log
    /// line. It goes to the audit chain and to the review queue, which is
    /// where a human decides what it was.
    pub fn record_refusal(&self, caller: &Caller, method: &str, path: &str) {
        let (kind, detail) = match caller {
            Caller::Agent {
                pid,
                agent_pid,
                agent_name,
            } => (
                "agent_caller",
                serde_json::json!({
                    "caller_pid": pid,
                    "agent_pid": agent_pid,
                    "agent_name": agent_name,
                }),
            ),
            Caller::Unresolved { reason } => {
                ("unresolved_caller", serde_json::json!({ "reason": reason }))
            }
            Caller::Trusted { .. } => return,
        };

        tracing::warn!(
            %method, %path, kind,
            detail = %detail,
            "refused a policy-mutating call: the caller could not be shown to be a human operator"
        );

        let _ = self.audit.append(
            crate::audit::AuditEntryType::PolicyChange,
            serde_json::json!({
                "action": "mutation_refused",
                "reason": kind,
                "method": method,
                "path": path,
                "detail": detail,
            }),
        );

        let summary = match caller {
            Caller::Agent {
                agent_name,
                agent_pid,
                ..
            } => format!(
                "An AI agent ({agent_name}, pid {agent_pid}) tried to change policy: {method} {path}"
            ),
            _ => format!("A caller that could not be identified tried to change policy: {method} {path}"),
        };
        let _ = self.review.push(
            crate::review::Source::PolicyMutationRefused,
            "",
            summary,
            serde_json::json!({
                "method": method,
                "path": path,
                "reason": kind,
                "detail": detail,
            }),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn our_own_process_resolves_and_is_not_an_agent() {
        // The test binary is not an agent, and its ancestry is cargo and a
        // shell. If this ever fails, the walk is broken rather than the
        // machine being compromised.
        let me = std::process::id();
        assert!(parent_pid(me).is_some(), "we must find our own parent");
        match classify_pid(me) {
            Caller::Trusted { pid } => assert_eq!(pid, me),
            other => panic!("the test process classified as {other:?}"),
        }
    }

    #[test]
    fn the_walk_terminates_at_init_and_on_a_dead_pid() {
        assert_eq!(agent_in_lineage(1), None, "pid 1 must end the walk");
        assert_eq!(agent_in_lineage(0), None, "pid 0 is not walkable");
        // A pid that almost certainly does not exist.
        assert_eq!(agent_in_lineage(4_194_303), None);
    }

    /// Only a resolved, non-agent caller may mutate. The other two are the
    /// same answer for a different reason, and both must refuse.
    #[test]
    fn only_a_proven_non_agent_may_mutate() {
        assert!(Caller::Trusted { pid: 42 }.may_mutate());
        assert!(!Caller::Agent {
            pid: 42,
            agent_pid: 7,
            agent_name: "claude".into()
        }
        .may_mutate());
        assert!(!Caller::Unresolved {
            reason: "gone".into()
        }
        .may_mutate());
    }

    #[test]
    fn a_refusal_says_which_process_and_what_to_do() {
        let m = Caller::Agent {
            pid: 42,
            agent_pid: 7,
            agent_name: "claude".into(),
        }
        .refusal_message();
        assert!(m.contains("claude"), "names the agent: {m}");
        assert!(m.contains("pid 7"), "names the pid: {m}");
        assert!(
            m.contains("not a child of an agent"),
            "says what to do: {m}"
        );

        let u = Caller::Unresolved {
            reason: "no /proc/net/tcp entry for port 1234".into(),
        }
        .refusal_message();
        assert!(u.contains("port 1234"), "carries the reason: {u}");
        assert!(u.contains("Reads are unaffected"), "scopes itself: {u}");
    }

    #[test]
    fn proc_addresses_parse_back_to_the_address_they_encode() {
        use std::net::{IpAddr, Ipv4Addr};
        // 127.0.0.1 as /proc/net/tcp writes it.
        assert_eq!(
            parse_proc_ip("0100007F"),
            Some(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)))
        );
        // ::ffff:127.0.0.1 from /proc/net/tcp6 is the same caller.
        assert_eq!(
            parse_proc_ip("0000000000000000FFFF00000100007F"),
            Some(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)))
        );
        assert_eq!(parse_proc_ip("nonsense"), None);
    }

    /// A socket inode nothing holds must be reported, not guessed.
    #[test]
    fn an_unheld_socket_inode_does_not_resolve() {
        assert_eq!(pid_holding_socket(u64::MAX), None);
    }
}
