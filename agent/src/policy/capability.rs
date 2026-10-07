// SPDX-License-Identifier: Apache-2.0
// policy/capability.rs — what each agent and each MCP server is allowed to do.
//
// A capability profile is a short, human-readable statement attached to one
// agent or one MCP server:
//
//     network:  only these hosts
//     programs: may start other programs? if so, only these
//
// STAGE 1 (this file): OBSERVE. Every connection and process start inside an
// agent's process tree is attributed to the nearest profiled agent or MCP
// server and checked against its profile. A mismatch is recorded on the event
// as "would block" and counted, so the Policy screen shows, per profile, what
// it allowed and what it would have refused. This is also how a profile is
// rolled out for real: watch it against real work first, then enforce.
//
// STAGE 2 (not here): the kernel refuses. The network half maps onto the
// connect hook's existing IP allowlist; the programs half needs a new exec
// denial, reviewed like every other kernel change.
//
// Nothing here can allow something the kernel denied. It only adds a
// "would block" observation.

use std::collections::{HashMap, HashSet, VecDeque};
use std::net::IpAddr;
use std::sync::RwLock;

use serde::{Deserialize, Serialize};

/// One profile, as written in daemon.toml under `[[profiles]]`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct ProfileConfig {
    /// Shown on the Policy screen, e.g. "Claude Code".
    pub name: String,
    /// Applies to this agent (an `agent_detect` id: "claude", "codex", …).
    pub agent: Option<String>,
    /// Or to an MCP server: a process whose command line contains ALL of
    /// these substrings, e.g. ["server-filesystem"].
    pub mcp_match: Vec<String>,
    /// Hosts it may connect to. Exact names, "*.example.com", or IPs.
    /// Empty = no network at all. `["*"]` = any.
    pub allow_hosts: Vec<String>,
    /// May its process tree start other programs?
    pub allow_spawn: bool,
    /// If non-empty, only these programs (basenames) may be started.
    pub allow_programs: Vec<String>,
}

impl Default for ProfileConfig {
    fn default() -> Self {
        ProfileConfig {
            name: String::new(),
            agent: None,
            mcp_match: Vec::new(),
            allow_hosts: vec!["*".into()],
            allow_spawn: true,
            allow_programs: Vec::new(),
        }
    }
}

impl ProfileConfig {
    pub fn kind(&self) -> &'static str {
        if self.agent.is_some() {
            "agent"
        } else {
            "mcp"
        }
    }
}

/// What the check found.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct Violation {
    pub profile: String,
    /// "network" | "spawn" | "program"
    pub rule: String,
    /// Plain language, e.g. "connected to 203.0.113.9:443, not an allowed host".
    pub detail: String,
    pub pid: u32,
    pub process: String,
    pub at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct ProfileStats {
    pub allowed: u64,
    pub would_block: u64,
}

/// The Policy screen's view of one profile.
#[derive(Debug, Clone, Serialize)]
pub struct ProfileReport {
    #[serde(flatten)]
    pub config: ProfileConfig,
    pub kind: &'static str,
    pub stats: ProfileStats,
    pub recent: Vec<Violation>,
}

const RECENT_PER_PROFILE: usize = 20;

/// The daemon's engine, built from `[[profiles]]` at startup.
pub static ENGINE: once_cell::sync::Lazy<CapabilityEngine> =
    once_cell::sync::Lazy::new(|| CapabilityEngine::new(crate::config::DaemonConfig::load().profiles));
const MAX_ANCESTRY: usize = 32;

pub struct CapabilityEngine {
    profiles: RwLock<Vec<ProfileConfig>>,
    /// Allowed host name -> resolved IPs, refreshed in the background.
    resolved: RwLock<HashMap<String, HashSet<IpAddr>>>,
    stats: RwLock<HashMap<String, ProfileStats>>,
    recent: RwLock<HashMap<String, VecDeque<Violation>>>,
}

impl CapabilityEngine {
    pub fn new(profiles: Vec<ProfileConfig>) -> Self {
        CapabilityEngine {
            profiles: RwLock::new(profiles),
            resolved: RwLock::new(HashMap::new()),
            stats: RwLock::new(HashMap::new()),
            recent: RwLock::new(HashMap::new()),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.profiles.read().map(|p| p.is_empty()).unwrap_or(true)
    }

    /// Resolve every named host in every profile. Call at start and
    /// periodically; connect events carry IPs, profiles carry names.
    pub async fn refresh_dns(&self) {
        let hosts: Vec<String> = self
            .profiles
            .read()
            .map(|ps| {
                ps.iter()
                    .flat_map(|p| p.allow_hosts.iter().cloned())
                    .filter(|h| h != "*" && !h.starts_with("*.") && h.parse::<IpAddr>().is_err())
                    .collect()
            })
            .unwrap_or_default();
        let mut out: HashMap<String, HashSet<IpAddr>> = HashMap::new();
        for h in hosts {
            let ips: Vec<IpAddr> = match tokio::net::lookup_host((h.as_str(), 443)).await {
                Ok(addrs) => addrs.map(|a| a.ip()).collect(),
                Err(_) => continue,
            };
            out.entry(h).or_default().extend(ips);
        }
        if let Ok(mut r) = self.resolved.write() {
            *r = out;
        }
    }

    /// Check one event from an agent's process tree. `ancestry` is the
    /// process and its ancestors as (pid, cmdline), nearest first; `agent_of`
    /// names the agent at a pid, if any. Returns a violation to record.
    pub fn check(
        &self,
        kind: EventShape<'_>,
        pid: u32,
        process: &str,
        ancestry: &[(u32, String)],
        agent_of: impl Fn(u32, &str) -> Option<String>,
    ) -> Option<Violation> {
        let profiles = self.profiles.read().ok()?;
        let (profile, depth) = attribute(&profiles, ancestry, agent_of)?;
        let violation = match kind {
            EventShape::Connect { ip, port, host } => {
                if self.host_allowed(profile, ip, host) {
                    None
                } else {
                    let shown = host.map(str::to_string).unwrap_or_else(|| format!("{ip}"));
                    Some(("network", format!("connected to {shown}:{port}, not an allowed host")))
                }
            }
            EventShape::Exec { program } => {
                // depth 0 is the profiled process itself starting: not a spawn.
                if depth == 0 {
                    None
                } else if !profile.allow_spawn {
                    Some(("spawn", format!("started {program}; this profile may not start programs")))
                } else if !profile.allow_programs.is_empty()
                    && !profile.allow_programs.iter().any(|p| p == program)
                {
                    Some(("program", format!("started {program}, not an allowed program")))
                } else {
                    None
                }
            }
        };
        let name = profile.name.clone();
        drop(profiles);

        let mut stats = self.stats.write().ok()?;
        let s = stats.entry(name.clone()).or_default();
        match violation {
            None => {
                s.allowed += 1;
                None
            }
            Some((rule, detail)) => {
                s.would_block += 1;
                let v = Violation {
                    profile: name.clone(),
                    rule: rule.to_string(),
                    detail,
                    pid,
                    process: process.to_string(),
                    at: chrono::Utc::now(),
                };
                if let Ok(mut recent) = self.recent.write() {
                    let q = recent.entry(name).or_default();
                    q.push_front(v.clone());
                    q.truncate(RECENT_PER_PROFILE);
                }
                Some(v)
            }
        }
    }

    fn host_allowed(&self, p: &ProfileConfig, ip: IpAddr, host: Option<&str>) -> bool {
        if ip.is_loopback() {
            return true;
        }
        let resolved = self.resolved.read().ok();
        p.allow_hosts.iter().any(|h| {
            if h == "*" {
                return true;
            }
            if let Ok(a) = h.parse::<IpAddr>() {
                return a == ip;
            }
            if let Some(name) = host {
                if host_matches(h, name) {
                    return true;
                }
            }
            resolved
                .as_ref()
                .and_then(|r| r.get(h))
                .is_some_and(|ips| ips.contains(&ip))
        })
    }

    pub fn report(&self) -> Vec<ProfileReport> {
        let profiles = self.profiles.read().map(|p| p.clone()).unwrap_or_default();
        let stats = self.stats.read().ok();
        let recent = self.recent.read().ok();
        profiles
            .into_iter()
            .map(|c| {
                let kind = c.kind();
                let st = stats.as_ref().and_then(|s| s.get(&c.name).cloned()).unwrap_or_default();
                let rc = recent
                    .as_ref()
                    .and_then(|r| r.get(&c.name))
                    .map(|q| q.iter().cloned().collect())
                    .unwrap_or_default();
                ProfileReport { config: c, kind, stats: st, recent: rc }
            })
            .collect()
    }
}

/// The two event shapes a profile speaks about.
#[derive(Debug, Clone, Copy)]
pub enum EventShape<'a> {
    Connect { ip: IpAddr, port: u16, host: Option<&'a str> },
    Exec { program: &'a str },
}

/// Which profile owns this event: the nearest ancestor (or the process itself)
/// that is a profiled MCP server or a profiled agent. MCP servers are matched
/// first at each level because they run inside an agent's tree.
fn attribute<'p>(
    profiles: &'p [ProfileConfig],
    ancestry: &[(u32, String)],
    agent_of: impl Fn(u32, &str) -> Option<String>,
) -> Option<(&'p ProfileConfig, usize)> {
    for (depth, (pid, cmdline)) in ancestry.iter().take(MAX_ANCESTRY).enumerate() {
        if let Some(p) = profiles
            .iter()
            .find(|p| !p.mcp_match.is_empty() && p.mcp_match.iter().all(|m| cmdline.contains(m.as_str())))
        {
            return Some((p, depth));
        }
        if let Some(agent) = agent_of(*pid, cmdline) {
            if let Some(p) = profiles.iter().find(|p| p.agent.as_deref() == Some(agent.as_str())) {
                return Some((p, depth));
            }
        }
    }
    None
}

fn host_matches(pattern: &str, host: &str) -> bool {
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    let pattern = pattern.to_ascii_lowercase();
    match pattern.strip_prefix("*.") {
        Some(suffix) => host == suffix || host.ends_with(&format!(".{suffix}")),
        None => host == pattern,
    }
}

/// The process and its ancestors, nearest first, as (pid, cmdline). Reads
/// /proc; a process that already exited simply ends the chain.
pub fn ancestry(pid: u32) -> Vec<(u32, String)> {
    let mut out = Vec::new();
    let mut cur = pid;
    for _ in 0..MAX_ANCESTRY {
        if cur <= 1 {
            break;
        }
        let cmdline = std::fs::read(format!("/proc/{cur}/cmdline"))
            .map(|b| String::from_utf8_lossy(&b).replace('\0', " ").trim().to_string())
            .unwrap_or_default();
        let comm = std::fs::read_to_string(format!("/proc/{cur}/comm"))
            .map(|s| s.trim().to_string())
            .unwrap_or_default();
        out.push((cur, if cmdline.is_empty() { comm } else { cmdline }));
        let ppid = std::fs::read_to_string(format!("/proc/{cur}/stat"))
            .ok()
            .and_then(|s| {
                // Field 4, after the parenthesised comm which may contain spaces.
                let after = s.rsplit_once(')')?.1;
                after.split_whitespace().nth(1)?.parse::<u32>().ok()
            });
        match ppid {
            Some(p) if p != cur => cur = p,
            _ => break,
        }
    }
    out
}

/// Parse a connect event target "ip:port" or "[v6]:port".
pub fn parse_target(target: &str) -> Option<(IpAddr, u16)> {
    let (host, port) = target.rsplit_once(':')?;
    let host = host.trim_start_matches('[').trim_end_matches(']');
    Some((host.parse().ok()?, port.parse().ok()?))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn claude() -> ProfileConfig {
        ProfileConfig {
            name: "Claude Code".into(),
            agent: Some("claude".into()),
            allow_hosts: vec!["api.anthropic.com".into(), "*.github.com".into(), "140.82.112.3".into()],
            allow_spawn: true,
            allow_programs: vec!["git".into(), "gh".into(), "node".into()],
            ..Default::default()
        }
    }
    fn fs_mcp() -> ProfileConfig {
        ProfileConfig {
            name: "Filesystem MCP".into(),
            mcp_match: vec!["server-filesystem".into()],
            allow_hosts: vec![],
            allow_spawn: false,
            ..Default::default()
        }
    }
    fn agent_of(_pid: u32, cmd: &str) -> Option<String> {
        cmd.split_whitespace()
            .next()
            .and_then(|c| c.rsplit('/').next())
            .filter(|b| *b == "claude")
            .map(str::to_string)
    }
    // pid 30 = child, 20 = MCP server, 10 = claude
    fn tree() -> Vec<(u32, String)> {
        vec![
            (30, "/usr/bin/sh -c ls".into()),
            (20, "node /x/node_modules/@modelcontextprotocol/server-filesystem /home".into()),
            (10, "/home/u/.local/bin/claude".into()),
        ]
    }

    #[test]
    fn mcp_server_is_attributed_before_its_agent() {
        let e = CapabilityEngine::new(vec![claude(), fs_mcp()]);
        let v = e.check(EventShape::Exec { program: "sh" }, 30, "sh", &tree(), agent_of).unwrap();
        assert_eq!(v.profile, "Filesystem MCP");
        assert_eq!(v.rule, "spawn");
    }

    #[test]
    fn mcp_server_with_no_network_is_flagged_on_connect() {
        let e = CapabilityEngine::new(vec![claude(), fs_mcp()]);
        let anc = &tree()[1..];
        let v = e
            .check(EventShape::Connect { ip: "203.0.113.9".parse().unwrap(), port: 443, host: None }, 20, "node", anc, agent_of)
            .unwrap();
        assert_eq!(v.rule, "network");
        assert!(v.detail.contains("203.0.113.9:443"));
    }

    #[test]
    fn agent_program_allowlist() {
        let e = CapabilityEngine::new(vec![claude()]);
        let anc = vec![(40, "/usr/bin/gh pr list".into()), (10, "/home/u/.local/bin/claude".into())];
        assert!(e.check(EventShape::Exec { program: "gh" }, 40, "gh", &anc, agent_of).is_none());
        let anc = vec![(41, "/usr/bin/curl x".into()), (10, "/home/u/.local/bin/claude".into())];
        let v = e.check(EventShape::Exec { program: "curl" }, 41, "curl", &anc, agent_of).unwrap();
        assert_eq!(v.rule, "program");
    }

    #[test]
    fn the_agent_starting_itself_is_not_a_spawn() {
        let mut p = claude();
        p.allow_spawn = false;
        let e = CapabilityEngine::new(vec![p]);
        let anc = vec![(10, "/home/u/.local/bin/claude".into())];
        assert!(e.check(EventShape::Exec { program: "claude" }, 10, "claude", &anc, agent_of).is_none());
    }

    #[test]
    fn hosts_by_name_wildcard_ip_and_loopback() {
        let e = CapabilityEngine::new(vec![claude()]);
        let anc = vec![(10, "/home/u/.local/bin/claude".into())];
        let ok = |ip: &str, host: Option<&str>| {
            e.check(EventShape::Connect { ip: ip.parse().unwrap(), port: 443, host }, 10, "claude", &anc, agent_of).is_none()
        };
        assert!(ok("140.82.112.3", None), "listed IP");
        assert!(ok("1.2.3.4", Some("api.github.com")), "wildcard by name");
        assert!(ok("127.0.0.1", None), "loopback always allowed");
        assert!(!ok("1.2.3.4", Some("evil.example")), "unlisted host");
    }

    #[test]
    fn outside_any_profile_is_not_judged() {
        let e = CapabilityEngine::new(vec![claude()]);
        let anc = vec![(50, "/usr/bin/vim".into())];
        assert!(e.check(EventShape::Exec { program: "sh" }, 50, "sh", &anc, agent_of).is_none());
        assert!(e.report()[0].stats.allowed == 0, "unattributed events are not counted");
    }

    #[test]
    fn report_counts_and_recent() {
        let e = CapabilityEngine::new(vec![claude()]);
        let anc = vec![(41, "/usr/bin/curl x".into()), (10, "/home/u/.local/bin/claude".into())];
        e.check(EventShape::Exec { program: "curl" }, 41, "curl", &anc, agent_of);
        let anc = vec![(40, "/usr/bin/git status".into()), (10, "/home/u/.local/bin/claude".into())];
        e.check(EventShape::Exec { program: "git" }, 40, "git", &anc, agent_of);
        let r = &e.report()[0];
        assert_eq!((r.stats.allowed, r.stats.would_block), (1, 1));
        assert_eq!(r.recent.len(), 1);
        assert_eq!(r.kind, "agent");
    }

    #[test]
    fn targets_parse() {
        assert_eq!(parse_target("1.2.3.4:443"), Some(("1.2.3.4".parse().unwrap(), 443)));
        assert_eq!(parse_target("[::1]:80"), Some(("::1".parse().unwrap(), 80)));
        assert_eq!(parse_target("nope"), None);
    }
}
