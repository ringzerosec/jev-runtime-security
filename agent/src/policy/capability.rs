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
// STAGE 2: ENFORCE. A profile whose network_mode or programs_mode is
// "enforce" is loaded into the kernel (`kernel_state`): every process in the
// agent's tree carries the profile's slot, and the kernel refuses a program
// or destination outside the profile at the call itself, so a process that
// lives for a millisecond is judged like any other. Host names become
// addresses two ways: they are looked up on a timer, and addresses in the
// agent's own DNS answers for an approved name are added for the answer's TTL
// (`learn_dns`), which is what keeps CDN-fronted services working.
//
// Nothing here can allow something the kernel denied.

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
    /// Network rules: watch (record "would block") or enforce (kernel refuses).
    pub network_mode: Mode,
    /// Program rules: watch or enforce.
    pub programs_mode: Mode,
}

/// Watch records what a rule would have refused; enforce makes the kernel
/// refuse it. Every rule starts in watch so it can be checked against real
/// work before it can break anything.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    #[default]
    Watch,
    Enforce,
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
            network_mode: Mode::Watch,
            programs_mode: Mode::Watch,
        }
    }
}

/// Where profiles edited from the app are kept. When this file exists it is
/// the complete list; `[[profiles]]` in daemon.toml only seeds it.
pub const PROFILES_PATH: &str = "/etc/ringzero/profiles.json";

/// Reject a profile that is malformed or would be ambiguous. Called on every
/// write, so a bad edit never reaches the engine or the kernel.
pub fn validate(p: &ProfileConfig) -> Result<(), String> {
    let name_ok = !p.name.trim().is_empty()
        && p.name.len() <= 64
        && !p.name.chars().any(|c| c.is_control());
    if !name_ok {
        return Err("name must be 1–64 printable characters".into());
    }
    match (&p.agent, p.mcp_match.is_empty()) {
        (Some(a), true) => {
            if a.is_empty() || a.len() > 32 || !a.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_') {
                return Err("agent must be an agent id like claude or codex".into());
            }
        }
        (None, false) => {
            if p.mcp_match.iter().any(|m| m.trim().len() < 3 || m.len() > 256 || m.chars().any(|c| c.is_control())) {
                return Err("each MCP match string must be 3–256 printable characters".into());
            }
        }
        (Some(_), false) => return Err("a profile is for an agent or an MCP server, not both".into()),
        (None, true) => return Err("set agent, or mcp_match for an MCP server".into()),
    }
    if p.allow_hosts.len() > 256 {
        return Err("at most 256 allowed hosts".into());
    }
    for h in &p.allow_hosts {
        if !valid_host_entry(h) {
            return Err(format!("{h:?} is not a host name, *.domain, IP address or IP range"));
        }
    }
    if p.allow_programs.len() > 256 {
        return Err("at most 256 allowed programs".into());
    }
    for prog in &p.allow_programs {
        if prog.is_empty() || prog.len() > 64 || prog.contains('/') || prog.chars().any(|c| c.is_control() || c.is_whitespace()) {
            return Err(format!("{prog:?} is not a program name (use the name, not a path)"));
        }
    }
    Ok(())
}

fn valid_host_entry(h: &str) -> bool {
    if h == "*" || h.parse::<IpAddr>().is_ok() || parse_cidr(h).is_some() {
        return true;
    }
    let name = h.strip_prefix("*.").unwrap_or(h);
    !name.is_empty()
        && name.len() <= 253
        && name.contains('.')
        && name.split('.').all(|l| {
            !l.is_empty() && l.len() <= 63 && l.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
        })
}

/// "10.0.0.0/24" or "fd00::/8" -> (network, prefix length).
pub fn parse_cidr(s: &str) -> Option<(IpAddr, u8)> {
    let (net, len) = s.split_once('/')?;
    let net: IpAddr = net.parse().ok()?;
    let len: u8 = len.parse().ok()?;
    let max = if net.is_ipv4() { 32 } else { 128 };
    (len <= max).then_some((net, len))
}

fn in_cidr(ip: IpAddr, net: IpAddr, len: u8) -> bool {
    match (ip, net) {
        (IpAddr::V4(a), IpAddr::V4(b)) => {
            let mask = if len == 0 { 0 } else { u32::MAX << (32 - len as u32) };
            (u32::from(a) & mask) == (u32::from(b) & mask)
        }
        (IpAddr::V6(a), IpAddr::V6(b)) => {
            let mask = if len == 0 { 0 } else { u128::MAX << (128 - len as u32) };
            (u128::from(a) & mask) == (u128::from(b) & mask)
        }
        _ => false,
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
    once_cell::sync::Lazy::new(|| CapabilityEngine::new(load_profiles()));

/// profiles.json if present, else daemon.toml's `[[profiles]]`. Entries that
/// fail validation are skipped with a warning rather than loaded.
pub fn load_profiles() -> Vec<ProfileConfig> {
    let from_file: Option<Vec<ProfileConfig>> = std::fs::read_to_string(PROFILES_PATH)
        .ok()
        .and_then(|t| match serde_json::from_str(&t) {
            Ok(v) => Some(v),
            Err(e) => {
                tracing::error!(path = PROFILES_PATH, err = %e, "profiles file unreadable; falling back to daemon.toml");
                None
            }
        });
    let all = from_file.unwrap_or_else(|| crate::config::DaemonConfig::load().profiles);
    all.into_iter()
        .filter(|p| match validate(p) {
            Ok(()) => true,
            Err(e) => {
                tracing::warn!(profile = %p.name, err = %e, "skipping invalid profile");
                false
            }
        })
        .collect()
}
const MAX_ANCESTRY: usize = 32;

pub struct CapabilityEngine {
    profiles: RwLock<Vec<ProfileConfig>>,
    /// Allowed host name -> resolved IPs, refreshed in the background.
    resolved: RwLock<HashMap<String, HashSet<IpAddr>>>,
    stats: RwLock<HashMap<String, ProfileStats>>,
    recent: RwLock<HashMap<String, VecDeque<Violation>>>,
    /// Addresses seen in agents' DNS answers for an allowed name or *.domain,
    /// keyed by the profile's host entry, each with its expiry.
    learned: RwLock<HashMap<String, HashMap<std::net::Ipv4Addr, std::time::Instant>>>,
    /// Set after the first lookup of every host name. Until then a profile
    /// that names hosts is not network-enforced, so the seconds after the
    /// daemon starts cannot cut agents off from approved hosts.
    names_ready: std::sync::atomic::AtomicBool,
    /// Concrete names seen in DNS answers for an approved *.domain, kept so
    /// the timer looks them up too. Persisted, so after the first sighting a
    /// name's addresses are already loaded when an agent next connects.
    seen_names: RwLock<HashSet<String>>,
}

/// Where names learned for *.domain entries are kept across restarts.
const SEEN_NAMES_PATH: &str = "/var/lib/ringzero/learned-names.json";
const MAX_SEEN_NAMES: usize = 2048;

/// What the kernel needs to enforce the profiles. Slots start at 2: the
/// kernel uses 1 for "an agent with no profile".
#[derive(Debug, Clone, Default, PartialEq)]
pub struct KernelProfiles {
    /// Process name -> slot, for agents the kernel recognises by name.
    pub names: Vec<(String, u8)>,
    /// slot -> (programs_enforce, allow_spawn, network_enforce)
    pub policies: Vec<(u8, bool, bool, bool)>,
    /// (slot, program basename)
    pub programs: Vec<(u8, String)>,
    /// (slot, IPv4 network, prefix length)
    pub hosts: Vec<(u8, std::net::Ipv4Addr, u8)>,
}

/// The process names an agent runs under, as the kernel sees them (comm,
/// 15 characters at most). Agents that run under a runtime's name (node,
/// python) are tagged by the daemon from their command line instead.
pub fn agent_process_names(agent: &str) -> &'static [&'static str] {
    match agent {
        "claude" => &["claude"],
        "codex" => &["codex"],
        "cursor" => &["cursor-agent", "agent"],
        "gemini" => &["gemini"],
        "aider" => &["aider"],
        "opencode" => &["opencode", "opencode.exe"],
        "windsurf" => &["windsurf"],
        "copilot" => &["copilot"],
        "devin" => &["devin"],
        _ => &[],
    }
}

/// The names a program is really executed under: follow every symlink of
/// `name` found in the standard program directories. Only names that differ
/// from `name` are returned.
pub fn real_program_names(name: &str) -> Vec<String> {
    const DIRS: &[&str] = &["/usr/local/sbin", "/usr/local/bin", "/usr/sbin", "/usr/bin", "/sbin", "/bin"];
    let mut out = Vec::new();
    for d in DIRS {
        let path = std::path::Path::new(d).join(name);
        if let Ok(real) = std::fs::canonicalize(&path) {
            if let Some(f) = real.file_name().and_then(|f| f.to_str()) {
                if f != name && !out.iter().any(|x| x == f) {
                    out.push(f.to_string());
                }
            }
        }
    }
    out
}

const MIN_LEARN_TTL: std::time::Duration = std::time::Duration::from_secs(60);
const MAX_LEARN_TTL: std::time::Duration = std::time::Duration::from_secs(3600);

impl CapabilityEngine {
    pub fn new(profiles: Vec<ProfileConfig>) -> Self {
        CapabilityEngine {
            learned: RwLock::new(HashMap::new()),
            names_ready: std::sync::atomic::AtomicBool::new(false),
            seen_names: RwLock::new(
                std::fs::read_to_string(SEEN_NAMES_PATH)
                    .ok()
                    .and_then(|t| serde_json::from_str::<HashSet<String>>(&t).ok())
                    .unwrap_or_default(),
            ),
            profiles: RwLock::new(profiles),
            resolved: RwLock::new(HashMap::new()),
            stats: RwLock::new(HashMap::new()),
            recent: RwLock::new(HashMap::new()),
        }
    }

    /// Current profile list.
    pub fn profiles(&self) -> Vec<ProfileConfig> {
        self.profiles.read().map(|p| p.clone()).unwrap_or_default()
    }

    /// Add or replace (by name) one profile, persist the whole list, apply it
    /// live. Returns the saved list.
    pub fn upsert(&self, p: ProfileConfig) -> Result<Vec<ProfileConfig>, String> {
        validate(&p)?;
        let mut list = self.profiles();
        match list.iter_mut().find(|x| x.name == p.name) {
            Some(slot) => *slot = p,
            None => list.push(p),
        }
        self.replace(list)
    }

    /// Remove one profile by name. Err if there is no such profile.
    pub fn remove(&self, name: &str) -> Result<Vec<ProfileConfig>, String> {
        let mut list = self.profiles();
        let before = list.len();
        list.retain(|x| x.name != name);
        if list.len() == before {
            return Err(format!("no profile named {name:?}"));
        }
        self.replace(list)
    }

    fn replace(&self, list: Vec<ProfileConfig>) -> Result<Vec<ProfileConfig>, String> {
        persist(&list)?;
        if let Ok(mut w) = self.profiles.write() {
            *w = list.clone();
        }
        Ok(list)
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
                    .filter(|h| h != "*" && !h.starts_with("*.") && h.parse::<IpAddr>().is_err() && parse_cidr(h).is_none())
                    .collect()
            })
            .unwrap_or_default();
        let mut out: HashMap<String, HashSet<IpAddr>> = HashMap::new();
        // Names learned for *.domain entries, looked up like the rest. Their
        // addresses are filed under the matching *.domain pattern.
        let seen: Vec<String> = self.seen_names.read().map(|s| s.iter().cloned().collect()).unwrap_or_default();
        let wildcards: Vec<String> = self
            .profiles
            .read()
            .map(|ps| ps.iter().flat_map(|p| p.allow_hosts.iter()).filter(|h| h.starts_with("*.")).cloned().collect())
            .unwrap_or_default();
        for name in seen {
            let pats: Vec<&String> = wildcards.iter().filter(|w| host_matches(w, &name)).collect();
            if pats.is_empty() {
                continue;
            }
            if let Ok(addrs) = tokio::net::lookup_host((name.as_str(), 443)).await {
                let ips: Vec<IpAddr> = addrs.map(|a| a.ip()).collect();
                for w in pats {
                    out.entry(w.clone()).or_default().extend(ips.iter().copied());
                }
            }
        }
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
        self.names_ready.store(true, std::sync::atomic::Ordering::Release);
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
            if let Some((net, len)) = parse_cidr(h) {
                return in_cidr(ip, net, len);
            }
            if let Some(name) = host {
                if host_matches(h, name) {
                    return true;
                }
            }
            let learned_hit = match ip {
                IpAddr::V4(a) => self
                    .learned
                    .read()
                    .ok()
                    .and_then(|l| l.get(h).map(|m| m.contains_key(&a)))
                    .unwrap_or(false),
                _ => false,
            };
            learned_hit
                || resolved
                    .as_ref()
                    .and_then(|r| r.get(h))
                    .is_some_and(|ips| ips.contains(&ip))
        })
    }

    /// The kernel slot for a profile, by its position in the list.
    fn slot_of(index: usize) -> Option<u8> {
        u8::try_from(index + 2).ok()
    }

    /// Slot of the profile for this agent id, if one exists.
    pub fn slot_for_agent(&self, agent: &str) -> Option<u8> {
        let ps = self.profiles.read().ok()?;
        ps.iter().position(|p| p.agent.as_deref() == Some(agent)).and_then(Self::slot_of)
    }

    /// Slot of the MCP-server profile whose match strings all occur in this
    /// command line, if any.
    pub fn mcp_slot_for(&self, cmdline: &str) -> Option<u8> {
        let ps = self.profiles.read().ok()?;
        ps.iter()
            .position(|p| !p.mcp_match.is_empty() && p.mcp_match.iter().all(|m| cmdline.contains(m.as_str())))
            .and_then(Self::slot_of)
    }

    /// True when any profile enforces anything, so the daemon knows whether
    /// keeping addresses fresh matters.
    pub fn any_enforced(&self) -> bool {
        self.profiles
            .read()
            .map(|ps| ps.iter().any(|p| p.network_mode == Mode::Enforce || p.programs_mode == Mode::Enforce))
            .unwrap_or(false)
    }

    /// Everything the kernel needs, computed from the profiles, the looked-up
    /// addresses and the learned ones.
    pub fn kernel_state(&self) -> KernelProfiles {
        let mut out = KernelProfiles::default();
        let Ok(ps) = self.profiles.read() else { return out };
        let resolved = self.resolved.read().ok();
        let learned = self.learned.read().ok();
        let now = std::time::Instant::now();
        for (i, p) in ps.iter().enumerate() {
            let Some(slot) = Self::slot_of(i) else { break };
            if let Some(agent) = &p.agent {
                for n in agent_process_names(agent) {
                    out.names.push((n.to_string(), slot));
                }
            }
            let any_host = p.allow_hosts.iter().any(|h| h == "*");
            let names_pending = !self.names_ready.load(std::sync::atomic::Ordering::Acquire)
                && p.allow_hosts.iter().any(|h| h.parse::<IpAddr>().is_err() && parse_cidr(h).is_none());
            let net_enforce = p.network_mode == Mode::Enforce && !any_host && !names_pending;
            let prog_limited = !p.allow_spawn || !p.allow_programs.is_empty();
            let prog_enforce = p.programs_mode == Mode::Enforce && prog_limited;
            out.policies.push((slot, prog_enforce, p.allow_spawn, net_enforce));
            if prog_enforce {
                for prog in &p.allow_programs {
                    out.programs.push((slot, prog.clone()));
                    // The kernel sees the file actually executed. python3 is
                    // usually a link to python3.14 and sh a link to dash, so
                    // approve the real name too.
                    for real in real_program_names(prog) {
                        out.programs.push((slot, real));
                    }
                }
                out.programs.sort();
                out.programs.dedup();
            }
            if net_enforce {
                for h in &p.allow_hosts {
                    if let Ok(IpAddr::V4(a)) = h.parse::<IpAddr>() {
                        out.hosts.push((slot, a, 32));
                    } else if let Some((IpAddr::V4(n), len)) = parse_cidr(h) {
                        out.hosts.push((slot, n, len));
                    } else {
                        if let Some(ips) = resolved.as_ref().and_then(|r| r.get(h)) {
                            for ip in ips {
                                if let IpAddr::V4(a) = ip {
                                    out.hosts.push((slot, *a, 32));
                                }
                            }
                        }
                        if let Some(ips) = learned.as_ref().and_then(|l| l.get(h)) {
                            for (a, exp) in ips {
                                if *exp > now {
                                    out.hosts.push((slot, *a, 32));
                                }
                            }
                        }
                    }
                }
            }
        }
        out.hosts.sort();
        out.hosts.dedup();
        out
    }

    /// Admit addresses from a DNS answer an agent received, for every
    /// profile host entry (name or *.domain) the answered name matches.
    /// Returns true when something new was learned.
    pub fn learn_dns(&self, records: &[crate::dns_allow::ARecord]) -> bool {
        let patterns: Vec<String> = match self.profiles.read() {
            Ok(ps) => ps
                .iter()
                .flat_map(|p| p.allow_hosts.iter())
                .filter(|h| *h != "*" && h.parse::<IpAddr>().is_err() && parse_cidr(h).is_none())
                .cloned()
                .collect(),
            Err(_) => return false,
        };
        if patterns.is_empty() {
            return false;
        }
        let now = std::time::Instant::now();
        let mut new = false;
        let Ok(mut l) = self.learned.write() else { return false };
        for r in records {
            let ttl = std::time::Duration::from_secs(r.ttl_secs as u64).clamp(MIN_LEARN_TTL, MAX_LEARN_TTL);
            for pat in patterns.iter().filter(|pat| host_matches(pat, &r.name)) {
                let e = l.entry(pat.clone()).or_default();
                if e.insert(r.addr, now + ttl).is_none() {
                    new = true;
                }
                if pat.starts_with("*.") {
                    let name = r.name.trim_end_matches('.').to_ascii_lowercase();
                    if let Ok(mut sn) = self.seen_names.write() {
                        if sn.len() < MAX_SEEN_NAMES && sn.insert(name) {
                            if let Ok(t) = serde_json::to_string(&*sn) {
                                let _ = std::fs::write(SEEN_NAMES_PATH, t);
                            }
                        }
                    }
                }
            }
        }
        new
    }

    /// Forget learned addresses whose TTL has run out. True if any went.
    pub fn expire_learned(&self) -> bool {
        let now = std::time::Instant::now();
        let Ok(mut l) = self.learned.write() else { return false };
        let mut gone = false;
        for ips in l.values_mut() {
            let before = ips.len();
            ips.retain(|_, exp| *exp > now);
            gone |= ips.len() != before;
        }
        gone
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

/// Push the current profiles into the kernel. Safe to call often: the loader
/// only changes what differs.
pub async fn sync_kernel() {
    if let Some(tx) = crate::ebpf_loader::CMD_TX.get() {
        let _ = tx.send(crate::ebpf_loader::EbpfCommand::SyncProfiles(ENGINE.kernel_state())).await;
    }
}

/// Write the list atomically (temp file + rename), root-only.
fn persist(list: &[ProfileConfig]) -> Result<(), String> {
    use std::io::Write;
    let path = std::path::Path::new(PROFILES_PATH);
    let dir = path.parent().ok_or("bad profiles path")?;
    let tmp = dir.join(".profiles.json.tmp");
    let json = serde_json::to_string_pretty(list).map_err(|e| e.to_string())?;
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode_0600()
        .open(&tmp)
        .map_err(|e| format!("cannot write {}: {e}", tmp.display()))?;
    f.write_all(json.as_bytes()).map_err(|e| e.to_string())?;
    f.sync_all().map_err(|e| e.to_string())?;
    std::fs::rename(&tmp, path).map_err(|e| format!("cannot replace {}: {e}", path.display()))
}

trait Mode0600 {
    fn mode_0600(&mut self) -> &mut Self;
}
impl Mode0600 for std::fs::OpenOptions {
    fn mode_0600(&mut self) -> &mut Self {
        use std::os::unix::fs::OpenOptionsExt;
        self.mode(0o600)
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
    fn cidr_ranges() {
        let mut p = claude();
        p.allow_hosts = vec!["10.0.0.0/24".into(), "fd00::/8".into()];
        let e = CapabilityEngine::new(vec![p]);
        let anc = vec![(10, "/home/u/.local/bin/claude".into())];
        let ok = |ip: &str| e.check(EventShape::Connect { ip: ip.parse().unwrap(), port: 443, host: None }, 10, "claude", &anc, agent_of).is_none();
        assert!(ok("10.0.0.5"));
        assert!(ok("10.0.0.255"));
        assert!(!ok("10.0.1.1"));
        assert!(ok("fd12::1"));
        assert!(!ok("2001:db8::1"));
    }

    #[test]
    fn validation() {
        assert!(validate(&claude()).is_ok());
        assert!(validate(&fs_mcp()).is_ok());
        let mut p = claude(); p.name = "".into(); assert!(validate(&p).is_err());
        let mut p = claude(); p.mcp_match = vec!["x-server".into()]; assert!(validate(&p).is_err(), "agent and mcp both set");
        let mut p = claude(); p.agent = None; assert!(validate(&p).is_err(), "neither set");
        let mut p = claude(); p.allow_hosts = vec!["not a host".into()]; assert!(validate(&p).is_err());
        let mut p = claude(); p.allow_hosts = vec!["10.0.0.0/33".into()]; assert!(validate(&p).is_err());
        let mut p = claude(); p.allow_hosts = vec!["10.0.0.0/8".into(), "*.corp.example".into(), "::1".into()]; assert!(validate(&p).is_ok());
        let mut p = claude(); p.allow_programs = vec!["/usr/bin/git".into()]; assert!(validate(&p).is_err(), "path, not name");
        let mut p = claude(); p.agent = Some("bad id!".into()); assert!(validate(&p).is_err());
    }

    #[test]
    fn mode_defaults_to_watch_and_round_trips() {
        let p: ProfileConfig = serde_json::from_str(r#"{"name":"x","agent":"claude"}"#).unwrap();
        assert_eq!(p.network_mode, Mode::Watch);
        let p: ProfileConfig = serde_json::from_str(r#"{"name":"x","agent":"claude","network_mode":"enforce"}"#).unwrap();
        assert_eq!(p.network_mode, Mode::Enforce);
    }

    #[test]
    fn targets_parse() {
        assert_eq!(parse_target("1.2.3.4:443"), Some(("1.2.3.4".parse().unwrap(), 443)));
        assert_eq!(parse_target("[::1]:80"), Some(("::1".parse().unwrap(), 80)));
        assert_eq!(parse_target("nope"), None);
    }

    fn ready(e: CapabilityEngine) -> CapabilityEngine {
        e.names_ready.store(true, std::sync::atomic::Ordering::Release);
        e
    }

    fn prof(name: &str, agent: &str) -> ProfileConfig {
        ProfileConfig { name: name.into(), agent: Some(agent.into()), ..Default::default() }
    }

    #[test]
    fn watch_profiles_load_nothing_that_refuses() {
        let mut p = prof("Claude Code", "claude");
        p.allow_hosts = vec!["10.0.0.5".into()];
        p.allow_programs = vec!["git".into()];
        let e = CapabilityEngine::new(vec![p]);
        let st = e.kernel_state();
        assert_eq!(st.names, vec![("claude".to_string(), 2)]);
        assert_eq!(st.policies, vec![(2, false, true, false)]);
        assert!(st.programs.is_empty() && st.hosts.is_empty());
    }

    #[test]
    fn enforced_profile_loads_its_lists() {
        let mut p = prof("Claude Code", "claude");
        p.allow_hosts = vec!["10.0.0.5".into(), "192.168.1.0/24".into(), "fd00::1".into()];
        p.allow_programs = vec!["git".into(), "bash".into()];
        p.network_mode = Mode::Enforce;
        p.programs_mode = Mode::Enforce;
        let e = ready(CapabilityEngine::new(vec![prof("Other", "codex"), p]));
        let st = e.kernel_state();
        assert!(st.policies.contains(&(3, true, true, true)));
        assert!(st.programs.contains(&(3, "git".to_string())));
        // IPv6 entries are not loaded: the kernel allowlist is IPv4.
        assert_eq!(
            st.hosts,
            vec![(3, "10.0.0.5".parse().unwrap(), 32), (3, "192.168.1.0".parse().unwrap(), 24)]
        );
    }

    #[test]
    fn names_not_enforced_before_first_lookup() {
        let mut p = prof("Claude Code", "claude");
        p.allow_hosts = vec!["api.anthropic.com".into()];
        p.network_mode = Mode::Enforce;
        let e = CapabilityEngine::new(vec![p]);
        assert_eq!(e.kernel_state().policies, vec![(2, false, true, false)]);
        let e = ready(e);
        assert_eq!(e.kernel_state().policies, vec![(2, false, true, true)]);
    }

    #[test]
    fn any_host_or_any_program_never_enforces() {
        let mut p = prof("Codex", "codex");
        p.network_mode = Mode::Enforce;
        p.programs_mode = Mode::Enforce;
        // defaults: allow_hosts ["*"], allow_spawn true, no list
        let st = CapabilityEngine::new(vec![p]).kernel_state();
        assert_eq!(st.policies, vec![(2, false, true, false)]);
    }

    #[test]
    fn no_spawn_enforces_with_empty_list() {
        let mut p = prof("MCP", "x");
        p.agent = None;
        p.mcp_match = vec!["server-fs".into()];
        p.allow_spawn = false;
        p.programs_mode = Mode::Enforce;
        let e = CapabilityEngine::new(vec![p]);
        assert_eq!(e.kernel_state().policies, vec![(2, true, false, false)]);
        assert_eq!(e.mcp_slot_for("node /x/server-fs/index.js"), Some(2));
        assert_eq!(e.mcp_slot_for("node other.js"), None);
    }

    #[test]
    fn dns_answers_teach_approved_names_only() {
        let mut p = prof("Claude Code", "claude");
        p.allow_hosts = vec!["api.anthropic.com".into(), "*.githubusercontent.com".into()];
        p.network_mode = Mode::Enforce;
        let e = ready(CapabilityEngine::new(vec![p]));
        let rec = |n: &str, a: &str| crate::dns_allow::ARecord { name: n.into(), addr: a.parse().unwrap(), ttl_secs: 300 };
        assert!(e.learn_dns(&[rec("api.anthropic.com.", "160.79.104.10")]));
        assert!(e.learn_dns(&[rec("raw.githubusercontent.com", "185.199.108.133")]));
        assert!(!e.learn_dns(&[rec("evil.example", "203.0.113.9")]));
        assert!(!e.learn_dns(&[rec("api.anthropic.com", "160.79.104.10")]), "already known");
        let hosts = e.kernel_state().hosts;
        assert!(hosts.contains(&(2, "160.79.104.10".parse().unwrap(), 32)));
        assert!(hosts.contains(&(2, "185.199.108.133".parse().unwrap(), 32)));
        assert!(!hosts.iter().any(|h| h.1 == "203.0.113.9".parse::<std::net::Ipv4Addr>().unwrap()));
        // The watch-mode check agrees with what the kernel was given.
        let pr = e.profiles();
        assert!(e.host_allowed(&pr[0], "160.79.104.10".parse().unwrap(), None));
    }
}
