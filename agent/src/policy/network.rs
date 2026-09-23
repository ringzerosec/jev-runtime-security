// SPDX-License-Identifier: Apache-2.0
// policy/network.rs — NetworkMode enforcement
// low:    only agent-origin process
// medium: agent + full child process tree
// high:   all outbound + consent prompt per new destination

use super::acl::Decision;
use crate::common::event::SecurityEvent;
use crate::common::policy::{EnforceMode, NetworkMode};
use std::collections::{HashMap, HashSet};
use tokio::sync::RwLock;

/// Well-known AI provider and package registry endpoints that agents
/// legitimately connect to. These are always allowed regardless of
/// network mode — blocking them would break every coding agent.
const WHITELISTED_HOSTS: &[&str] = &[
    // AI providers
    "api.anthropic.com",
    "api.openai.com",
    "generativelanguage.googleapis.com",
    // Gemini CLI on its OAuth/free (Code Assist) tier talks to cloudcode-pa,
    // and Vertex to aiplatform; oauth2/accounts for the Google sign-in. Without
    // these, gemini's normal traffic was treated as exfil and SIGKILLed.
    "cloudcode-pa.googleapis.com",
    "aiplatform.googleapis.com",
    "oauth2.googleapis.com",
    "accounts.google.com",
    "api.github.com",
    "copilot-proxy.githubusercontent.com",
    "api.githubcopilot.com",
    // Package registries
    "registry.npmjs.org",
    "pypi.org",
    "files.pythonhosted.org",
    "crates.io",
    "static.crates.io",
    "rubygems.org",
    // Common dev infra
    "github.com",
    "raw.githubusercontent.com",
    "objects.githubusercontent.com",
    "gitlab.com",
    "bitbucket.org",
    // Claude Code specific
    "sentry.io",
    "statsig.anthropic.com",
];

/// Known IP ranges for AI providers (checked when DNS isn't available
/// and we only see raw IP:port). These are Anthropic API server IPs.
const WHITELISTED_IP_PREFIXES: &[&str] = &[
    "160.79.", // Anthropic
    "104.18.", // Cloudflare (fronts many AI APIs)
    "172.64.", // Cloudflare
    "104.16.", // Cloudflare
];

pub struct NetworkPolicy {
    pub mode: RwLock<NetworkMode>,
    pub enforce: RwLock<EnforceMode>,
    /// Agent root PIDs (started by user as AI agents)
    agent_pids: RwLock<HashSet<u32>>,
    /// pid → parent_pid for tree walking
    pid_tree: RwLock<HashMap<u32, u32>>,
    /// Approved destinations (high mode consent)
    approved: RwLock<HashSet<String>>,
}

impl NetworkPolicy {
    pub fn new() -> Self {
        Self {
            mode: RwLock::new(NetworkMode::Low),
            enforce: RwLock::new(EnforceMode::Enforce),
            agent_pids: RwLock::new(HashSet::new()),
            pid_tree: RwLock::new(HashMap::new()),
            approved: RwLock::new(HashSet::new()),
        }
    }

    #[allow(dead_code)]
    pub async fn register_agent(&self, pid: u32) {
        self.agent_pids.write().await.insert(pid);
    }

    #[allow(dead_code)]
    pub async fn register_fork(&self, parent_pid: u32, child_pid: u32) {
        self.pid_tree.write().await.insert(child_pid, parent_pid);
    }

    #[allow(dead_code)]
    pub async fn approve_destination(&self, dest: String) {
        self.approved.write().await.insert(dest);
    }

    /// Evaluate a network event against the current mode.
    pub async fn evaluate(&self, event: &SecurityEvent) -> Decision {
        // Infrastructure (DNS / loopback / link-local) is never a threat.
        if is_infrastructure_destination(&event.target) {
            return Decision::Allow;
        }

        // Always allow whitelisted destinations (AI APIs, package registries)
        if is_whitelisted_destination(&event.target) {
            return Decision::Allow;
        }

        let mode = self.mode.read().await.clone();
        let enforce = self.enforce.read().await.clone();

        let should_block = match mode {
            NetworkMode::Low => {
                // Agent-origin traffic. The agent itself rarely opens sockets —
                // it shells out (curl/node/python), so the connecting PID is a
                // CHILD of the agent. Authorize the agent PID and its direct
                // children (ppid in the agent set); otherwise every benign tool
                // the agent spawns is flagged (the §6.3 FP storm).
                let agents = self.agent_pids.read().await;
                !(agents.contains(&event.pid)
                    || event.ppid.map(|pp| agents.contains(&pp)).unwrap_or(false))
            }
            NetworkMode::Medium => {
                // Allow agent PID + descendants
                !self.is_in_agent_tree(event.pid).await
            }
            NetworkMode::High => {
                // Allow all, but require consent for new destinations
                let dest = &event.target;
                !self.approved.read().await.contains(dest.as_str()) && !dest.is_empty()
            }
        };

        if should_block {
            match enforce {
                EnforceMode::Enforce => Decision::Block {
                    reason: format!(
                        "Network {:?} mode: PID {} not authorized for '{}'",
                        mode, event.pid, event.target
                    ),
                },
                EnforceMode::Observe => {
                    tracing::warn!(
                        pid = event.pid,
                        target = %event.target,
                        mode = ?mode,
                        "Network violation (observe mode — not blocked)"
                    );
                    Decision::Allow
                }
            }
        } else {
            Decision::Allow
        }
    }

    async fn is_in_agent_tree(&self, pid: u32) -> bool {
        let agents = self.agent_pids.read().await;
        let tree = self.pid_tree.read().await;
        let mut cur = pid;
        loop {
            if agents.contains(&cur) {
                return true;
            }
            match tree.get(&cur) {
                Some(&parent) => cur = parent,
                None => return false,
            }
        }
    }
}

/// LLM API domains — if a process connects to any of these, it's an AI agent.
/// The resolved IPv4 addresses of the known LLM API endpoints.
///
/// Seeded into the kernel egress allowlist so a tainted agent can still reach
/// its model — without this, turning egress enforcement on would strangle the
/// agent itself. Best effort: a host that does not resolve is skipped.
pub fn resolved_llm_ipv4s() -> Vec<std::net::Ipv4Addr> {
    let mut out = Vec::new();
    for domain in LLM_API_HOSTS {
        if let Ok(addrs) = std::net::ToSocketAddrs::to_socket_addrs(&format!("{domain}:443")) {
            for a in addrs {
                if let std::net::IpAddr::V4(v4) = a.ip() {
                    out.push(v4);
                }
            }
        }
    }
    out
}

const LLM_API_HOSTS: &[&str] = &[
    "api.anthropic.com",
    "api.openai.com",
    "generativelanguage.googleapis.com",
    "cloudcode-pa.googleapis.com",
    "aiplatform.googleapis.com",
    "api.github.com",
    "copilot-proxy.githubusercontent.com",
    "api.githubcopilot.com",
    "api.cursor.sh",
    "api2.cursor.sh",
    "api2geo.cursor.sh",
    "api2direct.cursor.sh",
    "api3.cursor.sh",
    "chatgpt.com",
];

/// Check if a destination target (host:port or IP:port) is an LLM API endpoint.
/// Used to auto-detect AI agent processes by their network destination.
/// Works with both hostnames and IP addresses.
pub fn is_llm_api_destination(target: &str) -> bool {
    let host = target.split(':').next().unwrap_or(target);
    // Check hostname match
    if LLM_API_HOSTS.iter().any(|h| host.contains(h)) {
        return true;
    }
    // If target looks like an IP address, check against pre-resolved LLM provider IPs
    if host
        .chars()
        .next()
        .map(|c| c.is_ascii_digit())
        .unwrap_or(false)
    {
        use std::collections::HashSet;
        use std::sync::OnceLock;

        static LLM_IPS: OnceLock<HashSet<String>> = OnceLock::new();
        let ips = LLM_IPS.get_or_init(|| {
            let mut set = HashSet::new();
            for domain in LLM_API_HOSTS {
                if let Ok(addrs) =
                    std::net::ToSocketAddrs::to_socket_addrs(&format!("{}:443", domain))
                {
                    for addr in addrs {
                        set.insert(addr.ip().to_string());
                    }
                }
            }
            tracing::info!(
                count = set.len(),
                "Resolved LLM provider IPs for auto-detection"
            );
            set
        });
        return ips.contains(host);
    }
    false
}

/// Check if a destination (host:port or IP:port) matches a whitelisted endpoint.
pub fn is_whitelisted_destination(target: &str) -> bool {
    let host = target.split(':').next().unwrap_or(target);

    // Loopback is always trusted: the agent's HTTPS is routed through Ring Zero's
    // own inspection proxy on 127.0.0.1, so every captured request would otherwise
    // look like a connection to an "unknown" destination and trip the session gate
    // + baseline network warnings. The proxy inspects the REAL destination itself.
    if host == "127.0.0.1" || host == "::1" || host == "localhost" || host.starts_with("127.") {
        return true;
    }

    // Check hostname-based whitelist
    for &wl in WHITELISTED_HOSTS {
        if host == wl || host.ends_with(&format!(".{}", wl)) {
            return true;
        }
    }

    // Check IP prefix whitelist (for raw IP connections without DNS)
    for &prefix in WHITELISTED_IP_PREFIXES {
        if host.starts_with(prefix) {
            return true;
        }
    }

    false
}

/// Split a `host:port` target into (host, port), IPv6-aware. Handles
/// `1.2.3.4:443`, `[::1]:443`, bare `::1` (no port), and bare hostnames.
fn split_host_port(target: &str) -> (&str, Option<u16>) {
    if let Some(rest) = target.strip_prefix('[') {
        // Bracketed IPv6: [addr]:port  or  [addr]
        if let Some((h, p)) = rest.split_once("]:") {
            return (h, p.parse::<u16>().ok());
        }
        return (rest.trim_end_matches(']'), None);
    }
    // Two or more colons and not bracketed → bare IPv6 literal, no port.
    if target.matches(':').count() >= 2 {
        return (target, None);
    }
    match target.rsplit_once(':') {
        Some((h, p)) => (h, p.parse::<u16>().ok()),
        None => (target, None),
    }
}

/// Infrastructure traffic that is NEVER a threat regardless of network mode:
/// DNS resolution, loopback, the unspecified address, and link-local. Flagging
/// these floods the threat feed with phantom "violations" (§6.3) — e.g. every
/// `curl` triggers a DNS lookup to the systemd-resolved stub `127.0.0.53:53`,
/// which is benign infrastructure, not an agent reaching out. Network events
/// carry raw IP:port (no DNS name), so this must match on IP form.
pub fn is_infrastructure_destination(target: &str) -> bool {
    let (host, port) = split_host_port(target);

    // DNS — resolution itself is infrastructure, not an outbound agent action.
    if port == Some(53) {
        return true;
    }
    // Loopback / unspecified / link-local (IPv4 + IPv6).
    host.starts_with("127.")            // IPv4 loopback
        || host == "0.0.0.0"            // unspecified (pre-connect artifact)
        || host.is_empty()             // DNS events with no captured target
        || host.starts_with("169.254.") // IPv4 link-local
        || host == "::1"               // IPv6 loopback
        || host == "::"                // IPv6 unspecified
        || host.starts_with("fe80:") // IPv6 link-local
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn whitelist_anthropic_api() {
        assert!(is_whitelisted_destination("api.anthropic.com:443"));
        assert!(is_whitelisted_destination("api.anthropic.com"));
    }

    #[test]
    fn whitelist_gemini_endpoints() {
        // Gemini CLI's real endpoints — without these its normal traffic was
        // treated as exfil and the agent was SIGKILLed.
        assert!(is_whitelisted_destination("cloudcode-pa.googleapis.com"));
        assert!(is_whitelisted_destination(
            "cloudcode-pa.googleapis.com:443"
        ));
        assert!(is_whitelisted_destination(
            "generativelanguage.googleapis.com"
        ));
        assert!(is_whitelisted_destination("aiplatform.googleapis.com"));
        assert!(is_whitelisted_destination("oauth2.googleapis.com"));
        // A non-provider host is still NOT whitelisted (real exfil still caught).
        assert!(!is_whitelisted_destination("evil.attacker.example"));
    }

    #[test]
    fn whitelist_anthropic_ip() {
        assert!(is_whitelisted_destination("160.79.104.10:443"));
        assert!(is_whitelisted_destination("160.79.0.1:443"));
    }

    #[test]
    fn whitelist_openai() {
        assert!(is_whitelisted_destination("api.openai.com:443"));
    }

    #[test]
    fn whitelist_registries() {
        assert!(is_whitelisted_destination("registry.npmjs.org:443"));
        assert!(is_whitelisted_destination("pypi.org:443"));
        assert!(is_whitelisted_destination("crates.io:443"));
    }

    #[test]
    fn infrastructure_is_never_a_threat() {
        // DNS (the dominant FP — systemd-resolved stub every curl hits)
        assert!(is_infrastructure_destination("127.0.0.53:53"));
        assert!(is_infrastructure_destination("8.8.8.8:53"));
        // loopback / unspecified / link-local
        assert!(is_infrastructure_destination("127.0.0.1:8080"));
        assert!(is_infrastructure_destination("0.0.0.0:443"));
        assert!(is_infrastructure_destination("::1"));
        assert!(is_infrastructure_destination("169.254.1.1:80"));
        assert!(is_infrastructure_destination("")); // DNS event w/o captured target
                                                    // a real public destination is NOT infrastructure
        assert!(!is_infrastructure_destination("151.101.64.223:443"));
    }

    #[test]
    fn unknown_host_not_whitelisted() {
        assert!(!is_whitelisted_destination("evil.com:443"));
        assert!(!is_whitelisted_destination("45.33.32.156:53"));
        assert!(!is_whitelisted_destination("exfil.attacker.com:80"));
    }
}
