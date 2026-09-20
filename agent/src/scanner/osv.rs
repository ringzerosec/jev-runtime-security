// SPDX-License-Identifier: Apache-2.0
// scanner/osv.rs — OSV.dev vulnerability lookup for package installs
//
// Hooks into the eBPF event pipeline: when an agent runs `npm install`,
// `pip install`, `cargo add`, etc., we extract the package name + version
// and query the OSV.dev API (https://api.osv.dev/v1/query) for known
// vulnerabilities.
//
// Integration:
//   - main.rs: call osv::check_install_event() on ProcessExec events
//   - Produces SecurityEvent(AttackChain) if vulns found
//   - Enriches the provenance graph with VulnerabilityNode
//
// OSV API is free, unauthenticated, rate-limit-friendly (~100 req/min).

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

// ── Package install parsing ─────────────────────────────────────────────────

/// A package install extracted from a ProcessExec event's arguments.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackageInstall {
    pub name: String,
    pub version: Option<String>,
    pub ecosystem: Ecosystem,
    pub command: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Ecosystem {
    Npm,
    PyPI,
    #[serde(rename = "crates.io")]
    CratesIo,
    Go,
    Maven,
    RubyGems,
    NuGet,
    Packagist,
}

impl Ecosystem {
    /// OSV ecosystem string as expected by the API.
    pub fn osv_name(&self) -> &'static str {
        match self {
            Ecosystem::Npm => "npm",
            Ecosystem::PyPI => "PyPI",
            Ecosystem::CratesIo => "crates.io",
            Ecosystem::Go => "Go",
            Ecosystem::Maven => "Maven",
            Ecosystem::RubyGems => "RubyGems",
            Ecosystem::NuGet => "NuGet",
            Ecosystem::Packagist => "Packagist",
        }
    }
}

/// Try to extract a package install from a process exec event.
/// Returns None if this isn't a package install command.
pub fn parse_install_command(process: &str, target: &str) -> Option<PackageInstall> {
    let proc_name = process.rsplit('/').next().unwrap_or(process).to_lowercase();
    let target_name = target.rsplit('/').next().unwrap_or(target).to_lowercase();

    // npm install <pkg>, npm i <pkg>, npm add <pkg>
    // pnpm add <pkg>, yarn add <pkg>, bun add <pkg>
    if matches!(proc_name.as_str(), "npm" | "pnpm" | "yarn" | "bun") {
        return parse_npm_install(target, &proc_name);
    }
    if matches!(target_name.as_str(), "npm" | "pnpm" | "yarn" | "bun") {
        return parse_npm_install(target, &target_name);
    }

    // pip install <pkg>, pip3 install <pkg>
    if matches!(proc_name.as_str(), "pip" | "pip3" | "uv") {
        return parse_pip_install(target, &proc_name);
    }
    if matches!(target_name.as_str(), "pip" | "pip3" | "uv") {
        return parse_pip_install(target, &target_name);
    }

    // cargo add <pkg>, cargo install <pkg>
    if proc_name == "cargo" || target_name == "cargo" {
        return parse_cargo_install(target);
    }

    // go get <pkg>
    if proc_name == "go" || target_name == "go" {
        return parse_go_install(target);
    }

    // gem install <pkg>
    if proc_name == "gem" || target_name == "gem" {
        return parse_gem_install(target);
    }

    None
}

fn parse_npm_install(target: &str, tool: &str) -> Option<PackageInstall> {
    let parts: Vec<&str> = target.split_whitespace().collect();

    // Find the install/add subcommand position
    let cmd_idx = parts
        .iter()
        .position(|p| matches!(*p, "install" | "i" | "add"))?;

    // Find the first non-flag argument after the subcommand
    let pkg_str = parts
        .iter()
        .skip(cmd_idx + 1)
        .find(|p| !p.starts_with('-'))?;

    // Parse name@version
    let (name, version) = parse_name_at_version(pkg_str);

    // Skip bare `npm install` (installs from package.json, not a specific pkg)
    if name.is_empty() {
        return None;
    }

    Some(PackageInstall {
        name,
        version,
        ecosystem: Ecosystem::Npm,
        command: format!("{} {}", tool, parts[cmd_idx..].join(" ")),
    })
}

fn parse_pip_install(target: &str, tool: &str) -> Option<PackageInstall> {
    let parts: Vec<&str> = target.split_whitespace().collect();

    let cmd_idx = parts.iter().position(|p| *p == "install")?;

    let pkg_str = parts
        .iter()
        .skip(cmd_idx + 1)
        .find(|p| !p.starts_with('-') && !p.starts_with('/'))?;

    // pip uses == for version pinning: requests==2.28.0
    let (name, version) = if pkg_str.contains("==") {
        let mut split = pkg_str.splitn(2, "==");
        (
            split.next().unwrap_or("").to_string(),
            split.next().map(|s| s.to_string()),
        )
    } else if pkg_str.contains(">=") || pkg_str.contains("<=") || pkg_str.contains("~=") {
        let re_split: Vec<&str> = pkg_str
            .splitn(2, |c: char| c == '>' || c == '<' || c == '~')
            .collect();
        (re_split[0].to_string(), None) // version constraint, not exact
    } else {
        (pkg_str.to_string(), None)
    };

    if name.is_empty() || name == "-r" || name == "-e" {
        return None;
    }

    Some(PackageInstall {
        name,
        version,
        ecosystem: Ecosystem::PyPI,
        command: format!("{} {}", tool, parts[cmd_idx..].join(" ")),
    })
}

fn parse_cargo_install(target: &str) -> Option<PackageInstall> {
    let parts: Vec<&str> = target.split_whitespace().collect();

    let cmd_idx = parts.iter().position(|p| matches!(*p, "add" | "install"))?;

    let pkg_str = parts
        .iter()
        .skip(cmd_idx + 1)
        .find(|p| !p.starts_with('-'))?;

    // cargo add foo@1.2.3 or cargo install foo --version 1.2.3
    let (name, mut version) = parse_name_at_version(pkg_str);

    // Check for --version flag
    if version.is_none() {
        if let Some(vi) = parts
            .iter()
            .position(|p| *p == "--version" || *p == "--vers")
        {
            version = parts.get(vi + 1).map(|v| v.to_string());
        }
    }

    if name.is_empty() {
        return None;
    }

    Some(PackageInstall {
        name,
        version,
        ecosystem: Ecosystem::CratesIo,
        command: format!("cargo {}", parts[cmd_idx..].join(" ")),
    })
}

fn parse_go_install(target: &str) -> Option<PackageInstall> {
    let parts: Vec<&str> = target.split_whitespace().collect();

    let cmd_idx = parts.iter().position(|p| *p == "get")?;

    let pkg_str = parts
        .iter()
        .skip(cmd_idx + 1)
        .find(|p| !p.starts_with('-'))?;

    // go get github.com/foo/bar@v1.2.3
    let (name, version) = if pkg_str.contains('@') {
        let mut split = pkg_str.splitn(2, '@');
        (
            split.next().unwrap_or("").to_string(),
            split.next().map(|s| s.to_string()),
        )
    } else {
        (pkg_str.to_string(), None)
    };

    if name.is_empty() {
        return None;
    }

    Some(PackageInstall {
        name,
        version,
        ecosystem: Ecosystem::Go,
        command: format!("go {}", parts[cmd_idx..].join(" ")),
    })
}

fn parse_gem_install(target: &str) -> Option<PackageInstall> {
    let parts: Vec<&str> = target.split_whitespace().collect();

    let cmd_idx = parts.iter().position(|p| *p == "install")?;

    let pkg_str = parts
        .iter()
        .skip(cmd_idx + 1)
        .find(|p| !p.starts_with('-'))?;

    let mut version = None;
    if let Some(vi) = parts.iter().position(|p| *p == "-v" || *p == "--version") {
        version = parts.get(vi + 1).map(|v| v.to_string());
    }

    Some(PackageInstall {
        name: pkg_str.to_string(),
        version,
        ecosystem: Ecosystem::RubyGems,
        command: format!("gem {}", parts[cmd_idx..].join(" ")),
    })
}

/// Parse "name@version" → (name, Some(version)) or (name, None).
fn parse_name_at_version(s: &str) -> (String, Option<String>) {
    // Handle scoped npm packages: @scope/name@version
    if s.starts_with('@') {
        // @scope/name@version — the second '@' is the version separator
        if let Some(idx) = s[1..].find('@') {
            let (name, ver) = s.split_at(idx + 1);
            return (name.to_string(), Some(ver[1..].to_string()));
        }
        return (s.to_string(), None);
    }
    if let Some(idx) = s.find('@') {
        let (name, ver) = s.split_at(idx);
        (name.to_string(), Some(ver[1..].to_string()))
    } else {
        (s.to_string(), None)
    }
}

// ── OSV API types ───────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize)]
struct OsvQuery {
    package: OsvPackage,
    #[serde(skip_serializing_if = "Option::is_none")]
    version: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
struct OsvPackage {
    name: String,
    ecosystem: String,
}

#[derive(Debug, Clone, Deserialize)]
struct OsvResponse {
    #[serde(default)]
    vulns: Vec<OsvVulnerability>,
}

/// Subset of the OSV vulnerability schema we care about.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OsvVulnerability {
    pub id: String,
    #[serde(default)]
    pub summary: Option<String>,
    /// Detailed description of the vulnerability mechanism (how it's exploited).
    #[serde(default)]
    pub details: Option<String>,
    #[serde(default)]
    pub severity: Vec<OsvSeverity>,
    #[serde(default)]
    pub aliases: Vec<String>,
    #[serde(default)]
    pub references: Vec<OsvReference>,
    /// Affected version ranges + fix versions from OSV.
    #[serde(default)]
    pub affected: Vec<OsvAffected>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OsvSeverity {
    #[serde(rename = "type")]
    pub severity_type: String,
    pub score: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OsvReference {
    #[serde(rename = "type")]
    pub ref_type: String,
    pub url: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OsvAffected {
    #[serde(default)]
    pub ranges: Vec<OsvRange>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OsvRange {
    #[serde(rename = "type")]
    pub range_type: String,
    #[serde(default)]
    pub events: Vec<OsvRangeEvent>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OsvRangeEvent {
    #[serde(default)]
    pub introduced: Option<String>,
    #[serde(default)]
    pub fixed: Option<String>,
}

impl OsvVulnerability {
    /// Extract the highest CVSS score from severity entries.
    pub fn max_cvss(&self) -> Option<f32> {
        self.severity
            .iter()
            .filter(|s| s.severity_type == "CVSS_V3" || s.severity_type == "CVSS_V4")
            .filter_map(|s| {
                // Score can be a vector string like "CVSS:3.1/AV:N/AC:L/..." or a float
                s.score.parse::<f32>().ok().or_else(|| {
                    // Try to extract the base score from a CVSS vector
                    None // Let the caller handle missing scores
                })
            })
            .reduce(f32::max)
    }

    /// Get the first CVE alias if available.
    pub fn cve(&self) -> Option<&str> {
        self.aliases
            .iter()
            .find(|a| a.starts_with("CVE-"))
            .map(|s| s.as_str())
    }

    /// Get the first fix version (the version that patches this vuln).
    pub fn fix_version(&self) -> Option<&str> {
        self.affected
            .iter()
            .flat_map(|a| &a.ranges)
            .flat_map(|r| &r.events)
            .find_map(|e| e.fixed.as_deref())
    }

    /// Short exploit mechanism description for SLM context.
    /// Prefers `summary` (one-liner), falls back to first 200 chars of `details`.
    pub fn exploit_description(&self) -> Option<String> {
        if let Some(ref s) = self.summary {
            return Some(s.clone());
        }
        self.details.as_ref().map(|d| {
            if d.len() <= 200 {
                d.clone()
            } else {
                format!("{}...", &d[..200])
            }
        })
    }
}

// ── OSV query result ────────────────────────────────────────────────────────

/// Result of an OSV vulnerability check.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VulnCheckResult {
    pub package: PackageInstall,
    pub vulns: Vec<OsvVulnerability>,
    pub checked_at: DateTime<Utc>,
}

impl VulnCheckResult {
    pub fn is_vulnerable(&self) -> bool {
        !self.vulns.is_empty()
    }

    pub fn vuln_count(&self) -> usize {
        self.vulns.len()
    }

    pub fn highest_severity(&self) -> Option<f32> {
        self.vulns
            .iter()
            .filter_map(|v| v.max_cvss())
            .reduce(f32::max)
    }

    pub fn cve_ids(&self) -> Vec<&str> {
        self.vulns.iter().filter_map(|v| v.cve()).collect()
    }

    pub fn summary(&self) -> String {
        if self.vulns.is_empty() {
            return format!(
                "{}@{}: clean",
                self.package.name,
                self.package.version.as_deref().unwrap_or("latest")
            );
        }
        let cves = self.cve_ids();
        let cve_str = if cves.is_empty() {
            self.vulns
                .iter()
                .map(|v| v.id.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        } else {
            cves.join(", ")
        };
        format!(
            "{}@{}: {} vuln(s) [{}]",
            self.package.name,
            self.package.version.as_deref().unwrap_or("latest"),
            self.vulns.len(),
            cve_str,
        )
    }

    /// Collect all known fix versions across vulns.
    pub fn fix_versions(&self) -> Vec<&str> {
        self.vulns.iter().filter_map(|v| v.fix_version()).collect()
    }

    /// Build a rich exploit context string for SLM RAG.
    /// This gives the SLM the "how it's exploited" + "what to watch for" info
    /// so it can correlate runtime kernel events to known exploit patterns.
    pub fn exploit_context(&self) -> String {
        let mut ctx = String::new();
        for vuln in &self.vulns {
            let id = vuln.cve().unwrap_or(&vuln.id);
            ctx.push_str(&format!("  {}", id));
            if let Some(cvss) = vuln.max_cvss() {
                ctx.push_str(&format!(" (CVSS:{:.1})", cvss));
            }
            if let Some(fix) = vuln.fix_version() {
                ctx.push_str(&format!(" fix={}", fix));
            }
            if let Some(desc) = vuln.exploit_description() {
                ctx.push_str(&format!(": {}", desc));
            }
            ctx.push('\n');
        }
        ctx
    }
}

// ── OSV API client ──────────────────────────────────────────────────────────

const OSV_API_URL: &str = "https://api.osv.dev/v1/query";
const OSV_TIMEOUT_SECS: u64 = 10;

/// Query the OSV.dev API for known vulnerabilities affecting a package.
pub async fn check_package(install: &PackageInstall) -> Option<VulnCheckResult> {
    let query = OsvQuery {
        package: OsvPackage {
            name: install.name.clone(),
            ecosystem: install.ecosystem.osv_name().to_string(),
        },
        version: install.version.clone(),
    };

    let resp = match reqwest::Client::new()
        .post(OSV_API_URL)
        .json(&query)
        .timeout(std::time::Duration::from_secs(OSV_TIMEOUT_SECS))
        .send()
        .await
    {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!(
                package = %install.name,
                err = %e,
                "OSV: query failed"
            );
            return None;
        }
    };

    if !resp.status().is_success() {
        tracing::warn!(
            package = %install.name,
            status = %resp.status(),
            "OSV: non-success response"
        );
        return None;
    }

    let osv: OsvResponse = match resp.json().await {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!(
                package = %install.name,
                err = %e,
                "OSV: failed to parse response"
            );
            return None;
        }
    };

    let result = VulnCheckResult {
        package: install.clone(),
        vulns: osv.vulns,
        checked_at: Utc::now(),
    };

    if result.is_vulnerable() {
        tracing::warn!(
            package = %install.name,
            version = ?install.version,
            ecosystem = %install.ecosystem.osv_name(),
            vuln_count = result.vuln_count(),
            cves = ?result.cve_ids(),
            "OSV: VULNERABLE PACKAGE DETECTED"
        );
    } else {
        tracing::debug!(
            package = %install.name,
            ecosystem = %install.ecosystem.osv_name(),
            "OSV: package clean"
        );
    }

    Some(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_npm_install_basic() {
        let result = parse_install_command("npm", "npm install express");
        assert!(result.is_some());
        let pkg = result.unwrap();
        assert_eq!(pkg.name, "express");
        assert_eq!(pkg.ecosystem, Ecosystem::Npm);
        assert!(pkg.version.is_none());
    }

    #[test]
    fn parse_npm_install_with_version() {
        let result = parse_install_command("npm", "npm install lodash@4.17.20");
        assert!(result.is_some());
        let pkg = result.unwrap();
        assert_eq!(pkg.name, "lodash");
        assert_eq!(pkg.version.as_deref(), Some("4.17.20"));
    }

    #[test]
    fn parse_npm_scoped_package() {
        let result = parse_install_command("npm", "npm install @anthropic-ai/sdk@1.0.0");
        assert!(result.is_some());
        let pkg = result.unwrap();
        assert_eq!(pkg.name, "@anthropic-ai/sdk");
        assert_eq!(pkg.version.as_deref(), Some("1.0.0"));
    }

    #[test]
    fn parse_npm_i_shorthand() {
        let result = parse_install_command("npm", "npm i react");
        assert!(result.is_some());
        let pkg = result.unwrap();
        assert_eq!(pkg.name, "react");
    }

    #[test]
    fn parse_yarn_add() {
        let result = parse_install_command("yarn", "yarn add axios@1.6.0");
        assert!(result.is_some());
        let pkg = result.unwrap();
        assert_eq!(pkg.name, "axios");
        assert_eq!(pkg.version.as_deref(), Some("1.6.0"));
        assert_eq!(pkg.ecosystem, Ecosystem::Npm);
    }

    #[test]
    fn parse_pip_install_basic() {
        let result = parse_install_command("pip", "pip install requests");
        assert!(result.is_some());
        let pkg = result.unwrap();
        assert_eq!(pkg.name, "requests");
        assert_eq!(pkg.ecosystem, Ecosystem::PyPI);
    }

    #[test]
    fn parse_pip_install_pinned() {
        let result = parse_install_command("pip", "pip install requests==2.28.0");
        assert!(result.is_some());
        let pkg = result.unwrap();
        assert_eq!(pkg.name, "requests");
        assert_eq!(pkg.version.as_deref(), Some("2.28.0"));
    }

    #[test]
    fn parse_pip_with_flags() {
        let result = parse_install_command("pip3", "pip3 install --user flask");
        assert!(result.is_some());
        let pkg = result.unwrap();
        assert_eq!(pkg.name, "flask");
    }

    #[test]
    fn parse_cargo_add() {
        let result = parse_install_command("cargo", "cargo add serde@1.0.200");
        assert!(result.is_some());
        let pkg = result.unwrap();
        assert_eq!(pkg.name, "serde");
        assert_eq!(pkg.version.as_deref(), Some("1.0.200"));
        assert_eq!(pkg.ecosystem, Ecosystem::CratesIo);
    }

    #[test]
    fn parse_cargo_install_with_version_flag() {
        let result = parse_install_command("cargo", "cargo install ripgrep --version 14.0.0");
        assert!(result.is_some());
        let pkg = result.unwrap();
        assert_eq!(pkg.name, "ripgrep");
        assert_eq!(pkg.version.as_deref(), Some("14.0.0"));
    }

    #[test]
    fn parse_go_get() {
        let result = parse_install_command("go", "go get github.com/gin-gonic/gin@v1.9.1");
        assert!(result.is_some());
        let pkg = result.unwrap();
        assert_eq!(pkg.name, "github.com/gin-gonic/gin");
        assert_eq!(pkg.version.as_deref(), Some("v1.9.1"));
        assert_eq!(pkg.ecosystem, Ecosystem::Go);
    }

    #[test]
    fn parse_gem_install() {
        let result = parse_install_command("gem", "gem install rails -v 7.1.0");
        assert!(result.is_some());
        let pkg = result.unwrap();
        assert_eq!(pkg.name, "rails");
        assert_eq!(pkg.version.as_deref(), Some("7.1.0"));
        assert_eq!(pkg.ecosystem, Ecosystem::RubyGems);
    }

    #[test]
    fn non_install_command_returns_none() {
        assert!(parse_install_command("git", "git push origin main").is_none());
        assert!(parse_install_command("npm", "npm run build").is_none());
        assert!(parse_install_command("pip", "pip list").is_none());
        assert!(parse_install_command("cargo", "cargo build").is_none());
    }

    #[test]
    fn bare_npm_install_returns_none() {
        // `npm install` with no package arg installs from package.json — not a specific pkg
        assert!(parse_install_command("npm", "npm install").is_none());
    }

    #[test]
    fn npm_install_with_save_dev_flag() {
        let result = parse_install_command("npm", "npm install --save-dev typescript@5.3.0");
        assert!(result.is_some());
        let pkg = result.unwrap();
        assert_eq!(pkg.name, "typescript");
        assert_eq!(pkg.version.as_deref(), Some("5.3.0"));
    }

    #[test]
    fn vuln_check_result_summary() {
        let result = VulnCheckResult {
            package: PackageInstall {
                name: "lodash".to_string(),
                version: Some("4.17.20".to_string()),
                ecosystem: Ecosystem::Npm,
                command: "npm install lodash@4.17.20".to_string(),
            },
            vulns: vec![OsvVulnerability {
                id: "GHSA-xxxx-yyyy".to_string(),
                summary: Some("Prototype pollution".to_string()),
                details: None,
                severity: vec![],
                aliases: vec!["CVE-2021-23337".to_string()],
                references: vec![],
                affected: vec![],
            }],
            checked_at: Utc::now(),
        };
        assert!(result.is_vulnerable());
        assert_eq!(result.vuln_count(), 1);
        assert_eq!(result.cve_ids(), vec!["CVE-2021-23337"]);
        assert!(result.summary().contains("1 vuln"));
        assert!(result.summary().contains("CVE-2021-23337"));
    }
}
