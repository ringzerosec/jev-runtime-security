// SPDX-License-Identifier: Apache-2.0
// policy/acl.rs — per-skill ACL engine

use crate::common::event::{EventKind, SecurityEvent};
use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, path::Path};

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SkillPolicy {
    pub skill: String,
    pub author: Option<String>,
    pub files: FileRules,
    pub network: NetworkRules,
    pub process: ProcessRules,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct FileRules {
    pub read: Vec<String>,
    pub write: Vec<String>,
    pub deny: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct NetworkRules {
    pub allow: Vec<String>,
    pub deny: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ProcessRules {
    pub spawn: Vec<String>,
    pub deny: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    Allow,
    Block { reason: String },
}

pub struct AclEngine {
    /// skill_name → policy
    policies: HashMap<String, SkillPolicy>,
    /// Default-deny for unknown skills
    default_deny: bool,
}

impl AclEngine {
    pub fn new(default_deny: bool) -> Self {
        Self {
            policies: HashMap::new(),
            default_deny,
        }
    }

    #[allow(dead_code)]
    pub fn load_dir(&mut self, dir: &Path) -> Result<()> {
        for entry in walkdir::WalkDir::new(dir)
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|e| {
                e.file_type().is_file() && e.path().extension().map_or(false, |x| x == "toml")
            })
        {
            let content = std::fs::read_to_string(entry.path())?;
            match toml::from_str::<SkillPolicy>(&content) {
                Ok(p) => {
                    self.policies.insert(p.skill.clone(), p);
                }
                Err(e) => {
                    tracing::warn!(path = ?entry.path(), err = %e, "Skipping policy (parse error)")
                }
            }
        }
        tracing::info!(count = self.policies.len(), "ACL policies loaded");

        // Fail-safe: if default_deny is on but no valid policies loaded,
        // switch to observe-only to avoid blocking everything silently.
        if self.default_deny && self.policies.is_empty() {
            tracing::warn!(
                "No valid ACL policies loaded while in default-deny mode — \
                 falling back to observe-only (default_deny=false) to prevent \
                 blocking all agent activity"
            );
            self.default_deny = false;
        }

        Ok(())
    }

    #[allow(dead_code)]
    pub fn add_policy(&mut self, policy: SkillPolicy) {
        self.policies.insert(policy.skill.clone(), policy);
    }

    /// Return the current enforce (default-deny) mode.
    pub fn default_deny(&self) -> bool {
        self.default_deny
    }

    /// Toggle enforce (default-deny) mode.
    pub fn set_default_deny(&mut self, deny: bool) {
        self.default_deny = deny;
    }

    /// Add a filename to the file deny list for all skills.
    pub fn block_file(&mut self, name: &str) {
        for policy in self.policies.values_mut() {
            if !policy.files.deny.contains(&name.to_string()) {
                policy.files.deny.push(name.to_string());
            }
        }
    }

    /// Remove a filename from the file deny list for all skills.
    pub fn unblock_file(&mut self, name: &str) {
        for policy in self.policies.values_mut() {
            policy.files.deny.retain(|f| f != name);
        }
    }

    /// Remove a domain from the network deny list for all skills.
    pub fn unblock_domain(&mut self, domain: &str) {
        for policy in self.policies.values_mut() {
            policy.network.deny.retain(|d| d != domain);
        }
    }

    /// Add a process to the process deny list for all skills.
    pub fn block_process(&mut self, name: &str) {
        for policy in self.policies.values_mut() {
            if !policy.process.deny.contains(&name.to_string()) {
                policy.process.deny.push(name.to_string());
            }
        }
    }

    /// Remove a process from the process deny list for all skills.
    pub fn unblock_process(&mut self, name: &str) {
        for policy in self.policies.values_mut() {
            policy.process.deny.retain(|p| p != name);
        }
    }

    /// Return all loaded skill policies.
    pub fn policies(&self) -> &HashMap<String, SkillPolicy> {
        &self.policies
    }

    /// Add a domain to the network deny list for all skills.
    pub fn block_domain(&mut self, domain: &str) {
        for policy in self.policies.values_mut() {
            if !policy.network.deny.contains(&domain.to_string()) {
                policy.network.deny.push(domain.to_string());
            }
        }
    }

    pub fn evaluate(&self, event: &SecurityEvent) -> Decision {
        let policy = match self.policies.get(&event.process) {
            Some(p) => p,
            // Unknown skill: ALLOW + observe — never default-deny an unknown exec.
            // Blanket-blocking unknown commands is the FP storm (a coding agent
            // runs hundreds of benign commands like git/npm/find/locale). The
            // exec is captured for async SLM judgment (→ cached allow-policy or
            // block+alert), and the HARD FLOOR (credential/persistence/exfil/
            // priv-esc) is enforced independently at L0 regardless of this allow.
            None => return Decision::Allow,
        };

        match &event.kind {
            EventKind::FileOpen
            | EventKind::FileCreate
            | EventKind::FileWrite
            | EventKind::FileDelete
            | EventKind::FileRename => self.evaluate_file(policy, event),
            EventKind::NetworkConnect
            | EventKind::NetworkSend
            | EventKind::NetworkRecv
            | EventKind::DnsQuery => self.evaluate_network(policy, event),
            EventKind::ProcessExec | EventKind::ProcessFork => self.evaluate_process(policy, event),
            _ => Decision::Allow,
        }
    }

    fn evaluate_file(&self, policy: &SkillPolicy, event: &SecurityEvent) -> Decision {
        let target = &event.target;

        // Explicit deny takes priority
        if glob_match_any(&policy.files.deny, target) {
            return Decision::Block {
                reason: format!(
                    "[ACL-101] File '{}' is in deny list for skill '{}'",
                    target, policy.skill
                ),
            };
        }

        // For writes, check write allow-list
        if matches!(
            event.kind,
            EventKind::FileWrite
                | EventKind::FileCreate
                | EventKind::FileDelete
                | EventKind::FileRename
        ) {
            if !policy.files.write.is_empty() && !glob_match_any(&policy.files.write, target) {
                return Decision::Block {
                    reason: format!(
                        "[ACL-102] File write to '{}' not in write allowlist for skill '{}'",
                        target, policy.skill
                    ),
                };
            }
        }

        Decision::Allow
    }

    fn evaluate_network(&self, policy: &SkillPolicy, event: &SecurityEvent) -> Decision {
        let target = &event.target;

        if glob_match_any(&policy.network.deny, target) {
            return Decision::Block {
                reason: format!(
                    "[ACL-201] Network target '{}' is denied for skill '{}'",
                    target, policy.skill
                ),
            };
        }

        // If explicit allow list exists, target must match
        if !policy.network.allow.is_empty() && !glob_match_any(&policy.network.allow, target) {
            return Decision::Block {
                reason: format!(
                    "[ACL-202] Network target '{}' not in allowlist for skill '{}'",
                    target, policy.skill
                ),
            };
        }

        Decision::Allow
    }

    fn evaluate_process(&self, policy: &SkillPolicy, event: &SecurityEvent) -> Decision {
        let target = &event.target;

        if glob_match_any(&policy.process.deny, target) {
            return Decision::Block {
                reason: format!(
                    "[ACL-301] Process '{}' is denied for skill '{}'",
                    target, policy.skill
                ),
            };
        }

        if !policy.process.spawn.is_empty() && !glob_match_any(&policy.process.spawn, target) {
            return Decision::Block {
                reason: format!(
                    "[ACL-302] Process spawn '{}' not in allowlist for skill '{}'",
                    target, policy.skill
                ),
            };
        }

        Decision::Allow
    }
}

/// Simple glob matching: `*` matches any sequence within a path segment,
/// `**` matches any number of segments.
fn glob_match(pattern: &str, path: &str) -> bool {
    // Expand ~ to home dir for comparison
    let expanded_path;
    let path = if path.starts_with('~') {
        if let Ok(home) = std::env::var("HOME") {
            expanded_path = format!("{}{}", home, &path[1..]);
            &expanded_path
        } else {
            path
        }
    } else {
        path
    };

    let expanded_pat;
    let pattern = if pattern.starts_with('~') {
        if let Ok(home) = std::env::var("HOME") {
            expanded_pat = format!("{}{}", home, &pattern[1..]);
            &expanded_pat
        } else {
            pattern
        }
    } else {
        pattern
    };

    glob_match_inner(pattern, path)
}

fn glob_match_inner(pat: &str, s: &str) -> bool {
    let mut pat_chars = pat.chars().peekable();
    let mut s_chars = s.chars().peekable();

    while let Some(p) = pat_chars.next() {
        match p {
            '*' => {
                if pat_chars.peek() == Some(&'*') {
                    pat_chars.next();
                    // ** matches everything
                    let rest: String = pat_chars.collect();
                    if rest.is_empty() {
                        return true;
                    }
                    let s_rem: String = s_chars.collect();
                    for i in 0..=s_rem.len() {
                        if glob_match_inner(&rest, &s_rem[i..]) {
                            return true;
                        }
                    }
                    return false;
                } else {
                    // * matches until '/'
                    let rest: String = pat_chars.collect();
                    let s_rem: String = s_chars.collect();
                    for (i, c) in s_rem.char_indices() {
                        if c == '/' {
                            break;
                        }
                        if glob_match_inner(&rest, &s_rem[i..]) {
                            return true;
                        }
                    }
                    return glob_match_inner(&rest, "");
                }
            }
            '?' => {
                s_chars.next();
            }
            c => {
                if s_chars.next() != Some(c) {
                    return false;
                }
            }
        }
    }
    s_chars.next().is_none()
}

fn glob_match_any(patterns: &[String], path: &str) -> bool {
    patterns.iter().any(|p| glob_match(p, path))
}
