// SPDX-License-Identifier: Apache-2.0
//
// baseline.rs — accepted-findings snapshot, so a scan can report what is NEW.
//
// A scan of a real machine finds a lot that is expected: an agent's own config
// mentions credentials because it holds one, its documentation discusses the
// techniques it defends against. Reporting all of it on every scan trains
// people to ignore the scanner. So an operator accepts the current state once,
// and afterwards a scan shows what changed.
//
// This is a convenience for noise, NOT a fix for bad classification. If a scan
// is noisy because findings are mis-scored or prose is read as instructions,
// fix that; do not paper over it with a baseline.
//
// Root-only to write, consistent with the rest of the authority model: the
// agent runs as the operator and must not be able to accept away its own
// findings.

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

/// Where the snapshot lives. Root-owned, 0600.
pub fn baseline_path() -> PathBuf {
    if crate::platform::is_elevated() {
        PathBuf::from("/var/lib/ringzero/scan-baseline.json")
    } else {
        std::env::temp_dir().join("ringzero-scan-baseline.json")
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Baseline {
    /// Who ran `rz scan baseline accept`, and when. An accepted baseline is an
    /// operator decision, so it carries a name and a timestamp.
    pub accepted_by: String,
    pub accepted_at: Option<DateTime<Utc>>,
    /// Surface path -> the set of finding hashes accepted for it.
    pub surfaces: BTreeMap<String, BTreeSet<String>>,
}

impl Baseline {
    pub fn load() -> Baseline {
        let p = baseline_path();
        match std::fs::read_to_string(&p) {
            Ok(s) => serde_json::from_str(&s).unwrap_or_else(|e| {
                tracing::warn!(path = %p.display(), err = %e,
                    "scan baseline is unreadable — treating every finding as new");
                Baseline::default()
            }),
            Err(_) => Baseline::default(),
        }
    }

    pub fn save(&self) -> Result<()> {
        let p = baseline_path();
        if let Some(parent) = p.parent() {
            std::fs::create_dir_all(parent).ok();
        }
        let json = serde_json::to_string_pretty(self)?;
        // 0600 and O_NOFOLLOW: a pre-placed symlink must not redirect a
        // root-owned write.
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .custom_flags(libc::O_NOFOLLOW)
            .mode(0o600)
            .open(&p)
            .with_context(|| format!("writing {}", p.display()))?;
        f.write_all(json.as_bytes())?;
        Ok(())
    }

    /// Has this finding already been accepted for this surface?
    pub fn contains(&self, surface: &str, finding_hash: &str) -> bool {
        self.surfaces
            .get(surface)
            .is_some_and(|set| set.contains(finding_hash))
    }

    pub fn total_accepted(&self) -> usize {
        self.surfaces.values().map(|s| s.len()).sum()
    }
}

/// A stable identity for a finding: what it is and where, never the line number
/// — a finding that only moved down the file is not a new finding.
pub fn finding_hash(rule_id: &str, file: &str, matched: Option<&str>) -> String {
    let mut h = blake3::Hasher::new();
    h.update(rule_id.as_bytes());
    h.update(b"\0");
    h.update(file.as_bytes());
    h.update(b"\0");
    h.update(matched.unwrap_or("").as_bytes());
    h.finalize().to_hex().to_string()[..32].to_string()
}

/// Hash for a supply-chain finding, which has a kind and a detail rather than a
/// rule id. The detail carries a masked secret, so it is part of the identity:
/// a different key in the same file is a new finding.
pub fn supply_finding_hash(kind: &str, file: &str, detail: &str) -> String {
    finding_hash(kind, file, Some(detail))
}

/// Snapshot every finding in a scan result as accepted.
pub fn accept(result: &super::skill_surface::SkillScanAutoResult, accepted_by: &str) -> Baseline {
    let mut b = Baseline {
        accepted_by: accepted_by.to_string(),
        accepted_at: Some(Utc::now()),
        surfaces: BTreeMap::new(),
    };
    for root in &result.results {
        let set = b.surfaces.entry(root.path.clone()).or_default();
        for f in &root.pattern_findings {
            set.insert(finding_hash(&f.rule_id, &f.file, f.matched_text.as_deref()));
        }
        for r in &root.supply_findings {
            for f in &r.findings {
                set.insert(supply_finding_hash(
                    &format!("{:?}", f.kind),
                    &f.file,
                    &f.detail,
                ));
            }
        }
        for rep in &root.injection_reports {
            for f in &rep.findings {
                set.insert(finding_hash(
                    "injection",
                    &rep.path,
                    Some(&f.signals.join(",")),
                ));
            }
        }
    }
    b
}

/// Remove the snapshot entirely.
pub fn clear() -> Result<()> {
    let p = baseline_path();
    if p.exists() {
        std::fs::remove_file(&p).with_context(|| format!("removing {}", p.display()))?;
    }
    Ok(())
}

/// Drop everything already accepted from a scan result, leaving only what is
/// new. Returns how many findings were suppressed so the report can say so.
pub fn filter_to_new(result: &mut super::skill_surface::SkillScanAutoResult) -> usize {
    let b = Baseline::load();
    if b.accepted_at.is_none() {
        return 0;
    }
    let mut suppressed = 0usize;

    for root in &mut result.results {
        let surface = root.path.clone();

        let before = root.pattern_findings.len();
        root.pattern_findings.retain(|f| {
            !b.contains(
                &surface,
                &finding_hash(&f.rule_id, &f.file, f.matched_text.as_deref()),
            )
        });
        suppressed += before - root.pattern_findings.len();

        for rep in &mut root.injection_reports {
            let before = rep.findings.len();
            let path = rep.path.clone();
            rep.findings.retain(|f| {
                !b.contains(
                    &surface,
                    &finding_hash("injection", &path, Some(&f.signals.join(","))),
                )
            });
            suppressed += before - rep.findings.len();
        }
        root.injection_reports.retain(|r| !r.findings.is_empty());

        for r in &mut root.supply_findings {
            let before = r.findings.len();
            r.findings.retain(|f| {
                !b.contains(
                    &surface,
                    &supply_finding_hash(&format!("{:?}", f.kind), &f.file, &f.detail),
                )
            });
            suppressed += before - r.findings.len();
        }
        root.supply_findings.retain(|r| !r.findings.is_empty());
    }
    suppressed
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finding_identity_ignores_position_but_not_content() {
        let a = finding_hash("RZ001", "/s/SKILL.md", Some("curl evil.com"));
        let b = finding_hash("RZ001", "/s/SKILL.md", Some("curl evil.com"));
        let c = finding_hash("RZ001", "/s/SKILL.md", Some("curl other.com"));
        let d = finding_hash("RZ002", "/s/SKILL.md", Some("curl evil.com"));
        assert_eq!(a, b, "same finding hashes the same");
        assert_ne!(a, c, "different matched text is a different finding");
        assert_ne!(a, d, "different rule is a different finding");
    }

    #[test]
    fn an_empty_baseline_accepts_nothing() {
        let b = Baseline::default();
        assert!(!b.contains("/s", "abc"));
        assert_eq!(b.total_accepted(), 0);
    }

    #[test]
    fn accepted_findings_are_recognised() {
        let mut b = Baseline {
            accepted_by: "root".into(),
            accepted_at: Some(Utc::now()),
            surfaces: BTreeMap::new(),
        };
        let h = finding_hash("RZ001", "/s/SKILL.md", None);
        b.surfaces
            .entry("/s".to_string())
            .or_default()
            .insert(h.clone());
        assert!(b.contains("/s", &h));
        assert!(
            !b.contains("/other", &h),
            "accepted per surface, not globally"
        );
        assert_eq!(b.total_accepted(), 1);
    }
}
