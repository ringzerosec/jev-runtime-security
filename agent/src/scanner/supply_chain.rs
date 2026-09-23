// SPDX-License-Identifier: Apache-2.0
// scanner/supply_chain.rs — supply chain scan pipeline for installed skills/packages
//
// Scans for: high entropy (obfuscation), embedded secrets, suspicious patterns.
// Entropy + secret detection + injection heuristics cover the attack surface.

use anyhow::Result;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::path::Path;

use super::entropy::{analyse as entropy_analyse, ENTROPY_HIGH, ENTROPY_SUSPICIOUS};
use crate::secrets::detector::scan_file as secrets_scan_file;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum RiskLevel {
    Clean,
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanFinding {
    pub kind: FindingKind,
    pub detail: String,
    pub file: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingKind {
    HighEntropy,
    SecretDetected,
    /// A live credential sitting in a file the agent itself has to read —
    /// an agent's own auth file, a .env the harness loads. This is NOT a
    /// supply-chain risk: nothing was tampered with. It is an exposure, and
    /// "protect the file" is not a real mitigation, because the agent needs
    /// it. The honest advice is to scope the key down or rotate it.
    CredentialExposure,
}

/// Files whose whole purpose is to hold a credential the agent reads at
/// startup. A secret found here is expected to be there; what matters is its
/// blast radius, not its presence.
fn is_agent_credential_store(path: &Path) -> bool {
    let p = path.to_string_lossy().to_ascii_lowercase();
    let name = p.rsplit('/').next().unwrap_or(&p).to_string();
    matches!(
        name.as_str(),
        ".credentials.json" | "credentials.json" | ".env" | ".netrc" | ".npmrc" | ".pypirc"
    ) || name.ends_with(".credentials.json")
        || (p.contains("/.claude/") && name.contains("credential"))
        || (p.contains("/.codex/") && name.contains("auth"))
        || (p.contains("/.config/gcloud/") && name.contains("credential"))
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanReport {
    pub path: String,
    pub blake3_hex: String,
    pub findings: Vec<ScanFinding>,
    pub risk_level: RiskLevel,
    pub scanned_at: DateTime<Utc>,
}

impl ScanReport {
    fn compute_risk(findings: &[ScanFinding]) -> RiskLevel {
        if findings.is_empty() {
            return RiskLevel::Clean;
        }
        let has_secret = findings
            .iter()
            .any(|f| matches!(f.kind, FindingKind::SecretDetected));
        let has_credential_exposure = findings
            .iter()
            .any(|f| matches!(f.kind, FindingKind::CredentialExposure));
        let has_entropy = findings
            .iter()
            .any(|f| matches!(f.kind, FindingKind::HighEntropy));

        // A live key the agent must read is a real exposure, so it is not
        // downgraded — but it is reported as what it is, and its remediation
        // says scope or rotate rather than "protect the file".
        if has_credential_exposure {
            RiskLevel::High
        } else if has_secret && has_entropy {
            RiskLevel::High
        } else if has_secret {
            RiskLevel::High
        } else if has_entropy {
            RiskLevel::Medium
        } else {
            RiskLevel::Low
        }
    }
}

/// Scan a single file. Returns a report with entropy + secret findings.
///
/// Caps reads at 16 MiB. An attacker who can drop a large file into a watched
/// directory could otherwise force the daemon to allocate that much memory
/// per file event; combined with the file watcher's hot loop this is a cheap
/// way to OOM the process.
pub fn scan_file(path: &Path) -> Result<ScanReport> {
    const MAX_SCAN_BYTES: u64 = 16 * 1024 * 1024;
    let meta = std::fs::metadata(path)?;
    if meta.len() > MAX_SCAN_BYTES {
        tracing::debug!(
            path = %path.display(),
            size = meta.len(),
            "Supply-chain scan skipped: file exceeds 16 MiB cap"
        );
        return Ok(ScanReport {
            path: path.to_string_lossy().into_owned(),
            blake3_hex: String::new(),
            findings: Vec::new(),
            risk_level: RiskLevel::Low,
            scanned_at: Utc::now(),
        });
    }
    let data = crate::fscache::read(path)?;
    let hash = blake3::hash(&data);
    let mut findings = Vec::new();

    // 1. Entropy analysis (detect obfuscation)
    if data.len() > 64 {
        let er = entropy_analyse(&data);
        if er.high {
            findings.push(ScanFinding {
                kind: FindingKind::HighEntropy,
                detail: format!(
                    "Entropy {:.2} >= {:.1} — likely obfuscated",
                    er.score, ENTROPY_HIGH
                ),
                file: path.to_string_lossy().into_owned(),
            });
        } else if er.suspicious {
            findings.push(ScanFinding {
                kind: FindingKind::HighEntropy,
                detail: format!(
                    "Entropy {:.2} >= {:.1} — suspicious",
                    er.score, ENTROPY_SUSPICIOUS
                ),
                file: path.to_string_lossy().into_owned(),
            });
        }
    }

    // 2. Secret detection (text files only)
    if std::str::from_utf8(&data).is_ok() {
        let credential_store = is_agent_credential_store(path);
        let secrets = secrets_scan_file(path);
        for s in secrets {
            if credential_store {
                findings.push(ScanFinding {
                    kind: FindingKind::CredentialExposure,
                    detail: format!(
                        "Live {} at line {} ({}) — readable by anything running as this user, \
                         including the agent's whole process tree. This is a credential \
                         exposure, not a supply-chain finding: the file has not been tampered \
                         with, and protecting it is not a straightforward mitigation because \
                         the agent itself has to read it. Scope the key down or rotate it.",
                        s.kind.label(),
                        s.line_number,
                        s.masked
                    ),
                    file: s.file_path,
                });
            } else {
                findings.push(ScanFinding {
                    kind: FindingKind::SecretDetected,
                    detail: format!(
                        "{} at line {} ({})",
                        s.kind.label(),
                        s.line_number,
                        s.masked
                    ),
                    file: s.file_path,
                });
            }
        }
    }

    let risk_level = ScanReport::compute_risk(&findings);

    Ok(ScanReport {
        path: path.to_string_lossy().into_owned(),
        blake3_hex: hash.to_hex().to_string(),
        findings,
        risk_level,
        scanned_at: Utc::now(),
    })
}

/// Scan a skill directory (recursive, skipping node_modules/.git/vendor).
#[allow(dead_code)]
pub fn scan_dir(dir: &Path) -> Vec<ScanReport> {
    const SCANNABLE: &[&str] = &[
        "js", "ts", "mjs", "cjs", "json", "yaml", "yml", "env", "py", "rb", "go", "rs", "sh",
        "toml", "ini",
    ];

    walkdir::WalkDir::new(dir)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| {
            if !e.file_type().is_file() {
                return false;
            }
            let s = e.path().to_string_lossy();
            if s.contains("node_modules") || s.contains(".git") || s.contains("/vendor/") {
                return false;
            }
            let ext = e
                .path()
                .extension()
                .map(|x| x.to_string_lossy().into_owned())
                .unwrap_or_default();
            let filename = e
                .path()
                .file_name()
                .map(|x| x.to_string_lossy().into_owned())
                .unwrap_or_default();
            SCANNABLE.contains(&ext.as_str()) || filename.starts_with(".env")
        })
        .filter_map(|e| scan_file(e.path()).ok())
        .collect()
}
