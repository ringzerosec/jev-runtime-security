// SPDX-License-Identifier: Apache-2.0
// scanner/verified_registry.rs — Ring Zero Verified registry for AI agent packages
//
// Tracks installed MCP servers, Claude Code extensions, Cursor plugins etc.
// Each entry has a verification status: Verified | Unverified | Malicious | Quarantined
//
// "Ring Zero Verified" = scanned clean by Ring Zero (entropy + secrets + injection heuristics)
// and optionally countersigned by the publisher.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Mutex;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use super::supply_chain::{RiskLevel, ScanReport};

// ── Types ──────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum VerificationStatus {
    /// Clean scan + Ring Zero countersign
    Verified,
    /// Scanned but not countersigned (unknown publisher)
    Unverified,
    /// Scan found malware / injection / secrets
    Malicious,
    /// Blocked by policy — user must explicitly allow
    Quarantined,
    /// Not yet scanned
    Pending,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PackageKind {
    McpServer,
    ClaudeCodeExtension,
    CursorPlugin,
    CopilotExtension,
    VsCodeExtension,
    NpmPackage,
    PipPackage,
    Other,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistryEntry {
    /// Stable ID = blake3 of (name + publisher)
    pub id: String,
    pub name: String,
    pub publisher: Option<String>,
    pub kind: PackageKind,
    pub version: Option<String>,
    pub install_path: String,
    pub blake3_hex: String,
    pub status: VerificationStatus,
    pub risk_level: RiskLevel,
    /// Most recent scan report summary
    pub last_scan: Option<ScanSummary>,
    pub detected_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    /// User explicitly allowed despite quarantine
    pub user_allowed: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanSummary {
    pub scanned_at: DateTime<Utc>,
    pub risk_level: RiskLevel,
    pub findings: usize,
    pub secrets_found: usize,
    pub injection: bool,
}

impl From<&ScanReport> for ScanSummary {
    fn from(r: &ScanReport) -> Self {
        use super::supply_chain::FindingKind;
        ScanSummary {
            scanned_at: r.scanned_at,
            risk_level: r.risk_level.clone(),
            findings: r.findings.len(),
            secrets_found: r
                .findings
                .iter()
                .filter(|f| matches!(f.kind, FindingKind::SecretDetected))
                .count(),
            injection: false, // set externally from model_armor result
        }
    }
}

// ── VerifiedRegistry ─────────────────────────────────────────────────────────

pub struct VerifiedRegistry {
    entries: Mutex<HashMap<String, RegistryEntry>>,
}

impl VerifiedRegistry {
    pub fn new() -> Self {
        VerifiedRegistry {
            entries: Mutex::new(HashMap::new()),
        }
    }

    /// Register or update an entry from a supply chain scan result.
    pub fn ingest_scan(
        &self,
        path: &PathBuf,
        report: &ScanReport,
        injection: bool,
    ) -> RegistryEntry {
        let mut guard = self.entries.lock().unwrap();

        let name = path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| path.to_string_lossy().into_owned());

        let id = blake3_id(&name, &report.blake3_hex);

        let kind = detect_kind(path);

        let mut summary = ScanSummary::from(report);
        summary.injection = injection;

        let status = derive_status(&report.risk_level, injection);

        let entry = RegistryEntry {
            id: id.clone(),
            name,
            publisher: None,
            kind,
            version: None,
            install_path: path.to_string_lossy().into_owned(),
            blake3_hex: report.blake3_hex.clone(),
            status,
            risk_level: report.risk_level.clone(),
            last_scan: Some(summary),
            detected_at: Utc::now(),
            updated_at: Utc::now(),
            user_allowed: false,
        };

        guard.insert(id, entry.clone());
        entry
    }

    pub fn list(&self) -> Vec<RegistryEntry> {
        self.entries.lock().unwrap().values().cloned().collect()
    }

    #[allow(dead_code)]
    pub fn get(&self, id: &str) -> Option<RegistryEntry> {
        self.entries.lock().unwrap().get(id).cloned()
    }

    pub fn allow(&self, id: &str) -> bool {
        let mut guard = self.entries.lock().unwrap();
        if let Some(e) = guard.get_mut(id) {
            e.user_allowed = true;
            e.status = VerificationStatus::Unverified;
            e.updated_at = Utc::now();
            return true;
        }
        false
    }

    pub fn quarantine(&self, id: &str) -> bool {
        let mut guard = self.entries.lock().unwrap();
        if let Some(e) = guard.get_mut(id) {
            e.status = VerificationStatus::Quarantined;
            e.user_allowed = false;
            e.updated_at = Utc::now();
            return true;
        }
        false
    }

    pub fn summary(&self) -> RegistrySummary {
        let guard = self.entries.lock().unwrap();
        let total = guard.len();
        let verified = guard
            .values()
            .filter(|e| e.status == VerificationStatus::Verified)
            .count();
        let malicious = guard
            .values()
            .filter(|e| e.status == VerificationStatus::Malicious)
            .count();
        let quarantine = guard
            .values()
            .filter(|e| e.status == VerificationStatus::Quarantined)
            .count();
        let pending = guard
            .values()
            .filter(|e| e.status == VerificationStatus::Pending)
            .count();
        RegistrySummary {
            total,
            verified,
            malicious,
            quarantine,
            pending,
        }
    }
}

#[derive(Debug, Serialize)]
pub struct RegistrySummary {
    pub total: usize,
    pub verified: usize,
    pub malicious: usize,
    pub quarantine: usize,
    pub pending: usize,
}

// ── helpers ───────────────────────────────────────────────────────────────────

fn blake3_id(name: &str, hash: &str) -> String {
    let combined = format!("{}-{}", name, hash);
    let h = blake3::hash(combined.as_bytes());
    h.to_hex().chars().take(16).collect()
}

fn detect_kind(path: &PathBuf) -> PackageKind {
    let s = path.to_string_lossy().to_lowercase();
    if s.contains("mcp") || s.contains(".mcp") {
        PackageKind::McpServer
    } else if s.contains("claude") || s.contains(".clauderc") {
        PackageKind::ClaudeCodeExtension
    } else if s.contains("cursor") {
        PackageKind::CursorPlugin
    } else if s.contains("copilot") {
        PackageKind::CopilotExtension
    } else if s.contains("node_modules") || s.ends_with(".js") || s.ends_with(".mjs") {
        PackageKind::NpmPackage
    } else if s.contains("site-packages") || s.ends_with(".py") {
        PackageKind::PipPackage
    } else if s.contains(".vscode") {
        PackageKind::VsCodeExtension
    } else {
        PackageKind::Other
    }
}

fn derive_status(risk: &RiskLevel, injection: bool) -> VerificationStatus {
    if injection || *risk == RiskLevel::Critical {
        VerificationStatus::Malicious
    } else if *risk == RiskLevel::High {
        VerificationStatus::Quarantined
    } else if *risk == RiskLevel::Clean || *risk == RiskLevel::Low {
        VerificationStatus::Verified
    } else {
        VerificationStatus::Unverified
    }
}
