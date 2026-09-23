#![allow(dead_code)]
// SPDX-License-Identifier: Apache-2.0
// secrets/rotation.rs — Secret rotation automation
//
// Tracks detected secrets, their age, rotation status, and provides a
// rotation workflow surface for the console and CLI.

use super::detector::{SecretFinding, SecretKind};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Mutex;

// ── Rotation status ───────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RotationStatus {
    /// Not yet acted on
    Pending,
    /// Rotation triggered — waiting for confirmation
    InProgress,
    /// Secret has been confirmed rotated by admin
    Rotated,
    /// Acknowledged — admin confirmed this is intentional / not a real secret
    Acknowledged,
    /// Revoked — secret is invalid (leaked credentials)
    Revoked,
}

// ── Severity ──────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum SecretSeverity {
    Critical, // Private keys, AWS root, Stripe live keys
    High,     // AWS access keys, GitHub tokens, OpenAI keys
    Medium,   // Slack tokens, API keys
    Low,      // Generic secrets, passwords
}

impl SecretSeverity {
    pub fn from_kind(kind: &SecretKind) -> Self {
        match kind {
            SecretKind::PrivateKey => SecretSeverity::Critical,
            SecretKind::AwsAccessKey
            | SecretKind::AwsSecretKey
            | SecretKind::GitHubToken
            | SecretKind::OpenAiKey
            | SecretKind::AnthropicKey
            | SecretKind::GcpServiceAccount => SecretSeverity::High,
            SecretKind::SlackToken => SecretSeverity::Medium,
            SecretKind::GenericApiKey | SecretKind::GenericSecret | SecretKind::Password => {
                SecretSeverity::Low
            }
        }
    }

    /// Age threshold in days after which this secret is considered overdue for rotation.
    pub fn max_age_days(&self) -> i64 {
        match self {
            SecretSeverity::Critical => 0, // Immediate — should never be in files
            SecretSeverity::High => 90,    // Rotate every 90 days
            SecretSeverity::Medium => 180,
            SecretSeverity::Low => 365,
        }
    }
}

// ── Tracked secret ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrackedSecret {
    /// Unique ID: blake3 hash of (kind + file_path + line_number + masked)
    pub id: String,
    pub kind: SecretKind,
    pub severity: SecretSeverity,
    pub file_path: String,
    pub line_number: usize,
    pub masked: String,
    pub status: RotationStatus,
    pub detected_at: DateTime<Utc>,
    pub last_seen_at: DateTime<Utc>,
    /// When the admin triggered rotation
    pub rotation_triggered_at: Option<DateTime<Utc>>,
    /// Who triggered rotation ("admin", "auto", "cli")
    pub rotation_by: Option<String>,
    /// When rotation was confirmed
    pub rotated_at: Option<DateTime<Utc>>,
    /// Notes / reviewer comment
    pub notes: Option<String>,
}

impl TrackedSecret {
    pub fn from_finding(finding: &SecretFinding) -> Self {
        let severity = SecretSeverity::from_kind(&finding.kind);
        let id = {
            let raw = format!(
                "{:?}:{}:{}:{}",
                finding.kind, finding.file_path, finding.line_number, finding.masked
            );
            let hash = blake3::hash(raw.as_bytes());
            format!("{:.8}", hash.to_hex())
        };
        let now = Utc::now();
        Self {
            id,
            kind: finding.kind.clone(),
            severity,
            file_path: finding.file_path.clone(),
            line_number: finding.line_number,
            masked: finding.masked.clone(),
            status: RotationStatus::Pending,
            detected_at: now,
            last_seen_at: now,
            rotation_triggered_at: None,
            rotation_by: None,
            rotated_at: None,
            notes: None,
        }
    }

    /// Days since detection.
    pub fn age_days(&self) -> i64 {
        (Utc::now() - self.detected_at).num_days()
    }

    /// Is this secret overdue for rotation?
    pub fn is_overdue(&self) -> bool {
        self.age_days() > self.severity.max_age_days()
            && matches!(
                self.status,
                RotationStatus::Pending | RotationStatus::InProgress
            )
    }

    /// Rotation guidance URL / instructions for each secret type.
    pub fn rotation_guide(&self) -> &'static str {
        match self.kind {
            SecretKind::AwsAccessKey | SecretKind::AwsSecretKey =>
                "Rotate via AWS Console → IAM → Users → Security credentials → Create access key",
            SecretKind::GitHubToken =>
                "Revoke via GitHub Settings → Developer settings → Personal access tokens",
            SecretKind::OpenAiKey =>
                "Rotate via platform.openai.com → API keys → Create new secret key",
            SecretKind::AnthropicKey =>
                "Rotate via console.anthropic.com → API Keys",
            SecretKind::GcpServiceAccount =>
                "Rotate via Google Cloud Console → IAM & Admin → Service Accounts → Keys",
            SecretKind::SlackToken =>
                "Rotate via api.slack.com → Your Apps → OAuth & Permissions → Regenerate",
            SecretKind::PrivateKey =>
                "Generate a new key pair: ssh-keygen -t ed25519 -C your@email.com, then remove the old key from all authorized_keys",
            _ => "Rotate the secret by invalidating the old value and generating a new one.",
        }
    }
}

// ── Rotation store ────────────────────────────────────────────────────────────

pub struct RotationStore {
    secrets: Mutex<HashMap<String, TrackedSecret>>,
}

impl RotationStore {
    pub fn new() -> Self {
        Self {
            secrets: Mutex::new(HashMap::new()),
        }
    }

    /// Ingest a batch of findings from a scan. New findings are added;
    /// existing ones get their `last_seen_at` refreshed.
    pub fn ingest(&self, findings: &[SecretFinding]) {
        let mut map = self.secrets.lock().unwrap();
        for f in findings {
            let ts = TrackedSecret::from_finding(f);
            map.entry(ts.id.clone())
                .and_modify(|e| e.last_seen_at = Utc::now())
                .or_insert(ts);
        }
    }

    /// List all tracked secrets, optionally filtered by status.
    pub fn list(&self, status_filter: Option<&RotationStatus>) -> Vec<TrackedSecret> {
        let map = self.secrets.lock().unwrap();
        let mut v: Vec<TrackedSecret> = map
            .values()
            .filter(|s| status_filter.map(|f| &s.status == f).unwrap_or(true))
            .cloned()
            .collect();
        // Sort: critical first, then by age descending
        v.sort_by(|a, b| {
            let sev_ord = |s: &SecretSeverity| match s {
                SecretSeverity::Critical => 0,
                SecretSeverity::High => 1,
                SecretSeverity::Medium => 2,
                SecretSeverity::Low => 3,
            };
            sev_ord(&a.severity)
                .cmp(&sev_ord(&b.severity))
                .then(b.detected_at.cmp(&a.detected_at))
        });
        v
    }

    /// Trigger rotation for a secret: moves it to InProgress.
    pub fn trigger_rotation(&self, id: &str, triggered_by: &str) -> bool {
        let mut map = self.secrets.lock().unwrap();
        if let Some(s) = map.get_mut(id) {
            if matches!(s.status, RotationStatus::Pending) {
                s.status = RotationStatus::InProgress;
                s.rotation_triggered_at = Some(Utc::now());
                s.rotation_by = Some(triggered_by.to_string());
                return true;
            }
        }
        false
    }

    /// Confirm a secret has been rotated.
    pub fn confirm_rotated(&self, id: &str, notes: Option<String>) -> bool {
        let mut map = self.secrets.lock().unwrap();
        if let Some(s) = map.get_mut(id) {
            if matches!(
                s.status,
                RotationStatus::InProgress | RotationStatus::Pending
            ) {
                s.status = RotationStatus::Rotated;
                s.rotated_at = Some(Utc::now());
                if notes.is_some() {
                    s.notes = notes;
                }
                return true;
            }
        }
        false
    }

    /// Acknowledge a finding as intentional / not a real secret.
    pub fn acknowledge(&self, id: &str, notes: Option<String>) -> bool {
        let mut map = self.secrets.lock().unwrap();
        if let Some(s) = map.get_mut(id) {
            s.status = RotationStatus::Acknowledged;
            if notes.is_some() {
                s.notes = notes;
            }
            return true;
        }
        false
    }

    /// Revoke a secret (mark as leaked — escalate to critical).
    pub fn revoke(&self, id: &str, notes: Option<String>) -> bool {
        let mut map = self.secrets.lock().unwrap();
        if let Some(s) = map.get_mut(id) {
            s.status = RotationStatus::Revoked;
            s.severity = SecretSeverity::Critical;
            if notes.is_some() {
                s.notes = notes;
            }
            return true;
        }
        false
    }

    /// Get a single tracked secret by ID.
    pub fn get(&self, id: &str) -> Option<TrackedSecret> {
        self.secrets.lock().unwrap().get(id).cloned()
    }

    /// Summary metrics.
    pub fn summary(&self) -> RotationSummary {
        let map = self.secrets.lock().unwrap();
        let mut summary = RotationSummary::default();
        summary.total = map.len();
        for s in map.values() {
            match s.status {
                RotationStatus::Pending => summary.pending += 1,
                RotationStatus::InProgress => summary.in_progress += 1,
                RotationStatus::Rotated => summary.rotated += 1,
                RotationStatus::Acknowledged => summary.acknowledged += 1,
                RotationStatus::Revoked => summary.revoked += 1,
            }
            if s.is_overdue() {
                summary.overdue += 1;
            }
            match s.severity {
                SecretSeverity::Critical => summary.critical += 1,
                SecretSeverity::High => summary.high += 1,
                SecretSeverity::Medium => summary.medium += 1,
                SecretSeverity::Low => summary.low += 1,
            }
        }
        summary
    }

    /// Return all secrets that are overdue for rotation.
    pub fn overdue(&self) -> Vec<TrackedSecret> {
        self.list(None)
            .into_iter()
            .filter(|s| s.is_overdue())
            .collect()
    }
}

impl Default for RotationStore {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct RotationSummary {
    pub total: usize,
    pub pending: usize,
    pub in_progress: usize,
    pub rotated: usize,
    pub acknowledged: usize,
    pub revoked: usize,
    pub overdue: usize,
    pub critical: usize,
    pub high: usize,
    pub medium: usize,
    pub low: usize,
}
