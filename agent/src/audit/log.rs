// SPDX-License-Identifier: Apache-2.0
// audit/log.rs — Append-only, hash-chained audit log backed by sled

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

// ── Entry types ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditEntryType {
    SecurityEvent,
    ThreatDetected,
    PolicyChange,
    ConfigChange,
    DaemonStart,
    DaemonStop,
    AccessGranted,
    AccessDenied,
    EscalationRequested,
    EscalationResolved,
}

impl AuditEntryType {
    fn as_str(&self) -> &'static str {
        match self {
            AuditEntryType::SecurityEvent => "security_event",
            AuditEntryType::ThreatDetected => "threat_detected",
            AuditEntryType::PolicyChange => "policy_change",
            AuditEntryType::ConfigChange => "config_change",
            AuditEntryType::DaemonStart => "daemon_start",
            AuditEntryType::DaemonStop => "daemon_stop",
            AuditEntryType::AccessGranted => "access_granted",
            AuditEntryType::AccessDenied => "access_denied",
            AuditEntryType::EscalationRequested => "escalation_requested",
            AuditEntryType::EscalationResolved => "escalation_resolved",
        }
    }
}

// ── AuditEntry ────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    /// Monotonic sequence number (starts at 0).
    pub seq: u64,
    pub timestamp: DateTime<Utc>,
    pub entry_type: AuditEntryType,
    /// Event / threat / config data as free-form JSON.
    pub payload: serde_json::Value,
    /// SHA-256 (hex) of the previous entry; empty string for seq == 0.
    pub prev_hash: String,
    /// SHA-256 (hex) of this entry's canonical fields.
    pub hash: String,
}

// ── Hash computation ──────────────────────────────────────────────────────────

fn compute_hash(
    seq: u64,
    timestamp: &str,
    entry_type: &str,
    payload: &str,
    prev_hash: &str,
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(seq.to_string());
    hasher.update("|");
    hasher.update(timestamp);
    hasher.update("|");
    hasher.update(entry_type);
    hasher.update("|");
    hasher.update(payload);
    hasher.update("|");
    hasher.update(prev_hash);
    format!("{:x}", hasher.finalize())
}

// ── AuditLog ──────────────────────────────────────────────────────────────────

pub struct AuditLog {
    db: Arc<sled::Db>,
    /// Next sequence number to assign.
    seq: AtomicU64,
    /// Hash of the most-recently committed entry (or empty string if empty).
    last_hash: Mutex<String>,
}

impl AuditLog {
    /// Open (or create) a persistent audit log at `path`.
    pub fn open(path: &std::path::Path) -> Result<Self> {
        let db = sled::open(path)
            .with_context(|| format!("Failed to open audit log at {}", path.display()))?;

        let (seq, last_hash) = Self::recover_state(&db)?;

        Ok(Self {
            db: Arc::new(db),
            seq: AtomicU64::new(seq),
            last_hash: Mutex::new(last_hash),
        })
    }

    /// Open a temporary in-memory-style audit log (new temp dir each run).
    pub fn open_temp() -> Result<Self> {
        let tmp_dir = std::env::temp_dir().join(format!(
            "ringzero-audit-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        ));
        Self::open(&tmp_dir)
    }

    /// Scan existing entries to find the highest seq + its hash.
    fn recover_state(db: &sled::Db) -> Result<(u64, String)> {
        match db.last()? {
            None => Ok((0, String::new())),
            Some((_, raw)) => {
                let entry: AuditEntry = serde_json::from_slice(&raw)
                    .context("Failed to deserialize last audit entry during recovery")?;
                Ok((entry.seq + 1, entry.hash))
            }
        }
    }

    /// Append an entry, logging (but not propagating) write failures.
    ///
    /// Use this from event-loop hot paths where the previous code did
    /// `let _ = audit.append(...)`. The audit log is a tamper-evident chain,
    /// so a write failure is a real operational problem — never silently
    /// swallow it.
    pub fn try_append(&self, entry_type: AuditEntryType, payload: serde_json::Value) {
        let type_label = entry_type.as_str();
        if let Err(e) = self.append(entry_type, payload) {
            tracing::error!(
                err   = %e,
                kind  = type_label,
                "Audit log append failed — chain may have a gap (disk full? read-only?)"
            );
        }
    }

    /// Append an entry. Returns the completed entry (with hash filled in).
    pub fn append(
        &self,
        entry_type: AuditEntryType,
        payload: serde_json::Value,
    ) -> Result<AuditEntry> {
        // 1. Claim a sequence number.
        let seq = self.seq.fetch_add(1, Ordering::SeqCst);

        // 2. Capture timestamp.
        let timestamp = Utc::now();
        let ts_str = timestamp.to_rfc3339();

        // 3. Snapshot prev_hash under the lock.
        let prev_hash = {
            self.last_hash
                .lock()
                .map_err(|_| anyhow::anyhow!("audit last_hash mutex poisoned"))?
                .clone()
        };

        // 4. Serialize payload deterministically.
        let payload_str = payload.to_string();

        // 5. Compute hash.
        let hash = compute_hash(seq, &ts_str, entry_type.as_str(), &payload_str, &prev_hash);

        // 6. Build entry.
        let entry = AuditEntry {
            seq,
            timestamp,
            entry_type,
            payload,
            prev_hash,
            hash: hash.clone(),
        };

        // 7. Persist to sled with big-endian seq as key (sorts correctly).
        let key = seq.to_be_bytes();
        let value = serde_json::to_vec(&entry).context("Failed to serialize audit entry")?;
        self.db
            .insert(key, value)
            .context("Failed to write audit entry to sled")?;

        // 8. Update last_hash under the lock.
        {
            let mut lh = self
                .last_hash
                .lock()
                .map_err(|_| anyhow::anyhow!("audit last_hash mutex poisoned"))?;
            *lh = hash;
        }

        Ok(entry)
    }

    /// Verify the entire chain. Returns `(valid, first_invalid_seq)`.
    /// Iterates every stored entry in order and checks:
    ///   1. The entry's own hash matches its declared content.
    ///   2. The entry's `prev_hash` matches the previous entry's `hash`.
    pub fn verify_chain(&self) -> (bool, Option<u64>) {
        let mut prev_hash = String::new();

        for result in self.db.iter() {
            let (_, raw) = match result {
                Ok(pair) => pair,
                Err(_) => return (false, None),
            };

            let entry: AuditEntry = match serde_json::from_slice(&raw) {
                Ok(e) => e,
                Err(_) => return (false, None),
            };

            // Check linkage.
            if entry.prev_hash != prev_hash {
                return (false, Some(entry.seq));
            }

            // Recompute hash and verify.
            let ts_str = entry.timestamp.to_rfc3339();
            let payload_str = entry.payload.to_string();
            let expected = compute_hash(
                entry.seq,
                &ts_str,
                entry.entry_type.as_str(),
                &payload_str,
                &entry.prev_hash,
            );
            if expected != entry.hash {
                return (false, Some(entry.seq));
            }

            prev_hash = entry.hash.clone();
        }

        (true, None)
    }

    /// Return the last `limit` entries (most-recent first).
    pub fn recent(&self, limit: usize) -> Vec<AuditEntry> {
        self.db
            .iter()
            .rev()
            .take(limit)
            .filter_map(|r| r.ok())
            .filter_map(|(_, raw)| serde_json::from_slice(&raw).ok())
            .collect()
    }

    /// Return a single entry by sequence number, or `None` if not found.
    #[allow(dead_code)]
    pub fn get(&self, seq: u64) -> Option<AuditEntry> {
        let key = seq.to_be_bytes();
        self.db
            .get(key)
            .ok()
            .flatten()
            .and_then(|raw| serde_json::from_slice(&raw).ok())
    }
}
