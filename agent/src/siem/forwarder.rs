// SPDX-License-Identifier: Apache-2.0
// siem/forwarder.rs — SIEM forwarding for Ring Zero Security
//
// Supports:
//   • Syslog / UDP  — RFC 5424 framing
//   • Splunk HEC    — HTTP Event Collector
//   • Elasticsearch — /_bulk API

use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::RwLock;

use crate::common::event::SecurityEvent;

// ── Config types ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SiemConfig {
    pub enabled: bool,
    pub targets: Vec<SiemTarget>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum SiemTarget {
    Syslog {
        host: String,
        port: u16,
        facility: u8,
    },
    SplunkHec {
        url: String,
        token: String,
        index: Option<String>,
    },
    Elasticsearch {
        url: String,
        index: String,
        api_key: Option<String>,
    },
    /// Microsoft Sentinel — Log Analytics Data Collector API
    Sentinel {
        workspace_id: String,
        shared_key: String,
        /// Custom log table name (without _CL suffix)
        log_type: String,
    },
}

impl Default for SiemConfig {
    fn default() -> Self {
        SiemConfig {
            enabled: false,
            targets: vec![],
        }
    }
}

// ── SiemForwarder ─────────────────────────────────────────────────────────────

pub struct SiemForwarder {
    config: Arc<RwLock<SiemConfig>>,
    client: reqwest::Client,
    /// Single drain channel for fire-and-forget threat forwards. Callers
    /// use `try_enqueue_threat()` instead of spawning a fresh tokio task
    /// per threat. A single background task consumes the channel and
    /// performs the HTTP sends serially per target (which still parallel
    /// across targets internally via `tokio::join!` if needed).
    threat_tx: tokio::sync::mpsc::Sender<serde_json::Value>,
}

impl SiemForwarder {
    /// Build the forwarder and spawn its single drain task.
    ///
    /// Returns an `Arc<Self>` so the spawned drain task can hold a strong
    /// reference and call `forward_threat` on the same forwarder that
    /// callers see. Drop semantics: when every external `Arc<SiemForwarder>`
    /// drops, the drain task's reference keeps the forwarder alive until
    /// the channel closes (when `threat_tx` drops). The threat_tx is
    /// stored in the forwarder, so this is effectively forever — fine
    /// for daemon lifetime.
    pub fn new(config: SiemConfig) -> Arc<Self> {
        // Bounded channel; on overflow we drop the threat and log. 4096 is
        // generous — at sustained 4k threats/sec the daemon has bigger
        // problems than SIEM backpressure.
        let (threat_tx, mut threat_rx) = tokio::sync::mpsc::channel::<serde_json::Value>(4096);

        let forwarder = Arc::new(SiemForwarder {
            config: Arc::new(RwLock::new(config)),
            client: reqwest::Client::new(),
            threat_tx,
        });

        // Single drain task. Holds a weak ref so it doesn't keep the
        // forwarder alive on its own; when the last external Arc drops
        // and the channel closes, the drain task exits cleanly.
        let weak = Arc::downgrade(&forwarder);
        tokio::spawn(async move {
            while let Some(payload) = threat_rx.recv().await {
                let Some(fwd) = weak.upgrade() else { break };
                fwd.forward_threat(&payload).await;
            }
            tracing::debug!("SIEM drain task exiting");
        });

        forwarder
    }

    /// Fire-and-forget threat forward. Replaces the
    /// `tokio::spawn(async move { siem.forward_threat(...).await })` pattern
    /// scattered across `main.rs` — one task allocation per threat. Drops
    /// the payload on channel-full and logs at warn level so operators
    /// notice SIEM backpressure.
    pub fn try_enqueue_threat(&self, threat: serde_json::Value) {
        if let Err(e) = self.threat_tx.try_send(threat) {
            use tokio::sync::mpsc::error::TrySendError;
            match e {
                TrySendError::Full(_) => {
                    tracing::warn!("SIEM drain queue full — dropping threat");
                }
                TrySendError::Closed(_) => {
                    tracing::error!("SIEM drain task gone — dropping threat");
                }
            }
        }
    }

    /// Forward a security event to all configured SIEM targets.
    pub async fn forward_event(&self, event: &SecurityEvent) {
        let cfg = self.config.read().await;
        if !cfg.enabled {
            return;
        }
        let payload = match serde_json::to_value(event) {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!(err = %e, "SIEM: failed to serialize SecurityEvent");
                return;
            }
        };
        let severity = if event.allowed { 5u8 } else { 3u8 }; // 5=notice, 3=error
        for target in &cfg.targets {
            if let Err(e) = self.send(target, &payload, severity).await {
                tracing::warn!(err = %e, "SIEM forwarding failed");
            }
        }
    }

    /// Forward a threat payload (arbitrary JSON) to all SIEM targets.
    pub async fn forward_threat(&self, threat: &serde_json::Value) {
        let cfg = self.config.read().await;
        if !cfg.enabled {
            return;
        }
        // Threats are always severity 3 (error)
        for target in &cfg.targets {
            if let Err(e) = self.send(target, threat, 3).await {
                tracing::warn!(err = %e, "SIEM threat forwarding failed");
            }
        }
    }

    /// Update the runtime configuration.
    pub async fn update_config(&self, config: SiemConfig) {
        let mut cfg = self.config.write().await;
        *cfg = config;
    }

    /// Returns a copy of the current config with sensitive tokens masked.
    #[allow(dead_code)]
    pub async fn masked_config(&self) -> SiemConfig {
        let cfg = self.config.read().await;
        let targets = cfg
            .targets
            .iter()
            .map(|t| match t {
                SiemTarget::SplunkHec {
                    url,
                    token: _,
                    index,
                } => SiemTarget::SplunkHec {
                    url: url.clone(),
                    token: "***".to_string(),
                    index: index.clone(),
                },
                SiemTarget::Elasticsearch {
                    url,
                    index,
                    api_key: Some(_),
                } => SiemTarget::Elasticsearch {
                    url: url.clone(),
                    index: index.clone(),
                    api_key: Some("***".to_string()),
                },
                SiemTarget::Sentinel {
                    workspace_id,
                    shared_key: _,
                    log_type,
                } => SiemTarget::Sentinel {
                    workspace_id: workspace_id.clone(),
                    shared_key: "***".to_string(),
                    log_type: log_type.clone(),
                },
                other => other.clone(),
            })
            .collect();
        SiemConfig {
            enabled: cfg.enabled,
            targets,
        }
    }

    // ── private dispatch ─────────────────────────────────────────────────────

    async fn send(
        &self,
        target: &SiemTarget,
        payload: &serde_json::Value,
        severity: u8,
    ) -> anyhow::Result<()> {
        match target {
            SiemTarget::Syslog {
                host,
                port,
                facility,
            } => {
                self.send_syslog(host, *port, *facility, severity, payload)
                    .await
            }
            SiemTarget::SplunkHec { url, token, index } => {
                self.send_splunk(url, token, index.as_deref(), payload)
                    .await
            }
            SiemTarget::Elasticsearch {
                url,
                index,
                api_key,
            } => {
                self.send_elasticsearch(url, index, api_key.as_deref(), payload)
                    .await
            }
            SiemTarget::Sentinel {
                workspace_id,
                shared_key,
                log_type,
            } => {
                self.send_sentinel(workspace_id, shared_key, log_type, payload)
                    .await
            }
        }
    }

    // ── Syslog / UDP ─────────────────────────────────────────────────────────

    async fn send_syslog(
        &self,
        host: &str,
        port: u16,
        facility: u8,
        severity: u8,
        payload: &serde_json::Value,
    ) -> anyhow::Result<()> {
        use tokio::net::UdpSocket;

        let priority = (facility as u16) * 8 + (severity as u16);
        let timestamp = chrono::Utc::now().to_rfc3339();
        let event_json = serde_json::to_string(payload)?;
        // RFC 5424: <PRI>VERSION SP TIMESTAMP SP HOSTNAME SP APP-NAME SP PROCID SP MSGID SP STRUCTURED-DATA SP MSG
        let message = format!(
            "<{}>1 {} ringzero-daemon - - - {}",
            priority, timestamp, event_json
        );

        let socket = UdpSocket::bind("0.0.0.0:0").await?;
        let addr = format!("{}:{}", host, port);
        socket.send_to(message.as_bytes(), &addr).await?;
        tracing::debug!(addr, bytes = message.len(), "Syslog event forwarded");
        Ok(())
    }

    // ── Splunk HEC ───────────────────────────────────────────────────────────

    async fn send_splunk(
        &self,
        url: &str,
        token: &str,
        index: Option<&str>,
        event: &serde_json::Value,
    ) -> anyhow::Result<()> {
        use std::time::{SystemTime, UNIX_EPOCH};

        let unix_ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs_f64())
            .unwrap_or(0.0);

        let mut body = serde_json::json!({
            "time":       unix_ts,
            "host":       "ringzero-daemon",
            "source":     "ringzero",
            "sourcetype": "ringzero:security",
            "event":      event,
        });

        if let Some(idx) = index {
            body["index"] = serde_json::Value::String(idx.to_string());
        }

        let resp = self
            .client
            .post(url)
            .header("Authorization", format!("Splunk {}", token))
            .header("Content-Type", "application/json")
            .json(&body)
            .send()
            .await?;

        let status = resp.status();
        if !status.is_success() {
            let text = resp.text().await.unwrap_or_default();
            return Err(anyhow::anyhow!("Splunk HEC error {}: {}", status, text));
        }
        tracing::debug!("Splunk HEC event forwarded");
        Ok(())
    }

    // ── Elasticsearch ────────────────────────────────────────────────────────

    async fn send_elasticsearch(
        &self,
        url: &str,
        index: &str,
        api_key: Option<&str>,
        event: &serde_json::Value,
    ) -> anyhow::Result<()> {
        // Elasticsearch bulk API requires newline-delimited JSON (NDJSON)
        let meta = serde_json::json!({ "index": { "_index": index } });
        let bulk_body = format!(
            "{}\n{}\n",
            serde_json::to_string(&meta)?,
            serde_json::to_string(event)?
        );

        let bulk_url = format!("{}/{}/_bulk", url.trim_end_matches('/'), index);

        let mut req = self
            .client
            .post(&bulk_url)
            .header("Content-Type", "application/x-ndjson")
            .body(bulk_body);

        if let Some(key) = api_key {
            req = req.header("Authorization", format!("ApiKey {}", key));
        }

        let resp = req.send().await?;
        let status = resp.status();
        if !status.is_success() {
            let text = resp.text().await.unwrap_or_default();
            return Err(anyhow::anyhow!("Elasticsearch error {}: {}", status, text));
        }
        tracing::debug!(index, "Elasticsearch event forwarded");
        Ok(())
    }

    // ── Microsoft Sentinel — Log Analytics Data Collector API ────────────────
    // https://learn.microsoft.com/azure/azure-monitor/logs/data-collector-api

    async fn send_sentinel(
        &self,
        workspace_id: &str,
        shared_key: &str,
        log_type: &str,
        event: &serde_json::Value,
    ) -> anyhow::Result<()> {
        use std::time::{SystemTime, UNIX_EPOCH};

        // Wrap single event in array (API requires JSON array)
        let body = serde_json::to_string(&serde_json::json!([event]))?;
        let body_bytes = body.as_bytes();
        let content_length = body_bytes.len();

        // RFC 1123 date for signing
        let rfc1123_date = {
            let secs = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            // Simple RFC 1123 approximation — production code should use chrono
            chrono::DateTime::from_timestamp(secs as i64, 0)
                .map(|dt| dt.format("%a, %d %b %Y %H:%M:%S GMT").to_string())
                .unwrap_or_default()
        };

        // Build HMAC-SHA256 signature
        let string_to_sign = format!(
            "POST\n{}\napplication/json\nx-ms-date:{}\n/api/logs",
            content_length, rfc1123_date
        );

        let decoded_key = base64_decode(shared_key)?;
        let signature = hmac_sha256_base64(&decoded_key, &string_to_sign)?;
        let auth_header = format!("SharedKey {}:{}", workspace_id, signature);

        let url = format!(
            "https://{}.ods.opinsights.azure.com/api/logs?api-version=2016-04-01",
            workspace_id
        );

        let resp = self
            .client
            .post(&url)
            .header("Authorization", auth_header)
            .header("Log-Type", log_type)
            .header("x-ms-date", &rfc1123_date)
            .header("Content-Type", "application/json")
            .header("Content-Length", content_length.to_string())
            .body(body)
            .send()
            .await?;

        let status = resp.status();
        if !status.is_success() {
            let text = resp.text().await.unwrap_or_default();
            return Err(anyhow::anyhow!("Sentinel error {}: {}", status, text));
        }
        tracing::debug!(workspace_id, log_type, "Sentinel event forwarded");
        Ok(())
    }
}

// ── Sentinel signing helpers ──────────────────────────────────────────────────

fn base64_decode(s: &str) -> anyhow::Result<Vec<u8>> {
    // Use a simple approach without pulling in base64 crate:
    // shared_key arrives as standard base64; decode via openssl-style table
    // In production, use the `base64` crate. Here we shell out to avoid new dep.
    // Actually safer: just require sha2 (already a dep) and do it inline.
    // For now we'll use a minimal decoder.
    let cleaned: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    base64_decode_inner(&cleaned)
}

fn base64_decode_inner(s: &str) -> anyhow::Result<Vec<u8>> {
    const TABLE: &[u8; 128] = b"\
        \xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\
        \xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\
        \xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\x3e\xff\xff\xff\x3f\
        \x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\xff\xff\xff\xff\xff\xff\
        \xff\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\
        \x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\xff\xff\xff\xff\xff\
        \xff\x1a\x1b\x1c\x1d\x1e\x1f\x20\x21\x22\x23\x24\x25\x26\x27\x28\
        \x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\xff\xff\xff\xff\xff";
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len() * 3 / 4);
    let mut i = 0;
    while i + 3 < bytes.len() {
        let a = bytes[i] as usize;
        let b = bytes[i + 1] as usize;
        let c = bytes[i + 2] as usize;
        let d = bytes[i + 3] as usize;
        if a >= 128 || b >= 128 {
            break;
        }
        let va = TABLE[a];
        let vb = TABLE[b];
        let vc = if bytes[i + 2] == b'=' { 0 } else { TABLE[c] };
        let vd = if bytes[i + 3] == b'=' { 0 } else { TABLE[d] };
        if va == 0xff || vb == 0xff {
            break;
        }
        out.push((va << 2) | (vb >> 4));
        if bytes[i + 2] != b'=' {
            out.push(((vb & 0xf) << 4) | (vc >> 2));
        }
        if bytes[i + 3] != b'=' {
            out.push(((vc & 0x3) << 6) | vd);
        }
        i += 4;
    }
    Ok(out)
}

fn hmac_sha256_base64(key: &[u8], data: &str) -> anyhow::Result<String> {
    use sha2::Digest;

    // HMAC-SHA256: inner = SHA256(key XOR ipad || data), outer = SHA256(key XOR opad || inner)
    let block_size = 64usize;
    let mut k = key.to_vec();
    if k.len() > block_size {
        k = sha2::Sha256::digest(&k).to_vec();
    }
    k.resize(block_size, 0);

    let mut ipad = k.clone();
    let mut opad = k.clone();
    for b in &mut ipad {
        *b ^= 0x36;
    }
    for b in &mut opad {
        *b ^= 0x5c;
    }

    let mut inner = ipad;
    inner.extend_from_slice(data.as_bytes());
    let inner_hash = sha2::Sha256::digest(&inner);

    let mut outer = opad;
    outer.extend_from_slice(&inner_hash);
    let mac = sha2::Sha256::digest(&outer);

    // Encode to base64
    Ok(base64_encode(&mac))
}

fn base64_encode(bytes: &[u8]) -> String {
    const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity((bytes.len() + 2) / 3 * 4);
    for chunk in bytes.chunks(3) {
        let b0 = chunk[0] as usize;
        let b1 = if chunk.len() > 1 {
            chunk[1] as usize
        } else {
            0
        };
        let b2 = if chunk.len() > 2 {
            chunk[2] as usize
        } else {
            0
        };
        out.push(CHARS[b0 >> 2] as char);
        out.push(CHARS[((b0 & 3) << 4) | (b1 >> 4)] as char);
        if chunk.len() > 1 {
            out.push(CHARS[((b1 & 0xf) << 2) | (b2 >> 6)] as char);
        } else {
            out.push('=');
        }
        if chunk.len() > 2 {
            out.push(CHARS[b2 & 0x3f] as char);
        } else {
            out.push('=');
        }
    }
    out
}
