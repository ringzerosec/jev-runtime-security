// SPDX-License-Identifier: Apache-2.0
// secrets/dlp.rs — Context-aware API key routing / Data Loss Prevention
// Intercepts outbound network payloads and ensures API keys only reach
// their legitimate service endpoints.
//
// Example: an OpenAI key (sk-...) going to api.somedomain.com → BLOCKED
//          same key going to api.openai.com → ALLOWED
//
// Two layers:
//   1. Registered routes: user/config-defined key→destination mappings
//   2. Provider auto-detect: built-in patterns match key format to known providers

use once_cell::sync::Lazy;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::time::Instant;
use tokio::sync::RwLock;

use super::detector::{classify, mask, SecretKind};
use crate::config::{PiiAction, PiiSection};

// ── Built-in provider routes ─────────────────────────────────────────────────
// Maps key patterns to their legitimate API domains.
// If a key matching a pattern is sent to a domain NOT in the allowed list → block.

struct ProviderRoute {
    #[allow(dead_code)]
    kind: SecretKind,
    pattern: Regex,
    allowed_domains: &'static [&'static str],
    label: &'static str,
}

static PROVIDER_ROUTES: Lazy<Vec<ProviderRoute>> = Lazy::new(|| {
    vec![
        // Anthropic MUST be before OpenAI — both start with "sk-" but
        // Anthropic's "sk-ant-" prefix is more specific.
        ProviderRoute {
            kind: SecretKind::AnthropicKey,
            pattern: Regex::new(r"sk-ant-[A-Za-z0-9\-_]{20,}").unwrap(),
            allowed_domains: &["api.anthropic.com", ".anthropic.com", ".claude.com"],
            label: "Anthropic API Key",
        },
        ProviderRoute {
            kind: SecretKind::OpenAiKey,
            // OpenAI keys: sk-proj-xxx or sk-xxx (old format).
            // Anthropic keys (sk-ant-) are matched above and won't reach here
            // because inspect() returns on the first provider match.
            pattern: Regex::new(r"sk-[A-Za-z0-9\-_]{20,}").unwrap(),
            allowed_domains: &["api.openai.com", ".openai.com"],
            label: "OpenAI API Key",
        },
        ProviderRoute {
            kind: SecretKind::AwsAccessKey,
            pattern: Regex::new(r"AKIA[0-9A-Z]{16}").unwrap(),
            allowed_domains: &[".amazonaws.com", ".aws.amazon.com"],
            label: "AWS Access Key",
        },
        ProviderRoute {
            kind: SecretKind::GitHubToken,
            pattern: Regex::new(r"gh[pousr]_[A-Za-z0-9_]{36,}").unwrap(),
            allowed_domains: &["api.github.com", "uploads.github.com"],
            label: "GitHub Token",
        },
        ProviderRoute {
            kind: SecretKind::SlackToken,
            pattern: Regex::new(r"xox[baprs]-[0-9]{10,}-[0-9A-Za-z\-]{10,}").unwrap(),
            allowed_domains: &["slack.com", ".slack.com"],
            label: "Slack Token",
        },
        // Stripe keys
        ProviderRoute {
            kind: SecretKind::GenericApiKey,
            pattern: Regex::new(r"sk_(?:live|test)_[A-Za-z0-9]{24,}").unwrap(),
            allowed_domains: &["api.stripe.com"],
            label: "Stripe Secret Key",
        },
        // Google AI / Vertex
        ProviderRoute {
            kind: SecretKind::GenericApiKey,
            pattern: Regex::new(r"AIza[0-9A-Za-z\-_]{35}").unwrap(),
            allowed_domains: &[".googleapis.com", "generativelanguage.googleapis.com"],
            label: "Google API Key",
        },
    ]
});

// ── PII redaction patterns ───────────────────────────────────────────────────

static PII_SSN: Lazy<Regex> = Lazy::new(|| Regex::new(r"\b(\d{3})-(\d{2})-(\d{4})\b").unwrap());
static PII_CREDIT_CARD: Lazy<Regex> = Lazy::new(|| Regex::new(r"\b(\d{13,19})\b").unwrap());
static PII_EMAIL: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b").unwrap());
static PII_PHONE: Lazy<Regex> = Lazy::new(|| Regex::new(r"\b\d{3}[-.]?\d{3}[-.]?\d{4}\b").unwrap());
static PII_IP: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"\b(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\b").unwrap());

/// Result of PII redaction: the redacted text + count of replacements.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RedactResult {
    pub text: String,
    pub count: usize,
    pub details: Vec<String>,
}

/// Check if `dest_host` matches any of the allowed domains.
/// Supports exact match and suffix match (for ".amazonaws.com" style patterns).
fn domain_matches(dest_host: &str, allowed: &[&str]) -> bool {
    for pattern in allowed {
        if pattern.starts_with('.') {
            // Suffix match: ".amazonaws.com" matches "s3.amazonaws.com"
            if dest_host.ends_with(pattern) || dest_host == &pattern[1..] {
                return true;
            }
        } else {
            // Exact match
            if dest_host == *pattern {
                return true;
            }
        }
    }
    false
}

// ── Public types ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(dead_code)]
pub struct KeyRoute {
    /// Human label, e.g. "OPENAI_KEY"
    pub key_name: String,
    /// First 4 + last 4 visible, rest masked
    pub masked: String,
    /// Allowed destination hostname, e.g. "api.openai.com"
    pub destination: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DlpVerdict {
    Allow,
    Block { reason: String },
    Warn { reason: String },
}

/// Config-driven key route: maps a key name to its allowed destination.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DlpRouteConfig {
    pub key_env_var: String,
    pub destination: String,
}

// ── Behavioral exfiltration detection ────────────────────────────────────────
// Tracks per-PID indicators: sensitive file reads → archive/compress → network send.
// When multiple indicators fire for the same PID within a 5-minute window,
// confidence of active data exfiltration increases.

/// Known archive/compression tool names.
const ARCHIVE_TOOLS: &[&str] = &[
    "tar", "zip", "gzip", "gunzip", "bzip2", "xz", "7z", "7za", "7zr", "rar", "unrar", "zstd",
    "lz4", "pigz",
];

/// Per-PID behavioral indicators for exfiltration detection.
#[derive(Debug, Clone)]
pub struct PidIndicators {
    /// Count of sensitive file reads (credentials, keys, etc.)
    pub sensitive_reads: u32,
    /// Count of archive/compression operations detected
    pub archive_operations: u32,
    /// Count of outbound network sends after sensitive reads
    pub network_sends: u32,
    /// Count of high-entropy outbound sends (encrypted/compressed data)
    pub entropy_high_sends: u32,
    /// When this PID first triggered an indicator
    #[allow(dead_code)]
    pub first_seen: Instant,
    /// Most recent indicator timestamp
    pub last_seen: Instant,
}

impl PidIndicators {
    fn new() -> Self {
        let now = Instant::now();
        Self {
            sensitive_reads: 0,
            archive_operations: 0,
            network_sends: 0,
            entropy_high_sends: 0,
            first_seen: now,
            last_seen: now,
        }
    }
}

/// Alert emitted when behavioral exfiltration confidence exceeds threshold.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExfilAlert {
    /// Process ID that triggered the alert
    pub pid: u32,
    /// Process name (if known)
    pub process_name: String,
    /// Confidence score (0.0 = unlikely, 1.0 = near-certain exfiltration)
    pub confidence: f64,
    /// Human-readable summary of which indicators fired
    pub indicators: String,
    /// Recommended action
    pub recommended_action: String,
}

/// Tracks behavioral exfiltration indicators per PID.
pub struct ExfilIndicators {
    indicators: RwLock<HashMap<u32, PidIndicators>>,
}

impl ExfilIndicators {
    pub fn new() -> Self {
        Self {
            indicators: RwLock::new(HashMap::new()),
        }
    }

    /// Record that a process opened a sensitive file (credential, key, etc.)
    pub async fn record_sensitive_read(&self, pid: u32) {
        let mut map = self.indicators.write().await;
        let entry = map.entry(pid).or_insert_with(PidIndicators::new);
        entry.sensitive_reads += 1;
        entry.last_seen = Instant::now();
        tracing::debug!(
            pid,
            reads = entry.sensitive_reads,
            "Exfil indicator: sensitive read"
        );
    }

    /// Record that a process executed an archive/compression tool.
    pub async fn record_archive_op(&self, pid: u32) {
        let mut map = self.indicators.write().await;
        let entry = map.entry(pid).or_insert_with(PidIndicators::new);
        entry.archive_operations += 1;
        entry.last_seen = Instant::now();
        tracing::debug!(
            pid,
            ops = entry.archive_operations,
            "Exfil indicator: archive operation"
        );
    }

    /// Record an outbound network send, with Shannon entropy of the payload.
    /// High entropy (>7.0) suggests encrypted or compressed data.
    pub async fn record_network_send(&self, pid: u32, entropy: f64) {
        let mut map = self.indicators.write().await;
        let entry = map.entry(pid).or_insert_with(PidIndicators::new);
        entry.network_sends += 1;
        if entropy > 7.0 {
            entry.entropy_high_sends += 1;
        }
        entry.last_seen = Instant::now();
        tracing::debug!(
            pid,
            sends = entry.network_sends,
            high_entropy = entry.entropy_high_sends,
            entropy = format!("{:.2}", entropy),
            "Exfil indicator: network send"
        );
    }

    /// Check if a PID's indicators exceed the exfiltration confidence threshold.
    /// Returns an alert if confidence >= 0.5.
    pub async fn check_exfil_confidence(&self, pid: u32, process_name: &str) -> Option<ExfilAlert> {
        let map = self.indicators.read().await;
        let ind = map.get(&pid)?;

        // Scoring: each indicator type contributes to confidence.
        // Sensitive reads alone are not exfiltration — they need to be
        // combined with compression and/or network egress.
        let mut score: f64 = 0.0;
        let mut parts = Vec::new();

        if ind.sensitive_reads > 0 {
            // Baseline: accessing sensitive files
            score += 0.15 * (ind.sensitive_reads as f64).min(3.0);
            parts.push(format!("{} sensitive reads", ind.sensitive_reads));
        }

        if ind.archive_operations > 0 {
            // Staging: compressing/archiving after reading secrets
            score += 0.2 * (ind.archive_operations as f64).min(2.0);
            parts.push(format!("{} archive ops", ind.archive_operations));
        }

        if ind.network_sends > 0 && ind.sensitive_reads > 0 {
            // Egress after sensitive access — strong signal
            score += 0.15 * (ind.network_sends as f64).min(3.0);
            parts.push(format!("{} network sends", ind.network_sends));
        }

        if ind.entropy_high_sends > 0 && ind.sensitive_reads > 0 {
            // High-entropy egress after sensitive reads — very strong signal
            score += 0.25 * (ind.entropy_high_sends as f64).min(2.0);
            parts.push(format!("{} high-entropy sends", ind.entropy_high_sends));
        }

        // Cap at 1.0
        let confidence = score.min(1.0);

        if confidence >= 0.5 {
            let recommended_action = if confidence >= 0.8 {
                "BLOCK: terminate process and alert operator".to_string()
            } else {
                "WARN: flag session for manual review".to_string()
            };

            Some(ExfilAlert {
                pid,
                process_name: process_name.to_string(),
                confidence,
                indicators: parts.join(", "),
                recommended_action,
            })
        } else {
            None
        }
    }

    /// Remove entries older than 5 minutes (300 seconds).
    pub async fn prune_stale(&self) {
        let cutoff = Instant::now() - std::time::Duration::from_secs(300);
        let mut map = self.indicators.write().await;
        let before = map.len();
        map.retain(|_, v| v.last_seen > cutoff);
        let pruned = before - map.len();
        if pruned > 0 {
            tracing::debug!(
                pruned,
                remaining = map.len(),
                "Exfil indicators pruned stale entries"
            );
        }
    }

    /// Get list of PIDs currently being tracked.
    pub async fn tracked_pids(&self) -> Vec<u32> {
        self.indicators.read().await.keys().copied().collect()
    }
}

/// Re-export Shannon entropy from scanner module (single canonical implementation).
/// Returns a value between 0.0 (uniform/all same byte) and 8.0 (maximally random).
/// High entropy (>7.0) suggests encrypted or compressed data.
#[allow(unused_imports)]
pub use crate::scanner::entropy::entropy as shannon_entropy;

/// Check if a process name matches a known archive/compression tool.
pub fn is_archive_tool(process_name: &str) -> bool {
    // Strip path prefix if present (e.g., "/usr/bin/tar" → "tar")
    let basename = process_name.rsplit('/').next().unwrap_or(process_name);
    ARCHIVE_TOOLS.iter().any(|&tool| basename == tool)
}

pub struct DlpEngine {
    /// key_name → (raw_value, allowed_destination)
    routes: RwLock<HashMap<String, (String, String)>>,
    /// User-configured extra allowed domains per provider kind
    custom_routes: RwLock<Vec<DlpRouteConfig>>,
    /// PII redaction toggles (atomic for lock-free reads on hot path)
    pii_ssn: AtomicBool,
    pii_credit_card: AtomicBool,
    pii_email: AtomicBool,
    pii_phone: AtomicBool,
    pii_ip: AtomicBool,
    /// PII action mode: 0 = redact, 1 = block (atomic for lock-free reads)
    pii_action: AtomicU8,
    /// Behavioral exfiltration indicator tracker
    pub exfil: ExfilIndicators,
}

impl DlpEngine {
    pub fn new() -> Self {
        Self {
            routes: RwLock::new(HashMap::new()),
            custom_routes: RwLock::new(Vec::new()),
            pii_ssn: AtomicBool::new(true),
            pii_credit_card: AtomicBool::new(true),
            pii_email: AtomicBool::new(true),
            pii_phone: AtomicBool::new(true),
            pii_ip: AtomicBool::new(false),
            pii_action: AtomicU8::new(1), // 1 = Block (default)
            exfil: ExfilIndicators::new(),
        }
    }

    /// Load PII toggles from config.
    pub fn load_pii_config(&self, pii: &PiiSection) {
        self.pii_ssn.store(pii.ssn, Ordering::Relaxed);
        self.pii_credit_card
            .store(pii.credit_card, Ordering::Relaxed);
        self.pii_email.store(pii.email, Ordering::Relaxed);
        self.pii_phone.store(pii.phone, Ordering::Relaxed);
        self.pii_ip.store(pii.ip_address, Ordering::Relaxed);
        self.set_pii_action(&pii.action);
        let action_str = match pii.action {
            PiiAction::Redact => "redact",
            PiiAction::Block => "block",
        };
        tracing::info!(
            ssn = pii.ssn,
            credit_card = pii.credit_card,
            email = pii.email,
            phone = pii.phone,
            ip = pii.ip_address,
            action = action_str,
            "PII config loaded"
        );
    }

    /// Set the PII action mode (block vs redact).
    pub fn set_pii_action(&self, action: &PiiAction) {
        let val = match action {
            PiiAction::Redact => 0u8,
            PiiAction::Block => 1u8,
        };
        self.pii_action.store(val, Ordering::Relaxed);
    }

    /// Get the current PII action mode.
    pub fn get_pii_action(&self) -> PiiAction {
        match self.pii_action.load(Ordering::Relaxed) {
            0 => PiiAction::Redact,
            _ => PiiAction::Block,
        }
    }

    /// Toggle a PII type on/off. Returns the new state.
    pub fn set_pii(&self, pii_type: &str, enabled: bool) -> bool {
        match pii_type {
            "ssn" => self.pii_ssn.store(enabled, Ordering::Relaxed),
            "credit_card" => self.pii_credit_card.store(enabled, Ordering::Relaxed),
            "email" => self.pii_email.store(enabled, Ordering::Relaxed),
            "phone" => self.pii_phone.store(enabled, Ordering::Relaxed),
            "ip_address" => self.pii_ip.store(enabled, Ordering::Relaxed),
            _ => return false,
        }
        tracing::info!(pii_type, enabled, "PII redaction toggled");
        enabled
    }

    /// Get current PII config state.
    pub fn get_pii_config(&self) -> PiiSection {
        PiiSection {
            ssn: self.pii_ssn.load(Ordering::Relaxed),
            credit_card: self.pii_credit_card.load(Ordering::Relaxed),
            email: self.pii_email.load(Ordering::Relaxed),
            phone: self.pii_phone.load(Ordering::Relaxed),
            ip_address: self.pii_ip.load(Ordering::Relaxed),
            action: self.get_pii_action(),
        }
    }

    /// Redact PII from text according to current toggle state.
    /// Returns the redacted text and metadata about what was redacted.
    pub fn redact(&self, text: &str) -> RedactResult {
        let mut output = text.to_string();
        let mut count = 0usize;
        let mut details = Vec::new();

        // SSN: 123-45-6789 → ***-**-6789
        if self.pii_ssn.load(Ordering::Relaxed) {
            let before = output.clone();
            output = PII_SSN.replace_all(&output, "***-**-$3").to_string();
            if output != before {
                let n = PII_SSN.find_iter(&before).count();
                count += n;
                details.push(format!("ssn:{}", n));
            }
        }

        // Credit card: 4111111111111111 → ************1111
        if self.pii_credit_card.load(Ordering::Relaxed) {
            let before = output.clone();
            output = PII_CREDIT_CARD
                .replace_all(&output, |caps: &regex::Captures| {
                    let m = &caps[1];
                    if m.len() >= 13 && luhn_check(m) {
                        let masked = "*".repeat(m.len() - 4);
                        format!("{}{}", masked, &m[m.len() - 4..])
                    } else {
                        m.to_string()
                    }
                })
                .to_string();
            if output != before {
                let n = PII_CREDIT_CARD
                    .find_iter(&before)
                    .filter(|m| m.as_str().len() >= 13 && luhn_check(m.as_str()))
                    .count();
                count += n;
                if n > 0 {
                    details.push(format!("credit_card:{}", n));
                }
            }
        }

        // Email: john.doe@company.com → j*******e@company.com
        if self.pii_email.load(Ordering::Relaxed) {
            let before = output.clone();
            output = PII_EMAIL
                .replace_all(&output, |caps: &regex::Captures| {
                    let m = caps[0].to_string();
                    let parts: Vec<&str> = m.splitn(2, '@').collect();
                    if parts.len() != 2 {
                        return m;
                    }
                    let local = parts[0];
                    let domain = parts[1];
                    if local.len() <= 2 {
                        format!("{}@{}", "*".repeat(local.len()), domain)
                    } else {
                        format!(
                            "{}{}{}@{}",
                            &local[..1],
                            "*".repeat(local.len() - 2),
                            &local[local.len() - 1..],
                            domain
                        )
                    }
                })
                .to_string();
            if output != before {
                let n = PII_EMAIL.find_iter(&before).count();
                count += n;
                details.push(format!("email:{}", n));
            }
        }

        // Phone: 555-123-4567 → (***) ***-4567
        if self.pii_phone.load(Ordering::Relaxed) {
            let before = output.clone();
            output = PII_PHONE
                .replace_all(&output, |caps: &regex::Captures| {
                    let m = caps[0].to_string();
                    let digits: String = m.chars().filter(|c| c.is_ascii_digit()).collect();
                    if digits.len() >= 10 {
                        format!("(***) ***-{}", &digits[digits.len() - 4..])
                    } else {
                        m
                    }
                })
                .to_string();
            if output != before {
                let n = PII_PHONE.find_iter(&before).count();
                count += n;
                details.push(format!("phone:{}", n));
            }
        }

        // IP: 192.168.1.100 → ***.***.***.100
        if self.pii_ip.load(Ordering::Relaxed) {
            let before = output.clone();
            output = PII_IP.replace_all(&output, "***.***.***.$4").to_string();
            if output != before {
                let n = PII_IP.find_iter(&before).count();
                count += n;
                details.push(format!("ip:{}", n));
            }
        }

        RedactResult {
            text: output,
            count,
            details,
        }
    }

    /// Load routes from config-specified environment variables.
    /// For each entry, reads the env var value and registers a route.
    pub async fn load_from_config(&self, routes: &[DlpRouteConfig]) {
        for route in routes {
            if let Ok(value) = std::env::var(&route.key_env_var) {
                if !value.is_empty() {
                    self.add_route(route.key_env_var.clone(), value, route.destination.clone())
                        .await;
                    tracing::info!(
                        key = %route.key_env_var,
                        dest = %route.destination,
                        "DLP route registered from config"
                    );
                }
            }
        }
        *self.custom_routes.write().await = routes.to_vec();
    }

    pub async fn add_route(&self, key_name: String, key_value: String, destination: String) {
        self.routes
            .write()
            .await
            .insert(key_name, (key_value, destination));
    }

    pub async fn remove_route(&self, key_name: &str) {
        self.routes.write().await.remove(key_name);
    }

    #[allow(dead_code)]
    pub async fn list_routes(&self) -> Vec<KeyRoute> {
        self.routes
            .read()
            .await
            .iter()
            .map(|(name, (value, dest))| KeyRoute {
                key_name: name.clone(),
                masked: mask(value),
                destination: dest.clone(),
            })
            .collect()
    }

    /// Inspect an outbound payload destined for `dest_host`.
    ///
    /// Three-layer check:
    /// 1. Registered routes: if a known key value appears and destination doesn't match → Block
    /// 2. Provider auto-detect: if a key pattern matches a known provider and destination
    ///    doesn't match that provider's domains → Block
    /// 3. Unregistered keys: warn but allow (no route to enforce)
    pub async fn inspect(&self, payload: &[u8], dest_host: &str) -> DlpVerdict {
        let text = match std::str::from_utf8(payload) {
            Ok(s) => s,
            Err(_) => return DlpVerdict::Allow, // binary payload, skip
        };

        // Layer 1: Check registered (explicit) routes
        {
            let routes = self.routes.read().await;
            for (name, (value, allowed_dest)) in routes.iter() {
                if text.contains(value.as_str()) {
                    if domain_matches(dest_host, &[allowed_dest.as_str()]) {
                        // Key going to its allowed destination — allow
                        tracing::debug!(
                            key = %name, dest = %dest_host,
                            "DLP: registered key going to authorized destination"
                        );
                        return DlpVerdict::Allow;
                    } else {
                        tracing::warn!(
                            key = %name, dest = %dest_host, allowed = %allowed_dest,
                            "DLP BLOCK: registered API key sent to unauthorized destination"
                        );
                        return DlpVerdict::Block {
                            reason: format!(
                                "API key '{}' sent to '{}' — only allowed to '{}'",
                                name, dest_host, allowed_dest
                            ),
                        };
                    }
                }
            }
        }

        // Layer 2: Provider auto-detect — match key patterns against known providers
        for provider in PROVIDER_ROUTES.iter() {
            if provider.pattern.is_match(text) {
                if domain_matches(dest_host, provider.allowed_domains) {
                    // Key going to its legitimate provider — allow
                    tracing::debug!(
                        provider = %provider.label, dest = %dest_host,
                        "DLP: detected key going to legitimate provider"
                    );
                    return DlpVerdict::Allow;
                } else {
                    tracing::warn!(
                        provider = %provider.label,
                        dest = %dest_host,
                        allowed = ?provider.allowed_domains,
                        "DLP BLOCK: API key detected going to wrong provider"
                    );
                    return DlpVerdict::Block {
                        reason: format!(
                            "{} detected in request to '{}' — only allowed to {:?}",
                            provider.label, dest_host, provider.allowed_domains
                        ),
                    };
                }
            }
        }

        // Layer 3: Check for unregistered known-format keys via classifier
        // These are patterns we recognize but don't have a provider route for
        // (e.g., generic api_key=xxx patterns). Warn but don't block.
        for word in
            text.split(|c: char| c.is_whitespace() || c == '"' || c == '\'' || c == ',' || c == ':')
        {
            if word.len() >= 20 {
                if let Some(kind) = classify(word) {
                    tracing::warn!(
                        dest = %dest_host,
                        key_kind = ?kind,
                        "DLP WARN: unregistered secret pattern in outbound payload"
                    );
                    return DlpVerdict::Warn {
                        reason: format!(
                            "{:?} pattern detected in request to '{}' (no route configured — allowing)",
                            kind, dest_host
                        ),
                    };
                }
            }
        }

        DlpVerdict::Allow
    }
}

// ── Base64 exfil detection (NX P3) ──────────────────────────────────────────
// NX attack uses triple-base64 encoding to obfuscate exfiltrated credentials.
// Recursively decode base64 blobs to detect hidden secrets.

use base64::Engine as _;

/// Result of recursive base64 decode analysis.
#[derive(Debug, Clone, Serialize)]
pub struct Base64ExfilResult {
    pub detected: bool,
    pub decode_depth: u32,
    pub decoded_content: String,
    pub details: Vec<String>,
}

/// Attempt recursive base64 decode (up to 5 layers) to detect obfuscated exfil.
/// Returns findings if decoded content contains PII/secrets.
///
/// Called per SSL chunk in ssl_sniff.rs; the regex is hoisted into a Lazy
/// so we don't recompile it for every outbound HTTPS write.
pub fn detect_base64_exfil(text: &str) -> Option<Base64ExfilResult> {
    static B64_RE: once_cell::sync::Lazy<regex::Regex> =
        once_cell::sync::Lazy::new(|| regex::Regex::new(r"[A-Za-z0-9+/]{40,}={0,2}").unwrap());

    for mat in B64_RE.find_iter(text) {
        let blob = mat.as_str();
        let mut current = blob.to_string();
        let mut depth = 0u32;

        // Try decoding up to 5 layers deep
        for _ in 0..5 {
            match base64::engine::general_purpose::STANDARD.decode(current.trim()) {
                Ok(decoded_bytes) => {
                    depth += 1;
                    match String::from_utf8(decoded_bytes) {
                        Ok(decoded_str) => {
                            // Check if decoded content contains secrets/PII
                            let mut details = Vec::new();

                            // Check for API keys
                            if decoded_str.contains("sk-") || decoded_str.contains("AKIA") {
                                details.push("API key pattern in decoded content".into());
                            }
                            // Check for common credential patterns
                            if decoded_str.contains("password")
                                || decoded_str.contains("secret")
                                || decoded_str.contains("token")
                                || decoded_str.contains("credential")
                            {
                                details.push("Credential keyword in decoded content".into());
                            }
                            // Check for SSH keys
                            if decoded_str.contains("BEGIN") && decoded_str.contains("PRIVATE KEY")
                            {
                                details.push("Private key in decoded content".into());
                            }
                            // Check for email/PII
                            if decoded_str.contains('@') && decoded_str.contains('.') {
                                details.push("Email pattern in decoded content".into());
                            }

                            if !details.is_empty() {
                                return Some(Base64ExfilResult {
                                    detected: true,
                                    decode_depth: depth,
                                    decoded_content: decoded_str.chars().take(200).collect(),
                                    details,
                                });
                            }

                            // Check if the decoded content is itself base64
                            if B64_RE.is_match(&decoded_str) {
                                current = decoded_str;
                                continue;
                            }
                        }
                        Err(_) => break, // binary data, stop
                    }
                }
                Err(_) => break,
            }
            break; // not another base64 layer
        }

        // Even without secret content, flag triple+ base64 encoding as suspicious
        if depth >= 3 {
            return Some(Base64ExfilResult {
                detected: true,
                decode_depth: depth,
                decoded_content: "[multi-layer encoded data]".into(),
                details: vec![format!(
                    "{}-layer base64 encoding detected — likely obfuscated exfil",
                    depth
                )],
            });
        }
    }

    None
}

/// Luhn algorithm — validates credit card numbers to avoid false positives
/// on random 13-19 digit sequences.
fn luhn_check(digits: &str) -> bool {
    let mut sum = 0u32;
    let mut double = false;
    for ch in digits.chars().rev() {
        let Some(d) = ch.to_digit(10) else {
            return false;
        };
        let val = if double {
            let doubled = d * 2;
            if doubled > 9 {
                doubled - 9
            } else {
                doubled
            }
        } else {
            d
        };
        sum += val;
        double = !double;
    }
    sum % 10 == 0
}

// ── Obfuscation detection types ──────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ObfuscationType {
    Base64,
    Base32,
    Hex,
    UrlEncoding,
    UnicodeAnomaly,
    HighEntropy,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObfuscationResult {
    pub encoding_type: ObfuscationType,
    pub confidence: f32,
    pub decoded_content: Option<String>,
    pub entropy: f32,
    pub details: Vec<String>,
}

/// Scan text for all forms of obfuscated exfiltration.
/// Returns a list of detections with confidence scores.
pub fn detect_obfuscated_exfil(text: &str) -> Vec<ObfuscationResult> {
    let mut results = vec![];
    // Existing base64 check
    if let Some(b64) = detect_base64_exfil(text) {
        results.push(ObfuscationResult {
            encoding_type: ObfuscationType::Base64,
            confidence: if b64.decode_depth >= 3 { 0.95 } else { 0.8 },
            decoded_content: Some(b64.decoded_content),
            entropy: 0.0,
            details: b64.details,
        });
    }
    results.extend(detect_hex_encoding(text));
    results.extend(detect_base32(text));
    results.extend(detect_url_encoding(text));
    results.extend(detect_unicode_anomalies(text));
    results.extend(detect_high_entropy_segments(text));
    results
}

// ── Hex encoding detection ──────────────────────────────────────────────────

fn detect_hex_encoding(text: &str) -> Vec<ObfuscationResult> {
    // Hot path: compile once. Was re-compiled per call.
    static HEX_RE: once_cell::sync::Lazy<Regex> =
        once_cell::sync::Lazy::new(|| Regex::new(r"(?i)\b([0-9a-f]{40,})\b").unwrap());
    let hex_re = &*HEX_RE;

    let mut results = vec![];
    for cap in hex_re.captures_iter(text) {
        let hex_str = &cap[1];
        // Skip Git SHAs (exactly 40 hex chars)
        if hex_str.len() == 40 {
            continue;
        }
        // Skip UUIDs (32 hex chars without dashes)
        let without_dashes: String = hex_str.chars().filter(|c| *c != '-').collect();
        if without_dashes.len() == 32 {
            continue;
        }

        // Try to decode
        let decoded = hex_decode(hex_str);
        let mut details = vec![];
        let mut confidence: f32 = 0.5;

        if let Some(ref decoded_str) = decoded {
            if decoded_str.contains("sk-")
                || decoded_str.contains("AKIA")
                || decoded_str.contains("password")
                || decoded_str.contains("token")
                || decoded_str.contains("secret")
            {
                details.push("Credential pattern in hex-decoded content".into());
                confidence = 0.9;
            }
            if decoded_str.contains("BEGIN") && decoded_str.contains("PRIVATE KEY") {
                details.push("Private key in hex-decoded content".into());
                confidence = 0.95;
            }
        }

        if details.is_empty() {
            details.push(format!("{}-char hex string detected", hex_str.len()));
        }

        results.push(ObfuscationResult {
            encoding_type: ObfuscationType::Hex,
            confidence,
            decoded_content: decoded,
            entropy: 0.0,
            details,
        });
    }
    results
}

/// Manual hex decode (no external crate needed).
fn hex_decode(hex: &str) -> Option<String> {
    let hex = hex.to_ascii_lowercase();
    if hex.len() % 2 != 0 {
        return None;
    }
    let bytes: Result<Vec<u8>, _> = (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16))
        .collect();
    bytes.ok().and_then(|b| String::from_utf8(b).ok())
}

// ── Base32 detection ─────────────────────────────────────────────────────────

fn detect_base32(text: &str) -> Vec<ObfuscationResult> {
    static B32_RE: once_cell::sync::Lazy<Regex> =
        once_cell::sync::Lazy::new(|| Regex::new(r"\b([A-Z2-7]{40,}={0,6})\b").unwrap());
    let b32_re = &*B32_RE;
    let mut results = vec![];
    for cap in b32_re.captures_iter(text) {
        let b32_str = &cap[1];
        let details = vec![format!(
            "{}-char base32-like pattern detected",
            b32_str.len()
        )];
        results.push(ObfuscationResult {
            encoding_type: ObfuscationType::Base32,
            confidence: 0.6,
            decoded_content: None,
            entropy: 0.0,
            details,
        });
    }
    results
}

// ── URL encoding detection ───────────────────────────────────────────────────

fn detect_url_encoding(text: &str) -> Vec<ObfuscationResult> {
    static URL_RE: once_cell::sync::Lazy<Regex> =
        once_cell::sync::Lazy::new(|| Regex::new(r"(%[0-9A-Fa-f]{2}){3,}").unwrap());
    let url_re = &*URL_RE;
    let mut results = vec![];
    for mat in url_re.find_iter(text) {
        let encoded = mat.as_str();
        // Decode the percent-encoded string
        let decoded = url_decode(encoded);
        let mut details = vec![format!("{}-char URL-encoded sequence", encoded.len())];
        let mut confidence: f32 = 0.5;

        if let Some(ref dec) = decoded {
            if dec.contains("sk-")
                || dec.contains("AKIA")
                || dec.contains("password")
                || dec.contains("token")
            {
                details.push("Credential pattern in URL-decoded content".into());
                confidence = 0.9;
            }
        }

        results.push(ObfuscationResult {
            encoding_type: ObfuscationType::UrlEncoding,
            confidence,
            decoded_content: decoded,
            entropy: 0.0,
            details,
        });
    }
    results
}

fn url_decode(encoded: &str) -> Option<String> {
    let mut result = Vec::new();
    let bytes = encoded.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let Ok(b) = u8::from_str_radix(std::str::from_utf8(&bytes[i + 1..i + 3]).ok()?, 16) {
                result.push(b);
                i += 3;
                continue;
            }
        }
        result.push(bytes[i]);
        i += 1;
    }
    String::from_utf8(result).ok()
}

// ── Unicode anomaly detection ────────────────────────────────────────────────

fn detect_unicode_anomalies(text: &str) -> Vec<ObfuscationResult> {
    let mut results = vec![];
    let mut details = vec![];
    let mut confidence: f32 = 0.0;

    // 1. Zero-width characters
    let zero_width_count = text
        .chars()
        .filter(|c| {
            matches!(
                *c,
                '\u{200B}'
                    | '\u{200C}'
                    | '\u{200D}'
                    | '\u{FEFF}'
                    | '\u{2060}'
                    | '\u{200E}'
                    | '\u{200F}'
            )
        })
        .count();
    if zero_width_count > 0 {
        details.push(format!(
            "{} zero-width characters detected",
            zero_width_count
        ));
        confidence = (zero_width_count as f32 * 0.1).min(0.9);
    }

    // 2. RTL override characters
    let rtl_overrides = text
        .chars()
        .filter(|c| {
            matches!(
                *c,
                '\u{202A}' | '\u{202B}' | '\u{202C}' | '\u{202D}' | '\u{202E}'
            )
        })
        .count();
    if rtl_overrides > 0 {
        details.push(format!(
            "{} RTL override characters detected",
            rtl_overrides
        ));
        confidence = confidence.max(0.8);
    }

    // 3. Homoglyph detection: mixed Latin and Cyrillic in same word
    let has_latin = text
        .chars()
        .any(|c| (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z'));
    let has_cyrillic = text.chars().any(|c| ('\u{0400}'..='\u{04FF}').contains(&c));
    if has_latin && has_cyrillic {
        for word in text.split_whitespace() {
            let w_latin = word
                .chars()
                .any(|c| (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z'));
            let w_cyrillic = word.chars().any(|c| ('\u{0400}'..='\u{04FF}').contains(&c));
            if w_latin && w_cyrillic {
                details.push(format!(
                    "Mixed Latin+Cyrillic in word: '{}'",
                    &word.chars().take(30).collect::<String>()
                ));
                confidence = confidence.max(0.85);
                break; // one example is enough
            }
        }
    }

    if !details.is_empty() {
        results.push(ObfuscationResult {
            encoding_type: ObfuscationType::UnicodeAnomaly,
            confidence,
            decoded_content: None,
            entropy: 0.0,
            details,
        });
    }
    results
}

// ── High entropy segment detection ───────────────────────────────────────────

fn detect_high_entropy_segments(text: &str) -> Vec<ObfuscationResult> {
    use crate::scanner::entropy;

    let bytes = text.as_bytes();
    if bytes.len() < 40 {
        return vec![];
    }

    let mut results = vec![];
    let window_size = 256.min(bytes.len());

    // Text-appropriate entropy thresholds:
    // - Normal English prose: ~3.5-4.3 bits/byte
    // - Source code / config: ~4.0-4.8 bits/byte
    // - Base64 / hex encoded: ~5.0-6.0 bits/byte
    // - Encrypted / compressed: ~6.0-8.0 bits/byte (rarely valid UTF-8)
    // We flag >= 5.0 as suspicious (obfuscated text) and >= 5.7 as high confidence.
    const TEXT_ENTROPY_SUSPICIOUS: f64 = 5.0;
    const TEXT_ENTROPY_HIGH: f64 = 5.7;

    let mut i = 0;
    while i + window_size <= bytes.len() {
        let window = &bytes[i..i + window_size];
        let ent = entropy::entropy(window);

        if ent >= TEXT_ENTROPY_SUSPICIOUS {
            // Extract the segment as a string for allowlist checks
            if let Ok(segment) = std::str::from_utf8(window) {
                // Skip known safe patterns: UUID
                let uuid_re = Regex::new(
                    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$",
                ).unwrap();
                if uuid_re.is_match(segment) {
                    i += window_size;
                    continue;
                }
                // Skip Git SHA (exactly 40 hex chars)
                if segment.len() == 40 && segment.chars().all(|c| c.is_ascii_hexdigit()) {
                    i += window_size;
                    continue;
                }
            }

            results.push(ObfuscationResult {
                encoding_type: ObfuscationType::HighEntropy,
                confidence: if ent >= TEXT_ENTROPY_HIGH { 0.8 } else { 0.6 },
                decoded_content: None,
                entropy: ent as f32,
                details: vec![format!(
                    "Entropy {:.2} in {}-byte segment at offset {}",
                    ent, window_size, i
                )],
            });

            // Skip ahead to avoid overlapping detections
            i += window_size;
            continue;
        }
        i += window_size / 2; // slide by half
    }
    results
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redact_detects_pii_findings_for_dlp_view() {
        // The exact shape the SSL-sniff DLP path relies on: redact() must report
        // count>0 and itemised details so a DlpPii *finding* event is emitted and
        // shows in the UI's "Recent Detections". (Regression guard for the bug
        // where PII detections never reached the timeline.)
        let dlp = DlpEngine::new();
        let body = r#"{"messages":[{"role":"user","content":"patient ssn 123-45-6789, email jane.doe@hospital.com, card 4111111111111111"}]}"#;
        let r = dlp.redact(body);
        assert!(
            r.count >= 3,
            "expected ssn+email+card detected, got {} ({:?})",
            r.count,
            r.details
        );
        assert!(
            r.details.iter().any(|d| d.starts_with("ssn:")),
            "ssn missing: {:?}",
            r.details
        );
        assert!(
            r.details.iter().any(|d| d.starts_with("email:")),
            "email missing: {:?}",
            r.details
        );
        assert!(
            r.details.iter().any(|d| d.starts_with("credit_card:")),
            "cc missing: {:?}",
            r.details
        );
        // And the original PII must not survive in the redacted text.
        assert!(!r.text.contains("123-45-6789"));
    }

    #[test]
    fn test_hex_detection_basic() {
        // "Hello World! This is a secret token value" in hex (48+ chars)
        let hex_encoded =
            "48656c6c6f20576f726c6421205468697320697320612073656372657420746f6b656e2076616c7565";
        let results = detect_hex_encoding(hex_encoded);
        assert!(!results.is_empty(), "Should detect long hex-encoded string");
        assert_eq!(results[0].encoding_type, ObfuscationType::Hex);
        // The decoded content should contain "secret" and "token"
        assert!(
            results[0].confidence >= 0.9,
            "Should have high confidence due to credential pattern"
        );
    }

    #[test]
    fn test_hex_skips_git_sha() {
        // Exactly 40-char hex string (Git SHA)
        let sha = "a94a8fe5ccb19ba61c4c0873d391e987982fbbd3";
        let results = detect_hex_encoding(sha);
        assert!(
            results.is_empty(),
            "Should skip exactly 40-char hex (Git SHA)"
        );
    }

    #[test]
    fn test_hex_skips_uuid() {
        // 32 hex chars (UUID without dashes)
        let uuid_hex = "550e8400e29b41d4a716446655440000";
        // This is only 32 chars, which the regex requires 40+, so it won't match at all.
        let results = detect_hex_encoding(uuid_hex);
        assert!(results.is_empty(), "Should skip UUID-length hex strings");
    }

    #[test]
    fn test_base32_detection() {
        // A base32-encoded string (A-Z, 2-7), 40+ chars
        let b32 = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP";
        let results = detect_base32(b32);
        assert!(!results.is_empty(), "Should detect base32-like pattern");
        assert_eq!(results[0].encoding_type, ObfuscationType::Base32);
    }

    #[test]
    fn test_url_encoding_detection() {
        // URL-encoded "password=secret123"
        let encoded = "%70%61%73%73%77%6f%72%64%3d%73%65%63%72%65%74%31%32%33";
        let results = detect_url_encoding(encoded);
        assert!(!results.is_empty(), "Should detect URL-encoded sequences");
        assert_eq!(results[0].encoding_type, ObfuscationType::UrlEncoding);
        // Should contain decoded content
        assert!(results[0].decoded_content.is_some());
        let decoded = results[0].decoded_content.as_ref().unwrap();
        assert!(
            decoded.contains("password"),
            "Decoded should contain 'password'"
        );
        assert!(
            results[0].confidence >= 0.9,
            "Should have high confidence due to credential pattern"
        );
    }

    #[test]
    fn test_unicode_zero_width() {
        let text = "hello\u{200B}\u{200B}\u{200B}world";
        let results = detect_unicode_anomalies(text);
        assert!(!results.is_empty(), "Should detect zero-width chars");
        assert_eq!(results[0].encoding_type, ObfuscationType::UnicodeAnomaly);
        assert!(
            results[0].details[0].contains("zero-width"),
            "Details should mention zero-width"
        );
    }

    #[test]
    fn test_unicode_homoglyph() {
        // Mix Latin 'a' with Cyrillic 'а' (\u{0430}) in the same word
        let text = "p\u{0430}ssword";
        let results = detect_unicode_anomalies(text);
        assert!(
            !results.is_empty(),
            "Should detect mixed Latin+Cyrillic homoglyphs"
        );
        assert!(
            results[0]
                .details
                .iter()
                .any(|d| d.contains("Latin+Cyrillic")),
            "Details should mention Latin+Cyrillic"
        );
    }

    #[test]
    fn test_unicode_rtl_override() {
        let text = "normal\u{202E}txet desrever";
        let results = detect_unicode_anomalies(text);
        assert!(!results.is_empty(), "Should detect RTL override chars");
        assert!(
            results[0].details.iter().any(|d| d.contains("RTL")),
            "Details should mention RTL"
        );
    }

    #[test]
    fn test_high_entropy_detection() {
        // Build a string with high byte-level Shannon entropy.
        // We need 256+ bytes for the sliding window with diverse byte values.
        // Mix ASCII, Greek, Cyrillic to get entropy > 5.0 (the text threshold).
        let mut high_entropy = String::new();
        for cp in (0x21..0x7Eu32) // ASCII printable (93 chars, 93 bytes)
            .chain(0x391..0x3C9u32) // Greek (56 chars, 112 bytes)
            .chain(0x410..0x44Fu32)
        // Cyrillic (63 chars, 126 bytes)
        {
            if let Some(c) = char::from_u32(cp) {
                high_entropy.push(c);
            }
        }
        let byte_len = high_entropy.as_bytes().len();
        assert!(byte_len >= 256, "Need at least 256 bytes, got {}", byte_len);

        let results = detect_high_entropy_segments(&high_entropy);
        assert!(
            !results.is_empty(),
            "Should detect high-entropy segment (byte_len={})",
            byte_len
        );
        assert_eq!(results[0].encoding_type, ObfuscationType::HighEntropy);
        assert!(
            results[0].entropy >= 5.0,
            "Entropy should be >= 5.0, got {}",
            results[0].entropy
        );
    }

    #[test]
    fn test_entropy_skips_normal_text() {
        // Must be >= 256 bytes to actually trigger the sliding window scan.
        // Normal English prose has entropy ~4.0-4.5 bits, well below the 6.5 threshold.
        let normal = "This is a perfectly normal English sentence with regular words \
            and spaces. It should not trigger any high entropy detection because natural \
            language has relatively low Shannon entropy due to letter frequency patterns. \
            The quick brown fox jumps over the lazy dog near the riverbank on a sunny day.";
        assert!(
            normal.as_bytes().len() >= 256,
            "Test string must be >= 256 bytes"
        );
        let results = detect_high_entropy_segments(normal);
        assert!(
            results.is_empty(),
            "Normal English text should not trigger high-entropy detection"
        );
    }

    #[test]
    fn test_obfuscated_exfil_aggregation() {
        // Input that triggers multiple detectors: hex-encoded credential + zero-width chars
        let hex_with_cred =
            "48656c6c6f20576f726c6421205468697320697320612073656372657420746f6b656e2076616c7565";
        let input = format!("\u{200B}\u{200B}\u{200B}{}", hex_with_cred);
        let results = detect_obfuscated_exfil(&input);
        // Should have at least hex + unicode anomaly
        let has_hex = results
            .iter()
            .any(|r| r.encoding_type == ObfuscationType::Hex);
        let has_unicode = results
            .iter()
            .any(|r| r.encoding_type == ObfuscationType::UnicodeAnomaly);
        assert!(has_hex, "Aggregation should include hex detection");
        assert!(has_unicode, "Aggregation should include unicode anomaly");
    }

    #[test]
    fn test_empty_input() {
        assert!(detect_hex_encoding("").is_empty());
        assert!(detect_base32("").is_empty());
        assert!(detect_url_encoding("").is_empty());
        assert!(detect_unicode_anomalies("").is_empty());
        assert!(detect_high_entropy_segments("").is_empty());
        assert!(detect_obfuscated_exfil("").is_empty());
    }
}
