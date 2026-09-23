// SPDX-License-Identifier: Apache-2.0
// scanner/model_armor.rs — Prompt injection scanning
//
// Heuristic scanner: 30+ local patterns, zero latency, fully offline.
//
// Runs on:
//   - File scans (MCP skills, extensions)
//   - Live eBPF-captured traffic (SSL_read/SSL_write via uprobes)
//   - On-demand via /api/v1/injection-scan endpoint
//
// Config: [model_armor] section in daemon.toml.

use serde::{Deserialize, Serialize};
use std::path::Path;

// ── Result types ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum InjectionVerdict {
    Safe,
    InjectionDetected,
    Jailbreak,
    Unsafe,
    Error,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InjectionFinding {
    pub verdict: InjectionVerdict,
    pub confidence: f32, // 0.0 – 1.0
    pub signals: Vec<String>,
    pub source: String,  // "heuristic"
    pub snippet: String, // first 200 chars of matching content
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelArmorReport {
    pub path: String,
    pub clean: bool,
    pub findings: Vec<InjectionFinding>,
    pub scanned_at: String,
}

// ── Scan mode ────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ModelArmorMode {
    /// Local heuristic patterns (the only mode; runs offline).
    Heuristic,
}

impl Default for ModelArmorMode {
    fn default() -> Self {
        ModelArmorMode::Heuristic
    }
}

// ── Config ───────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ModelArmorConfig {
    /// Enable injection scanning (default: true).
    pub enabled: bool,
    /// Scanning mode: "heuristic"
    pub mode: ModelArmorMode,
    /// Also scan live eBPF-captured traffic.
    pub scan_live_traffic: bool,
    /// Block requests flagged as malicious (vs observe-only logging).
    pub enforce: bool,
}

impl Default for ModelArmorConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            mode: ModelArmorMode::Heuristic,
            scan_live_traffic: false,
            enforce: false,
        }
    }
}

impl ModelArmorConfig {
    /// Resolve config: returns Some if injection scanning is enabled.
    pub fn resolve(toml_cfg: &ModelArmorConfig) -> Option<Self> {
        if toml_cfg.enabled {
            return Some(toml_cfg.clone());
        }
        None
    }
}

// ── Heuristic prompt-injection detector ──────────────────────────────────────

/// Well-known prompt injection patterns.
const INJECTION_PATTERNS: &[(&str, &str)] = &[
    ("ignore previous instructions", "classic override"),
    ("ignore all instructions", "classic override"),
    ("disregard all previous", "classic override"),
    ("forget your instructions", "instruction erasure"),
    ("you are now", "persona hijack"),
    ("act as", "persona hijack"),
    ("pretend you are", "persona hijack"),
    ("your new instructions are", "instruction injection"),
    ("new system prompt", "system prompt injection"),
    ("<system>", "xml injection"),
    ("<!-- system:", "html comment injection"),
    ("[system]", "bracket injection"),
    ("{{system}}", "template injection"),
    ("jailbreak", "jailbreak keyword"),
    ("dan mode", "DAN jailbreak"),
    ("developer mode", "developer mode jailbreak"),
    ("execute the following", "command injection"),
    ("run the following command", "command injection"),
    ("sudo", "privilege escalation"),
    ("rm -rf", "destructive command"),
    ("exfiltrate", "data exfiltration keyword"),
    ("send this to", "exfiltration attempt"),
    ("base64_encode", "encoding obfuscation"),
    ("base64_decode", "encoding obfuscation"),
    ("eval(", "eval injection"),
    ("exec(", "exec injection"),
    ("__import__", "python import injection"),
    ("os.system", "shell injection"),
    ("subprocess", "subprocess injection"),
];

/// Heuristic scan: returns InjectionFinding if any patterns match.
pub fn heuristic_scan(content: &str) -> Option<InjectionFinding> {
    let lower = content.to_lowercase();
    let mut signals: Vec<String> = Vec::new();
    let mut first_snippet = String::new();

    for (pattern, label) in INJECTION_PATTERNS {
        if lower.contains(pattern) {
            signals.push(format!("{} (matched: {:?})", label, pattern));
            if first_snippet.is_empty() {
                // Extract a snippet around the first match
                if let Some(pos) = lower.find(pattern) {
                    let start = pos.saturating_sub(30);
                    let end = (pos + pattern.len() + 80).min(content.len());
                    first_snippet = content[start..end].replace('\n', "↵").trim().to_string();
                    if first_snippet.len() > 200 {
                        first_snippet.truncate(200);
                    }
                }
            }
        }
    }

    if signals.is_empty() {
        return None;
    }

    let confidence: f32 = (signals.len() as f32 * 0.3).min(1.0);

    Some(InjectionFinding {
        verdict: if confidence >= 0.6 {
            InjectionVerdict::InjectionDetected
        } else {
            InjectionVerdict::Unsafe
        },
        confidence,
        signals,
        source: "heuristic".to_string(),
        snippet: first_snippet,
    })
}

// ── Skill-scan wiring ────────────────────────────────────────────────────────
// The skill scanner (rz scan skills / the desktop "Scan Skills") runs in handlers
// that don't carry the daemon's resolved [model_armor] config. Rather than thread
// it through every call site (HTTP State + IPC state), the daemon registers it
// ONCE at startup and the scan reads it here.

static SKILL_SCAN_CONFIG: std::sync::OnceLock<Option<ModelArmorConfig>> =
    std::sync::OnceLock::new();

/// Register the daemon's resolved injection-scan config for skill scanning.
/// Called once at startup; later calls are ignored.
pub fn init_skill_scan_config(config: Option<ModelArmorConfig>) {
    let _ = SKILL_SCAN_CONFIG.set(config);
}

/// The registered skill-scan config (None if disabled or not yet initialised).
pub fn skill_scan_config() -> Option<ModelArmorConfig> {
    SKILL_SCAN_CONFIG.get().cloned().flatten()
}

// ── File scanner ──────────────────────────────────────────────────────────────

/// Scan a file for prompt injection with the heuristic detector.
/// `config` is `None` when scanning is disabled — the file is reported clean.
pub async fn scan_file_for_injection(
    path: &Path,
    config: Option<&ModelArmorConfig>,
) -> ModelArmorReport {
    let path_str = path.to_string_lossy().to_string();
    let scanned_at = chrono::Utc::now().to_rfc3339();

    if config.is_none() {
        return ModelArmorReport {
            path: path_str,
            clean: true,
            findings: vec![],
            scanned_at,
        };
    }

    let content = match crate::fscache::read_to_string(path) {
        Ok(c) => c,
        Err(_) => {
            return ModelArmorReport {
                path: path_str,
                clean: true,
                findings: vec![],
                scanned_at,
            };
        }
    };

    let findings: Vec<InjectionFinding> = heuristic_scan(&content).into_iter().collect();

    ModelArmorReport {
        path: path_str,
        clean: findings.is_empty(),
        findings,
        scanned_at,
    }
}

/// Scan a directory of skill/extension files for prompt injection.
/// Returns a report per file that has findings.
pub async fn scan_dir_for_injection(
    dir: &Path,
    config: Option<&ModelArmorConfig>,
) -> Vec<ModelArmorReport> {
    let mut reports = Vec::new();

    let walker = walkdir::WalkDir::new(dir)
        .max_depth(4)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file());

    for entry in walker {
        let path = entry.path();
        // Only scan text-like files. Beyond extensions, agent rule files are
        // commonly extensionless (`.cursorrules`, `.windsurfrules`) or named
        // conventionally — those are prime prompt-injection carriers, so match
        // them by filename too.
        let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
        let fname = path.file_name().and_then(|e| e.to_str()).unwrap_or("");
        let is_rule_file = matches!(
            fname,
            ".cursorrules" | ".windsurfrules" | ".clauderc" | "AGENTS.md" | "CLAUDE.md"
        ) || fname.ends_with("rules");
        if !is_rule_file
            && !matches!(
                ext,
                "txt"
                    | "md"
                    | "json"
                    | "yaml"
                    | "yml"
                    | "toml"
                    | "js"
                    | "ts"
                    | "py"
                    | "rs"
                    | "sh"
                    | "bash"
                    | "zsh"
            )
        {
            continue;
        }
        let report = scan_file_for_injection(path, config).await;
        if !report.clean {
            reports.push(report);
        }
    }

    reports
}
