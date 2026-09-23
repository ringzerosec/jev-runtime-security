// SPDX-License-Identifier: Apache-2.0
// secrets/detector.rs — regex-based secret detection

use once_cell::sync::Lazy;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::{fs, path::Path};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SecretKind {
    AwsAccessKey,
    AwsSecretKey,
    GitHubToken,
    OpenAiKey,
    AnthropicKey,
    GcpServiceAccount,
    SlackToken,
    PrivateKey,
    GenericApiKey,
    GenericSecret,
    Password,
}

impl SecretKind {
    pub fn label(&self) -> &'static str {
        match self {
            Self::AwsAccessKey => "AWS Access Key",
            Self::AwsSecretKey => "AWS Secret Key",
            Self::GitHubToken => "GitHub Token",
            Self::OpenAiKey => "OpenAI API Key",
            Self::AnthropicKey => "Anthropic API Key",
            Self::GcpServiceAccount => "GCP Service Account",
            Self::SlackToken => "Slack Token",
            Self::PrivateKey => "Private Key",
            Self::GenericApiKey => "API Key",
            Self::GenericSecret => "Secret/Token",
            Self::Password => "Password",
        }
    }

    #[allow(dead_code)]
    pub fn is_rotatable(&self) -> bool {
        matches!(
            self,
            Self::AwsAccessKey | Self::GitHubToken | Self::SlackToken
        )
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretFinding {
    pub kind: SecretKind,
    pub file_path: String,
    pub line_number: usize,
    pub masked: String,
    pub context: String,
}

struct Pattern {
    kind: SecretKind,
    regex: Regex,
}

static PATTERNS: Lazy<Vec<Pattern>> = Lazy::new(|| {
    let raw: &[(&str, &str)] = &[
        ("aws_access_key", r"AKIA[0-9A-Z]{16}"),
        (
            "aws_secret_key",
            r#"(?i)(?:aws_secret_access_key|AWS_SECRET_ACCESS_KEY)\s*[=:]\s*['"]?([0-9a-zA-Z/+=]{40})['"]?"#,
        ),
        ("github_token", r"gh[pousr]_[A-Za-z0-9_]{36,}"),
        ("openai_key", r"sk-[A-Za-z0-9]{20,}"),
        ("anthropic_key", r"sk-ant-[A-Za-z0-9\-_]{40,}"),
        ("gcp_service_acct", r#""type"\s*:\s*"service_account""#),
        ("slack_token", r"xox[baprs]-[0-9]{10,}-[0-9A-Za-z\-]{10,}"),
        (
            "private_key",
            r"-----BEGIN\s+(?:RSA\s+|EC\s+|OPENSSH\s+)?PRIVATE\s+KEY-----",
        ),
        (
            "generic_api_key",
            r#"(?i)(?:api[_-]?key|apikey)\s*[=:]\s*['"]([A-Za-z0-9_\-]{20,})['"]"#,
        ),
        (
            "generic_secret",
            r#"(?i)(?:secret|token)\s*[=:]\s*['"]([A-Za-z0-9_\-]{20,})['"]"#,
        ),
        (
            "password",
            r#"(?i)(?:password|passwd|pwd)\s*[=:]\s*['"]([^'"]{8,})['"]"#,
        ),
    ];

    let kinds = [
        SecretKind::AwsAccessKey,
        SecretKind::AwsSecretKey,
        SecretKind::GitHubToken,
        SecretKind::OpenAiKey,
        SecretKind::AnthropicKey,
        SecretKind::GcpServiceAccount,
        SecretKind::SlackToken,
        SecretKind::PrivateKey,
        SecretKind::GenericApiKey,
        SecretKind::GenericSecret,
        SecretKind::Password,
    ];

    raw.iter()
        .zip(kinds.into_iter())
        .filter_map(|((_, pat), kind)| Regex::new(pat).ok().map(|regex| Pattern { kind, regex }))
        .collect()
});

pub fn mask(value: &str) -> String {
    if value.len() <= 8 {
        return "*".repeat(value.len());
    }
    let stars = "*".repeat(value.len().saturating_sub(8));
    format!("{}{}{}", &value[..4], stars, &value[value.len() - 4..])
}

pub fn scan_content(content: &str, file_path: &str) -> Vec<SecretFinding> {
    let mut findings = Vec::new();

    for (line_idx, line) in content.lines().enumerate() {
        for pat in PATTERNS.iter() {
            for m in pat.regex.find_iter(line) {
                findings.push(SecretFinding {
                    kind: pat.kind.clone(),
                    file_path: file_path.to_string(),
                    line_number: line_idx + 1,
                    masked: mask(m.as_str()),
                    context: line.to_string(),
                });
            }
        }
    }

    findings
}

pub fn scan_file(path: &Path) -> Vec<SecretFinding> {
    // Cap reads at 16 MiB. Without this, dropping a 10GB file into a watched
    // directory OOM-kills the daemon. Real source files and configs are
    // overwhelmingly under this; anything larger is almost certainly not
    // human-edited text we'd find a secret in.
    const MAX_SCAN_BYTES: u64 = 16 * 1024 * 1024;
    let meta = match fs::metadata(path) {
        Ok(m) => m,
        Err(_) => return vec![],
    };
    if meta.len() > MAX_SCAN_BYTES {
        tracing::debug!(
            path = %path.display(),
            size = meta.len(),
            "Skipping secret scan: file exceeds 16 MiB cap"
        );
        return vec![];
    }
    match crate::fscache::read_to_string(path) {
        Ok(content) => scan_content(&content, &path.to_string_lossy()),
        Err(_) => vec![],
    }
}

/// Quick check: does a single value look like a known secret?
///
/// Hot path — called from `DlpEngine::inspect` for every long token in every
/// outbound payload. Compile the regexes once at process start; recompiling
/// per call was previously a throughput killer (5 fresh `Regex::new` per
/// candidate token × thousands of tokens per request).
pub fn classify(value: &str) -> Option<SecretKind> {
    static CLASSIFIERS: Lazy<Vec<(Regex, SecretKind)>> = Lazy::new(|| {
        let raw: &[(&str, SecretKind)] = &[
            (r"^AKIA[0-9A-Z]{16}$", SecretKind::AwsAccessKey),
            (r"^gh[pousr]_[A-Za-z0-9_]{36,}$", SecretKind::GitHubToken),
            (r"^sk-[A-Za-z0-9]{20,}$", SecretKind::OpenAiKey),
            (r"^sk-ant-[A-Za-z0-9\-_]{40,}$", SecretKind::AnthropicKey),
            (
                r"^xox[baprs]-[0-9]{10,}-[0-9A-Za-z\-]{10,}$",
                SecretKind::SlackToken,
            ),
        ];
        raw.iter()
            .filter_map(|(pat, kind)| Regex::new(pat).ok().map(|r| (r, kind.clone())))
            .collect()
    });

    for (re, kind) in CLASSIFIERS.iter() {
        if re.is_match(value) {
            return Some(kind.clone());
        }
    }
    None
}
