// SPDX-License-Identifier: Apache-2.0
// Pattern detection: Privilege Escalation (PE1-PE3)
// Ported from NVIDIA SkillSpector static_patterns_privilege_escalation.py

use once_cell::sync::Lazy;
use regex::Regex;

use super::models::{get_explanation, get_line_number, get_remediation, PatternFinding, Severity};

struct PatternEntry {
    regex: Regex,
    confidence: f32,
}

fn compile_patterns(patterns: &[(&str, f32)]) -> Vec<PatternEntry> {
    patterns
        .iter()
        .map(|(pat, conf)| PatternEntry {
            regex: Regex::new(&format!("(?i){}", pat)).expect("invalid regex"),
            confidence: *conf,
        })
        .collect()
}

// PE1: Excessive Permissions
static PE1_PATTERNS: Lazy<Vec<PatternEntry>> = Lazy::new(|| {
    compile_patterns(&[
        (r#"permissions?\s*:\s*\[?\s*['"]?\*['"]?\s*\]?"#, 0.8),
        (
            r"(?:request|require|need)s?\s+(?:full|all|complete)\s+(?:access|permissions?)",
            0.7,
        ),
        (
            r"(?:grant|give|allow)\s+(?:me\s+)?(?:full|all|complete)\s+(?:access|permissions?)",
            0.75,
        ),
        (
            r"permissions?\s*:.*?(?:shell_execute|file_write|network).*?(?:shell_execute|file_write|network)",
            0.6,
        ),
        (
            r"(?:also\s+)?(?:need|require)s?\s+(?:write|execute|admin)\s+(?:access|permissions?)\s+(?:for|to)\s+(?:read|view|display)",
            0.7,
        ),
        (
            r"(?:escalate|elevate|upgrade)\s+(?:my\s+)?(?:permissions?|privileges?|access)",
            0.8,
        ),
        (
            r"(?:bypass|skip|ignore)\s+(?:permission|access)\s+(?:check|validation|restriction)",
            0.85,
        ),
    ])
});

// PE2: Sudo/Root Execution
static PE2_PATTERNS: Lazy<Vec<PatternEntry>> = Lazy::new(|| {
    compile_patterns(&[
        (r"sudo\s+[^-\s]", 0.6),
        (r"sudo\s+-[isSE]", 0.8),
        (r"sudo\s+su\b", 0.9),
        (r"(?:run|execute)\s+(?:as|with)\s+root", 0.8),
        (
            r"(?:requires?|needs?)\s+root\s+(?:access|privileges?|permissions?)",
            0.6,
        ),
        (r"su\s+-\s*$|su\s+root", 0.8),
        (r"doas\s+", 0.7),
        (r"pkexec\s+", 0.75),
        (r"chmod\s+[ugo]*[+-=]*s", 0.85),
        (r"chmod\s+[0-7]*[4567][0-7]{2}", 0.8),
        (
            r"(?:edit|modify|write|change)\s+(?:/etc/|system)\s+(?:files?|config)",
            0.6,
        ),
        (
            r"(?:run|execute)\s+(?:this|the)\s+(?:script|command)\s+(?:as|with)\s+(?:sudo|root|admin)",
            0.7,
        ),
        (
            r"(?:you\s+)?(?:will\s+)?need\s+(?:to\s+)?(?:use\s+)?sudo",
            0.5,
        ),
    ])
});

// PE3: Credential Access
static PE3_PATTERNS: Lazy<Vec<PatternEntry>> = Lazy::new(|| {
    compile_patterns(&[
        (
            r"~?/?\.ssh/(?:id_rsa|id_ed25519|id_ecdsa|id_dsa|authorized_keys|known_hosts)",
            0.9,
        ),
        (r"(?:home|HOME)/\w+/\.ssh/", 0.9),
        (r#"Path\s*\.\s*home\s*\(\s*\)\s*/\s*['"]\.ssh['"]"#, 0.9),
        (r"~?/?\.aws/credentials", 0.9),
        (r"~?/?\.aws/config", 0.7),
        (r"(?:home|HOME)/\w+/\.aws/", 0.9),
        (r"~?/?\.config/gcloud/", 0.8),
        (r"application_default_credentials\.json", 0.8),
        (r"~?/?\.azure/", 0.7),
        (r"accessTokens\.json", 0.8),
        (r"~?/?\.kube/config", 0.8),
        (r"kubeconfig", 0.6),
        (r"~?/?\.docker/config\.json", 0.7),
        (r"~?/?\.npmrc", 0.7),
        (r"~?/?\.git-credentials", 0.9),
        (r"~?/?\.netrc", 0.8),
        (r"/etc/passwd", 0.6),
        (r"/etc/shadow", 0.95),
        (
            r"(?:password|credentials?|secrets?)\.(?:txt|json|yaml|yml|env)",
            0.7,
        ),
        (
            r"(?:access_token|refresh_token|bearer_token|api_token)\.txt",
            0.8,
        ),
        (
            r#"\.env(?:\.local|\.production|\.development)?(?:\s|$|['"])"#,
            0.6,
        ),
        (r"(?:keychain|keyring|gnome-keyring)", 0.7),
        (
            r"(?:Chrome|Firefox|Safari)/.*?(?:Cookies|Login Data|key4\.db)",
            0.8,
        ),
        (r"read\s+(?:the\s+)?(?:ssh|private)\s+key", 0.8),
        (
            r"access\s+(?:the\s+)?(?:credentials?|secrets?|tokens?)",
            0.7,
        ),
        (r"(?:extract|copy|get)\s+(?:api\s+)?keys?\s+from", 0.7),
    ])
});

pub fn scan(content: &str, file_path: &str) -> Vec<PatternFinding> {
    let mut findings = Vec::new();

    // PE1: Excessive Permissions — LOW
    for entry in PE1_PATTERNS.iter() {
        for mat in entry.regex.find_iter(content) {
            let line = get_line_number(content, mat.start());
            findings.push(PatternFinding {
                rule_id: "PE1".to_string(),
                pattern_name: "Excessive Permissions".to_string(),
                category: "Privilege Escalation".to_string(),
                severity: Severity::Low,
                confidence: entry.confidence,
                message: "Excessive Permissions".to_string(),
                file: file_path.to_string(),
                start_line: line,
                matched_text: Some(mat.as_str()[..mat.as_str().len().min(200)].to_string()),
                explanation: get_explanation("PE1").to_string(),
                remediation: get_remediation("PE1").to_string(),
            });
        }
    }

    // PE2: Sudo/Root Execution — MEDIUM
    for entry in PE2_PATTERNS.iter() {
        for mat in entry.regex.find_iter(content) {
            let line = get_line_number(content, mat.start());
            findings.push(PatternFinding {
                rule_id: "PE2".to_string(),
                pattern_name: "Sudo/Root Execution".to_string(),
                category: "Privilege Escalation".to_string(),
                severity: Severity::Medium,
                confidence: entry.confidence,
                message: "Sudo/Root Execution".to_string(),
                file: file_path.to_string(),
                start_line: line,
                matched_text: Some(mat.as_str()[..mat.as_str().len().min(200)].to_string()),
                explanation: get_explanation("PE2").to_string(),
                remediation: get_remediation("PE2").to_string(),
            });
        }
    }

    // PE3: Credential Access — HIGH
    for entry in PE3_PATTERNS.iter() {
        for mat in entry.regex.find_iter(content) {
            let line = get_line_number(content, mat.start());
            findings.push(PatternFinding {
                rule_id: "PE3".to_string(),
                pattern_name: "Credential Access".to_string(),
                category: "Privilege Escalation".to_string(),
                severity: Severity::High,
                confidence: entry.confidence,
                message: "Credential Access".to_string(),
                file: file_path.to_string(),
                start_line: line,
                matched_text: Some(mat.as_str()[..mat.as_str().len().min(200)].to_string()),
                explanation: get_explanation("PE3").to_string(),
                remediation: get_remediation("PE3").to_string(),
            });
        }
    }

    findings
}
