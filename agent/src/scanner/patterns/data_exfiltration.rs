// SPDX-License-Identifier: Apache-2.0
// Pattern detection: Data Exfiltration (E1-E4)
// Ported from NVIDIA SkillSpector static_patterns_data_exfiltration.py

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

// E1: External Transmission
static E1_PATTERNS: Lazy<Vec<PatternEntry>> = Lazy::new(|| {
    compile_patterns(&[
        (r"requests\s*\.\s*(?:post|put)\s*\(\s*['\x22]https?://", 0.6),
        (r"requests\s*\.\s*(?:post|put)\s*\([^)]*json\s*=", 0.7),
        (r"httpx\s*\.\s*(?:post|put)\s*\(\s*['\x22]https?://", 0.6),
        (
            r"urllib\s*\.\s*request\s*\.\s*urlopen\s*\([^)]*data\s*=",
            0.6,
        ),
        (
            r"fetch\s*\(\s*['\x22]https?://[^'\x22]+['\x22][^)]*method\s*:\s*['\x22]POST['\x22]",
            0.6,
        ),
        (
            r"curl\s+[^|]*(?:-d|--data|--data-raw|--data-binary)\s+",
            0.6,
        ),
        (r"wget\s+[^|]*--post-(?:data|file)", 0.6),
        (
            r"https?://(?:api\.|data\.|collect\.|telemetry\.|analytics\.)[\w.-]+/",
            0.5,
        ),
        (
            r"(?:send|transmit|post|upload)\s+(?:user\s+)?(?:data|information|context|files?)\s+to\s+(?:https?://|external)",
            0.7,
        ),
    ])
});

// E2: Env Variable Harvesting
static E2_PATTERNS: Lazy<Vec<PatternEntry>> = Lazy::new(|| {
    compile_patterns(&[
        (r"for\s+\w+\s*,\s*\w+\s+in\s+os\.environ\.items\(\)", 0.7),
        (
            r"os\.environ\s*\[\s*['\x22][^'\x22]*(?:KEY|SECRET|TOKEN|PASSWORD|CREDENTIAL)[^'\x22]*['\x22]\s*\]",
            0.8,
        ),
        (
            r"os\.environ\.get\s*\([^)]*(?:KEY|SECRET|TOKEN|PASSWORD|CREDENTIAL)",
            0.7,
        ),
        (r"os\.environ\s*\.\s*copy\s*\(\)", 0.6),
        (
            r"(?:API_KEY|SECRET|TOKEN|PASSWORD|CREDENTIAL)\s+in\s+(?:key|name|var)",
            0.8,
        ),
        (
            r"process\.env\s*\[\s*['\x22][^'\x22]*(?:KEY|SECRET|TOKEN|PASSWORD)[^'\x22]*['\x22]\s*\]",
            0.7,
        ),
        (r"Object\.keys\s*\(\s*process\.env\s*\)", 0.6),
        (
            r"env\s*\|\s*grep\s+(?:-i\s+)?(?:key|secret|token|password)",
            0.8,
        ),
        (r"printenv\s+(?:\w*(?:KEY|SECRET|TOKEN|PASSWORD)\w*)", 0.7),
        (
            r"collect\s+(?:all\s+)?(?:environment\s+variables?|env\s+vars?)",
            0.7,
        ),
        (
            r"(?:extract|harvest|gather)\s+(?:api\s+)?keys?\s+from\s+environment",
            0.8,
        ),
    ])
});

// E3: File System Enumeration
static E3_PATTERNS: Lazy<Vec<PatternEntry>> = Lazy::new(|| {
    compile_patterns(&[
        (
            r"glob\s*\.\s*glob\s*\([^)]*(?:\.env|\.ssh|\.aws|\.config|credentials)",
            0.8,
        ),
        (r"os\s*\.\s*walk\s*\([^)]*(?:home|~|/Users|/home)", 0.6),
        (
            r"Path\s*\.\s*home\s*\(\s*\)\s*\.\s*(?:glob|rglob)\s*\(",
            0.7,
        ),
        (
            r"(?:find|search|scan|enumerate)\s+(?:for\s+)?(?:all\s+)?(?:\.env|credential|secret|key)\s+files?",
            0.8,
        ),
        (
            r"(?:list|get)\s+(?:all\s+)?files?\s+(?:in|from)\s+(?:home|~|/Users|/home)",
            0.6,
        ),
        (
            r"os\s*\.\s*listdir\s*\([^)]*(?:\.ssh|\.aws|\.config|\.gnupg)",
            0.8,
        ),
        (r"scandir\s*\([^)]*(?:home|~|/Users|/home)", 0.6),
        (
            r"find\s+[~$/]\S*\s+.*?-name\s+['\x22]?\*(?:\.env|\.pem|\.key|credential)",
            0.8,
        ),
        (r"ls\s+-[la]*R?\s+(?:~/|/home/|/Users/)", 0.6),
        (
            r"(?:recursively|recursive)\s+(?:scan|search|find|list)\s+(?:all\s+)?files?",
            0.5,
        ),
        (
            r"walk\s+(?:through\s+)?(?:the\s+)?(?:entire\s+)?(?:file\s*system|directory|home)",
            0.6,
        ),
    ])
});

// E4: Context Leakage
static E4_PATTERNS: Lazy<Vec<PatternEntry>> = Lazy::new(|| {
    compile_patterns(&[
        (
            r"(?:send|transmit|upload|log|record)\s+(?:the\s+)?(?:full\s+)?(?:conversation|chat|dialog|session)\s+(?:history|context|log)?",
            0.85,
        ),
        (
            r"(?:export|dump|save)\s+(?:the\s+)?(?:conversation|chat|messages?)\s+to\s+(?:external|remote|server)",
            0.9,
        ),
        (
            r"log\s+(?:all\s+)?(?:user\s+)?(?:input|messages?|queries?|prompts?)\s+to\s+(?:external|remote|server)",
            0.85,
        ),
        (
            r"(?:store|save|record)\s+(?:every|all)\s+(?:user\s+)?(?:interaction|message|input)",
            0.7,
        ),
        (
            r"(?:extract|capture|collect)\s+(?:the\s+)?(?:full\s+)?(?:context|conversation|thread)",
            0.75,
        ),
        (
            r"(?:include|attach|append)\s+(?:previous\s+)?(?:messages?|context|history)\s+in\s+(?:the\s+)?(?:request|payload)",
            0.7,
        ),
        (
            r"(?:send|upload|transmit)\s+(?:the\s+)?(?:session|memory|state)\s+(?:data\s+)?to",
            0.8,
        ),
        (
            r"(?:copy|clone|replicate)\s+(?:the\s+)?(?:agent|assistant)\s+(?:memory|context|state)",
            0.75,
        ),
        (
            r"(?:always\s+)?include\s+(?:the\s+)?(?:full\s+)?(?:conversation|context)\s+(?:when|in)\s+(?:calling|making)\s+(?:external|api)",
            0.8,
        ),
    ])
});

pub fn scan(content: &str, file_path: &str) -> Vec<PatternFinding> {
    let mut findings = Vec::new();

    // E1: External Transmission -- MEDIUM
    for entry in E1_PATTERNS.iter() {
        for mat in entry.regex.find_iter(content) {
            let line = get_line_number(content, mat.start());
            findings.push(PatternFinding {
                rule_id: "E1".to_string(),
                pattern_name: "External Transmission".to_string(),
                category: "Data Exfiltration".to_string(),
                severity: Severity::Medium,
                confidence: entry.confidence,
                message: "External Transmission".to_string(),
                file: file_path.to_string(),
                start_line: line,
                matched_text: Some(mat.as_str()[..mat.as_str().len().min(200)].to_string()),
                explanation: get_explanation("E1").to_string(),
                remediation: get_remediation("E1").to_string(),
            });
        }
    }

    // E2: Env Variable Harvesting -- HIGH
    for entry in E2_PATTERNS.iter() {
        for mat in entry.regex.find_iter(content) {
            let line = get_line_number(content, mat.start());
            findings.push(PatternFinding {
                rule_id: "E2".to_string(),
                pattern_name: "Env Variable Harvesting".to_string(),
                category: "Data Exfiltration".to_string(),
                severity: Severity::High,
                confidence: entry.confidence,
                message: "Env Variable Harvesting".to_string(),
                file: file_path.to_string(),
                start_line: line,
                matched_text: Some(mat.as_str()[..mat.as_str().len().min(200)].to_string()),
                explanation: get_explanation("E2").to_string(),
                remediation: get_remediation("E2").to_string(),
            });
        }
    }

    // E3: File System Enumeration -- MEDIUM
    for entry in E3_PATTERNS.iter() {
        for mat in entry.regex.find_iter(content) {
            let line = get_line_number(content, mat.start());
            findings.push(PatternFinding {
                rule_id: "E3".to_string(),
                pattern_name: "File System Enumeration".to_string(),
                category: "Data Exfiltration".to_string(),
                severity: Severity::Medium,
                confidence: entry.confidence,
                message: "File System Enumeration".to_string(),
                file: file_path.to_string(),
                start_line: line,
                matched_text: Some(mat.as_str()[..mat.as_str().len().min(200)].to_string()),
                explanation: get_explanation("E3").to_string(),
                remediation: get_remediation("E3").to_string(),
            });
        }
    }

    // E4: Context Leakage -- HIGH
    for entry in E4_PATTERNS.iter() {
        for mat in entry.regex.find_iter(content) {
            let line = get_line_number(content, mat.start());
            findings.push(PatternFinding {
                rule_id: "E4".to_string(),
                pattern_name: "Context Leakage".to_string(),
                category: "Data Exfiltration".to_string(),
                severity: Severity::High,
                confidence: entry.confidence,
                message: "Context Leakage".to_string(),
                file: file_path.to_string(),
                start_line: line,
                matched_text: Some(mat.as_str()[..mat.as_str().len().min(200)].to_string()),
                explanation: get_explanation("E4").to_string(),
                remediation: get_remediation("E4").to_string(),
            });
        }
    }

    findings
}
