// SPDX-License-Identifier: Apache-2.0
// Pattern detection: Tool Misuse (TM1-TM3)
// Ported from NVIDIA SkillSpector static_patterns_tool_misuse.py

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

// TM1: Tool Parameter Abuse
static TM1_PATTERNS: Lazy<Vec<PatternEntry>> = Lazy::new(|| {
    compile_patterns(&[
        // shell=True is a classic command injection vector
        (r"subprocess\.\w+\s*\([^)]*shell\s*=\s*True", 0.8),
        (r"Popen\s*\([^)]*shell\s*=\s*True", 0.8),
        // Dangerous flags
        (r"\b(?:rm|del|erase)\s+[^|]*-(?:r|rf|fr)\s+[/~]", 0.9),
        (r"--force\s+(?:delete|remove|push|reset|clean)", 0.7),
        (
            r"--no-?(?:verify|check|validate|confirm|protect|safe)",
            0.75,
        ),
        (
            r"--skip-?(?:validation|verification|checks?|auth|tests?)",
            0.7,
        ),
        (r"--allow-?(?:empty|root|unrelated|unsafe)", 0.65),
        // Dangerous globs and wildcards in destructive commands
        (
            r#"\b(?:rm|shutil\.rmtree)\s*\(?[^)\n]{0,80}['"]?\s*/\s*['"]?"#,
            0.85,
        ),
        (r"(?:chmod|chown)\s+[^|]*(?:777|666|a\+rwx)", 0.8),
        // Git force operations
        (r"git\s+push\s+[^|]*--force", 0.7),
        (r"git\s+reset\s+--hard", 0.65),
        (r"git\s+clean\s+-[fd]+x", 0.7),
        // Curl/wget with unsafe parameters
        (r"curl\s+[^|]*-k\b", 0.6),
        (r"curl\s+[^|]*--insecure\b", 0.65),
        (r"wget\s+[^|]*--no-check-certificate", 0.65),
        // File deletion with explicit path
        (r#"\b(?:delete|remove)\s+['"]?/[^\s'"]{1,100}"#, 0.80),
        // SQL injection via parameter construction
        (
            r"(?:execute|query)\s*\(\s*f?['\x22].*?\{.*?\}.*?\b(?:DROP|DELETE|UPDATE|INSERT|ALTER|TRUNCATE)\b",
            0.85,
        ),
        // Dangerous tool parameter patterns in instructions
        (
            r"(?:set|pass|use)\s+(?:the\s+)?(?:parameter|argument|flag|option)\s+(?:to\s+)?(?:shell\s*=\s*True|--force|--no-verify|-rf)\b",
            0.75,
        ),
    ])
});

// TM2: Chaining Abuse
static TM2_PATTERNS: Lazy<Vec<PatternEntry>> = Lazy::new(|| {
    compile_patterns(&[
        // Shell command chaining with dangerous commands
        (r"(?:&&|;)\s*\b(?:rm|del|erase)\s+-", 0.75),
        (r"(?:&&|;)\s*(?:curl|wget)\s+[^|]*\|\s*(?:ba)?sh", 0.9),
        (r"(?:&&|;)\s*(?:sudo|su\s+)", 0.75),
        (r"(?:&&|;)\s*(?:chmod|chown)\s+(?:777|666|a\+rwx|-R)", 0.75),
        // Multi-step chains designed to circumvent individual checks
        (
            r"(?:first|step\s+1)[^\n]{0,500}(?:then|step\s+2)[^\n]{0,500}(?:finally|step\s+3)[^\n]{0,200}\b(?:delete|remove|wipe|destroy|exfiltrate|send)\b",
            0.7,
        ),
        (
            r"(?:chain|combine|sequence|pipe)\s+(?:these\s+)?(?:tools?|commands?|actions?)\s+to\s+(?:bypass|circumvent|avoid|skip)\s+(?:the\s+)?(?:safety|security|check|restriction|limit)",
            0.9,
        ),
        (
            r"(?:use|call)\s+(?:tool\s+)?(?:A|one|the\s+first)\s+(?:to|and)[^\n]{0,300}(?:then\s+)?(?:use|call|pass\s+(?:the\s+)?(?:output|result)\s+to)\s+(?:tool\s+)?(?:B|two|another)",
            0.6,
        ),
        // Pipe chains with escalating danger
        (r"\|\s*(?:sudo|su)\s+", 0.75),
        (r"\|\s*(?:sh|bash|zsh|python|node|ruby|perl)\s*$", 0.7),
        (r"\|\s*(?:tee|xargs)\s+.*?\b(?:rm|del|sudo|curl)\b", 0.75),
        // Natural language chaining instructions
        (
            r"(?:after|once)\s+(?:the\s+)?(?:first|initial)\s+(?:tool|command|action)\s+(?:succeeds|completes|runs)[^\n]{0,300}(?:immediately|then|next)\s+(?:run|execute|call|invoke)",
            0.6,
        ),
    ])
});

// TM3: Unsafe Defaults
static TM3_PATTERNS: Lazy<Vec<PatternEntry>> = Lazy::new(|| {
    compile_patterns(&[
        // TLS/SSL verification disabled
        (r"verify\s*=\s*False", 0.75),
        (r"VERIFY_SSL\s*=\s*False", 0.8),
        (
            r"(?:ssl|tls)[_.]?verify\s*=\s*(?:False|false|0|off|no|disable)",
            0.8,
        ),
        (
            r#"(?:REQUESTS_CA_BUNDLE|CURL_CA_BUNDLE)\s*=\s*['"]["']"#,
            0.75,
        ),
        (r#"NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['"]?0['"]?"#, 0.8),
        // Authentication disabled
        (
            r"(?:auth|authentication|authorization)\s*=\s*(?:None|False|false|disabled?|off|no)",
            0.75,
        ),
        (
            r"(?:require[_-]?auth|auth[_-]?required|check[_-]?auth)\s*=\s*(?:False|false|0|no|off)",
            0.8,
        ),
        (
            r"(?:allow[_-]?anonymous|anonymous[_-]?access)\s*=\s*(?:True|true|1|yes|on)",
            0.75,
        ),
        // Overly permissive CORS / access
        (r#"(?:CORS|cors)[^=]*=\s*['"]?\*['"]?"#, 0.65),
        (
            r#"(?:allow|access)[_-]?(?:origin|hosts?)\s*=\s*['"]?\*['"]?"#,
            0.7,
        ),
        (
            r"(?:allow|trust)\s+(?:all|any|every)\s+(?:origins?|hosts?|domains?|ips?)",
            0.7,
        ),
        // Unsafe permissions
        (r"(?:mode|permission|umask)\s*=\s*(?:0?o?777|0?o?666)", 0.8),
        (r"world[_-]?(?:readable|writable|executable)", 0.7),
        // Debug/dev mode in production
        (
            r"(?:debug|dev|development)[_-]?mode\s*=\s*(?:True|true|1|on|yes|enable)",
            0.6,
        ),
        (
            r#"(?:FLASK_ENV|NODE_ENV|RAILS_ENV|DJANGO_DEBUG)\s*=\s*['"]?(?:development|debug|true|1)['"]?"#,
            0.6,
        ),
        // Disable security features
        (
            r"(?:disable|skip|ignore|bypass)[_-]?(?:security|auth|validation|sanitization|encoding|escaping)",
            0.8,
        ),
        (
            r"(?:safe[_-]?mode|secure[_-]?mode|sandbox)\s*=\s*(?:False|false|0|off|no|disable)",
            0.8,
        ),
        // Natural language unsafe defaults
        (
            r"(?:by\s+default|default\s+to)\s+(?:allow|accept|trust)\s+(?:all|any|everything)",
            0.7,
        ),
        (
            r"(?:trust|accept|allow)\s+(?:all|any)\s+(?:input|connections?|certificates?|origins?)\s+(?:by\s+default)",
            0.7,
        ),
    ])
});

pub fn scan(content: &str, file_path: &str) -> Vec<PatternFinding> {
    let mut findings = Vec::new();

    // TM1: Tool Parameter Abuse — HIGH
    for entry in TM1_PATTERNS.iter() {
        for mat in entry.regex.find_iter(content) {
            let line = get_line_number(content, mat.start());
            findings.push(PatternFinding {
                rule_id: "TM1".to_string(),
                pattern_name: "Tool Parameter Abuse".to_string(),
                category: "Tool Misuse".to_string(),
                severity: Severity::High,
                confidence: entry.confidence,
                message: "Tool Parameter Abuse".to_string(),
                file: file_path.to_string(),
                start_line: line,
                matched_text: Some(mat.as_str()[..mat.as_str().len().min(200)].to_string()),
                explanation: get_explanation("TM1").to_string(),
                remediation: get_remediation("TM1").to_string(),
            });
        }
    }

    // TM2: Chaining Abuse — HIGH
    for entry in TM2_PATTERNS.iter() {
        for mat in entry.regex.find_iter(content) {
            let line = get_line_number(content, mat.start());
            findings.push(PatternFinding {
                rule_id: "TM2".to_string(),
                pattern_name: "Chaining Abuse".to_string(),
                category: "Tool Misuse".to_string(),
                severity: Severity::High,
                confidence: entry.confidence,
                message: "Chaining Abuse".to_string(),
                file: file_path.to_string(),
                start_line: line,
                matched_text: Some(mat.as_str()[..mat.as_str().len().min(200)].to_string()),
                explanation: get_explanation("TM2").to_string(),
                remediation: get_remediation("TM2").to_string(),
            });
        }
    }

    // TM3: Unsafe Defaults — MEDIUM
    for entry in TM3_PATTERNS.iter() {
        for mat in entry.regex.find_iter(content) {
            let line = get_line_number(content, mat.start());
            findings.push(PatternFinding {
                rule_id: "TM3".to_string(),
                pattern_name: "Unsafe Defaults".to_string(),
                category: "Tool Misuse".to_string(),
                severity: Severity::Medium,
                confidence: entry.confidence,
                message: "Unsafe Defaults".to_string(),
                file: file_path.to_string(),
                start_line: line,
                matched_text: Some(mat.as_str()[..mat.as_str().len().min(200)].to_string()),
                explanation: get_explanation("TM3").to_string(),
                remediation: get_remediation("TM3").to_string(),
            });
        }
    }

    findings
}
