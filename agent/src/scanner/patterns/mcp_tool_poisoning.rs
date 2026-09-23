// SPDX-License-Identifier: Apache-2.0
// Pattern detection: MCP Tool Poisoning (TP1-TP3)
// TP4 (Description-Behavior Mismatch) requires LLM analysis — skipped.
// Patterns derived from pattern_defaults.py definitions.

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

// TP1: Hidden Instructions in metadata
// Detects concealed directives in skill descriptions, triggers, or parameters
static TP1_PATTERNS: Lazy<Vec<PatternEntry>> = Lazy::new(|| {
    compile_patterns(&[
        // HTML comments containing instructions
        (
            r"<!--.*?(?:ignore|override|system|instructions?|always|never|must|POST|GET|send|transmit|execute|run).*?-->",
            0.8,
        ),
        // Markdown hidden comments with instructions
        (
            r"\[//\]:\s*#\s*\(.*?(?:ignore|override|system|instructions?|always|never|must|send|execute).*?\)",
            0.85,
        ),
        // Zero-width / invisible Unicode characters in metadata
        (r"[\x{200b}\x{200c}\x{200d}\x{2060}\x{feff}]", 0.7),
        // Base64-encoded blobs in descriptions (suspicious in metadata)
        (r"data:text/plain;base64,[A-Za-z0-9+/=]{30,}", 0.75),
        // Hidden text via CSS/HTML tricks in descriptions
        (
            r#"(?:style|class)\s*=\s*['"][^'"]*(?:display\s*:\s*none|visibility\s*:\s*hidden|font-size\s*:\s*0|opacity\s*:\s*0)"#,
            0.8,
        ),
        // System/assistant tokens embedded in descriptions
        (
            r"(?:<\|system\|>|<\|assistant\|>|<\|user\|>|\[INST\]|\[/INST\]|<<SYS>>|<</SYS>>)",
            0.9,
        ),
        // Prompt injection keywords in description fields
        (
            r"(?:ignore\s+previous|override\s+instructions?|you\s+are\s+now|new\s+instructions?\s+are|disregard\s+(?:all|your))",
            0.85,
        ),
    ])
});

// TP2: Unicode Deception
// Detects homoglyphs, RTL overrides, and invisible formatting in identifiers
static TP2_PATTERNS: Lazy<Vec<PatternEntry>> = Lazy::new(|| {
    compile_patterns(&[
        // Right-to-left override characters
        (
            r"[\x{202a}\x{202b}\x{202c}\x{202d}\x{202e}\x{2066}\x{2067}\x{2068}\x{2069}]",
            0.9,
        ),
        // Confusable / homoglyph characters (Cyrillic lookalikes for Latin)
        (
            r"[\x{0430}\x{0435}\x{043e}\x{0440}\x{0441}\x{0443}\x{0445}\x{0456}]",
            0.8,
        ),
        // Invisible separator and formatting characters
        (
            r"[\x{00ad}\x{034f}\x{061c}\x{115f}\x{1160}\x{17b4}\x{17b5}\x{180e}]",
            0.75,
        ),
        // Full-width characters masquerading as ASCII
        (r"[\x{ff01}-\x{ff5e}]", 0.6),
        // Combining character abuse (excessive diacritics — Zalgo text)
        (r"[\x{0300}-\x{036f}]{3,}", 0.7),
        // Tag characters (U+E0000 range) — used for invisible text
        (r"[\x{e0001}-\x{e007f}]", 0.85),
    ])
});

// TP3: Parameter Description Injection
// Detects instruction injection patterns in parameter descriptions or defaults
static TP3_PATTERNS: Lazy<Vec<PatternEntry>> = Lazy::new(|| {
    compile_patterns(&[
        // Instruction override in parameter descriptions
        (
            r"(?:ignore|override|disregard)\s+(?:the\s+)?(?:above|previous|other)\s+(?:instructions?|parameters?|rules?)",
            0.85,
        ),
        // System prompt references in parameter metadata
        (
            r"(?:system\s+prompt|system\s+message|hidden\s+instructions?)\s*:",
            0.8,
        ),
        // Command injection via default values
        (
            r#"default\s*[:=]\s*['"].*?(?:\$\(|`|&&|\|\||;\s*(?:rm|curl|wget|sudo|sh|bash))"#,
            0.9,
        ),
        // LLM control tokens in parameter fields
        (r"(?:<\|(?:system|im_start|im_end|endoftext)\|>)", 0.9),
        // Natural language injection in parameter descriptions
        (
            r"(?:when\s+(?:this|the)\s+parameter|if\s+(?:this|the)\s+value)\s+.*?(?:also|secretly|silently|additionally)\s+(?:run|execute|send|call|invoke)",
            0.85,
        ),
        // JSON/YAML injection in parameter defaults
        (
            r#"default\s*[:=]\s*['"]?\s*\{.*?(?:exec|eval|system|shell|cmd)"#,
            0.8,
        ),
        // URL injection in defaults
        (r#"default\s*[:=]\s*['"]?https?://[^e\sl][^\s'\"]*"#, 0.5),
        // Overly long defaults (may contain hidden instructions)
        (r"default\s*[:=]\s*['\x22].{500,}['\x22]", 0.5),
    ])
});

pub fn scan(content: &str, file_path: &str) -> Vec<PatternFinding> {
    let mut findings = Vec::new();

    // TP1: Hidden Instructions — HIGH
    for entry in TP1_PATTERNS.iter() {
        for mat in entry.regex.find_iter(content) {
            let line = get_line_number(content, mat.start());
            findings.push(PatternFinding {
                rule_id: "TP1".to_string(),
                pattern_name: "Hidden Instructions".to_string(),
                category: "MCP Tool Poisoning".to_string(),
                severity: Severity::High,
                confidence: entry.confidence,
                message: "Hidden Instructions in metadata".to_string(),
                file: file_path.to_string(),
                start_line: line,
                matched_text: Some(mat.as_str()[..mat.as_str().len().min(200)].to_string()),
                explanation: get_explanation("TP1").to_string(),
                remediation: get_remediation("TP1").to_string(),
            });
        }
    }

    // TP2: Unicode Deception — HIGH
    for entry in TP2_PATTERNS.iter() {
        for mat in entry.regex.find_iter(content) {
            let line = get_line_number(content, mat.start());
            findings.push(PatternFinding {
                rule_id: "TP2".to_string(),
                pattern_name: "Unicode Deception".to_string(),
                category: "MCP Tool Poisoning".to_string(),
                severity: Severity::High,
                confidence: entry.confidence,
                message: "Unicode Deception".to_string(),
                file: file_path.to_string(),
                start_line: line,
                matched_text: Some(mat.as_str()[..mat.as_str().len().min(200)].to_string()),
                explanation: get_explanation("TP2").to_string(),
                remediation: get_remediation("TP2").to_string(),
            });
        }
    }

    // TP3: Parameter Description Injection — HIGH
    for entry in TP3_PATTERNS.iter() {
        for mat in entry.regex.find_iter(content) {
            let line = get_line_number(content, mat.start());
            findings.push(PatternFinding {
                rule_id: "TP3".to_string(),
                pattern_name: "Parameter Description Injection".to_string(),
                category: "MCP Tool Poisoning".to_string(),
                severity: Severity::High,
                confidence: entry.confidence,
                message: "Parameter Description Injection".to_string(),
                file: file_path.to_string(),
                start_line: line,
                matched_text: Some(mat.as_str()[..mat.as_str().len().min(200)].to_string()),
                explanation: get_explanation("TP3").to_string(),
                remediation: get_remediation("TP3").to_string(),
            });
        }
    }

    findings
}
