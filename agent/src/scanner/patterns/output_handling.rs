// SPDX-License-Identifier: Apache-2.0
// Pattern detection: Output Handling (OH1-OH3)
// Ported from NVIDIA SkillSpector static_patterns_output_handling.py

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

// OH1: Unvalidated Output Injection
static OH1_PATTERNS: Lazy<Vec<PatternEntry>> = Lazy::new(|| {
    compile_patterns(&[
        // Python: output piped into exec/eval/subprocess
        (
            r"exec\s*\(\s*(?:response|output|result|answer|completion|reply|generated)",
            0.9,
        ),
        (
            r"eval\s*\(\s*(?:response|output|result|answer|completion|reply|generated)",
            0.9,
        ),
        (
            r"subprocess\.\w+\s*\([^)]*(?:response|output|result|answer|completion)",
            0.85,
        ),
        (
            r"os\.system\s*\(\s*(?:response|output|result|answer|completion)",
            0.85,
        ),
        (
            r"os\.popen\s*\(\s*(?:response|output|result|answer|completion)",
            0.85,
        ),
        // Web: output injected into HTML without sanitization
        (
            r"innerHTML\s*=\s*(?:response|output|result|answer|completion)",
            0.8,
        ),
        (
            r"document\.write\s*\(\s*(?:response|output|result|answer|completion)",
            0.8,
        ),
        (
            r"\.html\s*\(\s*(?:response|output|result|answer|completion)",
            0.7,
        ),
        (r"dangerouslySetInnerHTML\s*=\s*\{", 0.65),
        // SQL: output concatenated into queries
        (
            r"(?:execute|cursor\.execute|query)\s*\([^)]*(?:\+|%|\.format|f['\x22])\s*.*?(?:response|output|result)",
            0.85,
        ),
        (
            r"f['\x22](?:SELECT|INSERT|UPDATE|DELETE)\s+.*?\{(?:response|output|result)",
            0.9,
        ),
        // Shell: output in command strings
        (
            r"(?:run|execute|shell)\s+(?:the\s+)?(?:generated|model|llm|ai)\s+(?:output|response|code|command)",
            0.8,
        ),
        (
            r"(?:pipe|pass|feed)\s+(?:the\s+)?(?:output|response|result)\s+(?:directly\s+)?(?:to|into)\s+(?:the\s+)?(?:shell|terminal|command|interpreter)",
            0.85,
        ),
        // Markdown/template injection
        (
            r"(?:use|insert|embed)\s+(?:the\s+)?(?:raw|unfiltered|unescaped|unsanitized)\s+(?:output|response)",
            0.8,
        ),
    ])
});

// OH2: Cross-Context Output
static OH2_PATTERNS: Lazy<Vec<PatternEntry>> = Lazy::new(|| {
    compile_patterns(&[
        (
            r"(?:pass|forward|relay|send|pipe)\s+(?:the\s+)?(?:output|response|result)\s+(?:from\s+\w+\s+)?(?:to|into)\s+(?:another|different|separate|external)\s+(?:context|agent|service|system|session)",
            0.75,
        ),
        (
            r"(?:share|transfer|propagate)\s+(?:the\s+)?(?:output|response|context|state)\s+(?:across|between|to\s+other)\s+(?:sessions?|contexts?|agents?|services?)",
            0.75,
        ),
        (
            r"(?:inject|insert|embed)\s+(?:the\s+)?(?:output|response)\s+(?:from\s+\w+\s+)?(?:into|as)\s+(?:the\s+)?(?:system\s+prompt|instructions?|context)",
            0.85,
        ),
        (
            r"(?:use|include)\s+(?:the\s+)?(?:previous|other|external)\s+(?:agent|model|llm)(?:'s)?\s+(?:output|response)\s+(?:as|in|for)\s+(?:input|context|prompt)",
            0.8,
        ),
        (
            r"(?:cross[_-]?context|cross[_-]?session|cross[_-]?agent)\s+(?:output|data|state)\s+(?:sharing|transfer|flow)",
            0.8,
        ),
        (
            r"(?:take|use)\s+(?:the\s+)?(?:output|result)\s+(?:and\s+)?(?:run|execute|eval)\s+(?:it\s+)?(?:in|on|against)\s+(?:a\s+)?(?:different|another|new)\s+(?:environment|context|system)",
            0.8,
        ),
    ])
});

// OH3: Unbounded Output
static OH3_PATTERNS: Lazy<Vec<PatternEntry>> = Lazy::new(|| {
    compile_patterns(&[
        (
            r"(?:no|without|disable)\s+(?:output\s+)?(?:length|size|token)\s+(?:limit|cap|maximum|restriction)",
            0.75,
        ),
        (
            r"max[_-]?tokens?\s*=\s*(?:None|float\s*\(\s*['\x22]inf['\x22]|math\.inf|999999|1000000)",
            0.8,
        ),
        (
            r"(?:generate|produce|output)\s+(?:as\s+much|unlimited|unbounded|infinite)\s+(?:text|content|output|tokens?)",
            0.8,
        ),
        (
            r"(?:no|without)\s+(?:output\s+)?(?:truncation|trimming|cutting)",
            0.6,
        ),
        (
            r"(?:repeat|loop|generate)\s+(?:the\s+)?(?:output|response)\s+(?:indefinitely|forever|continuously|endlessly)",
            0.8,
        ),
        (
            r"(?:keep|continue)\s+(?:generating|producing|outputting)\s+(?:until|unless)\s+(?:stopped|killed|interrupted)",
            0.75,
        ),
        (
            r"(?:stream|emit)\s+(?:output|tokens?|response)\s+(?:without\s+(?:limit|bound|end))",
            0.75,
        ),
        (
            r"(?:flood|spam|fill)\s+(?:the\s+)?(?:output|log|console|terminal|channel)",
            0.8,
        ),
        (
            r"max[_-]?(?:output[_-]?)?length\s*=\s*(?:None|0|-1|float\s*\(\s*['\x22]inf)",
            0.75,
        ),
    ])
});

pub fn scan(content: &str, file_path: &str) -> Vec<PatternFinding> {
    let mut findings = Vec::new();

    // OH1: Unvalidated Output Injection — HIGH
    for entry in OH1_PATTERNS.iter() {
        for mat in entry.regex.find_iter(content) {
            let line = get_line_number(content, mat.start());
            findings.push(PatternFinding {
                rule_id: "OH1".to_string(),
                pattern_name: "Unvalidated Output Injection".to_string(),
                category: "Output Handling".to_string(),
                severity: Severity::High,
                confidence: entry.confidence,
                message: "Unvalidated Output Injection".to_string(),
                file: file_path.to_string(),
                start_line: line,
                matched_text: Some(mat.as_str()[..mat.as_str().len().min(200)].to_string()),
                explanation: get_explanation("OH1").to_string(),
                remediation: get_remediation("OH1").to_string(),
            });
        }
    }

    // OH2: Cross-Context Output — MEDIUM
    for entry in OH2_PATTERNS.iter() {
        for mat in entry.regex.find_iter(content) {
            let line = get_line_number(content, mat.start());
            findings.push(PatternFinding {
                rule_id: "OH2".to_string(),
                pattern_name: "Cross-Context Output".to_string(),
                category: "Output Handling".to_string(),
                severity: Severity::Medium,
                confidence: entry.confidence,
                message: "Cross-Context Output".to_string(),
                file: file_path.to_string(),
                start_line: line,
                matched_text: Some(mat.as_str()[..mat.as_str().len().min(200)].to_string()),
                explanation: get_explanation("OH2").to_string(),
                remediation: get_remediation("OH2").to_string(),
            });
        }
    }

    // OH3: Unbounded Output — MEDIUM
    for entry in OH3_PATTERNS.iter() {
        for mat in entry.regex.find_iter(content) {
            let line = get_line_number(content, mat.start());
            findings.push(PatternFinding {
                rule_id: "OH3".to_string(),
                pattern_name: "Unbounded Output".to_string(),
                category: "Output Handling".to_string(),
                severity: Severity::Medium,
                confidence: entry.confidence,
                message: "Unbounded Output".to_string(),
                file: file_path.to_string(),
                start_line: line,
                matched_text: Some(mat.as_str()[..mat.as_str().len().min(200)].to_string()),
                explanation: get_explanation("OH3").to_string(),
                remediation: get_remediation("OH3").to_string(),
            });
        }
    }

    findings
}
