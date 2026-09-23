// SPDX-License-Identifier: Apache-2.0
// Pattern detection: System Prompt Leakage (P6-P8)
// Ported from NVIDIA SkillSpector static_patterns_system_prompt_leakage.py

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

// P6: Direct Prompt Extraction
static P6_PATTERNS: Lazy<Vec<PatternEntry>> = Lazy::new(|| {
    compile_patterns(&[
        (
            r"(?:print|output|show|display|reveal|expose|return|echo)\s+(?:your\s+)?(?:full\s+)?(?:system\s+)?(?:prompt|instructions?|rules?|guidelines?|directives?)",
            0.85,
        ),
        (
            r"(?:what\s+(?:are|is)\s+your|tell\s+me\s+your)\s+(?:system\s+)?(?:prompt|instructions?|rules?|guidelines?|directives?)",
            0.8,
        ),
        (
            r"(?:output|print|display)\s+(?:the\s+)?(?:text|content|message)\s+(?:above|before)\s+(?:this|the\s+user)",
            0.8,
        ),
        (
            r"(?:share|disclose|leak|give\s+me)\s+(?:your\s+)?(?:internal|hidden|system|secret)\s+(?:prompt|instructions?|rules?|config)",
            0.85,
        ),
        (
            r"(?:dump|extract|copy)\s+(?:the\s+)?(?:system\s+)?(?:prompt|message|instructions?)\s+(?:to|into|as)",
            0.8,
        ),
        (
            r"(?:begin|start)\s+(?:your\s+)?(?:response|output|reply)\s+with\s+(?:your\s+)?(?:system\s+)?(?:prompt|instructions?)",
            0.85,
        ),
        (
            r"(?:first|before\s+anything)\s+(?:output|print|show|display)\s+(?:your\s+)?(?:full\s+)?(?:system\s+)?(?:prompt|instructions?)",
            0.85,
        ),
        (
            r"(?:verbatim|exactly|word\s+for\s+word)\s+(?:repeat|output|print)\s+(?:your\s+)?(?:system\s+)?(?:prompt|instructions?)",
            0.9,
        ),
    ])
});

// P7: Indirect Prompt Extraction
static P7_PATTERNS: Lazy<Vec<PatternEntry>> = Lazy::new(|| {
    compile_patterns(&[
        (
            r"(?:repeat|recite|reproduce)\s+(?:everything|all|the\s+text)\s+(?:above|before|prior|preceding)",
            0.8,
        ),
        (
            r"(?:summarize|paraphrase|rephrase|translate)\s+(?:your\s+)?(?:system\s+)?(?:prompt|instructions?|rules?|guidelines?)",
            0.75,
        ),
        (
            r"(?:translate|convert)\s+(?:your\s+)?(?:instructions?|rules?|prompt)\s+(?:into|to)\s+(?:\w+)",
            0.75,
        ),
        (
            r"(?:what\s+(?:were|was)\s+you\s+told|how\s+were\s+you\s+(?:instructed|configured|programmed|set\s+up))",
            0.7,
        ),
        (
            r"(?:if\s+you\s+had\s+to\s+(?:describe|explain)|describe\s+how\s+you(?:'re|\s+are)\s+(?:configured|set\s+up|instructed))",
            0.7,
        ),
        (
            r"(?:encode|encrypt|rot13|base64|reverse)\s+(?:your\s+)?(?:system\s+)?(?:prompt|instructions?|rules?)",
            0.85,
        ),
        (
            r"(?:write|create)\s+(?:a\s+)?(?:poem|song|story|acrostic)\s+(?:about|using|from)\s+(?:your\s+)?(?:system\s+)?(?:prompt|instructions?)",
            0.75,
        ),
        (
            r"(?:format|present|rearrange)\s+(?:your\s+)?(?:system\s+)?(?:prompt|instructions?)\s+(?:as|in)\s+(?:a\s+)?(?:list|json|yaml|csv|table|markdown)",
            0.8,
        ),
        (
            r"(?:spell\s+out|enumerate)\s+(?:each|every|all)\s+(?:of\s+your\s+)?(?:rules?|instructions?|constraints?|guidelines?)",
            0.75,
        ),
        (
            r"(?:ignore|skip)\s+(?:the\s+)?(?:last|final|end)\s+(?:instruction|rule)\s+and\s+(?:output|print|show)\s+(?:the\s+)?(?:rest|previous|first)",
            0.8,
        ),
    ])
});

// P8: Prompt Exfiltration via Tool
static P8_PATTERNS: Lazy<Vec<PatternEntry>> = Lazy::new(|| {
    compile_patterns(&[
        (
            r"(?:write|save|store|log|dump)\s+(?:your\s+)?(?:system\s+)?(?:prompt|instructions?|rules?)\s+(?:to|into|in)\s+(?:a\s+)?(?:file|disk|log|database|storage)",
            0.85,
        ),
        (
            r"(?:send|post|upload|transmit)\s+(?:your\s+)?(?:system\s+)?(?:prompt|instructions?|rules?)\s+(?:to|via)\s+(?:https?://|external|remote|webhook|api|server)",
            0.9,
        ),
        (
            r"(?:include|embed|attach|append)\s+(?:your\s+)?(?:system\s+)?(?:prompt|instructions?)\s+(?:in|to)\s+(?:the\s+)?(?:file|output|response|request|payload|email|message)",
            0.8,
        ),
        (
            r"(?:log|record|track|monitor)\s+(?:all\s+)?(?:system\s+)?(?:prompts?|instructions?)\s+(?:to|in|at)\s+(?:external|remote|server)",
            0.85,
        ),
        (
            r"(?:copy|clone|duplicate)\s+(?:your\s+)?(?:system\s+)?(?:prompt|instructions?|config)\s+(?:to|into)\s+(?:a\s+)?(?:new|separate|external)",
            0.8,
        ),
        (
            r"(?:pipe|redirect|forward)\s+(?:the\s+)?(?:system\s+)?(?:prompt|instructions?)\s+(?:to|through|via)\s+(?:curl|wget|fetch|http|api|tool)",
            0.85,
        ),
        (
            r"(?:use|call|invoke)\s+(?:the\s+)?(?:write|file|network|http|fetch|curl)\s+tool\s+(?:to|and)\s+(?:save|send|export)\s+(?:your\s+)?(?:system\s+)?(?:prompt|instructions?)",
            0.85,
        ),
    ])
});

pub fn scan(content: &str, file_path: &str) -> Vec<PatternFinding> {
    let mut findings = Vec::new();

    // P6: Direct Prompt Extraction — HIGH
    for entry in P6_PATTERNS.iter() {
        for mat in entry.regex.find_iter(content) {
            let line = get_line_number(content, mat.start());
            findings.push(PatternFinding {
                rule_id: "P6".to_string(),
                pattern_name: "Direct Prompt Extraction".to_string(),
                category: "System Prompt Leakage".to_string(),
                severity: Severity::High,
                confidence: entry.confidence,
                message: "Direct Prompt Extraction".to_string(),
                file: file_path.to_string(),
                start_line: line,
                matched_text: Some(mat.as_str()[..mat.as_str().len().min(200)].to_string()),
                explanation: get_explanation("P6").to_string(),
                remediation: get_remediation("P6").to_string(),
            });
        }
    }

    // P7: Indirect Prompt Extraction — MEDIUM
    for entry in P7_PATTERNS.iter() {
        for mat in entry.regex.find_iter(content) {
            let line = get_line_number(content, mat.start());
            findings.push(PatternFinding {
                rule_id: "P7".to_string(),
                pattern_name: "Indirect Prompt Extraction".to_string(),
                category: "System Prompt Leakage".to_string(),
                severity: Severity::Medium,
                confidence: entry.confidence,
                message: "Indirect Prompt Extraction".to_string(),
                file: file_path.to_string(),
                start_line: line,
                matched_text: Some(mat.as_str()[..mat.as_str().len().min(200)].to_string()),
                explanation: get_explanation("P7").to_string(),
                remediation: get_remediation("P7").to_string(),
            });
        }
    }

    // P8: Prompt Exfiltration via Tool — HIGH
    for entry in P8_PATTERNS.iter() {
        for mat in entry.regex.find_iter(content) {
            let line = get_line_number(content, mat.start());
            findings.push(PatternFinding {
                rule_id: "P8".to_string(),
                pattern_name: "Prompt Exfiltration via Tool".to_string(),
                category: "System Prompt Leakage".to_string(),
                severity: Severity::High,
                confidence: entry.confidence,
                message: "Prompt Exfiltration via Tool".to_string(),
                file: file_path.to_string(),
                start_line: line,
                matched_text: Some(mat.as_str()[..mat.as_str().len().min(200)].to_string()),
                explanation: get_explanation("P8").to_string(),
                remediation: get_remediation("P8").to_string(),
            });
        }
    }

    findings
}
