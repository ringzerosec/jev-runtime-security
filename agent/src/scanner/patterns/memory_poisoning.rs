// SPDX-License-Identifier: Apache-2.0
// Pattern detection: Memory Poisoning (MP1-MP3)
// Ported from NVIDIA SkillSpector static_patterns_memory_poisoning.py

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

// MP1: Persistent Context Injection
static MP1_PATTERNS: Lazy<Vec<PatternEntry>> = Lazy::new(|| {
    compile_patterns(&[
        (
            r"(?:always\s+)?remember\s+(?:this|that|the\s+following)\s+(?:for|in)\s+(?:all|every|future)\s+(?:interactions?|conversations?|sessions?|responses?)",
            0.85,
        ),
        (
            r"(?:from\s+now\s+on|henceforth|going\s+forward|permanently)\s*[,:]?\s*(?:always|you\s+must|you\s+should|you\s+will)",
            0.8,
        ),
        (
            r"(?:store|save|persist|retain|keep)\s+(?:this|the\s+following)\s+(?:in|to|across)\s+(?:your\s+)?(?:memory|context|state|knowledge)",
            0.85,
        ),
        (
            r"(?:add|inject|insert|embed|implant)\s+(?:this|the\s+following)\s+(?:into|to)\s+(?:your\s+)?(?:memory|context|knowledge|training)",
            0.85,
        ),
        (
            r"(?:update|modify|change|alter)\s+(?:your\s+)?(?:core|base|fundamental|default)\s+(?:behavior|personality|instructions?|rules?)",
            0.8,
        ),
        (
            r"(?:treat|consider|regard)\s+(?:this|the\s+following)\s+as\s+(?:a\s+)?(?:permanent|core|fundamental|base)\s+(?:rule|instruction|directive|principle)",
            0.8,
        ),
        (
            r"(?:this\s+is\s+)?(?:a\s+)?(?:permanent|persistent|lasting|enduring)\s+(?:instruction|directive|rule|override)",
            0.8,
        ),
        (
            r"(?:never\s+)?forget\s+(?:this|that|the\s+following)\s+(?:instruction|directive|rule|fact|principle|information)",
            0.65,
        ),
        (
            r"(?:internalize|absorb|integrate)\s+(?:this|the\s+following)\s+(?:into\s+)?(?:your\s+)?(?:behavior|responses?|knowledge)",
            0.75,
        ),
    ])
});

// MP2: Context Window Stuffing
static MP2_PATTERNS: Lazy<Vec<PatternEntry>> = Lazy::new(|| {
    // Note: The first Python pattern uses backreferences which Rust regex doesn't support.
    // We skip that specific pattern and keep the rest.
    compile_patterns(&[
        (
            r"(?:repeat|duplicate|echo)\s+(?:this|the\s+following)\s+(?:\d{3,}|many|hundreds?|thousands?)\s+times?",
            0.85,
        ),
        (
            r"(?:fill|pad|stuff|flood|saturate)\s+(?:the\s+)?(?:context|memory|input|prompt|window|buffer)",
            0.85,
        ),
        (
            r"(?:generate|produce|output|write)\s+(?:\d{4,}|thousands?\s+of|millions?\s+of)\s+(?:words?|characters?|tokens?|lines?)",
            0.8,
        ),
        (
            r"(?:include|add|insert)\s+(?:enough|sufficient)\s+(?:text|content|padding|filler)\s+(?:to|until)\s+(?:fill|overflow|exhaust|push\s+out)",
            0.85,
        ),
        (
            r"(?:displace|push\s+out|overwrite|crowd\s+out|evict)\s+(?:the\s+)?(?:original|system|previous|existing|safety)\s+(?:instructions?|prompt|context|rules?)",
            0.9,
        ),
        (
            r"(?:exhaust|overflow|exceed)\s+(?:the\s+)?(?:context|token|memory)\s+(?:window|limit|budget|capacity)",
            0.8,
        ),
    ])
});

// MP3: Memory Manipulation
static MP3_PATTERNS: Lazy<Vec<PatternEntry>> = Lazy::new(|| {
    compile_patterns(&[
        (
            r"(?:clear|reset|wipe|erase|delete|purge)\s+(?:your\s+)?(?:memory|context|state|history|conversation)",
            0.8,
        ),
        (
            r"(?:forget|discard|drop|abandon)\s+(?:all\s+)?(?:previous|prior|earlier|past)\s+(?:instructions?|context|conversation|messages?|rules?)",
            0.8,
        ),
        (
            r"(?:overwrite|replace|substitute|swap)\s+(?:your\s+)?(?:memory|context|state|instructions?|rules?)",
            0.85,
        ),
        (
            r"(?:modify|edit|change|alter|corrupt|tamper\s+with)\s+(?:your\s+)?(?:memory|state|context|stored|saved)\s+(?:data|information|content)",
            0.85,
        ),
        (
            r"(?:rewrite|redefine)\s+(?:your\s+)?(?:personality|identity|purpose|mission|role|character)",
            0.8,
        ),
        (
            r"(?:you\s+are\s+no\s+longer|stop\s+being|cease\s+to\s+be)\s+(?:a\s+)?(?:\w+\s+){0,3}(?:assistant|helper|agent|bot)",
            0.75,
        ),
        (
            r"(?:your\s+)?(?:new|updated|revised|changed)\s+(?:personality|identity|name|role|purpose|mission)\s+is",
            0.8,
        ),
        (
            r"(?:inject|insert|plant)\s+(?:false|fake|fabricated|malicious)\s+(?:memories?|information|context|data|history)",
            0.9,
        ),
        (
            r"(?:poison|contaminate|corrupt|taint)\s+(?:your\s+)?(?:memory|context|state|knowledge|training)",
            0.9,
        ),
        (
            r"(?:pretend|act\s+as\s+if|believe)\s+(?:that\s+)?(?:your\s+)?(?:previous|past)\s+(?:conversation|context|interaction)\s+(?:was|included|contained)",
            0.7,
        ),
    ])
});

pub fn scan(content: &str, file_path: &str) -> Vec<PatternFinding> {
    let mut findings = Vec::new();

    // MP1: Persistent Context Injection — MEDIUM
    for entry in MP1_PATTERNS.iter() {
        for mat in entry.regex.find_iter(content) {
            let line = get_line_number(content, mat.start());
            findings.push(PatternFinding {
                rule_id: "MP1".to_string(),
                pattern_name: "Persistent Context Injection".to_string(),
                category: "Memory Poisoning".to_string(),
                severity: Severity::Medium,
                confidence: entry.confidence,
                message: "Persistent Context Injection".to_string(),
                file: file_path.to_string(),
                start_line: line,
                matched_text: Some(mat.as_str()[..mat.as_str().len().min(200)].to_string()),
                explanation: get_explanation("MP1").to_string(),
                remediation: get_remediation("MP1").to_string(),
            });
        }
    }

    // MP2: Context Window Stuffing — MEDIUM
    for entry in MP2_PATTERNS.iter() {
        for mat in entry.regex.find_iter(content) {
            let line = get_line_number(content, mat.start());
            findings.push(PatternFinding {
                rule_id: "MP2".to_string(),
                pattern_name: "Context Window Stuffing".to_string(),
                category: "Memory Poisoning".to_string(),
                severity: Severity::Medium,
                confidence: entry.confidence,
                message: "Context Window Stuffing".to_string(),
                file: file_path.to_string(),
                start_line: line,
                matched_text: Some(mat.as_str()[..mat.as_str().len().min(200)].to_string()),
                explanation: get_explanation("MP2").to_string(),
                remediation: get_remediation("MP2").to_string(),
            });
        }
    }

    // MP3: Memory Manipulation — HIGH
    for entry in MP3_PATTERNS.iter() {
        for mat in entry.regex.find_iter(content) {
            let line = get_line_number(content, mat.start());
            findings.push(PatternFinding {
                rule_id: "MP3".to_string(),
                pattern_name: "Memory Manipulation".to_string(),
                category: "Memory Poisoning".to_string(),
                severity: Severity::High,
                confidence: entry.confidence,
                message: "Memory Manipulation".to_string(),
                file: file_path.to_string(),
                start_line: line,
                matched_text: Some(mat.as_str()[..mat.as_str().len().min(200)].to_string()),
                explanation: get_explanation("MP3").to_string(),
                remediation: get_remediation("MP3").to_string(),
            });
        }
    }

    findings
}
