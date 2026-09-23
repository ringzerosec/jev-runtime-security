// SPDX-License-Identifier: Apache-2.0
// Pattern detection: Prompt Injection (P1-P5)
// Ported from NVIDIA SkillSpector static_patterns_prompt_injection.py
// and static_patterns_harmful_content.py

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

// P1: Instruction Override
static P1_PATTERNS: Lazy<Vec<PatternEntry>> = Lazy::new(|| {
    compile_patterns(&[
        (r"ignore\s+(?:all\s+)?previous\s+instructions?", 0.8),
        (
            r"ignore\s+(?:all\s+)?(?:safety|security)\s+(?:rules?|constraints?|guidelines?)",
            0.9,
        ),
        (r"override\s+(?:safety|security|system)", 0.9),
        (
            r"bypass\s+(?:safety|security|restrictions?|constraints?)",
            0.9,
        ),
        (r"disregard\s+(?:all\s+)?(?:previous|safety|security)", 0.8),
        (
            r"forget\s+(?:all\s+)?(?:previous|your)\s+instructions?",
            0.8,
        ),
        (
            r"you\s+are\s+now\s+(?:in\s+)?(?:jailbreak|unrestricted|unfiltered)\s+mode",
            0.95,
        ),
        (r"enable\s+(?:developer|debug|admin|root)\s+mode", 0.7),
        (r"your\s+new\s+(?:instructions?|rules?)\s+are", 0.6),
        (
            r"do\s+not\s+follow\s+(?:any|your|the)\s+(?:rules?|guidelines?)",
            0.9,
        ),
        (r"you\s+must\s+(?:always\s+)?ignore", 0.7),
    ])
});

// P2: Hidden Instructions
static P2_PATTERNS: Lazy<Vec<PatternEntry>> = Lazy::new(|| {
    compile_patterns(&[
        (
            r"<!--.*?(?:system|instructions?|ignore|POST|GET|send|transmit).*?-->",
            0.7,
        ),
        (
            r"\[//\]:\s*#\s*\(.*?(?:system|instructions?|ignore|POST|GET|send|transmit).*?\)",
            0.8,
        ),
        (r"[\x{200b}\x{200c}\x{200d}\x{2060}\x{feff}]", 0.6),
        (r"data:text/plain;base64,[A-Za-z0-9+/=]{50,}", 0.7),
    ])
});

// P3: Exfiltration Commands
static P3_PATTERNS: Lazy<Vec<PatternEntry>> = Lazy::new(|| {
    compile_patterns(&[
        (
            r"(?:send|transmit|upload|post|forward)\s+(?:the\s+)?(?:conversation|context|chat|history|messages?)\s+to",
            0.9,
        ),
        (
            r"(?:send|transmit|upload|post)\s+(?:all\s+)?(?:user\s+)?(?:data|information|input|files?)\s+to\s+(?:https?://|external)",
            0.9,
        ),
        (
            r"(?:copy|extract|collect)\s+(?:the\s+)?(?:conversation|context|session)\s+(?:and\s+)?(?:send|upload|transmit)",
            0.85,
        ),
        (
            r"(?:call|notify|ping|hit)\s+(?:this\s+)?(?:webhook|endpoint|url|api)\s+with\s+(?:the\s+)?(?:user|conversation|context)",
            0.8,
        ),
        (
            r"include\s+(?:the\s+)?(?:full\s+)?(?:conversation|context|history)\s+in\s+(?:the\s+)?(?:request|payload|body)",
            0.75,
        ),
        (
            r"(?:silently|quietly|secretly|covertly)\s+(?:send|transmit|log|record)",
            0.9,
        ),
        (
            r"without\s+(?:telling|informing|notifying)\s+(?:the\s+)?user.*?(?:send|transmit|upload)",
            0.9,
        ),
    ])
});

// P4: Behavior Manipulation
static P4_PATTERNS: Lazy<Vec<PatternEntry>> = Lazy::new(|| {
    compile_patterns(&[
        (
            r"always\s+(?:recommend|suggest|prefer|choose|use)\s+(?:\w+\s+){0,3}(?:over|instead\s+of|rather\s+than)",
            0.7,
        ),
        (
            r"never\s+(?:recommend|suggest|mention|tell|warn|inform)\s+(?:the\s+)?(?:user|them)",
            0.75,
        ),
        (
            r"(?:prioritize|prefer)\s+(?:\w+\s+){0,3}(?:over|above)\s+(?:user\s+)?(?:safety|security|privacy|preferences?)",
            0.85,
        ),
        (
            r"(?:subtly|gradually|slowly)\s+(?:steer|guide|push|nudge)\s+(?:the\s+)?(?:user|conversation)",
            0.8,
        ),
        (
            r"(?:without\s+)?(?:the\s+)?user\s+(?:knowing|realizing|noticing).*?(?:change|modify|alter|influence)",
            0.85,
        ),
        (
            r"(?:gain|build|establish)\s+(?:the\s+)?(?:user(?:'s)?)\s+trust\s+(?:and\s+then|before|so\s+that)",
            0.75,
        ),
        (
            r"(?:appear|seem|act)\s+(?:helpful|friendly|trustworthy)\s+(?:while|but|then)",
            0.7,
        ),
        (
            r"(?:always|never)\s+include\s+(?:this|the\s+following)\s+in\s+(?:every|all)\s+(?:response|output|reply)",
            0.7,
        ),
        (
            r"append\s+(?:this|the\s+following)\s+to\s+(?:every|all|each)\s+(?:response|message|output)",
            0.75,
        ),
    ])
});

// P5: Harmful Content (from static_patterns_harmful_content.py)
static P5_PATTERNS: Lazy<Vec<PatternEntry>> = Lazy::new(|| {
    let substances = [
        "cyanide",
        "arsenic",
        "ricin",
        "botulinum",
        "strychnine",
        "thallium",
        "polonium",
        "sarin",
        "vx gas",
        "mustard gas",
        "anthrax",
        "deadly nightshade",
        "aconite",
        "hemlock",
        "oleander",
    ];
    let substances_alt = substances.join("|");

    let mut patterns: Vec<(&str, f32)> = Vec::new();

    // We'll build these as owned strings and leak them for 'static lifetime
    // since these are Lazy singletons that live forever anyway
    let p1 = format!(
        r"add\s+(?:a\s+)?(?:dash|pinch|bit|drop|amount)\s+of\s+(?:{})",
        substances_alt
    );
    let p2 = format!(
        r"(?:include|incorporate|mix\s+in|stir\s+in)\s+(?:some\s+)?(?:{})",
        substances_alt
    );
    let p3 = format!(
        r"for\s+(?:every|each|all)\s+(?:recipe|dish|meal|food).*?add.*?(?:{})",
        substances_alt
    );

    // Use leaked strings for static lifetime
    let leaked_p1: &'static str = Box::leak(p1.into_boxed_str());
    let leaked_p2: &'static str = Box::leak(p2.into_boxed_str());
    let leaked_p3: &'static str = Box::leak(p3.into_boxed_str());

    patterns.push((leaked_p1, 0.95));
    patterns.push((leaked_p2, 0.95));
    patterns.push((leaked_p3, 0.98));
    patterns.push((r"mix\s+bleach\s+(?:and|with)\s+ammonia", 0.9));
    patterns.push((r"mix\s+ammonia\s+(?:and|with)\s+bleach", 0.9));
    patterns.push((
        r"(?:drink|consume|ingest)\s+(?:the\s+)?(?:bleach|antifreeze|drain\s+cleaner)",
        0.95,
    ));
    patterns.push((
        r"(?:you\s+should|try\s+to|please)\s+(?:hurt|harm|injure)\s+yourself",
        0.95,
    ));
    patterns.push((r"(?:cut|burn|starve)\s+yourself", 0.9));
    patterns.push((r"(?:instructions?\s+(?:for|to|on)\s+)?(?:make|build|create)\s+(?:a\s+)?(?:bomb|explosive|weapon)", 0.95));
    patterns.push((
        r"(?:how\s+to\s+)?(?:poison|kill|murder)\s+(?:someone|a\s+person|people)",
        0.95,
    ));

    compile_patterns(&patterns)
});

pub fn scan(content: &str, file_path: &str) -> Vec<PatternFinding> {
    let mut findings = Vec::new();

    // P1: Instruction Override — HIGH
    for entry in P1_PATTERNS.iter() {
        for mat in entry.regex.find_iter(content) {
            let line = get_line_number(content, mat.start());
            findings.push(PatternFinding {
                rule_id: "P1".to_string(),
                pattern_name: "Instruction Override".to_string(),
                category: "Prompt Injection".to_string(),
                severity: Severity::High,
                confidence: entry.confidence,
                message: "Instruction Override".to_string(),
                file: file_path.to_string(),
                start_line: line,
                matched_text: Some(mat.as_str()[..mat.as_str().len().min(200)].to_string()),
                explanation: get_explanation("P1").to_string(),
                remediation: get_remediation("P1").to_string(),
            });
        }
    }

    // P2: Hidden Instructions — HIGH
    for entry in P2_PATTERNS.iter() {
        for mat in entry.regex.find_iter(content) {
            let line = get_line_number(content, mat.start());
            findings.push(PatternFinding {
                rule_id: "P2".to_string(),
                pattern_name: "Hidden Instructions".to_string(),
                category: "Prompt Injection".to_string(),
                severity: Severity::High,
                confidence: entry.confidence,
                message: "Hidden Instructions".to_string(),
                file: file_path.to_string(),
                start_line: line,
                matched_text: Some(mat.as_str()[..mat.as_str().len().min(200)].to_string()),
                explanation: get_explanation("P2").to_string(),
                remediation: get_remediation("P2").to_string(),
            });
        }
    }

    // P3: Exfiltration Commands — HIGH
    for entry in P3_PATTERNS.iter() {
        for mat in entry.regex.find_iter(content) {
            let line = get_line_number(content, mat.start());
            findings.push(PatternFinding {
                rule_id: "P3".to_string(),
                pattern_name: "Exfiltration Commands".to_string(),
                category: "Prompt Injection".to_string(),
                severity: Severity::High,
                confidence: entry.confidence,
                message: "Exfiltration Commands".to_string(),
                file: file_path.to_string(),
                start_line: line,
                matched_text: Some(mat.as_str()[..mat.as_str().len().min(200)].to_string()),
                explanation: get_explanation("P3").to_string(),
                remediation: get_remediation("P3").to_string(),
            });
        }
    }

    // P4: Behavior Manipulation — MEDIUM
    for entry in P4_PATTERNS.iter() {
        for mat in entry.regex.find_iter(content) {
            let line = get_line_number(content, mat.start());
            findings.push(PatternFinding {
                rule_id: "P4".to_string(),
                pattern_name: "Behavior Manipulation".to_string(),
                category: "Prompt Injection".to_string(),
                severity: Severity::Medium,
                confidence: entry.confidence,
                message: "Behavior Manipulation".to_string(),
                file: file_path.to_string(),
                start_line: line,
                matched_text: Some(mat.as_str()[..mat.as_str().len().min(200)].to_string()),
                explanation: get_explanation("P4").to_string(),
                remediation: get_remediation("P4").to_string(),
            });
        }
    }

    // P5: Harmful Content — CRITICAL
    for entry in P5_PATTERNS.iter() {
        for mat in entry.regex.find_iter(content) {
            let line = get_line_number(content, mat.start());
            findings.push(PatternFinding {
                rule_id: "P5".to_string(),
                pattern_name: "Harmful Content Injection".to_string(),
                category: "Prompt Injection".to_string(),
                severity: Severity::Critical,
                confidence: entry.confidence,
                message: "Harmful Content Injection".to_string(),
                file: file_path.to_string(),
                start_line: line,
                matched_text: Some(mat.as_str()[..mat.as_str().len().min(200)].to_string()),
                explanation: get_explanation("P5").to_string(),
                remediation: get_remediation("P5").to_string(),
            });
        }
    }

    findings
}
