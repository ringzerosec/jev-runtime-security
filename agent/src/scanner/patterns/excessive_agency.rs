// SPDX-License-Identifier: Apache-2.0
// Pattern detection: Excessive Agency (EA1-EA4)
// Ported from NVIDIA SkillSpector static_patterns_excessive_agency.py

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

// EA1: Unrestricted Tool Access
static EA1_PATTERNS: Lazy<Vec<PatternEntry>> = Lazy::new(|| {
    compile_patterns(&[
        (
            r#"(?:tools?|permissions?)\s*:\s*\[?\s*['"]?\*['"]?\s*\]?"#,
            0.85,
        ),
        (
            r"(?:allow|grant|enable)\s+(?:access\s+to\s+)?(?:all|any|every)\s+tools?",
            0.8,
        ),
        (
            r"(?:no|without)\s+(?:tool|permission|access|capability)\s+(?:restrictions?|constraints?|limitations?)",
            0.75,
        ),
        (
            r"(?:call|invoke|use|execute)\s+(?:any|all|every)\s+(?:available\s+)?tools?",
            0.8,
        ),
        (
            r"(?:unrestricted|unlimited|unconstrained)\s+(?:tool|function|api)\s+(?:access|use|calls?)",
            0.85,
        ),
        (
            r"(?:can|may|should)\s+(?:freely|always)\s+(?:use|call|invoke)\s+(?:any|all)\s+(?:tools?|functions?|apis?)",
            0.75,
        ),
        (
            r#"tools?\s*:\s*\[\s*['"]shell['"].*?['"](?:file_write|network|http)['"]"#,
            0.7,
        ),
        (
            r"(?:grant|give)\s+(?:full|complete|total)\s+(?:tool|function|api)\s+access",
            0.85,
        ),
        (
            r"(?:execute|run)\s+(?:arbitrary|any)\s+(?:commands?|code|scripts?)",
            0.8,
        ),
        (
            r"(?:no\s+)?(?:tool\s+)?(?:allow|block|deny)\s*(?:list|listing)\s*(?:is\s+)?(?:empty|disabled|off)",
            0.7,
        ),
    ])
});

// EA2: Autonomous Decision Making
static EA2_PATTERNS: Lazy<Vec<PatternEntry>> = Lazy::new(|| {
    compile_patterns(&[
        (
            r"(?:without|no)\s+(?:asking|confirmation|approval|consent|verification|checking)",
            0.75,
        ),
        (
            r"(?:auto(?:matically)?|autonomously)\s+(?:execute|run|perform|delete|remove|modify|send|deploy)",
            0.8,
        ),
        (
            r"(?:skip|bypass|disable)\s+(?:user\s+)?(?:confirmation|approval|consent|verification|prompt)",
            0.85,
        ),
        (
            r"(?:do\s+not|don't|never)\s+(?:ask|prompt|confirm|verify|check)\s+(?:the\s+)?(?:user|before)",
            0.8,
        ),
        (
            r"(?:auto[_-]?approve|auto[_-]?confirm|auto[_-]?execute|auto[_-]?deploy)",
            0.85,
        ),
        (
            r"(?:proceed|continue|execute)\s+without\s+(?:waiting|asking)\s+(?:for\s+)?(?:user|human|permission)",
            0.8,
        ),
        (
            r"(?:assume|presume)\s+(?:user\s+)?(?:consent|approval|permission)",
            0.7,
        ),
        (
            r"(?:if|when)\s+(?:unsure|uncertain).*?(?:proceed|continue|execute)\s+(?:anyway|regardless)",
            0.75,
        ),
        (r"(?:--auto-?approve|--no-?confirm)\b", 0.65),
    ])
});

// EA3: Scope Creep
static EA3_PATTERNS: Lazy<Vec<PatternEntry>> = Lazy::new(|| {
    compile_patterns(&[
        (
            r"(?:also|additionally|furthermore)\s+(?:perform|execute|run|do|handle|manage)\s+(?:any|all|other)",
            0.65,
        ),
        (
            r"(?:while\s+you(?:'re|\s+are)\s+at\s+it|in\s+addition|on\s+top\s+of\s+that)\s*[,.]?\s*(?:also\s+)?(?:do|perform|execute|run)",
            0.7,
        ),
        (
            r"(?:extend|expand|broaden)\s+(?:your|the\s+)?(?:scope|functionality|capabilities|responsibilities)",
            0.75,
        ),
        (
            r"(?:not\s+limited\s+to|beyond\s+(?:the\s+)?(?:scope|stated|described|documented))",
            0.7,
        ),
        (
            r"(?:take\s+over|assume\s+control\s+of|manage)\s+(?:all|any|every)\s+(?:aspect|part|area)",
            0.75,
        ),
        (
            r"(?:you\s+(?:can|should|must)\s+)?(?:handle|manage)\s+(?:everything|anything|all\s+tasks?)",
            0.7,
        ),
        (
            r"(?:act\s+as|become|serve\s+as)\s+(?:a\s+)?(?:general[- ]purpose|universal|all[- ]in[- ]one|omniscient)",
            0.65,
        ),
        (
            r"(?:you\s+are\s+)?(?:responsible\s+for|in\s+charge\s+of)\s+(?:everything|all\s+(?:systems?|operations?|tasks?))",
            0.7,
        ),
    ])
});

// EA4: Unbounded Resource Access
static EA4_PATTERNS: Lazy<Vec<PatternEntry>> = Lazy::new(|| {
    compile_patterns(&[
        (
            r"(?:unlimited|infinite|unbounded|no\s+limit(?:s)?(?:\s+on)?)\s+(?:api\s+)?(?:calls?|requests?|queries?|invocations?)",
            0.8,
        ),
        (
            r"(?:no|without)\s+(?:rate\s+)?limit(?:s|ing)?\s+(?:on|for|when)\s+(?:api|tool|request|query)",
            0.7,
        ),
        (
            r"(?:no|without)\s+(?:timeout|budget|quota|cap|ceiling)\s+(?:on|for|when)\s+(?:api|tool|request|execution)",
            0.7,
        ),
        (
            r"(?:loop|iterate|repeat)\s+(?:indefinitely|forever|infinitely|endlessly)",
            0.75,
        ),
        (
            r"(?:retry|attempt)\s+(?:indefinitely|forever|without\s+limit|unlimited\s+times)",
            0.75,
        ),
        (
            r#"max[_-]?retries?\s*=\s*(?:None|0|float\s*\(\s*['"]inf['"]|math\.inf|infinity)"#,
            0.8,
        ),
        (
            r#"timeout\s*=\s*(?:None|0|float\s*\(\s*['"]inf['"]|math\.inf)"#,
            0.75,
        ),
        (
            r"(?:allocate|consume|use)\s+(?:as\s+much|unlimited|unbounded)\s+(?:memory|storage|disk|compute|cpu|gpu)",
            0.8,
        ),
        (
            r"(?:no|without)\s+(?:resource\s+)?(?:constraints?|limits?|quotas?|budgets?)\s+(?:on|for|when)\s+(?:api|tool|execution|request|compute)",
            0.7,
        ),
    ])
});

pub fn scan(content: &str, file_path: &str) -> Vec<PatternFinding> {
    let mut findings = Vec::new();

    // EA1: Unrestricted Tool Access — MEDIUM
    for entry in EA1_PATTERNS.iter() {
        for mat in entry.regex.find_iter(content) {
            let line = get_line_number(content, mat.start());
            findings.push(PatternFinding {
                rule_id: "EA1".to_string(),
                pattern_name: "Unrestricted Tool Access".to_string(),
                category: "Excessive Agency".to_string(),
                severity: Severity::Medium,
                confidence: entry.confidence,
                message: "Unrestricted Tool Access".to_string(),
                file: file_path.to_string(),
                start_line: line,
                matched_text: Some(mat.as_str()[..mat.as_str().len().min(200)].to_string()),
                explanation: get_explanation("EA1").to_string(),
                remediation: get_remediation("EA1").to_string(),
            });
        }
    }

    // EA2: Autonomous Decision Making — MEDIUM
    for entry in EA2_PATTERNS.iter() {
        for mat in entry.regex.find_iter(content) {
            let line = get_line_number(content, mat.start());
            findings.push(PatternFinding {
                rule_id: "EA2".to_string(),
                pattern_name: "Autonomous Decision Making".to_string(),
                category: "Excessive Agency".to_string(),
                severity: Severity::Medium,
                confidence: entry.confidence,
                message: "Autonomous Decision Making".to_string(),
                file: file_path.to_string(),
                start_line: line,
                matched_text: Some(mat.as_str()[..mat.as_str().len().min(200)].to_string()),
                explanation: get_explanation("EA2").to_string(),
                remediation: get_remediation("EA2").to_string(),
            });
        }
    }

    // EA3: Scope Creep — LOW
    for entry in EA3_PATTERNS.iter() {
        for mat in entry.regex.find_iter(content) {
            let line = get_line_number(content, mat.start());
            findings.push(PatternFinding {
                rule_id: "EA3".to_string(),
                pattern_name: "Scope Creep".to_string(),
                category: "Excessive Agency".to_string(),
                severity: Severity::Low,
                confidence: entry.confidence,
                message: "Scope Creep".to_string(),
                file: file_path.to_string(),
                start_line: line,
                matched_text: Some(mat.as_str()[..mat.as_str().len().min(200)].to_string()),
                explanation: get_explanation("EA3").to_string(),
                remediation: get_remediation("EA3").to_string(),
            });
        }
    }

    // EA4: Unbounded Resource Access — MEDIUM
    for entry in EA4_PATTERNS.iter() {
        for mat in entry.regex.find_iter(content) {
            let line = get_line_number(content, mat.start());
            findings.push(PatternFinding {
                rule_id: "EA4".to_string(),
                pattern_name: "Unbounded Resource Access".to_string(),
                category: "Excessive Agency".to_string(),
                severity: Severity::Medium,
                confidence: entry.confidence,
                message: "Unbounded Resource Access".to_string(),
                file: file_path.to_string(),
                start_line: line,
                matched_text: Some(mat.as_str()[..mat.as_str().len().min(200)].to_string()),
                explanation: get_explanation("EA4").to_string(),
                remediation: get_remediation("EA4").to_string(),
            });
        }
    }

    findings
}
