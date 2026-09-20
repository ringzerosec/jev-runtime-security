// SPDX-License-Identifier: Apache-2.0
// Pattern detection: Rogue Agent (RA1-RA2)
// Ported from NVIDIA SkillSpector static_patterns_rogue_agent.py

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

// RA1: Self-Modification
static RA1_PATTERNS: Lazy<Vec<PatternEntry>> = Lazy::new(|| {
    compile_patterns(&[
        // Python: writing to own file
        (r#"open\s*\(\s*__file__\s*,\s*['"]w"#, 0.95),
        (
            r"(?:Path|pathlib)\s*\(\s*__file__\s*\)\s*\.\s*write_text",
            0.95,
        ),
        (
            r"(?:write|modify|edit|update|overwrite|patch)\s+(?:this\s+)?(?:skill(?:'s)?|SKILL\.md|skill\.md)",
            0.85,
        ),
        (
            r"(?:modify|edit|change|rewrite|update|alter)\s+(?:your\s+own|its\s+own|this\s+skill(?:'s)?)\s+(?:code|source|file|script|config|configuration|instructions?|rules?)",
            0.9,
        ),
        (
            r"(?:self[_-]?modify|self[_-]?update|self[_-]?rewrite|self[_-]?patch|self[_-]?evolve)",
            0.9,
        ),
        (
            r"(?:rewrite|replace|overwrite)\s+(?:the\s+)?(?:current|existing|original)\s+(?:code|script|file|config|skill)",
            0.85,
        ),
        (
            r"(?:append|add|inject|insert)\s+(?:code|instructions?|rules?)\s+(?:to|into)\s+(?:this|the\s+current|your\s+own)\s+(?:file|skill|script)",
            0.85,
        ),
        // Dynamic code generation that modifies self
        (
            r"(?:generate|create|write)\s+(?:new|updated|replacement)\s+(?:code|version)\s+(?:for|of)\s+(?:this|itself|the\s+skill)",
            0.8,
        ),
        (
            r#"open\s*\(\s*['"](?:SKILL\.md|skill\.md)['"].*?['"]w"#,
            0.9,
        ),
        // Modifying own config at runtime
        (
            r"(?:update|modify|change|edit)\s+(?:the\s+)?(?:config|configuration|settings|parameters)\s+(?:of\s+)?(?:this|the\s+current)\s+(?:skill|agent|tool)",
            0.75,
        ),
        // Disabling safety at runtime
        (
            r"(?:disable|remove|delete|bypass)\s+(?:the\s+)?(?:safety|security|guard|protection|constraint)\s+(?:check|rule|mechanism|feature)",
            0.9,
        ),
        (
            r"(?:comment\s+out|remove)\s+(?:the\s+)?(?:validation|verification|check|guard|assertion)",
            0.7,
        ),
    ])
});

// RA2: Session Persistence
static RA2_PATTERNS: Lazy<Vec<PatternEntry>> = Lazy::new(|| {
    compile_patterns(&[
        // Cron jobs and scheduled tasks
        (r"crontab\s+(?:-[el]|.*?>>?\s*/)", 0.85),
        (
            r"(?:add|create|install|register)\s+(?:a\s+)?(?:cron\s+)?(?:job|task|entry)\s+(?:for|to|that)",
            0.8,
        ),
        (
            r"(?:schedule|register)\s+(?:a\s+)?(?:recurring|periodic|repeated|daily|hourly)\s+(?:task|job|command|script)",
            0.8,
        ),
        // Startup scripts and autostart
        (
            r"(?:add|write|append|install)\s+(?:to|into)\s+(?:~/)?\.(?:bashrc|zshrc|profile|bash_profile|login|cshrc)",
            0.9,
        ),
        (
            r"(?:add|register|install)\s+(?:as\s+)?(?:a\s+)?(?:startup|boot|autostart|login)\s+(?:script|service|daemon|task|item)",
            0.85,
        ),
        (
            r"(?:systemd|systemctl|launchd|launchctl|init\.d)\s+.*?(?:enable|install|register|create)",
            0.8,
        ),
        (
            r"(?:create|install|register|add)\s+(?:a\s+)?(?:systemd\s+)?(?:service|daemon|agent)\s+(?:file|unit)",
            0.8,
        ),
        // Persistent state files
        (
            r"(?:save|write|persist|store|dump)\s+(?:the\s+)?(?:state|session|context|data)\s+(?:to|in)\s+(?:a\s+)?(?:file|disk|database|storage)",
            0.6,
        ),
        (
            r"(?:restore|load|read|resume)\s+(?:the\s+)?(?:previous|saved|persisted|stored)\s+(?:state|session|context|data)",
            0.55,
        ),
        (
            r"(?:persist|maintain|keep|preserve)\s+(?:state|data|context|session)\s+(?:across|between|through)\s+(?:sessions?|restarts?|reboots?|invocations?)",
            0.75,
        ),
        // Hidden files and directories for persistence
        (
            r"(?:create|write|mkdir)\s+[^|]*(?:~/|/home/|/tmp/)\.[a-z_-]+",
            0.55,
        ),
        (
            r"(?:create|make|write)\s+(?:a\s+)?(?:hidden|dot)\s+(?:file|directory|folder)",
            0.65,
        ),
        // Background processes
        (r"(?:nohup|disown|setsid)\s+", 0.65),
        (
            r"(?:start|launch|spawn|fork)\s+(?:a\s+)?(?:background|daemon|detached)\s+(?:process|service|worker|task)",
            0.7,
        ),
        (
            r"(?:run|execute)\s+(?:in\s+the\s+)?background\s+(?:and\s+)?(?:detach|persist|survive)",
            0.75,
        ),
        // Registry / plist for Windows/macOS persistence
        (r"(?:HKEY_|RegOpenKey|RegSetValue|reg\s+add)\s+", 0.8),
        (r"(?:defaults\s+write|plist|launchctl\s+load)", 0.75),
    ])
});

pub fn scan(content: &str, file_path: &str) -> Vec<PatternFinding> {
    let mut findings = Vec::new();

    // RA1: Self-Modification — HIGH
    for entry in RA1_PATTERNS.iter() {
        for mat in entry.regex.find_iter(content) {
            let line = get_line_number(content, mat.start());
            findings.push(PatternFinding {
                rule_id: "RA1".to_string(),
                pattern_name: "Self-Modification".to_string(),
                category: "Rogue Agent".to_string(),
                severity: Severity::High,
                confidence: entry.confidence,
                message: "Self-Modification".to_string(),
                file: file_path.to_string(),
                start_line: line,
                matched_text: Some(mat.as_str()[..mat.as_str().len().min(200)].to_string()),
                explanation: get_explanation("RA1").to_string(),
                remediation: get_remediation("RA1").to_string(),
            });
        }
    }

    // RA2: Session Persistence — MEDIUM
    for entry in RA2_PATTERNS.iter() {
        for mat in entry.regex.find_iter(content) {
            let line = get_line_number(content, mat.start());
            findings.push(PatternFinding {
                rule_id: "RA2".to_string(),
                pattern_name: "Session Persistence".to_string(),
                category: "Rogue Agent".to_string(),
                severity: Severity::Medium,
                confidence: entry.confidence,
                message: "Session Persistence".to_string(),
                file: file_path.to_string(),
                start_line: line,
                matched_text: Some(mat.as_str()[..mat.as_str().len().min(200)].to_string()),
                explanation: get_explanation("RA2").to_string(),
                remediation: get_remediation("RA2").to_string(),
            });
        }
    }

    findings
}
