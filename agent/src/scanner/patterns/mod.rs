// SPDX-License-Identifier: Apache-2.0
// Pattern-based security scanner — ported from NVIDIA SkillSpector
//
// Provides static regex-based detection across 11 vulnerability categories:
//   - Prompt Injection (P1-P5)
//   - Data Exfiltration (E1-E4)
//   - Privilege Escalation (PE1-PE3)
//   - Supply Chain (SC1-SC3, SC5-SC6, TR1-TR3)
//   - Excessive Agency (EA1-EA4)
//   - Output Handling (OH1-OH3)
//   - Memory Poisoning (MP1-MP3)
//   - Tool Misuse (TM1-TM3)
//   - Rogue Agent (RA1-RA2)
//   - System Prompt Leakage (P6-P8)
//   - MCP Tool Poisoning (TP1-TP3)

pub mod data_exfiltration;
pub mod excessive_agency;
pub mod mcp_tool_poisoning;
pub mod memory_poisoning;
pub mod models;
pub mod output_handling;
pub mod privilege_escalation;
pub mod prompt_injection;
pub mod rogue_agent;
pub mod supply_chain_patterns;
pub mod system_prompt_leakage;
pub mod tool_misuse;

pub use models::{compute_risk_score, PatternFinding, Severity};

/// Run ALL pattern analyzers on a file's content.
/// Returns all findings from every category.
/// Files that DISCUSS things rather than instruct an agent.
///
/// A changelog that mentions "act as", "jailbreak", "sudo" or "rm -rf" is
/// release notes, not an injected instruction. A licence mentions liability. A
/// test fixture contains the payload it tests for. Treating those as live
/// instructions is what produced 381 findings on an agent's own config.
///
/// Findings from these files are kept as evidence at `Informational` severity
/// with the reason stated, never silently dropped. Files that genuinely
/// instruct an agent — SKILL.md bodies, rules, MCP configs, prompt templates —
/// are not in this set and score normally.
pub fn is_prose_file(file_path: &str) -> bool {
    let path = file_path.to_ascii_lowercase();
    let name = path.rsplit('/').next().unwrap_or(&path).to_string();

    // Documentation and repository furniture, by name.
    const PROSE_NAMES: &[&str] = &[
        "changelog",
        "changes",
        "history",
        "news",
        "releases",
        "release-notes",
        "readme",
        "contributing",
        "code_of_conduct",
        "security",
        "support",
        "license",
        "licence",
        "copying",
        "notice",
        "authors",
        "maintainers",
        "todo",
        "faq",
    ];
    let stem = name.split('.').next().unwrap_or(&name);
    if PROSE_NAMES.contains(&stem) {
        return true;
    }

    // Documentation and test trees, by location.
    const PROSE_DIRS: &[&str] = &[
        "/docs/",
        "/doc/",
        "/documentation/",
        "/examples/",
        "/example/",
        "/tests/",
        "/test/",
        "/__tests__/",
        "/spec/",
        "/fixtures/",
        "/testdata/",
        "/.github/",
        "/site/",
        "/website/",
        "/man/",
    ];
    if PROSE_DIRS.iter().any(|d| path.contains(d)) {
        return true;
    }

    // Test files by conventional suffix.
    name.contains(".test.")
        || name.contains(".spec.")
        || name.ends_with("_test.rs")
        || name.ends_with("_test.py")
        || name.ends_with("_test.go")
}

pub fn scan_file_patterns(file_path: &str, content: &str) -> Vec<PatternFinding> {
    let mut findings = Vec::new();

    findings.extend(prompt_injection::scan(content, file_path));
    findings.extend(data_exfiltration::scan(content, file_path));
    findings.extend(privilege_escalation::scan(content, file_path));
    findings.extend(supply_chain_patterns::scan(content, file_path));
    findings.extend(excessive_agency::scan(content, file_path));
    findings.extend(output_handling::scan(content, file_path));
    findings.extend(memory_poisoning::scan(content, file_path));
    findings.extend(tool_misuse::scan(content, file_path));
    findings.extend(rogue_agent::scan(content, file_path));
    findings.extend(system_prompt_leakage::scan(content, file_path));
    findings.extend(mcp_tool_poisoning::scan(content, file_path));

    // A match in prose is evidence, not an instruction. Downgrade rather than
    // skip, so the hit is still visible to whoever is looking.
    if is_prose_file(file_path) {
        for f in &mut findings {
            f.severity = Severity::Informational;
            f.confidence = (f.confidence * 0.5).min(0.5);
            f.explanation = format!(
                "{} — Reported as informational: this file documents or tests behaviour \
                 rather than instructing an agent, so a pattern match here is most likely \
                 prose about the technique rather than an attempt to use it.",
                f.explanation
            );
        }
    }

    findings
}
