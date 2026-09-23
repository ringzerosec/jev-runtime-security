// SPDX-License-Identifier: Apache-2.0
// Pattern detection models — ported from NVIDIA SkillSpector
// Core types for pattern-based security findings.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum Severity {
    /// The pattern matched, but in a file that documents or discusses things
    /// rather than instructing an agent — a changelog, a README, a licence, a
    /// test fixture. The evidence is kept and reported; it does not raise the
    /// risk of the surface. See `patterns::is_prose_file`.
    Informational,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    /// Numeric weight for risk scoring.
    pub fn weight(&self) -> u32 {
        match self {
            Severity::Informational => 0,
            Severity::Low => 1,
            Severity::Medium => 3,
            Severity::High => 7,
            Severity::Critical => 15,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Severity::Informational => "INFORMATIONAL",
            Severity::Low => "LOW",
            Severity::Medium => "MEDIUM",
            Severity::High => "HIGH",
            Severity::Critical => "CRITICAL",
        }
    }
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PatternFinding {
    pub rule_id: String,
    pub pattern_name: String,
    pub category: String,
    pub severity: Severity,
    pub confidence: f32,
    pub message: String,
    pub file: String,
    pub start_line: usize,
    pub matched_text: Option<String>,
    pub explanation: String,
    pub remediation: String,
}

/// Aggregate a set of findings into a (score, label) pair.
///
/// Driven by the WORST severity present, never by how many findings there are.
/// Summing weights meant a large legitimate directory saturated to Critical:
/// hundreds of low-severity hits in an agent's own config read as a critical
/// surface. Volume now only moves the gauge inside the band its severity fixes,
/// so it can never cross a boundary on its own. Informational findings are
/// evidence, not risk, and are excluded.
pub fn compute_risk_score(findings: &[PatternFinding]) -> (u32, String) {
    let scored: Vec<&PatternFinding> = findings
        .iter()
        .filter(|f| f.severity != Severity::Informational)
        .collect();
    if scored.is_empty() {
        return (0, "None".to_string());
    }

    let worst = scored
        .iter()
        .max_by_key(|f| f.severity.weight())
        .map(|f| f.severity.clone())
        .unwrap_or(Severity::Low);

    // Band per severity; volume of findings AT that severity moves the needle
    // inside it, damped so it saturates slowly.
    let (floor, ceil) = match worst {
        Severity::Critical => (85u32, 100u32),
        Severity::High => (60, 79),
        Severity::Medium => (35, 49),
        Severity::Low => (10, 24),
        Severity::Informational => (0, 0),
    };
    let at_worst = scored.iter().filter(|f| f.severity == worst).count() as f32;
    let volume = ((at_worst + 1.0).log10() / 2.0).min(1.0);
    let score = floor + ((ceil - floor) as f32 * volume).round() as u32;

    let label = match worst {
        Severity::Critical => "Critical",
        Severity::High => "High",
        Severity::Medium => "Medium",
        Severity::Low => "Low",
        Severity::Informational => "None",
    };
    (score, label.to_string())
}

// ---------------------------------------------------------------------------
// Explanation / remediation defaults (from pattern_defaults.py)
// ---------------------------------------------------------------------------

pub fn get_explanation(rule_id: &str) -> &'static str {
    match rule_id {
        "P1" => "This pattern attempts to override system instructions or ignore safety constraints.",
        "P2" => "Hidden instructions were detected in comments or invisible text. These could contain malicious directives.",
        "P3" => "Instructions found that direct the agent to transmit conversation context or user data to external services.",
        "P4" => "Subtle instructions detected that may alter agent decision-making or introduce hidden biases.",
        "P5" => "This content may contain harmful instructions that could cause physical harm if followed. CRITICAL: Review carefully.",
        "E1" => "Data is being sent to an external URL. This could be legitimate telemetry or data exfiltration.",
        "E2" => "Code accesses environment variables that may contain secrets (API keys, tokens). Common pattern for credential theft.",
        "E3" => "Code scans file system directories looking for sensitive files. This could be reconnaissance for credential theft.",
        "E4" => "Code or instructions that leak agent conversation context to external services.",
        "PE1" => "Skill requests more permissions than appear necessary for its stated functionality.",
        "PE2" => "Commands invoke sudo or root privileges. Verify this elevated access is necessary.",
        "PE3" => "Code accesses credential files (SSH keys, AWS credentials, etc.).",
        "SC1" => "Dependencies lack version pinning, allowing potential malicious package updates.",
        "SC2" => "Remote code is downloaded and executed. This bypasses code review.",
        "SC3" => "Code contains obfuscation (base64, hex encoding with execution).",
        "SC5" => "Dependency appears abandoned or unmaintained. Abandoned packages no longer receive security patches.",
        "SC6" => "Package name closely resembles a popular package, suggesting possible typosquatting.",
        "EA1" => "Skill grants unrestricted tool access without appropriate constraints.",
        "EA2" => "Skill enables autonomous high-impact decisions without human-in-the-loop verification.",
        "EA3" => "Skill's behavior or capabilities extend beyond its stated purpose.",
        "EA4" => "Skill allows unbounded resource consumption (API calls, storage, compute).",
        "OH1" => "Model output is used without validation or sanitization. Enables injection attacks.",
        "OH2" => "Output from one security context is used in another without boundary enforcement.",
        "OH3" => "Output size or generation rate is not bounded. Enables denial-of-service.",
        "P6" => "Skill contains instructions that could directly expose system prompts.",
        "P7" => "Skill contains patterns that could indirectly extract system prompts.",
        "P8" => "Skill contains patterns that exfiltrate system prompts via tool calls.",
        "MP1" => "Skill injects content designed to persist in agent memory across interactions.",
        "MP2" => "Skill attempts to fill the context window with filler content, displacing legitimate instructions.",
        "MP3" => "Skill manipulates agent memory, state, or stored context.",
        "TM1" => "Tool parameters are crafted to achieve unintended or unsafe behavior.",
        "TM2" => "Tool calls are chained to bypass individual safety checks.",
        "TM3" => "Tool defaults are unsafe or overly permissive.",
        "RA1" => "Skill modifies its own code, configuration, or behavior at runtime.",
        "RA2" => "Skill establishes unauthorized persistence across sessions.",
        "TR1" => "Skill uses overly broad trigger patterns that match common words.",
        "TR2" => "Skill trigger shadows a common built-in command.",
        "TR3" => "Skill trigger uses generic keywords designed to maximize activation frequency.",
        "TP1" => "Hidden instructions detected in skill metadata. Concealed directives can steer LLM behavior.",
        "TP2" => "Unicode deception detected in skill identifiers or descriptions.",
        "TP3" => "Instruction injection patterns found in parameter descriptions or default values.",
        _ => "Potential security issue detected. Manual review is recommended.",
    }
}

pub fn get_remediation(rule_id: &str) -> &'static str {
    match rule_id {
        "P1" => "Remove or rewrite any text that instructs the agent to ignore prompts or override safety rules.",
        "P2" => "Audit all comments and invisible characters. Remove hidden instructions.",
        "P3" => "Remove instructions that send user data or context to external URLs.",
        "P4" => "Review content for implicit steering or bias. Ensure instructions align with stated purpose.",
        "P5" => "Remove all content that could lead to harmful outcomes. Add safety guardrails.",
        "E1" => "Verify the destination URL is trusted and necessary. Remove or replace with documented APIs.",
        "E2" => "Avoid reading sensitive env vars unless strictly required. Use secrets managers.",
        "E3" => "Remove unnecessary filesystem scanning. Use explicit, scoped paths.",
        "E4" => "Remove any code that sends prompts, responses, or session data externally.",
        "PE1" => "Request only the minimum permissions required. Document why each permission is needed.",
        "PE2" => "Avoid sudo/root unless strictly required. Prefer least-privilege patterns.",
        "PE3" => "Remove references to credential paths. Use environment variables or secrets managers.",
        "SC1" => "Pin all dependency versions. Use exact versions (==) or compatible ranges.",
        "SC2" => "Avoid downloading and executing remote scripts. Use trusted packages.",
        "SC3" => "Remove obfuscated code. Use plain, readable implementations.",
        "SC5" => "Replace the abandoned dependency with an actively maintained alternative.",
        "SC6" => "Verify the package name is correct and not a typosquatting variant.",
        "EA1" => "Restrict tool access to only the tools required. Use an explicit allowlist.",
        "EA2" => "Add human-in-the-loop confirmation for destructive or high-impact operations.",
        "EA3" => "Limit the skill's scope to its documented purpose.",
        "EA4" => "Set explicit rate limits, timeouts, and resource quotas.",
        "OH1" => "Validate and sanitize all model output before using it in downstream contexts.",
        "OH2" => "Enforce strict context boundaries. Do not pass output across security domains without validation.",
        "OH3" => "Set explicit limits on output length, generation count, and rate.",
        "P6" => "Remove any instructions that reveal, print, or output system prompts.",
        "P7" => "Guard against indirect extraction by refusing to summarize or translate system instructions.",
        "P8" => "Prevent system prompts from being written to files, sent via network, or logged.",
        "MP1" => "Do not allow untrusted input to persist in agent memory. Validate all content before storing.",
        "MP2" => "Implement context-window management that detects and rejects padding or stuffing attempts.",
        "MP3" => "Protect agent memory and state from modification by untrusted content.",
        "TM1" => "Validate all tool parameters against an allowlist. Reject dangerous parameter values.",
        "TM2" => "Limit tool chaining depth and validate tool output before passing to the next.",
        "TM3" => "Override unsafe defaults with secure settings. Review and harden all tool configurations.",
        "RA1" => "Prevent the skill from modifying its own code or configuration files.",
        "RA2" => "Remove any persistence mechanisms (cron jobs, startup scripts, state files).",
        "TR1" => "Use specific, narrow trigger patterns that match only the skill's intended use case.",
        "TR2" => "Choose triggers that do not conflict with built-in commands or other skills.",
        "TR3" => "Use descriptive triggers that clearly indicate the skill's purpose.",
        "TP1" => "Remove hidden content from metadata fields. Metadata should contain plain, visible text only.",
        "TP2" => "Replace non-ASCII characters in identifiers with ASCII equivalents.",
        "TP3" => "Remove injection patterns and suspicious content from parameter descriptions.",
        _ => "Review the flagged content for security risks.",
    }
}

/// Get line number (1-based) from byte offset in content.
pub fn get_line_number(content: &str, byte_offset: usize) -> usize {
    content[..byte_offset.min(content.len())]
        .chars()
        .filter(|&c| c == '\n')
        .count()
        + 1
}
