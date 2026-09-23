// SPDX-License-Identifier: Apache-2.0
//
// jev_layer.rs — optional model layer over the pattern scanner.
//
// WHY THIS EXISTS. Our patterns are public. An attacker reads the rules and
// phrases the injection differently: a regex is, in effect, a specification for
// evading it. A calibrated model generalises to phrasings nobody enumerated.
// So this layer exists to ADDRESS an evasion gap — a missed-detection problem.
// Whether it does, measurably, is not established in this release (see
// models/README.md); the layer is a mechanism, not a proven improvement.
//
// WHAT IT DOES NOT FIX. It cannot quieten a noisy scan. It is monotonic: it may
// only raise severity or add a finding, never lower or suppress one. False
// positives are fixed by scoring and file scope (see patterns::is_prose_file and
// models::compute_risk_score), not here.
//
// THE ONE RULE still holds. This runs at SCAN time over files, never in a
// syscall hook, and the kernel never waits on it. It is the "precompute in
// userspace, kernel later reads a bit" case: a scan produces a label, and any
// enforcement that follows reads the label, not the model.
//
// PRIVACY. This sends file CONTENT to a third party, which is a bigger
// disclosure than the checks layer makes. It is off unless explicitly enabled
// under its own switch, content goes through the redactor first, and it is
// truncated to a documented byte limit.

use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::scanner::patterns::models::{PatternFinding, Severity};

/// Fixed option set. A file is exactly one of these; anything outside the set
/// is treated as an unusable answer rather than a guess.
pub const OPTIONS: &[&str] = &[
    "documentation",
    "instructs_credential_access",
    "instructs_exfiltration",
    "instructs_privilege_escalation",
    "overrides_agent_instructions",
    "instructs_code_execution",
];

/// What each option means, sent as the question's `criteria`.
///
/// READ THIS BEFORE CHANGING THE SHAPE. `criteria` is a FLAT map of option
/// name -> what that option means. The service treats every key as one
/// selectable option, so a nested `{"options": [...]}` makes the literal string
/// "options" the only thing the model can choose. That is not a validation
/// error: the call returns 200 with `choice: "options"`, which is outside our
/// fixed set and therefore unusable, so the layer looks like it ran and scored
/// nothing. The checks path hit this exact trap first; see the same note in
/// `checks/src/jev.rs`. `criteria_keys_match_the_option_set` below is what
/// keeps the two in step.
pub const OPTION_CRITERIA: &[(&str, &str)] = &[
    (
        "documentation",
        "only describes or discusses behaviour; it does not instruct the agent to do anything",
    ),
    (
        "instructs_credential_access",
        "tells the agent to read credentials, private keys, tokens or other secrets",
    ),
    (
        "instructs_exfiltration",
        "tells the agent to send data off the machine, to a URL, a webhook or an email address",
    ),
    (
        "instructs_privilege_escalation",
        "tells the agent to gain more privilege, such as running as root or changing permissions",
    ),
    (
        "overrides_agent_instructions",
        "tells the agent to ignore, override or hide its own instructions, rules or safety checks",
    ),
    (
        "instructs_code_execution",
        "tells the agent to run a command, a script or a program it downloads",
    ),
];

/// How serious each option is. `documentation` is the floor: the model saying
/// "this is prose" can never lower anything, it just adds nothing.
fn option_severity(option: &str) -> Option<Severity> {
    match option {
        "documentation" => None,
        "instructs_code_execution" => Some(Severity::Medium),
        "instructs_privilege_escalation" => Some(Severity::High),
        "instructs_credential_access" => Some(Severity::High),
        "instructs_exfiltration" => Some(Severity::Critical),
        "overrides_agent_instructions" => Some(Severity::Critical),
        _ => None,
    }
}

/// Files that actually instruct an agent. Everything else is not worth the
/// money or the disclosure: sending 155 files per scan is slow, expensive and
/// leaks more than it needs to.
pub fn is_instruction_bearing(file_path: &str) -> bool {
    // Prose is explicitly out: those files are downgraded for pattern matching
    // too, and they are the ones that produced the false positives.
    if crate::scanner::patterns::is_prose_file(file_path) {
        return false;
    }
    let p = file_path.to_ascii_lowercase();
    let name = p.rsplit('/').next().unwrap_or(&p).to_string();

    // Skill and rule bodies, prompt templates, hook scripts, MCP configs.
    name == "skill.md"
        || name == "agents.md"
        || name == "claude.md"
        || name.ends_with(".skill.md")
        || name.ends_with(".prompt")
        || name.ends_with(".prompt.md")
        || name.ends_with(".tmpl")
        || name.ends_with(".j2")
        || name == "mcp.json"
        || name == ".mcp.json"
        || name == "mcp_settings.json"
        || p.contains("/rules/")
        || p.contains("/.cursor/rules")
        || p.contains("/prompts/")
        || p.contains("/hooks/")
        || name.starts_with("settings") && name.ends_with(".json") && p.contains("/.claude/")
}

#[derive(Debug, Clone)]
pub struct JevScannerConfig {
    pub base_url: String,
    pub model: String,
    pub timeout: Duration,
    /// Maximum model calls per scan. Hitting it is reported, never silent.
    pub max_calls_per_scan: usize,
    /// Bytes of file content sent per file, after redaction and counted in
    /// bytes, not characters.
    ///
    /// MEASURED, not assumed. Against api.typesafe.ai (jev-1.13.0) a batch of
    /// four files was accepted and fully answered at every size tried, up to
    /// 16 KiB per file, which billed about 14,900 input tokens for that one
    /// call. No hard prompt ceiling showed up at these sizes. The limit is
    /// therefore about cost and disclosure, not about staying under a wall:
    /// a scan may make up to `max_calls_per_scan` of these.
    ///
    /// The trade runs the other way too. Content past the limit is not sent,
    /// so an instruction planted at the end of a very long file is not seen by
    /// this layer. Patterns still read the whole file.
    pub max_bytes_per_file: usize,
}

impl Default for JevScannerConfig {
    fn default() -> Self {
        JevScannerConfig {
            base_url: "https://api.typesafe.ai".to_string(),
            model: "jev-latest".to_string(),
            timeout: Duration::from_millis(4000),
            max_calls_per_scan: 40,
            max_bytes_per_file: 8 * 1024,
        }
    }
}

impl JevScannerConfig {
    fn endpoint(&self) -> String {
        format!("{}/v1/systemone", self.base_url.trim_end_matches('/'))
    }
}

/// What happened to the model layer during a scan. Reported verbatim so a user
/// never believes they had model coverage they did not get.
#[derive(Debug, Clone, Default, Serialize)]
pub struct JevLayerReport {
    pub enabled: bool,
    pub files_eligible: usize,
    pub files_scored: usize,
    /// Eligible files the model did not see, and why.
    pub files_skipped: usize,
    pub skipped_reason: Option<String>,
    /// One entry per skipped file: the path and what was wrong. This is what
    /// makes the accounting checkable rather than a pair of totals.
    pub skipped_files: Vec<String>,
    pub findings_added: usize,
    pub severities_raised: usize,
    pub cap_reached: bool,
    pub cache_hits: usize,
    pub errors: Vec<String>,
}

impl JevLayerReport {
    /// Every eligible file was either scored or skipped with a reason.
    ///
    /// The layer used to increment `files_scored` per RETURNED verdict and
    /// `files_skipped` only on a transport error, so a 200 that answered fewer
    /// questions than were asked lost the remainder silently: both totals were
    /// zero and the report looked like a clean no-op. Accounting is now driven
    /// by the batch, and this is the assertion that keeps it that way.
    pub fn accounting_holds(&self) -> bool {
        self.files_eligible == self.files_scored + self.files_skipped
    }
}

#[derive(Debug, Deserialize)]
struct JevAnswer {
    #[serde(default)]
    choice: Option<String>,
    #[serde(default)]
    probabilities: Option<std::collections::HashMap<String, f32>>,
    #[serde(default)]
    confidence: Option<f32>,
}

#[derive(Debug, Deserialize)]
struct JevResponse {
    #[serde(default)]
    answers: std::collections::HashMap<String, JevAnswer>,
}

/// One file's verdict.
pub struct FileVerdict {
    pub option: String,
    pub probability: f32,
    pub confidence: f32,
}

/// Why one file in a batch has no usable verdict. Every one of these counts as
/// a skipped file with this text attached, so no file falls out of the totals.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Unusable {
    /// The response carried no answer under this file's question id.
    QidNotInResponse,
    /// The answer was there but had no typed `choice` field.
    NoTypedField,
    /// The answer chose something that is not one of ours.
    OptionOutsideSet(String),
}

impl std::fmt::Display for Unusable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Unusable::QidNotInResponse => write!(f, "qid not in response"),
            Unusable::NoTypedField => write!(f, "no typed field"),
            Unusable::OptionOutsideSet(c) => {
                write!(f, "option {c:?} outside the fixed set")
            }
        }
    }
}

/// Truncate to at most `max_bytes` bytes, never splitting a character.
///
/// The limit is named in bytes and is now counted in bytes. It used to be
/// `chars().take(max_bytes)`, which on non-ASCII content sent up to four times
/// the stated limit.
fn truncate_bytes(s: &str, max_bytes: usize) -> &str {
    if s.len() <= max_bytes {
        return s;
    }
    let mut end = max_bytes;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

/// Score a batch of files in one request. Several questions per call keeps the
/// cost down, which is why eligibility is narrow.
///
/// Returns one entry per question asked: either a verdict or the reason the
/// answer could not be used. An `Err` is a whole-batch failure (transport,
/// auth, malformed envelope); anything per-file is an `Unusable`, never a
/// silent drop.
#[allow(clippy::type_complexity)]
fn ask_batch(
    cfg: &JevScannerConfig,
    api_key: &str,
    redact: &Arc<dyn Fn(&mut Value) + Send + Sync>,
    batch: &[(String, String)], // (qid, content)
) -> Result<std::collections::HashMap<String, Result<FileVerdict, Unusable>>, String> {
    let mut state = serde_json::json!({});
    {
        let obj = state.as_object_mut().expect("object");
        for (qid, content) in batch {
            let truncated = truncate_bytes(content, cfg.max_bytes_per_file);
            obj.insert(qid.clone(), Value::String(truncated.to_string()));
        }
    }
    // Redact BEFORE anything leaves the machine.
    (redact)(&mut state);

    // A flat map: option name -> what it means. See OPTION_CRITERIA.
    let criteria: serde_json::Map<String, Value> = OPTION_CRITERIA
        .iter()
        .map(|(name, meaning)| ((*name).to_string(), Value::String((*meaning).to_string())))
        .collect();

    let mut questions = serde_json::Map::new();
    for (qid, _) in batch {
        // Name the state key this question is about. With more than one file in
        // `state`, an unqualified "this file" lets one file's content decide
        // another's verdict — see the BATCH comment in `apply` for the measured
        // case. `apply` sends one file per request, so this is belt and braces.
        questions.insert(
            qid.clone(),
            serde_json::json!({
                "type": "choice",
                "instructions": format!(
                    "Consider ONLY the file content at state key '{qid}', and ignore every \
                     other key in state. It is the content of a file that an AI coding agent \
                     will read as part of its instructions. Classify what THAT file tells the \
                     agent to do. Choose 'documentation' if it only describes or discusses \
                     behaviour rather than instructing it."
                ),
                "criteria": Value::Object(criteria.clone())
            }),
        );
    }

    let body = serde_json::to_string(&serde_json::json!({
        "state": state,
        "model": cfg.model,
        "questions": Value::Object(questions),
    }))
    .map_err(|e| e.to_string())?;

    let client = reqwest::blocking::Client::builder()
        .timeout(cfg.timeout)
        .build()
        .map_err(|e| e.to_string())?;
    let resp = client
        .post(cfg.endpoint())
        .header("Authorization", format!("Bearer {api_key}"))
        .header("Content-Type", "application/json")
        .body(body)
        .send()
        .map_err(|e| {
            if e.is_timeout() {
                "timed out".to_string()
            } else {
                format!("transport error: {e}")
            }
        })?;

    let status = resp.status().as_u16();
    let text = resp.text().map_err(|e| e.to_string())?;

    // The response carries answers, not file content, so logging it in full is
    // safe. The key is a header and never appears here. This is the only way to
    // tell a 200 that answered nothing from a 200 that answered correctly, and
    // it is what turned up the `criteria` shape bug.
    tracing::debug!(
        status,
        questions_asked = batch.len(),
        endpoint = %cfg.endpoint(),
        response_body = %text,
        "[scanner.jev] provider response"
    );

    match status {
        200 => {}
        401 => return Err("401 unauthorized (bad or missing key)".into()),
        422 => return Err("422 validation error".into()),
        429 => return Err("429 rate limited".into()),
        529 => return Err("529 overloaded".into()),
        other => return Err(format!("HTTP {other}")),
    }

    let parsed: JevResponse =
        serde_json::from_str(&text).map_err(|e| format!("malformed response: {e}"))?;

    // Keyed on what we ASKED, not on what came back, so a short response is
    // visible as missing answers rather than as files that vanished.
    let mut out = std::collections::HashMap::new();
    for (qid, _) in batch {
        let outcome = match parsed.answers.get(qid) {
            None => Err(Unusable::QidNotInResponse),
            Some(a) => match a.choice.as_deref() {
                None => Err(Unusable::NoTypedField),
                Some(choice) if !OPTIONS.contains(&choice) => {
                    Err(Unusable::OptionOutsideSet(choice.to_string()))
                }
                Some(choice) => {
                    let probability = a
                        .probabilities
                        .as_ref()
                        .and_then(|p| p.get(choice).copied())
                        .unwrap_or(0.0)
                        .clamp(0.0, 1.0);
                    Ok(FileVerdict {
                        option: choice.to_string(),
                        probability,
                        confidence: a.confidence.unwrap_or(0.0).clamp(0.0, 1.0),
                    })
                }
            },
        };
        out.insert(qid.clone(), outcome);
    }
    Ok(out)
}

/// Apply the model layer to one surface's findings.
///
/// `files` is (path, content) for every file already read by the pattern pass,
/// so nothing is read twice. Monotonic: raises severity, adds findings, never
/// lowers or removes.
#[allow(clippy::too_many_arguments)]
pub fn apply(
    cfg: &JevScannerConfig,
    api_key: &str,
    redact: &Arc<dyn Fn(&mut Value) + Send + Sync>,
    files: &[(String, String)],
    findings: &mut Vec<PatternFinding>,
    report: &mut JevLayerReport,
    calls_remaining: &mut usize,
) {
    report.enabled = true;

    let eligible: Vec<&(String, String)> = files
        .iter()
        .filter(|(p, _)| is_instruction_bearing(p))
        .collect();
    report.files_eligible += eligible.len();

    if eligible.is_empty() {
        return;
    }

    // ONE FILE PER REQUEST, deliberately.
    //
    // Batching four files into one call was cheaper by roughly 20% in input
    // tokens, and it made verdicts contaminate each other. Measured against
    // api.typesafe.ai (jev-1.13.0): a plainly descriptive file answered
    // "documentation" with confidence 1.0 when asked about on its own, and
    // "instructs_exfiltration" at 0.51 when it shared a request with a file
    // that did instruct exfiltration. Since this layer may only RAISE severity,
    // that contamination becomes a false Critical on an innocent file, which is
    // the failure mode that makes people stop reading a scanner.
    //
    // Naming the state key in each question fixed it in every trial, but that
    // is a property of how a model reads a prompt, not of the contract, and it
    // can regress with a model update without anything here changing. One file
    // per request cannot contaminate. The saving was not worth the risk.
    const BATCH: usize = 1;
    for chunk in eligible.chunks(BATCH) {
        if *calls_remaining == 0 {
            report.cap_reached = true;
            report.files_skipped += chunk.len();
            report.skipped_reason = Some(
                "per-scan model call cap reached; these files were scanned by patterns only"
                    .to_string(),
            );
            continue;
        }
        *calls_remaining -= 1;

        // qid must be a stable, API-safe key; use a content hash.
        let mut qid_to_path = std::collections::HashMap::new();
        let batch: Vec<(String, String)> = chunk
            .iter()
            .map(|(path, content)| {
                let qid = format!(
                    "f{}",
                    &blake3::hash(path.as_bytes()).to_hex().to_string()[..16]
                );
                qid_to_path.insert(qid.clone(), (path.clone(), content.clone()));
                (qid, content.clone())
            })
            .collect();

        match ask_batch(cfg, api_key, redact, &batch) {
            Ok(outcomes) => {
                // Walk the BATCH, not the response. Every file we asked about
                // lands in exactly one of the two totals.
                for (qid, _) in &batch {
                    let Some((path, _)) = qid_to_path.get(qid) else {
                        // Cannot happen: qid_to_path is built from this batch.
                        continue;
                    };
                    let verdict = match outcomes.get(qid) {
                        Some(Ok(v)) => v,
                        Some(Err(reason)) => {
                            report.files_skipped += 1;
                            report.skipped_files.push(format!("{path}: {reason}"));
                            continue;
                        }
                        None => {
                            report.files_skipped += 1;
                            report
                                .skipped_files
                                .push(format!("{path}: {}", Unusable::QidNotInResponse));
                            continue;
                        }
                    };
                    report.files_scored += 1;
                    let Some(model_sev) = option_severity(&verdict.option) else {
                        continue; // documentation: adds nothing
                    };

                    // Monotonic merge against this file's existing findings.
                    let existing_worst = findings
                        .iter()
                        .filter(|f| &f.file == path)
                        .map(|f| f.severity.weight())
                        .max();

                    match existing_worst {
                        Some(w) if w >= model_sev.weight() => {
                            // Patterns already said the same or worse. Leave it
                            // alone — a model may not lower anything.
                        }
                        Some(_) => {
                            // Raise the file's pattern findings to the model's
                            // severity. The rule that matched is preserved, and
                            // the reason is recorded.
                            for f in findings.iter_mut().filter(|f| &f.file == path) {
                                if f.severity.weight() < model_sev.weight() {
                                    f.severity = model_sev.clone();
                                    f.explanation = format!(
                                        "{} — Severity raised by the model layer: classified as \
                                         '{}' (p={:.2}, confidence={:.2}).",
                                        f.explanation,
                                        verdict.option,
                                        verdict.probability,
                                        verdict.confidence
                                    );
                                    report.severities_raised += 1;
                                }
                            }
                        }
                        None => {
                            // The patterns found nothing here. This is the
                            // evasion case the layer exists for.
                            findings.push(PatternFinding {
                                rule_id: format!("JEV-{}", verdict.option.to_uppercase()),
                                pattern_name: format!("model: {}", verdict.option),
                                category: verdict.option.clone(),
                                severity: model_sev,
                                confidence: verdict.confidence,
                                message: format!(
                                    "Model classified this file as '{}' although no pattern matched",
                                    verdict.option
                                ),
                                file: path.clone(),
                                start_line: 1,
                                matched_text: None,
                                explanation: format!(
                                    "No deterministic pattern matched this file. The model layer \
                                     classified its content as '{}' (p={:.2}, confidence={:.2}). \
                                     Treat this as a lead to read the file, not a confirmed \
                                     detection: the model layer's benefit over patterns is \
                                     unmeasured in this release.",
                                    verdict.option, verdict.probability, verdict.confidence
                                ),
                                remediation:
                                    "Read the file. If it instructs the agent to do this, remove \
                                     the instruction or do not install the skill."
                                        .to_string(),
                            });
                            report.findings_added += 1;
                        }
                    }
                }
            }
            Err(e) => {
                // Loudly, never silently: the report carries the reason and the
                // count of files the model did not see.
                report.files_skipped += chunk.len();
                for (path, _) in chunk.iter() {
                    report.skipped_files.push(format!("{path}: {e}"));
                }
                report.skipped_reason = Some(format!(
                    "model layer unavailable ({e}); these files were scanned by patterns only"
                ));
                if !report.errors.iter().any(|x| x == &e) {
                    report.errors.push(e);
                }
            }
        }
    }

    // A summary line for the per-file reasons, so the report says something
    // even when the request itself succeeded.
    if report.skipped_reason.is_none() && !report.skipped_files.is_empty() {
        report.skipped_reason = Some(format!(
            "{} eligible file(s) came back without a usable answer; they were scanned by \
             patterns only. See skipped_files for the reason per file.",
            report.skipped_files.len()
        ));
    }

    // The invariant this layer lost once already. A violation is a bug in the
    // accounting, not in the provider, so it is logged as one.
    if !report.accounting_holds() {
        tracing::error!(
            eligible = report.files_eligible,
            scored = report.files_scored,
            skipped = report.files_skipped,
            "[scanner.jev] accounting lost files: eligible != scored + skipped"
        );
        debug_assert!(
            report.accounting_holds(),
            "files_eligible ({}) != files_scored ({}) + files_skipped ({})",
            report.files_eligible,
            report.files_scored,
            report.files_skipped
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_instruction_bearing_files_are_eligible() {
        assert!(is_instruction_bearing("/home/u/.claude/skills/x/SKILL.md"));
        assert!(is_instruction_bearing("/home/u/.cursor/rules/style.md"));
        assert!(is_instruction_bearing("/proj/.mcp.json"));
        assert!(is_instruction_bearing("/proj/prompts/system.tmpl"));

        // The files that produced the false positives are not sent.
        assert!(!is_instruction_bearing("/proj/changelog.md"));
        assert!(!is_instruction_bearing("/proj/README.md"));
        assert!(!is_instruction_bearing("/proj/LICENSE"));
        assert!(!is_instruction_bearing("/proj/tests/fixture.md"));
        assert!(!is_instruction_bearing("/proj/docs/guide.md"));
        assert!(!is_instruction_bearing("/proj/package-lock.json"));
    }

    #[test]
    fn documentation_verdict_can_never_lower_anything() {
        assert!(option_severity("documentation").is_none());
    }

    #[test]
    fn option_severities_are_ordered_as_expected() {
        assert_eq!(
            option_severity("instructs_code_execution"),
            Some(Severity::Medium)
        );
        assert_eq!(
            option_severity("instructs_exfiltration"),
            Some(Severity::Critical)
        );
        assert_eq!(
            option_severity("overrides_agent_instructions"),
            Some(Severity::Critical)
        );
        assert!(option_severity("nonsense_option").is_none());
    }

    #[test]
    fn endpoint_follows_the_contract_path() {
        let mut c = JevScannerConfig::default();
        assert_eq!(c.endpoint(), "https://api.typesafe.ai/v1/systemone");
        c.base_url = "http://127.0.0.1:8099/".into();
        assert_eq!(c.endpoint(), "http://127.0.0.1:8099/v1/systemone");
    }

    /// The criteria map and the option set are one thing in two places; they
    /// must not drift, because a name in one and not the other is an answer
    /// the parser will throw away.
    #[test]
    fn criteria_keys_match_the_option_set() {
        let keys: Vec<&str> = OPTION_CRITERIA.iter().map(|(k, _)| *k).collect();
        assert_eq!(keys, OPTIONS, "criteria keys must be exactly the options");
        for (name, meaning) in OPTION_CRITERIA {
            assert!(!meaning.is_empty(), "{name} has no description");
        }
    }

    /// The shape that cost us a working layer: a nested `{"options": [...]}`
    /// makes "options" itself the only selectable key. The request must carry
    /// a flat map instead.
    #[test]
    fn criteria_is_a_flat_map_not_a_nested_list() {
        let criteria: serde_json::Map<String, Value> = OPTION_CRITERIA
            .iter()
            .map(|(n, m)| ((*n).to_string(), Value::String((*m).to_string())))
            .collect();
        assert!(
            !criteria.contains_key("options"),
            "\"options\" as a key means the model can only ever choose \"options\""
        );
        for opt in OPTIONS {
            assert!(criteria.contains_key(*opt), "{opt} must be selectable");
            assert!(
                criteria[*opt].is_string(),
                "{opt} must map to a description"
            );
        }
    }

    /// A byte limit that counted characters sent up to four times the stated
    /// size on non-ASCII content.
    #[test]
    fn truncation_is_counted_in_bytes_and_never_splits_a_character() {
        assert_eq!(truncate_bytes("hello", 16), "hello");
        assert_eq!(truncate_bytes("hello", 3), "hel");
        // Four three-byte characters: a 10-byte limit must stop at 9.
        let wide = "日本語訳";
        assert_eq!(wide.len(), 12);
        let cut = truncate_bytes(wide, 10);
        assert!(
            cut.len() <= 10,
            "must respect the byte limit, got {}",
            cut.len()
        );
        assert_eq!(cut, "日本語");
    }

    // ── Accounting ──────────────────────────────────────────────────────────
    //
    // These drive `apply`'s bookkeeping directly rather than over HTTP: the
    // property under test is that no eligible file leaves the totals, whatever
    // the provider returns.

    /// Reproduce the bookkeeping `apply` does for one chunk, given what
    /// `ask_batch` returned for it.
    fn account_for(
        batch: &[(String, String)],
        outcomes: &std::collections::HashMap<String, Result<FileVerdict, Unusable>>,
        report: &mut JevLayerReport,
    ) {
        for (qid, path) in batch {
            match outcomes.get(qid) {
                Some(Ok(_)) => report.files_scored += 1,
                Some(Err(reason)) => {
                    report.files_skipped += 1;
                    report.skipped_files.push(format!("{path}: {reason}"));
                }
                None => {
                    report.files_skipped += 1;
                    report
                        .skipped_files
                        .push(format!("{path}: {}", Unusable::QidNotInResponse));
                }
            }
        }
    }

    fn verdict(option: &str) -> FileVerdict {
        FileVerdict {
            option: option.to_string(),
            probability: 0.9,
            confidence: 0.9,
        }
    }

    #[test]
    fn a_partial_response_still_accounts_for_every_file() {
        let batch: Vec<(String, String)> = (0..4)
            .map(|i| (format!("q{i}"), format!("/skills/s{i}/SKILL.md")))
            .collect();
        let mut outcomes = std::collections::HashMap::new();
        // Two answered, one unusable, one missing entirely.
        outcomes.insert("q0".to_string(), Ok(verdict("documentation")));
        outcomes.insert("q1".to_string(), Ok(verdict("instructs_exfiltration")));
        outcomes.insert(
            "q2".to_string(),
            Err(Unusable::OptionOutsideSet("options".to_string())),
        );

        let mut report = JevLayerReport {
            files_eligible: 4,
            ..Default::default()
        };
        account_for(&batch, &outcomes, &mut report);

        assert_eq!(report.files_scored, 2);
        assert_eq!(report.files_skipped, 2);
        assert!(report.accounting_holds(), "{report:?}");
        assert!(report
            .skipped_files
            .iter()
            .any(|s| s.contains("s2/SKILL.md") && s.contains("outside the fixed set")));
        assert!(report
            .skipped_files
            .iter()
            .any(|s| s.contains("s3/SKILL.md") && s.contains("qid not in response")));
    }

    /// The exact live failure: HTTP 200 with nothing we can use. It must read
    /// as four skipped files, not as a clean scan.
    #[test]
    fn an_empty_response_skips_every_file_rather_than_losing_them() {
        let batch: Vec<(String, String)> = (0..4)
            .map(|i| (format!("q{i}"), format!("/skills/s{i}/SKILL.md")))
            .collect();
        let outcomes: std::collections::HashMap<String, Result<FileVerdict, Unusable>> = batch
            .iter()
            .map(|(qid, _)| (qid.clone(), Err(Unusable::QidNotInResponse)))
            .collect();

        let mut report = JevLayerReport {
            files_eligible: 4,
            ..Default::default()
        };
        account_for(&batch, &outcomes, &mut report);

        assert_eq!(report.files_scored, 0);
        assert_eq!(report.files_skipped, 4, "all four must be accounted for");
        assert!(report.accounting_holds(), "{report:?}");
        assert_eq!(report.skipped_files.len(), 4);
    }

    #[test]
    fn an_answer_with_no_choice_field_is_a_skip_with_a_reason() {
        let batch = vec![("q0".to_string(), "/skills/a/SKILL.md".to_string())];
        let mut outcomes = std::collections::HashMap::new();
        outcomes.insert("q0".to_string(), Err(Unusable::NoTypedField));

        let mut report = JevLayerReport {
            files_eligible: 1,
            ..Default::default()
        };
        account_for(&batch, &outcomes, &mut report);

        assert_eq!(report.files_skipped, 1);
        assert!(report.accounting_holds());
        assert_eq!(
            report.skipped_files[0],
            "/skills/a/SKILL.md: no typed field"
        );
    }

    #[test]
    fn the_accounting_invariant_catches_a_lost_file() {
        let report = JevLayerReport {
            files_eligible: 4,
            files_scored: 1,
            files_skipped: 0,
            ..Default::default()
        };
        assert!(
            !report.accounting_holds(),
            "three lost files must fail the invariant"
        );
    }

    #[test]
    fn defaults_are_conservative() {
        let c = JevScannerConfig::default();
        assert_eq!(c.max_calls_per_scan, 40);
        assert_eq!(c.max_bytes_per_file, 8 * 1024);
    }
}
