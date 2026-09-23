// SPDX-License-Identifier: Apache-2.0
//
// jev.rs — optional scoring provider backed by TypeSafe's hosted Jev API.
//
// THE ONE RULE STILL GOVERNS. Enforcement is deterministic and models never
// decide the syscall. Nothing in this file runs in a file-open, exec or connect
// hook, and the kernel never waits on it. This provider runs off the hot path,
// on agent hook events, and its output is an observation written into the trace
// — exactly like the deterministic scorer's output. It cannot allow or deny
// anything.
//
// Two properties are enforced structurally rather than by comment:
//
//   MONOTONIC. The deterministic result is always computed first and is the
//   floor. A Jev answer may raise a result to a more severe option or raise its
//   probability. It can never clear a flag, lower a probability, or downgrade
//   an option. See `merge_monotonic`, which is the only path a remote answer
//   takes into a CheckResult.
//
//   FAIL SAFE. Every failure path — timeout, 401, 429, 529, transport error,
//   malformed body, missing typed field — returns the deterministic result with
//   `provider_error` set. There is no path where a remote failure produces a
//   more permissive answer than we already had locally, and none where we block
//   waiting on the network.
//
// PRIVACY. Turning this on sends agent tool-call context to a third party. It
// is off by default and inert without a key. The caller supplies a redactor and
// it runs over the outbound state before the request is built. Raw prompt text
// is never sent: the trace format forbids it and `ToolCallContext` carries only
// structured tool-call fields plus a task hash.

use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{sensitive_data_exposure, tool_call_argument_risk, Check, CheckResult};

/// What the caller knows about the tool call being scored. Structured fields
/// only — never raw prompt text.
#[derive(Debug, Clone)]
pub struct ToolCallContext<'a> {
    pub tool: &'a str,
    pub args: &'a Value,
    pub workspace: Option<&'a str>,
    pub approved_hosts: &'a [String],
    /// Hash of the task the agent was given, never the task text itself.
    pub task_hash: Option<&'a str>,
}

#[derive(Debug, Clone)]
pub struct JevConfig {
    /// Origin of the service. The request path is always `/v1/systemone`, so
    /// pointing this at a self-hosted or fine-tuned endpoint that serves the
    /// same contract is a one-line config change and no code change.
    pub base_url: String,
    pub model: String,
    pub timeout: Duration,
}

impl JevConfig {
    /// Full request URL. Trailing slashes on `base_url` are tolerated.
    pub fn endpoint(&self) -> String {
        format!("{}/v1/systemone", self.base_url.trim_end_matches('/'))
    }
}

impl Default for JevConfig {
    fn default() -> Self {
        JevConfig {
            base_url: "https://api.typesafe.ai".to_string(),
            model: "jev-latest".to_string(),
            timeout: Duration::from_millis(1500),
        }
    }
}

/// Why a remote answer was not used. Every variant falls back to deterministic.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JevError {
    Unauthorized,
    RateLimited,
    Overloaded,
    Validation(u16),
    Timeout,
    Transport(String),
    Malformed(String),
    /// The response parsed, but the typed field this question needed was absent.
    MissingTypedField(String),
}

impl std::fmt::Display for JevError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            JevError::Unauthorized => write!(f, "jev: 401 unauthorized (bad or missing key)"),
            JevError::RateLimited => write!(f, "jev: 429 rate limited"),
            JevError::Overloaded => write!(f, "jev: 529 overloaded"),
            JevError::Validation(c) => write!(f, "jev: {c} validation error"),
            JevError::Timeout => write!(f, "jev: timed out"),
            JevError::Transport(e) => write!(f, "jev: transport error: {e}"),
            JevError::Malformed(e) => write!(f, "jev: malformed response: {e}"),
            JevError::MissingTypedField(q) => {
                write!(f, "jev: response had no typed answer for {q}")
            }
        }
    }
}

/// The HTTP call, abstracted so tests never touch the network.
pub trait Transport: Send + Sync {
    /// POST `body` and return (status, body). Implementations enforce `timeout`.
    fn post(
        &self,
        endpoint: &str,
        api_key: &str,
        body: String,
        timeout: Duration,
    ) -> Result<(u16, String), JevError>;
}

// ── Wire types ──────────────────────────────────────────────────────────────

#[derive(Debug, Serialize)]
struct JevRequest<'a> {
    state: Value,
    model: &'a str,
    questions: Value,
}

#[derive(Debug, Deserialize)]
struct JevResponse {
    #[serde(default)]
    answers: std::collections::HashMap<String, JevAnswer>,
}

#[derive(Debug, Deserialize)]
struct JevAnswer {
    #[serde(default)]
    choice: Option<String>,
    #[serde(default)]
    probabilities: Option<std::collections::HashMap<String, f32>>,
    #[serde(default)]
    noul: Option<f32>,
    #[serde(default)]
    confidence: Option<f32>,
}

const Q_TOOL_RISK: &str = "tool_call_argument_risk";
const Q_DATA_EXPOSURE: &str = "sensitive_data_exposure";
const Q_AGENT_OUTPUT: &str = "agent_output_risk";

/// The optional provider. Wraps the deterministic scorer, which is both the
/// fallback and the floor.
pub struct JevProvider<T: Transport> {
    transport: T,
    api_key: String,
    cfg: JevConfig,
    redact: Arc<dyn Fn(&mut Value) + Send + Sync>,
}

impl<T: Transport> JevProvider<T> {
    /// `redact` runs over the outbound state before the request is built. Pass
    /// the same redactor the webhook path uses so a secret is not shipped to a
    /// third party.
    pub fn new(
        transport: T,
        api_key: String,
        cfg: JevConfig,
        redact: Arc<dyn Fn(&mut Value) + Send + Sync>,
    ) -> Self {
        JevProvider {
            transport,
            api_key,
            cfg,
            redact,
        }
    }

    /// Score a tool call. Returns the deterministic result raised by whatever
    /// the remote answer justifies, or the deterministic result untouched on
    /// any failure.
    pub fn score_tool_call(&self, ctx: &ToolCallContext<'_>) -> (CheckResult, CheckResult) {
        let baseline_risk =
            tool_call_argument_risk(ctx.tool, ctx.args, ctx.workspace, ctx.approved_hosts);
        let baseline_exposure = sensitive_data_exposure(&ctx.args.to_string());

        match self.ask(ctx) {
            Ok(answers) => {
                let risk = match Self::answer_to_choice(&answers, Q_TOOL_RISK) {
                    Ok(r) => merge_monotonic(baseline_risk.clone(), r),
                    Err(e) => with_error(baseline_risk.clone(), &e),
                };
                let exposure = match Self::answer_to_noul(&answers, Q_DATA_EXPOSURE) {
                    Ok(r) => merge_monotonic(baseline_exposure.clone(), r),
                    Err(e) => with_error(baseline_exposure.clone(), &e),
                };
                (risk, exposure)
            }
            Err(e) => (
                with_error(baseline_risk, &e),
                with_error(baseline_exposure, &e),
            ),
        }
    }

    /// Score text the agent printed to its terminal.
    ///
    /// PRIVACY, read this before changing it. The deterministic scorer runs
    /// first and GATES the call: text it reads as benign never leaves the
    /// machine, so the only captured output that reaches a third party is
    /// output that already matched a phrase an operator can read in
    /// `checks/src/lib.rs`. What is sent then goes through the same redactor
    /// every other outbound state goes through.
    ///
    /// Monotonic like everything else here: the remote answer may raise the
    /// option or its probability, never lower either.
    pub fn score_agent_output(&self, text: &str) -> CheckResult {
        let baseline = crate::agent_output_risk(text);
        if !baseline.is_flag() {
            // Nothing local flagged it. No call, nothing sent.
            return baseline;
        }
        match self.ask_output(text) {
            Ok(remote) => merge_monotonic(baseline, remote),
            Err(e) => with_error(baseline, &e),
        }
    }

    /// The one request behind `score_agent_output`.
    fn ask_output(&self, text: &str) -> Result<CheckResult, JevError> {
        if self.api_key.trim().is_empty() {
            return Err(JevError::Unauthorized);
        }
        let mut state = json!({ "agent_output": text });
        // Redact before the value leaves this machine.
        (self.redact)(&mut state);

        let questions = json!({
            Q_AGENT_OUTPUT: {
                "type": "choice",
                "instructions": "This is text an AI coding agent printed to its terminal. \
                                 Classify what the text SAYS the agent is doing. Judge the \
                                 words, not what actually happened.",
                // Flat map: every key is one selectable option. A nested
                // {"options": [...]} makes "options" the only choice — the trap
                // that cost the scanner layer a working release.
                "criteria": {
                    "benign": "ordinary progress reporting, code, test output or explanation",
                    "states_credential_access": "says it is reading or using credentials, \
                                                 private keys, tokens or other secrets",
                    "states_exfiltration": "says it is sending data off this machine, to a \
                                            URL, a webhook, an email address or a paste site",
                    "states_policy_evasion": "says it is getting around, disabling or hiding \
                                              from a security control"
                }
            }
        });

        let body = serde_json::to_string(&JevRequest {
            state,
            model: &self.cfg.model,
            questions,
        })
        .map_err(|e| JevError::Malformed(e.to_string()))?;

        let (status, text_body) =
            self.transport
                .post(&self.cfg.endpoint(), &self.api_key, body, self.cfg.timeout)?;

        match status {
            200 => {}
            401 => return Err(JevError::Unauthorized),
            422 => return Err(JevError::Validation(422)),
            429 => return Err(JevError::RateLimited),
            529 => return Err(JevError::Overloaded),
            other => return Err(JevError::Validation(other)),
        }

        let parsed: JevResponse =
            serde_json::from_str(&text_body).map_err(|e| JevError::Malformed(e.to_string()))?;
        let a = parsed
            .answers
            .get(Q_AGENT_OUTPUT)
            .ok_or_else(|| JevError::MissingTypedField(Q_AGENT_OUTPUT.to_string()))?;
        let choice = a
            .choice
            .as_deref()
            .ok_or_else(|| JevError::MissingTypedField(format!("{Q_AGENT_OUTPUT}.choice")))?;
        let check = Check::AgentOutputRisk;
        if !check.options().contains(&choice) {
            return Err(JevError::Malformed(format!(
                "{Q_AGENT_OUTPUT}: option {choice:?} is not in the fixed set"
            )));
        }
        let probability = a
            .probabilities
            .as_ref()
            .and_then(|p| p.get(choice).copied())
            .unwrap_or(0.0)
            .clamp(0.0, 1.0);
        Ok(remote_result(
            check,
            choice,
            probability,
            a.confidence.map(|c| c.clamp(0.0, 1.0)),
        ))
    }

    /// Build the request, send it, and parse the envelope.
    fn ask(
        &self,
        ctx: &ToolCallContext<'_>,
    ) -> Result<std::collections::HashMap<String, JevAnswer>, JevError> {
        if self.api_key.trim().is_empty() {
            return Err(JevError::Unauthorized);
        }

        // Structured fields only. No prompt text, ever.
        let mut state = json!({
            "tool": ctx.tool,
            "arguments": ctx.args,
            "workspace": ctx.workspace,
            "approved_hosts": ctx.approved_hosts,
            "task_hash": ctx.task_hash,
        });
        // Redact before the value leaves this machine.
        (self.redact)(&mut state);

        let questions = json!({
            Q_TOOL_RISK: {
                "type": "choice",
                "instructions": "Classify what this agent tool call is about to do. \
                                 Choose the single option that best describes the risk.",
                // `criteria` is a map of option name -> what that option means.
                // The API treats every key as one selectable option, so the set
                // must be flat: a nested {"options": [...]} makes "options"
                // itself the only choice.
                "criteria": {
                    "benign": "ordinary work: reads or writes inside the workspace, \
                               or a call to an approved host",
                    "reads_sensitive_path": "reads credentials, private keys, tokens \
                                             or other secrets, such as .aws/credentials, \
                                             .ssh/id_rsa or a .env file",
                    "writes_outside_workspace": "creates or modifies a file outside \
                                                 the stated workspace directory",
                    "unapproved_network_host": "contacts a host that is not in the \
                                                approved list"
                }
            },
            Q_DATA_EXPOSURE: {
                "type": "noul",
                "instructions": "Probability that a secret or credential is about to leave \
                                 the machine through this tool call.",
                "criteria": {}
            }
        });

        let body = serde_json::to_string(&JevRequest {
            state,
            model: &self.cfg.model,
            questions,
        })
        .map_err(|e| JevError::Malformed(e.to_string()))?;

        let (status, text) =
            self.transport
                .post(&self.cfg.endpoint(), &self.api_key, body, self.cfg.timeout)?;

        match status {
            200 => {}
            401 => return Err(JevError::Unauthorized),
            422 => return Err(JevError::Validation(422)),
            429 => return Err(JevError::RateLimited),
            529 => return Err(JevError::Overloaded),
            other => return Err(JevError::Validation(other)),
        }

        let parsed: JevResponse =
            serde_json::from_str(&text).map_err(|e| JevError::Malformed(e.to_string()))?;
        Ok(parsed.answers)
    }

    /// A `choice` answer becomes a candidate result. Anything unexpected — a
    /// missing choice, an option outside our fixed set — is a failure, not a
    /// guess.
    fn answer_to_choice(
        answers: &std::collections::HashMap<String, JevAnswer>,
        qid: &str,
    ) -> Result<CheckResult, JevError> {
        let a = answers
            .get(qid)
            .ok_or_else(|| JevError::MissingTypedField(qid.to_string()))?;
        let choice = a
            .choice
            .as_deref()
            .ok_or_else(|| JevError::MissingTypedField(format!("{qid}.choice")))?;
        let check = Check::ToolCallArgumentRisk;
        if !check.options().contains(&choice) {
            return Err(JevError::Malformed(format!(
                "{qid}: option {choice:?} is not in the fixed set"
            )));
        }
        let probability = a
            .probabilities
            .as_ref()
            .and_then(|p| p.get(choice).copied())
            .unwrap_or(0.0)
            .clamp(0.0, 1.0);
        let confidence = a.confidence.map(|c| c.clamp(0.0, 1.0));
        Ok(remote_result(check, choice, probability, confidence))
    }

    /// A `noul` answer is a probability in [0,1]. We map it onto the fixed
    /// option set with fixed thresholds, so the option space never grows.
    fn answer_to_noul(
        answers: &std::collections::HashMap<String, JevAnswer>,
        qid: &str,
    ) -> Result<CheckResult, JevError> {
        let a = answers
            .get(qid)
            .ok_or_else(|| JevError::MissingTypedField(qid.to_string()))?;
        let noul = a
            .noul
            .ok_or_else(|| JevError::MissingTypedField(format!("{qid}.noul")))?;
        if !noul.is_finite() || !(0.0..=1.0).contains(&noul) {
            return Err(JevError::Malformed(format!(
                "{qid}: noul {noul} out of range"
            )));
        }
        // The bands are configuration, not constants: see
        // checks/src/thresholds.rs and [checks.thresholds] in daemon.toml.
        let option = crate::thresholds::current().exposure_option(noul);
        // A `noul` answers with the probability alone — the API documents no
        // separate confidence for it, so we record none rather than zero.
        let confidence = a.confidence.map(|c| c.clamp(0.0, 1.0));
        Ok(remote_result(
            Check::SensitiveDataExposure,
            option,
            noul,
            confidence,
        ))
    }
}

fn remote_result(
    check: Check,
    option: &str,
    probability: f32,
    confidence: Option<f32>,
) -> CheckResult {
    CheckResult {
        check: check.wire_name().to_string(),
        option: option.to_string(),
        probability,
        confidence,
        evidence: vec!["scored by jev".to_string()],
        provider: "jev".to_string(),
        provider_error: None,
    }
}

fn with_error(mut baseline: CheckResult, e: &JevError) -> CheckResult {
    baseline.provider_error = Some(e.to_string());
    baseline
}

/// The only way a remote answer reaches a result.
///
/// The baseline is a floor on SEVERITY: the merged result is never less severe
/// than what the deterministic scorer already decided. A remote answer can
/// escalate to a more severe option, or raise probability and confidence within
/// the same option. It cannot downgrade an option, and it cannot lower a number
/// for an option it agrees with.
///
/// Probabilities are per-option weights, so on escalation the remote option's
/// own probability stands rather than being maxed against a number that
/// described a different option.
pub fn merge_monotonic(baseline: CheckResult, remote: CheckResult) -> CheckResult {
    let Some(check) = baseline.check_kind() else {
        return baseline;
    };
    let base_rank = check.severity_rank(&baseline.option);
    let remote_rank = check.severity_rank(&remote.option);

    if remote_rank > base_rank {
        // Escalation. Take the remote option and its own numbers: a probability
        // is the weight for ONE option, so carrying the baseline's number across
        // to a different option would be comparing two different claims. What is
        // monotonic here is severity, which only ever rises.
        let mut out = remote;
        for e in baseline.evidence {
            out.evidence.push(format!("deterministic: {e}"));
        }
        out
    } else if remote_rank == base_rank {
        // Same severity: the remote answer may only raise the numbers. If any
        // of them were taken, the numbers a reader sees are partly the model's,
        // so `provider` says so — it names whose values these are, and a
        // fallback is always marked by `provider_error` instead.
        let mut out = baseline;
        let took_probability = remote.probability > out.probability;
        let took_confidence = match (remote.confidence, out.confidence) {
            (Some(r), Some(o)) => r > o,
            (Some(_), None) => true,
            _ => false,
        };
        out.probability = out.probability.max(remote.probability);
        out.confidence = match (out.confidence, remote.confidence) {
            (Some(o), Some(r)) => Some(o.max(r)),
            (None, r) => r,
            (o, None) => o,
        };
        if took_probability || took_confidence {
            out.provider = remote.provider;
            out.evidence.push("deterministic floor agreed".to_string());
        } else {
            out.evidence
                .push("jev agreed but added nothing".to_string());
        }
        out
    } else {
        // Remote is less severe. Ignore it: a provider may never downgrade.
        let mut out = baseline;
        out.evidence.push(format!(
            "jev proposed a lower option ({}), ignored",
            remote.option
        ));
        out
    }
}

// ── Real transport ──────────────────────────────────────────────────────────

/// Blocking reqwest transport. The agent calls this from a blocking task so the
/// async runtime is never held up, and `timeout` bounds it regardless.
#[cfg(feature = "http")]
pub struct HttpTransport;

#[cfg(feature = "http")]
impl Transport for HttpTransport {
    fn post(
        &self,
        endpoint: &str,
        api_key: &str,
        body: String,
        timeout: Duration,
    ) -> Result<(u16, String), JevError> {
        let client = reqwest::blocking::Client::builder()
            .timeout(timeout)
            .build()
            .map_err(|e| JevError::Transport(e.to_string()))?;
        let resp = client
            .post(endpoint)
            .header("Authorization", format!("Bearer {api_key}"))
            .header("Content-Type", "application/json")
            .body(body)
            .send()
            .map_err(|e| {
                if e.is_timeout() {
                    JevError::Timeout
                } else {
                    JevError::Transport(e.to_string())
                }
            })?;
        let status = resp.status().as_u16();
        let text = resp
            .text()
            .map_err(|e| JevError::Transport(e.to_string()))?;
        Ok((status, text))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// Records what was sent and replays a canned response. No network.
    struct MockTransport {
        reply: Mutex<Result<(u16, String), JevError>>,
        last_body: Mutex<Option<String>>,
    }

    impl MockTransport {
        fn ok(body: &str) -> Self {
            MockTransport {
                reply: Mutex::new(Ok((200, body.to_string()))),
                last_body: Mutex::new(None),
            }
        }
        fn status(code: u16) -> Self {
            MockTransport {
                reply: Mutex::new(Ok((code, "{}".to_string()))),
                last_body: Mutex::new(None),
            }
        }
        fn err(e: JevError) -> Self {
            MockTransport {
                reply: Mutex::new(Err(e)),
                last_body: Mutex::new(None),
            }
        }
    }

    impl Transport for MockTransport {
        fn post(
            &self,
            _e: &str,
            _k: &str,
            body: String,
            _t: Duration,
        ) -> Result<(u16, String), JevError> {
            *self.last_body.lock().unwrap() = Some(body);
            self.reply.lock().unwrap().clone()
        }
    }

    fn provider<T: Transport>(t: T) -> JevProvider<T> {
        JevProvider::new(t, "test-key".into(), JevConfig::default(), Arc::new(|_| {}))
    }

    fn ctx<'a>(args: &'a Value) -> ToolCallContext<'a> {
        ToolCallContext {
            tool: "Bash",
            args,
            workspace: Some("/work"),
            approved_hosts: &[],
            task_hash: Some("abc123"),
        }
    }

    #[test]
    fn base_url_builds_the_contract_path_and_tolerates_a_trailing_slash() {
        let mut c = JevConfig::default();
        assert_eq!(c.endpoint(), "https://api.typesafe.ai/v1/systemone");
        c.base_url = "http://127.0.0.1:8099/".to_string();
        assert_eq!(c.endpoint(), "http://127.0.0.1:8099/v1/systemone");
    }

    #[test]
    fn typed_response_escalates_a_benign_baseline() {
        let body = r#"{"model":"jev-latest","answers":{
            "tool_call_argument_risk":{"type":"choice","choice":"writes_outside_workspace",
                "probabilities":{"writes_outside_workspace":0.88},"confidence":0.81},
            "sensitive_data_exposure":{"type":"noul","noul":0.93}}}"#;
        let args = json!({"command": "echo hi"});
        let (risk, exposure) = provider(MockTransport::ok(body)).score_tool_call(&ctx(&args));

        assert_eq!(risk.option, "writes_outside_workspace");
        assert_eq!(risk.provider, "jev");
        assert!((risk.probability - 0.88).abs() < 1e-6);
        assert!((risk.confidence.unwrap() - 0.81).abs() < 1e-6);
        assert_eq!(exposure.option, "secret_pattern_matched");
        assert!((exposure.probability - 0.93).abs() < 1e-6);
        assert!(risk.provider_error.is_none());
    }

    #[test]
    fn a_remote_answer_can_never_downgrade_the_deterministic_result() {
        // Baseline is reads_sensitive_path (rank 3); jev says benign (rank 0).
        let body = r#"{"answers":{
            "tool_call_argument_risk":{"choice":"benign","probabilities":{"benign":0.99},"confidence":0.99},
            "sensitive_data_exposure":{"noul":0.01,"confidence":0.99}}}"#;
        let args = json!({"command": "cat ~/.aws/credentials"});
        let (risk, _) = provider(MockTransport::ok(body)).score_tool_call(&ctx(&args));

        assert_eq!(
            risk.option, "reads_sensitive_path",
            "must not be downgraded"
        );
        assert_eq!(risk.provider, "deterministic");
        assert!(risk.probability >= 0.9);
        assert!(risk.evidence.iter().any(|e| e.contains("ignored")));
    }

    #[test]
    fn agreement_that_raises_a_number_is_attributed_to_the_model() {
        // Deterministic says reads_sensitive_path p=0.9; jev agrees at p=0.95.
        let body = r#"{"answers":{
            "tool_call_argument_risk":{"choice":"reads_sensitive_path",
                "probabilities":{"reads_sensitive_path":0.95},"confidence":0.99}}}"#;
        let args = json!({"command": "cat ~/.aws/credentials"});
        let (risk, _) = provider(MockTransport::ok(body)).score_tool_call(&ctx(&args));
        assert_eq!(risk.option, "reads_sensitive_path");
        assert_eq!(risk.provider, "jev", "the number shown is the model's");
        assert!((risk.probability - 0.95).abs() < 1e-6);
        assert!(risk.provider_error.is_none());
    }

    #[test]
    fn agreement_that_adds_nothing_stays_attributed_to_the_local_scorer() {
        let body = r#"{"answers":{
            "tool_call_argument_risk":{"choice":"reads_sensitive_path",
                "probabilities":{"reads_sensitive_path":0.10},"confidence":0.10}}}"#;
        let args = json!({"command": "cat ~/.aws/credentials"});
        let (risk, _) = provider(MockTransport::ok(body)).score_tool_call(&ctx(&args));
        assert_eq!(risk.provider, "deterministic");
        assert!((risk.probability - 0.9).abs() < 1e-6, "floor held");
    }

    #[test]
    fn rate_limit_falls_back_and_records_the_failure() {
        let args = json!({"command": "cat ~/.aws/credentials"});
        let (risk, exposure) = provider(MockTransport::status(429)).score_tool_call(&ctx(&args));

        assert_eq!(risk.option, "reads_sensitive_path");
        assert_eq!(risk.provider, "deterministic");
        assert_eq!(
            risk.provider_error.as_deref(),
            Some("jev: 429 rate limited")
        );
        assert!(exposure.provider_error.is_some());
    }

    #[test]
    fn timeout_falls_back_and_never_blocks_the_result() {
        let args = json!({"command": "ls"});
        let (risk, _) =
            provider(MockTransport::err(JevError::Timeout)).score_tool_call(&ctx(&args));
        assert_eq!(risk.provider, "deterministic");
        assert_eq!(risk.provider_error.as_deref(), Some("jev: timed out"));
        assert_eq!(risk.option, "benign");
    }

    #[test]
    fn malformed_body_falls_back() {
        let (risk, _) = provider(MockTransport::ok("not json at all"))
            .score_tool_call(&ctx(&json!({"command": "ls"})));
        assert_eq!(risk.provider, "deterministic");
        assert!(risk
            .provider_error
            .as_deref()
            .unwrap()
            .contains("malformed response"));
    }

    #[test]
    fn a_missing_typed_field_is_a_failure_not_a_guess() {
        // Valid envelope, but the choice field is absent.
        let body = r#"{"answers":{"tool_call_argument_risk":{"type":"choice","confidence":0.9},
                                   "sensitive_data_exposure":{"type":"noul","confidence":0.5}}}"#;
        let (risk, exposure) =
            provider(MockTransport::ok(body)).score_tool_call(&ctx(&json!({"command": "ls"})));
        assert_eq!(risk.provider, "deterministic");
        assert!(risk
            .provider_error
            .as_deref()
            .unwrap()
            .contains("no typed answer"));
        assert!(exposure.provider_error.is_some());
    }

    #[test]
    fn an_option_outside_the_fixed_set_is_rejected() {
        let body = r#"{"answers":{"tool_call_argument_risk":
            {"choice":"launch_the_missiles","probabilities":{"launch_the_missiles":1.0},"confidence":1.0}}}"#;
        let (risk, _) =
            provider(MockTransport::ok(body)).score_tool_call(&ctx(&json!({"command": "ls"})));
        assert_eq!(risk.provider, "deterministic");
        assert!(risk
            .provider_error
            .as_deref()
            .unwrap()
            .contains("not in the fixed set"));
    }

    #[test]
    fn an_empty_key_never_reaches_the_network() {
        let t = MockTransport::ok(r#"{"answers":{}}"#);
        let p = JevProvider::new(t, "  ".into(), JevConfig::default(), Arc::new(|_| {}));
        let (risk, _) = p.score_tool_call(&ctx(&json!({"command": "ls"})));
        assert_eq!(
            risk.provider_error.as_deref(),
            Some("jev: 401 unauthorized (bad or missing key)")
        );
        assert!(
            p.transport.last_body.lock().unwrap().is_none(),
            "no request was built"
        );
    }

    #[test]
    fn the_redactor_runs_before_anything_leaves_and_no_prompt_text_is_sent() {
        let t = MockTransport::ok(r#"{"answers":{}}"#);
        let redact: Arc<dyn Fn(&mut Value) + Send + Sync> = Arc::new(|v: &mut Value| {
            // Stand-in for the webhook redactor: mask anything AKIA-shaped.
            if let Some(s) = v.pointer_mut("/arguments/command") {
                *s = json!("[REDACTED]");
            }
        });
        let p = JevProvider::new(t, "k".into(), JevConfig::default(), redact);
        let args = json!({"command": "export KEY=AKIAIOSFODNN7EXAMPLE"});
        let _ = p.score_tool_call(&ctx(&args));

        let sent = p.transport.last_body.lock().unwrap().clone().unwrap();
        assert!(
            !sent.contains("AKIAIOSFODNN7EXAMPLE"),
            "secret must not be sent"
        );
        assert!(sent.contains("[REDACTED]"));
        assert!(sent.contains("task_hash"), "hash is sent");
        assert!(!sent.contains("prompt"), "no prompt field is ever sent");
    }
}
