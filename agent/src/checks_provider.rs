// SPDX-License-Identifier: Apache-2.0
//
// checks_provider.rs — selects and holds the scorer the checks layer uses.
//
// THE ONE RULE. Nothing here runs in a syscall hook. The kernel never waits on
// any of it. These scorers label what an agent is about to do; they cannot
// allow or deny anything.
//
// The deterministic scorer always runs, even when the hosted provider is
// selected. It costs microseconds and it is the FLOOR: a model answer may
// raise a result to a more severe option, never lower one. When the hosted
// provider is unavailable the deterministic result is what gets recorded, and
// the trace says so in `provider` and `provider_error`.

use std::sync::Arc;
use std::time::Duration;

use ringzero_checks::jev::{HttpTransport, JevConfig, JevProvider, ToolCallContext};
use ringzero_checks::{
    agent_output_risk, sensitive_data_exposure, tool_call_argument_risk, CheckResult,
};
use serde_json::Value;

use crate::config::ChecksSection;

/// Which scorer is in force.
pub enum ScoringProvider {
    /// Everything stays on this machine.
    Deterministic,
    /// TypeSafe's hosted model, with the deterministic scorer as floor and
    /// fallback.
    Jev(Box<JevProvider<HttpTransport>>),
}

impl ScoringProvider {
    pub fn name(&self) -> &'static str {
        match self {
            ScoringProvider::Deterministic => "deterministic",
            ScoringProvider::Jev(_) => "jev",
        }
    }

    /// Build the provider the config asks for.
    ///
    /// Returns `Err` when the operator selected the hosted provider but it
    /// cannot be used. That is a configuration error, not a reason to quietly
    /// run something else: the caller disables the checks layer and logs it.
    pub fn from_config(
        cfg: &ChecksSection,
        redact: Arc<dyn Fn(&mut Value) + Send + Sync>,
    ) -> Result<Self, String> {
        match cfg.provider.trim().to_ascii_lowercase().as_str() {
            "deterministic" => Ok(ScoringProvider::Deterministic),
            "jev" => {
                let key = cfg.jev.load_key()?;
                let jev_cfg = JevConfig {
                    base_url: cfg.jev.base_url.clone(),
                    model: cfg.jev.model.clone(),
                    timeout: Duration::from_millis(cfg.jev.timeout_ms),
                };
                Ok(ScoringProvider::Jev(Box::new(JevProvider::new(
                    HttpTransport,
                    key,
                    jev_cfg,
                    redact,
                ))))
            }
            other => Err(format!(
                "unknown checks provider {other:?}; use \"jev\" or \"deterministic\""
            )),
        }
    }

    /// Score one tool call. Blocking: the hosted provider does a bounded HTTP
    /// request, so callers on an async runtime must run this on a blocking
    /// task. It is never called from an enforcement path.
    pub fn score_tool_call(
        &self,
        tool: &str,
        args: &Value,
        workspace: Option<&str>,
        approved_hosts: &[String],
        task_hash: Option<&str>,
    ) -> (CheckResult, CheckResult) {
        match self {
            ScoringProvider::Deterministic => (
                tool_call_argument_risk(tool, args, workspace, approved_hosts),
                sensitive_data_exposure(&args.to_string()),
            ),
            ScoringProvider::Jev(p) => p.score_tool_call(&ToolCallContext {
                tool,
                args,
                workspace,
                approved_hosts,
                task_hash,
            }),
        }
    }

    /// Score text the agent printed to its terminal.
    ///
    /// The caller has already run the operator's redactor over `text`. The
    /// deterministic scorer runs first and gates any remote call, so benign
    /// output never leaves the machine. Blocking, for the same reason
    /// `score_tool_call` is, and never called from an enforcement path.
    pub fn score_agent_output(&self, text: &str) -> CheckResult {
        match self {
            ScoringProvider::Deterministic => agent_output_risk(text),
            ScoringProvider::Jev(p) => p.score_agent_output(text),
        }
    }
}
