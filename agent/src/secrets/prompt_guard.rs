// SPDX-License-Identifier: Apache-2.0
// secrets/prompt_guard.rs — secrets never leave the machine inside a prompt.
//
// A developer pastes a log, a config or an .env into an agent prompt and the
// credential goes to a model provider. By the time anything downstream sees it,
// it has left the machine and cannot be taken back. So the check runs where the
// prompt is submitted: the agent's UserPromptSubmit hook posts the prompt to
// the local daemon, this module scans it, and on a hit the hook tells the agent
// not to send it. Nothing in this path makes a network call.
//
// TWO LAYERS, ONE DIRECTION.
//   1. Deterministic: the same secret patterns the file scanner uses
//      (`detector::find_spans`). Exact for known key formats.
//   2. Model (optional, later): an on-device span model for what
//      patterns miss. It may only ADD
//      findings, never remove one, like every other model layer here.
//
// The prompt that is stored in the trace is the REDACTED one. Recording the raw
// prompt would put the very secret we refused to send into our own logs.

use serde::Serialize;

use super::detector::{find_spans, SecretKind};

/// What the guard does with a finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, serde::Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum PromptGuardMode {
    /// Don't scan.
    Off,
    /// Scan, record a redacted finding, let the prompt through.
    #[default]
    Warn,
    /// Scan, record, and tell the agent not to send the prompt.
    Block,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct PromptFinding {
    pub kind: SecretKind,
    /// Human label, e.g. "GitHub Token".
    pub label: String,
    /// First/last four characters, the rest masked. Never the value.
    pub masked: String,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct PromptVerdict {
    pub findings: Vec<PromptFinding>,
    /// The prompt with every finding replaced by its masked form. This, never
    /// the original, is what may be stored or forwarded.
    pub redacted: String,
    /// True when the mode is Block and there is at least one finding.
    pub block: bool,
}

impl PromptVerdict {
    /// The reason shown to the person who submitted the prompt. Names the kinds
    /// found, never the values.
    pub fn reason(&self) -> Option<String> {
        if self.findings.is_empty() {
            return None;
        }
        let mut labels: Vec<&str> = self.findings.iter().map(|f| f.label.as_str()).collect();
        labels.sort_unstable();
        labels.dedup();
        Some(format!(
            "Ring Zero: this prompt contains {} ({}). It was not sent. Remove the secret, or reference it by name instead of pasting the value.",
            if self.findings.len() == 1 { "a secret".to_string() } else { format!("{} secrets", self.findings.len()) },
            labels.join(", ")
        ))
    }
}

/// Scan a prompt. Pure and synchronous, so it can sit on the hook's path.
pub fn check(prompt: &str, mode: PromptGuardMode) -> PromptVerdict {
    if mode == PromptGuardMode::Off {
        return PromptVerdict {
            findings: Vec::new(),
            redacted: prompt.to_string(),
            block: false,
        };
    }
    let spans = find_spans(prompt);
    let mut redacted = String::with_capacity(prompt.len());
    let mut findings = Vec::with_capacity(spans.len());
    let mut cursor = 0usize;
    for (kind, range) in spans {
        let value = &prompt[range.clone()];
        let masked = super::detector::mask(value);
        redacted.push_str(&prompt[cursor..range.start]);
        redacted.push_str(&masked);
        cursor = range.end;
        findings.push(PromptFinding {
            label: kind.label().to_string(),
            kind,
            masked,
        });
    }
    redacted.push_str(&prompt[cursor..]);
    let block = mode == PromptGuardMode::Block && !findings.is_empty();
    PromptVerdict {
        findings,
        redacted,
        block,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Synthetic values in the right shape; none of these is a real credential.
    const GH: &str = "ghp_0123456789abcdefghijABCDEFGHIJ012345";
    const AWS: &str = "AKIAABCDEFGHIJKLMNOP";

    #[test]
    fn clean_prompt_passes() {
        let v = check(
            "please refactor the auth module and add tests",
            PromptGuardMode::Block,
        );
        assert!(v.findings.is_empty());
        assert!(!v.block);
        assert_eq!(v.redacted, "please refactor the auth module and add tests");
        assert!(v.reason().is_none());
    }

    #[test]
    fn token_in_prompt_blocks_and_is_redacted() {
        let p = format!("why does this fail? export GITHUB_TOKEN={GH} then gh pr list");
        let v = check(&p, PromptGuardMode::Block);
        assert!(v.block);
        assert_eq!(v.findings.len(), 1);
        assert_eq!(v.findings[0].kind, SecretKind::GitHubToken);
        assert!(
            !v.redacted.contains(GH),
            "the stored prompt must not contain the secret"
        );
        assert!(v
            .redacted
            .starts_with("why does this fail? export GITHUB_TOKEN=ghp_"));
        assert!(v.redacted.ends_with(" then gh pr list"));
        let r = v.reason().unwrap();
        assert!(r.contains("GitHub Token"));
        assert!(!r.contains(GH));
    }

    #[test]
    fn warn_mode_records_but_does_not_block() {
        let v = check(&format!("key {AWS}"), PromptGuardMode::Warn);
        assert_eq!(v.findings.len(), 1);
        assert!(!v.block);
        assert!(!v.redacted.contains(AWS));
    }

    #[test]
    fn multiple_secrets_all_masked() {
        let p = format!("aws {AWS} and gh {GH} and password = \"hunter2hunter2\"");
        let v = check(&p, PromptGuardMode::Block);
        assert_eq!(v.findings.len(), 3);
        assert!(
            !v.redacted.contains(AWS)
                && !v.redacted.contains(GH)
                && !v.redacted.contains("hunter2hunter2")
        );
        assert!(
            v.redacted.contains("password = \""),
            "only the value is masked, the name stays readable"
        );
    }

    #[test]
    fn off_mode_scans_nothing() {
        let v = check(&format!("{GH}"), PromptGuardMode::Off);
        assert!(v.findings.is_empty() && !v.block);
    }

    #[test]
    fn utf8_text_around_a_secret_is_preserved() {
        let p = format!("résumé → {AWS} ✓");
        let v = check(&p, PromptGuardMode::Block);
        assert!(v.redacted.starts_with("résumé → "));
        assert!(v.redacted.ends_with(" ✓"));
    }
}
