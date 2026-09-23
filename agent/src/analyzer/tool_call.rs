// SPDX-License-Identifier: Apache-2.0
// analyzer/tool_call.rs — the runtime structured-action interface.
//
// The fine-tuned on-device FunctionGemma reads a provenance-graph context and
// emits EXACTLY ONE function call (see ml/schema/security_tools.json). This
// module parses that call into a typed `SecurityToolCall` the daemon can act on
// — turning the model's *decision* into a dispatchable action (alert / block /
// quarantine / escalate), not prose.
//
// Parsing is deliberately lenient: small models wrap JSON in ``` fences, add
// prose around it, or omit optional fields. We recover the call where we can
// and fail closed (Err) only when there is no recognisable call at all.

use serde::{Deserialize, Serialize};

use crate::analyzer::slm::{SlmAction, SlmVerdict};

/// Severity buckets mirror ml/schema/security_tools.json.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    /// Lenient parse — defaults to High when a non-benign tool gives no/garbage severity.
    pub fn parse(s: &str) -> Severity {
        match s.trim().to_ascii_lowercase().as_str() {
            "low" => Severity::Low,
            "medium" | "med" => Severity::Medium,
            "high" => Severity::High,
            "critical" | "crit" => Severity::Critical,
            _ => Severity::High,
        }
    }

    /// Representative risk score (0-100) for downstream handling / SIEM.
    pub fn risk_score(self) -> u32 {
        match self {
            Severity::Low => 20,
            Severity::Medium => 45,
            Severity::High => 70,
            Severity::Critical => 92,
        }
    }
}

/// One parsed defensive action emitted by the edge model.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "tool", rename_all = "lowercase")]
pub enum SecurityToolCall {
    Allow {
        rationale: String,
    },
    Alert {
        severity: Severity,
        category: String,
        mitre_id: String,
        rationale: String,
    },
    Block {
        severity: Severity,
        category: String,
        mitre_id: String,
        target: String,
        rationale: String,
    },
    Quarantine {
        /// 0 = session-wide containment.
        pid: u32,
        category: String,
        rationale: String,
    },
    Escalate {
        action_requested: String,
        category: String,
        rationale: String,
    },
}

impl SecurityToolCall {
    /// The tool name as in the schema (for logging / metrics).
    pub fn name(&self) -> &'static str {
        match self {
            SecurityToolCall::Allow { .. } => "allow",
            SecurityToolCall::Alert { .. } => "alert",
            SecurityToolCall::Block { .. } => "block",
            SecurityToolCall::Quarantine { .. } => "quarantine",
            SecurityToolCall::Escalate { .. } => "escalate",
        }
    }

    /// Coarse enforcement action, so a tool call flows through the daemon's
    /// existing Allow/Alert/Block verdict handling. Quarantine is the strongest
    /// (containment → Block); Escalate pauses for a human (→ Alert).
    pub fn action(&self) -> SlmAction {
        match self {
            SecurityToolCall::Allow { .. } => SlmAction::Allow,
            SecurityToolCall::Alert { .. } => SlmAction::Alert,
            SecurityToolCall::Block { .. } => SlmAction::Block,
            SecurityToolCall::Quarantine { .. } => SlmAction::Block,
            SecurityToolCall::Escalate { .. } => SlmAction::Alert,
        }
    }

    pub fn risk_score(&self) -> u32 {
        match self {
            SecurityToolCall::Allow { .. } => 5,
            SecurityToolCall::Alert { severity, .. } | SecurityToolCall::Block { severity, .. } => {
                severity.risk_score()
            }
            SecurityToolCall::Quarantine { .. } => 95,
            SecurityToolCall::Escalate { .. } => 50,
        }
    }

    pub fn rationale(&self) -> &str {
        match self {
            SecurityToolCall::Allow { rationale }
            | SecurityToolCall::Alert { rationale, .. }
            | SecurityToolCall::Block { rationale, .. }
            | SecurityToolCall::Quarantine { rationale, .. }
            | SecurityToolCall::Escalate { rationale, .. } => rationale,
        }
    }

    /// Map into the existing SlmVerdict so edge-model output reuses every
    /// downstream path (threat broadcast, SIEM forward, status metrics).
    pub fn to_verdict(&self, model: &str, latency_ms: u64) -> SlmVerdict {
        // Prefix the explanation with the tool name so operators see the precise
        // action the brain chose, not just the coarse Allow/Alert/Block.
        let explanation = format!("[{}] {}", self.name(), self.rationale());
        // Compile the judgment into L0 eBPF policy here, while the structured
        // call (with its target/pid) still exists — the coarse SlmVerdict drops
        // those fields. analyze_graph pushes the resulting `l0_rules` to the kernel.
        let policy = crate::analyzer::rule_compiler::compile(self);
        SlmVerdict {
            risk_score: self.risk_score(),
            explanation,
            action: self.action(),
            model: model.to_string(),
            latency_ms,
            compiled_rules: policy.notes,
            l0_rules: policy.commands,
        }
    }
}

/// Strip ``` fences / leading prose and isolate the first balanced JSON object.
fn extract_json_object(text: &str) -> Option<&str> {
    let bytes = text.as_bytes();
    let start = text.find('{')?;
    let mut depth = 0usize;
    let mut in_str = false;
    let mut escaped = false;
    for i in start..bytes.len() {
        let c = bytes[i] as char;
        if in_str {
            if escaped {
                escaped = false;
            } else if c == '\\' {
                escaped = true;
            } else if c == '"' {
                in_str = false;
            }
            continue;
        }
        match c {
            '"' => in_str = true,
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    return Some(&text[start..=i]);
                }
            }
            _ => {}
        }
    }
    None
}

fn str_field(args: &serde_json::Value, key: &str) -> String {
    args.get(key)
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim()
        .to_string()
}

/// Parse the model's emitted text into a SecurityToolCall.
///
/// Accepts both `{"name": "...", "arguments": {...}}` (Gemini / function-calling
/// convention) and `{"tool": "...", ...flattened-args}`. Lenient about fences,
/// missing optional fields, and pid as string/number. Fails closed.
pub fn parse_tool_call(text: &str) -> anyhow::Result<SecurityToolCall> {
    let json_str = extract_json_object(text)
        .ok_or_else(|| anyhow::anyhow!("no JSON object found in model output"))?;
    let v: serde_json::Value = serde_json::from_str(json_str)
        .map_err(|e| anyhow::anyhow!("tool call is not valid JSON: {e}"))?;

    // Tool name may live in "name" or "tool".
    let name = v
        .get("name")
        .or_else(|| v.get("tool"))
        .and_then(|x| x.as_str())
        .map(|s| s.trim().to_ascii_lowercase())
        .ok_or_else(|| anyhow::anyhow!("tool call missing name/tool field"))?;

    // Arguments may be nested under "arguments"/"args" or flattened at top level.
    let args = v
        .get("arguments")
        .or_else(|| v.get("args"))
        .cloned()
        .unwrap_or_else(|| v.clone());

    let pid = args
        .get("pid")
        .map(|p| {
            p.as_u64()
                .or_else(|| p.as_str().and_then(|s| s.trim().parse::<u64>().ok()))
                .unwrap_or(0) as u32
        })
        .unwrap_or(0);

    let call = match name.as_str() {
        "allow" => SecurityToolCall::Allow {
            rationale: str_field(&args, "rationale"),
        },
        "alert" => SecurityToolCall::Alert {
            severity: Severity::parse(&str_field(&args, "severity")),
            category: str_field(&args, "category"),
            mitre_id: str_field(&args, "mitre_id"),
            rationale: str_field(&args, "rationale"),
        },
        "block" => SecurityToolCall::Block {
            severity: Severity::parse(&str_field(&args, "severity")),
            category: str_field(&args, "category"),
            mitre_id: str_field(&args, "mitre_id"),
            target: str_field(&args, "target"),
            rationale: str_field(&args, "rationale"),
        },
        "quarantine" => SecurityToolCall::Quarantine {
            pid,
            category: str_field(&args, "category"),
            rationale: str_field(&args, "rationale"),
        },
        "escalate" => SecurityToolCall::Escalate {
            action_requested: str_field(&args, "action_requested"),
            category: str_field(&args, "category"),
            rationale: str_field(&args, "rationale"),
        },
        other => anyhow::bail!("unknown tool: {other}"),
    };
    Ok(call)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_block_function_calling_form() {
        let out = r#"{"name": "block", "arguments": {"severity": "critical", "category": "credential_access", "mitre_id": "T1552", "target": "/home/u/.ssh/id_rsa", "rationale": "SSH key read by coding agent"}}"#;
        let call = parse_tool_call(out).unwrap();
        assert_eq!(call.name(), "block");
        assert_eq!(call.action(), SlmAction::Block);
        assert_eq!(call.risk_score(), 92);
        match call {
            SecurityToolCall::Block {
                severity,
                category,
                target,
                ..
            } => {
                assert_eq!(severity, Severity::Critical);
                assert_eq!(category, "credential_access");
                assert_eq!(target, "/home/u/.ssh/id_rsa");
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn parse_strips_code_fences_and_prose() {
        let out = "Here is my decision:\n```json\n{\"tool\":\"alert\",\"args\":{\"severity\":\"high\",\"category\":\"exfiltration\",\"rationale\":\"cred read then outbound\"}}\n```\nDone.";
        let call = parse_tool_call(out).unwrap();
        assert_eq!(call.name(), "alert");
        assert_eq!(call.action(), SlmAction::Alert);
    }

    #[test]
    fn parse_allow_minimal() {
        let call =
            parse_tool_call(r#"{"name":"allow","arguments":{"rationale":"in baseline"}}"#).unwrap();
        assert_eq!(call.action(), SlmAction::Allow);
        assert_eq!(call.risk_score(), 5);
    }

    #[test]
    fn quarantine_maps_to_block_enforcement() {
        let call = parse_tool_call(r#"{"name":"quarantine","arguments":{"pid":"5641","category":"exfiltration","rationale":"session compromised"}}"#).unwrap();
        assert_eq!(call.action(), SlmAction::Block); // strongest enforcement
        match call {
            SecurityToolCall::Quarantine { pid, .. } => assert_eq!(pid, 5641),
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn escalate_maps_to_alert() {
        let call = parse_tool_call(r#"{"name":"escalate","arguments":{"action_requested":"read ~/.aws/credentials","rationale":"ambiguous intent"}}"#).unwrap();
        assert_eq!(call.action(), SlmAction::Alert);
    }

    #[test]
    fn severity_defaults_high_when_missing() {
        let call = parse_tool_call(
            r#"{"name":"block","arguments":{"category":"tampering","rationale":"x"}}"#,
        )
        .unwrap();
        assert_eq!(call.risk_score(), Severity::High.risk_score());
    }

    #[test]
    fn unknown_tool_errors() {
        assert!(parse_tool_call(r#"{"name":"nuke","arguments":{}}"#).is_err());
    }

    #[test]
    fn no_json_errors() {
        assert!(parse_tool_call("I think this is fine, allow it.").is_err());
    }

    #[test]
    fn to_verdict_prefixes_tool_name() {
        let call = parse_tool_call(r#"{"name":"allow","arguments":{"rationale":"routine read"}}"#)
            .unwrap();
        let v = call.to_verdict("functiongemma-rz", 12);
        assert!(v.explanation.starts_with("[allow]"));
        assert_eq!(v.model, "functiongemma-rz");
        assert_eq!(v.latency_ms, 12);
    }
}
