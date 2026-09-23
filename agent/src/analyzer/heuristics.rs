// SPDX-License-Identifier: Apache-2.0
// analyzer/heuristics.rs — pattern-based behavioral risk scoring

use crate::common::event::{EventKind, SecurityEvent};

/// Risk score 0..=100
#[derive(Debug, Clone)]
pub struct RiskScore {
    pub total: u8,
    pub reasons: Vec<String>,
}

impl RiskScore {
    pub fn is_high(&self) -> bool {
        self.total >= 70
    }
    #[allow(dead_code)]
    pub fn is_medium(&self) -> bool {
        self.total >= 40
    }
}

/// Score a timeline of recent events for a single process.
pub fn score(events: &[SecurityEvent]) -> RiskScore {
    let mut exfil_score = 0u8;
    let mut injection_score = 0u8;
    let mut escalation_score = 0u8;
    let mut reasons = Vec::new();

    // ── Exfiltration pattern ─────────────────────────────────────────────────
    // Classic: credential read → DNS lookup → outbound connect → send
    let cred_read = events
        .iter()
        .any(|e| matches!(e.kind, EventKind::FileOpen) && is_credential_path(&e.target));
    let dns_lookup = events.iter().any(|e| matches!(e.kind, EventKind::DnsQuery));
    let net_send = events
        .iter()
        .any(|e| matches!(e.kind, EventKind::NetworkSend));

    if cred_read && dns_lookup && net_send {
        exfil_score = exfil_score.saturating_add(60);
        reasons.push("Credential read → DNS lookup → outbound send (exfil pattern)".into());
    } else if cred_read && net_send {
        exfil_score = exfil_score.saturating_add(40);
        reasons.push("Credential read followed by outbound send".into());
    } else if cred_read {
        exfil_score = exfil_score.saturating_add(10);
    }

    // ── Prompt injection ─────────────────────────────────────────────────────
    // File writes containing injection keywords
    let injection_writes = events
        .iter()
        .filter(|e| matches!(e.kind, EventKind::FileWrite) && has_injection_marker(&e.target))
        .count();
    if injection_writes > 0 {
        injection_score = injection_score.saturating_add((injection_writes * 20).min(60) as u8);
        reasons.push(format!(
            "{} file writes with injection markers",
            injection_writes
        ));
    }

    // ── Privilege escalation ─────────────────────────────────────────────────
    let priv_exec = events
        .iter()
        .any(|e| matches!(e.kind, EventKind::ProcessExec) && is_privilege_binary(&e.target));
    if priv_exec {
        escalation_score = escalation_score.saturating_add(50);
        reasons.push("Privileged binary executed from agent process tree".into());
    }

    // Shell escape patterns in exec targets
    let shell_escape = events
        .iter()
        .any(|e| matches!(e.kind, EventKind::ProcessExec) && has_shell_escape(&e.target));
    if shell_escape {
        escalation_score = escalation_score.saturating_add(30);
        reasons.push("Shell escape pattern detected in exec arguments".into());
    }

    let total = ((exfil_score as u16 + injection_score as u16 + escalation_score as u16) / 3)
        .min(100) as u8;

    RiskScore { total, reasons }
}

fn is_credential_path(path: &str) -> bool {
    const CRED_PATHS: &[&str] = &[
        ".ssh/",
        ".aws/credentials",
        ".aws/config",
        ".config/gcloud",
        "keychain",
        "Keychain",
        ".gnupg/",
        ".netrc",
        ".npmrc",
        ".pypirc",
        "id_rsa",
        "id_ed25519",
        "id_ecdsa",
    ];
    CRED_PATHS.iter().any(|c| path.contains(c))
}

fn has_injection_marker(path: &str) -> bool {
    // Heuristic: skill writing files with suspicious names
    const MARKERS: &[&str] = &[
        "ignore_previous",
        "system_prompt",
        "jailbreak",
        "forget_instructions",
        "new_instructions",
    ];
    let lower = path.to_lowercase();
    MARKERS.iter().any(|m| lower.contains(m))
}

fn is_privilege_binary(target: &str) -> bool {
    const PRIV_BINS: &[&str] = &[
        "/usr/bin/sudo",
        "/bin/su",
        "/usr/bin/su",
        "doas",
        "/usr/bin/security",
        "security find-generic-password",
        "secret-tool",
        "/usr/bin/passwd",
    ];
    PRIV_BINS
        .iter()
        .any(|b| target.starts_with(b) || target.contains(b))
}

fn has_shell_escape(target: &str) -> bool {
    const ESCAPES: &[&str] = &[
        "bash -i",
        "bash -c",
        "sh -i",
        "sh -c",
        "python -c",
        "python3 -c",
        "perl -e",
        "ruby -e",
        "node -e",
        "/bin/bash",
        "/bin/sh",
    ];
    ESCAPES.iter().any(|e| target.contains(e))
}
