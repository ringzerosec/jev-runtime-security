// SPDX-License-Identifier: Apache-2.0
//
// privileged.rs — how the viewer changes something it is not allowed to change.
//
// THE TOKEN MODEL DOES NOT CHANGE. This app holds the READ-ONLY token and only
// ever holds that one. An AI coding agent runs as the same user as the person
// using this app, so a full-scope token anywhere in that user's reach would
// hand the agent the ability to turn enforcement off. Nothing here reads, moves
// or copies the full token: it never enters this process.
//
// WHAT THIS DOES INSTEAD. A write action runs the equivalent `rz` command
// through `pkexec`. Polkit authenticates an administrator, `rz` runs as root,
// and root is where the full-scope token lives. The privilege boundary is the
// polkit prompt, not a token this process is holding.
//
// WHY THAT IS THE PROPERTY WE WANT. The prompt requires an interactive
// administrator authentication (`auth_admin`, with no remembered answer, in
// packaging/polkit/com.ringzerosecurity.app.policy). An agent running as the
// developer, with no password and no way to answer an authentication dialog,
// cannot satisfy it non-interactively. A human at the machine can. That is
// exactly the line we are trying to draw, and it is drawn by polkit rather than
// by us hiding a button.
//
// WHAT IS ALLOWED. `validate` below is an allow-list of complete command
// shapes. The webview cannot ask this process to run an arbitrary `rz`
// subcommand, let alone an arbitrary program: arguments are passed as argv, so
// there is no shell to inject into, and anything not on the list is refused
// before `pkexec` is reached.

use std::path::Path;
use std::process::Command;

/// The exact binary polkit is annotated for. Anything else would fall back to
/// the generic `org.freedesktop.policykit.exec` action, so this path and the
/// `exec.path` annotation in the policy file must stay in step.
pub const RZ_PATH: &str = "/usr/bin/rz";

/// What happened. Every variant is something the UI can say out loud; there is
/// no variant that means "it quietly did not work".
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// The command ran as root and exited 0.
    Ok { stdout: String },
    /// The authentication dialog was dismissed, or authentication failed.
    Cancelled,
    /// There is no `pkexec`, no `rz`, or polkit could not run it at all.
    Unavailable { message: String },
    /// It ran and failed. `stderr` is the command's own words.
    Failed { code: i32, stderr: String },
}

impl Outcome {
    pub fn status(&self) -> &'static str {
        match self {
            Outcome::Ok { .. } => "ok",
            Outcome::Cancelled => "cancelled",
            Outcome::Unavailable { .. } => "unavailable",
            Outcome::Failed { .. } => "failed",
        }
    }
}

/// A value that goes into argv. No control characters, no NUL, bounded.
///
/// argv means there is no shell and therefore no quoting to get wrong; this is
/// about keeping a terminal-hostile or absurd value out of a root command, not
/// about escaping.
fn sane_value(v: &str, max: usize) -> bool {
    !v.is_empty() && v.len() <= max && !v.chars().any(|c| c.is_control())
}

/// An identifier or keyword: conservative on purpose.
fn sane_token(v: &str, max: usize) -> bool {
    !v.is_empty()
        && v.len() <= max
        && v.chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
}

/// The complete set of command shapes this app may ask polkit to run.
///
/// Adding to this list is adding to what a compromised webview could ask an
/// administrator to authorise, so each entry is a whole command, not a prefix.
pub fn validate(args: &[String]) -> Result<(), String> {
    let a: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
    match a.as_slice() {
        // rz file-access add <pattern> <block|allow> [--dir|--file] [-d <description>]
        //
        // The kind flag is how a directory rule says it is one. It used to be
        // inferred from whether the description happened to contain
        // "[dir-block]", which meant an edit to a human note could disarm a
        // rule; the app now says it outright.
        ["file-access", "add", pattern, action, rest @ ..] => {
            if !sane_value(pattern, 4096) {
                return Err("file pattern is empty or has control characters".into());
            }
            if !matches!(*action, "block" | "allow") {
                return Err(format!("action must be block or allow, got {action:?}"));
            }
            let mut i = 0;
            let mut seen_kind = false;
            let mut seen_description = false;
            while i < rest.len() {
                match rest[i] {
                    "--dir" | "--file" => {
                        if seen_kind {
                            return Err("the rule kind was given twice".into());
                        }
                        seen_kind = true;
                        i += 1;
                    }
                    "-d" => {
                        if seen_description {
                            return Err("the description was given twice".into());
                        }
                        let Some(text) = rest.get(i + 1) else {
                            return Err("-d needs a description after it".into());
                        };
                        if !sane_value(text, 512) {
                            return Err("description is empty or has control characters".into());
                        }
                        seen_description = true;
                        i += 2;
                    }
                    other => {
                        return Err(format!(
                            "this app will not pass {other:?} to a root command"
                        ))
                    }
                }
            }
            Ok(())
        }
        // rz file-access remove <id>
        ["file-access", "remove", id] => {
            if !sane_token(id, 128) {
                return Err("rule id is not an identifier".into());
            }
            Ok(())
        }
        // rz enforcement set-default <action>
        ["enforcement", "set-default", action] => {
            if !matches!(*action, "observe" | "alert" | "block") {
                return Err(format!(
                    "action must be observe, alert or block, got {action:?}"
                ));
            }
            Ok(())
        }
        // rz enforcement set-category <category> <action>
        ["enforcement", "set-category", category, action] => {
            if !sane_token(category, 64) {
                return Err("category is not an identifier".into());
            }
            if !matches!(*action, "observe" | "alert" | "block") {
                return Err(format!(
                    "action must be observe, alert or block, got {action:?}"
                ));
            }
            Ok(())
        }
        // rz review label <id> <label>
        ["review", "label", id, label] => {
            if !sane_token(id, 128) {
                return Err("review id is not an identifier".into());
            }
            if !matches!(*label, "benign" | "real-threat" | "false-positive") {
                return Err(format!(
                    "label must be benign, real-threat or false-positive, got {label:?}"
                ));
            }
            Ok(())
        }
        _ => Err(format!(
            "this app will not run `rz {}` with elevated privilege",
            args.join(" ")
        )),
    }
}

/// The command as a human would type it, for showing before and after the
/// prompt. Never used to build the invocation — that is argv.
pub fn display_command(args: &[String]) -> String {
    format!("sudo rz {}", args.join(" "))
}

/// Run one allow-listed `rz` command through polkit.
///
/// Blocking: `pkexec` sits there while a human authenticates. Callers run this
/// off the UI thread.
pub fn run(args: &[String]) -> Outcome {
    if let Err(e) = validate(args) {
        return Outcome::Unavailable { message: e };
    }
    if !Path::new(RZ_PATH).exists() {
        return Outcome::Unavailable {
            message: format!("{RZ_PATH} is not installed, so there is nothing to run as root"),
        };
    }

    let output = match Command::new("pkexec").arg(RZ_PATH).args(args).output() {
        Ok(o) => o,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Outcome::Unavailable {
                message: "pkexec is not installed, so this app cannot ask for authentication"
                    .to_string(),
            }
        }
        Err(e) => {
            return Outcome::Unavailable {
                message: format!("could not start pkexec: {e}"),
            }
        }
    };

    let code = output.status.code().unwrap_or(-1);
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();

    // pkexec(1): 126 means the authentication failed or the dialog was
    // dismissed; 127 means the program could not be run at all. Both are the
    // app's fault to explain, not the user's to decode.
    match code {
        0 => Outcome::Ok { stdout },
        126 => Outcome::Cancelled,
        // 127 is also what a caller with nothing to authenticate through gets:
        // no polkit agent and no controlling terminal, which is exactly what a
        // background process looks like. Say that, and keep polkit's own words.
        127 => Outcome::Unavailable {
            message: if stderr.is_empty() {
                "polkit could not authenticate this change (no authentication agent available)"
                    .to_string()
            } else {
                format!("polkit could not authenticate this change: {stderr}")
            },
        },
        other => Outcome::Failed {
            code: other,
            stderr: if stderr.is_empty() { stdout } else { stderr },
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(args: &[&str]) -> Result<(), String> {
        validate(&args.iter().map(|s| s.to_string()).collect::<Vec<_>>())
    }

    #[test]
    fn the_three_write_actions_are_allowed() {
        assert!(v(&["file-access", "add", "*id_rsa", "block"]).is_ok());
        assert!(v(&[
            "file-access",
            "add",
            "~/.aws/*",
            "block",
            "-d",
            "AWS credentials"
        ])
        .is_ok());
        assert!(v(&["file-access", "remove", "rule-17"]).is_ok());
        assert!(v(&["enforcement", "set-default", "block"]).is_ok());
        assert!(v(&["enforcement", "set-category", "credential_access", "alert"]).is_ok());
        assert!(v(&["review", "label", "abc123", "false-positive"]).is_ok());
    }

    /// The allow-list is the whole point: a webview that has been taken over
    /// must not be able to pick the command an administrator is asked to
    /// authorise.
    #[test]
    fn anything_else_is_refused() {
        for bad in [
            vec!["status"],
            vec!["run", "bash"],
            vec!["sandbox", "sh"],
            vec!["setup", "--all"],
            vec!["checks", "set-key"],
            vec!["file-access"],
            vec!["file-access", "add"],
            // A prefix match would have let this through.
            vec!["file-access", "remove", "id", "extra"],
            vec![
                "enforcement",
                "set-default",
                "block",
                "--api",
                "http://evil",
            ],
            // No unknown flag is ever forwarded to a command that runs as root.
            vec!["file-access", "add", "x", "block", "--api", "http://evil"],
            vec!["file-access", "add", "x", "block", "-d"],
            vec!["file-access", "add", "x", "block", "--dir", "--file"],
            vec!["file-access", "add", "x", "block", "-d", "a", "-d", "b"],
        ] {
            assert!(v(&bad).is_err(), "must refuse: {bad:?}");
        }
    }

    #[test]
    fn values_outside_the_fixed_sets_are_refused() {
        assert!(v(&["enforcement", "set-default", "off"]).is_err());
        assert!(v(&["enforcement", "set-category", "cred access", "block"]).is_err());
        assert!(v(&["file-access", "add", "*.pem", "delete"]).is_err());
        assert!(v(&["review", "label", "abc", "looks-fine"]).is_err());
        assert!(v(&["file-access", "remove", "../../etc/passwd"]).is_err());
    }

    #[test]
    fn control_characters_never_reach_a_root_command() {
        assert!(v(&["file-access", "add", "a\nb", "block"]).is_err());
        assert!(v(&["file-access", "add", "ok", "block", "-d", "line\r\nbreak"]).is_err());
        assert!(v(&["file-access", "add", "", "block"]).is_err());
    }

    #[test]
    fn the_displayed_command_is_what_a_human_would_type() {
        let args: Vec<String> = ["enforcement", "set-default", "block"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        assert_eq!(
            display_command(&args),
            "sudo rz enforcement set-default block"
        );
    }
}
