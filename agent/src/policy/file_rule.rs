// SPDX-License-Identifier: Apache-2.0
//
// file_rule.rs — what a file-access rule means, and whether it can enforce.
//
// THE BUG THIS EXISTS TO PREVENT. A rule used to be stored whether or not any
// kernel mechanism could act on it. `~/projects/*` was accepted, listed by
// `rz file-access show` as BLOCK, and enforced nothing: the basename map is
// keyed on whole basenames, so a pattern whose basename is `*` expands to
// nothing, and the inode pin is skipped for anything containing a glob. The
// only thing that made a directory rule work was the literal substring
// `[dir-block]` appearing in the human-readable description, so whether a rule
// enforced depended on a note someone typed. A save path that dropped the
// description silently disarmed the rule.
//
// THE RULE NOW. If a rule is stored, some mechanism can act on it. If nothing
// can, it is refused at the point of entry with a reason. What a rule IS lives
// in a real field, `kind`, never in prose.
//
// THREE MECHANISMS, and a rule enforces through at least one:
//
//   basename map   `blocked_files`, keyed on a whole basename. This is what
//                  makes `.env` or `id_rsa` work anywhere on the machine.
//   inode pin      `blocked_inodes`, keyed on (dev, ino) for one concrete
//                  existing file, so a rename or hardlink cannot dodge it.
//   directory      `blocked_dir_inodes`, keyed on the directory's (dev, ino),
//                  which refuses every file underneath.
//
// A directory rule ALSO contributes its basenames where it has any. That is
// deliberate: inferring `kind = dir` for an existing rule like `~/.ssh/*` must
// not take away the basename protection that rule already had. The inference
// can only add.

/// What a rule is about. Stored in the rule, never inferred from prose.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// One file, or a basename wherever it appears.
    File,
    /// A directory: everything underneath it is refused.
    Dir,
}

impl Kind {
    pub fn as_str(self) -> &'static str {
        match self {
            Kind::File => "file",
            Kind::Dir => "dir",
        }
    }

    pub fn parse(s: &str) -> Option<Kind> {
        match s {
            "file" => Some(Kind::File),
            "dir" => Some(Kind::Dir),
            _ => None,
        }
    }
}

/// Whether the kernel can act on a rule as it stands right now.
///
/// This is about resolution, not a readback of the BPF map: it answers "is
/// there something at this path for the kernel to pin", which is the failure
/// the operator actually hits. A rule that is fine in shape but points at a
/// directory that does not exist yet is `Unresolved`, and must be shown
/// differently from one that is live.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    /// The kernel holds this, or will on the next load.
    Enforced,
    /// Accepted, but nothing at that path resolves yet, so the kernel holds
    /// nothing for it.
    Unresolved,
}

impl Status {
    pub fn as_str(self) -> &'static str {
        match self {
            Status::Enforced => "enforced",
            Status::Unresolved => "unresolved",
        }
    }
}

/// Expand a leading `~` against the operator's home, not the daemon's.
///
/// The daemon runs as root, so `$HOME` is `/root`, but a rule written in the
/// app or the CLI means the person's home. One copy of this, used by the API,
/// the loader and the validator, so all three agree on what a pattern points
/// at.
pub fn expand_tilde(path: &str) -> String {
    if !path.starts_with('~') {
        return path.to_string();
    }
    if let Ok(entries) = std::fs::read_dir("/home") {
        for entry in entries.flatten() {
            if entry.path().is_dir() {
                let candidate = path.replacen('~', &entry.path().to_string_lossy(), 1);
                if std::path::Path::new(&candidate).exists() {
                    return candidate;
                }
            }
        }
    }
    let fallback = path.replacen('~', "/root", 1);
    if std::path::Path::new(&fallback).exists() {
        return fallback;
    }
    if let Ok(entries) = std::fs::read_dir("/home") {
        if let Some(first) = entries.flatten().find(|e| e.path().is_dir()) {
            return path.replacen('~', &first.path().to_string_lossy(), 1);
        }
    }
    path.replacen(
        '~',
        &std::env::var("HOME").unwrap_or_else(|_| "/root".into()),
        1,
    )
}

/// The directory a `dir` rule refers to, with the trailing glob taken off.
pub fn dir_target(pattern: &str) -> String {
    expand_tilde(pattern.trim().trim_end_matches("/*").trim_end_matches('/'))
}

/// True if this pattern names a concrete file the inode pin can hold.
fn is_concrete_path(pattern: &str) -> bool {
    let expanded = expand_tilde(pattern.trim());
    expanded.starts_with('/') && !expanded.contains(['*', '?', '['])
}

/// Decide what an incoming rule is.
///
/// Explicit `kind` wins. Everything else is for rules written before the field
/// existed, so an upgrade does not silently change what a machine enforces.
///
/// `legacy_marker_used` is set when the decision came from the old
/// `[dir-block]` description marker, so the caller can say so once in the log
/// and we can drop that path in a later release.
pub fn infer_kind(
    pattern: &str,
    explicit_kind: Option<&str>,
    description: Option<&str>,
    legacy_marker_used: &mut bool,
) -> Kind {
    if let Some(k) = explicit_kind.and_then(Kind::parse) {
        return k;
    }
    // LEGACY, one release only: a description that says [dir-block]. Read so
    // that an existing install keeps enforcing exactly what it enforced before
    // the field existed.
    if description.is_some_and(|d| d.contains("[dir-block]")) {
        *legacy_marker_used = true;
        return Kind::Dir;
    }
    let p = pattern.trim();
    if p.ends_with("/*") {
        return Kind::Dir;
    }
    if !p.is_empty() && std::path::Path::new(&expand_tilde(p)).is_dir() {
        return Kind::Dir;
    }
    Kind::File
}

/// The identity of a rule: what it actually does, not how it was written.
///
/// Two rules are the same rule when they resolve to the same target with the
/// same action and kind. `~/projects/*` and `/home/dev/projects/*` are one
/// rule, not two, and adding the second must not produce a duplicate row.
///
/// The description is deliberately NOT part of this. It is a human note, and a
/// second add with a better note should update the note rather than create a
/// rule that blocks the same path twice.
pub fn identity(pattern: &str, kind: Kind, action: &str) -> (String, &'static str, String) {
    let resolved = match kind {
        // A directory rule is its directory, however it was spelled.
        Kind::Dir => dir_target(pattern),
        Kind::File => expand_tilde(pattern.trim()),
    };
    // Resolve symlinks, so one directory has one identity.
    //
    // Found the hard way: a box with /home/alice.linux symlinked to
    // /home/alice.guest gave `~/projects/*` and `/home/alice.guest/projects/*`
    // two different strings for one directory, and both were stored. The
    // kernel side never had this problem, because it pins (dev, ino) and both
    // spellings stat to the same inode — it was only the bookkeeping that saw
    // two rules. A path that does not exist yet cannot be canonicalised, and
    // then the lexical form stands.
    let resolved = std::fs::canonicalize(&resolved)
        .map(|p| p.to_string_lossy().to_string())
        .unwrap_or(resolved);
    (resolved, kind.as_str(), action.trim().to_string())
}

/// Do these two rules do the same thing?
pub fn same_rule(
    a_pattern: &str,
    a_kind: Kind,
    a_action: &str,
    b_pattern: &str,
    b_kind: Kind,
    b_action: &str,
) -> bool {
    identity(a_pattern, a_kind, a_action) == identity(b_pattern, b_kind, b_action)
}

/// Refuse a rule nothing can enforce.
///
/// `Ok(())` means at least one mechanism applies to this shape. It does not
/// promise the path exists — that is `status`, and it is reported separately
/// rather than being a reason to reject, because an operator may legitimately
/// write a rule for a directory they are about to create.
pub fn validate(pattern: &str, kind: Kind, action: &str) -> Result<(), String> {
    let p = pattern.trim();
    if p.is_empty() {
        return Err("a rule needs a pattern".to_string());
    }
    if !matches!(action, "block" | "allow") {
        return Err(format!("action must be block or allow, got {action:?}"));
    }
    // An allow rule scopes what an agent may touch; it is not pushed through
    // the basename map, so the shape requirements below do not apply to it.
    if action == "allow" {
        return Ok(());
    }

    match kind {
        Kind::Dir => {
            let target = dir_target(p);
            if target.is_empty() || target == "/" {
                return Err(format!(
                    "{p:?} is not a directory this can block. Name the directory, \
                     for example ~/projects/*"
                ));
            }
            if target.contains(['*', '?', '[']) {
                return Err(format!(
                    "{p:?} still has a glob in it after the trailing /*. A directory rule \
                     names one directory, for example ~/projects/*"
                ));
            }
            Ok(())
        }
        Kind::File => {
            if is_concrete_path(p) {
                return Ok(());
            }
            if !crate::api::routes::pattern_to_basenames(p).is_empty() {
                return Ok(());
            }
            // Everything that reaches here matches nothing in the kernel.
            // Say which of the two mistakes it is.
            if p.starts_with("*.") {
                Err(format!(
                    "{p:?} cannot be enforced: the kernel matches whole file names, not \
                     extensions. Name the file itself, or block the directory it lives in \
                     with a trailing /*"
                ))
            } else {
                Err(format!(
                    "{p:?} cannot be enforced: it expands to no file name the kernel can \
                     match. If you meant everything inside a directory, add a trailing /* \
                     to make it a directory rule"
                ))
            }
        }
    }
}

/// Can the kernel hold this rule as things stand?
pub fn status(pattern: &str, kind: Kind, action: &str) -> Status {
    if action != "block" {
        return Status::Enforced;
    }
    match kind {
        Kind::Dir => {
            if std::path::Path::new(&dir_target(pattern)).is_dir() {
                Status::Enforced
            } else {
                Status::Unresolved
            }
        }
        Kind::File => {
            // A basename rule needs nothing to exist: the map is keyed on the
            // name, and it bites the moment such a file is opened.
            if !crate::api::routes::pattern_to_basenames(pattern).is_empty() {
                return Status::Enforced;
            }
            // A concrete path is pinned by (dev, ino), which needs the file.
            if is_concrete_path(pattern)
                && std::path::Path::new(&expand_tilde(pattern.trim())).exists()
            {
                Status::Enforced
            } else {
                Status::Unresolved
            }
        }
    }
}

/// Why a rule is not live, in words an operator can act on.
pub fn unresolved_reason(pattern: &str, kind: Kind) -> String {
    match kind {
        Kind::Dir => format!(
            "no directory at {} yet, so the kernel holds nothing for this rule",
            dir_target(pattern)
        ),
        Kind::File => format!(
            "no file at {} yet, so the kernel holds nothing for this rule",
            expand_tilde(pattern.trim())
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every shape the CLI and the API accept, and what must happen to it.
    ///
    /// This table is the contract. A shape that is accepted has a mechanism; a
    /// shape that is refused has none. The bug that started this was a shape in
    /// the first column being stored and enforcing nothing.
    const SHAPES: &[(&str, &str, bool)] = &[
        // (pattern, kind, accepted?)
        // Directory rules.
        ("~/projects/*", "dir", true),
        ("/srv/data/*", "dir", true),
        ("~/projects", "dir", true),
        ("*", "dir", false),
        ("/*", "dir", false),
        ("~/*/build/*", "dir", false),
        // Concrete files: pinned by inode.
        ("/etc/shadow", "file", true),
        ("~/.config/thing.conf", "file", true),
        // Basenames the expander knows.
        ("~/.ssh/*", "file", true),
        ("~/.aws/*", "file", true),
        (".env*", "file", true),
        ("*.env", "file", true),
        (".git-credentials", "file", true),
        ("id_rsa", "file", true),
        // Nothing in the kernel matches these.
        ("*.pem", "file", false),
        ("*.key", "file", false),
        ("~/projects/*", "file", false),
        ("*", "file", false),
        ("", "file", false),
    ];

    #[test]
    fn every_accepted_shape_has_a_mechanism_and_every_refused_one_does_not() {
        for (pattern, kind, accepted) in SHAPES {
            let k = Kind::parse(kind).expect("test kind");
            let got = validate(pattern, k, "block");
            assert_eq!(
                got.is_ok(),
                *accepted,
                "pattern {pattern:?} as {kind}: expected accepted={accepted}, got {got:?}"
            );
            if !*accepted {
                let msg = got.unwrap_err();
                assert!(
                    msg.len() > 20,
                    "a refusal must say why, got {msg:?} for {pattern:?}"
                );
            }
        }
    }

    /// The reported defect, as a test: the rule the user added enforced
    /// nothing and was still stored.
    #[test]
    fn the_bare_directory_glob_is_never_silently_stored_as_a_file_rule() {
        // As a file rule it is refused outright.
        assert!(validate("~/projects/*", Kind::File, "block").is_err());
        // And it is not read as one in the first place: a trailing /* is a
        // directory rule whether or not anybody typed a description.
        let mut legacy = false;
        assert_eq!(
            infer_kind("~/projects/*", None, None, &mut legacy),
            Kind::Dir
        );
        assert!(!legacy, "no description was involved");
        assert!(validate("~/projects/*", Kind::Dir, "block").is_ok());
    }

    #[test]
    fn an_explicit_kind_beats_every_guess() {
        let mut legacy = false;
        // A trailing /* would infer dir, but the field says file.
        assert_eq!(
            infer_kind("~/x/*", Some("file"), Some("[dir-block] note"), &mut legacy),
            Kind::File
        );
        assert!(!legacy, "the marker must not be consulted when kind is set");
        assert_eq!(
            infer_kind("id_rsa", Some("dir"), None, &mut legacy),
            Kind::Dir
        );
    }

    /// The old marker still works for one release, and says so.
    #[test]
    fn the_legacy_description_marker_is_read_and_flagged() {
        let mut legacy = false;
        let k = infer_kind(
            "~/projects",
            None,
            Some("Block directory [dir-block]"),
            &mut legacy,
        );
        assert_eq!(k, Kind::Dir);
        assert!(legacy, "using the old marker must be reportable");
    }

    /// Description is a human note. It cannot decide anything on its own.
    #[test]
    fn an_ordinary_description_changes_nothing() {
        let mut legacy = false;
        assert_eq!(
            infer_kind("id_rsa", None, Some("my ssh key"), &mut legacy),
            Kind::File
        );
        assert!(!legacy);
    }

    #[test]
    fn a_directory_that_does_not_exist_is_accepted_but_not_reported_as_live() {
        let pattern = "/definitely/not/here/*";
        assert!(validate(pattern, Kind::Dir, "block").is_ok());
        assert_eq!(status(pattern, Kind::Dir, "block"), Status::Unresolved);
        assert!(unresolved_reason(pattern, Kind::Dir).contains("/definitely/not/here"));
    }

    #[test]
    fn a_basename_rule_is_live_without_the_file_existing() {
        assert_eq!(status(".env*", Kind::File, "block"), Status::Enforced);
        assert_eq!(status("~/.ssh/*", Kind::File, "block"), Status::Enforced);
    }

    #[test]
    fn a_directory_that_exists_is_live() {
        assert_eq!(status("/tmp/*", Kind::Dir, "block"), Status::Enforced);
    }

    #[test]
    fn allow_rules_are_not_held_to_the_block_shapes() {
        assert!(validate("*.pem", Kind::File, "allow").is_ok());
        assert!(validate("~/projects/*", Kind::Dir, "allow").is_ok());
    }

    /// The same rule written two ways is one rule. This is what stops a repeat
    /// `rz file-access add` piling up rows that all block the same path, where
    /// removing one leaves the path blocked and "remove" looks broken.
    #[test]
    fn the_same_rule_written_differently_is_one_rule() {
        assert!(same_rule(
            "/srv/data/*",
            Kind::Dir,
            "block",
            "/srv/data",
            Kind::Dir,
            "block"
        ));
        assert!(same_rule(
            "/srv/data/*",
            Kind::Dir,
            "block",
            "/srv/data/",
            Kind::Dir,
            "block"
        ));
        // Same path, different action or kind: different rules.
        assert!(!same_rule(
            "/srv/data/*",
            Kind::Dir,
            "block",
            "/srv/data/*",
            Kind::Dir,
            "allow"
        ));
        assert!(!same_rule(
            "/srv/data",
            Kind::Dir,
            "block",
            "/srv/data",
            Kind::File,
            "block"
        ));
        // Different paths stay different.
        assert!(!same_rule(
            "/srv/a/*",
            Kind::Dir,
            "block",
            "/srv/b/*",
            Kind::Dir,
            "block"
        ));
    }

    /// Two spellings of one directory are one rule. A symlinked home is the
    /// case that made this necessary.
    #[test]
    fn a_symlinked_path_and_its_target_are_the_same_rule() {
        let dir = std::env::temp_dir().join(format!("rz-ident-{}", std::process::id()));
        let link = std::env::temp_dir().join(format!("rz-ident-link-{}", std::process::id()));
        let _ = std::fs::remove_file(&link);
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("temp dir");
        if std::os::unix::fs::symlink(&dir, &link).is_ok() {
            let a = format!("{}/*", dir.display());
            let b = format!("{}/*", link.display());
            assert!(
                same_rule(&a, Kind::Dir, "block", &b, Kind::Dir, "block"),
                "a symlink and its target are one directory"
            );
        }
        let _ = std::fs::remove_file(&link);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A tilde and its expansion name the same directory, so they are one rule.
    #[test]
    fn a_tilde_and_its_expansion_are_the_same_rule() {
        let expanded = expand_tilde("~/projects/*");
        // Only meaningful when the tilde actually expanded on this host.
        if expanded != "~/projects/*" {
            assert!(same_rule(
                "~/projects/*",
                Kind::Dir,
                "block",
                &expanded,
                Kind::Dir,
                "block"
            ));
        }
    }

    #[test]
    fn dir_target_strips_one_trailing_glob_and_slash() {
        assert_eq!(dir_target("/srv/data/*"), "/srv/data");
        assert_eq!(dir_target("/srv/data/"), "/srv/data");
        assert_eq!(dir_target("/srv/data"), "/srv/data");
    }
}
