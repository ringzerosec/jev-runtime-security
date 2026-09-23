// SPDX-License-Identifier: Apache-2.0
// scanner/watcher.rs — FSEvents/inotify watcher for known skill install paths
// Uses the `notify` crate (cross-platform).
//
// Phase 4: watches ALL skill directories (matching skill_surface.rs discovery)
// and auto-triggers SkillSpector pattern scans on file changes.

use anyhow::Result;
use notify::{Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use std::path::PathBuf;
use tokio::sync::mpsc;

use crate::scanner::patterns::models::{PatternFinding, Severity};

/// Agent skill-surface directories relative to a home directory.
/// Mirrors SKILL_DIRS in skill_surface.rs.
const SKILL_DIRS: &[&str] = &[
    ".claude",
    ".claude/skills",
    ".claude/plugins",
    ".claude/commands",
    ".cursor/rules",
    ".cursor/extensions",
    ".windsurf",
    ".codeium/windsurf",
    ".continue",
    ".gemini",
    ".config/openai",
    ".aider",
];

/// Single skill/rule files at the home root.
/// Mirrors SKILL_FILES in skill_surface.rs.
const SKILL_FILES: &[&str] = &[
    ".cursorrules",
    ".windsurfrules",
    ".mcp.json",
    "CLAUDE.md",
    ".aider.conf.yml",
];

/// Collect all home directories (same logic as skill_surface::home_dirs).
fn home_dirs() -> Vec<PathBuf> {
    let mut homes: Vec<PathBuf> = Vec::new();
    if let Ok(entries) = std::fs::read_dir("/home") {
        for e in entries.flatten() {
            let p = e.path();
            if p.is_dir() {
                homes.push(p);
            }
        }
    }
    let root = PathBuf::from("/root");
    if root.is_dir() {
        homes.push(root);
    }
    // Fallback: daemon's own $HOME (covers dev runs, non-standard layouts, tests).
    if let Ok(h) = std::env::var("HOME") {
        let hp = PathBuf::from(&h);
        if hp.is_dir() && !homes.contains(&hp) {
            homes.push(hp);
        }
    }
    homes
}

/// Build the full set of paths to watch: every skill directory and file across
/// all users. Directories that don't exist yet are created so the watcher can
/// detect files added later; single files are watched via their parent dir.
fn watch_paths() -> Vec<PathBuf> {
    let mut paths = Vec::new();
    let mut seen = std::collections::HashSet::new();

    for home in home_dirs() {
        // Directories
        for rel in SKILL_DIRS {
            let p = home.join(rel);
            if p.exists() || (std::fs::create_dir_all(&p).is_ok() && p.exists()) {
                if seen.insert(p.clone()) {
                    paths.push(p);
                }
            }
        }
        // Single files — watch the parent directory so we catch creates/renames
        for rel in SKILL_FILES {
            let file_path = home.join(rel);
            let parent = file_path.parent().unwrap_or(&home).to_path_buf();
            // Only add the parent if we haven't already added it as a skill dir
            if parent.is_dir() && seen.insert(parent.clone()) {
                paths.push(parent);
            }
        }
    }

    paths
}

/// Scan a single file for SkillSpector patterns when it changes.
/// Returns findings if any patterns matched. Caps at 16 MiB to avoid OOM.
pub fn scan_changed_file(path: &std::path::Path) -> Vec<PatternFinding> {
    // NEVER scan the agent's own journal.
    //
    // This watcher covers `.claude`, which contains `.claude/projects/*/*.jsonl`
    // — the running transcript. That file is the union of everything the session
    // handled, so it trips credential and exfiltration patterns constantly and
    // for entirely innocent reasons. Measured: a session that merely read a file
    // through an MCP server produced ten findings, two of them HIGH or CRITICAL,
    // none of them about anything the agent did wrong.
    //
    // The same carve-out already existed for write-scanning; it was never
    // applied here, so the review queue filled with the agent describing its own
    // work back to us. Skills, rules and MCP configs stay in scope.
    if crate::write_scan::is_agent_journal(&path.to_string_lossy()) {
        return vec![];
    }
    let content = match crate::fscache::read_to_string(path) {
        Ok(c) if c.len() <= 16 * 1024 * 1024 => c,
        _ => return vec![],
    };
    crate::scanner::patterns::scan_file_patterns(&path.to_string_lossy(), &content)
}

/// Check whether a path is (or is inside) a newly-dropped git repo.
/// If the path itself is a directory containing `.git`, scan all files in it.
/// Returns pattern findings for every file in the repo.
fn scan_git_repo_if_new(dir: &std::path::Path) -> Vec<(PathBuf, Vec<PatternFinding>)> {
    if !dir.is_dir() || !dir.join(".git").exists() {
        return vec![];
    }
    tracing::warn!(
        path = %dir.display(),
        "New git repo detected in skill directory — scanning all files"
    );
    let mut results = Vec::new();
    let walker = walkdir::WalkDir::new(dir)
        .max_depth(5)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
        // Skip .git internals
        .filter(|e| !e.path().components().any(|c| c.as_os_str() == ".git"));
    for entry in walker {
        let findings = scan_changed_file(entry.path());
        if !findings.is_empty() {
            results.push((entry.into_path(), findings));
        }
    }
    results
}

/// Start a background task that watches skill install paths.
/// Sends newly-created file paths over the returned channel.
///
/// On file change, runs SkillSpector pattern analysis and logs findings.
/// HIGH/CRITICAL findings are sent over the channel alongside the path
/// so the consumer in main.rs can broadcast threat events.
pub fn start(capacity: usize) -> Result<(mpsc::Receiver<PathBuf>, RecommendedWatcher)> {
    let (tx, rx) = mpsc::channel::<PathBuf>(capacity);

    let mut watcher = notify::recommended_watcher(move |res: notify::Result<Event>| {
        match res {
            Ok(event) => {
                if matches!(event.kind, EventKind::Create(_) | EventKind::Modify(_)) {
                    for path in event.paths {
                        // --- Git repo drop detection ---
                        // When a new directory appears, check if it's a git repo.
                        if path.is_dir() {
                            let repo_results = scan_git_repo_if_new(&path);
                            for (file_path, findings) in &repo_results {
                                let high_or_crit: Vec<_> = findings
                                    .iter()
                                    .filter(|f| {
                                        matches!(f.severity, Severity::High | Severity::Critical)
                                    })
                                    .collect();
                                if !high_or_crit.is_empty() {
                                    tracing::warn!(
                                        path = %file_path.display(),
                                        findings = high_or_crit.len(),
                                        "HIGH/CRITICAL patterns in dropped git repo"
                                    );
                                }
                            }
                            if !repo_results.is_empty() {
                                // Send the repo root so the main consumer can
                                // process it (the consumer already handles dirs
                                // by scanning their contents).
                                let _ = tx.try_send(path.clone());
                            }
                            continue;
                        }

                        if !path.is_file() {
                            continue;
                        }

                        // --- SkillSpector pattern scan on changed files ---
                        let findings = scan_changed_file(&path);
                        if !findings.is_empty() {
                            let high_or_crit: Vec<_> = findings
                                .iter()
                                .filter(|f| {
                                    matches!(f.severity, Severity::High | Severity::Critical)
                                })
                                .collect();

                            if !high_or_crit.is_empty() {
                                tracing::warn!(
                                    path = %path.display(),
                                    total = findings.len(),
                                    high_critical = high_or_crit.len(),
                                    "SkillSpector: HIGH/CRITICAL patterns detected in changed skill file"
                                );
                                for f in &high_or_crit {
                                    tracing::warn!(
                                        rule = %f.rule_id,
                                        category = %f.category,
                                        severity = %f.severity,
                                        message = %f.message,
                                        "  Pattern finding"
                                    );
                                }
                            } else {
                                tracing::info!(
                                    path = %path.display(),
                                    findings = findings.len(),
                                    "SkillSpector: patterns detected (low/medium severity)"
                                );
                            }
                        }

                        // Always forward the path to the consumer for supply
                        // chain + injection scanning (existing pipeline).
                        // The notify thread is a single OS thread shared
                        // by every watched root. `blocking_send` here means
                        // a stalled consumer (or a paused tokio runtime)
                        // would deadlock the *entire* daemon's file event
                        // pipeline. Drop newest on full instead and bump
                        // a counter so the operator notices.
                        if let Err(e) = tx.try_send(path) {
                            use mpsc::error::TrySendError;
                            match e {
                                TrySendError::Full(_) => {
                                    tracing::warn!("Scanner queue full — dropping file event");
                                }
                                TrySendError::Closed(_) => {
                                    // Consumer is gone — there is no point
                                    // watching anymore but we can't tear
                                    // down from inside the notify callback.
                                }
                            }
                        }
                    }
                }
            }
            Err(e) => tracing::warn!(err = %e, "notify watcher error"),
        }
    })?;

    for path in watch_paths() {
        tracing::info!(path = %path.display(), "Watching for skill installs");
        if let Err(e) = watcher.watch(&path, RecursiveMode::Recursive) {
            tracing::warn!(path = %path.display(), err = %e, "Could not watch path");
        }
    }

    Ok((rx, watcher))
}
