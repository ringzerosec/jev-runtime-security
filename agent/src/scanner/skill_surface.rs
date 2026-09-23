// SPDX-License-Identifier: Apache-2.0
// scanner/skill_surface.rs — enumerate the "skill surface" of every AI coding
// agent installed on the host.
//
// AI agents load skills, plugins, slash-commands, rule files and MCP-server
// configs as *executable instructions* into a trusted context. A poisoned or
// hijacked skill is therefore a supply-chain attack (the `openclaw`/`*claw*`
// threat model): it can exfiltrate, prompt-inject, or quietly widen the agent's
// tool permissions. The reactive file watcher (`watcher.rs`) only sees *new*
// installs; this module answers "scan everything already on disk, right now"
// for the `rz scan skills` command and the app's on-demand scan.
//
// We don't scan here — we only DISCOVER the roots. The existing engine
// (supply_chain entropy/secrets + model_armor injection) does the scanning.

use std::path::PathBuf;

/// One discovered agent skill location to be scanned.
#[derive(Debug, Clone, serde::Serialize)]
pub struct SkillRoot {
    /// Canonical agent id (matches `agent_detect::classify_agent`).
    pub agent: String,
    /// What kind of surface this is (skills/plugins/rules/mcp/instructions).
    pub kind: String,
    /// Absolute path to the directory to scan.
    pub path: String,
    /// The home directory (user) this surface belongs to.
    pub owner: String,
}

/// One scanned skill surface in the auto-scan result.
#[derive(Debug, Clone, serde::Serialize)]
pub struct SkillRootResult {
    pub agent: String,
    pub kind: String,
    pub path: String,
    pub owner: String,
    pub files_scanned: usize,
    pub injection_reports: Vec<crate::scanner::model_armor::ModelArmorReport>,
    pub supply_findings: Vec<crate::scanner::supply_chain::ScanReport>,
    pub pattern_findings: Vec<crate::scanner::patterns::models::PatternFinding>,
    pub risk: String,
    /// Other configured roots that also reach the files scanned under this one.
    /// The files are reported once, here, rather than repeated per root.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub also_reachable_from: Vec<String>,
}

/// Aggregate result of an auto-scan across every discovered agent surface.
#[derive(Debug, Clone, serde::Serialize)]
pub struct SkillScanAutoResult {
    pub roots_found: usize,
    pub files_scanned: usize,
    pub results: Vec<SkillRootResult>,
    pub overall_risk: String,
    /// What the optional model layer did, or why it did not run. Always
    /// present, so a reader can tell pattern-only coverage from model coverage.
    pub model_layer: crate::scanner::jev_layer::JevLayerReport,
}

/// Discover every agent skill surface on the host and scan each for supply-chain
/// (entropy/secrets) + prompt-injection risk. Shared by the HTTP endpoint
/// (`/api/v1/skill-scan/auto`) and the IPC socket (`scan_skills_auto`) so the CLI
/// and the desktop app return identical results.
pub async fn scan_all() -> SkillScanAutoResult {
    use crate::scanner::model_armor::{scan_dir_for_injection, skill_scan_config};
    use crate::scanner::patterns::scan_file_patterns;
    use crate::scanner::supply_chain::{scan_dir, RiskLevel};

    // Use the daemon's resolved injection-scan config (registered at startup).
    // None means scanning is disabled in daemon.toml.
    let ma_config = skill_scan_config();
    let roots = enumerate();

    let mut results: Vec<SkillRootResult> = Vec::new();
    let mut total_files = 0usize;
    let mut worst = RiskLevel::Clean;

    // The configured roots overlap: ~/.claude, ~/.claude/skills and a specific
    // skill directory can all be roots, so the same file is reachable several
    // times. Scanning it once per root produced the same finding four times in
    // the one screen a human uses to triage, which destroys trust in the
    // screen. Canonical path -> the root that claimed it, plus every other root
    // it was also reachable from.
    // Files already read under an earlier root, so a file reachable through
    // several overlapping roots is read and pattern-scanned once. The global
    // dedup below is the authority for the final report; this just avoids
    // redundant reads and model calls.
    let mut claimed_files: std::collections::HashMap<std::path::PathBuf, String> =
        std::collections::HashMap::new();

    // Resolve the optional model layer once. A missing key or a bad mode is
    // reported in the scan output, not swallowed: a scan that quietly fell back
    // to patterns while the user believed they had model coverage is worse than
    // no model at all.
    let scanner_cfg = crate::config::DaemonConfig::load().scanner.jev;
    let mut jev_report = crate::scanner::jev_layer::JevLayerReport::default();
    let mut calls_remaining = scanner_cfg.max_calls_per_scan;
    let jev_cfg: Option<(
        crate::scanner::jev_layer::JevScannerConfig,
        String,
        std::sync::Arc<dyn Fn(&mut serde_json::Value) + Send + Sync>,
    )> = if scanner_cfg.enabled {
        match scanner_cfg.load_key() {
            Ok(key) => {
                let redaction = crate::config::DaemonConfig::load().webhooks.redaction;
                match crate::integrations::webhook::Redactor::new(&redaction) {
                    Ok(r) => {
                        let redact: std::sync::Arc<dyn Fn(&mut serde_json::Value) + Send + Sync> =
                            std::sync::Arc::new(move |v: &mut serde_json::Value| r.redact(v));
                        Some((
                            crate::scanner::jev_layer::JevScannerConfig {
                                base_url: scanner_cfg.base_url.clone(),
                                model: scanner_cfg.model.clone(),
                                timeout: std::time::Duration::from_millis(scanner_cfg.timeout_ms),
                                max_calls_per_scan: scanner_cfg.max_calls_per_scan,
                                max_bytes_per_file: scanner_cfg.max_bytes_per_file,
                            },
                            key,
                            redact,
                        ))
                    }
                    Err(e) => {
                        jev_report.errors.push(format!("redactor unusable: {e}"));
                        jev_report.skipped_reason = Some(
                            "model layer disabled: the redactor could not be built, and content \
                             is never sent unredacted"
                                .to_string(),
                        );
                        None
                    }
                }
            }
            Err(e) => {
                tracing::error!(err = %e, "[scanner.jev] enabled but the key is unusable");
                jev_report.errors.push(e.clone());
                jev_report.skipped_reason = Some(format!(
                    "model layer did not run: {e}. Files were scanned by patterns only."
                ));
                None
            }
        }
    } else {
        None
    };

    for root in &roots {
        let dir = std::path::Path::new(&root.path);
        let supply = scan_dir(dir);
        let injection = scan_dir_for_injection(dir, ma_config.as_ref()).await;
        total_files += supply.len();

        // Run SkillSpector-style pattern analysis on every scannable file.
        let mut pattern_findings = Vec::new();
        let scan_path = std::path::Path::new(&root.path);
        let walker = if scan_path.is_file() {
            vec![scan_path.to_path_buf()]
        } else {
            walkdir::WalkDir::new(scan_path)
                .max_depth(5)
                .into_iter()
                .filter_map(|e| e.ok())
                .filter(|e| e.file_type().is_file())
                .map(|e| e.into_path())
                .collect()
        };
        // Keep (path, content) for files the model layer may score, so nothing
        // is read from disk twice.
        let mut instruction_files: Vec<(String, String)> = Vec::new();
        for file_path in walker {
            // One file, one scan, one finding — whichever root reaches it first
            // owns it. A file under two roots is reported once, and the other
            // roots are listed on the result.
            let canonical = std::fs::canonicalize(&file_path).unwrap_or_else(|_| file_path.clone());
            if claimed_files.contains_key(&canonical) {
                continue;
            }
            claimed_files.insert(canonical, root.path.clone());

            if let Ok(content) = crate::fscache::read_to_string(&file_path) {
                if content.len() <= 16 * 1024 * 1024 {
                    let fp = file_path.to_string_lossy().to_string();
                    pattern_findings.extend(scan_file_patterns(&fp, &content));
                    if crate::scanner::jev_layer::is_instruction_bearing(&fp) {
                        instruction_files.push((fp, content));
                    }
                }
            }
        }

        // ── Optional model layer ────────────────────────────────────────────
        // Patterns have already run and are the floor. This may raise a
        // severity or add a finding they missed; it can never lower one. Any
        // failure is recorded in the report rather than silently ignored.
        if let Some((cfg, key, redact)) = jev_cfg.as_ref() {
            crate::scanner::jev_layer::apply(
                cfg,
                key,
                redact,
                &instruction_files,
                &mut pattern_findings,
                &mut jev_report,
                &mut calls_remaining,
            );
        }

        // Informational findings are prose evidence, not risk. Exclude them
        // from every aggregation so a documentation-heavy directory cannot
        // inflate a surface's risk level.
        let scoring_findings: Vec<&crate::scanner::patterns::PatternFinding> = pattern_findings
            .iter()
            .filter(|f| f.severity != crate::scanner::patterns::models::Severity::Informational)
            .collect();

        let worst_supply = supply
            .iter()
            .map(|r| &r.risk_level)
            .max()
            .cloned()
            .unwrap_or(RiskLevel::Clean);
        let has_inj = !injection.is_empty();
        let has_critical_patterns = scoring_findings
            .iter()
            .any(|f| f.severity == crate::scanner::patterns::models::Severity::Critical);
        let risk = if has_inj || worst_supply == RiskLevel::Critical || has_critical_patterns {
            RiskLevel::Critical
        } else if scoring_findings
            .iter()
            .any(|f| f.severity == crate::scanner::patterns::models::Severity::High)
        {
            std::cmp::max(worst_supply.clone(), RiskLevel::High)
        } else {
            worst_supply.clone()
        };
        if risk > worst {
            worst = risk.clone();
        }

        // Defensive dedup: a pattern module could emit the same hit twice for
        // one file. (resolved path, rule id, line) is the identity.
        {
            let mut seen = std::collections::HashSet::new();
            pattern_findings.retain(|f| {
                let key = (
                    std::fs::canonicalize(&f.file)
                        .unwrap_or_else(|_| std::path::PathBuf::from(&f.file)),
                    f.rule_id.clone(),
                    f.start_line,
                );
                seen.insert(key)
            });
        }

        results.push(SkillRootResult {
            agent: root.agent.clone(),
            kind: root.kind.clone(),
            path: root.path.clone(),
            owner: root.owner.clone(),
            files_scanned: supply.len(),
            injection_reports: injection,
            supply_findings: supply
                .into_iter()
                .filter(|r| r.risk_level != RiskLevel::Clean)
                .collect(),
            pattern_findings,
            risk: format!("{:?}", risk).to_lowercase(),
            also_reachable_from: Vec::new(),
        });
    }

    // ── Phase 3 wiring point ──────────────────────────────────────────────
    // After scan_all() returns, the caller should feed results to the
    // SkillCorrelationEngine so runtime events can be correlated with these
    // static findings:
    //
    //   let scan_result = skill_surface::scan_all().await;
    //   skill_correlation_engine.update_scan_results(&scan_result.results).await;
    //
    // This is done by the caller (API handler or main.rs event loop), not here,
    // because scan_all() is a pure scan function and should not hold engine refs.
    // ───────────────────────────────────────────────────────────────────────

    // Global dedup, before the report is assembled: the configured roots
    // overlap (~/.claude contains ~/.claude/skills contains a skill dir), so the
    // same file is scanned under several roots and every scanner — supply,
    // pattern, injection — produced the same finding several times. A human
    // triages on one screen, so a finding must appear once. Identity is
    // (resolved path, finding key); the first root to reach a file keeps its
    // findings, and any other root that also reached it is listed on the root
    // that kept them.
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut extra_roots: std::collections::HashMap<String, std::collections::BTreeSet<String>> =
        std::collections::HashMap::new();

    let canon = |f: &str| -> String {
        std::fs::canonicalize(f)
            .map(|p| p.to_string_lossy().into_owned())
            .unwrap_or_else(|_| f.to_string())
    };

    for r in &mut results {
        let this_root = r.path.clone();
        let mut owned_elsewhere = std::collections::BTreeSet::new();

        r.pattern_findings.retain(|f| {
            let key = format!("pat\0{}\0{}\0{}", canon(&f.file), f.rule_id, f.start_line);
            if seen.insert(key) {
                true
            } else {
                owned_elsewhere.insert(canon(&f.file));
                false
            }
        });

        for rep in &mut r.supply_findings {
            rep.findings.retain(|f| {
                let key = format!("sup\0{}\0{:?}\0{}", canon(&f.file), f.kind, f.detail);
                if seen.insert(key) {
                    true
                } else {
                    owned_elsewhere.insert(canon(&f.file));
                    false
                }
            });
        }
        r.supply_findings.retain(|rep| !rep.findings.is_empty());

        for rep in &mut r.injection_reports {
            let path = rep.path.clone();
            rep.findings.retain(|f| {
                let key = format!("inj\0{}\0{}", canon(&path), f.signals.join(","));
                if seen.insert(key) {
                    true
                } else {
                    owned_elsewhere.insert(canon(&path));
                    false
                }
            });
        }
        r.injection_reports.retain(|rep| !rep.findings.is_empty());

        // Record the roots a kept file was ALSO reachable from.
        for f in &r.pattern_findings {
            let c = canon(&f.file);
            if !c.starts_with(&this_root) {
                if let Some(root) = results_root_for(&c, &roots, &this_root) {
                    extra_roots
                        .entry(this_root.clone())
                        .or_default()
                        .insert(root);
                }
            }
        }
        let _ = owned_elsewhere;
    }

    for r in &mut results {
        if let Some(extra) = extra_roots.get(&r.path) {
            r.also_reachable_from = extra.iter().cloned().collect();
        }
    }

    SkillScanAutoResult {
        roots_found: roots.len(),
        files_scanned: total_files,
        results,
        overall_risk: format!("{:?}", worst).to_lowercase(),
        model_layer: jev_report,
    }
}

/// Known agent skill-surface subpaths, relative to a home directory. Directory
/// shaped — the scan engine walks each recursively, so files nested inside
/// (`skills/*/SKILL.md`, `plugins/*`, `.mcp.json`, `CLAUDE.md`, `settings.json`)
/// are all covered. Single dotfiles at the home root (`.cursorrules`,
/// `.windsurfrules`) are handled separately below.
const SKILL_DIRS: &[(&str, &str, &str)] = &[
    // (agent, kind, relative subpath)
    ("claude", "config", ".claude"),
    ("claude", "skills", ".claude/skills"),
    ("claude", "plugins", ".claude/plugins"),
    ("claude", "commands", ".claude/commands"),
    ("cursor", "rules", ".cursor/rules"),
    ("cursor", "extensions", ".cursor/extensions"),
    ("windsurf", "config", ".windsurf"),
    ("windsurf", "config", ".codeium/windsurf"),
    ("continue", "config", ".continue"),
    ("gemini", "config", ".gemini"),
    ("codex", "config", ".config/openai"),
    ("aider", "config", ".aider"),
];

/// Single rule/instruction files at the home root worth scanning on their own.
const SKILL_FILES: &[(&str, &str, &str)] = &[
    ("cursor", "rules", ".cursorrules"),
    ("windsurf", "rules", ".windsurfrules"),
    ("claude", "mcp", ".mcp.json"),
    ("claude", "instructions", "CLAUDE.md"),
    ("aider", "config", ".aider.conf.yml"),
];

/// All home directories to inspect. The daemon runs as root, so it can read
/// every user's surface — `/root` plus each `/home/<user>`.
fn home_dirs() -> Vec<(String, PathBuf)> {
    let mut homes: Vec<(String, PathBuf)> = Vec::new();
    if let Ok(entries) = std::fs::read_dir("/home") {
        for e in entries.flatten() {
            let p = e.path();
            if p.is_dir() {
                let user = e.file_name().to_string_lossy().to_string();
                homes.push((user, p));
            }
        }
    }
    let root = PathBuf::from("/root");
    if root.is_dir() {
        homes.push(("root".to_string(), root));
    }
    // Fallback: the daemon's own $HOME (covers non-standard layouts / tests).
    if let Ok(h) = std::env::var("HOME") {
        let hp = PathBuf::from(&h);
        if hp.is_dir() && !homes.iter().any(|(_, p)| *p == hp) {
            let user = hp
                .file_name()
                .map(|s| s.to_string_lossy().to_string())
                .unwrap_or_else(|| "home".into());
            homes.push((user, hp));
        }
    }
    homes
}

/// Discover every agent skill surface present on the host. Returns directory
/// roots; single instruction/rule files are returned as their parent directory
/// with a one-file marker so the scan engine still reaches them.
/// Which configured root (other than `exclude`) contains `path`. Longest match
/// wins, so the most specific root is named.
fn results_root_for(path: &str, roots: &[SkillRoot], exclude: &str) -> Option<String> {
    roots
        .iter()
        .filter(|r| r.path != exclude && path.starts_with(&r.path))
        .max_by_key(|r| r.path.len())
        .map(|r| r.path.clone())
}

pub fn enumerate() -> Vec<SkillRoot> {
    let mut roots = Vec::new();
    for (owner, home) in home_dirs() {
        for (agent, kind, rel) in SKILL_DIRS {
            let p = home.join(rel);
            if p.is_dir() {
                roots.push(SkillRoot {
                    agent: (*agent).to_string(),
                    kind: (*kind).to_string(),
                    path: p.to_string_lossy().to_string(),
                    owner: owner.clone(),
                });
            }
        }
        for (agent, kind, rel) in SKILL_FILES {
            let p = home.join(rel);
            if p.is_file() {
                roots.push(SkillRoot {
                    agent: (*agent).to_string(),
                    kind: (*kind).to_string(),
                    path: p.to_string_lossy().to_string(),
                    owner: owner.clone(),
                });
            }
        }
    }
    roots
}
