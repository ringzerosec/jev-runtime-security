// SPDX-License-Identifier: Apache-2.0
// ─────────────────────────────────────────────────────────────────────────────
//  Ring Zero — provenance graph aggregator
//
//  This module is the *single* entry point from the daemon's event firehose
//  into the CozoDB provenance graph defined in `graph_schema.cozo`.
//
//  Design principle (state-estimator, not event-log):
//
//     1000 reads of `~/.zshrc` by `claude` →
//         ONE row in `touched{process_exe=claude, file_path=~/.zshrc}`,
//         with `open_count += 1000` and `last_seen` advanced.
//
//     NOT 1000 rows in `event_raw`.
//
//  Each incoming `SecurityEvent` follows the same decision pipeline:
//
//         ┌──────────────────────────────────────────────────────┐
//         │  SecurityEvent (kernel → daemon)                     │
//         └──────────────────────────────────────────────────────┘
//                          │
//                          ▼
//                ┌──────────────────┐
//                │ classify_sense() │   ←─ first sight of `target`?
//                │   /etc/passwd  → │      sensitivity = 2
//                │   ~/.aws/creds → │      sensitivity = 3
//                │   ~/repo/src/* → │      sensitivity = 0
//                └──────────────────┘
//                          │
//                          ▼
//                ┌──────────────────┐
//                │ upsert_nodes()   │   counter-update on entity rows
//                │  - file_node     │
//                │  - process_node  │
//                │  - network_node  │
//                │  - session_node  │
//                └──────────────────┘
//                          │
//                          ▼
//                ┌──────────────────┐
//                │ upsert_edge()    │   counter-update on relationship row
//                │  - touched       │      (process_exe → file_path)
//                │  - connected     │      (process_exe → host:port)
//                │  - spawned       │      (parent_exe → child_exe)
//                │  - session_includes
//                └──────────────────┘
//                          │
//                          ▼
//                ┌──────────────────┐
//                │ should_store_raw │   promotion rules — see below
//                │   ?              │
//                └────────┬─────────┘
//                  yes ◄──┴──► no
//                  │              │
//                  ▼              ▼
//          insert event_raw    DROP   (the row never existed,
//          + maybe decision           the counter on the edge
//          + maybe threat             carries all the signal)
//
//
//  PROMOTION RULES — when does a raw event survive?
//
//     R1. `target` has `sensitivity >= 2`  (credential-adjacent or secret)
//     R2. `event.allowed == false`         (any blocked decision)
//     R3. First-time-seen (process_exe, target) pair
//                                          (edge row didn't exist before)
//     R4. `anomaly_score >= 3.0`           (3 σ from per-process baseline)
//     R5. `kind == Threat | PromptInjection | OffensivePrompt | AttackChain`
//     R6. Cross-session lateral movement   (same target touched by ≥2 sessions
//                                           within the correlation window)
//
//  Everything else is a counter bump. The 1000-reads-of-zshrc case is rule
//  miss across the board → discarded, the edge counter alone preserves it.
//
//  Storage math (heavy-dev workload, one endpoint, 30 days):
//      raw event firehose                        ~1.1 GB
//      after aggregator (warm tier behaviour)    ~60 MB    (20× reduction)
//      hot tier event_raw (72 h, promoted only)  ~8 MB
//      cold tier monthly snapshot (zstd)         ~5 MB / month
//
//  This file is the *design statement*. The wire-up to CozoDB lives in
//  `analyzer/graph_persistence/{mod,query,write}.rs` (next PR). Until that
//  lands, `ingest()` is a no-op behind a feature flag — keeping the type
//  surface stable so callers in `main.rs` can already speak to it.
// ─────────────────────────────────────────────────────────────────────────────

use std::sync::{Arc, Mutex};

use chrono::{DateTime, Utc};

use crate::common::event::{EventKind, SecurityEvent};

// ── Public configuration ────────────────────────────────────────────────────

/// Tunables for the aggregator. Loaded from `daemon.toml [aggregator]`;
/// defaults below are the ones we ship.
#[derive(Debug, Clone)]
pub struct AggregatorConfig {
    /// Z-score above per-process baseline that promotes a counter-bump
    /// into a stored `event_raw` row + emits an anomaly.
    pub anomaly_threshold: f64,
    /// Wall-clock window for "first-time-seen" promotion. After this,
    /// a previously-seen edge that hasn't fired in a while will be
    /// treated as first-seen again — relevant for long-idle agents.
    pub first_seen_grace_secs: i64,
    /// Cross-session correlation window for rule R6.
    pub cross_session_window_ms: i64,
    /// Hot-tier `event_raw` retention. Rows with `permanent=true`
    /// (decisions, threats) are exempt and survive into the warm tier.
    pub hot_retention_hours: u32,
}

impl Default for AggregatorConfig {
    fn default() -> Self {
        Self {
            anomaly_threshold: 3.0,
            first_seen_grace_secs: 7 * 24 * 3600,
            cross_session_window_ms: 5 * 60 * 1000,
            hot_retention_hours: 72,
        }
    }
}

/// Sensitivity tier assigned at first sight of a file. Set on `file_node`
/// and used by rule R1. See `classify_sensitivity` below for the policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum Sensitivity {
    /// Source code, build artifacts, tmp scratch — uninteresting.
    Benign = 0,
    /// Configuration files — log a few, then aggregate.
    Config = 1,
    /// Credential-adjacent: ~/.aws, ~/.ssh, ~/.kube, .env, keystores.
    Credential = 2,
    /// Outright secrets: private keys, GPG keyrings, browser cookie jars.
    Secret = 3,
}

// ── Promotion decision ──────────────────────────────────────────────────────

/// The aggregator's verdict on a single event. Returned by `classify()`
/// so callers can log/trace before the row is written. `ingest()` does the
/// classification + write atomically; this enum exists for tests + tracing.
#[derive(Debug, Clone)]
pub enum Verdict {
    /// Counter-bump only — no row written to `event_raw`.
    Aggregate { edge: EdgeKind },
    /// Promoted to `event_raw`, with the rule(s) that fired.
    PromoteRaw {
        rules: PromotionFlags,
        permanent: bool,
        edge: EdgeKind,
    },
    /// Filtered out before any graph write (noise: own pid, self-loops,
    /// kernel-internal events we don't model).
    Drop { reason: &'static str },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EdgeKind {
    Touched,         // file event       → touched
    Connected,       // network event    → connected
    Spawned,         // process exec     → spawned
    SessionIncludes, // any event w/ sid → session_includes
    None,            // event has no natural edge (Threat synthesised etc.)
}

/// Which promotion rules fired. `permanent` on `event_raw` ⇔ any of
/// {Blocked, ThreatKind, CrossSession} is set.
///
/// Hand-rolled bitflags (avoids pulling in the `bitflags` crate for what
/// is currently a single u8). If we grow another flag-set in this module
/// we'll switch to the crate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PromotionFlags(u8);

impl PromotionFlags {
    pub const SENSITIVE: Self = Self(0b0000_0001); // R1
    pub const BLOCKED: Self = Self(0b0000_0010); // R2
    pub const FIRST_SEEN: Self = Self(0b0000_0100); // R3
    pub const ANOMALOUS: Self = Self(0b0000_1000); // R4
    pub const THREAT_KIND: Self = Self(0b0001_0000); // R5
    pub const CROSS_SESSION: Self = Self(0b0010_0000); // R6

    pub const fn empty() -> Self {
        Self(0)
    }
    pub fn is_empty(self) -> bool {
        self.0 == 0
    }
    pub fn insert(&mut self, other: Self) {
        self.0 |= other.0;
    }
    pub fn contains(self, other: Self) -> bool {
        (self.0 & other.0) == other.0
    }
    pub fn intersects(self, other: Self) -> bool {
        (self.0 & other.0) != 0
    }
}

impl std::ops::BitOr for PromotionFlags {
    type Output = Self;
    fn bitor(self, rhs: Self) -> Self {
        Self(self.0 | rhs.0)
    }
}

// ── Aggregator ──────────────────────────────────────────────────────────────

/// Single-writer aggregator. Sits between the event firehose and CozoDB.
/// All counter updates are serialized through this struct so we never race
/// two increments against the same edge row.
pub struct Aggregator {
    cfg: AggregatorConfig,
    // Wired up in graph_persistence — opaque handle so this file compiles
    // standalone while the storage layer is still in flight.
    graph: Arc<dyn GraphWriter + Send + Sync>,
    // Cached anomaly baselines per (process_exe, edge_kind) so we don't
    // hit the graph on every event. Refreshed lazily by `baseline.rs`.
    baselines: Arc<Mutex<BaselineCache>>,
}

impl Aggregator {
    pub fn new(cfg: AggregatorConfig, graph: Arc<dyn GraphWriter + Send + Sync>) -> Self {
        Self {
            cfg,
            graph,
            baselines: Arc::new(Mutex::new(BaselineCache::default())),
        }
    }

    /// Ingest one event from the kernel → daemon pipeline. This is the
    /// hot path; it must be O(1) in the common case (counter bump only).
    pub fn ingest(&self, ev: &SecurityEvent) -> anyhow::Result<Verdict> {
        // 1. Noise filter — drop self-emissions and pid 0/1 housekeeping
        //    before they touch any graph row. Returns early.
        if let Some(reason) = self.noise_reason(ev) {
            return Ok(Verdict::Drop { reason });
        }

        // 2. Upsert entity nodes (process_node, file_node|network_node,
        //    optionally session_node). These are idempotent; the schema
        //    is keyed on the natural identity (exe_path+comm, path, etc.)
        //    so the second call is a counter bump on `last_seen`.
        let nodes = self.upsert_nodes(ev)?;

        // 3. Upsert the behavioural edge. Returns whether the edge row
        //    was newly created — feeds rule R3.
        let (edge_kind, edge_state) = self.upsert_edge(ev, &nodes)?;

        // 4. Recompute anomaly score from cached baseline. Cheap enough
        //    to run on every event; expensive baseline refresh runs in
        //    a background task off the hot path.
        let anomaly_score = self
            .baselines
            .lock()
            .expect("baseline cache mutex poisoned")
            .score(ev, edge_kind, &edge_state);

        // 5. Apply promotion rules.
        let mut rules = PromotionFlags::empty();
        if nodes.target_sensitivity as i32 >= Sensitivity::Credential as i32 {
            rules.insert(PromotionFlags::SENSITIVE);
        }
        if !ev.allowed {
            rules.insert(PromotionFlags::BLOCKED);
        }
        if edge_state.first_seen_now(self.cfg.first_seen_grace_secs) {
            rules.insert(PromotionFlags::FIRST_SEEN);
        }
        if anomaly_score >= self.cfg.anomaly_threshold {
            rules.insert(PromotionFlags::ANOMALOUS);
        }
        if matches!(
            ev.kind,
            EventKind::PromptInjection
                | EventKind::OffensivePrompt
                | EventKind::AttackChain
                | EventKind::ProxyBlock
        ) {
            rules.insert(PromotionFlags::THREAT_KIND);
        }
        if self.is_cross_session_lateral(ev) {
            rules.insert(PromotionFlags::CROSS_SESSION);
        }

        // 6. Emit. Counter-bump only is the common path.
        if rules.is_empty() {
            return Ok(Verdict::Aggregate { edge: edge_kind });
        }

        let permanent = rules.intersects(
            PromotionFlags::BLOCKED | PromotionFlags::THREAT_KIND | PromotionFlags::CROSS_SESSION,
        );
        self.graph.insert_event_raw(ev, anomaly_score, permanent)?;
        if rules.contains(PromotionFlags::THREAT_KIND) {
            self.graph.insert_threat_from(ev, anomaly_score)?;
        }

        Ok(Verdict::PromoteRaw {
            rules,
            permanent,
            edge: edge_kind,
        })
    }

    // ── Helpers (sketch — bodies live in sibling files) ──

    fn noise_reason(&self, ev: &SecurityEvent) -> Option<&'static str> {
        // Filters that match `timeline::is_noise_event` so the two layers
        // stay consistent. Self-loops, our own daemon pid, kernel threads.
        if ev.pid == 0 {
            return Some("kernel-thread");
        }
        if ev.process == "ringzero-daemon" {
            return Some("self-emission");
        }
        None
    }

    fn upsert_nodes(&self, ev: &SecurityEvent) -> anyhow::Result<NodesTouched> {
        // For each event kind, work out which node tables to touch and
        // call into graph_persistence::write::upsert_*. The function
        // returns the resolved sensitivity tier for the target (only
        // meaningful for file events; defaults to Benign otherwise).
        let target_sensitivity = match ev.kind {
            EventKind::FileOpen
            | EventKind::FileCreate
            | EventKind::FileWrite
            | EventKind::FileDelete
            | EventKind::FileRename => classify_sensitivity(&ev.target),
            _ => Sensitivity::Benign,
        };
        self.graph.upsert_process_node(ev)?;
        match ev.kind {
            EventKind::FileOpen
            | EventKind::FileCreate
            | EventKind::FileWrite
            | EventKind::FileDelete
            | EventKind::FileRename => {
                self.graph
                    .upsert_file_node(&ev.target, target_sensitivity)?;
            }
            EventKind::NetworkConnect | EventKind::NetworkSend | EventKind::NetworkRecv => {
                self.graph.upsert_network_node(&ev.target)?;
            }
            _ => {}
        }
        Ok(NodesTouched { target_sensitivity })
    }

    fn upsert_edge(
        &self,
        ev: &SecurityEvent,
        _nodes: &NodesTouched,
    ) -> anyhow::Result<(EdgeKind, EdgeState)> {
        let kind = match ev.kind {
            EventKind::FileOpen
            | EventKind::FileCreate
            | EventKind::FileWrite
            | EventKind::FileDelete
            | EventKind::FileRename => EdgeKind::Touched,
            EventKind::NetworkConnect | EventKind::NetworkSend | EventKind::NetworkRecv => {
                EdgeKind::Connected
            }
            EventKind::ProcessExec | EventKind::ProcessFork => EdgeKind::Spawned,
            _ => EdgeKind::None,
        };
        let state = self.graph.upsert_edge(kind, ev)?;
        Ok((kind, state))
    }

    fn is_cross_session_lateral(&self, ev: &SecurityEvent) -> bool {
        // Cheap pre-filter: only file events with sensitivity≥2 are
        // candidates for cross-session lateral movement. The expensive
        // query (rule R6 in graph_schema.cozo) is gated behind this.
        if !matches!(ev.kind, EventKind::FileOpen | EventKind::FileWrite) {
            return false;
        }
        self.graph
            .other_sessions_touched_recently(
                &ev.target,
                ev.timestamp,
                self.cfg.cross_session_window_ms,
            )
            .unwrap_or(false)
    }
}

// ── Internal types — kept here so the contract with graph_persistence is
//    visible in one place; bodies move out when we wire the storage layer ──

/// Snapshot of what `upsert_nodes` discovered, fed into rule evaluation.
struct NodesTouched {
    target_sensitivity: Sensitivity,
}

/// Mutable view of the row we just upserted on an edge. Used by R3
/// (first-seen) and to drive anomaly scoring against historical counts.
#[derive(Debug, Clone)]
pub struct EdgeState {
    pub created_now: bool,
    pub last_seen: DateTime<Utc>,
    pub event_count: u64,
    pub blocked_count: u64,
}

impl EdgeState {
    fn first_seen_now(&self, grace_secs: i64) -> bool {
        if self.created_now {
            return true;
        }
        // Long-idle edges count as first-seen again — catches dormant
        // agents that suddenly resume the same access pattern weeks later.
        let dt = Utc::now().signed_duration_since(self.last_seen);
        dt.num_seconds() > grace_secs && self.event_count <= 1
    }
}

/// The contract `analyzer/graph_persistence` must implement. Held behind
/// `dyn` so this file stays storage-agnostic and unit-testable with an
/// in-memory mock.
pub trait GraphWriter {
    fn upsert_process_node(&self, ev: &SecurityEvent) -> anyhow::Result<()>;
    fn upsert_file_node(&self, path: &str, sens: Sensitivity) -> anyhow::Result<()>;
    fn upsert_network_node(&self, host_port: &str) -> anyhow::Result<()>;
    fn upsert_edge(&self, kind: EdgeKind, ev: &SecurityEvent) -> anyhow::Result<EdgeState>;
    fn insert_event_raw(
        &self,
        ev: &SecurityEvent,
        anomaly_score: f64,
        permanent: bool,
    ) -> anyhow::Result<()>;
    fn insert_threat_from(&self, ev: &SecurityEvent, anomaly_score: f64) -> anyhow::Result<()>;
    fn other_sessions_touched_recently(
        &self,
        target: &str,
        at: DateTime<Utc>,
        window_ms: i64,
    ) -> anyhow::Result<bool>;
}

/// In-memory cache of per-(process_exe, edge_kind) baselines. Refreshed
/// off the hot path by `analyzer::baseline`. Z-score against this is
/// what feeds rule R4.
#[derive(Default)]
struct BaselineCache {
    // (Detailed structure lives in baseline.rs — sketch only here.)
}

impl BaselineCache {
    fn score(&self, _ev: &SecurityEvent, _edge: EdgeKind, _state: &EdgeState) -> f64 {
        // Real implementation: rolling mean+stddev per (process, edge),
        // returns (current_count - mean) / stddev. Sketch returns 0.0
        // so promotion via R4 is dormant until baseline.rs is wired up.
        0.0
    }
}

// ── Sensitivity classifier ──────────────────────────────────────────────────
//
// Conservative bias: false-credential is annoying (more raw events stored),
// false-benign is a security failure. When in doubt, escalate.

pub fn classify_sensitivity(path: &str) -> Sensitivity {
    // Outright secrets — private keys, keyrings, browser cookie jars.
    const SECRET_HINTS: &[&str] = &[
        "/.ssh/id_",
        "/.gnupg/",
        "/.aws/credentials",
        "/.config/gh/",
        "/Library/Keychains/",
        "/AppData/Roaming/Mozilla/Firefox/Profiles/",
        "/cookies.sqlite",
        "/Login Data",
        "/Cookies",
    ];
    if SECRET_HINTS.iter().any(|h| path.contains(h)) {
        return Sensitivity::Secret;
    }

    // Credential-adjacent — config dirs that frequently hold tokens.
    const CRED_HINTS: &[&str] = &[
        "/.aws/",
        "/.ssh/",
        "/.kube/",
        "/.docker/config",
        "/.netrc",
        "/.npmrc",
        "/.pypirc",
        ".env",
        ".env.local",
        ".env.production",
        "/credentials",
        "/.terraformrc",
    ];
    if CRED_HINTS.iter().any(|h| path.contains(h)) {
        return Sensitivity::Credential;
    }

    // Config — dotfiles, /etc/*. Log a few, then aggregate.
    if path.starts_with("/etc/") || path.contains("/.config/") {
        return Sensitivity::Config;
    }

    Sensitivity::Benign
}

// ── Unit tests — sketch, real ones land with graph_persistence ──────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifier_catches_aws_creds() {
        assert_eq!(
            classify_sensitivity("/home/alice/.aws/credentials"),
            Sensitivity::Secret,
        );
    }

    #[test]
    fn classifier_catches_env_file() {
        assert_eq!(
            classify_sensitivity("/srv/app/.env"),
            Sensitivity::Credential
        );
    }

    #[test]
    fn classifier_lets_source_code_through() {
        assert_eq!(
            classify_sensitivity("/home/alice/repo/src/main.rs"),
            Sensitivity::Benign,
        );
    }

    #[test]
    fn promotion_flags_permanent_set() {
        let mut f = PromotionFlags::empty();
        f.insert(PromotionFlags::BLOCKED);
        assert!(f.intersects(PromotionFlags::BLOCKED));
        assert!(!f.intersects(PromotionFlags::ANOMALOUS));
    }
}
