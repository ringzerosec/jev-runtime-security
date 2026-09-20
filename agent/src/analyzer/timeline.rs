// SPDX-License-Identifier: Apache-2.0
// analyzer/timeline.rs — sled-backed per-PID event timeline
//
// Two layers:
//   * Persistent: sled `pid:{N}` trees. Survives daemon restart.
//   * In-memory ring per PID (capacity RING_CAPACITY). Fast path for the
//     hot per-event `recent()` calls from main.rs heuristic scoring.
//     Avoids JSON-deserializing the full per-PID tree on every event.

use crate::common::event::SecurityEvent;
use anyhow::Result;
use chrono::Utc;
use sled::Db;
use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, RwLock};

/// Per-PID ring capacity. Heuristics typically look back 60–120 s; at the
/// rate the noise filter lets through, a few-hundred-entry ring covers any
/// realistic window without unbounded growth.
const RING_CAPACITY: usize = 256;

pub struct Timeline {
    db: Arc<Db>,
    /// In-memory per-PID ring of recent events. Updated on `insert()`,
    /// drained on PID exit (cleanup_pid). Indexed by PID so the
    /// per-kernel-event hot path is a single HashMap lookup.
    recent_rings: Arc<RwLock<HashMap<u32, VecDeque<SecurityEvent>>>>,
}

impl Timeline {
    #[allow(dead_code)]
    pub fn open(path: &std::path::Path) -> Result<Self> {
        let db = sled::open(path)?;
        Ok(Self {
            db: Arc::new(db),
            recent_rings: Arc::new(RwLock::new(HashMap::new())),
        })
    }

    pub fn open_temp() -> Result<Self> {
        let db = sled::Config::default().temporary(true).open()?;
        Ok(Self {
            db: Arc::new(db),
            recent_rings: Arc::new(RwLock::new(HashMap::new())),
        })
    }

    /// Drop the in-memory ring for a PID (call when the session ends, or
    /// the PID exits, to keep `recent_rings` bounded under churn).
    pub fn cleanup_pid(&self, pid: u32) {
        if let Ok(mut rings) = self.recent_rings.write() {
            rings.remove(&pid);
        }
    }

    /// Returns true if the target is a noisy file that should be filtered out.
    /// These are cgroup/proc/sys entries and library loads that fire hundreds
    /// of times per second and bury real file operations.
    pub fn is_noise_target(target: &str) -> bool {
        // Cgroup/proc entries, runtime binaries, and other high-frequency noise
        const NOISE: &[&str] = &[
            "memory.high",
            "memory.max",
            "memory.low",
            "memory.current",
            "memory.stat",
            "memory.swap.current",
            "memory.swap.max",
            "cpu.max",
            "cpu.stat",
            "cpu.weight",
            "cgroup.procs",
            "cgroup.controllers",
            "cgroup.subtree_control",
            "cgroup.events",
            "cgroup", // bare filename from eBPF (no full path)
            "pids.max",
            "pids.current",
            "io.max",
            "io.stat",
            "maps",
            "filesystems",
            "mountinfo",
            "mounts",
            "status",
            "ld.so.cache",
            "version_signature",
            // Runtime binaries opened repeatedly by agent processes
            "node",
            "python3",
            "python",
            "bash",
            "sh",
            "zsh",
        ];
        if NOISE.contains(&target) {
            return true;
        }
        // cgroup filenames (eBPF may send bare names without full path)
        if target.starts_with("cgroup") {
            return true;
        }
        // Shared libraries (.so files)
        if target.contains(".so.") || target.ends_with(".so") {
            return true;
        }
        // ELF loader
        if target.starts_with("ld-linux") {
            return true;
        }
        // Runtime module files — JS/TS/Python modules loaded by agent runtimes
        if target.ends_with(".js")
            || target.ends_with(".mjs")
            || target.ends_with(".cjs")
            || target.ends_with(".ts")
            || target.ends_with(".json")
            || target.ends_with(".node")
            || target.ends_with(".pyc")
            || target.ends_with(".wasm")
        {
            return true;
        }
        // /proc and /sys kernel interfaces
        if target.starts_with("/proc/") || target.starts_with("/sys/") {
            return true;
        }
        // Runtime binaries and standard paths
        if target.starts_with("/usr/bin/")
            || target.starts_with("/usr/lib/")
            || target.starts_with("/usr/share/")
        {
            return true;
        }
        // Node.js / Python package dirs
        if target.contains("node_modules/")
            || target.contains("site-packages/")
            || target.contains(".npm/")
            || target.contains(".nvm/")
        {
            return true;
        }
        // Temp files, caches
        if target.starts_with("/tmp/") || target.contains("/.cache/") || target.contains("/.local/")
        {
            return true;
        }
        false
    }

    /// Returns true if this event should be dropped before persistence.
    /// Aggressively filters kernel noise that bloats sled (cgroup, /proc,
    /// shared libraries, process exits, repeated forks).
    pub fn is_noise_event(event: &SecurityEvent) -> bool {
        use crate::common::event::EventKind;
        match event.kind {
            // File opens: filter cgroup/proc/library noise
            EventKind::FileOpen => Self::is_noise_target(&event.target),
            // Process exits are pure bookkeeping — never useful to persist
            EventKind::ProcessExit => true,
            // /proc and /sys reads from any process
            _ if event.target.starts_with("/proc/") => true,
            _ if event.target.starts_with("/sys/") => true,
            // cgroup paths
            _ if event.target.contains("/sys/fs/cgroup/") => true,
            _ => false,
        }
    }

    /// Insert a security event into the timeline.
    /// Handles disk-full and other sled write failures gracefully: logs an error
    /// and returns Ok(()) to avoid crashing the event pipeline. The daemon
    /// continues in a degraded state (events not persisted) rather than panicking.
    pub fn insert(&self, event: &SecurityEvent) -> Result<()> {
        // Filter noise before writing to disk
        if Self::is_noise_event(event) {
            return Ok(());
        }

        // Push into the per-PID in-memory ring BEFORE we touch sled, so a
        // sled write failure still gives the hot-path `recent()` lookups a
        // best-effort answer for the current window.
        if let Ok(mut rings) = self.recent_rings.write() {
            let ring = rings
                .entry(event.pid)
                .or_insert_with(|| VecDeque::with_capacity(RING_CAPACITY));
            if ring.len() >= RING_CAPACITY {
                ring.pop_front();
            }
            ring.push_back(event.clone());
        }

        let tree = match self.db.open_tree(format!("pid:{}", event.pid)) {
            Ok(t) => t,
            Err(e) => {
                tracing::error!(
                    pid = event.pid,
                    err = %e,
                    "Failed to open sled tree for event insert (degraded: event not persisted)"
                );
                return Ok(());
            }
        };
        let key = event
            .timestamp
            .timestamp_nanos_opt()
            .unwrap_or(0)
            .to_be_bytes();
        let val = match serde_json::to_vec(event) {
            Ok(v) => v,
            Err(e) => {
                tracing::error!(
                    pid = event.pid,
                    err = %e,
                    "Failed to serialize event for sled (degraded: event not persisted)"
                );
                return Ok(());
            }
        };
        if let Err(e) = tree.insert(key, val) {
            tracing::error!(
                pid = event.pid,
                err = %e,
                db_bytes = self.db_size_bytes(),
                "Sled write failed (disk full?), event not persisted — daemon degraded"
            );
            // Don't propagate — the event pipeline should continue
        }
        Ok(())
    }

    /// Retrieve events for a PID within the last `window_secs` seconds.
    pub fn recent(&self, pid: u32, window_secs: i64) -> Result<Vec<SecurityEvent>> {
        // Hot path — called per kernel event from main.rs for heuristic
        // scoring. We keep a per-PID in-memory ring of the most recent events
        // so this doesn't deserialize the entire sled per-PID tree on every
        // call. Sled remains the persistent fallback when the ring is empty
        // (cold PID after daemon restart, or events older than the ring's
        // retention).
        let now_ns = Utc::now().timestamp_nanos_opt().unwrap_or(0);
        let cutoff_ns = now_ns - window_secs * 1_000_000_000;

        // Fast path: in-memory ring.
        {
            if let Ok(rings) = self.recent_rings.read() {
                if let Some(ring) = rings.get(&pid) {
                    let events: Vec<SecurityEvent> = ring
                        .iter()
                        .filter(|e| e.timestamp.timestamp_nanos_opt().unwrap_or(0) >= cutoff_ns)
                        .cloned()
                        .collect();
                    if !events.is_empty() {
                        return Ok(events);
                    }
                }
            }
        }

        // Cold path: sled.
        let tree = self.db.open_tree(format!("pid:{}", pid))?;
        let cutoff_key = cutoff_ns.to_be_bytes();

        let mut events = Vec::new();
        for item in tree.range(cutoff_key.as_ref()..) {
            let (_, v) = item?;
            if let Ok(ev) = serde_json::from_slice::<SecurityEvent>(&v) {
                events.push(ev);
            }
        }
        Ok(events)
    }

    /// Union of recent events across a SET of PIDs — e.g. every PID in an agent
    /// session (`SessionStore::find_by_pid(pid).pids`) or a process subtree.
    ///
    /// Returns events sorted **ascending** by timestamp so that
    /// `ProvenanceGraph::from_events` sees parents before children and can build
    /// `ChildOf`/`NextInPid` edges. Deduplicates by event id. This is what turns
    /// a degenerate single-PID record (1 node, 0 edges) into a real
    /// session-scoped provenance graph — each agent action is a fresh ephemeral
    /// PID doing one exec, so per-PID alone is never a graph.
    pub fn recent_for_pids(&self, pids: &[u32], window_secs: i64) -> Result<Vec<SecurityEvent>> {
        let mut events: Vec<SecurityEvent> = Vec::new();
        let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
        for &pid in pids {
            if let Ok(evs) = self.recent(pid, window_secs) {
                for e in evs {
                    if seen.insert(e.id.clone()) {
                        events.push(e);
                    }
                }
            }
        }
        events.sort_by(|a, b| a.timestamp.cmp(&b.timestamp));
        Ok(events)
    }

    /// Retrieve events across all PIDs within the last `window_secs` seconds, up to `limit` events.
    pub fn all_recent(&self, window_secs: i64, limit: usize) -> Result<Vec<SecurityEvent>> {
        let cutoff = (Utc::now().timestamp() - window_secs) * 1_000_000_000;
        let cutoff_key = cutoff.to_be_bytes();

        let mut events = Vec::new();
        for name in self.db.tree_names() {
            // Only process pid:* trees
            let name_str = String::from_utf8_lossy(&name);
            if !name_str.starts_with("pid:") {
                continue;
            }
            if let Ok(tree) = self.db.open_tree(&name) {
                for item in tree.range(cutoff_key.as_ref()..) {
                    if let Ok((_, v)) = item {
                        if let Ok(ev) = serde_json::from_slice::<SecurityEvent>(&v) {
                            events.push(ev);
                        }
                    }
                }
            }
        }
        // Sort descending by timestamp (most recent first) and truncate
        events.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));
        events.truncate(limit);
        Ok(events)
    }

    /// Purge events older than `max_age_secs` for all PIDs.
    pub fn gc(&self, max_age_secs: i64) -> Result<usize> {
        let cutoff = (Utc::now().timestamp() - max_age_secs) * 1_000_000_000;
        let cutoff_key = cutoff.to_be_bytes();
        let mut removed = 0usize;
        for name in self.db.tree_names() {
            if let Ok(tree) = self.db.open_tree(&name) {
                let old_keys: Vec<_> = tree
                    .range(..cutoff_key.as_ref())
                    .filter_map(|r| r.ok().map(|(k, _)| k))
                    .collect();
                removed += old_keys.len();
                for k in old_keys {
                    tree.remove(k)?;
                }
            }
        }
        Ok(removed)
    }

    /// Return events across all PIDs since a cursor (event ID), up to `limit`.
    /// If cursor is empty, returns the oldest events. Used by cloud sync.
    /// Caps total scan at MAX_SCAN_EVENTS to prevent OOM on large databases.
    pub fn events_since_cursor(&self, cursor: &str, limit: usize) -> Vec<SecurityEvent> {
        const MAX_SCAN_EVENTS: usize = 10_000;

        let mut events = Vec::new();
        let mut total_scanned = 0usize;
        'outer: for name in self.db.tree_names() {
            let name_str = String::from_utf8_lossy(&name);
            if !name_str.starts_with("pid:") {
                continue;
            }
            if let Ok(tree) = self.db.open_tree(&name) {
                for item in tree.iter() {
                    if total_scanned >= MAX_SCAN_EVENTS {
                        tracing::warn!(
                            max = MAX_SCAN_EVENTS,
                            "events_since_cursor hit scan cap — results may be incomplete"
                        );
                        break 'outer;
                    }
                    total_scanned += 1;
                    if let Ok((_, v)) = item {
                        if let Ok(ev) = serde_json::from_slice::<SecurityEvent>(&v) {
                            events.push(ev);
                        }
                    }
                }
            }
        }
        // Sort ascending by timestamp
        events.sort_by(|a, b| a.timestamp.cmp(&b.timestamp));

        // If cursor is non-empty, skip events up to and including the cursor ID
        if !cursor.is_empty() {
            if let Some(pos) = events.iter().position(|e| e.id == cursor) {
                events = events.into_iter().skip(pos + 1).collect();
            }
        }

        events.truncate(limit);
        events
    }

    /// Current on-disk size of the sled database in bytes.
    pub fn db_size_bytes(&self) -> u64 {
        self.db.size_on_disk().unwrap_or(0)
    }

    /// Combined pruning: enforce 7-day retention AND 100MB cap.
    /// Called on startup and every 5 minutes by the background timer.
    pub fn prune(&self, max_age_secs: i64, max_bytes: u64) -> Result<()> {
        // Phase 1: age-based GC
        let removed_age = self.gc(max_age_secs)?;
        if removed_age > 0 {
            tracing::info!(removed = removed_age, "Pruned old events by age");
        }

        // Phase 2: size-based cap — progressively shrink retention window
        let mut current_window = max_age_secs;
        let mut passes = 0u32;
        while self.db_size_bytes() > max_bytes && current_window > 3600 {
            current_window = current_window * 3 / 4; // shrink by 25% each pass
            let removed_size = self.gc(current_window)?;
            passes += 1;
            if removed_size > 0 {
                tracing::info!(
                    removed = removed_size,
                    window_secs = current_window,
                    db_bytes = self.db_size_bytes(),
                    "Pruned events for size cap (pass {passes})"
                );
            }
            if passes >= 10 {
                break;
            } // safety valve
        }

        // Phase 3: drop empty trees and flush WAL to reclaim disk space
        let mut dropped = 0usize;
        for name in self.db.tree_names() {
            let name_str = String::from_utf8_lossy(&name);
            if !name_str.starts_with("pid:") {
                continue;
            }
            if let Ok(tree) = self.db.open_tree(&name) {
                if tree.is_empty() {
                    drop(tree);
                    if self.db.drop_tree(&name).is_ok() {
                        dropped += 1;
                    }
                }
            }
        }
        if dropped > 0 {
            tracing::info!(dropped, "Dropped empty sled trees");
        }

        // Flush to disk so WAL segments can be reclaimed
        if let Err(e) = self.db.flush() {
            tracing::warn!(err = %e, "Sled flush after prune failed");
        }

        Ok(())
    }

    /// Attempt to recover a potentially corrupt sled database.
    ///
    /// Strategy: export all readable data, drop the DB, reopen, and re-import.
    /// If the DB is irrecoverably corrupt, wipe it and start fresh.
    /// Returns the number of events recovered (0 means a full wipe was needed).
    #[allow(dead_code)]
    pub fn recover(path: &std::path::Path) -> Result<Self> {
        tracing::warn!(path = %path.display(), "Attempting sled DB recovery");

        // Phase 1: try to open and export all readable events
        let mut recovered: Vec<(String, Vec<u8>, Vec<u8>)> = Vec::new();
        match sled::open(path) {
            Ok(db) => {
                for name in db.tree_names() {
                    let name_str = String::from_utf8_lossy(&name).to_string();
                    if !name_str.starts_with("pid:") {
                        continue;
                    }
                    if let Ok(tree) = db.open_tree(&name) {
                        for item in tree.iter() {
                            match item {
                                Ok((k, v)) => {
                                    recovered.push((name_str.clone(), k.to_vec(), v.to_vec()));
                                }
                                Err(e) => {
                                    tracing::warn!(
                                        tree = %name_str,
                                        err = %e,
                                        "Skipping corrupt entry during recovery"
                                    );
                                }
                            }
                        }
                    }
                }
                drop(db);
            }
            Err(e) => {
                tracing::error!(
                    path = %path.display(),
                    err = %e,
                    "Cannot open corrupt sled DB, will wipe and start fresh"
                );
            }
        }

        // Phase 2: remove the corrupt DB directory
        if let Err(e) = std::fs::remove_dir_all(path) {
            tracing::warn!(
                path = %path.display(),
                err = %e,
                "Failed to remove corrupt sled DB directory"
            );
        }

        // Phase 3: reopen a fresh DB and re-import recovered events
        let db = sled::open(path)?;
        let mut reimported = 0usize;
        for (tree_name, key, value) in &recovered {
            if let Ok(tree) = db.open_tree(tree_name) {
                if tree.insert(key.as_slice(), value.as_slice()).is_ok() {
                    reimported += 1;
                }
            }
        }

        tracing::info!(
            path = %path.display(),
            total_recovered = recovered.len(),
            reimported,
            "Sled DB recovery complete"
        );

        Ok(Self {
            db: Arc::new(db),
            recent_rings: Arc::new(RwLock::new(HashMap::new())),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::event::{EventKind, SecurityEvent};
    use chrono::Utc;

    fn make_event(pid: u32, id: &str, secs_ago: i64) -> SecurityEvent {
        SecurityEvent {
            id: id.to_string(),
            kind: EventKind::FileOpen,
            pid,
            uid: 501,
            process: "test".into(),
            // NOTE: must not match `is_noise_event`'s `/tmp/` filter, else
            // these events are silently dropped before persistence.
            target: "/var/data/test".into(),
            allowed: true,
            reason: None,
            timestamp: Utc::now() - chrono::Duration::seconds(secs_ago),
            ppid: None,
            parent_process: None,
            llm_context: None,
            extra: None,
        }
    }

    #[test]
    fn events_since_cursor_basic() {
        let tl = Timeline::open_temp().unwrap();
        let ev1 = make_event(1, "ev-1", 30);
        let ev2 = make_event(1, "ev-2", 20);
        let ev3 = make_event(1, "ev-3", 10);
        tl.insert(&ev1).unwrap();
        tl.insert(&ev2).unwrap();
        tl.insert(&ev3).unwrap();

        // Empty cursor → all events
        let all = tl.events_since_cursor("", 100);
        assert_eq!(all.len(), 3);

        // Cursor at ev-1 → skip ev-1, return ev-2 and ev-3
        let after = tl.events_since_cursor("ev-1", 100);
        assert_eq!(after.len(), 2);
        assert_eq!(after[0].id, "ev-2");

        // Limit works
        let limited = tl.events_since_cursor("", 1);
        assert_eq!(limited.len(), 1);
    }

    fn ev(
        pid: u32,
        ppid: u32,
        id: &str,
        kind: EventKind,
        target: &str,
        secs_ago: i64,
    ) -> SecurityEvent {
        SecurityEvent {
            id: id.to_string(),
            kind,
            pid,
            uid: 1000,
            process: "agent".into(),
            target: target.into(),
            allowed: true,
            reason: None,
            timestamp: Utc::now() - chrono::Duration::seconds(secs_ago),
            ppid: Some(ppid),
            parent_process: None,
            llm_context: None,
            extra: None,
        }
    }

    #[test]
    fn recent_for_pids_builds_a_real_multi_node_graph() {
        use crate::analyzer::graph::ProvenanceGraph;
        let tl = Timeline::open_temp().unwrap();
        // A session spanning 3 PIDs: claude(100) -> bash(101) -> curl(102),
        // curl reads an SSH key then connects out — a real exfil chain.
        // Realistic `{pid}-{nanos}` ids — the two pid-102 events share a 16-char
        // prefix, so a truncated node key would collapse them (the live bug).
        tl.insert(&ev(
            100,
            1,
            "100-1780737435001",
            EventKind::ProcessExec,
            "/usr/bin/bash",
            50,
        ))
        .unwrap();
        tl.insert(&ev(
            101,
            100,
            "101-1780737435002",
            EventKind::ProcessExec,
            "/usr/bin/curl",
            40,
        ))
        .unwrap();
        tl.insert(&ev(
            102,
            101,
            "102-1780737435003",
            EventKind::FileOpen,
            "/home/u/.ssh/id_rsa",
            30,
        ))
        .unwrap();
        tl.insert(&ev(
            102,
            101,
            "102-1780737435004",
            EventKind::NetworkConnect,
            "evil.example.com:443",
            20,
        ))
        .unwrap();

        // Per-PID (the old behavior) is degenerate: pid 100 alone = 1 node, 0 edges.
        let single = ProvenanceGraph::from_events(&tl.recent(100, 120).unwrap(), 40);
        assert_eq!(
            single.node_count(),
            1,
            "single ephemeral pid is not a graph"
        );

        // Session-scoped: union of all session PIDs builds a connected graph.
        let pids = [100u32, 101, 102];
        let events = tl.recent_for_pids(&pids, 120).unwrap();
        assert_eq!(events.len(), 4, "union of all session pids, deduped");
        // ascending time order so ChildOf/NextInPid can form
        assert!(events.windows(2).all(|w| w[0].timestamp <= w[1].timestamp));

        let graph = ProvenanceGraph::from_events(&events, 40);
        assert!(graph.node_count() >= 4, "got {} nodes", graph.node_count());
        assert!(
            graph.edge_count() >= 3,
            "expected ChildOf+AccessesCredential+ConnectsTo edges, got {}",
            graph.edge_count()
        );
    }

    #[test]
    fn events_since_cursor_empty_db() {
        let tl = Timeline::open_temp().unwrap();
        let events = tl.events_since_cursor("", 100);
        assert!(events.is_empty());
    }

    #[test]
    fn recover_creates_fresh_db_on_empty_path() {
        let path = std::env::temp_dir().join(format!("rz-test-recover-{}", uuid::Uuid::new_v4()));
        // No existing DB → recover should create a fresh one
        let tl = Timeline::recover(&path).unwrap();
        let events = tl.events_since_cursor("", 100);
        assert!(events.is_empty());
        drop(tl);
        let _ = std::fs::remove_dir_all(&path);
    }

    #[test]
    fn recover_preserves_existing_events() {
        let path =
            std::env::temp_dir().join(format!("rz-test-recover-pres-{}", uuid::Uuid::new_v4()));

        // Insert events into a normal DB
        {
            let tl = Timeline::open(&path).unwrap();
            let ev = make_event(42, "preserved-1", 5);
            tl.insert(&ev).unwrap();
        }

        // Recover should preserve the event
        let tl = Timeline::recover(&path).unwrap();
        let events = tl.events_since_cursor("", 100);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].id, "preserved-1");
        drop(tl);
        let _ = std::fs::remove_dir_all(&path);
    }
}
