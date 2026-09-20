// SPDX-License-Identifier: Apache-2.0
// session/store.rs — Session lifecycle management (sled-backed)
//
// Tracks every AI agent session: PENDING → ACTIVE → WAITING_APPROVAL → EXPIRED / TERMINATED
//
// Persistence: Sessions and per-session events are stored in sled trees.
// Sessions survive daemon restarts. Events are capped at 10,000 per session.
//
// Trees:
//   "sessions"          — key: session_id, value: bincode(Session)
//   "events:{session}"  — key: timestamp_nanos, value: bincode(SecurityEvent)

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sled::Db;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

static EVENT_SEQ: AtomicU64 = AtomicU64::new(0);

use crate::common::event::SecurityEvent;

/// Process liveness check.
/// Returns true if the process exists (even if we lack permission to signal it).
fn pid_alive(pid: u32) -> bool {
    use nix::libc;
    let ret = unsafe { libc::kill(pid as libc::pid_t, 0) };
    if ret == 0 {
        return true;
    }
    let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
    errno == libc::EPERM
}

// ── Session state ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SessionState {
    Pending,
    Active,
    WaitingApproval,
    Expired,
    Terminated,
}

// ── Agent type ────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AgentType {
    Claude,
    #[serde(rename = "chatgpt")]
    ChatGpt,
    Gemini,
    DeepSeek,
    Cursor,
    Copilot,
    Codex,
    Devin,
    /// Sessions originating from a Ring Zero platform driver (eBPF loader,
    /// eBPF loader, etc.). Distinct from `Custom` because
    /// `Custom(String)` serializes as `{"custom": "..."}`, which broke the
    /// frontend's `agentIcon()` helper. `Driver` serializes as the plain
    /// string `"driver"`.
    Driver,
    #[serde(rename = "custom")]
    Custom(String),
}

impl AgentType {
    /// Map an `agent_detect` class string ("gemini", "claude", …) to an AgentType.
    pub fn from_class(class: &str) -> Self {
        match class {
            "claude" => AgentType::Claude,
            "cursor" => AgentType::Cursor,
            "copilot" => AgentType::Copilot,
            "codex" => AgentType::Codex,
            "chatgpt" => AgentType::ChatGpt,
            "gemini" => AgentType::Gemini,
            "devin" => AgentType::Devin,
            other => AgentType::Custom(other.to_string()),
        }
    }
}

impl std::fmt::Display for AgentType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AgentType::Claude => write!(f, "claude"),
            AgentType::ChatGpt => write!(f, "chatgpt"),
            AgentType::Gemini => write!(f, "gemini"),
            AgentType::DeepSeek => write!(f, "deepseek"),
            AgentType::Cursor => write!(f, "cursor"),
            AgentType::Copilot => write!(f, "copilot"),
            AgentType::Codex => write!(f, "codex"),
            AgentType::Devin => write!(f, "devin"),
            AgentType::Driver => write!(f, "driver"),
            AgentType::Custom(s) => write!(f, "{}", s),
        }
    }
}

// ── Privilege escalation event ────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrivEscEvent {
    pub kind: String, // "sudo", "su", "doas", "shell_escape", "setuid", "credential_store"
    pub process: String,
    pub target: String,
    pub pid: u32,
    pub blocked: bool,
    pub timestamp: DateTime<Utc>,
}

// ── Session record ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JitIdentity {
    pub id: String,
    pub scope: String, // what resource/service this grants access to
    pub granted_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub revoked: bool,
}

impl JitIdentity {
    pub fn new(scope: impl Into<String>, ttl_secs: u64) -> Self {
        let now = Utc::now();
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            scope: scope.into(),
            granted_at: now,
            expires_at: now + chrono::Duration::seconds(ttl_secs as i64),
            revoked: false,
        }
    }
    #[allow(dead_code)]
    pub fn is_active(&self) -> bool {
        !self.revoked && Utc::now() < self.expires_at
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EscalationRequest {
    pub id: String,
    pub session_id: String,
    pub tool_name: String,
    pub reason: String,
    pub requested_at: DateTime<Utc>,
    pub resolved_at: Option<DateTime<Utc>>,
    pub approved: Option<bool>,
    pub reviewer: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    pub id: String,
    pub agent_type: AgentType,
    pub actor: String,
    pub declared_scope: Vec<String>,
    pub state: SessionState,
    pub privileged: bool,
    pub privileged_reason: Option<String>, // why it was flagged privileged
    pub policies: Vec<String>,
    pub granted_access: Vec<String>,
    pub jit_identities: Vec<JitIdentity>, // full JIT identity objects
    pub escalations: Vec<EscalationRequest>,
    pub start_time: DateTime<Utc>,
    pub end_time: Option<DateTime<Utc>>,
    pub ttl_secs: Option<u64>,
    pub event_count: usize,
    pub last_event_at: DateTime<Utc>,
    /// SPIFFE identity (set when SVID is issued for this session)
    pub spiffe_id: Option<String>,
    /// Certificate serial number (hex) from the issued SVID
    pub cert_serial: Option<String>,
    /// When the session's SVID certificate expires
    pub cert_expires_at: Option<DateTime<Utc>>,
    /// PIDs associated with this session (kernel→session wiring)
    pub pids: Vec<u32>,
    /// Privilege escalation detections (sudo/su/shell-escape)
    pub priv_esc_events: Vec<PrivEscEvent>,
}

impl Session {
    pub fn new(
        id: impl Into<String>,
        agent_type: AgentType,
        actor: impl Into<String>,
        declared_scope: Vec<String>,
        ttl_secs: Option<u64>,
    ) -> Self {
        Self {
            id: id.into(),
            agent_type,
            actor: actor.into(),
            declared_scope,
            state: SessionState::Pending,
            privileged: false,
            privileged_reason: None,
            policies: Vec::new(),
            granted_access: Vec::new(),
            jit_identities: Vec::new(),
            escalations: Vec::new(),
            start_time: Utc::now(),
            end_time: None,
            ttl_secs,
            event_count: 0,
            last_event_at: Utc::now(),
            spiffe_id: None,
            cert_serial: None,
            cert_expires_at: None,
            pids: Vec::new(),
            priv_esc_events: Vec::new(),
        }
    }

    /// Is this session currently live (PENDING or ACTIVE)?
    pub fn is_live(&self) -> bool {
        matches!(
            self.state,
            SessionState::Pending | SessionState::Active | SessionState::WaitingApproval
        )
    }

    /// Check if session has exceeded its TTL and should be expired.
    pub fn is_timed_out(&self) -> bool {
        if let Some(ttl) = self.ttl_secs {
            let elapsed = (Utc::now() - self.start_time).num_seconds();
            elapsed >= ttl as i64
        } else {
            false
        }
    }
}

// ── sled serialization helpers ───────────────────────────────────────────────

fn encode_session(s: &Session) -> Vec<u8> {
    serde_json::to_vec(s).unwrap_or_default()
}

fn decode_session(bytes: &[u8]) -> Option<Session> {
    serde_json::from_slice(bytes).ok()
}

fn encode_event(e: &SecurityEvent) -> Vec<u8> {
    serde_json::to_vec(e).unwrap_or_default()
}

fn decode_event(bytes: &[u8]) -> Option<SecurityEvent> {
    serde_json::from_slice(bytes).ok()
}

/// Monotonic key for event ordering within a session tree.
/// Uses nanosecond timestamp + monotonic sequence to avoid collisions.
fn event_key(ts: &DateTime<Utc>) -> Vec<u8> {
    let nanos = ts.timestamp_nanos_opt().unwrap_or(0) as u64;
    let seq = EVENT_SEQ.fetch_add(1, Ordering::Relaxed);
    let mut key = Vec::with_capacity(16);
    key.extend_from_slice(&nanos.to_be_bytes());
    key.extend_from_slice(&seq.to_be_bytes());
    key
}

// ── Store (sled-backed) ──────────────────────────────────────────────────────

const SESSIONS_TREE: &str = "sessions";
const MAX_EVENTS_PER_SESSION: usize = 10_000;

pub struct SessionStore {
    db: Arc<Db>,
    /// In-memory PID → session_id index. `find_by_pid` is called from the
    /// kernel event hot loop; without this we'd iterate the entire sled
    /// sessions tree for every eBPF event. Populated on startup from sled
    /// and kept in sync with `register_pid` / `terminate`.
    pid_index: Arc<std::sync::RwLock<std::collections::HashMap<u32, String>>>,
}

impl SessionStore {
    /// Open a sled-backed session store at the given path.
    /// Sessions and events survive daemon restarts.
    pub fn open(path: &std::path::Path) -> anyhow::Result<Self> {
        let db = sled::open(path)?;
        tracing::info!(path = %path.display(), "Session store opened (sled)");
        let store = Self {
            db: Arc::new(db),
            pid_index: Arc::new(std::sync::RwLock::new(std::collections::HashMap::new())),
        };
        store.migrate_waiting_approval();
        store.rebuild_pid_index();
        Ok(store)
    }

    /// Scan sled and rehydrate the in-memory PID→session_id index.
    /// Called on startup so kernel events for already-tracked PIDs route
    /// correctly even after a daemon restart.
    fn rebuild_pid_index(&self) {
        let tree = self.sessions_tree();
        let mut idx = match self.pid_index.write() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        idx.clear();
        for entry in tree.iter() {
            if let Ok((_k, v)) = entry {
                if let Some(s) = decode_session(&v) {
                    if s.is_live() {
                        for pid in &s.pids {
                            idx.insert(*pid, s.id.clone());
                        }
                    }
                }
            }
        }
        if !idx.is_empty() {
            tracing::info!(pids = idx.len(), "Rebuilt PID→session index");
        }
    }

    /// Migrate any persisted WAITING_APPROVAL sessions to ACTIVE on startup.
    /// WaitingApproval was removed from the UX — auto-containment replaces it.
    fn migrate_waiting_approval(&self) {
        let tree = self.sessions_tree();
        let mut migrated = 0u32;
        for entry in tree.iter() {
            let (k, v) = match entry {
                Ok(kv) => kv,
                Err(_) => continue,
            };
            let mut s = match decode_session(&v) {
                Some(s) => s,
                None => continue,
            };
            if s.state == SessionState::WaitingApproval {
                s.state = SessionState::Active;
                let _ = tree.insert(&k, encode_session(&s));
                migrated += 1;
            }
        }
        if migrated > 0 {
            tracing::info!(
                count = migrated,
                "Migrated WAITING_APPROVAL sessions to ACTIVE"
            );
        }
    }

    /// Create a temporary in-memory session store (for tests / fallback).
    pub fn new() -> Self {
        let db = sled::Config::default()
            .temporary(true)
            .open()
            .expect("Failed to open temporary sled DB");
        Self {
            db: Arc::new(db),
            pid_index: Arc::new(std::sync::RwLock::new(std::collections::HashMap::new())),
        }
    }

    fn sessions_tree(&self) -> sled::Tree {
        self.db.open_tree(SESSIONS_TREE).expect("sled tree open")
    }

    fn events_tree(&self, session_id: &str) -> sled::Tree {
        self.db
            .open_tree(format!("events:{}", session_id))
            .expect("sled tree open")
    }

    /// Persist a session to sled.
    fn persist(&self, session: &Session) {
        let tree = self.sessions_tree();
        if let Err(e) = tree.insert(session.id.as_bytes(), encode_session(session)) {
            tracing::warn!(session_id = %session.id, err = %e, "Failed to persist session");
        }
    }

    /// Read-modify-write a session. Returns the return value of the closure.
    fn update<F, R>(&self, id: &str, f: F) -> R
    where
        F: FnOnce(Option<&mut Session>) -> R,
    {
        let tree = self.sessions_tree();
        let mut session = tree
            .get(id.as_bytes())
            .ok()
            .flatten()
            .and_then(|v| decode_session(&v));
        let result = f(session.as_mut());
        if let Some(s) = &session {
            if let Err(e) = tree.insert(id.as_bytes(), encode_session(s)) {
                tracing::warn!(session_id = id, err = %e, "Failed to persist session update");
            }
        }
        result
    }

    /// Register a new session (starts in PENDING state).
    pub fn create(&self, session: Session) {
        // Index the pids the session already carries so `find_by_pid` works for
        // the very first event (auto-created sessions start with the agent pid).
        if let Ok(mut idx) = self.pid_index.write() {
            for &p in &session.pids {
                idx.insert(p, session.id.clone());
            }
        }
        self.persist(&session);
    }

    /// Transition a session to ACTIVE.
    pub fn activate(&self, id: &str) -> bool {
        self.update(id, |s| {
            if let Some(s) = s {
                if s.state == SessionState::Pending {
                    s.state = SessionState::Active;
                    return true;
                }
            }
            false
        })
    }

    /// Transition a session to WAITING_APPROVAL (human escalation).
    #[allow(dead_code)]
    pub fn request_approval(&self, id: &str) -> bool {
        self.update(id, |s| {
            if let Some(s) = s {
                if s.is_live() {
                    s.state = SessionState::WaitingApproval;
                    return true;
                }
            }
            false
        })
    }

    /// Approve a waiting session — moves it back to ACTIVE.
    pub fn approve(&self, id: &str) -> bool {
        self.update(id, |s| {
            if let Some(s) = s {
                if s.state == SessionState::WaitingApproval {
                    s.state = SessionState::Active;
                    return true;
                }
            }
            false
        })
    }

    /// Terminate a session immediately.
    pub fn terminate(&self, id: &str) -> bool {
        // Capture the PID set before flipping state so we can scrub the
        // in-memory PID→session index. Without this, terminated sessions
        // leak entries until the daemon restarts (find_by_pid does lazy
        // cleanup only when those PIDs are queried again).
        let pids_to_purge: Vec<u32> = self.get(id).map(|s| s.pids.clone()).unwrap_or_default();

        let terminated = self.update(id, |s| {
            if let Some(s) = s {
                if s.is_live() {
                    s.state = SessionState::Terminated;
                    s.end_time = Some(Utc::now());
                    return true;
                }
            }
            false
        });

        if terminated {
            if let Ok(mut idx) = self.pid_index.write() {
                for pid in pids_to_purge {
                    idx.remove(&pid);
                }
            }
        }

        terminated
    }

    /// Mark a session as privileged with a reason.
    pub fn set_privileged(&self, id: &str, reason: impl Into<String>) {
        let reason = reason.into();
        self.update(id, |s| {
            if let Some(s) = s {
                if !s.privileged {
                    s.privileged = true;
                    s.privileged_reason = Some(reason);
                }
            }
        });
    }

    /// Increment event counter for a session.
    pub fn inc_events(&self, id: &str) {
        self.update(id, |s| {
            if let Some(s) = s {
                s.event_count += 1;
                s.last_event_at = Utc::now();
            }
        });
    }

    /// Register a PID with a session (kernel→session wiring).
    pub fn register_pid(&self, session_id: &str, pid: u32) {
        self.update(session_id, |s| {
            if let Some(s) = s {
                if !s.pids.contains(&pid) {
                    s.pids.push(pid);
                }
            }
        });
        // Keep the in-memory index in sync so the next kernel event for this
        // PID is an O(1) lookup.
        if let Ok(mut idx) = self.pid_index.write() {
            idx.insert(pid, session_id.to_string());
        }
    }

    /// Find a **live** session by PID.
    ///
    /// Hot path: called from the kernel event loop for every eBPF event.
    /// O(1) via the in-memory index. We still verify the session is live
    /// and the PID is still in its set before returning, so a stale index
    /// entry can't surface a terminated session.
    pub fn find_by_pid(&self, pid: u32) -> Option<Session> {
        let session_id = {
            let idx = self.pid_index.read().ok()?;
            idx.get(&pid).cloned()
        };
        if let Some(sid) = session_id {
            if let Some(s) = self.get(&sid) {
                if s.is_live() && s.pids.contains(&pid) {
                    return Some(s);
                }
                // Stale entry — drop it so we don't keep visiting sled for
                // this PID.
                if let Ok(mut idx) = self.pid_index.write() {
                    idx.remove(&pid);
                }
            }
        }
        None
    }

    /// Record a privilege escalation event on a session.
    pub fn record_priv_esc(&self, session_id: &str, event: PrivEscEvent) {
        self.update(session_id, |s| {
            if let Some(s) = s {
                s.priv_esc_events.push(event);
                if !s.privileged {
                    s.privileged = true;
                    s.privileged_reason = Some("privilege_escalation_detected".to_string());
                }
            }
        });
    }

    /// Provision a JIT identity for a session scope. Returns the new identity ID.
    pub fn provision_jit(
        &self,
        session_id: &str,
        scope: impl Into<String>,
        ttl_secs: u64,
    ) -> Option<String> {
        let scope = scope.into();
        self.update(session_id, |s| {
            if let Some(s) = s {
                let jit = JitIdentity::new(scope, ttl_secs);
                let id = jit.id.clone();
                if !s.granted_access.contains(&jit.scope) {
                    s.granted_access.push(jit.scope.clone());
                }
                s.jit_identities.push(jit);
                return Some(id);
            }
            None
        })
    }

    /// Revoke a specific JIT identity by ID.
    pub fn revoke_jit(&self, session_id: &str, jit_id: &str) -> bool {
        self.update(session_id, |s| {
            if let Some(s) = s {
                for jit in &mut s.jit_identities {
                    if jit.id == jit_id {
                        jit.revoked = true;
                        return true;
                    }
                }
            }
            false
        })
    }

    /// Decommission all JIT identities for a session (called on terminate/expire).
    pub fn decommission_jit(&self, session_id: &str) {
        self.update(session_id, |s| {
            if let Some(s) = s {
                for jit in &mut s.jit_identities {
                    jit.revoked = true;
                }
            }
        });
    }

    /// Record an escalation request on a session. Returns the escalation ID.
    pub fn escalate(
        &self,
        session_id: &str,
        tool_name: impl Into<String>,
        reason: impl Into<String>,
    ) -> Option<String> {
        let tool_name = tool_name.into();
        let reason = reason.into();
        self.update(session_id, |s| {
            if let Some(s) = s {
                if s.is_live() {
                    // Record the escalation for audit + the threat alert, but DON'T
                    // flip the session to WAITING_APPROVAL — that approval gate was
                    // removed from the UX in favour of auto-containment (see
                    // migrate_waiting_approval). The session stays ACTIVE so it
                    // keeps showing live agent activity; enforcement is handled by
                    // containment, not a human approval queue.
                    let esc = EscalationRequest {
                        id: uuid::Uuid::new_v4().to_string(),
                        session_id: session_id.to_string(),
                        tool_name,
                        reason,
                        requested_at: Utc::now(),
                        resolved_at: None,
                        approved: None,
                        reviewer: None,
                    };
                    let esc_id = esc.id.clone();
                    s.escalations.push(esc);
                    return Some(esc_id);
                }
            }
            None
        })
    }

    /// Resolve an escalation (approve=true resumes session, false terminates).
    pub fn resolve_escalation(
        &self,
        session_id: &str,
        escalation_id: &str,
        approved: bool,
        reviewer: impl Into<String>,
    ) -> bool {
        let reviewer = reviewer.into();
        self.update(session_id, |s| {
            if let Some(s) = s {
                for esc in &mut s.escalations {
                    if esc.id == escalation_id && esc.approved.is_none() {
                        esc.approved = Some(approved);
                        esc.reviewer = Some(reviewer);
                        esc.resolved_at = Some(Utc::now());
                        if approved {
                            s.state = SessionState::Active;
                        } else {
                            s.state = SessionState::Terminated;
                            s.end_time = Some(Utc::now());
                        }
                        return true;
                    }
                }
            }
            false
        })
    }

    /// List all sessions with a pending escalation (WAITING_APPROVAL).
    pub fn list_waiting(&self) -> Vec<Session> {
        self.list()
            .into_iter()
            .filter(|s| s.state == SessionState::WaitingApproval)
            .collect()
    }

    /// Returns true if any live session is awaiting approval.
    /// Used by the TLS proxy to gate LLM API traffic.
    pub fn has_unapproved_sessions(&self) -> bool {
        let tree = self.sessions_tree();
        for entry in tree.iter() {
            if let Ok((_k, v)) = entry {
                if let Some(s) = decode_session(&v) {
                    if s.state == SessionState::WaitingApproval {
                        return true;
                    }
                }
            }
        }
        false
    }

    /// Check if LLM API traffic should be allowed through the proxy.
    /// Returns true only if there is at least one ACTIVE (approved) session.
    /// Returns false if there are no sessions or only unapproved/pending sessions.
    pub fn has_approved_session(&self) -> bool {
        let tree = self.sessions_tree();
        for entry in tree.iter() {
            if let Ok((_k, v)) = entry {
                if let Some(s) = decode_session(&v) {
                    if s.state == SessionState::Active {
                        return true;
                    }
                }
            }
        }
        false
    }

    /// Expire sessions that have exceeded their TTL or whose processes have exited.
    pub fn expire_stale(&self) {
        let now = Utc::now();
        let tree = self.sessions_tree();
        for entry in tree.iter() {
            let (k, v) = match entry {
                Ok(kv) => kv,
                Err(_) => continue,
            };
            let mut s = match decode_session(&v) {
                Some(s) => s,
                None => continue,
            };
            if !s.is_live() {
                continue;
            }
            let mut changed = false;
            // TTL-based expiry
            if s.is_timed_out() {
                s.state = SessionState::Expired;
                s.end_time = Some(now);
                changed = true;
            } else {
                // Idle expiry: no events for 120 seconds AND all PIDs dead
                let idle_secs = (now - s.last_event_at).num_seconds();
                if idle_secs > 120 && !s.pids.is_empty() {
                    let any_alive = s.pids.iter().any(|&pid| pid_alive(pid));
                    if !any_alive {
                        s.state = SessionState::Terminated;
                        s.end_time = Some(now);
                        changed = true;
                    }
                }
            }
            if changed {
                let _ = tree.insert(&k, encode_session(&s));
            }
        }
    }

    /// Fetch a single session by ID.
    pub fn get(&self, id: &str) -> Option<Session> {
        let tree = self.sessions_tree();
        tree.get(id.as_bytes())
            .ok()
            .flatten()
            .and_then(|v| decode_session(&v))
    }

    /// List all sessions, newest first.
    pub fn list(&self) -> Vec<Session> {
        let tree = self.sessions_tree();
        let mut v: Vec<Session> = tree
            .iter()
            .filter_map(|entry| entry.ok())
            .filter_map(|(_, v)| decode_session(&v))
            .collect();
        v.sort_by(|a, b| b.start_time.cmp(&a.start_time));
        v
    }

    /// List only live (non-terminal) sessions.
    pub fn list_active(&self) -> Vec<Session> {
        self.list().into_iter().filter(|s| s.is_live()).collect()
    }

    /// Append an event to the per-session log and bump the session counter.
    /// Silently drops if the session does not exist. Capped at 10 000 events.
    pub fn append_event(&self, session_id: &str, event: SecurityEvent) {
        // Check session exists and update metadata
        let exists = self.update(session_id, |s| {
            if let Some(s) = s {
                s.event_count += 1;
                s.last_event_at = event.timestamp;
                true
            } else {
                false
            }
        });
        if !exists {
            return;
        }

        // Store event in per-session tree
        let events_tree = self.events_tree(session_id);
        if events_tree.len() < MAX_EVENTS_PER_SESSION {
            let key = event_key(&event.timestamp);
            if let Err(e) = events_tree.insert(key, encode_event(&event)) {
                tracing::warn!(session_id, err = %e, "Failed to persist session event");
            }
        }
    }

    /// Return a copy of all events for a session, newest first.
    pub fn get_events(&self, session_id: &str) -> Vec<SecurityEvent> {
        let events_tree = self.events_tree(session_id);
        let mut events: Vec<SecurityEvent> = events_tree
            .iter()
            .rev()
            .filter_map(|entry| entry.ok())
            .filter_map(|(_, v)| decode_event(&v))
            .collect();
        events.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));
        events
    }
}

impl Default for SessionStore {
    fn default() -> Self {
        Self::new()
    }
}
