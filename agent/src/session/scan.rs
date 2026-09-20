// SPDX-License-Identifier: Apache-2.0
//! Running-agent discovery — registers a Session for every live AI-agent process
//! by scanning `/proc`, independent of LLM traffic.
//!
//! The SSL-traffic path (`ssl_sniff`) only creates a session once an agent makes
//! a recognized LLM API call. That misses agents that are running but idle, that
//! talk to an unrecognized endpoint, or that have no network at all — and it
//! never fired for Gemini CLI because its `comm` is `node`/`MainThread`, not
//! `gemini` (the identity is only in argv). This scan fixes that: it detects the
//! agent from the command line (`agent_detect::detect_agent_for_pid`) and shows
//! the session the moment the process is running.

use std::collections::HashSet;
use std::sync::Arc;

use crate::analyzer::observer::ObserverEngine;
use crate::common::agent_detect::detect_agent_for_pid;
use crate::session::store::{AgentType, Session, SessionState, SessionStore};

/// One reconciliation pass: register sessions for newly-seen agent processes and
/// terminate auto-created sessions whose processes have exited.
pub async fn reconcile(
    sessions: &Arc<SessionStore>,
    observer: &Arc<ObserverEngine>,
    track_agent_pid: &(dyn Fn(u32) + Send + Sync),
) {
    let Ok(dir) = std::fs::read_dir("/proc") else {
        return;
    };
    let mut live_agent_pids: HashSet<u32> = HashSet::new();

    // Pids with a recently-Terminated session (within the kill grace window). The
    // operator "Terminate" kills the process tree, but the SIGTERM→SIGKILL grace
    // (~2s) leaves a brief window where the process is still alive; don't
    // resurrect a session in that window. We do NOT skip ALL terminated pids
    // forever (that breaks pid reuse — a brand-new agent reusing the pid of an
    // old terminated session would be invisible).
    let now = chrono::Utc::now();
    let recently_terminated: HashSet<u32> = sessions
        .list()
        .iter()
        .filter(|s| {
            matches!(s.state, SessionState::Terminated)
                && s.end_time
                    .map(|t| (now - t).num_seconds() < 15)
                    .unwrap_or(false)
        })
        .flat_map(|s| s.pids.clone())
        .collect();

    for entry in dir.flatten() {
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|s| s.parse::<u32>().ok())
        else {
            continue;
        };
        let comm = std::fs::read_to_string(format!("/proc/{pid}/comm")).unwrap_or_default();
        let Some(class) = detect_agent_for_pid(pid, comm.trim()) else {
            continue;
        };
        if class == "custom" {
            continue;
        } // Skip unrecognized processes
        live_agent_pids.insert(pid);

        // Taint EVERY detected agent pid in the kernel (agent_descendants) so its
        // file/network/exec events are captured — the in-kernel comm check misses
        // Node/Python CLIs. Without this the session exists but has no events.
        track_agent_pid(pid);

        // The top-level agent process owns the session. Skip a pid whose PARENT is
        // also an agent process (e.g. Gemini's `node` wrapper forks a `node`
        // child — both match), so one invocation = one session, not two.
        if let Some(ppid) = parent_pid(pid) {
            let pcomm = std::fs::read_to_string(format!("/proc/{ppid}/comm")).unwrap_or_default();
            if detect_agent_for_pid(ppid, pcomm.trim()).is_some() {
                continue;
            }
        }

        if sessions.find_by_pid(pid).is_some() {
            continue; // already has a live session
        }
        if recently_terminated.contains(&pid) {
            continue; // just terminated by the operator — don't resurrect mid-kill
        }
        let sid = format!("auto-{class}-{pid}");
        let mut s = Session::new(
            sid.clone(),
            AgentType::from_class(class),
            class.to_string(),
            vec![],
            None,
        );
        s.state = SessionState::Active;
        s.pids.push(pid);
        sessions.create(s);
        observer.assign_policy(&sid, class, vec![]).await;
        tracing::info!(session_id = %sid, pid, agent = class, "Registered session from running agent process (/proc scan)");
    }

    // Reap: an auto-created session whose every pid is gone is terminated, so the
    // Sessions view reflects what's actually running.
    for s in sessions.list() {
        let active = matches!(
            s.state,
            SessionState::Active | SessionState::Pending | SessionState::WaitingApproval
        );
        if !s.id.starts_with("auto-") || !active {
            continue;
        }
        let any_alive = s
            .pids
            .iter()
            .any(|p| std::path::Path::new(&format!("/proc/{p}")).exists());
        if !any_alive {
            sessions.terminate(&s.id);
        }
    }
}

/// Parent pid from /proc/<pid>/status (PPid line). None if unreadable.
fn parent_pid(pid: u32) -> Option<u32> {
    let status = std::fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("PPid:") {
            return rest.trim().parse::<u32>().ok();
        }
    }
    None
}
