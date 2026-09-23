// SPDX-License-Identifier: Apache-2.0
// ipc/server.rs — IPC server (Unix socket, newline-delimited JSON)

use crate::analyzer::{
    intent_diff::{IntentDiffEngine, IntentRecord},
    timeline::Timeline,
};
use crate::common::protocol::{ClientRequest, DaemonMessage};
use crate::integrations::webhook::WebhookHandle;
use crate::policy::network::NetworkPolicy;
use crate::secrets::dlp::DlpEngine;
use anyhow::Result;
use std::sync::Arc;
use tokio::sync::broadcast;

/// Server handle — holds shared state and the broadcast sender for pushing events to subscribers.
///
/// Broadcast payload is `Arc<String>` (a fully-serialized, newline-terminated
/// JSON line) so we serialize each event exactly once and every subscriber
/// just writes the same bytes. Previously the channel carried `DaemonMessage`
/// and each receiver re-ran `serde_json::to_string` — at N subscribers and M
/// events/sec, that's N×M serializations per second.
pub struct IpcServer {
    pub tx: broadcast::Sender<Arc<String>>,
    pub intent_diff: Arc<IntentDiffEngine>,
    pub timeline: Arc<Timeline>,
    pub network: Arc<NetworkPolicy>,
    pub dlp: Arc<DlpEngine>,
    /// Detection webhooks: every broadcast event/threat is also offered to the
    /// async stream (no-op unless endpoints are configured).
    pub webhooks: Arc<WebhookHandle>,
}

impl IpcServer {
    /// Bind to `sock_path` and spawn the accept loop. Returns the server handle.
    pub fn bind(
        sock_path: &std::path::Path,
        network: Arc<NetworkPolicy>,
        dlp: Arc<DlpEngine>,
        webhooks: Arc<WebhookHandle>,
    ) -> Result<Arc<Self>> {
        use tokio::net::UnixListener;

        // Remove stale socket
        let _ = std::fs::remove_file(sock_path);

        // Ensure parent directory exists
        if let Some(parent) = sock_path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let listener = UnixListener::bind(sock_path)?;

        // Socket permissions: keep the path accessible so the local UI / CLI
        // can connect without group plumbing, but enforce a peer-credential
        // (SO_PEERCRED) check inside `handle_client` below.
        // The kernel hands us the connecting process's UID; we accept root
        // (uid 0) and the operator UID embedded in `RZ_OPERATOR_UID`, reject
        // everyone else. This is the same defence as 0o660 + group ownership,
        // but without an install-time group-membership step.
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = std::fs::Permissions::from_mode(0o666);
            if let Err(e) = std::fs::set_permissions(sock_path, perms) {
                tracing::warn!(err = %e, "Failed to set socket permissions");
            }
        }

        tracing::info!(path = %sock_path.display(), "IPC server listening");

        let (tx, _) = broadcast::channel::<Arc<String>>(256);
        // Use persistent sled DB so events survive daemon restarts.
        let timeline_path = std::path::PathBuf::from("/var/lib/ringzero/timeline");
        if let Some(parent) = timeline_path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }

        // Disk safety: if the sled DB or disk is bloated, nuke before opening.
        // This prevents the restart-refill cycle that fills the VM.
        Self::disk_safety_check(&timeline_path);

        let timeline = Timeline::open(&timeline_path).unwrap_or_else(|e| {
            tracing::warn!(err = %e, "Failed to open persistent timeline DB, falling back to temp");
            Timeline::open_temp().expect("timeline init failed")
        });
        let server = Arc::new(Self {
            tx,
            intent_diff: Arc::new(IntentDiffEngine::new()),
            timeline: Arc::new(timeline),
            network,
            dlp,
            webhooks,
        });

        // Allowlist of UIDs permitted to talk to the daemon.
        //  - root (uid 0): production daemon + the drivers that talk to it
        //  - the daemon's own euid: lets the dev-mode user (`cargo run -p daemon`)
        //    talk to their own daemon via the dev socket path
        //  - RZ_OPERATOR_UID: production install scripts inject the local
        //    UI/CLI user here so the Tauri app can connect over the socket
        let allowed_uids: std::collections::HashSet<u32> = {
            let mut s = std::collections::HashSet::new();
            s.insert(0);
            s.insert(unsafe { nix::libc::geteuid() } as u32);
            if let Ok(v) = std::env::var("RZ_OPERATOR_UID") {
                if let Ok(uid) = v.parse::<u32>() {
                    s.insert(uid);
                }
            }
            s
        };
        if std::env::var("RZ_OPERATOR_UID").is_err() && crate::platform::is_elevated() {
            tracing::warn!(
                "RZ_OPERATOR_UID not set — only root (uid 0) can talk to the IPC socket. \
                 The local UI will be rejected. Set RZ_OPERATOR_UID in the systemd unit \
                 to the operator's UID."
            );
        }

        let srv = Arc::clone(&server);
        tokio::spawn(async move {
            loop {
                match listener.accept().await {
                    Ok((stream, _)) => {
                        // Peer-credential check (SO_PEERCRED): reject any UID
                        // not in the allowlist before the client can send a
                        // single byte. The uid is kept so request handlers can
                        // require root for privileged operations.
                        // The pid comes from the same SO_PEERCRED answer the
                        // kernel gives us, so it is not something the client
                        // can claim. It is what lets a mutating command ask
                        // whether the caller is an agent, not just whether it
                        // is root — see api/caller.rs for why root is no longer
                        // sufficient on its own.
                        let peer_uid: u32;
                        let peer_pid: Option<u32>;
                        match stream.peer_cred() {
                            Ok(cred) => {
                                peer_uid = cred.uid();
                                peer_pid = cred.pid().map(|p| p as u32);
                                if !allowed_uids.contains(&peer_uid) {
                                    tracing::warn!(
                                        peer_uid,
                                        "Rejected IPC connection from disallowed UID"
                                    );
                                    drop(stream);
                                    continue;
                                }
                            }
                            Err(e) => {
                                tracing::warn!(err = %e, "Could not read IPC peer credentials — rejecting");
                                drop(stream);
                                continue;
                            }
                        }

                        let tx = srv.tx.clone();
                        let intent_diff = Arc::clone(&srv.intent_diff);
                        let timeline = Arc::clone(&srv.timeline);
                        let network = Arc::clone(&srv.network);
                        tokio::spawn(async move {
                            if let Err(e) = handle_client(
                                stream,
                                peer_uid,
                                peer_pid,
                                tx,
                                intent_diff,
                                timeline,
                                network,
                            )
                            .await
                            {
                                tracing::warn!(err = %e, "IPC client error");
                            }
                        });
                    }
                    Err(e) => tracing::error!(err = %e, "IPC accept error"),
                }
            }
        });

        Ok(server)
    }

    /// Broadcast a message to all subscribed clients.
    ///
    /// Serialises once into a single `Arc<String>` (with the trailing
    /// newline appended) and ships the Arc through the broadcast channel.
    /// Each subscriber bumps the refcount and writes the bytes — no
    /// per-subscriber serde.
    pub fn broadcast(&self, msg: DaemonMessage) {
        match &msg {
            DaemonMessage::Event { payload } => self.webhooks.publish_event(payload),
            DaemonMessage::Threat { payload } => self.webhooks.publish_threat(payload),
            _ => {}
        }
        match serde_json::to_string(&msg) {
            Ok(mut s) => {
                s.push('\n');
                let _ = self.tx.send(Arc::new(s));
            }
            Err(e) => {
                tracing::warn!(err = %e, "broadcast: failed to serialise message");
            }
        }
    }

    /// Check disk health before opening sled. If the timeline DB is bloated,
    /// nuke just the timeline subdirectory so we start fresh.
    ///
    /// CRITICAL: only delete the timeline path itself, never its parent.
    /// The parent (`/var/lib/ringzero` or `~/Library/Application Support/RingZero`)
    /// also contains the audit log, persistent sessions store, SPIFFE CA key,
    /// and other state that must survive a timeline reset.
    fn disk_safety_check(timeline_path: &std::path::Path) {
        if !timeline_path.exists() {
            return;
        }
        let dir_size = dir_size_bytes(timeline_path);
        if dir_size > 500 * 1024 * 1024 {
            tracing::warn!(
                size_mb = dir_size / (1024 * 1024),
                path = %timeline_path.display(),
                "Timeline DB too large — nuking timeline only (audit/sessions preserved)"
            );
            let _ = std::fs::remove_dir_all(timeline_path);
            let _ = std::fs::create_dir_all(timeline_path);
        }
    }
}

fn dir_size_bytes(path: &std::path::Path) -> u64 {
    walkdir::WalkDir::new(path)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter_map(|e| e.metadata().ok())
        .filter(|m| m.is_file())
        .map(|m| m.len())
        .sum()
}

async fn handle_client(
    stream: tokio::net::UnixStream,
    peer_uid: u32,
    peer_pid: Option<u32>,
    tx: broadcast::Sender<Arc<String>>,
    intent_diff: Arc<IntentDiffEngine>,
    timeline: Arc<Timeline>,
    network: Arc<NetworkPolicy>,
) -> Result<()> {
    use tokio::io::{AsyncBufReadExt, BufReader};

    let (read_half, mut write_half) = stream.into_split();
    let mut lines = BufReader::new(read_half).lines();

    let first = match lines.next_line().await? {
        Some(l) => l,
        None => return Ok(()),
    };

    let request: ClientRequest = match serde_json::from_str(&first) {
        Ok(r) => r,
        Err(e) => {
            let err = DaemonMessage::Error {
                message: format!("Invalid request: {e}"),
            };
            send_msg(&mut write_half, &err).await?;
            return Ok(());
        }
    };

    match request {
        ClientRequest::Subscribe => {
            send_msg(&mut write_half, &DaemonMessage::Subscribed).await?;
            let mut rx = tx.subscribe();
            loop {
                match rx.recv().await {
                    Ok(line) => {
                        // `line` is already serialised + newline-terminated;
                        // just write the bytes. No per-subscriber serde.
                        use tokio::io::AsyncWriteExt;
                        if write_half.write_all(line.as_bytes()).await.is_err() {
                            break;
                        }
                    }
                    Err(broadcast::error::RecvError::Lagged(n)) => {
                        tracing::warn!(n, "Subscriber lagged, dropping events");
                    }
                    Err(broadcast::error::RecvError::Closed) => break,
                }
            }
        }
        ClientRequest::GetStatus => {
            let status = serde_json::json!({ "status": "running" });
            send_msg(&mut write_half, &DaemonMessage::Status { payload: status }).await?;
        }
        ClientRequest::GetEvents { limit } => {
            let limit = limit.unwrap_or(100).min(1000);
            let events = timeline.all_recent(3600, limit).unwrap_or_default();
            send_msg(&mut write_half, &DaemonMessage::Events { payload: events }).await?;
        }
        ClientRequest::RecordIntent { record } => {
            match serde_json::from_value::<IntentRecord>(record) {
                Ok(intent_record) => {
                    tracing::debug!(
                        session = %intent_record.session_id,
                        tool = %intent_record.tool_name,
                        intent = %intent_record.intent,
                        "MCP proxy intent recorded"
                    );
                    intent_diff.record_intent(intent_record);
                    send_msg(&mut write_half, &DaemonMessage::Ok).await?;
                }
                Err(e) => {
                    let err = DaemonMessage::Error {
                        message: format!("Invalid IntentRecord: {e}"),
                    };
                    send_msg(&mut write_half, &err).await?;
                }
            }
        }
        ClientRequest::SetNetworkMode { mode } => {
            // Same gate as SetEnforceMode. The IPC socket accepts the operator
            // uid by design, so without it an agent running as the developer
            // could flip network mode with one line of JSON.
            if let Err(message) =
                require_root_human_caller(peer_uid, peer_pid, "network mode", &mode)
            {
                send_msg(&mut write_half, &DaemonMessage::Error { message }).await?;
                return Ok(());
            }
            *network.mode.write().await = mode.clone();
            tracing::info!(mode = ?mode, "Network mode updated via IPC");
            send_msg(&mut write_half, &DaemonMessage::NetworkMode { mode }).await?;
        }
        ClientRequest::GetNetworkMode => {
            let mode = network.mode.read().await.clone();
            send_msg(&mut write_half, &DaemonMessage::NetworkMode { mode }).await?;
        }
        ClientRequest::SetEnforceMode { mode } => {
            // Turning enforcement off is an operator action, not an agent one.
            if let Err(message) =
                require_root_human_caller(peer_uid, peer_pid, "enforcement", &mode)
            {
                send_msg(&mut write_half, &DaemonMessage::Error { message }).await?;
                return Ok(());
            }
            *network.enforce.write().await = mode.clone();
            tracing::warn!(peer_uid, mode = ?mode, "Enforce mode changed via IPC by root");
            send_msg(&mut write_half, &DaemonMessage::Ok).await?;
        }
        ClientRequest::ScanSkillsAuto => {
            // Auto-discover + scan every agent skill surface (desktop "Scan Skills").
            let result = crate::scanner::skill_surface::scan_all().await;
            let payload = serde_json::to_value(&result).unwrap_or(serde_json::Value::Null);
            send_msg(&mut write_half, &DaemonMessage::SkillScan { payload }).await?;
        }
        other => {
            tracing::debug!(request = ?other, "Unhandled request type (stub)");
            send_msg(&mut write_half, &DaemonMessage::Ok).await?;
        }
    }

    Ok(())
}

/// The gate for every IPC request that changes policy. Returns the refusal
/// message to send back when the caller is not allowed.
///
/// Root on the kernel-supplied peer credential is required because the agent
/// runs as the operator uid, so the operator uid proves nothing. Root is not
/// enough on its own either: sudo caches credentials per tty, so an agent in a
/// terminal where the operator recently authenticated can reach this as root
/// with no prompt. The caller must also be shown to be a human.
fn require_root_human_caller(
    peer_uid: u32,
    peer_pid: Option<u32>,
    what: &str,
    requested: &dyn std::fmt::Debug,
) -> Result<(), String> {
    if peer_uid != 0 {
        tracing::warn!(peer_uid, requested = ?requested, "Refused IPC {what} change from non-root peer");
        return Err(format!("changing {what} requires root (try: sudo rz ...)"));
    }
    let caller = match peer_pid {
        Some(pid) => crate::api::caller::classify_pid(pid),
        None => crate::api::caller::Caller::Unresolved {
            reason: "SO_PEERCRED carried no pid".to_string(),
        },
    };
    if !caller.may_mutate() {
        tracing::warn!(
            peer_uid,
            ?peer_pid,
            requested = ?requested,
            "Refused IPC {what} change: the caller could not be shown to be a human operator"
        );
        return Err(caller.refusal_message());
    }
    Ok(())
}

async fn send_msg(
    writer: &mut tokio::net::unix::OwnedWriteHalf,
    msg: &DaemonMessage,
) -> Result<()> {
    use tokio::io::AsyncWriteExt;
    let mut line = serde_json::to_string(msg)?;
    line.push('\n');
    writer.write_all(line.as_bytes()).await?;
    Ok(())
}
