// SPDX-License-Identifier: Apache-2.0
// api/server.rs — HTTP server startup

use anyhow::Result;
use axum::Router;
use std::sync::{
    atomic::{AtomicBool, AtomicU64},
    Arc,
};
use tokio::sync::RwLock;

use super::auth::AuthState;
use super::routes::{make_router, ApiState};
use crate::analyzer::baseline::BaselineEngine;
use crate::analyzer::correlation::CorrelationEngine;
use crate::analyzer::intent_diff::IntentDiffEngine;
use crate::analyzer::observer::ObserverEngine;
use crate::analyzer::timeline::Timeline;
use crate::audit::AuditLog;
use crate::integrations::webhook::WebhookHandle;
use crate::ipc::server::IpcServer;
use crate::policy::acl::AclEngine;
use crate::policy::intent_policy::IntentAwarePolicy;
use crate::policy::network::NetworkPolicy;
use crate::scanner::verified_registry::VerifiedRegistry;
use crate::secrets::dlp::DlpEngine;
use crate::secrets::rotation::RotationStore;
use crate::session::jwt::JwtIssuer;
use crate::session::SessionStore;
use crate::skill_correlation::SkillCorrelationEngine;

/// Spawn the HTTP management API on `addr` (default 127.0.0.1:7700).
pub async fn start(
    timeline: Arc<Timeline>,
    acl: Arc<RwLock<AclEngine>>,
    ipc: Arc<IpcServer>,
    intent_diff: Arc<IntentDiffEngine>,
    sessions: Arc<SessionStore>,
    audit: Arc<AuditLog>,
    network: Arc<NetworkPolicy>,
    jwt_issuer: Arc<JwtIssuer>,
    intent_policy: Arc<IntentAwarePolicy>,
    rotation_store: Arc<RotationStore>,
    verified_registry: Arc<VerifiedRegistry>,
    baseline_engine: Arc<BaselineEngine>,
    observer_engine: Arc<ObserverEngine>,
    correlation_engine: Arc<CorrelationEngine>,
    dlp: Arc<DlpEngine>,
    ebpf_active: Arc<AtomicBool>,
    events_total: Arc<AtomicU64>,
    threats_blocked: Arc<AtomicU64>,
    skill_correlation: Arc<SkillCorrelationEngine>,
    ebpf_block_file: Option<Arc<dyn Fn(String, bool) + Send + Sync>>,
    ebpf_set_allowed_dir: Option<Arc<dyn Fn(String) + Send + Sync>>,
    ebpf_block_dir: Option<Arc<dyn Fn(String) + Send + Sync>>,
    webhooks: Arc<WebhookHandle>,
    review: Arc<crate::review::ReviewQueue>,
    checks_cfg: crate::config::ChecksSection,
    checks_provider: Option<Arc<crate::checks_provider::ScoringProvider>>,
    addr: &str,
) -> Result<()> {
    let auth = AuthState::new();
    // Fill the auth slot before the listener accepts any connection, so no
    // local process can race /auth/register to seize the API. No-op if a token
    // is already provisioned (existing deployments keep theirs).
    auth.ensure_self_token().await;
    let state = ApiState {
        timeline,
        acl,
        ipc,
        intent_diff,
        sessions,
        audit,
        network,
        jwt_issuer,
        intent_policy,
        rotation_store,
        verified_registry,
        baseline_engine,
        observer_engine,
        correlation_engine,
        dlp,
        skill_correlation,
        ebpf_active,
        events_total,
        threats_blocked,
        auth,
        ebpf_block_file,
        ebpf_set_allowed_dir,
        ebpf_block_dir,
        webhooks,
        review,
        checks_cfg,
        checks_provider,
    };
    let app: Router = make_router(state);

    let listener = tokio::net::TcpListener::bind(addr).await?;
    tracing::info!(addr, "HTTP management API listening");

    // with_connect_info so the auth middleware can see which local process is
    // calling. Without it, every mutating call would resolve as an unidentified
    // caller and be refused.
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .await?;
    Ok(())
}
