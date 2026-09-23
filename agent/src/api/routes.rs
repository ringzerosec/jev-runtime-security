// SPDX-License-Identifier: Apache-2.0
// api/routes.rs — Axum route handlers for the management API

use axum::{
    extract::{Path, Query, State},
    http::{HeaderMap, HeaderValue, Method, StatusCode},
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use std::sync::{
    atomic::{AtomicBool, AtomicU64, Ordering},
    Arc,
};
use tokio::sync::RwLock;
use tower_http::cors::{Any, CorsLayer};
use tower_http::services::{ServeDir, ServeFile};

use super::auth::AuthState;
use super::identity;
use crate::analyzer::baseline::BaselineEngine;
use crate::analyzer::correlation::CorrelationEngine;
use crate::analyzer::intent_diff::IntentDiffEngine;
use crate::analyzer::observer::ObserverEngine;
use crate::analyzer::timeline::Timeline;
use crate::audit::{AuditEntryType, AuditLog};
use crate::common::event::{EventKind, SecurityEvent};
use crate::common::policy::{EnforceMode, NetworkMode};
use crate::ipc::server::IpcServer;
use crate::policy::acl::AclEngine;
use crate::policy::intent_policy::{IntentAwarePolicy, IntentRule};
use crate::policy::network::NetworkPolicy;
use crate::scanner::verified_registry::VerifiedRegistry;
use crate::secrets::rotation::{RotationStatus, RotationStore};
use crate::session::jwt::JwtIssuer;
use crate::session::SessionStore;

// ── Shared state ─────────────────────────────────────────────────────────────

#[derive(Clone)]
pub struct ApiState {
    pub timeline: Arc<Timeline>,
    pub acl: Arc<RwLock<AclEngine>>,
    pub ipc: Arc<IpcServer>,
    pub intent_diff: Arc<IntentDiffEngine>,
    pub sessions: Arc<SessionStore>,
    pub audit: Arc<AuditLog>,
    pub network: Arc<NetworkPolicy>,
    pub jwt_issuer: Arc<JwtIssuer>,
    pub intent_policy: Arc<IntentAwarePolicy>,
    pub rotation_store: Arc<RotationStore>,
    pub verified_registry: Arc<VerifiedRegistry>,
    pub baseline_engine: Arc<BaselineEngine>,
    pub observer_engine: Arc<ObserverEngine>,
    pub correlation_engine: Arc<CorrelationEngine>,
    pub dlp: Arc<crate::secrets::dlp::DlpEngine>,
    pub skill_correlation: Arc<crate::skill_correlation::SkillCorrelationEngine>,
    pub ebpf_active: Arc<AtomicBool>,
    /// Monotonic counters for fast status endpoint (avoids full timeline scan).
    pub events_total: Arc<AtomicU64>,
    pub threats_blocked: Arc<AtomicU64>,
    /// Bearer token auth state.
    pub auth: AuthState,

    /// Push a file block/unblock to the kernel eBPF map (platform-erased so the
    /// cross-platform API never references the Linux-only EbpfCommand). Set on
    /// Linux; None elsewhere. (path, block) — block=true adds, false removes.
    /// Makes API/mesh policy changes ENFORCE at L0, not just the advisory ACL.
    pub ebpf_block_file: Option<Arc<dyn Fn(String, bool) + Send + Sync>>,
    /// Push an allowed-directory to the kernel eBPF map for directory restriction.
    /// (path) — sets or clears (empty string) the allowed directory.
    pub ebpf_set_allowed_dir: Option<Arc<dyn Fn(String) + Send + Sync>>,
    /// Push a blocked-directory to the kernel eBPF map. All files inside the
    /// directory are blocked for agent processes. Empty string clears all.
    pub ebpf_block_dir: Option<Arc<dyn Fn(String) + Send + Sync>>,
    /// Detection webhooks (stats only — the config lives in daemon.toml, root-owned).
    pub webhooks: Arc<crate::integrations::webhook::WebhookHandle>,
    pub review: Arc<crate::review::ReviewQueue>,
    pub checks_cfg: crate::config::ChecksSection,
    pub checks_provider: Option<Arc<crate::checks_provider::ScoringProvider>>,
}

// ── Router ───────────────────────────────────────────────────────────────────

pub fn make_router(state: ApiState) -> Router {
    // CORS (`Any` would let any web page call the local API).
    // NOTE: CORS is defence-in-depth only — the bearer token is the real gate, and
    // CORS does nothing against a local NON-browser caller (curl/agent sets any
    // Origin). The Tauri app reaches the daemon over the Unix socket / `invoke`,
    // not webview fetch, so production needs NO daemon CORS origin; `tauri://`
    // entries were also non-unique (shared by every Tauri app) and are dropped.
    // The only real CORS consumer is the local dev browser UI on :1420.
    let cors = CorsLayer::new()
        .allow_origin([
            HeaderValue::from_static("http://localhost:1420"),
            HeaderValue::from_static("http://127.0.0.1:1420"),
        ])
        .allow_methods([Method::GET, Method::POST, Method::DELETE, Method::OPTIONS])
        .allow_headers(Any);

    // Inject AuthState into request extensions for the middleware
    let auth_state = state.auth.clone();
    // The mutation guard rides along so the auth middleware can record a
    // refused policy change in the audit chain and the review queue without
    // the whole ApiState being threaded through it.
    let guard = super::caller::MutationGuard {
        audit: state.audit.clone(),
        review: state.review.clone(),
    };
    let auth_layer = axum::middleware::from_fn(
        move |headers, mut request: axum::extract::Request, next: axum::middleware::Next| {
            let auth = auth_state.clone();
            let guard = guard.clone();
            async move {
                request.extensions_mut().insert(auth);
                request.extensions_mut().insert(guard);
                super::auth::auth_middleware(headers, request, next).await
            }
        },
    );

    let router = Router::new()
        // Core
        .route("/api/v1/health", get(health))
        .route("/api/v1/health/components", get(health_components))
        .route("/api/v1/status", get(get_status))
        .route("/api/v1/webhooks/stats", get(get_webhook_stats))
        .route("/api/v1/events", get(get_events))
        .route("/api/v1/threats", get(get_threats))
        .route("/api/v1/policy", get(get_policy).post(update_policy))
        .route("/api/v1/intent-diffs", get(get_intent_diffs))
        // Causal traces (intent → action correlation)
        .route("/api/v1/traces", get(get_traces))
        .route("/api/v1/traces/:trace_id", get(get_trace_by_id))
        // Network policy
        .route(
            "/api/v1/network",
            get(get_network_policy).post(set_network_policy),
        )
        // NHI inventory
        .route("/api/v1/nhi", get(get_nhi_inventory))
        // Shadow AI
        .route("/api/v1/shadow-ai", get(get_shadow_ai))
        // Session events (per-session kernel timeline)
        .route(
            "/api/v1/sessions/:id/events",
            get(get_session_events).post(post_session_event),
        )
        // Policy bundle
        .route("/api/v1/policy/bundle", get(export_policy_bundle))
        // Sessions + AAM
        .route("/api/v1/sessions", get(list_sessions).post(create_session))
        .route(
            "/api/v1/sessions/:id",
            get(get_session).delete(terminate_session),
        )
        .route("/api/v1/sessions/:id/approve", post(approve_session))
        .route("/api/v1/sessions/:id/escalate", post(escalate_session))
        .route("/api/v1/sessions/:id/jit", post(provision_jit))
        .route("/api/v1/sessions/:id/jit/:jit_id/revoke", post(revoke_jit))
        // Escalation queue (admin view)
        .route("/api/v1/escalations", get(list_escalations))
        .route(
            "/api/v1/escalations/:esc_id/resolve",
            post(resolve_escalation),
        )
        // Audit log
        .route("/api/v1/audit", get(get_audit))
        .route("/api/v1/audit/verify", get(verify_audit))
        .route("/api/v1/audit/export", get(export_audit))
        // Session JWT
        .route("/api/v1/sessions/:id/jwt", get(get_session_jwt))
        // Intent-aware policy
        .route(
            "/api/v1/intent-policy",
            get(get_intent_policy).post(update_intent_policy),
        )
        .route(
            "/api/v1/intent-policy/classify",
            post(classify_intent_request),
        )
        // Compliance reports
        .route("/api/v1/compliance/soc2", get(compliance_soc2))
        .route("/api/v1/compliance/nist", get(compliance_nist))
        .route("/api/v1/compliance/iso27001", get(compliance_iso27001))
        .route("/api/v1/compliance/summary", get(compliance_summary))
        // Prompt injection scan
        .route("/api/v1/injection-scan", post(injection_scan))
        // Secret rotation
        .route("/api/v1/secrets", get(list_secrets))
        .route("/api/v1/secrets/summary", get(secrets_summary))
        .route("/api/v1/secrets/overdue", get(secrets_overdue))
        .route("/api/v1/secrets/:id/trigger", post(trigger_rotation))
        .route("/api/v1/secrets/:id/confirm", post(confirm_rotation))
        .route("/api/v1/secrets/:id/acknowledge", post(acknowledge_secret))
        .route("/api/v1/secrets/:id/revoke", post(revoke_secret))
        // ML behavioral baseline
        .route("/api/v1/baseline", get(list_baselines))
        .route("/api/v1/baseline/:agent", get(get_baseline))
        // DLP config (PII redaction toggles)
        .route(
            "/api/v1/dlp/config",
            get(get_dlp_config).post(update_dlp_config),
        )
        .route("/api/v1/dlp/redact", post(test_dlp_redact))
        // TLS proxy status (consumer DLP)
        // Skill scanner — on-demand full scan
        .route("/api/v1/skill-scan", post(scan_skills))
        // Skill scanner — auto-enumerate every agent's skill surface
        .route("/api/v1/skill-scan/auto", post(scan_skills_auto))
        .route(
            "/api/v1/scan/baseline",
            get(get_scan_baseline)
                .post(accept_scan_baseline)
                .delete(clear_scan_baseline),
        )
        // Supply chain / verified registry
        .route("/api/v1/supply-chain", get(list_supply_chain))
        .route("/api/v1/supply-chain/summary", get(supply_chain_summary))
        .route("/api/v1/supply-chain/:id/allow", post(allow_package))
        .route(
            "/api/v1/supply-chain/:id/quarantine",
            post(quarantine_package),
        )
        // Auto-update status
        // Crash reporting
        // Cloud sync status
        // Health detailed (expansion #1: unified health dashboard)
        .route("/api/v1/health/detailed", get(health_detailed))
        // Auth
        .route("/api/v1/auth/register", post(register_auth_token))
        .route("/api/v1/auth/rotate", post(rotate_auth_token))
        .route("/api/v1/auth/status", get(auth_status))
        .route("/api/v1/auth/scope", get(auth_scope))
        .route("/api/v1/checks/status", get(checks_status))
        .route("/api/v1/checks/verify-key", post(verify_checks_key))
        // Policy quick-actions (expansion #2: persist to quick-rules.toml)
        .route("/api/v1/policy/quick-action", post(quick_action))
        .route("/api/v1/policy/quick-rules", get(list_quick_rules))
        // Threat intel feed
        // LLM session replay (expansion #5)
        .route("/api/v1/sessions/:id/llm-replay", get(get_llm_replay))
        // Observer baseline policies
        .route(
            "/api/v1/sessions/:id/policy",
            get(get_session_policy).post(update_session_policy),
        )
        .route("/api/v1/observer/profiles", get(list_observer_profiles))
        .route("/api/v1/observer/violations", get(get_observer_violations))
        // Agent Identity API (Phase 5)
        .route("/api/v1/agent-identity", get(list_agent_identities))
        .route(
            "/api/v1/agent-identity/:session_id",
            get(get_agent_identity),
        )
        // Attack pattern correlation (Phase 6)
        .route("/api/v1/attack-chains", get(get_attack_chains))
        .route(
            "/api/v1/attack-chains/:session_id",
            get(get_session_attack_chains),
        )
        .route("/api/v1/attack-patterns", get(list_attack_patterns))
        // Enforcement engine (per-category policy)
        .route(
            "/api/v1/enforcement",
            get(get_enforcement_config).post(update_enforcement_config),
        )
        .route("/api/v1/hook-event", post(receive_hook_event))
        .route("/api/v1/review", get(list_review_queue))
        .route("/api/v1/review/stats", get(review_stats))
        .route("/api/v1/review/:id/label", post(label_review_item))
        // File access rules (E2E kernel enforcement)
        .route(
            "/api/v1/file-access-rules",
            get(get_file_access_rules).post(update_file_access_rules),
        )
        // Skill↔Runtime correlation engine (Phase 3)
        .route("/api/v1/correlated-threats", get(get_correlated_threats))
        .layer(auth_layer)
        .layer(cors)
        .with_state(state);

    // Serve embedded web UI from /usr/share/ringzero/ui/ (if present)
    let ui_dir = std::path::PathBuf::from("/usr/share/ringzero/ui");
    if ui_dir.exists() {
        let index = ui_dir.join("index.html");
        tracing::info!(path = %ui_dir.display(), "Web UI enabled at http://127.0.0.1:7700/");
        // The browser-served copy has no bearer token and is only reachable on
        // loopback; still, give it the same CSP as the desktop app and forbid
        // framing so a rebinding page cannot embed it.
        let ui = tower::ServiceBuilder::new()
            .layer(tower_http::set_header::SetResponseHeaderLayer::overriding(
                axum::http::header::CONTENT_SECURITY_POLICY,
                HeaderValue::from_static(
                    "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; \
                     img-src 'self' data: blob:; font-src 'self' data:; connect-src 'self'; \
                     object-src 'none'; base-uri 'self'; form-action 'none'; frame-ancestors 'none'",
                ),
            ))
            .layer(tower_http::set_header::SetResponseHeaderLayer::overriding(
                axum::http::header::X_FRAME_OPTIONS,
                HeaderValue::from_static("DENY"),
            ))
            .layer(tower_http::set_header::SetResponseHeaderLayer::overriding(
                axum::http::header::X_CONTENT_TYPE_OPTIONS,
                HeaderValue::from_static("nosniff"),
            ))
            .service(ServeDir::new(&ui_dir).not_found_service(ServeFile::new(index)));
        return router.fallback_service(ui);
    }

    router
}

// ── Query params ─────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct EventsQuery {
    #[serde(default = "default_limit")]
    pub limit: usize,
    /// Optional comma-separated event kind filter (e.g. "llm_request,llm_response,llm_tool_call")
    pub kind: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct AuditQuery {
    #[serde(default = "default_audit_limit")]
    pub limit: usize,
}

fn default_limit() -> usize {
    100
}
fn default_audit_limit() -> usize {
    200
}

// ── Response helpers ──────────────────────────────────────────────────────────

#[derive(Serialize)]
struct OpResponse {
    ok: bool,
    message: String,
}

fn ok(msg: impl Into<String>) -> Json<OpResponse> {
    Json(OpResponse {
        ok: true,
        message: msg.into(),
    })
}
fn err_resp(code: StatusCode, msg: impl Into<String>) -> impl IntoResponse {
    (
        code,
        Json(OpResponse {
            ok: false,
            message: msg.into(),
        }),
    )
}

// ── Core handlers ─────────────────────────────────────────────────────────────

async fn health(State(state): State<ApiState>) -> Json<serde_json::Value> {
    let ebpf = state.ebpf_active.load(Ordering::Relaxed);
    Json(serde_json::json!({
        "ok": true,
        "version": env!("CARGO_PKG_VERSION"),
        "ebpf_active": ebpf,
        "kernel_monitoring": if ebpf { "active" } else { "inactive" },
    }))
}

/// GET /api/v1/health/components — per-subsystem health so the UI can show a
/// global WARNING/CRITICAL state when a load-bearing piece (kernel enforcement,
/// TLS inspection, the on-device AI engine) stops running. The engine entry also
/// reports endpoint-ownership (squatting) anomalies. See `crate::health`.
async fn health_components(State(state): State<ApiState>) -> Json<serde_json::Value> {
    let ebpf = state.ebpf_active.load(Ordering::Relaxed);
    Json(crate::health::components(ebpf))
}

async fn get_status(State(state): State<ApiState>) -> impl IntoResponse {
    let connected = state.ipc.tx.receiver_count() > 0;
    // Use atomic counters instead of scanning the full timeline on every poll
    let threats_blocked = state.threats_blocked.load(Ordering::Relaxed);
    let events_total = state.events_total.load(Ordering::Relaxed);
    let active_sessions = state.sessions.list_active().len();
    let waiting = 0; // WaitingApproval removed — auto-containment replaces it

    let ebpf = state.ebpf_active.load(Ordering::Relaxed);
    let acl = state.acl.read().await;
    let enforce_mode = acl.default_deny();
    drop(acl);

    let db_size_bytes = state.timeline.db_size_bytes();

    Json(serde_json::json!({
        "connected":        connected,
        "version":          env!("CARGO_PKG_VERSION"),
        "threats_blocked":  threats_blocked,
        "events_total":     events_total,
        "active_sessions":  active_sessions,
        "waiting_approval": waiting,
        "ebpf_active":      ebpf,
        "kernel_monitoring": if ebpf { "active" } else { "inactive" },
        "enforce_mode":     enforce_mode,
        "db_size_bytes":    db_size_bytes,
    }))
}

// ── DLP config (PII redaction) ───────────────────────────────────────────────

async fn get_dlp_config(State(state): State<ApiState>) -> Json<serde_json::Value> {
    let pii = state.dlp.get_pii_config();
    let action_str = match state.dlp.get_pii_action() {
        crate::config::PiiAction::Block => "block",
        crate::config::PiiAction::Redact => "redact",
    };
    Json(serde_json::json!({
        "pii": {
            "ssn":         pii.ssn,
            "credit_card": pii.credit_card,
            "email":       pii.email,
            "phone":       pii.phone,
            "ip_address":  pii.ip_address,
        },
        "pii_action": action_str,
    }))
}

async fn update_dlp_config(
    State(state): State<ApiState>,
    Json(body): Json<serde_json::Value>,
) -> Json<serde_json::Value> {
    // Handle toggle: { "action": "toggle_pii", "pii_type": "email", "enabled": false }
    if let Some(action) = body.get("action").and_then(|v| v.as_str()) {
        match action {
            "toggle_pii" => {
                let pii_type = body.get("pii_type").and_then(|v| v.as_str()).unwrap_or("");
                let enabled = body
                    .get("enabled")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(true);
                state.dlp.set_pii(pii_type, enabled);
            }
            _ => {}
        }
    }

    // Also accept bulk update: { "pii": { "ssn": true, "email": false, ... } }
    if let Some(pii) = body.get("pii") {
        if let Some(v) = pii.get("ssn").and_then(|v| v.as_bool()) {
            state.dlp.set_pii("ssn", v);
        }
        if let Some(v) = pii.get("credit_card").and_then(|v| v.as_bool()) {
            state.dlp.set_pii("credit_card", v);
        }
        if let Some(v) = pii.get("email").and_then(|v| v.as_bool()) {
            state.dlp.set_pii("email", v);
        }
        if let Some(v) = pii.get("phone").and_then(|v| v.as_bool()) {
            state.dlp.set_pii("phone", v);
        }
        if let Some(v) = pii.get("ip_address").and_then(|v| v.as_bool()) {
            state.dlp.set_pii("ip_address", v);
        }
    }

    // Handle pii_action: { "pii_action": "block" } or { "pii_action": "redact" }
    if let Some(action_str) = body.get("pii_action").and_then(|v| v.as_str()) {
        let action = match action_str {
            "redact" => crate::config::PiiAction::Redact,
            _ => crate::config::PiiAction::Block,
        };
        state.dlp.set_pii_action(&action);
        tracing::info!(pii_action = action_str, "PII action mode updated via API");
    }

    let pii = state.dlp.get_pii_config();
    let action_str = match state.dlp.get_pii_action() {
        crate::config::PiiAction::Block => "block",
        crate::config::PiiAction::Redact => "redact",
    };
    Json(serde_json::json!({ "ok": true, "pii": pii, "pii_action": action_str }))
}

async fn test_dlp_redact(
    State(state): State<ApiState>,
    Json(body): Json<serde_json::Value>,
) -> Json<serde_json::Value> {
    let text = body.get("text").and_then(|v| v.as_str()).unwrap_or("");
    let result = state.dlp.redact(text);
    Json(serde_json::json!({
        "original": text,
        "redacted": result.text,
        "count":    result.count,
        "details":  result.details,
    }))
}

async fn get_events(
    State(state): State<ApiState>,
    Query(p): Query<EventsQuery>,
) -> impl IntoResponse {
    // Fetch more than limit when filtering, to ensure enough results after filtering
    let fetch_limit = if p.kind.is_some() {
        p.limit.min(1000) * 10
    } else {
        p.limit.min(1000)
    };
    match state.timeline.all_recent(86400, fetch_limit) {
        Ok(events) => {
            // Filter noise targets (cgroup, proc, .so files) from file_open events
            let events: Vec<_> = events
                .into_iter()
                .filter(|e| {
                    if !matches!(e.kind, crate::common::event::EventKind::FileOpen) {
                        return true;
                    }
                    !crate::analyzer::timeline::Timeline::is_noise_target(&e.target)
                })
                .collect();

            let filtered = if let Some(ref kinds) = p.kind {
                let kind_set: Vec<String> =
                    kinds.split(',').map(|s| s.trim().to_lowercase()).collect();
                events
                    .into_iter()
                    .filter(|e| {
                        // Serialize kind to snake_case (matching serde rename_all)
                        let kind_str = serde_json::to_string(&e.kind).unwrap_or_default();
                        let kind_str = kind_str.trim_matches('"').to_lowercase();
                        kind_set.iter().any(|k| kind_str == *k)
                    })
                    .take(p.limit.min(1000))
                    .collect()
            } else {
                events
            };
            Json(filtered).into_response()
        }
        Err(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error":"timeline unavailable"})),
        )
            .into_response(),
    }
}

async fn get_threats(State(state): State<ApiState>) -> impl IntoResponse {
    match state.timeline.all_recent(86400, usize::MAX) {
        Ok(events) => {
            let threats: Vec<_> = events
                .into_iter()
                .filter(|e| !e.allowed)
                .filter(|e| !is_benign_system_flow(e))
                .collect();
            Json(threats).into_response()
        }
        Err(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error":"timeline unavailable"})),
        )
            .into_response(),
    }
}

/// Known-benign OS auth flows that touch sensitive files but are NEVER threats.
/// The PAM password helper (`unix_chkpwd`) reads `/etc/shadow` on every
/// sudo/login; surfacing that floods the threat feed (§6.3 noise — thousands/hour
/// observed while dogfooding) and buries the real threats. These reach the daemon
/// only because an agent triggered `sudo`, but the helper is OS machinery, not an
/// agent action — so they're kept out of the threat feed (still in raw events).
fn is_benign_system_flow(e: &SecurityEvent) -> bool {
    let proc = e.process.rsplit('/').next().unwrap_or(e.process.as_str());
    let touches_auth = e.target.contains("shadow")
        || e.target.contains("gshadow")
        || e.target.ends_with("passwd")
        || e.target.contains("/passwd");
    touches_auth
        && matches!(
            proc,
            "unix_chkpwd"
                | "unix_update"
                | "sudo"
                | "su"
                | "login"
                | "sshd"
                | "polkit-agent-helper-1"
                | "systemd-logind"
                | "gdm-session-worker"
        )
}

async fn get_policy(State(state): State<ApiState>) -> impl IntoResponse {
    let acl = state.acl.read().await;
    // Collect deny lists across all skill policies for the UI
    let mut blocked_files = Vec::new();
    let mut blocked_domains = Vec::new();
    let mut blocked_processes = Vec::new();
    for p in acl.policies().values() {
        for f in &p.files.deny {
            if !blocked_files.contains(f) {
                blocked_files.push(f.clone());
            }
        }
        for d in &p.network.deny {
            if !blocked_domains.contains(d) {
                blocked_domains.push(d.clone());
            }
        }
        for pr in &p.process.deny {
            if !blocked_processes.contains(pr) {
                blocked_processes.push(pr.clone());
            }
        }
    }
    Json(serde_json::json!({
        "enforce_mode": acl.default_deny(),
        "blocked_files": blocked_files,
        "blocked_domains": blocked_domains,
        "blocked_processes": blocked_processes,
        "skills": serde_json::to_value(acl.policies()).unwrap_or_default(),
    }))
    .into_response()
}

#[derive(Deserialize)]
pub struct PolicyUpdateRequest {
    pub action: String,
    pub value: serde_json::Value,
}

async fn update_policy(
    State(state): State<ApiState>,
    Json(req): Json<PolicyUpdateRequest>,
) -> impl IntoResponse {
    let val_str = req.value.as_str().unwrap_or("").to_string();
    let val_bool = req.value.as_bool().unwrap_or(false);

    match req.action.as_str() {
        "set_enforce" => {
            state.acl.write().await.set_default_deny(val_bool);
            let _ = state.audit.append(
                AuditEntryType::PolicyChange,
                serde_json::json!({"action":"set_enforce","value":val_bool}),
            );
            ok(format!("Enforce mode set to {val_bool}")).into_response()
        }
        "block_file" => {
            // Refuse to block basenames the agent needs to RUN (shells, loader,
            // core libs) or bare critical dirs — a basename-keyed block of "bash"
            // or "libc.so.6" would brick every monitored agent. This guard lived
            // only in the SLM path; it must gate the API/mesh path too (a signed
            // "tighten" brick is otherwise auto-applied).
            if let Some(reason) = crate::analyzer::rule_compiler::dangerous_path(&val_str) {
                return err_resp(
                    StatusCode::BAD_REQUEST,
                    format!("refused to block '{}': {}", val_str, reason),
                )
                .into_response();
            }
            state.acl.write().await.block_file(&val_str);
            // Enforce at L0: push the block to the kernel eBPF map (not just the ACL).
            if let Some(f) = &state.ebpf_block_file {
                f(val_str.clone(), true);
            }
            let _ = state.audit.append(
                AuditEntryType::PolicyChange,
                serde_json::json!({"action":"block_file","value":&val_str}),
            );
            ok(format!("File '{}' blocked", val_str)).into_response()
        }
        "unblock_file" => {
            state.acl.write().await.unblock_file(&val_str);
            if let Some(f) = &state.ebpf_block_file {
                f(val_str.clone(), false);
            }
            let _ = state.audit.append(
                AuditEntryType::PolicyChange,
                serde_json::json!({"action":"unblock_file","value":&val_str}),
            );
            ok(format!("File '{}' unblocked", val_str)).into_response()
        }
        "block_domain" => {
            state.acl.write().await.block_domain(&val_str);
            let _ = state.audit.append(
                AuditEntryType::PolicyChange,
                serde_json::json!({"action":"block_domain","value":&val_str}),
            );
            ok(format!("Domain '{}' blocked", val_str)).into_response()
        }
        "unblock_domain" => {
            state.acl.write().await.unblock_domain(&val_str);
            let _ = state.audit.append(
                AuditEntryType::PolicyChange,
                serde_json::json!({"action":"unblock_domain","value":&val_str}),
            );
            ok(format!("Domain '{}' unblocked", val_str)).into_response()
        }
        "block_process" => {
            state.acl.write().await.block_process(&val_str);
            let _ = state.audit.append(
                AuditEntryType::PolicyChange,
                serde_json::json!({"action":"block_process","value":&val_str}),
            );
            ok(format!("Process '{}' blocked", val_str)).into_response()
        }
        "unblock_process" => {
            state.acl.write().await.unblock_process(&val_str);
            let _ = state.audit.append(
                AuditEntryType::PolicyChange,
                serde_json::json!({"action":"unblock_process","value":&val_str}),
            );
            ok(format!("Process '{}' unblocked", val_str)).into_response()
        }
        // Feature toggles that are accepted for compatibility but currently no-op
        "set_model_armor" | "set_gliner" | "set_parental_controls" => {
            let _ = state.audit.append(
                AuditEntryType::PolicyChange,
                serde_json::json!({"action":&req.action,"value":val_bool}),
            );
            ok(format!("{} set to {val_bool}", req.action)).into_response()
        }
        other => {
            err_resp(StatusCode::BAD_REQUEST, format!("Unknown action: {other}")).into_response()
        }
    }
}

async fn get_intent_diffs(State(state): State<ApiState>) -> impl IntoResponse {
    Json(state.intent_diff.diffs()).into_response()
}

async fn get_traces(State(state): State<ApiState>) -> impl IntoResponse {
    Json(state.intent_diff.traces()).into_response()
}

async fn get_trace_by_id(
    State(state): State<ApiState>,
    Path(trace_id): Path<String>,
) -> impl IntoResponse {
    match state.intent_diff.get_trace(&trace_id) {
        Some(trace) => Json(serde_json::json!(trace)).into_response(),
        None => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "Trace not found"})),
        )
            .into_response(),
    }
}

// ── Session handlers ──────────────────────────────────────────────────────────

#[derive(Deserialize)]
struct CreateSessionRequest {
    agent_type: Option<String>,
    actor: String,
    declared_scope: Option<Vec<String>>,
    ttl_secs: Option<u64>,
}

async fn list_sessions(State(state): State<ApiState>) -> impl IntoResponse {
    state.sessions.expire_stale();
    Json(state.sessions.list()).into_response()
}

async fn create_session(
    State(state): State<ApiState>,
    Json(req): Json<CreateSessionRequest>,
) -> impl IntoResponse {
    use crate::session::store::{AgentType, Session};
    use uuid::Uuid;

    let agent_type = match req.agent_type.as_deref().unwrap_or("custom") {
        "claude" => AgentType::Claude,
        "chatgpt" => AgentType::ChatGpt,
        "gemini" => AgentType::Gemini,
        "deepseek" => AgentType::DeepSeek,
        "cursor" => AgentType::Cursor,
        "copilot" => AgentType::Copilot,
        "codex" => AgentType::Codex,
        "devin" => AgentType::Devin,
        // Platform driver sessions (e.g. the eBPF loader). Distinct from "custom" so the
        // frontend gets a plain-string agent_type instead of {"custom":"…"}.
        "driver" => AgentType::Driver,
        other => AgentType::Custom(other.to_string()),
    };

    let id = Uuid::new_v4().to_string();
    let agent_label = req.agent_type.as_deref().unwrap_or("custom").to_lowercase();
    let declared_scope = req.declared_scope.clone().unwrap_or_default();
    let mut session = Session::new(
        &id,
        agent_type,
        req.actor,
        req.declared_scope.unwrap_or_default(),
        req.ttl_secs,
    );
    session.state = crate::session::store::SessionState::Active;
    state.sessions.create(session.clone());

    // Assign observer baseline policy based on agent type
    state
        .observer_engine
        .assign_policy(&id, &agent_label, declared_scope)
        .await;

    let _ = state.audit.append(
        AuditEntryType::AccessGranted,
        serde_json::json!({"session_id":&id,"actor":&session.actor}),
    );

    (
        StatusCode::CREATED,
        Json(serde_json::json!({"id":&id,"state":"ACTIVE"})),
    )
        .into_response()
}

async fn get_session(State(state): State<ApiState>, Path(id): Path<String>) -> impl IntoResponse {
    state.sessions.expire_stale();
    match state.sessions.get(&id) {
        Some(s) => Json(s).into_response(),
        None => err_resp(StatusCode::NOT_FOUND, "session not found").into_response(),
    }
}

async fn approve_session(
    State(state): State<ApiState>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    if state.sessions.approve(&id) {
        let _ = state.audit.append(
            AuditEntryType::EscalationResolved,
            serde_json::json!({"session_id":&id,"approved":true}),
        );
        ok("Session approved").into_response()
    } else {
        err_resp(StatusCode::BAD_REQUEST, "Not found or not waiting").into_response()
    }
}

/// Validate a PID before sending signals. Rejects system PIDs and checks
/// that the process name still matches expectations (guards against PID recycling).
fn is_safe_to_kill(pid: u32, _expected_process: Option<&str>) -> bool {
    // Never kill system processes
    if pid < 100 {
        tracing::warn!(pid, "Refusing to kill system PID < 100");
        return false;
    }
    // Never kill the daemon itself
    if pid == std::process::id() {
        tracing::warn!(pid, "Refusing to kill self (daemon PID)");
        return false;
    }
    // Verify the process is an AI agent child — not a system service.
    // The actor name ("claude") may differ from the binary name ("node"),
    // so we check against known agent runtime binaries too.
    {
        let agent_runtimes = ["node", "python3", "python", "ruby", "deno", "bun"];
        if let Ok(comm) = std::fs::read_to_string(format!("/proc/{}/comm", pid)) {
            let actual = comm.trim();
            if actual.is_empty() {
                return true; // Process may have already exited
            }
            // A cmdline-detected agent is safe to kill even when its comm isn't the
            // agent name. Gemini CLI runs as node/MainThread, so the comm/runtime
            // checks below rejected it → the kill was filtered out and the session
            // stayed "live" after Terminate. This recognizes it by argv.
            if crate::common::agent_detect::detect_agent_for_pid(pid, actual).is_some() {
                return true;
            }
            // Allow if process matches expected name OR is a known agent runtime
            if let Some(expected) = _expected_process {
                if actual == expected || agent_runtimes.contains(&actual) {
                    return true;
                }
                // Check if the process is a child of the session (heuristic)
                if let Ok(status) = std::fs::read_to_string(format!("/proc/{}/status", pid)) {
                    // If it's a child process spawned by the session, allow
                    for line in status.lines() {
                        if line.starts_with("Name:") {
                            let name = line.split_whitespace().nth(1).unwrap_or("");
                            if agent_runtimes.contains(&name) {
                                return true;
                            }
                        }
                    }
                }
                tracing::warn!(
                    pid,
                    actual_process = actual,
                    expected = expected,
                    "PID may have been recycled — refusing to kill"
                );
                return false;
            }
        }
        // If /proc/{pid}/comm doesn't exist, process already exited — skip
    }
    true
}

/// Send SIGTERM to a process tree, then SIGKILL after 2 seconds.
/// Uses nix::libc::kill directly (we're root) instead of spawning subprocesses.
fn kill_process_tree(pids: &[u32], session_id: &str, expected_process: Option<&str>) {
    tracing::info!(
        session = %session_id,
        total_pids = pids.len(),
        expected = ?expected_process,
        pids = ?pids,
        "Terminate: attempting to kill process tree"
    );

    let safe_pids: Vec<u32> = pids
        .iter()
        .filter(|&&pid| is_safe_to_kill(pid, expected_process))
        .copied()
        .collect();

    if safe_pids.is_empty() && !pids.is_empty() {
        tracing::warn!(
            session = %session_id,
            "Terminate: all PIDs filtered by safety check — nothing to kill"
        );
    }

    for &pid in &safe_pids {
        // Kill the PID directly, NOT the process group.
        // Process group kill is dangerous — it can kill the user's entire
        // terminal/SSH session if the agent was launched from a shell.
        // Instead, kill the PID + its children via pkill -P.
        unsafe {
            nix::libc::kill(pid as nix::libc::pid_t, nix::libc::SIGTERM);
        }
        // Kill children of this PID
        let _ = std::process::Command::new("pkill")
            .args(["-TERM", "-P", &pid.to_string()])
            .output();
        tracing::info!(pid, session = %session_id, "Sent SIGTERM to session process + children");
    }

    let kill_pids = safe_pids.clone();
    let sid = session_id.to_string();
    tokio::spawn(async move {
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        for &pid in &kill_pids {
            unsafe {
                nix::libc::kill(pid as nix::libc::pid_t, nix::libc::SIGKILL);
            }
            let _ = std::process::Command::new("pkill")
                .args(["-9", "-P", &pid.to_string()])
                .output();
            tracing::info!(pid, session = %sid, "Sent SIGKILL to session process + children");
        }
    });
}

async fn terminate_session(
    State(state): State<ApiState>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    // Get session info before terminating so we can kill the OS processes
    let session_info = state.sessions.get(&id);
    let pids: Vec<u32> = session_info
        .as_ref()
        .map(|s| s.pids.clone())
        .unwrap_or_default();
    let process_name: Option<String> = session_info.as_ref().map(|s| s.actor.clone());

    state.sessions.decommission_jit(&id);
    if state.sessions.terminate(&id) {
        // Remove observer baseline policy for this session
        state.observer_engine.remove_policy(&id).await;
        kill_process_tree(&pids, &id, process_name.as_deref());

        let _ = state.audit.append(AuditEntryType::AccessDenied,
            serde_json::json!({"session_id":&id,"reason":"terminated_by_admin","pids_killed":&pids}));
        ok("Session terminated — processes killed").into_response()
    } else {
        err_resp(StatusCode::NOT_FOUND, "Not found or already ended").into_response()
    }
}

// ── Escalation handlers ───────────────────────────────────────────────────────

#[derive(Deserialize)]
struct EscalateRequest {
    tool_name: String,
    reason: String,
}

async fn escalate_session(
    State(state): State<ApiState>,
    Path(id): Path<String>,
    Json(req): Json<EscalateRequest>,
) -> impl IntoResponse {
    match state.sessions.escalate(&id, &req.tool_name, &req.reason) {
        Some(esc_id) => {
            let _ = state.audit.append(AuditEntryType::EscalationRequested,
                serde_json::json!({"session_id":&id,"tool":&req.tool_name,"reason":&req.reason,"escalation_id":&esc_id}));
            (
                StatusCode::CREATED,
                Json(serde_json::json!({"escalation_id":&esc_id})),
            )
                .into_response()
        }
        None => {
            err_resp(StatusCode::BAD_REQUEST, "Session not found or not active").into_response()
        }
    }
}

async fn list_escalations(State(state): State<ApiState>) -> impl IntoResponse {
    // Return all sessions that are WAITING_APPROVAL with their pending escalations
    let waiting = state.sessions.list_waiting();
    let result: Vec<serde_json::Value> = waiting
        .iter()
        .flat_map(|s| {
            s.escalations
                .iter()
                .filter(|e| e.approved.is_none())
                .map(|e| {
                    serde_json::json!({
                        "escalation_id": &e.id,
                        "session_id":    &s.id,
                        "actor":         &s.actor,
                        "agent_type":    &s.agent_type,
                        "tool_name":     &e.tool_name,
                        "reason":        &e.reason,
                        "requested_at":  &e.requested_at,
                        "privileged":    s.privileged,
                    })
                })
                .collect::<Vec<_>>()
        })
        .collect();
    Json(result).into_response()
}

#[derive(Deserialize)]
struct ResolveRequest {
    approved: bool,
    reviewer: Option<String>,
}

async fn resolve_escalation(
    State(state): State<ApiState>,
    Path(esc_id): Path<String>,
    Json(req): Json<ResolveRequest>,
) -> impl IntoResponse {
    // Find the session that owns this escalation
    let sessions = state.sessions.list();
    let session_id = sessions
        .iter()
        .find(|s| s.escalations.iter().any(|e| e.id == esc_id))
        .map(|s| s.id.clone());

    match session_id {
        None => err_resp(StatusCode::NOT_FOUND, "Escalation not found").into_response(),
        Some(sid) => {
            let reviewer = req.reviewer.unwrap_or_else(|| "admin".to_string());
            if state
                .sessions
                .resolve_escalation(&sid, &esc_id, req.approved, &reviewer)
            {
                if !req.approved {
                    state.sessions.decommission_jit(&sid);
                }
                let _ = state.audit.append(
                    AuditEntryType::EscalationResolved,
                    serde_json::json!({
                        "escalation_id": &esc_id,
                        "session_id":    &sid,
                        "approved":      req.approved,
                        "reviewer":      &reviewer,
                    }),
                );
                ok(if req.approved {
                    "Approved — session resumed"
                } else {
                    "Denied — session terminated"
                })
                .into_response()
            } else {
                err_resp(StatusCode::BAD_REQUEST, "Already resolved").into_response()
            }
        }
    }
}

// ── JIT handlers ──────────────────────────────────────────────────────────────

#[derive(Deserialize)]
struct JitRequest {
    scope: String,
    ttl_secs: Option<u64>,
}

async fn provision_jit(
    State(state): State<ApiState>,
    Path(session_id): Path<String>,
    Json(req): Json<JitRequest>,
) -> impl IntoResponse {
    let ttl = req.ttl_secs.unwrap_or(3600);
    match state.sessions.provision_jit(&session_id, &req.scope, ttl) {
        Some(jit_id) => {
            let _ = state.audit.append(
                AuditEntryType::AccessGranted,
                serde_json::json!({
                    "session_id": &session_id,
                    "jit_id":     &jit_id,
                    "scope":      &req.scope,
                    "ttl_secs":   ttl,
                }),
            );

            // Grant namespace access: unmount the bind-mount inside the sandbox
            if let Some(session) = state.sessions.get(&session_id) {
                for &pid in &session.pids {
                    let scope_path = req.scope.clone();
                    tokio::spawn(async move {
                        if let Err(e) =
                            crate::session::namespace::grant_namespace_access(pid, &scope_path)
                                .await
                        {
                            tracing::warn!(pid, path = %scope_path, err = %e, "Failed to grant namespace access");
                        }
                    });
                }
            }

            (
                StatusCode::CREATED,
                Json(serde_json::json!({"jit_id":&jit_id,"scope":&req.scope,"ttl_secs":ttl})),
            )
                .into_response()
        }
        None => err_resp(StatusCode::NOT_FOUND, "Session not found").into_response(),
    }
}

async fn revoke_jit(
    State(state): State<ApiState>,
    Path((session_id, jit_id)): Path<(String, String)>,
) -> impl IntoResponse {
    // Look up PIDs and scope *before* revoking so we can re-apply the bind-mount
    let namespace_targets: Vec<(u32, String)> = state
        .sessions
        .get(&session_id)
        .map(|session| {
            let scope = session
                .jit_identities
                .iter()
                .find(|j| j.id == jit_id)
                .map(|j| j.scope.clone());
            match scope {
                Some(scope_path) => session
                    .pids
                    .iter()
                    .map(|&pid| (pid, scope_path.clone()))
                    .collect(),
                None => Vec::new(),
            }
        })
        .unwrap_or_default();

    if state.sessions.revoke_jit(&session_id, &jit_id) {
        let _ = state.audit.append(
            AuditEntryType::AccessDenied,
            serde_json::json!({
                "session_id": &session_id,
                "jit_id":     &jit_id,
                "reason":     "revoked_by_admin",
            }),
        );

        // Revoke namespace access: re-apply the bind-mount inside the sandbox
        for (pid, scope_path) in namespace_targets {
            tokio::spawn(async move {
                if let Err(e) =
                    crate::session::namespace::revoke_namespace_access(pid, &scope_path).await
                {
                    tracing::warn!(pid, path = %scope_path, err = %e, "Failed to revoke namespace access");
                }
            });
        }

        ok("JIT identity revoked").into_response()
    } else {
        err_resp(StatusCode::NOT_FOUND, "JIT identity not found").into_response()
    }
}

// ── Audit handlers ────────────────────────────────────────────────────────────

async fn get_audit(
    State(state): State<ApiState>,
    Query(p): Query<AuditQuery>,
) -> impl IntoResponse {
    let entries = state.audit.recent(p.limit);
    Json(entries).into_response()
}

async fn verify_audit(State(state): State<ApiState>) -> impl IntoResponse {
    let (valid, first_invalid) = state.audit.verify_chain();
    Json(serde_json::json!({
        "valid":         valid,
        "first_invalid": first_invalid,
        "message": if valid { "Chain integrity verified." } else { "CHAIN TAMPERED — see first_invalid_seq." },
    })).into_response()
}

async fn export_audit(
    State(state): State<ApiState>,
    Query(p): Query<AuditQuery>,
) -> impl IntoResponse {
    let entries = state.audit.recent(p.limit.max(10000));
    let (valid, _) = state.audit.verify_chain();

    let export = serde_json::json!({
        "exported_at":     chrono::Utc::now().to_rfc3339(),
        "chain_valid":     valid,
        "entry_count":     entries.len(),
        "entries":         entries,
        "export_version":  "1.0",
        "product":         "Ring Zero Security",
        "compliance_note": "This audit log is SHA-256 hash-chained. Verify integrity with GET /api/v1/audit/verify.",
    });

    (
        [
            (
                axum::http::header::CONTENT_TYPE,
                HeaderValue::from_static("application/json"),
            ),
            (
                axum::http::header::CONTENT_DISPOSITION,
                HeaderValue::from_static("attachment; filename=\"ringzero-audit.json\""),
            ),
        ],
        Json(export),
    )
        .into_response()
}

// ── Network policy handlers ───────────────────────────────────────────────

async fn get_network_policy(State(state): State<ApiState>) -> impl IntoResponse {
    let mode = state.network.mode.read().await.clone();
    let enforce = state.network.enforce.read().await.clone();
    Json(serde_json::json!({
        "mode":    mode,
        "enforce": enforce,
    }))
    .into_response()
}

#[derive(Deserialize)]
struct NetworkPolicyRequest {
    mode: Option<NetworkMode>,
    enforce: Option<EnforceMode>,
}

async fn set_network_policy(
    State(state): State<ApiState>,
    Json(req): Json<NetworkPolicyRequest>,
) -> impl IntoResponse {
    if let Some(mode) = req.mode {
        *state.network.mode.write().await = mode.clone();
        let _ = state.audit.append(
            AuditEntryType::PolicyChange,
            serde_json::json!({"action":"set_network_mode","mode":mode}),
        );
    }
    if let Some(enforce) = req.enforce {
        *state.network.enforce.write().await = enforce.clone();
        let _ = state.audit.append(
            AuditEntryType::PolicyChange,
            serde_json::json!({"action":"set_enforce_mode","mode":enforce}),
        );
    }
    let mode = state.network.mode.read().await.clone();
    let enforce = state.network.enforce.read().await.clone();
    Json(serde_json::json!({"ok":true,"mode":mode,"enforce":enforce})).into_response()
}

// ── Per-session kernel event timeline ─────────────────────────

async fn get_session_events(
    State(state): State<ApiState>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    if state.sessions.get(&id).is_none() {
        return err_resp(StatusCode::NOT_FOUND, "session not found").into_response();
    }
    let events = state.sessions.get_events(&id);
    Json(serde_json::json!({
        "session_id":   id,
        "event_count":  events.len(),
        "events":       events,
    }))
    .into_response()
}

/// Ingest a single event into the timeline from an external source (e.g. mcp-proxy).
/// Body: `{"process": "claude", "target": "/path/to/file", "allowed": true, "kind": "file_open", "pid": 1234}`
#[derive(Debug, Deserialize)]
struct IngestEventRequest {
    process: String,
    target: String,
    allowed: bool,
    #[serde(default)]
    kind: Option<String>,
    #[serde(default)]
    pid: Option<u32>,
}

async fn post_session_event(
    State(state): State<ApiState>,
    Path(id): Path<String>,
    Json(body): Json<IngestEventRequest>,
) -> impl IntoResponse {
    if state.sessions.get(&id).is_none() {
        return err_resp(StatusCode::NOT_FOUND, "session not found").into_response();
    }
    let event = SecurityEvent {
        id: uuid::Uuid::new_v4().to_string(),
        kind: match body.kind.as_deref() {
            Some("file_open") => EventKind::FileOpen,
            Some("file_create") => EventKind::FileCreate,
            Some("file_write") => EventKind::FileWrite,
            Some("file_delete") => EventKind::FileDelete,
            Some("file_rename") => EventKind::FileRename,
            Some("process_exec") => EventKind::ProcessExec,
            Some("process_fork") => EventKind::ProcessFork,
            Some("process_exit") => EventKind::ProcessExit,
            Some("network_connect") => EventKind::NetworkConnect,
            Some("network_send") => EventKind::NetworkSend,
            Some("dns_query") => EventKind::DnsQuery,
            Some("mcp_tool_call") => EventKind::McpToolCall,
            _ => EventKind::FileOpen, // default for driver events
        },
        pid: body.pid.unwrap_or(0),
        uid: 0,
        process: body.process,
        target: body.target,
        allowed: body.allowed,
        reason: if !body.allowed {
            Some("Ring Zero Security policy".to_string())
        } else {
            None
        },
        timestamp: chrono::Utc::now(),
        ppid: None,
        parent_process: None,
        llm_context: None,
        extra: None,
    };
    // Wire the PID to the session (so the session knows which process it belongs to)
    if event.pid != 0 {
        state.sessions.register_pid(&id, event.pid);
    }

    // If the event was blocked (sensitive file), escalate the session for approval
    let was_blocked = !event.allowed;
    let target_for_esc = event.target.clone();

    // Increment global counters
    state.events_total.fetch_add(1, Ordering::Relaxed);
    if was_blocked {
        state.threats_blocked.fetch_add(1, Ordering::Relaxed);
    }

    // Feed correlation engine (Phase 6 — multi-step attack chain detection)
    if let Some(chain) = state.correlation_engine.evaluate(&event, &id).await {
        tracing::warn!(
            session = %id,
            pattern = %chain.pattern_name,
            severity = %chain.severity,
            "Attack chain detected via API event"
        );
    }

    // Store in the global timeline AND in the per-session log
    let _ = state.timeline.insert(&event);
    state.sessions.append_event(&id, event);

    if was_blocked {
        // Mark session as privileged (it touched something sensitive)
        state
            .sessions
            .set_privileged(&id, format!("Sensitive access: {}", &target_for_esc));
    }

    (StatusCode::CREATED, ok("event recorded")).into_response()
}

// ── NHI inventory ────────────────────────────────────────────────────────

/// Non-Human Identity inventory — scans common credential paths.
/// In production this runs as a daemon scan; this endpoint returns cached results.
async fn get_nhi_inventory(State(state): State<ApiState>) -> impl IntoResponse {
    // Return session-level NHI data derived from privileged access patterns
    let sessions = state.sessions.list();
    let nhi: Vec<serde_json::Value> = sessions
        .iter()
        .filter(|s| s.privileged)
        .map(|s| {
            serde_json::json!({
                "session_id":  s.id,
                "actor":       s.actor,
                "agent_type":  s.agent_type,
                "reason":      s.privileged_reason,
                "credentials_accessed": s.granted_access,
                "detected_at": s.start_time,
            })
        })
        .collect();

    Json(serde_json::json!({
        "scan_time":   chrono::Utc::now().to_rfc3339(),
        "nhi_count":   nhi.len(),
        "identities":  nhi,
        "scan_paths":  [
            "~/.aws/credentials", "~/.ssh/id_rsa", "~/.ssh/id_ed25519",
            "~/.kube/config", "~/.config/gcloud", "~/.azure",
            "~/.docker/config.json", "/etc/passwd", "/etc/shadow",
        ],
    }))
    .into_response()
}

// ── Shadow AI discovery ──────────────────────────────────────────────────

/// AI SaaS endpoints to flag as shadow AI
const SHADOW_AI_ENDPOINTS: &[(&str, &str)] = &[
    ("api.openai.com", "OpenAI"),
    ("api.anthropic.com", "Anthropic Claude"),
    ("generativelanguage.googleapis.com", "Google Gemini"),
    ("api.deepseek.com", "DeepSeek"),
    ("api.mistral.ai", "Mistral"),
    ("api.cohere.com", "Cohere"),
    ("api.together.xyz", "Together AI"),
    ("api.replicate.com", "Replicate"),
    ("api.groq.com", "Groq"),
    ("api.perplexity.ai", "Perplexity"),
    ("huggingface.co", "Hugging Face"),
    ("api.ai21.com", "AI21 Labs"),
];

async fn get_shadow_ai(State(state): State<ApiState>) -> impl IntoResponse {
    // Scan recent network events for traffic to known AI SaaS endpoints
    let events = state.timeline.all_recent(86400, 50000).unwrap_or_default();
    let mut detections: Vec<serde_json::Value> = Vec::new();

    for event in &events {
        if matches!(
            event.kind,
            crate::common::event::EventKind::NetworkConnect
                | crate::common::event::EventKind::DnsQuery
                | crate::common::event::EventKind::NetworkSend
        ) {
            for (endpoint, name) in SHADOW_AI_ENDPOINTS {
                if event.target.contains(endpoint) {
                    // Check if this came from a registered session
                    let session = state.sessions.list_active().into_iter().find(|s| {
                        s.actor.contains(&event.process) || event.process.contains(&s.actor)
                    });

                    let authorized = session.is_some();
                    if !authorized {
                        detections.push(serde_json::json!({
                            "provider":   name,
                            "endpoint":   endpoint,
                            "process":    event.process,
                            "pid":        event.pid,
                            "target":     event.target,
                            "timestamp":  event.timestamp,
                            "authorized": false,
                            "event_id":   event.id,
                        }));
                    }
                }
            }
        }
    }

    Json(serde_json::json!({
        "scan_time":         chrono::Utc::now().to_rfc3339(),
        "monitored_endpoints": SHADOW_AI_ENDPOINTS.len(),
        "unauthorized_count":  detections.len(),
        "detections":          detections,
    }))
    .into_response()
}

// ── Policy bundle export ─────────────────────────────────────────────────

async fn export_policy_bundle(State(state): State<ApiState>) -> impl IntoResponse {
    let acl = state.acl.read().await;
    let mode = state.network.mode.read().await.clone();
    let enforce = state.network.enforce.read().await.clone();

    let bundle = serde_json::json!({
        "bundle_version":  "1.0",
        "product":         "Ring Zero Security",
        "generated_at":    chrono::Utc::now().to_rfc3339(),
        "manifest": {
            "name":        "ringzero-policy-bundle",
            "version":     env!("CARGO_PKG_VERSION"),
        },
        "network": {
            "mode":    mode,
            "enforce": enforce,
        },
        "acl": {
            "default_deny": acl.default_deny(),
            "skill_policies": serde_json::to_value(acl.policies()).unwrap_or_default(),
        },
    });

    (
        [
            (
                axum::http::header::CONTENT_TYPE,
                HeaderValue::from_static("application/json"),
            ),
            (
                axum::http::header::CONTENT_DISPOSITION,
                HeaderValue::from_static("attachment; filename=\"ringzero-policy-bundle.json\""),
            ),
        ],
        Json(bundle),
    )
        .into_response()
}

// ── Session JWT ─────────────────────────────────────────────────────────

/// GET /api/v1/sessions/:id/jwt
/// Returns a short-lived HS256 JWT scoped to this session.
async fn get_session_jwt(
    State(state): State<ApiState>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    match state.sessions.get(&id) {
        None => err_resp(StatusCode::NOT_FOUND, "session not found").into_response(),
        Some(session) => {
            let agent_type = session.agent_type.to_string();
            let ttl = session.ttl_secs.unwrap_or(3600) as i64;
            match state.jwt_issuer.issue(
                &id,
                &session.actor,
                &agent_type,
                session.declared_scope.clone(),
                ttl,
            ) {
                Ok(token) => {
                    let _ = state.audit.append(
                        AuditEntryType::AccessGranted,
                        serde_json::json!({"event":"jwt_issued","session_id":&id}),
                    );
                    Json(serde_json::json!({
                        "session_id": id,
                        "token": token,
                        "ttl_secs": ttl,
                        "algorithm": "HS256",
                    }))
                    .into_response()
                }
                Err(e) => err_resp(StatusCode::INTERNAL_SERVER_ERROR, format!("JWT error: {e}"))
                    .into_response(),
            }
        }
    }
}

// ── Intent-aware policy ─────────────────────────────────────────────────

/// GET /api/v1/intent-policy — list all intent policy rules
async fn get_intent_policy(State(state): State<ApiState>) -> impl IntoResponse {
    let rules = state.intent_policy.rules().await;
    Json(serde_json::json!({
        "rule_count": rules.len(),
        "rules": rules,
    }))
    .into_response()
}

/// POST /api/v1/intent-policy — upsert a rule
async fn update_intent_policy(
    State(state): State<ApiState>,
    Json(rule): Json<IntentRule>,
) -> impl IntoResponse {
    state.intent_policy.set_rule(rule.clone()).await;
    let _ = state.audit.append(AuditEntryType::PolicyChange,
        serde_json::json!({"event":"intent_policy_updated","category":rule.category,"action":rule.action}));
    ok(format!(
        "Rule for {:?} updated → {:?}",
        rule.category, rule.action
    ))
    .into_response()
}

#[derive(Deserialize)]
struct ClassifyRequest {
    intent: String,
    context: Option<String>,
}

/// POST /api/v1/intent-policy/classify — classify an intent on demand
async fn classify_intent_request(
    State(state): State<ApiState>,
    Json(req): Json<ClassifyRequest>,
) -> impl IntoResponse {
    let result = state
        .intent_policy
        .classify_and_evaluate(&req.intent, req.context.as_deref())
        .await;
    Json(result).into_response()
}

// ── Compliance reports ──────────────────────────────────────────────────

/// GET /api/v1/compliance/soc2
async fn compliance_soc2(State(state): State<ApiState>) -> impl IntoResponse {
    let (chain_valid, first_invalid) = state.audit.verify_chain();
    let audit_entries = state.audit.recent(10000);
    let sessions = state.sessions.list();
    let active = sessions.iter().filter(|s| s.is_live()).count();
    let privileged = sessions.iter().filter(|s| s.privileged).count();
    let resolved_escs = sessions
        .iter()
        .flat_map(|s| &s.escalations)
        .filter(|e| e.approved.is_some())
        .count();

    Json(serde_json::json!({
        "framework":    "SOC 2 Type II",
        "generated_at": chrono::Utc::now().to_rfc3339(),
        "product":      "Ring Zero Security",
        "controls": {
            "CC6_1_logical_access": {
                "control": "Logical and physical access to the system is restricted to authorized users.",
                "evidence": {
                    "total_sessions":      sessions.len(),
                    "active_sessions":     active,
                    "privileged_sessions": privileged,
                    "jit_provisions":      sessions.iter().map(|s| s.jit_identities.len()).sum::<usize>(),
                },
                "status": if privileged == 0 { "PASS" } else { "REVIEW" },
            },
            "CC6_2_user_identification": {
                "control": "Prior to issuing credentials, subjects are registered and authorized.",
                "evidence": {
                    "audit_log_entries":   audit_entries.len(),
                    "chain_integrity":     chain_valid,
                    "first_invalid_seq":   first_invalid,
                },
                "status": if chain_valid { "PASS" } else { "FAIL" },
            },
            "CC6_3_access_removal": {
                "control": "Access is removed when no longer required.",
                "evidence": {
                    "terminated_sessions": sessions.iter().filter(|s| matches!(s.state,
                        crate::session::store::SessionState::Terminated |
                        crate::session::store::SessionState::Expired)).count(),
                    "resolved_escalations": resolved_escs,
                },
                "status": "PASS",
            },
            "CC7_2_monitoring": {
                "control": "The system is monitored to detect anomalies.",
                "evidence": {
                    "events_in_last_hour": state.timeline.all_recent(3600, usize::MAX)
                        .unwrap_or_default().len(),
                    "threats_detected":    state.timeline.all_recent(86400, usize::MAX)
                        .unwrap_or_default().iter().filter(|e| !e.allowed).count(),
                },
                "status": "PASS",
            },
        },
        "audit_log_integrity": {
            "valid":        chain_valid,
            "entry_count":  audit_entries.len(),
        },
    })).into_response()
}

/// GET /api/v1/compliance/nist
async fn compliance_nist(State(state): State<ApiState>) -> impl IntoResponse {
    let sessions = state.sessions.list();
    let audit_entries = state.audit.recent(10000);
    let (chain_valid, _) = state.audit.verify_chain();
    let escalations_total: usize = sessions.iter().map(|s| s.escalations.len()).sum();

    Json(serde_json::json!({
        "framework":    "NIST AI RMF 1.0",
        "generated_at": chrono::Utc::now().to_rfc3339(),
        "product":      "Ring Zero Security",
        "functions": {
            "GOVERN": {
                "description": "Organizational practices for AI risk management.",
                "evidence": {
                    "policy_rules_active": true,
                    "intent_policy_enabled": true,
                    "audit_log_integrity": chain_valid,
                },
                "status": "IMPLEMENTED",
            },
            "MAP": {
                "description": "Identifies and classifies AI risks.",
                "evidence": {
                    "session_count":       sessions.len(),
                    "agent_types":         sessions.iter().map(|s| s.agent_type.to_string()).collect::<std::collections::HashSet<_>>(),
                    "privileged_sessions": sessions.iter().filter(|s| s.privileged).count(),
                },
                "status": "IMPLEMENTED",
            },
            "MEASURE": {
                "description": "Analyzes and assesses AI risks.",
                "evidence": {
                    "events_tracked":      audit_entries.len(),
                    "escalation_requests": escalations_total,
                    "intent_diffs":        state.intent_diff.diffs().len(),
                },
                "status": "IMPLEMENTED",
            },
            "MANAGE": {
                "description": "Prioritizes and treats AI risks.",
                "evidence": {
                    "jit_grants_total": sessions.iter().map(|s| s.jit_identities.len()).sum::<usize>(),
                    "blocks_enforced":  state.timeline.all_recent(86400, usize::MAX)
                        .unwrap_or_default().iter().filter(|e| !e.allowed).count(),
                    "escalations_resolved": sessions.iter()
                        .flat_map(|s| &s.escalations)
                        .filter(|e| e.approved.is_some()).count(),
                },
                "status": "IMPLEMENTED",
            },
        },
    })).into_response()
}

/// GET /api/v1/compliance/iso27001
async fn compliance_iso27001(State(state): State<ApiState>) -> impl IntoResponse {
    let sessions = state.sessions.list();
    let (chain_valid, first_invalid) = state.audit.verify_chain();

    Json(serde_json::json!({
        "framework":    "ISO/IEC 27001:2022",
        "generated_at": chrono::Utc::now().to_rfc3339(),
        "product":      "Ring Zero Security",
        "clauses": {
            "A_5_15_access_control": {
                "clause": "Access to information and associated assets should be controlled.",
                "evidence": {
                    "active_sessions":     sessions.iter().filter(|s| s.is_live()).count(),
                    "session_jit_total":   sessions.iter().map(|s| s.jit_identities.len()).sum::<usize>(),
                    "network_mode":        state.network.mode.read().await.clone(),
                },
                "status": "CONFORMANT",
            },
            "A_8_15_logging": {
                "clause": "Logs recording user activities and events should be produced, stored and protected.",
                "evidence": {
                    "audit_entries":   state.audit.recent(10000).len(),
                    "chain_valid":     chain_valid,
                    "first_invalid":   first_invalid,
                },
                "status": if chain_valid { "CONFORMANT" } else { "NON-CONFORMANT" },
            },
            "A_8_16_monitoring": {
                "clause": "Networks, systems and applications should be monitored.",
                "evidence": {
                    "events_24h":      state.timeline.all_recent(86400, usize::MAX)
                        .unwrap_or_default().len(),
                    "threats_24h":     state.timeline.all_recent(86400, usize::MAX)
                        .unwrap_or_default().iter().filter(|e| !e.allowed).count(),
                    "intent_diffs":    state.intent_diff.diffs().len(),
                },
                "status": "CONFORMANT",
            },
            "A_5_18_access_rights": {
                "clause": "Access rights to information should be provisioned and de-provisioned.",
                "evidence": {
                    "privileged_sessions": sessions.iter().filter(|s| s.privileged).count(),
                    "terminated":          sessions.iter().filter(|s| matches!(s.state,
                        crate::session::store::SessionState::Terminated |
                        crate::session::store::SessionState::Expired)).count(),
                },
                "status": "CONFORMANT",
            },
        },
    })).into_response()
}

/// GET /api/v1/compliance/summary — aggregate health across all frameworks
async fn compliance_summary(State(state): State<ApiState>) -> impl IntoResponse {
    let (chain_valid, _) = state.audit.verify_chain();
    let sessions = state.sessions.list();
    let events_1h = state
        .timeline
        .all_recent(3600, usize::MAX)
        .unwrap_or_default();
    let threats_24h = state
        .timeline
        .all_recent(86400, usize::MAX)
        .unwrap_or_default()
        .iter()
        .filter(|e| !e.allowed)
        .count();

    let overall = if chain_valid && threats_24h == 0 {
        "GREEN"
    } else if chain_valid {
        "AMBER"
    } else {
        "RED"
    };

    Json(serde_json::json!({
        "generated_at":  chrono::Utc::now().to_rfc3339(),
        "overall_status": overall,
        "frameworks": {
            "SOC2_Type_II":   if chain_valid { "PASS" } else { "FAIL" },
            "NIST_AI_RMF":    "IMPLEMENTED",
            "ISO_27001_2022": if chain_valid { "CONFORMANT" } else { "NON-CONFORMANT" },
        },
        "metrics": {
            "sessions_total":       sessions.len(),
            "sessions_active":      sessions.iter().filter(|s| s.is_live()).count(),
            "sessions_privileged":  sessions.iter().filter(|s| s.privileged).count(),
            "events_last_hour":     events_1h.len(),
            "threats_last_24h":     threats_24h,
            "audit_chain_valid":    chain_valid,
            "intent_diffs_total":   state.intent_diff.diffs().len(),
            "jit_grants_total":     sessions.iter().map(|s| s.jit_identities.len()).sum::<usize>(),
        },
    }))
    .into_response()
}

// ── Secret rotation ─────────────────────────────────────────────────────

#[derive(Deserialize)]
struct SecretsQuery {
    status: Option<String>,
}

/// GET /api/v1/secrets — list tracked secrets (optionally filtered by status)
async fn list_secrets(
    State(state): State<ApiState>,
    Query(q): Query<SecretsQuery>,
) -> impl IntoResponse {
    let filter = q.status.as_deref().and_then(|s| match s {
        "pending" => Some(RotationStatus::Pending),
        "in_progress" => Some(RotationStatus::InProgress),
        "rotated" => Some(RotationStatus::Rotated),
        "acknowledged" => Some(RotationStatus::Acknowledged),
        "revoked" => Some(RotationStatus::Revoked),
        _ => None,
    });
    let secrets = state.rotation_store.list(filter.as_ref());
    Json(serde_json::json!({
        "count":   secrets.len(),
        "secrets": secrets,
    }))
    .into_response()
}

/// GET /api/v1/secrets/summary
async fn secrets_summary(State(state): State<ApiState>) -> impl IntoResponse {
    Json(state.rotation_store.summary()).into_response()
}

/// GET /api/v1/secrets/overdue
async fn secrets_overdue(State(state): State<ApiState>) -> impl IntoResponse {
    let overdue = state.rotation_store.overdue();
    Json(serde_json::json!({
        "overdue_count": overdue.len(),
        "secrets":       overdue,
    }))
    .into_response()
}

#[derive(Deserialize)]
struct RotationActionRequest {
    triggered_by: Option<String>,
    notes: Option<String>,
}

/// POST /api/v1/secrets/:id/trigger — trigger rotation workflow
async fn trigger_rotation(
    State(state): State<ApiState>,
    Path(id): Path<String>,
    Json(req): Json<RotationActionRequest>,
) -> impl IntoResponse {
    let by = req.triggered_by.as_deref().unwrap_or("admin");
    if state.rotation_store.trigger_rotation(&id, by) {
        let _ = state.audit.append(
            AuditEntryType::SecurityEvent,
            serde_json::json!({"event":"rotation_triggered","secret_id":&id,"by":by}),
        );
        ok(format!("Rotation triggered for {id}")).into_response()
    } else {
        err_resp(
            StatusCode::BAD_REQUEST,
            "Secret not found or already in progress",
        )
        .into_response()
    }
}

/// POST /api/v1/secrets/:id/confirm — confirm secret has been rotated
async fn confirm_rotation(
    State(state): State<ApiState>,
    Path(id): Path<String>,
    Json(req): Json<RotationActionRequest>,
) -> impl IntoResponse {
    if state.rotation_store.confirm_rotated(&id, req.notes) {
        let _ = state.audit.append(
            AuditEntryType::SecurityEvent,
            serde_json::json!({"event":"rotation_confirmed","secret_id":&id}),
        );
        ok(format!("Rotation confirmed for {id}")).into_response()
    } else {
        err_resp(StatusCode::NOT_FOUND, "Secret not found").into_response()
    }
}

/// POST /api/v1/secrets/:id/acknowledge — mark as intentional / false positive
async fn acknowledge_secret(
    State(state): State<ApiState>,
    Path(id): Path<String>,
    Json(req): Json<RotationActionRequest>,
) -> impl IntoResponse {
    if state.rotation_store.acknowledge(&id, req.notes) {
        let _ = state.audit.append(
            AuditEntryType::SecurityEvent,
            serde_json::json!({"event":"secret_acknowledged","secret_id":&id}),
        );
        ok(format!("Secret {id} acknowledged")).into_response()
    } else {
        err_resp(StatusCode::NOT_FOUND, "Secret not found").into_response()
    }
}

/// POST /api/v1/secrets/:id/revoke — mark as revoked / leaked
async fn revoke_secret(
    State(state): State<ApiState>,
    Path(id): Path<String>,
    Json(req): Json<RotationActionRequest>,
) -> impl IntoResponse {
    if state.rotation_store.revoke(&id, req.notes) {
        let _ = state.audit.append(
            AuditEntryType::SecurityEvent,
            serde_json::json!({"event":"secret_revoked","secret_id":&id}),
        );
        ok(format!("Secret {id} marked revoked")).into_response()
    } else {
        err_resp(StatusCode::NOT_FOUND, "Secret not found").into_response()
    }
}

// ── Prompt injection scan ───────────────────────────────────────────────

#[derive(Deserialize)]
struct InjectionScanRequest {
    /// File path to scan
    path: Option<String>,
    /// Raw text to scan (alternative to path)
    content: Option<String>,
}

/// POST /api/v1/injection-scan
/// Scan a file path or raw text snippet for prompt injection.
/// Uses the local heuristic detector.
async fn injection_scan(Json(req): Json<InjectionScanRequest>) -> impl IntoResponse {
    use crate::scanner::model_armor::{
        heuristic_scan, scan_file_for_injection, ModelArmorConfig, ModelArmorReport,
    };

    let config = ModelArmorConfig::resolve(&ModelArmorConfig::default());

    if let Some(path_str) = req.path {
        let path = std::path::Path::new(&path_str);
        let report = scan_file_for_injection(path, config.as_ref()).await;
        Json(report).into_response()
    } else if let Some(content) = req.content {
        let findings: Vec<_> = heuristic_scan(&content).into_iter().collect();

        let report = ModelArmorReport {
            path: "<inline>".to_string(),
            clean: findings.is_empty(),
            findings,
            scanned_at: chrono::Utc::now().to_rfc3339(),
        };
        Json(report).into_response()
    } else {
        err_resp(StatusCode::BAD_REQUEST, "Provide 'path' or 'content'").into_response()
    }
}

// ── Skill scanner — on-demand full scan ───────────────────────────────────────

#[derive(Debug, Deserialize)]
struct SkillScanRequest {
    /// Directory to scan (e.g. "~/.claude", "/home/user/.cursor/extensions")
    path: String,
}

#[derive(Debug, Serialize)]
struct SkillScanResult {
    path: String,
    files_scanned: usize,
    supply_chain: Vec<crate::scanner::supply_chain::ScanReport>,
    injection_reports: Vec<crate::scanner::model_armor::ModelArmorReport>,
    registry_entries: Vec<crate::scanner::verified_registry::RegistryEntry>,
    overall_risk: String,
}

/// POST /api/v1/skill-scan
/// Full scan of a skill/extension directory: supply chain (entropy + secrets)
/// + prompt injection (heuristic) + verified registry cross-check.
async fn scan_skills(
    State(state): State<ApiState>,
    Json(req): Json<SkillScanRequest>,
) -> impl IntoResponse {
    use crate::scanner::model_armor::{scan_dir_for_injection, ModelArmorConfig};
    use crate::scanner::supply_chain::scan_dir;

    // Expand ~ to home dir
    let expanded = if req.path.starts_with('~') {
        if let Some(home) = dirs_next::home_dir() {
            req.path.replacen('~', &home.to_string_lossy(), 1)
        } else {
            req.path.clone()
        }
    } else {
        req.path.clone()
    };

    let dir = std::path::Path::new(&expanded);
    if !dir.exists() || !dir.is_dir() {
        return err_resp(
            StatusCode::BAD_REQUEST,
            format!("Directory not found: {}", expanded),
        )
        .into_response();
    }

    // 1. Supply chain scan (entropy + secrets)
    let supply_chain_reports = scan_dir(dir);
    let files_scanned = supply_chain_reports.len();

    // 2. Injection scan (heuristic)
    let ma_config = ModelArmorConfig::resolve(&ModelArmorConfig::default());
    let injection_reports = scan_dir_for_injection(dir, ma_config.as_ref()).await;

    // 3. Register results in verified registry
    let mut registry_entries = Vec::new();
    for report in &supply_chain_reports {
        let path = std::path::PathBuf::from(&report.path);
        let has_injection = injection_reports
            .iter()
            .any(|ir| ir.path == report.path && !ir.clean);
        let entry = state
            .verified_registry
            .ingest_scan(&path, report, has_injection);
        registry_entries.push(entry);
    }

    // 4. Compute overall risk
    use crate::scanner::supply_chain::RiskLevel;
    let worst_supply = supply_chain_reports
        .iter()
        .map(|r| &r.risk_level)
        .max()
        .cloned()
        .unwrap_or(RiskLevel::Clean);
    let has_injection = !injection_reports.is_empty();

    let overall_risk = if has_injection || worst_supply == RiskLevel::Critical {
        "critical"
    } else if worst_supply == RiskLevel::High {
        "high"
    } else if worst_supply == RiskLevel::Medium {
        "medium"
    } else if worst_supply == RiskLevel::Low {
        "low"
    } else {
        "clean"
    };

    Json(SkillScanResult {
        path: expanded,
        files_scanned,
        supply_chain: supply_chain_reports,
        injection_reports,
        registry_entries,
        overall_risk: overall_risk.to_string(),
    })
    .into_response()
}

// ── Skill scanner — auto-enumerate every agent's skill surface ────────────────

/// POST /api/v1/skill-scan/auto
/// Discover EVERY agent skill surface on the host (all users) and scan each:
/// supply chain (entropy + secrets) + prompt injection (heuristic).
/// This is what `rz scan skills` and the desktop app's "Scan Skills" both call —
/// shared with the IPC handler via `skill_surface::scan_all`.
#[derive(Deserialize, Default)]
struct ScanQuery {
    /// Show every finding, including ones already accepted into the baseline.
    #[serde(default)]
    all: Option<bool>,
}

async fn scan_skills_auto(
    State(_state): State<ApiState>,
    Query(q): Query<ScanQuery>,
) -> impl IntoResponse {
    let mut result = crate::scanner::skill_surface::scan_all().await;
    let show_all = q.all.unwrap_or(false);
    let suppressed = if show_all {
        0
    } else {
        crate::scanner::baseline::filter_to_new(&mut result)
    };
    let b = crate::scanner::baseline::Baseline::load();

    let mut v = serde_json::to_value(&result).unwrap_or(serde_json::Value::Null);
    if let Some(obj) = v.as_object_mut() {
        obj.insert(
            "showing".into(),
            serde_json::json!(if show_all { "all" } else { "new" }),
        );
        obj.insert("baseline_suppressed".into(), serde_json::json!(suppressed));
        obj.insert(
            "baseline".into(),
            serde_json::json!({
                "accepted": b.accepted_at.is_some(),
                "accepted_by": b.accepted_by,
                "accepted_at": b.accepted_at,
                "findings_accepted": b.total_accepted(),
            }),
        );
    }
    Json(v).into_response()
}

// ── Scan baseline ───────────────────────────────────────────────────────────

/// GET /api/v1/scan/baseline — what has been accepted, and by whom.
async fn get_scan_baseline(State(_s): State<ApiState>) -> impl IntoResponse {
    let b = crate::scanner::baseline::Baseline::load();
    Json(serde_json::json!({
        "accepted": b.accepted_at.is_some(),
        "accepted_by": b.accepted_by,
        "accepted_at": b.accepted_at,
        "findings_accepted": b.total_accepted(),
        "surfaces": b.surfaces.len(),
        "path": crate::scanner::baseline::baseline_path().display().to_string(),
    }))
}

/// POST /api/v1/scan/baseline — accept the current findings as the baseline.
///
/// Full-scope only, like every other mutating call: the agent runs as the
/// operator and must not be able to accept away its own findings.
async fn accept_scan_baseline(State(s): State<ApiState>) -> impl IntoResponse {
    let result = crate::scanner::skill_surface::scan_all().await;
    let who = std::env::var("SUDO_USER").unwrap_or_else(|_| "root".to_string());
    let b = crate::scanner::baseline::accept(&result, &who);
    match b.save() {
        Ok(()) => {
            s.audit.try_append(
                AuditEntryType::ConfigChange,
                serde_json::json!({
                    "action": "scan_baseline_accept",
                    "accepted_by": who,
                    "findings_accepted": b.total_accepted(),
                    "surfaces": b.surfaces.len(),
                }),
            );
            tracing::warn!(
                accepted_by = %who,
                findings = b.total_accepted(),
                "Scan baseline accepted — later scans report only new findings"
            );
            Json(serde_json::json!({
                "ok": true,
                "findings_accepted": b.total_accepted(),
                "surfaces": b.surfaces.len(),
                "accepted_by": who,
            }))
            .into_response()
        }
        Err(e) => err_resp(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()).into_response(),
    }
}

/// DELETE /api/v1/scan/baseline — forget the snapshot; every finding is new again.
async fn clear_scan_baseline(State(s): State<ApiState>) -> impl IntoResponse {
    match crate::scanner::baseline::clear() {
        Ok(()) => {
            s.audit.try_append(
                AuditEntryType::ConfigChange,
                serde_json::json!({"action": "scan_baseline_clear"}),
            );
            ok("scan baseline cleared").into_response()
        }
        Err(e) => err_resp(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()).into_response(),
    }
}

// ── Supply chain / verified registry ───────────────────────────────────

async fn list_supply_chain(State(s): State<ApiState>) -> impl IntoResponse {
    Json(s.verified_registry.list())
}

async fn supply_chain_summary(State(s): State<ApiState>) -> impl IntoResponse {
    Json(s.verified_registry.summary())
}

async fn allow_package(State(s): State<ApiState>, Path(id): Path<String>) -> impl IntoResponse {
    if s.verified_registry.allow(&id) {
        ok(format!("Package {} allowed", id)).into_response()
    } else {
        err_resp(StatusCode::NOT_FOUND, "Package not found").into_response()
    }
}

async fn quarantine_package(
    State(s): State<ApiState>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    if s.verified_registry.quarantine(&id) {
        ok(format!("Package {} quarantined", id)).into_response()
    } else {
        err_resp(StatusCode::NOT_FOUND, "Package not found").into_response()
    }
}

// ── ML behavioral baseline ────────────────────────────────────────────

async fn list_baselines(State(s): State<ApiState>) -> impl IntoResponse {
    Json(s.baseline_engine.profiles())
}

async fn get_baseline(State(s): State<ApiState>, Path(agent): Path<String>) -> impl IntoResponse {
    match s.baseline_engine.get_profile(&agent) {
        Some(p) => Json(p).into_response(),
        None => err_resp(StatusCode::NOT_FOUND, "Agent baseline not found").into_response(),
    }
}

// ── Health detailed (expansion #1: unified health dashboard) ─────────────────

/// GET /api/v1/health/detailed — comprehensive system health telemetry
async fn health_detailed(State(s): State<ApiState>) -> Json<serde_json::Value> {
    let ebpf = s.ebpf_active.load(Ordering::Relaxed);
    let events_total = s.events_total.load(Ordering::Relaxed);
    let threats_blocked = s.threats_blocked.load(Ordering::Relaxed);
    let db_size_bytes = s.timeline.db_size_bytes();
    let active_sessions = s.sessions.list_active().len();

    let acl = s.acl.read().await;
    let policy_count = acl.policies().len();
    let enforce_mode = acl.default_deny();
    drop(acl);

    Json(serde_json::json!({
        "version":          env!("CARGO_PKG_VERSION"),
        "ebpf_active":      ebpf,
        "enforce_mode":     enforce_mode,
        "events_total":     events_total,
        "threats_blocked":  threats_blocked,
        "active_sessions":  active_sessions,
        "policy_count":     policy_count,
        "db_size_bytes":    db_size_bytes,
        "auth_active":      s.auth.is_active().await,
    }))
}

// ── Auth handlers (expansion #7: API authentication) ─────────────────────────

#[derive(Deserialize)]
struct RegisterTokenRequest {
    token: String,
}

/// POST /api/v1/auth/register — register a bearer token for API auth.
/// Called once by the Tauri app on first launch.
async fn register_auth_token(
    State(s): State<ApiState>,
    Json(req): Json<RegisterTokenRequest>,
) -> impl IntoResponse {
    if req.token.len() < 32 {
        return err_resp(
            StatusCode::BAD_REQUEST,
            "Token must be at least 32 characters",
        )
        .into_response();
    }
    // The register endpoint is unauthenticated and one-shot. Once a token is
    // present, further changes must go through the authenticated rotate path
    // so a local attacker can't simply overwrite the legitimate UI's token.
    if let Err(e) = s.auth.register_token(&req.token).await {
        return err_resp(StatusCode::CONFLICT, &e.to_string()).into_response();
    }
    let _ = s.audit.append(
        AuditEntryType::PolicyChange,
        serde_json::json!({"action": "auth_token_registered"}),
    );
    ok("Bearer token registered — all API requests now require Authorization header")
        .into_response()
}

/// POST /api/v1/auth/rotate — replace the current bearer token with a new one.
/// Authenticated: the auth middleware enforces the existing token before this
/// handler ever runs, so the rotate path is gated to the legitimate UI.
async fn rotate_auth_token(
    State(s): State<ApiState>,
    Json(req): Json<RegisterTokenRequest>,
) -> impl IntoResponse {
    if req.token.len() < 32 {
        return err_resp(
            StatusCode::BAD_REQUEST,
            "Token must be at least 32 characters",
        )
        .into_response();
    }
    if !s.auth.rotate_token(&req.token).await {
        // No-op rotation (UI re-sent the current token). Don't write an audit
        // entry claiming a change happened.
        return err_resp(
            StatusCode::BAD_REQUEST,
            "New token must differ from current token",
        )
        .into_response();
    }
    let _ = s.audit.append(
        AuditEntryType::PolicyChange,
        serde_json::json!({"action": "auth_token_rotated"}),
    );
    ok("Bearer token rotated").into_response()
}

/// GET /api/v1/auth/status — check if auth is active
async fn auth_status(State(s): State<ApiState>) -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "active": s.auth.is_active().await,
    }))
}

// ── Policy quick-actions (expansion #2: persist to quick-rules.toml) ────────

/// Quick-action rule persisted to disk so it survives daemon restarts.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct QuickRule {
    action: String, // "block", "whitelist", "trust"
    target: String, // domain, path glob, or process name
    scope: String,  // "domain", "path", "process"
    reason: Option<String>,
    created: String, // ISO 8601
}

/// Load quick-rules from disk.
fn load_quick_rules() -> Vec<QuickRule> {
    let path = quick_rules_path();
    if !path.exists() {
        return Vec::new();
    }
    match std::fs::read_to_string(&path) {
        Ok(content) => {
            #[derive(Deserialize)]
            struct Wrapper {
                rules: Vec<QuickRule>,
            }
            toml::from_str::<Wrapper>(&content)
                .map(|w| w.rules)
                .unwrap_or_default()
        }
        Err(_) => Vec::new(),
    }
}

/// Persist quick-rules to disk.
fn save_quick_rules(rules: &[QuickRule]) -> std::io::Result<()> {
    let path = quick_rules_path();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    #[derive(Serialize)]
    struct Wrapper<'a> {
        rules: &'a [QuickRule],
    }
    let content = toml::to_string_pretty(&Wrapper { rules })
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
    std::fs::write(&path, content)
}

fn quick_rules_path() -> std::path::PathBuf {
    // Same directory as daemon.toml
    std::path::PathBuf::from("/etc/ringzero/quick-rules.toml")
}

#[derive(Deserialize)]
struct QuickActionRequest {
    action: String, // "block", "whitelist", "trust"
    target: String, // what to act on
    scope: String,  // "domain", "path", "process"
    reason: Option<String>,
}

/// POST /api/v1/policy/quick-action — add a quick-action rule and persist.
async fn quick_action(
    State(state): State<ApiState>,
    Json(req): Json<QuickActionRequest>,
) -> impl IntoResponse {
    // Validate action
    if !["block", "whitelist", "trust"].contains(&req.action.as_str()) {
        return err_resp(
            StatusCode::BAD_REQUEST,
            "action must be block, whitelist, or trust",
        )
        .into_response();
    }
    if !["domain", "path", "process"].contains(&req.scope.as_str()) {
        return err_resp(
            StatusCode::BAD_REQUEST,
            "scope must be domain, path, or process",
        )
        .into_response();
    }

    // Apply to in-memory ACL immediately
    match req.action.as_str() {
        "block" if req.scope == "domain" => {
            state.acl.write().await.block_domain(&req.target);
        }
        _ => {
            // whitelist/trust and other scopes: update ACL via allow rules
            // For now, block_domain is the only immediate ACL mutation.
            // Other actions are persisted and loaded on restart.
        }
    }

    // Persist to disk
    let rule = QuickRule {
        action: req.action.clone(),
        target: req.target.clone(),
        scope: req.scope.clone(),
        reason: req.reason.clone(),
        created: chrono::Utc::now().to_rfc3339(),
    };
    let mut rules = load_quick_rules();
    // Deduplicate: remove existing rules for same target+scope
    rules.retain(|r| !(r.target == rule.target && r.scope == rule.scope));
    rules.push(rule);
    if let Err(e) = save_quick_rules(&rules) {
        tracing::error!(err = %e, "Failed to persist quick-rules.toml");
        return err_resp(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Failed to save rule to disk",
        )
        .into_response();
    }

    let _ = state.audit.append(
        AuditEntryType::PolicyChange,
        serde_json::json!({
            "action": "quick_action",
            "rule_action": &req.action,
            "target": &req.target,
            "scope": &req.scope,
            "reason": &req.reason,
        }),
    );

    tracing::info!(action = %req.action, target = %req.target, scope = %req.scope, "Quick-action rule applied and persisted");
    ok(format!(
        "{} rule applied for {} ({})",
        req.action, req.target, req.scope
    ))
    .into_response()
}

/// GET /api/v1/policy/quick-rules — list persisted quick-action rules
async fn list_quick_rules() -> impl IntoResponse {
    let rules = load_quick_rules();
    Json(serde_json::json!({
        "count": rules.len(),
        "rules": rules,
        "path":  quick_rules_path().display().to_string(),
    }))
    .into_response()
}

// ── LLM session replay (expansion #5) ────────────────────────────────────────

/// GET /api/v1/sessions/:id/llm-replay — returns LLM request/response events
/// for a session in chronological order, reconstructing the conversation flow.
async fn get_llm_replay(
    State(state): State<ApiState>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    if state.sessions.get(&id).is_none() {
        return err_resp(StatusCode::NOT_FOUND, "session not found").into_response();
    }

    let events = state.sessions.get_events(&id);

    // Filter to LLM-related events only, in chronological order
    let llm_events: Vec<serde_json::Value> = events
        .into_iter()
        .filter(|e| {
            matches!(
                e.kind,
                EventKind::LlmRequest | EventKind::LlmResponse | EventKind::LlmToolCall
            )
        })
        .rev() // get_events returns newest-first; we want chronological
        .map(|e| {
            let mut entry = serde_json::json!({
                "id":        e.id,
                "kind":      e.kind,
                "target":    e.target,
                "timestamp": e.timestamp,
            });
            if let Some(ref ctx) = e.llm_context {
                entry["provider"] = serde_json::json!(ctx.provider);
                entry["model"] = serde_json::json!(ctx.model);
                entry["response_text"] = serde_json::json!(ctx.response_text);
                entry["tool_call"] = serde_json::json!(ctx.tool_call);
                if let Some(ref usage) = ctx.usage {
                    entry["usage"] = serde_json::json!({
                        "input_tokens": usage.input_tokens,
                        "output_tokens": usage.output_tokens,
                    });
                }
            }
            entry
        })
        .collect();

    Json(serde_json::json!({
        "session_id":  id,
        "event_count": llm_events.len(),
        "events":      llm_events,
    }))
    .into_response()
}

// ── Observer baseline policy handlers ────────────────────────────────────────

/// GET /api/v1/sessions/:id/policy — get the active baseline policy for a session
async fn get_session_policy(
    State(state): State<ApiState>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    match state.observer_engine.get_policy(&id).await {
        Some(policy) => Json(serde_json::to_value(&policy).unwrap_or_default()).into_response(),
        None => {
            err_resp(StatusCode::NOT_FOUND, "No baseline policy for this session").into_response()
        }
    }
}

#[derive(Deserialize)]
struct UpdatePolicyRule {
    class: String,
    action: String,
    /// For AllowScoped: comma-separated pattern list
    patterns: Option<Vec<String>>,
    description: Option<String>,
}

/// POST /api/v1/sessions/:id/policy — update a specific rule in the session's baseline
async fn update_session_policy(
    State(state): State<ApiState>,
    Path(id): Path<String>,
    Json(req): Json<UpdatePolicyRule>,
) -> impl IntoResponse {
    use crate::analyzer::observer::{ActivityClass, ActivityRule, BaselineAction};

    let class = match req.class.as_str() {
        "file_read" => ActivityClass::FileRead,
        "file_write" => ActivityClass::FileWrite,
        "file_delete" => ActivityClass::FileDelete,
        "process_exec" => ActivityClass::ProcessExec,
        "process_fork" => ActivityClass::ProcessFork,
        "network_connect" => ActivityClass::NetworkConnect,
        "network_send" => ActivityClass::NetworkSend,
        "dns_query" => ActivityClass::DnsQuery,
        "credential_access" => ActivityClass::CredentialAccess,
        "privilege_escalation" => ActivityClass::PrivilegeEscalation,
        other => {
            return err_resp(
                StatusCode::BAD_REQUEST,
                format!("Unknown activity class: {other}"),
            )
            .into_response()
        }
    };

    let action = match req.action.as_str() {
        "allow" => BaselineAction::Allow,
        "allow_scoped" => BaselineAction::AllowScoped {
            patterns: req.patterns.unwrap_or_default(),
        },
        "warn" => BaselineAction::Warn,
        "block" => BaselineAction::Block,
        other => {
            return err_resp(StatusCode::BAD_REQUEST, format!("Unknown action: {other}"))
                .into_response()
        }
    };

    let rule = ActivityRule {
        class,
        action,
        description: req.description.unwrap_or_default(),
    };

    if state.observer_engine.update_rule(&id, rule).await {
        let _ = state.audit.append(
            AuditEntryType::PolicyChange,
            serde_json::json!({
                "event": "observer_policy_update",
                "session_id": &id,
                "class": &req.class,
                "action": &req.action,
            }),
        );
        ok("Policy rule updated").into_response()
    } else {
        err_resp(StatusCode::NOT_FOUND, "Session or rule not found").into_response()
    }
}

/// GET /api/v1/observer/profiles — list all available default profiles
async fn list_observer_profiles() -> impl IntoResponse {
    let profiles = ObserverEngine::list_profiles();
    Json(serde_json::to_value(&profiles).unwrap_or_default())
}

#[derive(Deserialize)]
struct ViolationsQuery {
    #[serde(default = "default_violation_limit")]
    limit: usize,
}
fn default_violation_limit() -> usize {
    50
}

/// GET /api/v1/observer/violations — recent baseline violations across all sessions
async fn get_observer_violations(
    State(state): State<ApiState>,
    Query(q): Query<ViolationsQuery>,
) -> impl IntoResponse {
    let violations = state.observer_engine.recent_violations(q.limit).await;
    Json(serde_json::to_value(&violations).unwrap_or_default())
}

// ── Agent Identity handlers (Phase 5) ────────────────────────────────────────

/// GET /api/v1/agent-identity — list all active agent identities (summary view)
async fn list_agent_identities(State(state): State<ApiState>) -> impl IntoResponse {
    state.sessions.expire_stale();
    let summaries =
        identity::build_all_identities(&state.sessions, &state.observer_engine, &state.dlp).await;

    tracing::debug!(count = summaries.len(), "Agent identity list requested");

    Json(serde_json::json!({
        "count":      summaries.len(),
        "identities": summaries,
    }))
}

/// GET /api/v1/agent-identity/:session_id — full agent identity for a session
async fn get_agent_identity(
    State(state): State<ApiState>,
    Path(session_id): Path<String>,
) -> impl IntoResponse {
    let session = match state.sessions.get(&session_id) {
        Some(s) => s,
        None => return err_resp(StatusCode::NOT_FOUND, "session not found").into_response(),
    };

    let identity = identity::build_agent_identity(
        &session,
        &state.sessions,
        &state.observer_engine,
        &state.dlp,
    )
    .await;

    tracing::info!(
        session_id = %session_id,
        agent_type = %identity.agent.agent_type,
        risk_score = identity.risk_score,
        "Agent identity requested"
    );

    Json(identity).into_response()
}

// ── Attack chain correlation (Phase 6) ──────────────────────────────────────

#[derive(Deserialize)]
struct AttackChainQuery {
    #[serde(default = "default_chain_limit")]
    limit: usize,
}
fn default_chain_limit() -> usize {
    100
}

/// GET /api/v1/attack-chains — list all recently detected attack chains
async fn get_attack_chains(
    State(state): State<ApiState>,
    Query(q): Query<AttackChainQuery>,
) -> impl IntoResponse {
    let chains = state.correlation_engine.recent_chains(q.limit).await;
    Json(serde_json::to_value(&chains).unwrap_or_default())
}

/// GET /api/v1/attack-chains/:session_id — chains for a specific session
async fn get_session_attack_chains(
    State(state): State<ApiState>,
    Path(session_id): Path<String>,
    Query(q): Query<AttackChainQuery>,
) -> impl IntoResponse {
    let chains = state
        .correlation_engine
        .chains_for_session(&session_id, q.limit)
        .await;
    Json(serde_json::to_value(&chains).unwrap_or_default())
}

/// GET /api/v1/attack-patterns — list all registered attack patterns (for UI display)
async fn list_attack_patterns(State(state): State<ApiState>) -> impl IntoResponse {
    let patterns = state.correlation_engine.list_patterns();
    Json(serde_json::to_value(&patterns).unwrap_or_default())
}

// ── Enforcement config handlers ─────────────────────────────────────────────

/// GET /api/v1/enforcement — returns current enforcement config
async fn get_enforcement_config(State(_state): State<ApiState>) -> impl IntoResponse {
    let cfg = crate::config::DaemonConfig::load();
    Json(serde_json::to_value(&cfg.enforcement).unwrap_or_default())
}

/// POST /api/v1/enforcement — updates enforcement config (writes to daemon.toml, reloads)
async fn update_enforcement_config(
    State(state): State<ApiState>,
    Json(new_enforcement): Json<crate::config::EnforcementSection>,
) -> impl IntoResponse {
    // Load the full config, update the enforcement section, write back.
    // Strict load: if the on-disk file is invalid we must not replace it with
    // defaults + this section (that would silently drop mode/DLP/webhooks).
    let mut cfg = match crate::config::DaemonConfig::load_strict() {
        Ok(c) => c,
        Err(e) => {
            tracing::error!(err = %e, "Refusing to rewrite an invalid daemon.toml");
            return (
                StatusCode::CONFLICT,
                Json(serde_json::json!({
                    "error": format!("daemon.toml is invalid; fix it by hand first: {}", e)
                })),
            )
                .into_response();
        }
    };
    let previous = serde_json::to_value(&cfg.enforcement).unwrap_or(serde_json::Value::Null);
    cfg.enforcement = new_enforcement;

    let path = crate::config::config_path();
    match toml::to_string_pretty(&cfg) {
        Ok(toml_str) => {
            if let Some(parent) = path.parent() {
                let _ = std::fs::create_dir_all(parent);
            }
            match write_config_file(&path, &toml_str) {
                Ok(_) => {
                    // An operator changing enforcement is exactly the event the
                    // audit log exists for. Record it in the hash chain with the
                    // before and after, so "who turned this off, and when" has an
                    // answer that is not just a log line.
                    state.audit.try_append(
                        AuditEntryType::PolicyChange,
                        serde_json::json!({
                            "action": "update_enforcement",
                            "before": previous,
                            "after":  serde_json::to_value(&cfg.enforcement)
                                .unwrap_or(serde_json::Value::Null),
                            "path":   path.display().to_string(),
                        }),
                    );
                    tracing::warn!(path = %path.display(), "Enforcement config updated by operator");
                    Json(serde_json::json!({
                        "status": "ok",
                        "message": "Enforcement config saved. Send SIGHUP to reload."
                    }))
                    .into_response()
                }
                Err(e) => {
                    tracing::error!(err = %e, "Failed to write enforcement config");
                    (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(serde_json::json!({"error": format!("write failed: {}", e)})),
                    )
                        .into_response()
                }
            }
        }
        Err(e) => {
            tracing::error!(err = %e, "Failed to serialize config");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": format!("serialize failed: {}", e)})),
            )
                .into_response()
        }
    }
}

/// Write daemon.toml atomically (temp file + rename) with 0640 perms and
/// O_NOFOLLOW. The file can hold webhook/SIEM secrets, so it must never be
/// created world-readable, and a crash mid-write must not leave it truncated.
fn write_config_file(path: &std::path::Path, content: &str) -> std::io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let tmp = path.with_extension("toml.tmp");
    let _ = std::fs::remove_file(&tmp);
    let mut f = std::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o640)
        .custom_flags(nix::libc::O_NOFOLLOW)
        .open(&tmp)?;
    f.write_all(content.as_bytes())?;
    f.sync_all()?;
    drop(f);
    std::fs::rename(&tmp, path)
}

// ── File access rules (E2E kernel enforcement) ──────────────────────────────

const FILE_ACCESS_RULES_PATH: &str = "/etc/ringzero/file-access-rules.json";

#[derive(Debug, Clone, Serialize, Deserialize)]
struct FileAccessRule {
    id: String,
    pattern: String,
    action: String, // "allow" or "block"
    source: String, // "template" or "custom"
    /// What this rule is about: "file" or "dir".
    ///
    /// A real field, because this used to be decided by whether the literal
    /// string "[dir-block]" appeared in `description` — so a rule's behaviour
    /// depended on a human note, and any save path that dropped the note
    /// silently disarmed it. Absent on rules written before the field existed;
    /// `file_rule::infer_kind` fills it in on the way through, and it is
    /// written back so it is only ever inferred once.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    kind: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    description: Option<String>,
}

/// GET /api/v1/file-access-rules — returns persisted file access rules
async fn get_file_access_rules(State(_state): State<ApiState>) -> impl IntoResponse {
    use crate::policy::file_rule;

    let rules: Vec<FileAccessRule> = match std::fs::read_to_string(FILE_ACCESS_RULES_PATH) {
        Ok(data) => serde_json::from_str(&data).unwrap_or_default(),
        Err(_) => Vec::new(),
    };

    // Every rule is returned with what it actually is and whether the kernel
    // can hold it right now. A caller that renders "BLOCK" next to a rule the
    // kernel is not holding is the failure this exists to stop, so the answer
    // is in the payload rather than left to be guessed.
    let mut out = Vec::with_capacity(rules.len());
    for r in rules {
        let mut legacy = false;
        let kind = file_rule::infer_kind(
            &r.pattern,
            r.kind.as_deref(),
            r.description.as_deref(),
            &mut legacy,
        );
        let status = file_rule::status(&r.pattern, kind, &r.action);
        let mut v = serde_json::to_value(&r).unwrap_or_else(|_| serde_json::json!({}));
        if let Some(obj) = v.as_object_mut() {
            obj.insert("kind".into(), serde_json::json!(kind.as_str()));
            obj.insert("status".into(), serde_json::json!(status.as_str()));
            if status == file_rule::Status::Unresolved {
                obj.insert(
                    "status_reason".into(),
                    serde_json::json!(file_rule::unresolved_reason(&r.pattern, kind)),
                );
            }
            if legacy {
                obj.insert("kind_from_legacy_marker".into(), serde_json::json!(true));
            }
        }
        out.push(v);
    }
    Json(serde_json::json!({ "rules": out })).into_response()
}

/// POST /api/v1/file-access-rules — saves rules, pushes block entries to eBPF
async fn update_file_access_rules(
    State(state): State<ApiState>,
    Json(body): Json<serde_json::Value>,
) -> impl IntoResponse {
    let rules: Vec<FileAccessRule> = match serde_json::from_value(body["rules"].clone()) {
        Ok(r) => r,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": format!("invalid rules: {}", e)})),
            )
                .into_response()
        }
    };

    // Same guard as POST /policy block_file: a basename block of "bash" or
    // "libc.so.6" would brick every monitored agent, so refuse it here too.
    for rule in &rules {
        if rule.action == "block" {
            for name in pattern_to_basenames(&rule.pattern) {
                if let Some(reason) = crate::analyzer::rule_compiler::dangerous_path(&name) {
                    return (
                        StatusCode::BAD_REQUEST,
                        Json(serde_json::json!({
                            "error": format!("refused to block '{}': {}", rule.pattern, reason)
                        })),
                    )
                        .into_response();
                }
            }
        }
    }

    // NOTHING IS STORED THAT CANNOT ENFORCE.
    //
    // A rule whose shape no kernel mechanism can act on used to be accepted,
    // persisted and then listed as BLOCK while doing nothing at all. It is now
    // refused here, with the reason, before anything is written. `kind` is
    // resolved at the same time and written back, so the guess happens once and
    // the stored rule says what it is.
    let mut rules = rules;
    let mut legacy_marker_seen = false;
    for rule in &mut rules {
        let mut legacy = false;
        let kind = crate::policy::file_rule::infer_kind(
            &rule.pattern,
            rule.kind.as_deref(),
            rule.description.as_deref(),
            &mut legacy,
        );
        legacy_marker_seen |= legacy;
        if let Err(reason) = crate::policy::file_rule::validate(&rule.pattern, kind, &rule.action) {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "error": reason,
                    "pattern": rule.pattern,
                    "kind": kind.as_str(),
                })),
            )
                .into_response();
        }
        rule.kind = Some(kind.as_str().to_string());
    }

    // NO TWO ROWS MAY DO THE SAME THING.
    //
    // Repeating an add used to append another row, so a list could hold four
    // rules blocking one path. Removing one of them left the path blocked,
    // which reads as "remove is broken" to anyone who cannot see the other
    // three. Identity is the resolved target plus action plus kind, so
    // `~/projects/*` and `/home/dev/projects/*` collapse into one. The
    // description is not part of identity: a later add with a better note
    // updates the note rather than adding a row.
    let mut deduped: Vec<FileAccessRule> = Vec::with_capacity(rules.len());
    let mut dropped = 0usize;
    for rule in rules {
        let kind = crate::policy::file_rule::Kind::parse(rule.kind.as_deref().unwrap_or("file"))
            .unwrap_or(crate::policy::file_rule::Kind::File);
        let id = crate::policy::file_rule::identity(&rule.pattern, kind, &rule.action);
        tracing::debug!(pattern = %rule.pattern, kind = kind.as_str(), resolved = %id.0, "file-access rule identity");
        let existing = deduped.iter_mut().find(|r| {
            let k = crate::policy::file_rule::Kind::parse(r.kind.as_deref().unwrap_or("file"))
                .unwrap_or(crate::policy::file_rule::Kind::File);
            crate::policy::file_rule::identity(&r.pattern, k, &r.action) == id
        });
        match existing {
            Some(first) => {
                // Keep the first row and its id, so anything holding that id
                // still works. Take a description if this one has one and the
                // first did not, or if it differs: the later word wins.
                if rule.description.is_some() && rule.description != first.description {
                    first.description = rule.description.clone();
                }
                dropped += 1;
            }
            None => deduped.push(rule),
        }
    }
    if dropped > 0 {
        tracing::info!(
            dropped,
            kept = deduped.len(),
            "file-access rules: collapsed duplicate rules that resolve to the same target"
        );
    }
    let rules = deduped;

    if legacy_marker_seen {
        // One line, once per save, for as long as we still read the old
        // marker. It is going away in a later release.
        tracing::warn!(
            "file-access rules: a rule still relies on the legacy \"[dir-block]\" description \
             marker to mean a directory. It has been rewritten with kind = \"dir\". Support for \
             the marker will be removed."
        );
    }

    // Persist to disk
    let path = std::path::Path::new(FILE_ACCESS_RULES_PATH);
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    match serde_json::to_string_pretty(&rules) {
        Ok(json_str) => {
            if let Err(e) = std::fs::write(path, &json_str) {
                tracing::error!(err = %e, "Failed to write file access rules");
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({"error": format!("write failed: {}", e)})),
                )
                    .into_response();
            }
        }
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": format!("serialize failed: {}", e)})),
            )
                .into_response()
        }
    }

    // Push block rules to eBPF kernel map
    if let Some(ref ebpf_fn) = state.ebpf_block_file {
        let mut blocked_count = 0usize;
        for rule in &rules {
            if rule.action == "block" && !rule.pattern.is_empty() {
                // A concrete absolute path (no glob) is pushed as-is: the eBPF
                // side then pins the file's (dev, ino) identity as well as its
                // basename, so a hardlink or rename under another name is
                // still refused. Globs and bare names reduce to basenames.
                let expanded = expand_rule_tilde(rule.pattern.trim());
                if expanded.starts_with('/') && !expanded.contains(['*', '?', '[']) {
                    ebpf_fn(expanded, true);
                    blocked_count += 1;
                    continue;
                }
                let basenames = pattern_to_basenames(&rule.pattern);
                for basename in &basenames {
                    ebpf_fn(basename.clone(), true);
                    blocked_count += 1;
                }
            }
        }
        tracing::info!(
            count = blocked_count,
            "File access rules: pushed {} blocks to eBPF",
            blocked_count
        );
    }

    // Push allowed directory rules to eBPF for directory restriction
    if let Some(ref dir_fn) = state.ebpf_set_allowed_dir {
        let allowed_dirs: Vec<&str> = rules
            .iter()
            .filter(|r| r.action == "allow" && !r.pattern.is_empty())
            .map(|r| r.pattern.as_str())
            .collect();

        if allowed_dirs.is_empty() {
            dir_fn(String::new());
        } else {
            for dir_pattern in &allowed_dirs {
                let dir_path =
                    expand_rule_tilde(dir_pattern.trim_end_matches("/*").trim_end_matches('/'));
                dir_fn(dir_path);
            }
        }
    }

    // Push blocked directory rules to eBPF — blocks ALL files inside specified dirs
    if let Some(ref block_dir_fn) = state.ebpf_block_dir {
        // By kind. The description is a human note and decides nothing.
        let blocked_dirs: Vec<&str> = rules
            .iter()
            .filter(|r| r.action == "block" && r.kind.as_deref() == Some("dir"))
            .map(|r| r.pattern.as_str())
            .collect();

        if blocked_dirs.is_empty() {
            block_dir_fn(String::new()); // clear
        } else {
            for dir_pattern in &blocked_dirs {
                let dir_path =
                    expand_rule_tilde(dir_pattern.trim_end_matches("/*").trim_end_matches('/'));
                block_dir_fn(dir_path);
            }
        }
    }

    let _ = state.audit.append(
        AuditEntryType::PolicyChange,
        serde_json::json!({"action": "update_file_access_rules", "rule_count": rules.len()}),
    );

    Json(serde_json::json!({
        "status": "ok",
        "message": format!("{} file access rules saved and enforced", rules.len()),
    }))
    .into_response()
}

/// Convert a glob pattern to concrete basenames for the eBPF blocked_files map.
/// The kernel map is keyed by basename (d_name.name), so we expand common patterns.
/// Expand `~` to actual user home dir. Daemon runs as root so $HOME=/root,
/// but user rules use `~` meaning the operator's home. Scan /home/*.
fn expand_rule_tilde(path: &str) -> String {
    if !path.starts_with('~') {
        return path.to_string();
    }
    if let Ok(entries) = std::fs::read_dir("/home") {
        for entry in entries.flatten() {
            if entry.path().is_dir() {
                let candidate = path.replacen("~", &entry.path().to_string_lossy(), 1);
                if std::path::Path::new(&candidate).exists() {
                    return candidate;
                }
            }
        }
    }
    // Fallback
    path.replacen(
        "~",
        &std::env::var("HOME").unwrap_or_else(|_| "/root".into()),
        1,
    )
}

pub fn pattern_to_basenames(pattern: &str) -> Vec<String> {
    let mut names = Vec::new();
    let pat = pattern.trim();

    // "~/.ssh/*" → block known SSH key basenames
    if pat.contains(".ssh") {
        // Note: "config" deliberately excluded — too generic a basename,
        // blocks every config file on the system (cursor config, npm, git, etc.)
        for name in [
            "id_rsa",
            "id_ed25519",
            "id_ecdsa",
            "id_dsa",
            "known_hosts",
            "authorized_keys",
        ] {
            names.push(name.to_string());
        }
        return names;
    }

    // "~/.aws/*" → block AWS credential files
    // "config" excluded — too generic; "credentials" is unique enough
    if pat.contains(".aws") {
        names.push("credentials".to_string());
        return names;
    }

    // "~/.kube/*" → basename "config" is too generic to block system-wide.
    // Kube config protection relies on the inode-based block (blocked_inodes)
    // which pins ~/.kube/config specifically. Skip basename expansion here.
    if pat.contains(".kube") {
        return names; // empty — protected via inode, not basename
    }

    // ".git-credentials" → exact basename
    if pat == ".git-credentials" {
        names.push(".git-credentials".to_string());
        return names;
    }

    // ".env*" or "*.env" patterns → block .env variants
    if pat.starts_with(".env") || pat.ends_with(".env") {
        for name in [
            ".env",
            ".env.local",
            ".env.production",
            ".env.development",
            ".env.staging",
        ] {
            names.push(name.to_string());
        }
        return names;
    }

    // "*.pem", "*.key", "*.p12", "*.pfx" — extension-based patterns
    // eBPF can only match basenames, not extensions. We log these as best-effort.
    // For now, these are caught by the daemon's userspace ACL, not kernel.
    if pat.starts_with("*.") {
        // Can't do extension matching in eBPF basename map — skip silently.
        // These are still caught by userspace policy.
        return names;
    }

    // Direct basename or path — extract the basename
    let basename = pat.rsplit('/').next().unwrap_or(pat);
    if !basename.is_empty() && basename != "*" && basename != "**" {
        names.push(basename.to_string());
    }

    names
}

// ── Skill↔Runtime correlated threats (Phase 3) ─────────────────────────────

#[derive(Deserialize)]
struct CorrelatedThreatsQuery {
    limit: Option<usize>,
}

/// GET /api/v1/correlated-threats?limit=50 — returns recent correlated threats
/// where static skill scan findings match runtime kernel events.
async fn get_correlated_threats(
    State(state): State<ApiState>,
    Query(q): Query<CorrelatedThreatsQuery>,
) -> impl IntoResponse {
    let limit = q.limit.unwrap_or(50).min(1000);
    let threats = state.skill_correlation.recent_threats(limit).await;
    let static_count = state.skill_correlation.static_finding_count().await;
    let categories = state.skill_correlation.loaded_categories().await;

    Json(serde_json::json!({
        "threats": threats,
        "count": threats.len(),
        "static_findings_loaded": static_count,
        "categories_indexed": categories,
    }))
}

// ── Agent hook event receiver ───────────────────────────────────────────────

/// POST /api/v1/hook-event — receives events from agent hooks (Codex, Claude Code)
async fn receive_hook_event(
    State(state): State<ApiState>,
    Json(payload): Json<serde_json::Value>,
) -> impl IntoResponse {
    let hook_event = payload
        .get("hook_event_name")
        .or_else(|| payload.get("type"))
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");

    let session_id = payload
        .get("session_id")
        .and_then(|v| v.as_str())
        .unwrap_or("");

    // Agents' hook payloads don't name the agent; infer it from the shape.
    let inferred_agent = match payload.get("transcript_path").and_then(|v| v.as_str()) {
        Some(p) if p.contains("/.claude/") => "claude",
        Some(p) if p.contains("/.codex/") => "codex",
        Some(p) if p.contains("/.gemini/") => "gemini",
        _ if payload.get("hook_event_name").is_some() => "claude",
        _ => "unknown",
    };
    let agent_type = payload
        .get("agent_type")
        .and_then(|v| v.as_str())
        .unwrap_or(inferred_agent);

    // Extract prompt from user input events
    let prompt = payload
        .get("prompt")
        .or_else(|| payload.get("last_assistant_message"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    // Extract tool calls
    let tool_name = payload
        .get("tool_name")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    tracing::info!(
        hook_event,
        session_id,
        agent_type,
        has_prompt = prompt.is_some(),
        has_tool = tool_name.is_some(),
        "Agent hook event received"
    );

    // Detail carried into `extra` (→ webhook `args`): which hook fired, the
    // tool's input/response (bounded), the agent's cwd and transcript path.
    // Tool inputs are what make these "agent action" events useful: for a
    // Write/Edit that is the file path and content, for Bash the command.
    let cwd = payload
        .get("cwd")
        .and_then(|v| v.as_str())
        .map(String::from);
    let transcript_path = payload
        .get("transcript_path")
        .and_then(|v| v.as_str())
        .map(String::from);
    let tool_input = payload
        .get("tool_input")
        .cloned()
        .map(|v| truncate_json(v, 16 * 1024));
    let tool_response = payload
        .get("tool_response")
        .cloned()
        .map(|v| truncate_json(v, 16 * 1024));
    let action_class = tool_name.as_deref().map(classify_tool_action);

    // ── Checks ──────────────────────────────────────────────────────────────
    // Score what this tool call is about to do. This runs here, on the hook
    // path, NOT in the kernel: nothing below can allow or deny a syscall. A
    // result is an observation written into the trace and joined to the
    // kernel's real decision by session id.
    //
    // When [checks] blocking = true this ALSO produces a decision the hook
    // acts on. Two bounds matter and are enforced below:
    //
    //   1. The deterministic floor runs first and GATES the model call. An
    //      ordinary tool call adds zero network latency, because a benign
    //      local result short-circuits before any request is made.
    //   2. Monotonic in one direction only: the model may turn an allow into a
    //      deny; it can never turn a deterministic deny into an allow.
    let mut decision_deny = false;
    let mut decision_rule: Option<String> = None;
    let mut decision_provider = "deterministic";
    let mut decision_latency_ms: u64 = 0;
    let mut decision_from_cache = false;
    let mut decision_fail_mode: Option<&str> = None;

    let check_results: Vec<ringzero_checks::CheckResult> = if let Some(provider) =
        state.checks_provider.clone()
    {
        let mut out = Vec::new();
        if let (Some(tool), Some(input)) = (tool_name.as_deref(), tool_input.as_ref()) {
            let blocking = state.checks_cfg.blocking;
            let cache_ttl = std::time::Duration::from_secs(state.checks_cfg.cache_ttl_secs.max(1));
            let cache_key = decision_cache_key(tool, input);

            if blocking {
                if let Some((deny, rule)) = decision_cache_get(&cache_key, cache_ttl) {
                    decision_deny = deny;
                    decision_rule = rule;
                    decision_from_cache = true;
                }
            }

            // The local scorer always runs: it is microseconds, it is the floor,
            // and it decides whether the model is worth calling at all.
            let local_risk = ringzero_checks::tool_call_argument_risk(
                tool,
                input,
                state.checks_cfg.workspace.as_deref(),
                &state.checks_cfg.approved_hosts,
            );
            let local_exposure = ringzero_checks::sensitive_data_exposure(&input.to_string());
            let local_flagged = local_risk.is_flag() || local_exposure.is_flag();

            if blocking && !decision_from_cache && local_flagged {
                // Blocking is on and something local looks wrong, so a scorer
                // call is justified. A benign call never reaches this branch,
                // and with blocking off no synchronous model call is made at
                // all — the hook stays fire-and-forget with zero added latency.
                let task_hash = prompt.as_ref().map(|p| {
                    let h = blake3::hash(p.as_bytes());
                    h.to_hex().to_string()[..16].to_string()
                });
                let tool_s = tool.to_string();
                let input_c = input.clone();
                let workspace = state.checks_cfg.workspace.clone();
                let hosts = state.checks_cfg.approved_hosts.clone();
                let budget = std::time::Duration::from_millis(state.checks_cfg.timeout_ms.max(100));

                let started = std::time::Instant::now();
                // Hard bound: whatever the provider does, the hook is released
                // when the budget expires. A developer's agent is never hung.
                let scored = tokio::time::timeout(
                    budget,
                    tokio::task::spawn_blocking(move || {
                        provider.score_tool_call(
                            &tool_s,
                            &input_c,
                            workspace.as_deref(),
                            &hosts,
                            task_hash.as_deref(),
                        )
                    }),
                )
                .await;
                decision_latency_ms = started.elapsed().as_millis() as u64;

                match scored {
                    Ok(Ok((risk, exposure))) => {
                        decision_provider = if risk.provider == "jev" || exposure.provider == "jev"
                        {
                            "jev"
                        } else {
                            "deterministic"
                        };
                        // The provider absorbs its own timeouts and transport
                        // errors into a deterministic fallback and sets
                        // `provider_error`. That is the fail_mode situation: the
                        // MODEL could not answer a call the floor gated to it.
                        let model_unavailable =
                            risk.provider_error.is_some() || exposure.provider_error.is_some();
                        if blocking {
                            if model_unavailable {
                                decision_fail_mode = Some(if state.checks_cfg.fail_closed() {
                                    "closed"
                                } else {
                                    "open"
                                });
                                decision_deny = state.checks_cfg.fail_closed();
                                decision_rule = Some(
                                    risk.provider_error
                                        .clone()
                                        .or_else(|| exposure.provider_error.clone())
                                        .unwrap_or_else(|| "scorer_unavailable".to_string()),
                                );
                            } else if risk.is_flag() {
                                // The model answered and confirmed the flag.
                                decision_deny = true;
                                decision_rule = Some(risk.option.clone());
                            } else if exposure.is_flag() {
                                decision_deny = true;
                                decision_rule = Some(exposure.option.clone());
                            }
                        }
                        out.push(risk);
                        out.push(exposure);
                    }
                    Ok(Err(e)) => {
                        tracing::warn!(err = %e, "Check scoring task failed");
                        if blocking {
                            decision_fail_mode = Some(if state.checks_cfg.fail_closed() {
                                "closed"
                            } else {
                                "open"
                            });
                            decision_deny = state.checks_cfg.fail_closed();
                            decision_rule = Some("scorer_unavailable".to_string());
                        }
                        out.push(local_risk.clone());
                        out.push(local_exposure.clone());
                    }
                    Err(_) => {
                        // Timed out. fail_mode decides, and the trace says so.
                        tracing::warn!(
                            timeout_ms = state.checks_cfg.timeout_ms,
                            "Check scoring timed out; fail_mode decides"
                        );
                        if blocking {
                            decision_fail_mode = Some(if state.checks_cfg.fail_closed() {
                                "closed"
                            } else {
                                "open"
                            });
                            decision_deny = state.checks_cfg.fail_closed();
                            decision_rule = Some("scorer_timeout".to_string());
                        }
                        out.push(local_risk.clone());
                        out.push(local_exposure.clone());
                    }
                }
            } else if !decision_from_cache {
                // Either benign, or blocking is off: no synchronous model call,
                // no network, no added latency. The deterministic result still
                // reaches the trace.
                out.push(local_risk.clone());
                out.push(local_exposure.clone());
            }

            // Monotonicity, the direction that matters: the model may raise an
            // allow to a deny, and it may never lower a deterministic deny to an
            // allow. The floor's job here is to GATE the model call, not to
            // decide by itself — otherwise a flagged call would always deny and
            // fail_mode would be dead code. The one exception is a hard local
            // deny: reading a credential path is a standalone deny the model is
            // not allowed to clear.
            if blocking && !decision_from_cache {
                let hard_local_deny = local_risk.option == "reads_sensitive_path"
                    || local_exposure.option == "secret_pattern_matched";
                if hard_local_deny {
                    decision_deny = true;
                    if decision_rule.is_none() {
                        decision_rule = Some(if local_risk.option == "reads_sensitive_path" {
                            local_risk.option.clone()
                        } else {
                            local_exposure.option.clone()
                        });
                    }
                }
            }

            if blocking && !decision_from_cache {
                decision_cache_put(&cache_key, decision_deny, decision_rule.clone());
            }

            // Anything not benign goes to a human with the trace attached.
            for r in out.iter().filter(|r| r.is_flag()) {
                // `confidence` is optional: a `noul` answers with a
                // probability alone, and absent is not the same as 0.0.
                let conf = r
                    .confidence
                    .map(|c| format!("{c:.2}"))
                    .unwrap_or_else(|| "n/a".to_string());
                let summary = format!(
                    "check {} scored {} (p={:.2}, confidence={})",
                    r.check, r.option, r.probability, conf
                );
                if let Err(e) = state.review.push(
                    crate::review::Source::CheckFlag,
                    session_id,
                    summary,
                    serde_json::json!({
                        "check": r,
                        "tool": tool_name,
                        "agent_type": agent_type,
                        "hook_event": hook_event,
                        "decision": if decision_deny { "deny" } else { "allow" },
                    }),
                ) {
                    tracing::warn!(err = %e, "Could not queue check flag for review");
                }
            }
        }
        out
    } else {
        Vec::new()
    };
    let hook_extra = |phase: &str| -> serde_json::Value {
        let mut m = serde_json::Map::new();
        m.insert("hook".into(), serde_json::json!(hook_event));
        m.insert("phase".into(), serde_json::json!(phase));
        if let Some(c) = &cwd {
            m.insert("cwd".into(), serde_json::json!(c));
        }
        if let Some(t) = &transcript_path {
            m.insert("transcript_path".into(), serde_json::json!(t));
        }
        if !session_id.is_empty() {
            m.insert("agent_session_id".into(), serde_json::json!(session_id));
        }
        if let Some(a) = &action_class {
            m.insert("action".into(), serde_json::json!(a));
        }
        if let Some(t) = &tool_input {
            m.insert("tool_input".into(), t.clone());
        }
        if let Some(t) = &tool_response {
            m.insert("tool_response".into(), t.clone());
        }
        if !check_results.is_empty() {
            m.insert(
                "checks".into(),
                serde_json::to_value(&check_results).unwrap_or(serde_json::Value::Null),
            );
        }
        // Everything an operator needs to answer "why did my tool call stall",
        // from the trace alone.
        if state.checks_cfg.blocking {
            let mut d = serde_json::Map::new();
            d.insert(
                "decision".into(),
                serde_json::json!(if decision_deny { "deny" } else { "allow" }),
            );
            d.insert("provider".into(), serde_json::json!(decision_provider));
            d.insert("latency_ms".into(), serde_json::json!(decision_latency_ms));
            d.insert("blocked".into(), serde_json::json!(decision_deny));
            d.insert("from_cache".into(), serde_json::json!(decision_from_cache));
            if let Some(r) = &decision_rule {
                d.insert("rule".into(), serde_json::json!(r));
            }
            if let Some(fm) = decision_fail_mode {
                // The scorer could not answer, so fail_mode decided, not the model.
                d.insert("fail_mode_applied".into(), serde_json::json!(fm));
            }
            m.insert("hook_decision".into(), serde_json::Value::Object(d));
        }
        serde_json::Value::Object(m)
    };
    let record = |ev: crate::common::event::SecurityEvent| {
        let _ = state.timeline.insert(&ev);
        // Broadcast so the desktop app, the CLI stream and the webhook event
        // stream see hook events too (previously they only reached the timeline).
        state
            .ipc
            .broadcast(crate::common::protocol::DaemonMessage::Event { payload: ev });
    };

    // Emit as SecurityEvent based on event type
    match hook_event {
        "UserPromptSubmit" | "UserInput" | "user_input" => {
            if let Some(ref text) = prompt {
                let ev = crate::common::event::SecurityEvent {
                    id: format!(
                        "hook-{}-{}",
                        session_id,
                        chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0)
                    ),
                    kind: crate::common::event::EventKind::LlmRequest,
                    pid: 0,
                    uid: 0,
                    process: agent_type.to_string(),
                    target: format!("{}:hook", agent_type),
                    allowed: true,
                    reason: None,
                    timestamp: chrono::Utc::now(),
                    ppid: None,
                    parent_process: None,
                    llm_context: Some(crate::common::event::LlmContext {
                        provider: agent_type.to_string(),
                        model: None,
                        response_text: Some(text.clone()),
                        tool_call: None,
                        usage: None,
                        response_ts: chrono::Utc::now(),
                    }),
                    extra: Some(hook_extra("prompt")),
                };
                record(ev);
            }
        }
        "MessageReceived" | "assistant_message" | "response.completed" => {
            if let Some(ref text) = prompt {
                let ev = crate::common::event::SecurityEvent {
                    id: format!(
                        "hook-resp-{}-{}",
                        session_id,
                        chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0)
                    ),
                    kind: crate::common::event::EventKind::LlmResponse,
                    pid: 0,
                    uid: 0,
                    process: agent_type.to_string(),
                    target: format!("{}:hook", agent_type),
                    allowed: true,
                    reason: None,
                    timestamp: chrono::Utc::now(),
                    ppid: None,
                    parent_process: None,
                    llm_context: Some(crate::common::event::LlmContext {
                        provider: agent_type.to_string(),
                        model: None,
                        response_text: Some(text.clone()),
                        tool_call: None,
                        usage: None,
                        response_ts: chrono::Utc::now(),
                    }),
                    extra: Some(hook_extra("response")),
                };
                record(ev);
            }
        }
        "ToolCall" | "tool_call" | "PreToolUse" | "PostToolUse" => {
            if let Some(ref tool) = tool_name {
                let ev = crate::common::event::SecurityEvent {
                    id: format!(
                        "hook-tool-{}-{}",
                        session_id,
                        chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0)
                    ),
                    kind: crate::common::event::EventKind::LlmToolCall,
                    pid: 0,
                    uid: 0,
                    process: agent_type.to_string(),
                    target: tool.clone(),
                    allowed: true,
                    reason: None,
                    timestamp: chrono::Utc::now(),
                    ppid: None,
                    parent_process: None,
                    llm_context: Some(crate::common::event::LlmContext {
                        provider: agent_type.to_string(),
                        model: None,
                        response_text: None,
                        tool_call: Some(tool.clone()),
                        usage: None,
                        response_ts: chrono::Utc::now(),
                    }),
                    extra: Some(hook_extra(if hook_event == "PostToolUse" {
                        "post"
                    } else {
                        "pre"
                    })),
                };
                record(ev);
            }
        }
        "Stop" | "stop" | "response.completed" => {
            // Stop event has last_assistant_message — the full response
            let response = payload
                .get("last_assistant_message")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());
            if let Some(ref text) = response {
                let ev = crate::common::event::SecurityEvent {
                    id: format!(
                        "hook-stop-{}-{}",
                        session_id,
                        chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0)
                    ),
                    kind: crate::common::event::EventKind::LlmResponse,
                    pid: 0,
                    uid: 0,
                    process: agent_type.to_string(),
                    target: format!("{}:hook", agent_type),
                    allowed: true,
                    reason: None,
                    timestamp: chrono::Utc::now(),
                    ppid: None,
                    parent_process: None,
                    llm_context: Some(crate::common::event::LlmContext {
                        provider: agent_type.to_string(),
                        model: payload
                            .get("model")
                            .and_then(|v| v.as_str())
                            .map(|s| s.to_string()),
                        response_text: Some(text.clone()),
                        tool_call: None,
                        usage: None,
                        response_ts: chrono::Utc::now(),
                    }),
                    extra: Some(hook_extra("response")),
                };
                record(ev);
            }
        }
        "SessionStart" | "session_start" => {
            tracing::info!(session_id, agent_type, "Agent session started via hook");
        }
        _ => {
            // Log unknown events for debugging
            tracing::debug!(hook_event, "Unhandled hook event type");
        }
    }

    // The hook reads `decision`. When blocking is off this is always "allow"
    // and the hook stays fire-and-forget.
    //
    // `reason` is what the harness shows the model. Per Claude Code's hook
    // documentation (code.claude.com/docs/en/hooks), Claude Code "reads the
    // JSON decision, blocks the tool call, and shows Claude the reason", so an
    // agent that is told the rule name learns the path is out of policy and
    // stops retrying, instead of writing a binary to get around an opaque
    // refusal. It names the RULE THAT FIRED and nothing else: no allow-list, no
    // policy contents, no protected-path inventory.
    // Only when actually denying: an allow carries no reason for the model.
    let reason = if decision_deny {
        decision_rule.as_deref().map(|rule| {
            format!("Ring Zero policy: {rule}. This tool call is out of policy for this agent.")
        })
    } else {
        None
    };
    Json(serde_json::json!({
        "status": "ok",
        "decision": if decision_deny { "deny" } else { "allow" },
        "rule": decision_rule,
        "reason": reason,
        "provider": decision_provider,
        "latency_ms": decision_latency_ms,
        "fail_mode_applied": decision_fail_mode,
    }))
}

/// Normalize an agent tool name into a coarse action class so integrators can
/// route on "the agent wrote a file" without knowing every agent's tool names.
fn classify_tool_action(tool: &str) -> &'static str {
    let t = tool.to_ascii_lowercase();
    match t.as_str() {
        "read" | "read_file" | "view" | "cat" | "notebookread" => "file_read",
        "write" | "write_file" | "create_file" | "notebookedit" => "file_write",
        "edit" | "multiedit" | "apply_patch" | "str_replace_editor" | "replace" => "file_edit",
        "bash" | "shell" | "exec_command" | "run_command" | "terminal" | "execute" | "run" => {
            "process_exec"
        }
        "glob" | "grep" | "ls" | "search" | "find" | "list_directory" => "file_search",
        "webfetch" | "websearch" | "fetch" | "http" | "browser" => "network",
        "task" | "agent" | "subagent" => "delegate",
        _ => {
            if t.contains("write") || t.contains("create") {
                "file_write"
            } else if t.contains("edit") || t.contains("patch") {
                "file_edit"
            } else if t.contains("read") || t.contains("view") {
                "file_read"
            } else if t.contains("exec") || t.contains("shell") || t.contains("command") {
                "process_exec"
            } else if t.contains("web") || t.contains("http") || t.contains("fetch") {
                "network"
            } else {
                "other"
            }
        }
    }
}

/// Bound a JSON value carried into an event: any string longer than `max`
/// bytes is cut (on a char boundary) and marked with a trailing "…[truncated]".
fn truncate_json(v: serde_json::Value, max: usize) -> serde_json::Value {
    match v {
        serde_json::Value::String(s) if s.len() > max => {
            let mut cut = max;
            while !s.is_char_boundary(cut) {
                cut -= 1;
            }
            serde_json::Value::String(format!("{}…[truncated {} bytes]", &s[..cut], s.len() - cut))
        }
        serde_json::Value::Array(a) => serde_json::Value::Array(
            a.into_iter()
                .take(256)
                .map(|x| truncate_json(x, max))
                .collect(),
        ),
        serde_json::Value::Object(m) => serde_json::Value::Object(
            m.into_iter()
                .take(256)
                .map(|(k, x)| (k, truncate_json(x, max)))
                .collect(),
        ),
        other => other,
    }
}

// ── Detection webhooks ───────────────────────────────────────────────────────

/// GET /api/v1/webhooks/stats — delivery/verdict counters and the configured
/// endpoint + hook names. Read-only: the webhook config itself is only
/// changeable by editing /etc/ringzero/daemon.toml (root) and reloading.
async fn get_webhook_stats(State(state): State<ApiState>) -> impl IntoResponse {
    Json(state.webhooks.stats())
}

// ── Review queue ────────────────────────────────────────────────────────────

#[derive(Deserialize)]
struct ReviewQuery {
    #[serde(default)]
    limit: Option<usize>,
    /// Default true: the queue is an inbox, so labelled items drop out of it.
    #[serde(default)]
    unlabeled_only: Option<bool>,
}

/// GET /api/v1/review — items waiting for a human label, newest first.
async fn list_review_queue(
    State(s): State<ApiState>,
    Query(q): Query<ReviewQuery>,
) -> impl IntoResponse {
    let items = s.review.list(
        q.limit.unwrap_or(100).min(1000),
        q.unlabeled_only.unwrap_or(true),
    );
    Json(serde_json::json!({ "count": items.len(), "items": items }))
}

/// GET /api/v1/review/stats — how much is waiting, and how labelled items came out.
async fn review_stats(State(s): State<ApiState>) -> impl IntoResponse {
    Json(s.review.stats())
}

#[derive(Deserialize)]
struct LabelRequest {
    label: String,
}

/// POST /api/v1/review/{id}/label — set the human verdict on one item.
async fn label_review_item(
    State(s): State<ApiState>,
    axum::extract::Path(id): axum::extract::Path<String>,
    Json(req): Json<LabelRequest>,
) -> impl IntoResponse {
    let Some(label) = crate::review::Label::parse(&req.label) else {
        return err_resp(
            StatusCode::BAD_REQUEST,
            "label must be benign, real-threat or false-positive",
        )
        .into_response();
    };
    match s.review.label(&id, label) {
        Ok(true) => ok(format!("labelled {id} as {}", req.label)).into_response(),
        Ok(false) => err_resp(StatusCode::NOT_FOUND, "no such review item").into_response(),
        Err(e) => err_resp(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()).into_response(),
    }
}

// ── Token scope ─────────────────────────────────────────────────────────────

/// GET /api/v1/auth/scope — what the caller's own token is allowed to do.
///
/// The desktop app calls this at startup so it can render as a viewer when it
/// holds the read-only token. That is the normal case: the installer leaves the
/// operator a read-only token on purpose, because an AI agent runs as that same
/// user. `mutating_requires` names what a human has to do instead.
async fn auth_scope(State(s): State<ApiState>, headers: HeaderMap) -> impl IntoResponse {
    let token = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .unwrap_or_default();

    // The auth middleware already rejected anything invalid, so a miss here
    // only happens when auth is disabled entirely.
    let scope = s
        .auth
        .validate_scope(token)
        .await
        .map(|sc| sc.wire_name())
        .unwrap_or("readonly");

    Json(serde_json::json!({
        "scope": scope,
        "mutating_requires": if scope == "full" { serde_json::Value::Null }
                             else { serde_json::json!("root (sudo rz ...)") },
    }))
}

// ── Tool-call decision cache ────────────────────────────────────────────────
//
// An agent looping over the same path must not pay for a scorer call each time.
// Keyed on the tool plus its normalised arguments; entries expire quickly so a
// policy change is not masked for long.

struct CachedDecision {
    deny: bool,
    rule: Option<String>,
    at: std::time::Instant,
}

static DECISION_CACHE: std::sync::LazyLock<
    std::sync::Mutex<std::collections::HashMap<String, CachedDecision>>,
> = std::sync::LazyLock::new(|| std::sync::Mutex::new(std::collections::HashMap::new()));

fn decision_cache_key(tool: &str, args: &serde_json::Value) -> String {
    // Normalise by serialising the canonical JSON form, so key order in the
    // harness payload does not produce a cache miss.
    let normalised = serde_json::to_string(args).unwrap_or_default();
    let h = blake3::hash(format!("{tool}\0{normalised}").as_bytes());
    h.to_hex().to_string()[..32].to_string()
}

fn decision_cache_get(key: &str, ttl: std::time::Duration) -> Option<(bool, Option<String>)> {
    let mut map = DECISION_CACHE.lock().ok()?;
    match map.get(key) {
        Some(e) if e.at.elapsed() < ttl => Some((e.deny, e.rule.clone())),
        Some(_) => {
            map.remove(key);
            None
        }
        None => None,
    }
}

fn decision_cache_put(key: &str, deny: bool, rule: Option<String>) {
    if let Ok(mut map) = DECISION_CACHE.lock() {
        // Keep the map from growing without bound on a long-lived daemon.
        if map.len() > 4096 {
            map.clear();
        }
        map.insert(
            key.to_string(),
            CachedDecision {
                deny,
                rule,
                at: std::time::Instant::now(),
            },
        );
    }
}

// ── Checks provider administration ──────────────────────────────────────────

/// GET /api/v1/checks/status — what the checks layer is configured to do.
///
/// Never returns key material. It reports whether a key file is present and
/// what its mode is, because a group-readable key is the mistake worth
/// catching, and the mode is not a secret.
async fn checks_status(State(s): State<ApiState>) -> impl IntoResponse {
    let cfg = &s.checks_cfg;
    let key_path = std::path::Path::new(&cfg.jev.api_key_file);
    let (present, mode, mode_ok) = match std::fs::metadata(key_path) {
        Ok(m) => {
            use std::os::unix::fs::PermissionsExt;
            let bits = m.permissions().mode() & 0o777;
            (true, Some(format!("{bits:o}")), bits & 0o077 == 0)
        }
        Err(_) => (false, None, false),
    };
    Json(serde_json::json!({
        "enabled": cfg.enabled,
        "provider": cfg.provider,
        "running_provider": s.checks_provider.as_ref().map(|p| p.name()),
        "endpoint": format!("{}/v1/systemone", cfg.jev.base_url.trim_end_matches('/')),
        "model": cfg.jev.model,
        "timeout_ms": cfg.jev.timeout_ms,
        "key_file": cfg.jev.api_key_file,
        "key_present": present,
        "key_mode": mode,
        "key_mode_ok": mode_ok,
        "workspace": cfg.workspace,
        "approved_hosts": cfg.approved_hosts,
    }))
}

/// POST /api/v1/checks/verify-key — one live request against the configured
/// provider, using the configured key file.
///
/// Full-scope only. The key is read from the root-owned file and never appears
/// in a request body, a response or a log line.
async fn verify_checks_key(State(s): State<ApiState>) -> impl IntoResponse {
    let cfg = s.checks_cfg.jev.clone();
    let key = match cfg.load_key() {
        Ok(k) => k,
        Err(e) => {
            return Json(serde_json::json!({
                "ok": false, "stage": "key", "error": e
            }))
            .into_response()
        }
    };

    let endpoint = format!("{}/v1/systemone", cfg.base_url.trim_end_matches('/'));
    let model = cfg.model.clone();
    let timeout = std::time::Duration::from_millis(cfg.timeout_ms.max(1000));

    let started = std::time::Instant::now();
    let result = tokio::task::spawn_blocking(move || {
        let client = reqwest::blocking::Client::builder()
            .timeout(timeout)
            .build()
            .map_err(|e| e.to_string())?;
        // A trivial question: enough to prove the key and the contract, cheap
        // enough to run whenever someone asks.
        let body = serde_json::json!({
            "state": {"probe": "ringzero key verification"},
            "model": model,
            "questions": {
                "probe": {
                    "type": "noul",
                    "instructions": "Answer 0.5. This is a connectivity probe.",
                    "criteria": {}
                }
            }
        })
        .to_string();
        let resp = client
            .post(&endpoint)
            .header("Authorization", format!("Bearer {key}"))
            .header("Content-Type", "application/json")
            .body(body)
            .send()
            .map_err(|e| {
                if e.is_timeout() {
                    "timed out".to_string()
                } else {
                    format!("transport error: {e}")
                }
            })?;
        let status = resp.status().as_u16();
        let text = resp.text().unwrap_or_default();
        Ok::<(u16, String), String>((status, text))
    })
    .await;

    let elapsed_ms = started.elapsed().as_millis() as u64;

    match result {
        Ok(Ok((200, text))) => {
            let answered_model = serde_json::from_str::<serde_json::Value>(&text)
                .ok()
                .and_then(|v| v["model"].as_str().map(|m| m.to_string()));
            tracing::info!(elapsed_ms, "Checks provider key verified");
            Json(serde_json::json!({
                "ok": true, "status": 200, "elapsed_ms": elapsed_ms,
                "model": answered_model,
            }))
            .into_response()
        }
        Ok(Ok((401, _))) => Json(serde_json::json!({
            "ok": false, "stage": "auth", "status": 401,
            "error": "the provider rejected this key (401)",
            "elapsed_ms": elapsed_ms,
        }))
        .into_response(),
        Ok(Ok((code, _))) => Json(serde_json::json!({
            "ok": false, "stage": "http", "status": code,
            "error": format!("provider returned HTTP {code}"),
            "elapsed_ms": elapsed_ms,
        }))
        .into_response(),
        Ok(Err(e)) => Json(serde_json::json!({
            "ok": false, "stage": "transport", "error": e, "elapsed_ms": elapsed_ms,
        }))
        .into_response(),
        Err(e) => Json(serde_json::json!({
            "ok": false, "stage": "task", "error": e.to_string(),
        }))
        .into_response(),
    }
}
