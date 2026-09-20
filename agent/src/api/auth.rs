// SPDX-License-Identifier: Apache-2.0
// api/auth.rs — Bearer token authentication middleware
//
// Auth flow:
//   1. On first launch, Tauri app generates a random token and stores in keyring
//   2. App registers token with daemon via POST /api/v1/auth/register (one-time)
//   3. All subsequent requests include Authorization: Bearer <token>
//   4. This middleware validates the token on every request
//   5. /api/v1/health is exempt (healthcheck probes need it)
//
// The token is persisted as a blake3 hash on disk so daemon restarts /
// crashes don't force the UI to re-register from keyring on every boot.

use axum::{
    extract::Request,
    http::{HeaderMap, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Errors that can occur in auth flows.
#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    #[error("A bearer token has already been registered — use the rotate endpoint instead")]
    AlreadyRegistered,
}

/// Authorization scope a bearer token grants (per-consumer scoped tokens
/// instead of one all-powerful shared token). `Full` may mutate
/// policy/enforcement; `ReadOnly` may only read state + run non-mutating scans.
/// The advisory engineer (which reasons over untrusted LLM output) gets a
/// `ReadOnly` token so a prompt-injection can't escalate to a policy change even
/// if the in-process advisory guard were bypassed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scope {
    ReadOnly,
    Full,
}

impl Scope {
    /// Wire name, as reported by GET /api/v1/auth/scope.
    pub fn wire_name(self) -> &'static str {
        match self {
            Scope::ReadOnly => "readonly",
            Scope::Full => "full",
        }
    }

    /// Does a token granted `self` satisfy a request that requires `needed`?
    /// Full satisfies everything; ReadOnly satisfies only ReadOnly.
    fn satisfies(self, needed: Scope) -> bool {
        matches!(
            (self, needed),
            (Scope::Full, _) | (Scope::ReadOnly, Scope::ReadOnly)
        )
    }
}

/// Mutating POSTs would normally need `Full`, but a few POST endpoints are
/// read-only in effect (they trigger a scan / dry-run, not a policy change) and
/// the advisory ReadOnly engineer legitimately calls them. Fail CLOSED: only
/// these exact paths are downgraded to ReadOnly; every other non-GET defaults to
/// requiring Full, so a newly-added mutating endpoint is Full-gated by default.
const READONLY_SAFE_POSTS: &[&str] = &[
    "/api/v1/skill-scan/auto", // inventory agent skill surfaces (read-only scan)
    "/api/v1/dlp/redact",      // redaction dry-run / test (no state change)
];

/// The scope a request requires, from its method + path.
fn required_scope(method: &axum::http::Method, path: &str) -> Scope {
    use axum::http::Method;
    match *method {
        Method::GET | Method::HEAD | Method::OPTIONS => Scope::ReadOnly,
        _ if READONLY_SAFE_POSTS.contains(&path) => Scope::ReadOnly,
        _ => Scope::Full,
    }
}

/// On-disk path where the blake3-hashed token lives. Mode 0600.
///
/// We persist the *hash*, not the raw token. A read of this file lets an
/// attacker know a token exists, but not what it is — they'd still need to
/// brute-force the preimage to forge a request.
fn token_store_path() -> PathBuf {
    // Honor the same elevation logic the rest of the daemon uses so dev
    // runs (`cargo run`) write to a temp dir, not /var/lib.
    if crate::platform::is_elevated() {
        PathBuf::from("/var/lib/ringzero/auth.token")
    } else {
        std::env::temp_dir().join("ringzero-auth.token")
    }
}

/// On-disk store for the READONLY token's hash (mirrors `token_store_path`).
fn readonly_token_store_path() -> PathBuf {
    if crate::platform::is_elevated() {
        PathBuf::from("/var/lib/ringzero/auth-readonly.token")
    } else {
        std::env::temp_dir().join("ringzero-auth-readonly.token")
    }
}

/// Generate a 256-bit token as 64 lowercase-hex chars from the system CSPRNG.
/// Matches the format clients already expect (CLI `generate_token`).
fn generate_raw_token() -> String {
    use std::io::Read;
    let mut bytes = [0u8; 32];
    // /dev/urandom is the same source the CLI uses; on the daemon host it's
    // always present. A short read is effectively impossible for 32 bytes.
    if std::fs::File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut bytes))
        .is_err()
    {
        // Last-resort fallback — extremely unlikely; still 256 bits of entropy
        // mixed from the address-space + time, never all-zero.
        let mix =
            blake3::hash(format!("{:p}{:?}", &bytes, std::time::SystemTime::now()).as_bytes());
        bytes.copy_from_slice(&mix.as_bytes()[..32]);
    }
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Root-only locations the daemon writes a RAW token to so privileged local
/// clients (CLI/engineer/mesh) can resolve it without the seizable register
/// handshake. `name` is the basename — "api-token" (full) or
/// "api-token-readonly". These are exactly the paths those clients search.
fn raw_token_client_paths_named(name: &str) -> Vec<PathBuf> {
    if crate::platform::is_elevated() {
        vec![
            PathBuf::from(format!("/var/lib/ringzero/{name}")),
            PathBuf::from(format!("/root/.config/ringzero/{name}")),
        ]
    } else {
        // Dev (`cargo run`, non-root): keep everything under the user's config so
        // the local CLI/engineer find it without elevation.
        let mut v = Vec::new();
        if let Ok(home) = std::env::var("HOME") {
            v.push(PathBuf::from(home).join(format!(".config/ringzero/{name}")));
        }
        v.push(std::env::temp_dir().join(format!("ringzero-{name}")));
        v
    }
}

fn raw_token_client_paths() -> Vec<PathBuf> {
    raw_token_client_paths_named("api-token")
}

/// Write the raw token to `path` with 0600 perms and `O_NOFOLLOW` (a pre-placed
/// symlink can't redirect the write). Creates parent dirs as needed.
fn write_raw_token(path: &std::path::Path, token: &str) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .mode(0o600)
        .custom_flags(nix::libc::O_NOFOLLOW)
        .open(path)?;
    f.write_all(token.as_bytes())?;
    f.sync_all()?;
    Ok(())
}

/// Shared auth state holding the registered token hashes (full + readonly).
/// `full_hash == None` = auth disabled (no token provisioned yet).
#[derive(Clone)]
pub struct AuthState {
    /// Full-scope token (operator/CLI/app/mesh — may mutate policy).
    token_hash: Arc<RwLock<Option<String>>>,
    /// ReadOnly-scope token (advisory engine — read + non-mutating scans only).
    readonly_hash: Arc<RwLock<Option<String>>>,
}

impl AuthState {
    pub fn new() -> Self {
        // Try to rehydrate from disk so daemon restarts don't kick the UI off.
        //
        // Strict format check: a blake3 hash is exactly 64 lowercase-hex chars.
        // Anything else (truncated write, partial overwrite, garbage from a
        // file-fill attack, a stray symlink we trim+read) gets treated as
        // "no token registered" rather than installed-but-impossible-to-match.
        // Without this, a corrupted file would lock out the UI permanently —
        // every real token would hash to a different value than the corrupted
        // string, and the `register` endpoint would refuse because a token is
        // already "registered".
        let initial = Self::rehydrate(&token_store_path());
        let initial_ro = Self::rehydrate(&readonly_token_store_path());
        if initial.is_some() {
            tracing::info!("API bearer token rehydrated from disk");
        }
        AuthState {
            token_hash: Arc::new(RwLock::new(initial)),
            readonly_hash: Arc::new(RwLock::new(initial_ro)),
        }
    }

    /// Read + validate a persisted hash file; None if absent/malformed.
    fn rehydrate(path: &std::path::Path) -> Option<String> {
        match std::fs::read_to_string(path) {
            Ok(s) => {
                let trimmed = s.trim().to_string();
                if Self::looks_like_hash(&trimmed) {
                    Some(trimmed)
                } else {
                    if !trimmed.is_empty() {
                        tracing::warn!(
                            len = trimmed.len(),
                            "Auth token store contains malformed data — ignoring"
                        );
                    }
                    None
                }
            }
            Err(_) => None,
        }
    }

    /// Strict check: exactly 64 lowercase hex characters (blake3 to_hex output).
    fn looks_like_hash(s: &str) -> bool {
        s.len() == 64 && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
    }

    /// Register a bearer token. Stores the blake3 hash, not the raw token.
    /// Returns `Err` if a token has already been registered — rotation must go
    /// through a separate authenticated endpoint, not the unauthenticated
    /// `/auth/register`, otherwise any local caller could overwrite the token.
    pub async fn register_token(&self, raw_token: &str) -> Result<(), AuthError> {
        let mut guard = self.token_hash.write().await;
        if guard.is_some() {
            return Err(AuthError::AlreadyRegistered);
        }
        let hash = blake3::hash(raw_token.as_bytes()).to_hex().to_string();
        *guard = Some(hash.clone());
        if let Err(e) = Self::persist(&hash) {
            tracing::warn!(err = %e, "Failed to persist auth token to disk — will need re-registration on restart");
        }
        tracing::info!("API bearer token registered");
        Ok(())
    }

    /// Ensure a bearer token exists **before the API listener accepts any
    /// connection**. The original design let the first
    /// caller of the unauthenticated `/auth/register` win the token — so any
    /// local process that raced the legit UI/CLI at boot seized full API control
    /// (`set_enforce:false`, drain `/secrets`, mint session JWTs). By having the
    /// daemon itself fill the slot at startup, that race is gone: `register_token`
    /// always finds a token present and rejects, and a racer never learns it.
    ///
    /// No-op when a token is already active (rehydrated from disk), so existing
    /// deployments keep their token untouched. On a fresh install it generates a
    /// 256-bit token, persists the hash, and writes the RAW token to root-only
    /// files that local clients already resolve (`~root/.config/ringzero/api-token`
    /// and `/var/lib/ringzero/api-token`, both 0600) — so an operator/root caller
    /// can read it without the seizable register handshake.
    pub async fn ensure_self_token(&self) {
        // Provision the FULL token (operator/CLI/app/mesh).
        if self
            .ensure_one(&self.token_hash, &token_store_path(), "api-token")
            .await
        {
            tracing::info!(
                "API bearer token (full) generated by daemon at startup (register race closed)"
            );
        }
        // Provision the READONLY token independently — so a deployment that
        // already had only a full token gains a scoped readonly token on upgrade
        // without disturbing the existing full token.
        if self
            .ensure_one(
                &self.readonly_hash,
                &readonly_token_store_path(),
                "api-token-readonly",
            )
            .await
        {
            tracing::info!("API readonly token generated (advisory engine scope)");
        }
    }

    /// Provision one token slot if empty: generate a 256-bit token, persist its
    /// hash, and write the RAW token 0600 to the named client paths. Returns true
    /// if it generated (false = already present, untouched). Re-checks under the
    /// write lock so a concurrent rehydrate/register isn't clobbered.
    async fn ensure_one(
        &self,
        slot: &Arc<RwLock<Option<String>>>,
        hash_store: &std::path::Path,
        raw_name: &str,
    ) -> bool {
        if slot.read().await.is_some() {
            return false;
        }
        let raw = generate_raw_token();
        let hash = blake3::hash(raw.as_bytes()).to_hex().to_string();
        {
            let mut guard = slot.write().await;
            if guard.is_some() {
                return false;
            }
            *guard = Some(hash.clone());
        }
        if let Err(e) = Self::persist_hash(hash_store, &hash) {
            tracing::warn!(err = %e, path = %hash_store.display(), "Failed to persist auth token hash");
        }
        for path in raw_token_client_paths_named(raw_name) {
            if let Err(e) = write_raw_token(&path, &raw) {
                tracing::debug!(err = %e, path = %path.display(), "could not write raw token for clients (non-fatal)");
            }
        }
        true
    }

    /// Rotate the bearer token — caller must already be authenticated.
    /// Distinct from `register_token` so the unauthenticated registration
    /// endpoint cannot be used to overwrite an existing token.
    ///
    /// Returns `false` if the proposed token hashes to the same value as the
    /// current one (a buggy UI that re-rotates to the same token shouldn't
    /// register an audit-log entry that says "rotation happened" when nothing
    /// actually changed). Returns `true` on a real rotation.
    pub async fn rotate_token(&self, raw_token: &str) -> bool {
        let hash = blake3::hash(raw_token.as_bytes()).to_hex().to_string();
        let mut guard = self.token_hash.write().await;
        if guard.as_deref() == Some(hash.as_str()) {
            return false;
        }
        *guard = Some(hash.clone());
        drop(guard);
        if let Err(e) = Self::persist(&hash) {
            tracing::warn!(err = %e, "Failed to persist rotated token to disk");
        }
        tracing::info!("API bearer token rotated");
        true
    }

    /// Write the blake3 hash to the on-disk store with 0600 perms.
    ///
    /// Uses `O_NOFOLLOW` so a pre-placed symlink at the store path can't
    /// redirect our write to an arbitrary file. This matters most for the
    /// non-root dev path under `temp_dir()`, which lives in a world-writable
    /// directory and is therefore symlink-attackable.
    fn persist(hash: &str) -> std::io::Result<()> {
        Self::persist_hash(&token_store_path(), hash)
    }

    fn persist_hash(path: &std::path::Path, hash: &str) -> std::io::Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .mode(0o600)
            .custom_flags(nix::libc::O_NOFOLLOW)
            .open(path)?;
        f.write_all(hash.as_bytes())?;
        f.sync_all()?;
        Ok(())
    }

    /// Validate a raw token and return the SCOPE it grants, or None if it matches
    /// no registered token. When no full token is provisioned at all, auth is
    /// disabled (dev) → grant Full. Constant work either way (hash once, compare).
    pub async fn validate_scope(&self, raw_token: &str) -> Option<Scope> {
        let provided = blake3::hash(raw_token.as_bytes()).to_hex().to_string();
        let full = self.token_hash.read().await;
        if full.is_none() {
            return Some(Scope::Full); // auth disabled (no token provisioned)
        }
        if full.as_deref() == Some(provided.as_str()) {
            return Some(Scope::Full);
        }
        drop(full);
        if self.readonly_hash.read().await.as_deref() == Some(provided.as_str()) {
            return Some(Scope::ReadOnly);
        }
        None
    }

    /// Back-compat boolean check (any valid token). Prefer `validate_scope`.
    pub async fn validate_token(&self, raw_token: &str) -> bool {
        self.validate_scope(raw_token).await.is_some()
    }

    /// Whether any token has been registered (auth is active).
    pub async fn is_active(&self) -> bool {
        self.token_hash.read().await.is_some()
    }
}

/// Axum middleware that checks Bearer token on every request.
/// Exempt paths: /api/v1/health, /api/v1/auth/register
/// The caller check for a policy-mutating request. `None` means let it through.
///
/// The /proc walk touches the filesystem, so it runs on the blocking pool
/// rather than stalling the reactor. It only ever runs for mutating calls,
/// which are rare.
async fn refuse_untrusted_caller(
    peer: Option<std::net::SocketAddr>,
    guard: Option<super::caller::MutationGuard>,
    method: &axum::http::Method,
    path: &str,
) -> Option<Response> {
    use super::caller::{self, Caller};

    let caller = match peer {
        Some(addr) => tokio::task::spawn_blocking(move || caller::classify_http(addr))
            .await
            .unwrap_or_else(|e| Caller::Unresolved {
                reason: format!("caller lookup failed: {e}"),
            }),
        None => Caller::Unresolved {
            reason: "the connection carried no peer address".to_string(),
        },
    };

    if caller.may_mutate() {
        return None;
    }

    if let Some(guard) = guard {
        guard.record_refusal(&caller, method.as_str(), path);
    } else {
        tracing::warn!(%method, %path, "refused a mutating call from an untrusted caller (no guard wired, so it is not in the review queue)");
    }

    Some((StatusCode::FORBIDDEN, caller.refusal_message()).into_response())
}

pub async fn auth_middleware(headers: HeaderMap, request: Request, next: Next) -> Response {
    let path = request.uri().path().to_string();
    let method = request.method().clone();

    // Exempt paths — healthcheck(s) and registration don't need auth. The
    // component health is liveness info (subsystem up/down) the UI shows even on
    // the login screen; no sensitive data, consistent with /health.
    if path == "/api/v1/health"
        || path == "/api/v1/health/components"
        || path == "/api/v1/auth/register"
    {
        return next.run(request).await;
    }

    // Also exempt static file serving (UI assets)
    if !path.starts_with("/api/") {
        return next.run(request).await;
    }

    // Extract the auth state from request extensions.
    // Missing state is a configuration bug — fail closed, never silently allow.
    let auth_state = match request.extensions().get::<AuthState>() {
        Some(state) => state.clone(),
        None => {
            tracing::error!("Auth middleware: AuthState missing from request extensions");
            return (StatusCode::INTERNAL_SERVER_ERROR, "Auth misconfigured").into_response();
        }
    };

    // If no token has ever been registered, the daemon is in its first-run
    // window before the local UI calls /auth/register. Allow loopback callers
    // only so the registration handshake can complete; reject everything else.
    if !auth_state.is_active().await {
        // Best-effort: rely on the bind address being 127.0.0.1 (default) plus
        // the explicit exemption above for /auth/register. Any other API call
        // before registration is denied.
        return (
            StatusCode::UNAUTHORIZED,
            "API not yet activated — call /api/v1/auth/register first",
        )
            .into_response();
    }

    // Extract Bearer token from Authorization header
    let token = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "));

    let raw_token = match token {
        Some(t) => t,
        None => {
            return (
                StatusCode::UNAUTHORIZED,
                "Missing Authorization: Bearer <token> header",
            )
                .into_response()
        }
    };

    // Validate the token AND check its scope covers what this request needs
    // A ReadOnly token can read state and run
    // non-mutating scans, but a mutating call (policy/enforce/secrets/…) returns
    // 403 — defence in depth against an injection-driven engine escalating.
    match auth_state.validate_scope(raw_token).await {
        Some(granted) => {
            let needed = required_scope(&method, &path);
            if granted.satisfies(needed) {
                // A VALID TOKEN IS NOT ENOUGH TO CHANGE POLICY.
                //
                // sudo caches credentials per tty for about fifteen minutes, so
                // an agent running in a terminal where the operator recently
                // authenticated can read the root-only token with no prompt.
                // The token then proves nothing about who is calling. For a
                // mutating call we resolve the caller's pid and refuse it if
                // that process, or any ancestor, is an AI agent — and refuse it
                // just the same when the pid cannot be resolved, because the
                // check is to PROVE the caller is not an agent. Reads are never
                // affected. See api/caller.rs for what this cannot catch.
                if needed == Scope::Full {
                    // Copy what the check needs out of the request first: the
                    // body is not Sync, so holding a borrow across the await
                    // would make this future non-Send.
                    let peer = request
                        .extensions()
                        .get::<axum::extract::ConnectInfo<std::net::SocketAddr>>()
                        .map(|c| c.0);
                    let guard = request
                        .extensions()
                        .get::<super::caller::MutationGuard>()
                        .cloned();
                    if let Some(refusal) =
                        refuse_untrusted_caller(peer, guard, &method, &path).await
                    {
                        return refusal;
                    }
                }
                next.run(request).await
            } else {
                tracing::warn!(%method, %path, "readonly token denied a mutating request (read-only scope)");
                (
                    StatusCode::FORBIDDEN,
                    "This token is read-only. Changing policy needs the root-only token, so \
                     re-run the same command with sudo.",
                )
                    .into_response()
            }
        }
        None => (StatusCode::UNAUTHORIZED, "Invalid bearer token").into_response(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build an AuthState with no token, bypassing the disk rehydrate so the
    /// test is independent of any token file on the build host.
    fn empty_state() -> AuthState {
        AuthState {
            token_hash: Arc::new(RwLock::new(None)),
            readonly_hash: Arc::new(RwLock::new(None)),
        }
    }

    /// Seed a state directly with known full + readonly hashes (no disk I/O).
    fn seeded_state(full: &str, readonly: &str) -> AuthState {
        AuthState {
            token_hash: Arc::new(RwLock::new(Some(
                blake3::hash(full.as_bytes()).to_hex().to_string(),
            ))),
            readonly_hash: Arc::new(RwLock::new(Some(
                blake3::hash(readonly.as_bytes()).to_hex().to_string(),
            ))),
        }
    }

    #[test]
    fn generated_token_is_64_hex_and_unique() {
        let a = generate_raw_token();
        let b = generate_raw_token();
        assert!(
            AuthState::looks_like_hash(&a),
            "token must be 64 lowercase hex: {a}"
        );
        assert_ne!(a, b, "two CSPRNG draws must differ");
    }

    /// Invariant: once a token is present, the unauthenticated register
    /// endpoint can no longer hand control to a racer, and the racer's token
    /// never authenticates.
    #[tokio::test]
    async fn register_race_cannot_seize_after_token_exists() {
        let s = empty_state();
        // Daemon fills the slot first (as ensure_self_token does at startup).
        s.register_token("legit-operator-token").await.unwrap();
        assert!(s.is_active().await);

        // Attacker races register — must be refused, not overwrite.
        let seized = s.register_token("attacker-token").await;
        assert!(matches!(seized, Err(AuthError::AlreadyRegistered)));

        // Attacker token must not validate; the legit one still does.
        assert!(!s.validate_token("attacker-token").await);
        assert!(s.validate_token("legit-operator-token").await);
    }

    /// ensure_self_token populates an empty state and is a no-op when already
    /// provisioned (existing deployments keep their token).
    #[tokio::test]
    async fn ensure_self_token_fills_then_is_idempotent() {
        let s = empty_state();
        s.ensure_self_token().await;
        assert!(s.is_active().await, "daemon must self-provision when empty");

        // Capture the hash, ensure a second call doesn't rotate it.
        let h1 = s.token_hash.read().await.clone();
        s.ensure_self_token().await;
        let h2 = s.token_hash.read().await.clone();
        assert_eq!(h1, h2, "ensure_self_token must be idempotent");
    }

    /// The readonly token may READ but a mutating request needs the full token.
    #[tokio::test]
    async fn readonly_token_is_scoped_to_reads() {
        use axum::http::Method;
        let s = seeded_state("FULL-secret", "RO-secret");

        // Both tokens validate, with the right scope.
        assert_eq!(s.validate_scope("FULL-secret").await, Some(Scope::Full));
        assert_eq!(s.validate_scope("RO-secret").await, Some(Scope::ReadOnly));
        assert_eq!(s.validate_scope("bogus").await, None);

        // GET (read) — both scopes satisfy.
        let need_read = required_scope(&Method::GET, "/api/v1/policy");
        assert!(Scope::ReadOnly.satisfies(need_read));
        assert!(Scope::Full.satisfies(need_read));

        // POST /policy (mutating) — only Full satisfies.
        let need_write = required_scope(&Method::POST, "/api/v1/policy");
        assert_eq!(need_write, Scope::Full);
        assert!(!Scope::ReadOnly.satisfies(need_write));
        assert!(Scope::Full.satisfies(need_write));

        // POST skill-scan (allowlisted read-only action) — ReadOnly satisfies.
        let need_scan = required_scope(&Method::POST, "/api/v1/skill-scan/auto");
        assert_eq!(need_scan, Scope::ReadOnly);
        assert!(Scope::ReadOnly.satisfies(need_scan));
    }

    /// ensure_self_token provisions BOTH scopes, and upgrades a full-only state.
    #[tokio::test]
    async fn ensure_self_token_provisions_both_scopes() {
        let s = empty_state();
        s.ensure_self_token().await;
        assert!(
            s.token_hash.read().await.is_some(),
            "full token provisioned"
        );
        assert!(
            s.readonly_hash.read().await.is_some(),
            "readonly token provisioned"
        );
        // The two must be distinct hashes.
        assert_ne!(*s.token_hash.read().await, *s.readonly_hash.read().await);
    }
}
