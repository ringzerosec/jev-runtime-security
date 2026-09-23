// SPDX-License-Identifier: Apache-2.0
// session/jwt.rs — Per-session JWT issuance
//
// Issues HS256 JWTs scoped to a single Ring Zero session.
// The secret is generated fresh at daemon startup — JWTs are ephemeral
// and only valid for the lifetime of the daemon process.

use anyhow::{Context, Result};
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};

// ── Claims ────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionClaims {
    /// Subject — session ID
    pub sub: String,
    /// Issuer
    pub iss: String,
    /// Issued-at (Unix timestamp)
    pub iat: i64,
    /// Expiry (Unix timestamp)
    pub exp: i64,
    /// Actor (human/service that owns this session)
    pub actor: String,
    /// Agent type (claude, chatgpt, cursor, …)
    pub agent_type: String,
    /// Declared scope tags granted at session creation
    pub scope: Vec<String>,
}

// ── Issuer ────────────────────────────────────────────────────────────────────

pub struct JwtIssuer {
    encoding: EncodingKey,
    decoding: DecodingKey,
    validation: Validation,
}

impl JwtIssuer {
    /// Create a new issuer with a fresh 32-byte HMAC secret.
    pub fn new() -> Self {
        use std::collections::HashSet;
        let secret = generate_secret();
        let mut validation = Validation::new(Algorithm::HS256);
        validation.set_issuer(&["ringzero-daemon"]);
        validation.required_spec_claims = HashSet::new(); // we check exp manually
        Self {
            encoding: EncodingKey::from_secret(&secret[..]),
            decoding: DecodingKey::from_secret(&secret[..]),
            validation,
        }
    }

    /// Issue a JWT for the given session, valid for `ttl_secs`.
    pub fn issue(
        &self,
        session_id: &str,
        actor: &str,
        agent_type: &str,
        scope: Vec<String>,
        ttl_secs: i64,
    ) -> Result<String> {
        let now = chrono::Utc::now().timestamp();
        let claims = SessionClaims {
            sub: session_id.to_string(),
            iss: "ringzero-daemon".to_string(),
            iat: now,
            exp: now + ttl_secs,
            actor: actor.to_string(),
            agent_type: agent_type.to_string(),
            scope,
        };
        jsonwebtoken::encode(&Header::default(), &claims, &self.encoding)
            .context("JWT encoding failed")
    }

    /// Verify a JWT and return its claims.
    #[allow(dead_code)]
    pub fn verify(&self, token: &str) -> Result<SessionClaims> {
        let data = jsonwebtoken::decode::<SessionClaims>(token, &self.decoding, &self.validation)
            .context("JWT verification failed")?;
        // Manual expiry check
        let now = chrono::Utc::now().timestamp();
        if data.claims.exp < now {
            anyhow::bail!("JWT expired");
        }
        Ok(data.claims)
    }
}

impl Default for JwtIssuer {
    fn default() -> Self {
        Self::new()
    }
}

// ── Secret generation ─────────────────────────────────────────────────────────

/// Generate a 32-byte secret from the kernel CSPRNG. The secret rotates every
/// daemon restart. Falls back to hashing time + pid + address-space entropy
/// only if /dev/urandom is unreadable (should never happen on Linux).
fn generate_secret() -> [u8; 32] {
    use std::io::Read;
    let mut bytes = [0u8; 32];
    if std::fs::File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut bytes))
        .is_ok()
    {
        return bytes;
    }
    let input = format!(
        "ringzero-jwt-{:?}-{}-{:p}",
        std::time::SystemTime::now(),
        std::process::id(),
        &bytes
    );
    *blake3::hash(input.as_bytes()).as_bytes()
}
