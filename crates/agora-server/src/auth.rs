use std::sync::Arc;

use axum::extract::{FromRef, FromRequestParts};
use axum::http::request::Parts;
use axum::http::{HeaderMap, header};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, encode};
use rand::{RngCore, rng};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::error::ApiError;
use crate::limits::SESSION_TOKEN_LIFETIME_HOURS;
use crate::role::DocumentRole;

/// Env var holding the shared HS256 secret.
pub const SECRET_ENV: &str = "PLATFORM_JWT_SECRET";

/// Shortest HS256 secret we accept, matching the other platform services.
pub const MIN_SECRET_LEN: usize = 32;

/// Audience that separates a share link session token from a platform token.
///
/// Platform tokens carry no `aud`, and jsonwebtoken refuses a token whose
/// `aud` is not one the validation expects, so neither kind can be replayed as
/// the other even though both are signed with the same secret.
pub const SESSION_AUDIENCE: &str = "agora-session";
const TOOL_TOKEN_USE: &str = "tool";
pub const AGORA_READ_SCOPE: &str = "agora:read";
pub const AGORA_WRITE_SCOPE: &str = "agora:write";

/// Claims on a platform token. The platform `role` claim is deliberately not
/// read: authorization comes from this document's members row and from the
/// project it names, never from something the token asserts about itself.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlatformClaims {
    pub sub: String,
    pub exp: usize,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

#[derive(Debug, Deserialize)]
struct TokenClaims {
    sub: String,
    #[serde(rename = "exp")]
    _exp: usize,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    role: Option<serde_json::Value>,
    #[serde(default)]
    token_use: Option<String>,
    #[serde(default)]
    scope: Option<serde_json::Value>,
}

enum VerifiedCaller {
    Platform(Caller),
    Tool { caller: Caller, scopes: Vec<String> },
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum VerificationError {
    Invalid,
    MissingScope,
}

/// Claims on a share link session token.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionClaims {
    pub sub: String,
    pub exp: usize,
    pub aud: String,
    pub doc: Uuid,
    pub role: DocumentRole,
    pub link: String,
}

/// The signing secret both token kinds validate against.
#[derive(Clone)]
pub struct AuthConfig {
    secret: Arc<str>,
}

/// Redacted so a stray `{:?}` cannot put the secret in a log line.
impl std::fmt::Debug for AuthConfig {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_struct("AuthConfig").finish_non_exhaustive()
    }
}

impl AuthConfig {
    /// Reject a missing or short secret: HS256 with a short secret is
    /// brute forceable, and this is the only way to build the gate.
    pub fn new(secret: &str) -> Result<Self, String> {
        if secret.is_empty() {
            return Err(format!(
                "{SECRET_ENV} is not set. Set it to 32+ random bytes shared with the other \
                 platform services."
            ));
        }
        if secret.len() < MIN_SECRET_LEN {
            // the length, never the secret
            return Err(format!(
                "{SECRET_ENV} is {} bytes, need at least {MIN_SECRET_LEN}",
                secret.len()
            ));
        }
        Ok(Self {
            secret: Arc::from(secret),
        })
    }

    pub fn from_env() -> Result<Self, String> {
        Self::new(&std::env::var(SECRET_ENV).unwrap_or_default())
    }

    fn decoding_key(&self) -> DecodingKey {
        DecodingKey::from_secret(self.secret.as_bytes())
    }

    /// Validate a platform token. `Validation::default()` pins HS256 and
    /// requires `exp`, so another algorithm, `alg: none`, an expired token and
    /// a wrong secret all fail here.
    pub fn verify_platform(&self, token: &str) -> Option<Caller> {
        match self.decode_caller(token).ok()? {
            VerifiedCaller::Platform(caller) => Some(caller),
            VerifiedCaller::Tool { .. } => None,
        }
    }

    fn decode_caller(&self, token: &str) -> Result<VerifiedCaller, VerificationError> {
        let claims = decode::<TokenClaims>(token, &self.decoding_key(), &Validation::default())
            .map_err(|_| VerificationError::Invalid)?
            .claims;
        if claims.sub.is_empty() {
            return Err(VerificationError::Invalid);
        }
        let name = claims
            .name
            .filter(|name| !name.trim().is_empty())
            .unwrap_or_else(|| claims.sub.clone());
        let caller = Caller {
            user_id: claims.sub,
            name,
            platform_token: None,
        };
        match claims.token_use.as_deref() {
            None => Ok(VerifiedCaller::Platform(Caller {
                platform_token: Some(PlatformToken(Arc::from(token))),
                ..caller
            })),
            Some(TOOL_TOKEN_USE) => {
                if claims.role.is_some() {
                    return Err(VerificationError::Invalid);
                }
                let scopes = claims
                    .scope
                    .and_then(|scope| scope.as_array().cloned())
                    .ok_or(VerificationError::Invalid)?
                    .into_iter()
                    .map(|scope| {
                        scope
                            .as_str()
                            .map(str::to_owned)
                            .ok_or(VerificationError::Invalid)
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                Ok(VerifiedCaller::Tool { caller, scopes })
            }
            Some(_) => Err(VerificationError::Invalid),
        }
    }

    pub(crate) fn verify_for_scope(
        &self,
        token: &str,
        required_scope: &str,
    ) -> Result<Caller, VerificationError> {
        match self.decode_caller(token)? {
            VerifiedCaller::Platform(caller) => Ok(caller),
            VerifiedCaller::Tool { caller, scopes } => scopes
                .iter()
                .any(|scope| scope == required_scope)
                .then_some(caller)
                .ok_or(VerificationError::MissingScope),
        }
    }

    /// Validate a share link session token. `aud` is required here, so a
    /// platform token cannot stand in for one.
    pub fn verify_session(&self, token: &str) -> Option<SessionClaims> {
        let mut validation = Validation::new(Algorithm::HS256);
        validation.set_audience(&[SESSION_AUDIENCE]);
        validation.required_spec_claims = ["exp", "aud"].into_iter().map(str::to_string).collect();
        let claims = decode::<SessionClaims>(token, &self.decoding_key(), &validation)
            .ok()?
            .claims;
        (!claims.sub.is_empty() && !claims.link.is_empty()).then_some(claims)
    }

    /// Mint a short lived token for a share link visitor, carrying a fresh
    /// anonymous actor id that stays the same for the life of the token.
    pub fn mint_session(
        &self,
        document: Uuid,
        role: DocumentRole,
        link_token: &str,
    ) -> Result<String, ApiError> {
        let expires_at =
            OffsetDateTime::now_utc() + time::Duration::hours(SESSION_TOKEN_LIFETIME_HOURS);
        let exp = usize::try_from(expires_at.unix_timestamp())
            .map_err(|_| ApiError::internal("clock out of range"))?;
        let claims = SessionClaims {
            sub: format!("guest-{}", Uuid::new_v4()),
            exp,
            aud: SESSION_AUDIENCE.to_string(),
            doc: document,
            role,
            link: link_token.to_string(),
        };
        let key = EncodingKey::from_secret(self.secret.as_bytes());
        encode(&Header::new(Algorithm::HS256), &claims, &key)
            .map_err(|_| ApiError::internal("could not mint a session token"))
    }
}

/// A token that is itself the permission to reach something: a share link or an
/// attachment. Entropy from the OS backed thread rng, url safe so it can sit in
/// a link a person pastes.
pub fn random_capability_token(entropy_bytes: usize) -> String {
    let mut token = vec![0u8; entropy_bytes];
    rng().fill_bytes(&mut token);
    URL_SAFE_NO_PAD.encode(token)
}

/// The only form of a capability token the database ever holds, so a database
/// read hands over no working link and no working attachment url.
///
/// A plain digest and no salt on purpose: the token is 128 bits or more of
/// csprng output, so there is no guessing surface for a password style kdf to
/// defend, and a per row salt would cost the indexed equality lookup every
/// consumer depends on.
pub fn capability_token_hash(token: &str) -> String {
    hex::encode(Sha256::digest(token.as_bytes()))
}

/// A verified platform caller. Holding one is proof the signature and `exp`
/// checked out, nothing more: document access is still a role lookup.
#[derive(Debug, Clone)]
pub struct Caller {
    pub user_id: String,
    pub name: String,
    /// The caller's own token, kept so ptolemy can be asked what they may do
    /// with their credential rather than one of agora's.
    ///
    /// `None` for a scoped tool token: that token was minted to reach agora, and
    /// forwarding it to another service would spend it somewhere it was never
    /// scoped for. A tool caller keeps their members table role alone.
    pub platform_token: Option<PlatformToken>,
}

/// A bearer token held only long enough to make one call with it.
#[derive(Clone)]
pub struct PlatformToken(Arc<str>);

impl PlatformToken {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Redacted for the same reason [`AuthConfig`] is: a stray `{:?}` must not put a
/// working credential in a log line.
impl std::fmt::Debug for PlatformToken {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("PlatformToken(redacted)")
    }
}

pub fn bearer_token(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .filter(|token| !token.is_empty())
}

/// Subprotocol name marking a websocket handshake as carrying a bearer token,
/// the same marker tiletopia uses.
pub const BEARER_SUBPROTOCOL: &str = "bearer";

/// Token out of a `Sec-WebSocket-Protocol: bearer, <jwt>` offer. The order is
/// fixed, marker first and token second, which is what
/// `new WebSocket(url, ["bearer", jwt])` sends.
fn subprotocol_token(headers: &HeaderMap) -> Option<&str> {
    let offered = headers.get(header::SEC_WEBSOCKET_PROTOCOL)?.to_str().ok()?;
    let mut entries = offered.split(',').map(str::trim);
    if entries.next()? != BEARER_SUBPROTOCOL {
        return None;
    }
    entries.next().filter(|token| !token.is_empty())
}

/// The credential on a websocket handshake, in preference order: the
/// `Authorization` header, then a `bearer` subprotocol offer, then the `token`
/// query param.
///
/// A browser cannot set a header on a websocket handshake. The subprotocol is
/// preferred over the query param because proxies log urls and not headers.
/// Only the websocket route calls this, so nowhere else does a subprotocol or a
/// url act as a credential.
pub fn websocket_token<'a>(
    headers: &'a HeaderMap,
    query_token: Option<&'a str>,
) -> Option<&'a str> {
    bearer_token(headers)
        .or_else(|| subprotocol_token(headers))
        .or(query_token)
        .filter(|token| !token.is_empty())
}

impl<S> FromRequestParts<S> for Caller
where
    AuthConfig: FromRef<S>,
    S: Send + Sync,
{
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let config = AuthConfig::from_ref(state);
        let Some(token) = bearer_token(&parts.headers) else {
            return Err(ApiError::unauthorized("missing bearer token"));
        };
        // the decode error is not echoed back: it separates expired from bad
        // signature, which helps an attacker more than a caller
        let required_scope = if matches!(
            parts.method,
            axum::http::Method::GET | axum::http::Method::HEAD
        ) {
            AGORA_READ_SCOPE
        } else {
            AGORA_WRITE_SCOPE
        };
        config
            .verify_for_scope(token, required_scope)
            .map_err(|error| match error {
                VerificationError::Invalid => ApiError::unauthorized("invalid or expired token"),
                VerificationError::MissingScope => {
                    ApiError::forbidden("required tool scope missing")
                }
            })
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;
    use crate::limits::{ATTACHMENT_TOKEN_BYTES, SHARE_TOKEN_BYTES};
    use serde_json::json;

    const SECRET: &str = "0123456789abcdef0123456789abcdef";

    fn sign(claims: &serde_json::Value) -> String {
        let key = EncodingKey::from_secret(SECRET.as_bytes());
        encode(&Header::new(Algorithm::HS256), claims, &key).unwrap()
    }

    fn future() -> i64 {
        OffsetDateTime::now_utc().unix_timestamp() + 3600
    }

    #[test]
    fn weak_secrets_are_refused() {
        assert!(AuthConfig::new("").unwrap_err().contains("is not set"));
        let error = AuthConfig::new("short-secret").unwrap_err();
        assert!(error.contains("need at least 32"));
        assert!(!error.contains("short-secret"));
        assert!(AuthConfig::new(SECRET).is_ok());
    }

    #[test]
    fn debug_does_not_print_the_secret() {
        let config = AuthConfig::new("0123456789abcdef-s3cr3t-0123456789").unwrap();
        assert!(!format!("{config:?}").contains("s3cr3t"));
    }

    #[test]
    fn platform_tokens_validate_and_fall_back_to_the_subject_for_a_name() {
        let config = AuthConfig::new(SECRET).unwrap();
        let token = sign(&json!({"sub": "user-1", "exp": future(), "role": "editor"}));
        let caller = config.verify_platform(&token).unwrap();
        assert_eq!(caller.user_id, "user-1");
        assert_eq!(caller.name, "user-1");

        let named = sign(&json!({"sub": "user-2", "exp": future(), "name": "Ada"}));
        assert_eq!(config.verify_platform(&named).unwrap().name, "Ada");

        let blank = sign(&json!({"sub": "user-3", "exp": future(), "name": "  "}));
        assert_eq!(config.verify_platform(&blank).unwrap().name, "user-3");
    }

    #[test]
    fn platform_tokens_fail_on_a_wrong_secret_expiry_or_empty_subject() {
        let config = AuthConfig::new(SECRET).unwrap();
        let other = AuthConfig::new("ffffffffffffffffffffffffffffffff").unwrap();
        let token = sign(&json!({"sub": "user-1", "exp": future()}));
        assert!(other.verify_platform(&token).is_none());

        let expired = sign(&json!({"sub": "user-1", "exp": 1_000_000}));
        assert!(config.verify_platform(&expired).is_none());

        let anonymous = sign(&json!({"sub": "", "exp": future()}));
        assert!(config.verify_platform(&anonymous).is_none());

        assert!(config.verify_platform("").is_none());
        assert!(config.verify_platform("not.a.token").is_none());
    }

    #[test]
    fn tool_tokens_need_the_exact_operation_scope() {
        let config = AuthConfig::new(SECRET).unwrap();
        let write = sign(&json!({
            "sub": "user-1",
            "exp": future(),
            "token_use": "tool",
            "scope": [AGORA_WRITE_SCOPE]
        }));
        assert!(matches!(
            config.verify_for_scope(&write, AGORA_READ_SCOPE),
            Err(VerificationError::MissingScope)
        ));
        let caller = config.verify_for_scope(&write, AGORA_WRITE_SCOPE).unwrap();
        assert_eq!(caller.user_id, "user-1");

        let wrong_service = sign(&json!({
            "sub": "user-1",
            "exp": future(),
            "token_use": "tool",
            "scope": ["ptolemy:write"]
        }));
        assert!(matches!(
            config.verify_for_scope(&wrong_service, AGORA_WRITE_SCOPE),
            Err(VerificationError::MissingScope)
        ));
    }

    #[test]
    fn a_tool_token_cannot_fall_back_to_a_role() {
        let config = AuthConfig::new(SECRET).unwrap();
        let token = sign(&json!({
            "sub": "user-1",
            "exp": future(),
            "role": "admin",
            "token_use": "tool",
            "scope": [AGORA_WRITE_SCOPE]
        }));
        assert!(config.verify_platform(&token).is_none());
        assert!(matches!(
            config.verify_for_scope(&token, AGORA_WRITE_SCOPE),
            Err(VerificationError::Invalid)
        ));
    }

    #[test]
    fn malformed_and_unknown_tool_claims_are_invalid() {
        let config = AuthConfig::new(SECRET).unwrap();
        for claims in [
            json!({"sub": "user-1", "exp": future(), "token_use": "tool"}),
            json!({
                "sub": "user-1", "exp": future(), "token_use": "tool", "scope": "agora:write"
            }),
            json!({
                "sub": "user-1", "exp": future(), "token_use": "other", "scope": [AGORA_WRITE_SCOPE]
            }),
        ] {
            assert!(matches!(
                config.verify_for_scope(&sign(&claims), AGORA_WRITE_SCOPE),
                Err(VerificationError::Invalid)
            ));
        }
    }

    #[test]
    fn platform_tokens_keep_existing_access_to_both_operations() {
        let config = AuthConfig::new(SECRET).unwrap();
        let token = sign(&json!({"sub": "user-1", "exp": future(), "role": "viewer"}));
        assert!(config.verify_for_scope(&token, AGORA_READ_SCOPE).is_ok());
        assert!(config.verify_for_scope(&token, AGORA_WRITE_SCOPE).is_ok());
    }

    #[test]
    fn only_a_platform_caller_carries_a_token_and_no_debug_line_prints_it() {
        let config = AuthConfig::new(SECRET).unwrap();
        let token = sign(&json!({"sub": "user-1", "exp": future()}));
        let caller = config.verify_platform(&token).unwrap();
        let carried = caller.platform_token.as_ref().unwrap();
        assert_eq!(carried.as_str(), token);
        assert!(!format!("{caller:?}").contains(&token));

        let tool = sign(&json!({
            "sub": "user-1",
            "exp": future(),
            "token_use": "tool",
            "scope": [AGORA_WRITE_SCOPE]
        }));
        let tool_caller = config.verify_for_scope(&tool, AGORA_WRITE_SCOPE).unwrap();
        assert!(tool_caller.platform_token.is_none());
    }

    #[test]
    fn alg_none_is_refused() {
        let config = AuthConfig::new(SECRET).unwrap();
        let header = URL_SAFE_NO_PAD.encode(br#"{"alg":"none","typ":"JWT"}"#);
        let claims = URL_SAFE_NO_PAD.encode(format!(r#"{{"sub":"user-1","exp":{}}}"#, future()));
        assert!(
            config
                .verify_platform(&format!("{header}.{claims}."))
                .is_none()
        );
    }

    #[test]
    fn a_session_token_cannot_be_used_as_a_platform_token() {
        let config = AuthConfig::new(SECRET).unwrap();
        let document = Uuid::new_v4();
        let session = config
            .mint_session(document, DocumentRole::View, "link-token")
            .unwrap();
        assert!(config.verify_platform(&session).is_none());

        let claims = config.verify_session(&session).unwrap();
        assert_eq!(claims.doc, document);
        assert_eq!(claims.role, DocumentRole::View);
        assert_eq!(claims.link, "link-token");
        assert!(claims.sub.starts_with("guest-"));
    }

    #[test]
    fn a_platform_token_cannot_be_used_as_a_session_token() {
        let config = AuthConfig::new(SECRET).unwrap();
        let token = sign(&json!({"sub": "user-1", "exp": future(), "role": "admin"}));
        assert!(config.verify_session(&token).is_none());

        let forged = sign(&json!({
            "sub": "user-1",
            "exp": future(),
            "doc": Uuid::new_v4(),
            "role": "edit",
            "link": "made-up"
        }));
        assert!(config.verify_session(&forged).is_none());
    }

    #[test]
    fn session_tokens_with_the_wrong_audience_are_refused() {
        let config = AuthConfig::new(SECRET).unwrap();
        let forged = sign(&json!({
            "sub": "guest-1",
            "exp": future(),
            "aud": "some-other-service",
            "doc": Uuid::new_v4(),
            "role": "edit",
            "link": "made-up"
        }));
        assert!(config.verify_session(&forged).is_none());
        assert!(config.verify_platform(&forged).is_none());
    }

    #[test]
    fn session_actor_ids_are_unique_per_token() {
        let config = AuthConfig::new(SECRET).unwrap();
        let document = Uuid::new_v4();
        let first = config
            .mint_session(document, DocumentRole::Edit, "link")
            .unwrap();
        let second = config
            .mint_session(document, DocumentRole::Edit, "link")
            .unwrap();
        let first = config.verify_session(&first).unwrap();
        let second = config.verify_session(&second).unwrap();
        assert_ne!(first.sub, second.sub);
    }

    #[test]
    fn capability_tokens_carry_full_entropy_and_are_url_safe() {
        for entropy_bytes in [SHARE_TOKEN_BYTES, ATTACHMENT_TOKEN_BYTES] {
            let token = random_capability_token(entropy_bytes);
            assert!(
                token
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'),
                "{token}"
            );
            let decoded = URL_SAFE_NO_PAD.decode(&token).unwrap();
            assert_eq!(decoded.len(), entropy_bytes);

            let mut seen = std::collections::HashSet::new();
            for _ in 0..256 {
                assert!(seen.insert(random_capability_token(entropy_bytes)));
            }
        }
    }

    #[test]
    fn an_attachment_token_carries_at_least_256_bits() {
        let token = random_capability_token(ATTACHMENT_TOKEN_BYTES);
        let decoded = URL_SAFE_NO_PAD.decode(&token).unwrap();
        assert!(decoded.len() * 8 >= 256, "{} bits", decoded.len() * 8);
    }

    #[test]
    fn the_stored_hash_is_stable_hex_and_never_the_token() {
        let token = random_capability_token(SHARE_TOKEN_BYTES);
        let hash = capability_token_hash(&token);
        assert_eq!(hash.len(), 64);
        assert!(
            hash.chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_uppercase())
        );
        assert_ne!(hash, token);
        assert_eq!(hash, capability_token_hash(&token));
        assert_ne!(
            hash,
            capability_token_hash(&random_capability_token(SHARE_TOKEN_BYTES))
        );

        // the sha-256 of the empty string, so a swapped algorithm is caught
        assert_eq!(
            capability_token_hash(""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn bearer_extraction_needs_the_exact_scheme() {
        let mut headers = HeaderMap::new();
        assert_eq!(bearer_token(&headers), None);
        headers.insert(header::AUTHORIZATION, "Bearer abc".parse().unwrap());
        assert_eq!(bearer_token(&headers), Some("abc"));
        headers.insert(header::AUTHORIZATION, "bearer abc".parse().unwrap());
        assert_eq!(bearer_token(&headers), None);
        headers.insert(header::AUTHORIZATION, "Bearer ".parse().unwrap());
        assert_eq!(bearer_token(&headers), None);
    }

    fn subprotocol(value: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(header::SEC_WEBSOCKET_PROTOCOL, value.parse().unwrap());
        headers
    }

    #[test]
    fn a_subprotocol_offer_carries_the_token_after_the_marker() {
        let headers = subprotocol("bearer, jwt-here");
        assert_eq!(websocket_token(&headers, None), Some("jwt-here"));
        assert_eq!(
            websocket_token(&subprotocol("bearer,jwt-here"), None),
            Some("jwt-here")
        );
    }

    #[test]
    fn malformed_subprotocol_offers_carry_no_token() {
        for offer in [
            "bearer",
            "bearer, ",
            "jwt-here",
            "graphql-ws",
            "jwt, bearer",
            "",
        ] {
            assert_eq!(
                websocket_token(&subprotocol(offer), None),
                None,
                "{offer:?}"
            );
        }
    }

    #[test]
    fn the_header_wins_then_the_subprotocol_then_the_query() {
        let mut headers = subprotocol("bearer, from-subprotocol");
        headers.insert(header::AUTHORIZATION, "Bearer from-header".parse().unwrap());
        assert_eq!(
            websocket_token(&headers, Some("from-query")),
            Some("from-header")
        );
        assert_eq!(
            websocket_token(&subprotocol("bearer, from-subprotocol"), Some("from-query")),
            Some("from-subprotocol")
        );
        assert_eq!(
            websocket_token(&HeaderMap::new(), Some("from-query")),
            Some("from-query")
        );
        assert_eq!(websocket_token(&HeaderMap::new(), None), None);
        assert_eq!(websocket_token(&HeaderMap::new(), Some("")), None);
    }
}
