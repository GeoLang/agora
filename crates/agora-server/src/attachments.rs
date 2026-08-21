use std::collections::BTreeSet;
use std::time::Duration as StandardDuration;

use axum::Json;
use axum::body::{Body, Bytes, to_bytes};
use axum::extract::{Path, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use serde::Serialize;
use sqlx::{PgPool, Row};
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

use crate::AppState;
use crate::auth::{Caller, capability_token_hash, random_capability_token};
use crate::documents::require_editor;
use crate::error::ApiError;
use crate::limits::{
    ATTACHMENT_GRACE_DAYS, ATTACHMENT_SWEEP_INTERVAL_HOURS, ATTACHMENT_TOKEN_BYTES,
    MAX_ATTACHMENT_BYTES,
};
use crate::room::current_state;

/// An attachment never changes, so whoever has one never has to ask for it
/// again.
const CACHE_CONTROL: &str = "public, max-age=31536000, immutable";

/// What an attachment may be served as. An attachment is read from agora's own
/// origin with no credential, so anything a browser executes, `text/html` and
/// `image/svg+xml` above all, would be an editor's script running on the
/// platform origin against everyone they send the url to.
const ACCEPTED_CONTENT_TYPES: [&str; 5] = [
    "image/png",
    "image/jpeg",
    "image/webp",
    "image/gif",
    "image/avif",
];

/// The stored form of a content type, or `None` when it is not one agora
/// serves. Every content type goes through this, the stored one on the way out
/// included, so a response header can only ever carry one of these.
fn accepted_content_type(declared: &str) -> Option<&'static str> {
    let declared = declared
        .split(';')
        .next()
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase();
    ACCEPTED_CONTENT_TYPES
        .into_iter()
        .find(|accepted| *accepted == declared)
}

/// The path an attachment reads from. A document points at an attachment by
/// carrying this url in a value, which is what the sweep looks for.
const ATTACHMENT_URL_PREFIX: &str = "/attachments/";

/// Where an attachment reads from, relative to the agora base url the client
/// already talks to.
fn attachment_url(token: &str) -> String {
    format!("{ATTACHMENT_URL_PREFIX}{token}")
}

#[derive(Debug, Serialize)]
pub struct CreatedAttachment {
    token: String,
    url: String,
}

/// Store one blob against a document. Edit role on that document, the same
/// members lookup an op write goes through, and a caller who is not a member is
/// told the document does not exist.
///
/// The role is checked before the body is read, and the body is read through a
/// cap, so neither a stranger nor an editor can push more than
/// [`MAX_ATTACHMENT_BYTES`] into memory.
pub async fn create_attachment(
    State(state): State<AppState>,
    caller: Caller,
    Path(document_id): Path<Uuid>,
    headers: HeaderMap,
    body: Body,
) -> Result<(StatusCode, Json<CreatedAttachment>), ApiError> {
    require_editor(&state.pool, document_id, &caller.user_id).await?;

    let declared = headers
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default();
    let content_type = accepted_content_type(declared)
        .ok_or_else(|| ApiError::bad_request("attachment content type is not an accepted image"))?;

    let bytes = to_bytes(body, MAX_ATTACHMENT_BYTES)
        .await
        .map_err(|_| ApiError::payload_too_large("attachment too large"))?;
    if bytes.is_empty() {
        return Err(ApiError::bad_request("attachment is empty"));
    }

    let token = random_capability_token(ATTACHMENT_TOKEN_BYTES);
    sqlx::query(
        "insert into attachments (token_hash, doc_id, content_type, bytes, created_by)
         values ($1, $2, $3, $4, $5)",
    )
    .bind(capability_token_hash(&token))
    .bind(document_id)
    .bind(content_type)
    .bind(bytes.as_ref())
    .bind(&caller.user_id)
    .execute(&state.pool)
    .await?;

    Ok((
        StatusCode::CREATED,
        Json(CreatedAttachment {
            url: attachment_url(&token),
            token,
        }),
    ))
}

/// The token is the whole credential and it reaches exactly one blob, so a
/// wrong token is indistinguishable from one that never existed.
///
/// A read deliberately does not mark the attachment as still wanted. The
/// response is cached as immutable, so agora never sees most reads and
/// read driven liveness would call a live attachment dead. Being named by the
/// document is the signal, and the sweep is what checks it.
pub async fn get_attachment(
    State(state): State<AppState>,
    Path(token): Path<String>,
) -> Result<Response, ApiError> {
    let row = sqlx::query("select content_type, bytes from attachments where token_hash = $1")
        .bind(capability_token_hash(&token))
        .fetch_optional(&state.pool)
        .await?
        .ok_or_else(|| ApiError::not_found("no such attachment"))?;

    let stored: String = row.try_get("content_type")?;
    let content_type = accepted_content_type(&stored)
        .ok_or_else(|| ApiError::internal("stored content type is not one agora serves"))?;
    let bytes: Vec<u8> = row.try_get("bytes")?;

    Ok((
        [
            (header::CONTENT_TYPE, HeaderValue::from_static(content_type)),
            (
                header::CACHE_CONTROL,
                HeaderValue::from_static(CACHE_CONTROL),
            ),
            (
                header::X_CONTENT_TYPE_OPTIONS,
                HeaderValue::from_static("nosniff"),
            ),
        ],
        Bytes::from(bytes),
    )
        .into_response())
}

/// The attachment tokens a document's state points at.
///
/// Values are opaque json, so this looks for the read url and takes the token
/// characters after it rather than reading any field. A token is 256 random
/// bits, so a value that happens to contain one it does not mean is not a case
/// worth planning for.
fn referenced_tokens(serialized_state: &str) -> BTreeSet<String> {
    let mut tokens = BTreeSet::new();
    for (index, _) in serialized_state.match_indices(ATTACHMENT_URL_PREFIX) {
        let after = &serialized_state[index + ATTACHMENT_URL_PREFIX.len()..];
        let token: String = after
            .chars()
            .take_while(|character| {
                character.is_ascii_alphanumeric() || *character == '-' || *character == '_'
            })
            .collect();
        if !token.is_empty() {
            tokens.insert(token);
        }
    }
    tokens
}

/// Delete the attachments no document points at any more, and returns how many
/// went. An attachment is live while the document's current state carries its
/// url, which is the same state a joining client is sent.
///
/// Only rows nothing has confirmed for [`ATTACHMENT_GRACE_DAYS`] are looked at,
/// so a document whose attachments were confirmed recently costs nothing, and a
/// document with no attachments never appears here at all.
pub async fn sweep(pool: &PgPool) -> Result<u64, sqlx::Error> {
    let cutoff = OffsetDateTime::now_utc() - Duration::days(ATTACHMENT_GRACE_DAYS);
    let documents: Vec<Uuid> =
        sqlx::query_scalar("select distinct doc_id from attachments where last_referenced_at < $1")
            .bind(cutoff)
            .fetch_all(pool)
            .await?;

    let mut deleted = 0;
    for document_id in documents {
        deleted += sweep_document(pool, document_id, cutoff).await?;
    }
    Ok(deleted)
}

/// Refreshing and deleting share one transaction, so a crash between them
/// cannot take an attachment the document still points at.
async fn sweep_document(
    pool: &PgPool,
    document_id: Uuid,
    cutoff: OffsetDateTime,
) -> Result<u64, sqlx::Error> {
    // the document was deleted while the sweep ran, and the cascade already
    // took its attachments
    let Some((state, ..)) = current_state(pool, document_id).await? else {
        return Ok(0);
    };
    let referenced: Vec<String> = referenced_tokens(&state.snapshot().to_string())
        .iter()
        .map(|token| capability_token_hash(token))
        .collect();

    let mut transaction = pool.begin().await?;
    sqlx::query(
        "update attachments set last_referenced_at = now()
         where doc_id = $1 and token_hash = any($2)",
    )
    .bind(document_id)
    .bind(&referenced)
    .execute(&mut *transaction)
    .await?;
    let deleted =
        sqlx::query("delete from attachments where doc_id = $1 and last_referenced_at < $2")
            .bind(document_id)
            .bind(cutoff)
            .execute(&mut *transaction)
            .await?
            .rows_affected();
    transaction.commit().await?;
    Ok(deleted)
}

/// Sweep for as long as the server runs, starting with one pass at startup.
///
/// Started by the binary and not by `router`, so a test drives the sweep itself
/// rather than racing one.
pub async fn sweep_periodically(pool: PgPool) {
    let period = StandardDuration::from_secs(ATTACHMENT_SWEEP_INTERVAL_HOURS * 60 * 60);
    let mut ticker = tokio::time::interval(period);
    loop {
        ticker.tick().await;
        if let Err(error) = sweep(&pool).await {
            eprintln!("attachment sweep failed: {error}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_content_type_is_accepted_by_its_essence_only() {
        assert_eq!(accepted_content_type("image/png"), Some("image/png"));
        assert_eq!(accepted_content_type("IMAGE/PNG"), Some("image/png"));
        assert_eq!(
            accepted_content_type("image/jpeg; charset=binary"),
            Some("image/jpeg")
        );
        assert_eq!(accepted_content_type(" image/webp "), Some("image/webp"));
    }

    #[test]
    fn an_executable_or_unknown_content_type_is_refused() {
        for declared in [
            "",
            "text/html",
            "image/svg+xml",
            "application/pdf",
            "application/octet-stream",
            "text/html; charset=utf-8",
            "image/png/../text/html",
            "image/pngx",
        ] {
            assert_eq!(accepted_content_type(declared), None, "{declared:?}");
        }
    }

    #[test]
    fn every_accepted_content_type_is_a_usable_header_value() {
        for accepted in ACCEPTED_CONTENT_TYPES {
            assert!(HeaderValue::from_str(accepted).is_ok(), "{accepted}");
            assert_eq!(accepted_content_type(accepted), Some(accepted));
        }
    }

    #[test]
    fn the_url_reaches_the_read_route() {
        assert_eq!(attachment_url("abc-123"), "/attachments/abc-123");
    }

    fn tokens(state: &str) -> Vec<String> {
        referenced_tokens(state).into_iter().collect()
    }

    #[test]
    fn a_reference_is_found_wherever_the_url_sits_in_a_value() {
        let token = random_capability_token(ATTACHMENT_TOKEN_BYTES);
        let url = attachment_url(&token);
        for state in [
            format!(r#"{{"layers":{{"a":{{"image":"{url}"}}}}}}"#),
            format!(r#"{{"layers":{{"a":{{"image":"https://host/agora{url}"}}}}}}"#),
            format!(r#"{{"annotations":{{"a":{{"deep":[{{"src":"{url}?v=2"}}]}}}}}}"#),
        ] {
            assert_eq!(tokens(&state), vec![token.clone()], "{state}");
        }
    }

    #[test]
    fn every_reference_in_a_state_is_found_once() {
        let first = random_capability_token(ATTACHMENT_TOKEN_BYTES);
        let second = random_capability_token(ATTACHMENT_TOKEN_BYTES);
        let state = format!(
            r#"{{"layers":{{"a":{{"image":"{}"}},"b":{{"image":"{}"}},"c":{{"image":"{}"}}}}}}"#,
            attachment_url(&first),
            attachment_url(&second),
            attachment_url(&first)
        );
        let mut expected = vec![first, second];
        expected.sort();
        assert_eq!(tokens(&state), expected);
    }

    #[test]
    fn a_state_pointing_at_nothing_carries_no_tokens() {
        assert!(tokens(r#"{"layers":{}}"#).is_empty());
        assert!(tokens(r#"{"layers":{"a":{"image":"/attachments/"}}}"#).is_empty());
        assert!(tokens(r#"{"layers":{"a":{"note":"attachments/xyz"}}}"#).is_empty());
    }

    #[test]
    fn a_token_stops_at_the_first_character_outside_its_alphabet() {
        assert_eq!(tokens(r#"{"a":"/attachments/abc.def"}"#), vec!["abc"]);
        assert_eq!(tokens(r#"{"a":"/attachments/abc/thumb"}"#), vec!["abc"]);
        assert_eq!(tokens(r#"{"a":"/attachments/a-b_C9"}"#), vec!["a-b_C9"]);
    }
}
