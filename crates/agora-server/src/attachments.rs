use axum::Json;
use axum::body::{Body, Bytes, to_bytes};
use axum::extract::{Path, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use serde::Serialize;
use sqlx::Row;
use uuid::Uuid;

use crate::AppState;
use crate::auth::{Caller, capability_token_hash, random_capability_token};
use crate::documents::require_editor;
use crate::error::ApiError;
use crate::limits::{ATTACHMENT_TOKEN_BYTES, MAX_ATTACHMENT_BYTES};

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

/// Where an attachment reads from, relative to the agora base url the client
/// already talks to.
fn attachment_url(token: &str) -> String {
    format!("/attachments/{token}")
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
}
