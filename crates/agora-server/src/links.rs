use axum::Json;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use serde::{Deserialize, Serialize};
use sqlx::{PgPool, Row};
use uuid::Uuid;

use crate::AppState;
use crate::auth::{Caller, random_share_token};
use crate::documents::require_editor;
use crate::error::ApiError;
use crate::role::DocumentRole;

/// A live share link. Looked up fresh on every use, so the row is the authority
/// on both the role and whether the link still works.
pub struct ShareLink {
    pub document_id: Uuid,
    pub role: DocumentRole,
}

pub async fn live_link(pool: &PgPool, token: &str) -> Result<Option<ShareLink>, sqlx::Error> {
    let row =
        sqlx::query("select doc_id, role from share_links where token = $1 and revoked = false")
            .bind(token)
            .fetch_optional(pool)
            .await?;
    let Some(row) = row else {
        return Ok(None);
    };
    let role: String = row.try_get("role")?;
    let Some(role) = DocumentRole::parse(&role) else {
        return Ok(None);
    };
    Ok(Some(ShareLink {
        document_id: row.try_get("doc_id")?,
        role,
    }))
}

#[derive(Debug, Deserialize)]
pub struct CreateLinkRequest {
    role: DocumentRole,
}

#[derive(Debug, Serialize)]
pub struct CreatedLink {
    token: String,
}

pub async fn create_link(
    State(state): State<AppState>,
    caller: Caller,
    Path(document_id): Path<Uuid>,
    Json(request): Json<CreateLinkRequest>,
) -> Result<(StatusCode, Json<CreatedLink>), ApiError> {
    require_editor(&state.pool, document_id, &caller.user_id).await?;

    let token = random_share_token();
    sqlx::query(
        "insert into share_links (token, doc_id, role, created_by) values ($1, $2, $3, $4)",
    )
    .bind(&token)
    .bind(document_id)
    .bind(request.role.as_str())
    .bind(&caller.user_id)
    .execute(&state.pool)
    .await?;

    Ok((StatusCode::CREATED, Json(CreatedLink { token })))
}

pub async fn revoke_link(
    State(state): State<AppState>,
    caller: Caller,
    Path(token): Path<String>,
) -> Result<StatusCode, ApiError> {
    let row = sqlx::query("select doc_id from share_links where token = $1")
        .bind(&token)
        .fetch_optional(&state.pool)
        .await?;
    let missing = || ApiError::not_found("no such link");
    let Some(row) = row else {
        return Err(missing());
    };
    let document_id: Uuid = row.try_get("doc_id")?;
    // a caller who cannot edit the document is told the link does not exist,
    // so a token cannot be tested for existence
    require_editor(&state.pool, document_id, &caller.user_id)
        .await
        .map_err(|_| missing())?;

    sqlx::query("update share_links set revoked = true where token = $1")
        .bind(&token)
        .execute(&state.pool)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ResolvedLink {
    doc: Uuid,
    role: DocumentRole,
    session_token: String,
}

/// The only unauthenticated route. The 128 bit token is the credential, so a
/// wrong or revoked one is indistinguishable from one that never existed.
pub async fn resolve_link(
    State(state): State<AppState>,
    Path(token): Path<String>,
) -> Result<Json<ResolvedLink>, ApiError> {
    let link = live_link(&state.pool, &token)
        .await?
        .ok_or_else(|| ApiError::not_found("no such link"))?;
    let session_token = state
        .auth
        .mint_session(link.document_id, link.role, &token)?;
    Ok(Json(ResolvedLink {
        doc: link.document_id,
        role: link.role,
        session_token,
    }))
}
