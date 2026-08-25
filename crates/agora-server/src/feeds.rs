use axum::Json;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use serde::{Deserialize, Serialize};
use sqlx::{PgPool, Row};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::AppState;
use crate::auth::Caller;
use crate::documents::{project_grant, require_editor, require_member};
use crate::error::ApiError;
use crate::limits::{MAX_FEED_INTERVAL_SECONDS, MIN_FEED_INTERVAL_SECONDS};
use crate::state::valid_name;

/// One sensor feed reporting to a document.
pub struct Feed {
    pub id: Uuid,
    pub document_id: Uuid,
    pub interval_seconds: i32,
}

/// The feed a token names, or `None` when the row is gone. Deleting the row is
/// how a feed token is revoked, so this lookup is what makes revocation take
/// effect rather than anything in the token.
pub async fn feed(pool: &PgPool, feed_id: Uuid) -> Result<Option<Feed>, sqlx::Error> {
    let row = sqlx::query("select id, doc_id, interval_seconds from feeds where id = $1")
        .bind(feed_id)
        .fetch_optional(pool)
        .await?;
    let Some(row) = row else {
        return Ok(None);
    };
    Ok(Some(Feed {
        id: row.try_get("id")?,
        document_id: row.try_get("doc_id")?,
        interval_seconds: row.try_get("interval_seconds")?,
    }))
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateFeedRequest {
    name: String,
    interval_seconds: i32,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CreatedFeed {
    id: Uuid,
    name: String,
    interval_seconds: i32,
    token: String,
}

/// Register a feed and hand back its token. Edit role, the same lookup an op
/// write goes through.
///
/// The token is returned here and never stored, so this reply is the only place
/// it exists. A lost one is replaced by deleting the feed and creating another.
pub async fn create_feed(
    State(state): State<AppState>,
    caller: Caller,
    Path(document_id): Path<Uuid>,
    Json(request): Json<CreateFeedRequest>,
) -> Result<(StatusCode, Json<CreatedFeed>), ApiError> {
    let grant = project_grant(&state, document_id, &caller).await?;
    require_editor(&state.pool, document_id, &caller.user_id, grant).await?;

    let name = request.name.trim().to_string();
    if !valid_name(&name) {
        return Err(ApiError::bad_request("invalid feed name"));
    }
    let interval_seconds = request.interval_seconds;
    if !(MIN_FEED_INTERVAL_SECONDS..=MAX_FEED_INTERVAL_SECONDS).contains(&interval_seconds) {
        return Err(ApiError::bad_request("feed interval out of range"));
    }

    let feed_id = Uuid::new_v4();
    let token = state.auth.mint_feed(feed_id, document_id)?;
    sqlx::query(
        "insert into feeds (id, doc_id, name, interval_seconds, created_by)
         values ($1, $2, $3, $4, $5)",
    )
    .bind(feed_id)
    .bind(document_id)
    .bind(&name)
    .bind(interval_seconds)
    .bind(&caller.user_id)
    .execute(&state.pool)
    .await?;

    Ok((
        StatusCode::CREATED,
        Json(CreatedFeed {
            id: feed_id,
            name,
            interval_seconds,
            token,
        }),
    ))
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FeedSummary {
    id: Uuid,
    name: String,
    interval_seconds: i32,
    created_by: String,
    #[serde(with = "time::serde::rfc3339")]
    created_at: OffsetDateTime,
}

pub async fn list_feeds(
    State(state): State<AppState>,
    caller: Caller,
    Path(document_id): Path<Uuid>,
) -> Result<Json<Vec<FeedSummary>>, ApiError> {
    let grant = project_grant(&state, document_id, &caller).await?;
    require_member(&state.pool, document_id, &caller.user_id, grant).await?;

    let rows = sqlx::query(
        "select id, name, interval_seconds, created_by, created_at
         from feeds where doc_id = $1 order by created_at, id",
    )
    .bind(document_id)
    .fetch_all(&state.pool)
    .await?;

    let mut summaries = Vec::with_capacity(rows.len());
    for row in rows {
        summaries.push(FeedSummary {
            id: row.try_get("id")?,
            name: row.try_get("name")?,
            interval_seconds: row.try_get("interval_seconds")?,
            created_by: row.try_get("created_by")?,
            created_at: row.try_get("created_at")?,
        });
    }
    Ok(Json(summaries))
}

/// Revoke a feed. Its readings cascade away with it, and an ingest socket still
/// holding the token is closed on its next frame, because the insert no longer
/// has a feed row to point at.
pub async fn delete_feed(
    State(state): State<AppState>,
    caller: Caller,
    Path((document_id, feed_id)): Path<(Uuid, Uuid)>,
) -> Result<StatusCode, ApiError> {
    let grant = project_grant(&state, document_id, &caller).await?;
    require_editor(&state.pool, document_id, &caller.user_id, grant).await?;

    let deleted = sqlx::query("delete from feeds where id = $1 and doc_id = $2")
        .bind(feed_id)
        .bind(document_id)
        .execute(&state.pool)
        .await?
        .rows_affected();
    if deleted == 0 {
        return Err(ApiError::not_found("no such feed"));
    }
    Ok(StatusCode::NO_CONTENT)
}
