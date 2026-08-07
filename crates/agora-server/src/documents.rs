use axum::Json;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use serde::{Deserialize, Serialize};
use sqlx::{PgPool, Row};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::AppState;
use crate::auth::Caller;
use crate::error::ApiError;
use crate::role::DocumentRole;
use crate::state::{DocumentState, valid_document_name};

/// The caller's role on a document, or `None` when they are not a member. An
/// unreadable role denies access rather than defaulting to one.
pub async fn member_role(
    pool: &PgPool,
    document_id: Uuid,
    user_id: &str,
) -> Result<Option<DocumentRole>, sqlx::Error> {
    let row = sqlx::query("select role from members where doc_id = $1 and user_id = $2")
        .bind(document_id)
        .bind(user_id)
        .fetch_optional(pool)
        .await?;
    let Some(row) = row else {
        return Ok(None);
    };
    let role: String = row.try_get("role")?;
    Ok(DocumentRole::parse(&role))
}

/// A non member gets the same answer as someone asking about a document that
/// does not exist, so document ids cannot be probed.
pub async fn require_member(
    pool: &PgPool,
    document_id: Uuid,
    user_id: &str,
) -> Result<DocumentRole, ApiError> {
    member_role(pool, document_id, user_id)
        .await?
        .ok_or_else(|| ApiError::not_found("no such document"))
}

pub async fn require_editor(
    pool: &PgPool,
    document_id: Uuid,
    user_id: &str,
) -> Result<(), ApiError> {
    if require_member(pool, document_id, user_id).await?.can_edit() {
        return Ok(());
    }
    Err(ApiError::forbidden("edit role required"))
}

#[derive(Debug, Deserialize)]
pub struct CreateDocumentRequest {
    name: String,
}

#[derive(Debug, Serialize)]
pub struct CreatedDocument {
    id: Uuid,
    name: String,
}

pub async fn create_document(
    State(state): State<AppState>,
    caller: Caller,
    Json(request): Json<CreateDocumentRequest>,
) -> Result<(StatusCode, Json<CreatedDocument>), ApiError> {
    let name = request.name.trim().to_string();
    if !valid_document_name(&name) {
        return Err(ApiError::bad_request("invalid document name"));
    }

    let document_id = Uuid::new_v4();
    let checkpoint = DocumentState::new(&name).snapshot();
    let mut transaction = state.pool.begin().await?;
    sqlx::query(
        "insert into documents (id, name, created_by, checkpoint, checkpoint_seq)
         values ($1, $2, $3, $4, 0)",
    )
    .bind(document_id)
    .bind(&name)
    .bind(&caller.user_id)
    .bind(checkpoint)
    .execute(&mut *transaction)
    .await?;
    sqlx::query("insert into members (doc_id, user_id, role) values ($1, $2, 'edit')")
        .bind(document_id)
        .bind(&caller.user_id)
        .execute(&mut *transaction)
        .await?;
    transaction.commit().await?;

    Ok((
        StatusCode::CREATED,
        Json(CreatedDocument {
            id: document_id,
            name,
        }),
    ))
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DocumentSummary {
    id: Uuid,
    name: String,
    role: DocumentRole,
    #[serde(with = "time::serde::rfc3339")]
    created_at: OffsetDateTime,
}

pub async fn list_documents(
    State(state): State<AppState>,
    caller: Caller,
) -> Result<Json<Vec<DocumentSummary>>, ApiError> {
    let rows = sqlx::query(
        "select d.id, d.name, d.created_at, m.role
         from documents d join members m on m.doc_id = d.id
         where m.user_id = $1 order by d.created_at desc",
    )
    .bind(&caller.user_id)
    .fetch_all(&state.pool)
    .await?;

    let mut summaries = Vec::with_capacity(rows.len());
    for row in rows {
        let role: String = row.try_get("role")?;
        let Some(role) = DocumentRole::parse(&role) else {
            continue;
        };
        summaries.push(DocumentSummary {
            id: row.try_get("id")?,
            name: row.try_get("name")?,
            role,
            created_at: row.try_get("created_at")?,
        });
    }
    Ok(Json(summaries))
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MemberEntry {
    user_id: String,
    role: DocumentRole,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DocumentDetail {
    id: Uuid,
    name: String,
    created_by: String,
    #[serde(with = "time::serde::rfc3339")]
    created_at: OffsetDateTime,
    members: Vec<MemberEntry>,
}

pub async fn get_document(
    State(state): State<AppState>,
    caller: Caller,
    Path(document_id): Path<Uuid>,
) -> Result<Json<DocumentDetail>, ApiError> {
    require_member(&state.pool, document_id, &caller.user_id).await?;

    let row = sqlx::query("select id, name, created_by, created_at from documents where id = $1")
        .bind(document_id)
        .fetch_optional(&state.pool)
        .await?
        .ok_or_else(|| ApiError::not_found("no such document"))?;

    let member_rows =
        sqlx::query("select user_id, role from members where doc_id = $1 order by user_id")
            .bind(document_id)
            .fetch_all(&state.pool)
            .await?;
    let mut members = Vec::with_capacity(member_rows.len());
    for member in member_rows {
        let role: String = member.try_get("role")?;
        let Some(role) = DocumentRole::parse(&role) else {
            continue;
        };
        members.push(MemberEntry {
            user_id: member.try_get("user_id")?,
            role,
        });
    }

    Ok(Json(DocumentDetail {
        id: row.try_get("id")?,
        name: row.try_get("name")?,
        created_by: row.try_get("created_by")?,
        created_at: row.try_get("created_at")?,
        members,
    }))
}
