use axum::Json;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use serde::{Deserialize, Serialize};
use sqlx::{PgConnection, PgExecutor, Row};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::AppState;
use crate::auth::Caller;
use crate::error::ApiError;
use crate::limits::MAX_USER_ID_BYTES;
use crate::projects::{ProjectGrant, widest_role};
use crate::role::DocumentRole;
use crate::state::{DocumentState, valid_document_name};

/// The caller's row in the members table, or `None` when they have none. An
/// unreadable role denies access rather than defaulting to one.
///
/// Takes any executor so a mutation can read the role on its own transaction's
/// connection, where a lock already held there covers the row, rather than on a
/// pool connection where the answer can go stale before the write.
pub async fn member_role(
    executor: impl PgExecutor<'_>,
    document_id: Uuid,
    user_id: &str,
) -> Result<Option<DocumentRole>, sqlx::Error> {
    let row = sqlx::query("select role from members where doc_id = $1 and user_id = $2")
        .bind(document_id)
        .bind(user_id)
        .fetch_optional(executor)
        .await?;
    let Some(row) = row else {
        return Ok(None);
    };
    let role: String = row.try_get("role")?;
    Ok(DocumentRole::parse(&role))
}

/// The project a document belongs to, or `None` when it belongs to none and when
/// there is no such document. A document that is not there has no project role
/// to find, which is the same answer as an unlinked one.
pub async fn document_project(
    executor: impl PgExecutor<'_>,
    document_id: Uuid,
) -> Result<Option<Uuid>, sqlx::Error> {
    let project_id =
        sqlx::query_scalar::<_, Option<Uuid>>("select project_id from documents where id = $1")
            .bind(document_id)
            .fetch_optional(executor)
            .await?;
    Ok(project_id.flatten())
}

/// What the caller's project membership grants on this document.
///
/// Resolved before any transaction opens, because a call to ptolemy must never
/// run while this request holds a row lock.
///
/// Fails closed at every step: no configured resolver, an unlinked document, a
/// credential that is not a platform token, and a ptolemy call that does not
/// answer all give no grant, leaving the members table as the only authority.
pub async fn project_grant(
    state: &AppState,
    document_id: Uuid,
    caller: &Caller,
) -> Result<ProjectGrant, ApiError> {
    let Some(projects) = state.projects.as_deref() else {
        return Ok(ProjectGrant::none());
    };
    let Some(token) = caller.platform_token.as_ref() else {
        return Ok(ProjectGrant::none());
    };
    let Some(project_id) = document_project(&state.pool, document_id).await? else {
        return Ok(ProjectGrant::none());
    };
    Ok(projects
        .document_grant(document_id, &caller.user_id, project_id, token)
        .await)
}

/// The caller's role on a document: the wider of their members row and the
/// project grant handed in. `None` denies access.
pub async fn effective_role(
    executor: impl PgExecutor<'_>,
    document_id: Uuid,
    user_id: &str,
    grant: ProjectGrant,
) -> Result<Option<DocumentRole>, sqlx::Error> {
    Ok(widest_role(
        member_role(executor, document_id, user_id).await?,
        grant,
    ))
}

/// A caller with neither a members row nor a project grant gets the same answer
/// as someone asking about a document that does not exist, so document ids
/// cannot be probed.
pub async fn require_member(
    executor: impl PgExecutor<'_>,
    document_id: Uuid,
    user_id: &str,
    grant: ProjectGrant,
) -> Result<DocumentRole, ApiError> {
    effective_role(executor, document_id, user_id, grant)
        .await?
        .ok_or_else(|| ApiError::not_found("no such document"))
}

pub async fn require_editor(
    executor: impl PgExecutor<'_>,
    document_id: Uuid,
    user_id: &str,
    grant: ProjectGrant,
) -> Result<(), ApiError> {
    if require_member(executor, document_id, user_id, grant)
        .await?
        .can_edit()
    {
        return Ok(());
    }
    Err(ApiError::forbidden("edit role required"))
}

/// Editor or owner on the project, asked fresh so a membership dropped seconds
/// ago cannot still link a document.
///
/// Both a refusal and a ptolemy that cannot be reached land here as a refusal:
/// this is a write, so an unresolvable project role must not authorize it.
async fn require_project_editor(
    state: &AppState,
    project_id: Uuid,
    caller: &Caller,
) -> Result<(), ApiError> {
    let Some(projects) = state.projects.as_deref() else {
        return Err(ApiError::bad_request("project links are not enabled"));
    };
    let Some(token) = caller.platform_token.as_ref() else {
        return Err(ApiError::forbidden(
            "a platform token is required to link a project",
        ));
    };
    match projects.project_role(project_id, token).await {
        Some(role) if role.can_link_a_document() => Ok(()),
        _ => Err(ApiError::forbidden(
            "editor or owner on the project is required",
        )),
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateDocumentRequest {
    name: String,
    #[serde(default)]
    project_id: Option<Uuid>,
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
    if let Some(project_id) = request.project_id {
        require_project_editor(&state, project_id, &caller).await?;
    }

    let document_id = Uuid::new_v4();
    let checkpoint = DocumentState::new(&name).snapshot();
    let mut transaction = state.pool.begin().await?;
    sqlx::query(
        "insert into documents (id, name, created_by, checkpoint, checkpoint_seq, project_id)
         values ($1, $2, $3, $4, 0, $5)",
    )
    .bind(document_id)
    .bind(&name)
    .bind(&caller.user_id)
    .bind(checkpoint)
    .bind(request.project_id)
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
    project_id: Option<Uuid>,
    members: Vec<MemberEntry>,
}

pub async fn get_document(
    State(state): State<AppState>,
    caller: Caller,
    Path(document_id): Path<Uuid>,
) -> Result<Json<DocumentDetail>, ApiError> {
    let grant = project_grant(&state, document_id, &caller).await?;
    require_member(&state.pool, document_id, &caller.user_id, grant).await?;

    let row = sqlx::query(
        "select id, name, created_by, created_at, project_id from documents where id = $1",
    )
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
        project_id: row.try_get("project_id")?,
        members,
    }))
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SetProjectRequest {
    /// `null` unlinks the document.
    project_id: Option<Uuid>,
}

/// Point a document at a project, or unlink it.
///
/// Edit on the document either way. Linking also takes editor or owner on the
/// project being named, so reading a project is not enough to pull a document
/// under it and widen who reaches the document.
///
/// Unlinking takes only document edit: it narrows access rather than widening
/// it, and a project the caller has since left must still be droppable.
pub async fn set_document_project(
    State(state): State<AppState>,
    caller: Caller,
    Path(document_id): Path<Uuid>,
    Json(request): Json<SetProjectRequest>,
) -> Result<StatusCode, ApiError> {
    let grant = project_grant(&state, document_id, &caller).await?;
    // ahead of the project check so naming a project is not by itself enough to
    // send agora asking ptolemy about it. the check under the lock below is the
    // one the write rests on
    require_editor(&state.pool, document_id, &caller.user_id, grant).await?;
    if let Some(project_id) = request.project_id {
        require_project_editor(&state, project_id, &caller).await?;
    }

    let mut transaction = state.pool.begin().await?;
    lock_editors(&mut transaction, document_id).await?;
    require_editor(&mut *transaction, document_id, &caller.user_id, grant).await?;
    let updated = sqlx::query("update documents set project_id = $2 where id = $1")
        .bind(document_id)
        .bind(request.project_id)
        .execute(&mut *transaction)
        .await?
        .rows_affected();
    if updated == 0 {
        return Err(ApiError::not_found("no such document"));
    }
    transaction.commit().await?;

    Ok(StatusCode::NO_CONTENT)
}

/// A user id is whatever the platform put in a token's `sub`. Agora has no user
/// directory, so there is nothing to look it up against.
fn valid_user_id(user_id: &str) -> bool {
    !user_id.trim().is_empty()
        && user_id.len() <= MAX_USER_ID_BYTES
        && !user_id.chars().any(char::is_control)
}

/// The document's edit members, locked for the rest of the transaction. Without
/// the lock two concurrent removals each see the other editor and commit,
/// leaving the document with none.
///
/// The lock also covers the caller's own row whenever the caller is an editor,
/// which is what makes the role check that follows it trustworthy: a concurrent
/// demotion of the caller either lands before this lock and is seen, or blocks
/// behind it until the mutation has committed.
async fn lock_editors(
    connection: &mut PgConnection,
    document_id: Uuid,
) -> Result<Vec<String>, sqlx::Error> {
    sqlx::query_scalar("select user_id from members where doc_id = $1 and role = 'edit' for update")
        .bind(document_id)
        .fetch_all(connection)
        .await
}

fn is_the_last_editor(editors: &[String], user_id: &str) -> bool {
    editors.len() == 1 && editors[0] == user_id
}

#[derive(Debug, Deserialize)]
pub struct SetMemberRequest {
    role: DocumentRole,
}

/// Add a member or change their role. One idempotent operation, so a client
/// does not have to know whether the row already exists.
pub async fn set_member(
    State(state): State<AppState>,
    caller: Caller,
    Path((document_id, user_id)): Path<(Uuid, String)>,
    Json(request): Json<SetMemberRequest>,
) -> Result<StatusCode, ApiError> {
    let grant = project_grant(&state, document_id, &caller).await?;
    let mut transaction = state.pool.begin().await?;
    let editors = lock_editors(&mut transaction, document_id).await?;
    require_editor(&mut *transaction, document_id, &caller.user_id, grant).await?;
    if !valid_user_id(&user_id) {
        return Err(ApiError::bad_request("invalid user id"));
    }

    if !request.role.can_edit() && is_the_last_editor(&editors, &user_id) {
        return Err(ApiError::bad_request("the last editor cannot be demoted"));
    }
    sqlx::query(
        "insert into members (doc_id, user_id, role) values ($1, $2, $3)
         on conflict (doc_id, user_id) do update set role = excluded.role",
    )
    .bind(document_id)
    .bind(&user_id)
    .bind(request.role.as_str())
    .execute(&mut *transaction)
    .await?;
    transaction.commit().await?;

    Ok(StatusCode::NO_CONTENT)
}

pub async fn remove_member(
    State(state): State<AppState>,
    caller: Caller,
    Path((document_id, user_id)): Path<(Uuid, String)>,
) -> Result<StatusCode, ApiError> {
    let grant = project_grant(&state, document_id, &caller).await?;
    let mut transaction = state.pool.begin().await?;
    let editors = lock_editors(&mut transaction, document_id).await?;
    require_editor(&mut *transaction, document_id, &caller.user_id, grant).await?;

    if is_the_last_editor(&editors, &user_id) {
        return Err(ApiError::bad_request("the last editor cannot be removed"));
    }
    let removed = sqlx::query("delete from members where doc_id = $1 and user_id = $2")
        .bind(document_id)
        .bind(&user_id)
        .execute(&mut *transaction)
        .await?
        .rows_affected();
    if removed == 0 {
        return Err(ApiError::not_found("no such member"));
    }
    sqlx::query("delete from notifications where doc_id = $1 and user_id = $2")
        .bind(document_id)
        .bind(&user_id)
        .execute(&mut *transaction)
        .await?;
    transaction.commit().await?;

    Ok(StatusCode::NO_CONTENT)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn user_ids_are_bounded_and_printable() {
        assert!(valid_user_id("user-1"));
        assert!(valid_user_id(&"a".repeat(MAX_USER_ID_BYTES)));
        assert!(!valid_user_id(""));
        assert!(!valid_user_id("   "));
        assert!(!valid_user_id("user\n1"));
        assert!(!valid_user_id(&"a".repeat(MAX_USER_ID_BYTES + 1)));
    }

    #[test]
    fn only_a_sole_editor_is_the_last_one() {
        let editors = vec!["ada".to_string()];
        assert!(is_the_last_editor(&editors, "ada"));
        assert!(!is_the_last_editor(&editors, "grace"));

        let two = vec!["ada".to_string(), "grace".to_string()];
        assert!(!is_the_last_editor(&two, "ada"));
        assert!(!is_the_last_editor(&[], "ada"));
    }
}
