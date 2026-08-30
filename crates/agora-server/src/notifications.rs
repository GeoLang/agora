use std::collections::BTreeSet;

use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sqlx::{PgConnection, Row};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::AppState;
use crate::auth::Caller;
use crate::error::ApiError;
use crate::limits::{MAX_USER_ID_BYTES, NOTIFICATION_EXCERPT_CHARS, NOTIFICATIONS_PAGE_SIZE};

/// The `mentions` entries of a comment value that could name a member: an
/// array of `{userId}` objects. Anything else in the value stays opaque to the
/// server, the same as every other op.
fn mentioned_user_ids(value: &Value) -> BTreeSet<String> {
    let Some(mentions) = value.get("mentions").and_then(Value::as_array) else {
        return BTreeSet::new();
    };
    mentions
        .iter()
        .filter_map(|mention| mention.get("userId").and_then(Value::as_str))
        .filter(|user_id| !user_id.is_empty() && user_id.len() <= MAX_USER_ID_BYTES)
        .map(str::to_string)
        .collect()
}

fn char_prefix(text: &str, cap: usize) -> String {
    text.chars().take(cap).collect()
}

/// Write the notifications one comment op earns, on the op's own transaction so
/// a refused op never leaves a notification behind.
///
/// Only mentions absent from the key's previous value notify, so resolving or
/// editing a comment does not ping its mentions again. Recipients are filtered
/// to current document members, and never the acting user. A deleted comment
/// takes its unread notifications with it.
pub async fn record_comment_mentions(
    connection: &mut PgConnection,
    document_id: Uuid,
    comment_id: &str,
    actor: &str,
    previous: Option<&Value>,
    value: Option<&Value>,
) -> Result<(), sqlx::Error> {
    let Some(value) = value else {
        sqlx::query(
            "delete from notifications
             where doc_id = $1 and comment_id = $2 and read_at is null",
        )
        .bind(document_id)
        .bind(comment_id)
        .execute(&mut *connection)
        .await?;
        return Ok(());
    };

    let already_mentioned = previous.map(mentioned_user_ids).unwrap_or_default();
    let fresh: Vec<String> = mentioned_user_ids(value)
        .into_iter()
        .filter(|user_id| !already_mentioned.contains(user_id) && user_id != actor)
        .collect();
    if fresh.is_empty() {
        return Ok(());
    }

    let recipients: Vec<String> =
        sqlx::query_scalar("select user_id from members where doc_id = $1 and user_id = any($2)")
            .bind(document_id)
            .bind(&fresh)
            .fetch_all(&mut *connection)
            .await?;
    if recipients.is_empty() {
        return Ok(());
    }

    let author_name = value
        .get("authorName")
        .and_then(Value::as_str)
        .unwrap_or(actor);
    let author_name = char_prefix(author_name, NOTIFICATION_EXCERPT_CHARS);
    let excerpt = char_prefix(
        value.get("text").and_then(Value::as_str).unwrap_or(""),
        NOTIFICATION_EXCERPT_CHARS,
    );
    for user_id in recipients {
        sqlx::query(
            "insert into notifications (id, user_id, doc_id, comment_id, author_name, excerpt)
             values ($1, $2, $3, $4, $5, $6)",
        )
        .bind(Uuid::new_v4())
        .bind(user_id)
        .bind(document_id)
        .bind(comment_id)
        .bind(&author_name)
        .bind(&excerpt)
        .execute(&mut *connection)
        .await?;
    }
    Ok(())
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NotificationEntry {
    id: Uuid,
    doc_id: Uuid,
    doc_name: String,
    comment_id: String,
    author_name: String,
    excerpt: String,
    #[serde(with = "time::serde::rfc3339")]
    created_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339::option")]
    read_at: Option<OffsetDateTime>,
}

pub async fn list_notifications(
    State(state): State<AppState>,
    caller: Caller,
) -> Result<Json<Vec<NotificationEntry>>, ApiError> {
    let rows = sqlx::query(
        "select n.id, n.doc_id, d.name as doc_name, n.comment_id, n.author_name,
                n.excerpt, n.created_at, n.read_at
         from notifications n join documents d on d.id = n.doc_id
         where n.user_id = $1
         order by n.created_at desc, n.id limit $2",
    )
    .bind(&caller.user_id)
    .bind(NOTIFICATIONS_PAGE_SIZE)
    .fetch_all(&state.pool)
    .await?;

    let mut entries = Vec::with_capacity(rows.len());
    for row in rows {
        entries.push(NotificationEntry {
            id: row.try_get("id")?,
            doc_id: row.try_get("doc_id")?,
            doc_name: row.try_get("doc_name")?,
            comment_id: row.try_get("comment_id")?,
            author_name: row.try_get("author_name")?,
            excerpt: row.try_get("excerpt")?,
            created_at: row.try_get("created_at")?,
            read_at: row.try_get("read_at")?,
        });
    }
    Ok(Json(entries))
}

/// `ids` marks just those notifications, absent marks everything unread. Ids
/// belonging to someone else are simply not matched.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MarkReadRequest {
    ids: Option<Vec<Uuid>>,
}

pub async fn mark_notifications_read(
    State(state): State<AppState>,
    caller: Caller,
    Json(request): Json<MarkReadRequest>,
) -> Result<StatusCode, ApiError> {
    match request.ids {
        Some(ids) => {
            sqlx::query(
                "update notifications set read_at = now()
                 where user_id = $1 and id = any($2) and read_at is null",
            )
            .bind(&caller.user_id)
            .bind(&ids)
            .execute(&state.pool)
            .await?;
        }
        None => {
            sqlx::query(
                "update notifications set read_at = now()
                 where user_id = $1 and read_at is null",
            )
            .bind(&caller.user_id)
            .execute(&state.pool)
            .await?;
        }
    }
    Ok(StatusCode::NO_CONTENT)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn mentions_come_only_from_well_formed_entries() {
        let value = json!({
            "text": "ping",
            "mentions": [
                {"userId": "ada", "name": "Ada"},
                {"userId": "ada"},
                {"userId": ""},
                {"userId": 7},
                {"name": "no id"},
                "bare string",
                {"userId": "x".repeat(MAX_USER_ID_BYTES + 1)}
            ]
        });
        let ids = mentioned_user_ids(&value);
        assert_eq!(ids.into_iter().collect::<Vec<_>>(), vec!["ada"]);

        assert!(mentioned_user_ids(&json!({"text": "none"})).is_empty());
        assert!(mentioned_user_ids(&json!({"mentions": "not an array"})).is_empty());
    }

    #[test]
    fn excerpts_cut_on_a_character_boundary() {
        let text = "é".repeat(NOTIFICATION_EXCERPT_CHARS + 40);
        let excerpt = char_prefix(&text, NOTIFICATION_EXCERPT_CHARS);
        assert_eq!(excerpt.chars().count(), NOTIFICATION_EXCERPT_CHARS);
        assert_eq!(char_prefix("short", NOTIFICATION_EXCERPT_CHARS), "short");
    }
}
