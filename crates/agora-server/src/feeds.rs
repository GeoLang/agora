use axum::Json;
use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::Response;
use futures_util::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use sqlx::{PgPool, Row};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use uuid::Uuid;

use crate::AppState;
use crate::assets::{rfc3339, valid_reading_identifier};
use crate::auth::{BEARER_SUBPROTOCOL, Caller, websocket_token};
use crate::documents::{project_grant, require_editor, require_member};
use crate::error::ApiError;
use crate::limits::{
    MAX_FEED_INTERVAL_SECONDS, MAX_FEED_READINGS_PER_FRAME, MAX_FEED_READINGS_PER_SECOND,
    MAX_INBOUND_FRAME_BYTES, MIN_FEED_INTERVAL_SECONDS, RateLimiter,
};
use crate::protocol::{FeedMessage, FeedReading, FeedReply, Reading, ServerMessage};
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

/// No `Debug`: `token` is a bearer credential and must never reach a log line.
#[derive(Deserialize)]
pub struct IngestQuery {
    token: Option<String>,
}

/// The socket a sensor feed pushes readings into.
///
/// The token names a feed and a document, and both have to match a live feed
/// row. It reaches nothing else: it is not a caller anywhere, and all it can do
/// here is append readings to that one feed. A revoked feed, a forged one and a
/// token of any other kind are one answer, so a feed id cannot be probed.
pub async fn ingest(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<IngestQuery>,
    upgrade: WebSocketUpgrade,
) -> Result<Response, ApiError> {
    let token = websocket_token(&headers, query.token.as_deref())
        .ok_or_else(|| ApiError::unauthorized("missing bearer token"))?;
    let refused = || ApiError::unauthorized("invalid or expired token");
    let claims = state.auth.verify_feed(token).ok_or_else(refused)?;
    let feed = feed(&state.pool, claims.sub)
        .await?
        .filter(|feed| feed.document_id == claims.doc)
        .ok_or_else(refused)?;

    Ok(upgrade
        .protocols([BEARER_SUBPROTOCOL])
        .max_message_size(MAX_INBOUND_FRAME_BYTES)
        .on_upgrade(move |socket| async move {
            run(state, socket, feed).await;
        }))
}

/// One reading that has passed every check and is ready to store.
#[derive(Debug, PartialEq)]
struct AcceptedReading {
    asset: String,
    kind: String,
    value: f64,
    at: OffsetDateTime,
}

/// Anything a frame can be refused for. A feed is a device rather than a person,
/// so a refusal closes the socket instead of leaving it open: whatever the feed
/// is sending, it will keep sending until it reconnects.
async fn close_with(mut socket: WebSocket, reason: &str) {
    let message = FeedReply::error(reason).encode();
    let _ = socket.send(Message::text(message.as_ref())).await;
    let _ = socket.close().await;
}

async fn run(state: AppState, mut socket: WebSocket, feed: Feed) {
    let mut limiter = RateLimiter::with_cap(MAX_FEED_READINGS_PER_SECOND);
    while let Some(Ok(message)) = socket.next().await {
        let text = match message {
            Message::Text(text) => text,
            Message::Binary(_) => {
                return close_with(socket, "binary frames are not accepted").await;
            }
            Message::Close(_) => return,
            Message::Ping(_) | Message::Pong(_) => continue,
        };
        let count = match accept(&state, &feed, &mut limiter, text.as_str()).await {
            Ok(count) => count,
            Err(reason) => return close_with(socket, reason).await,
        };
        let ack = FeedReply::Ack { count }.encode();
        if socket.send(Message::text(ack.as_ref())).await.is_err() {
            return;
        }
    }
}

/// Validate, store and fan out one frame, and return how many readings it
/// carried. The `Err` is the reason the socket closes with.
async fn accept(
    state: &AppState,
    feed: &Feed,
    limiter: &mut RateLimiter,
    text: &str,
) -> Result<usize, &'static str> {
    let Ok(FeedMessage::Readings { readings }) = serde_json::from_str::<FeedMessage>(text) else {
        return Err("malformed message");
    };
    if readings.is_empty() {
        return Err("frame carries no readings");
    }
    if readings.len() > MAX_FEED_READINGS_PER_FRAME {
        return Err("too many readings");
    }
    if !limiter.allow_many(readings.len()) {
        return Err("rate limit exceeded");
    }

    let now = OffsetDateTime::now_utc();
    let accepted = readings
        .into_iter()
        .map(|reading| validate(reading, now))
        .collect::<Result<Vec<_>, _>>()?;

    store(&state.pool, feed.id, &accepted).await?;
    relay(state, feed, &accepted, now).await;
    Ok(accepted.len())
}

fn validate(reading: FeedReading, now: OffsetDateTime) -> Result<AcceptedReading, &'static str> {
    if !valid_reading_identifier(&reading.asset) {
        return Err("invalid asset id");
    }
    if !valid_reading_identifier(&reading.kind) {
        return Err("invalid reading kind");
    }
    if !reading.value.is_finite() {
        return Err("reading value is not a finite number");
    }
    let at = match reading.at.as_deref() {
        Some(at) => OffsetDateTime::parse(at, &Rfc3339).map_err(|_| "invalid reading time")?,
        None => now,
    };
    Ok(AcceptedReading {
        asset: reading.asset,
        kind: reading.kind,
        value: reading.value,
        at,
    })
}

/// One insert for the whole frame. A reading that repeats one already stored is
/// dropped, so a feed replaying after a reconnect costs nothing.
///
/// A deleted feed lands here as a foreign key violation, which is what closes a
/// socket whose feed was revoked while it was open.
async fn store(
    pool: &PgPool,
    feed_id: Uuid,
    readings: &[AcceptedReading],
) -> Result<(), &'static str> {
    let assets: Vec<&str> = readings
        .iter()
        .map(|reading| reading.asset.as_str())
        .collect();
    let kinds: Vec<&str> = readings
        .iter()
        .map(|reading| reading.kind.as_str())
        .collect();
    let times: Vec<OffsetDateTime> = readings.iter().map(|reading| reading.at).collect();
    let values: Vec<f64> = readings.iter().map(|reading| reading.value).collect();

    let outcome = sqlx::query(
        "insert into readings (feed_id, asset_id, kind, at, value)
         select $1, asset_id, kind, at, value
         from unnest($2::text[], $3::text[], $4::timestamptz[], $5::float8[])
             as reading (asset_id, kind, at, value)
         on conflict do nothing",
    )
    .bind(feed_id)
    .bind(&assets)
    .bind(&kinds)
    .bind(&times)
    .bind(&values)
    .execute(pool)
    .await;

    match outcome {
        Ok(_) => Ok(()),
        Err(sqlx::Error::Database(error)) if error.is_foreign_key_violation() => {
            Err("feed revoked")
        }
        Err(_) => Err("database error"),
    }
}

/// Hand the frame to everyone looking at the document, then tell them about any
/// asset that has started reporting again. A document nobody has open has no
/// room, and its tracker is rebuilt from the readings the next time one loads.
async fn relay(state: &AppState, feed: &Feed, readings: &[AcceptedReading], now: OffsetDateTime) {
    let Some(room) = state.rooms.loaded(feed.document_id).await else {
        return;
    };
    room.relay(&ServerMessage::Readings {
        feed: feed.id,
        readings: readings
            .iter()
            .map(|reading| Reading {
                asset: reading.asset.clone(),
                kind: reading.kind.clone(),
                value: reading.value,
                at: rfc3339(reading.at),
            })
            .collect(),
    });

    let reported: Vec<(&str, OffsetDateTime)> = readings
        .iter()
        .map(|reading| (reading.asset.as_str(), reading.at))
        .collect();
    let came_online = room
        .record_readings(feed.id, feed.interval_seconds, &reported, now)
        .await;
    for (asset, at) in came_online {
        room.relay(&ServerMessage::Liveness {
            asset,
            online: true,
            at: rfc3339(at),
        });
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    fn sent(asset: &str, kind: &str, value: f64, at: Option<&str>) -> FeedReading {
        FeedReading {
            asset: asset.to_string(),
            kind: kind.to_string(),
            value,
            at: at.map(str::to_owned),
        }
    }

    fn now() -> OffsetDateTime {
        OffsetDateTime::UNIX_EPOCH
    }

    #[test]
    fn a_reading_with_no_time_is_stamped_when_the_frame_arrived() {
        let accepted = validate(sent("TWIN-03", "temperature", 21.5, None), now()).unwrap();
        assert_eq!(accepted.at, now());
        assert_eq!(accepted.value, 21.5);

        let stamped = validate(
            sent("TWIN-03", "temperature", 21.5, Some("2026-08-25T12:00:00Z")),
            now(),
        )
        .unwrap();
        assert_eq!(rfc3339(stamped.at), "2026-08-25T12:00:00Z");
    }

    #[test]
    fn a_reading_that_is_not_a_finite_number_is_refused() {
        for value in [f64::NAN, f64::INFINITY, f64::NEG_INFINITY] {
            assert_eq!(
                validate(sent("TWIN-03", "temperature", value, None), now()),
                Err("reading value is not a finite number")
            );
        }
    }

    #[test]
    fn a_reading_naming_a_bad_asset_kind_or_time_is_refused() {
        assert_eq!(
            validate(sent("TWIN 03", "temperature", 1.0, None), now()),
            Err("invalid asset id")
        );
        assert_eq!(
            validate(sent("TWIN-03", "", 1.0, None), now()),
            Err("invalid reading kind")
        );
        assert_eq!(
            validate(
                sent("TWIN-03", "temperature", 1.0, Some("yesterday")),
                now()
            ),
            Err("invalid reading time")
        );
    }
}
