use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration as StandardDuration;

use axum::Json;
use axum::extract::{Path, Query, State};
use serde::{Deserialize, Serialize};
use sqlx::{PgPool, Row};
use time::format_description::well_known::Rfc3339;
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

use crate::AppState;
use crate::auth::Caller;
use crate::documents::{project_grant, require_member};
use crate::error::ApiError;
use crate::limits::{
    MAX_ASSET_ID_BYTES, READINGS_RETENTION_DAYS, READINGS_SWEEP_INTERVAL_HOURS,
    STALE_CHECK_INTERVAL_SECONDS, STALE_MISSED_INTERVALS,
};
use crate::protocol::{AssetState, AssetValue, ServerMessage};
use crate::room::RoomRegistry;

/// The wire form of a reading time. Formatting only fails past year 9999, which
/// the RFC 3339 parse on the way in cannot produce.
pub fn rfc3339(at: OffsetDateTime) -> String {
    at.format(&Rfc3339).unwrap_or_default()
}

/// An asset id and a reading kind are opaque ids a feed chooses, and agora has
/// no asset directory to check them against. No whitespace, so an id stays one
/// word wherever a client renders it.
pub fn valid_reading_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_ASSET_ID_BYTES
        && !value
            .chars()
            .any(|character| character.is_control() || character.is_whitespace())
}

/// Whether an asset still counts as reporting: its newest reading is at or
/// after `now` minus the intervals it is allowed to miss.
///
/// The one predicate behind both the asset routes and the liveness frames, so
/// the two can never disagree about an asset.
pub fn is_online(latest_at: OffsetDateTime, interval_seconds: i32, now: OffsetDateTime) -> bool {
    let allowed = Duration::seconds(i64::from(interval_seconds) * STALE_MISSED_INTERVALS);
    latest_at >= now - allowed
}

struct TrackedAsset {
    feed_id: Uuid,
    interval_seconds: i32,
    latest_at: OffsetDateTime,
    online: bool,
}

/// What a loaded room knows about the assets its feeds report: enough to notice
/// one going quiet, and nothing about the values themselves.
#[derive(Default)]
pub struct AssetTracker {
    assets: HashMap<String, TrackedAsset>,
}

impl AssetTracker {
    /// Note one ingested reading. `true` when the asset was not reporting and
    /// now is, which is what the room relays a liveness frame for.
    ///
    /// A backfilled reading old enough to be stale leaves an offline asset
    /// offline, since the answer comes from the same predicate the routes use.
    pub fn record(
        &mut self,
        asset: &str,
        feed_id: Uuid,
        interval_seconds: i32,
        at: OffsetDateTime,
        now: OffsetDateTime,
    ) -> bool {
        let tracked = self
            .assets
            .entry(asset.to_string())
            .or_insert(TrackedAsset {
                feed_id,
                interval_seconds,
                latest_at: at,
                online: false,
            });
        if at >= tracked.latest_at {
            tracked.latest_at = at;
            tracked.feed_id = feed_id;
            tracked.interval_seconds = interval_seconds;
        }
        let online = is_online(tracked.latest_at, tracked.interval_seconds, now);
        let came_online = online && !tracked.online;
        tracked.online = online;
        came_online
    }

    /// Mark every asset that has missed too many reports offline and hand back
    /// the ones that just flipped.
    pub fn go_offline(&mut self, now: OffsetDateTime) -> Vec<String> {
        let mut gone = Vec::new();
        for (asset, tracked) in &mut self.assets {
            if tracked.online && !is_online(tracked.latest_at, tracked.interval_seconds, now) {
                tracked.online = false;
                gone.push(asset.clone());
            }
        }
        gone
    }
}

/// What every asset on the document was doing when the room loaded, rebuilt
/// from the readings themselves. A room holds no asset state between lives.
pub async fn load_tracker(
    pool: &PgPool,
    document_id: Uuid,
    now: OffsetDateTime,
) -> Result<AssetTracker, sqlx::Error> {
    let rows = sqlx::query(
        "select distinct on (reading.asset_id)
             reading.asset_id, reading.feed_id, reading.at, feed.interval_seconds
         from readings reading
         join feeds feed on feed.id = reading.feed_id
         where feed.doc_id = $1
         order by reading.asset_id, reading.at desc",
    )
    .bind(document_id)
    .fetch_all(pool)
    .await?;

    let mut tracker = AssetTracker::default();
    for row in rows {
        let asset: String = row.try_get("asset_id")?;
        let feed_id: Uuid = row.try_get("feed_id")?;
        let interval_seconds: i32 = row.try_get("interval_seconds")?;
        let latest_at: OffsetDateTime = row.try_get("at")?;
        tracker.assets.insert(
            asset,
            TrackedAsset {
                feed_id,
                interval_seconds,
                latest_at,
                online: is_online(latest_at, interval_seconds, now),
            },
        );
    }
    Ok(tracker)
}

/// Every asset the document's feeds report, with the latest value of each kind
/// at or before `upper_bound`, and liveness judged at `now`.
///
/// `upper_bound` is `None` for the live view, where a reading stamped in the
/// future still counts as the latest.
pub async fn asset_states(
    pool: &PgPool,
    document_id: Uuid,
    upper_bound: Option<OffsetDateTime>,
    now: OffsetDateTime,
) -> Result<Vec<AssetState>, sqlx::Error> {
    let rows = sqlx::query(
        "select distinct on (reading.asset_id, reading.kind)
             reading.asset_id, reading.kind, reading.value, reading.at, reading.feed_id,
             feed.interval_seconds
         from readings reading
         join feeds feed on feed.id = reading.feed_id
         where feed.doc_id = $1 and ($2::timestamptz is null or reading.at <= $2)
         order by reading.asset_id, reading.kind, reading.at desc",
    )
    .bind(document_id)
    .bind(upper_bound)
    .fetch_all(pool)
    .await?;

    // rows arrive grouped by asset, so one asset is finished before the next
    // starts and the feed with its newest reading is the one that reports it
    let mut states: Vec<AssetState> = Vec::new();
    let mut newest: Option<(OffsetDateTime, i32)> = None;
    for row in rows {
        let asset: String = row.try_get("asset_id")?;
        let feed_id: Uuid = row.try_get("feed_id")?;
        let interval_seconds: i32 = row.try_get("interval_seconds")?;
        let at: OffsetDateTime = row.try_get("at")?;
        let value = AssetValue {
            kind: row.try_get("kind")?,
            value: row.try_get("value")?,
            at: rfc3339(at),
        };

        match states.last_mut() {
            Some(state) if state.asset == asset => {
                state.values.push(value);
                if newest.is_none_or(|(latest_at, _)| at > latest_at) {
                    newest = Some((at, interval_seconds));
                    state.feed = feed_id;
                    state.online = is_online(at, interval_seconds, now);
                }
            }
            _ => {
                newest = Some((at, interval_seconds));
                states.push(AssetState {
                    asset,
                    feed: feed_id,
                    online: is_online(at, interval_seconds, now),
                    values: vec![value],
                });
            }
        }
    }
    Ok(states)
}

#[derive(Debug, Serialize)]
pub struct AssetsResponse {
    assets: Vec<AssetState>,
}

pub async fn list_assets(
    State(state): State<AppState>,
    caller: Caller,
    Path(document_id): Path<Uuid>,
) -> Result<Json<AssetsResponse>, ApiError> {
    let grant = project_grant(&state, document_id, &caller).await?;
    require_member(&state.pool, document_id, &caller.user_id, grant).await?;

    let now = OffsetDateTime::now_utc();
    Ok(Json(AssetsResponse {
        assets: asset_states(&state.pool, document_id, None, now).await?,
    }))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AtQuery {
    t: Option<String>,
}

/// The same shape as [`list_assets`] as of a moment in the past: every value the
/// latest at or before `t`, and liveness judged against `t` rather than now.
pub async fn list_assets_at(
    State(state): State<AppState>,
    caller: Caller,
    Path(document_id): Path<Uuid>,
    Query(query): Query<AtQuery>,
) -> Result<Json<AssetsResponse>, ApiError> {
    let grant = project_grant(&state, document_id, &caller).await?;
    require_member(&state.pool, document_id, &caller.user_id, grant).await?;

    let at = query
        .t
        .as_deref()
        .and_then(|t| OffsetDateTime::parse(t, &Rfc3339).ok())
        .ok_or_else(|| ApiError::bad_request("t must be an rfc 3339 time"))?;
    Ok(Json(AssetsResponse {
        assets: asset_states(&state.pool, document_id, Some(at), at).await?,
    }))
}

/// One pass over the loaded rooms, marking the assets that have gone quiet
/// offline and telling everyone looking. Rooms exist only while someone is
/// connected, so an asset nobody is watching flips the next time a room loads.
pub async fn mark_stale(rooms: &RoomRegistry, now: OffsetDateTime) {
    let at = rfc3339(now);
    for room in rooms.loaded_rooms().await {
        for asset in room.mark_assets_offline(now).await {
            room.relay(&ServerMessage::Liveness {
                asset,
                online: false,
                at: at.clone(),
            });
        }
    }
}

/// Started by the binary and not by `router`, so a test drives one pass itself
/// rather than racing this.
pub async fn mark_stale_periodically(rooms: Arc<RoomRegistry>) {
    let period = StandardDuration::from_secs(STALE_CHECK_INTERVAL_SECONDS);
    let mut ticker = tokio::time::interval(period);
    loop {
        ticker.tick().await;
        mark_stale(&rooms, OffsetDateTime::now_utc()).await;
    }
}

/// Delete the readings past the retention window, sensor and watch alike, and
/// return how many went.
pub async fn sweep(pool: &PgPool) -> Result<u64, sqlx::Error> {
    let cutoff = OffsetDateTime::now_utc() - Duration::days(READINGS_RETENTION_DAYS);
    let sensor = sqlx::query("delete from readings where at < $1")
        .bind(cutoff)
        .execute(pool)
        .await?
        .rows_affected();
    let watched = sqlx::query("delete from watch_readings where at < $1")
        .bind(cutoff)
        .execute(pool)
        .await?
        .rows_affected();
    Ok(sensor + watched)
}

pub async fn sweep_periodically(pool: PgPool) {
    let period = StandardDuration::from_secs(READINGS_SWEEP_INTERVAL_HOURS * 60 * 60);
    let mut ticker = tokio::time::interval(period);
    loop {
        ticker.tick().await;
        if let Err(error) = sweep(&pool).await {
            eprintln!("readings sweep failed: {error}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const INTERVAL_SECONDS: i32 = 5;

    fn at(seconds: i64) -> OffsetDateTime {
        OffsetDateTime::UNIX_EPOCH + Duration::seconds(seconds)
    }

    #[test]
    fn asset_ids_and_kinds_are_bounded_and_carry_no_whitespace() {
        assert!(valid_reading_identifier("TWIN-03"));
        assert!(valid_reading_identifier("temperature"));
        assert!(valid_reading_identifier(&"a".repeat(MAX_ASSET_ID_BYTES)));
        for value in [
            "",
            " ",
            "TWIN 03",
            "TWIN\t03",
            "TWIN\n03",
            "TWIN\u{0}03",
            "\u{00a0}",
        ] {
            assert!(!valid_reading_identifier(value), "{value:?}");
        }
        assert!(!valid_reading_identifier(
            &"a".repeat(MAX_ASSET_ID_BYTES + 1)
        ));
    }

    #[test]
    fn an_asset_is_online_until_it_misses_the_intervals_it_is_allowed() {
        let reported = at(0);
        let allowed = i64::from(INTERVAL_SECONDS) * STALE_MISSED_INTERVALS;
        assert!(is_online(reported, INTERVAL_SECONDS, reported));
        assert!(is_online(reported, INTERVAL_SECONDS, at(allowed)));
        assert!(!is_online(reported, INTERVAL_SECONDS, at(allowed + 1)));
        // a reading stamped ahead of the clock still counts
        assert!(is_online(at(100), INTERVAL_SECONDS, at(0)));
    }

    #[test]
    fn a_reading_brings_an_asset_online_once_and_a_quiet_one_goes_offline_once() {
        let feed_id = Uuid::new_v4();
        let mut tracker = AssetTracker::default();
        assert!(tracker.record("TWIN-03", feed_id, INTERVAL_SECONDS, at(0), at(0)));
        assert!(!tracker.record("TWIN-03", feed_id, INTERVAL_SECONDS, at(1), at(1)));
        assert!(tracker.go_offline(at(1)).is_empty());

        assert_eq!(tracker.go_offline(at(100)), vec!["TWIN-03".to_string()]);
        assert!(tracker.go_offline(at(100)).is_empty(), "it flipped twice");

        assert!(tracker.record("TWIN-03", feed_id, INTERVAL_SECONDS, at(100), at(100)));
    }

    #[test]
    fn a_backfilled_reading_leaves_a_quiet_asset_offline() {
        let feed_id = Uuid::new_v4();
        let mut tracker = AssetTracker::default();
        tracker.record("TWIN-03", feed_id, INTERVAL_SECONDS, at(0), at(0));
        assert_eq!(tracker.go_offline(at(100)), vec!["TWIN-03".to_string()]);

        assert!(!tracker.record("TWIN-03", feed_id, INTERVAL_SECONDS, at(1), at(100)));
    }
}
