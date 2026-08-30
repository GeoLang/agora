use std::time::Duration;

use axum::Json;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sqlx::{PgPool, Row};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use uuid::Uuid;

use crate::AppState;
use crate::auth::Caller;
use crate::documents::{project_grant, require_editor, require_member};
use crate::error::ApiError;
use crate::limits::{
    MAX_LAYER_NAME_BYTES, MAX_REGION_BYTES, MAX_REGION_POSITIONS, MAX_WATCH_READINGS_PAGE,
    MAX_WEBHOOK_SECRET_BYTES, MAX_WEBHOOK_URL_BYTES, MIN_RING_POSITIONS,
    MIN_WATCH_INTERVAL_SECONDS,
};
use crate::projects::read_capped_body;
use crate::protocol::{Reducer, ThresholdOp, WatchState};
use crate::state::valid_name;

/// Env var holding geoplumb's base url. Unset turns region watches off: a
/// create is refused and nothing is scheduled.
pub const GEOPLUMB_URL_ENV: &str = "GEOPLUMB_URL";

/// Ceiling on the layer listing, which is read while a caller waits on their
/// create.
const GEOPLUMB_LAYERS_TIMEOUT: Duration = Duration::from_secs(5);

/// Bytes of the layer listing read before it is refused. A layer is a handful
/// of json fields and geoplumb serves a few of them.
const MAX_LAYERS_BYTES: usize = 1024 * 1024;

/// Longitude and latitude bounds of a geojson position in degrees, RFC 7946.
const LONGITUDE_LIMIT: f64 = 180.0;
const LATITUDE_LIMIT: f64 = 90.0;

/// Client for geoplumb, which answers what a watch is watching.
///
/// It carries no credential: geoplumb has no auth inside the platform network,
/// and this reads public layer metadata and reduces a region a member drew.
pub struct Geoplumb {
    client: reqwest::Client,
    /// No trailing slash, so joining a path is one format string.
    base_url: String,
}

impl std::fmt::Debug for Geoplumb {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Geoplumb")
            .field("base_url", &self.base_url)
            .finish_non_exhaustive()
    }
}

impl Geoplumb {
    pub fn new(base_url: &str) -> Result<Self, String> {
        let base_url = base_url.trim().trim_end_matches('/').to_string();
        if !base_url.starts_with("http://") && !base_url.starts_with("https://") {
            return Err(format!(
                "{GEOPLUMB_URL_ENV} must start with http:// or https://, got {base_url:?}"
            ));
        }
        let client = reqwest::Client::builder()
            .timeout(GEOPLUMB_LAYERS_TIMEOUT)
            // a reduction is asked of the host the operator named and of
            // nowhere a redirect points
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|error| format!("could not build the geoplumb client: {error}"))?;
        Ok(Self { client, base_url })
    }

    /// `Ok(None)` when the env var is unset, which turns region watches off. An
    /// `Err` is a broken setting and should stop startup.
    pub fn from_env() -> Result<Option<Self>, String> {
        let Some(url) = std::env::var(GEOPLUMB_URL_ENV)
            .ok()
            .filter(|url| !url.trim().is_empty())
        else {
            return Ok(None);
        };
        Self::new(&url).map(Some)
    }

    /// Whether geoplumb serves this layer. An `Err` is geoplumb not answering,
    /// which refuses the create rather than storing a watch nothing can run.
    async fn serves_layer(&self, layer: &str) -> Result<bool, ApiError> {
        let unreachable = || ApiError::service_unavailable("could not reach geoplumb");
        let response = self
            .client
            .get(format!("{}/layers", self.base_url))
            .send()
            .await
            .map_err(|_| unreachable())?;
        if !response.status().is_success() {
            return Err(unreachable());
        }
        let body = read_capped_body(response, MAX_LAYERS_BYTES)
            .await
            .ok_or_else(unreachable)?;
        let body: Value = serde_json::from_slice(&body).map_err(|_| unreachable())?;
        let listed = body.as_array().ok_or_else(unreachable)?;
        Ok(listed
            .iter()
            .filter_map(|entry| entry.get("name").and_then(Value::as_str))
            .any(|name| name == layer))
    }
}

/// A layer name reaches geoplumb inside a url path, so the charset is what
/// keeps it one path segment: no slash, no dot pair, nothing to percent encode.
fn valid_layer_name(layer: &str) -> bool {
    !layer.is_empty()
        && layer.len() <= MAX_LAYER_NAME_BYTES
        && layer
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || matches!(character, '-' | '_'))
}

/// The positions in one geojson polygon, or the reason it is not one.
fn polygon_positions(polygon: &Value) -> Result<usize, &'static str> {
    let rings = polygon
        .as_array()
        .ok_or("region coordinates are not a polygon")?;
    if rings.is_empty() {
        return Err("region carries a polygon with no ring");
    }
    let mut total = 0;
    for ring in rings {
        let positions = ring.as_array().ok_or("region carries a ring that is not")?;
        if positions.len() < MIN_RING_POSITIONS {
            return Err("region carries a ring with too few positions");
        }
        for position in positions {
            let position = position
                .as_array()
                .ok_or("region carries a position that is not")?;
            let (Some(longitude), Some(latitude)) = (
                position.first().and_then(Value::as_f64),
                position.get(1).and_then(Value::as_f64),
            ) else {
                return Err("region carries a position without two numbers");
            };
            if !longitude.is_finite()
                || !latitude.is_finite()
                || longitude.abs() > LONGITUDE_LIMIT
                || latitude.abs() > LATITUDE_LIMIT
            {
                return Err("region carries a position off the earth");
            }
        }
        total += positions.len();
    }
    Ok(total)
}

/// A region as geoplumb takes it: one geojson `Polygon` or `MultiPolygon` in
/// lon/lat degrees, small enough that the reduction it drives is bounded.
fn valid_region(region: &Value) -> Result<(), &'static str> {
    if serde_json::to_string(region).map_or(usize::MAX, |text| text.len()) > MAX_REGION_BYTES {
        return Err("region too large");
    }
    let geometry_type = region
        .get("type")
        .and_then(Value::as_str)
        .ok_or("region has no geojson type")?;
    let coordinates = region
        .get("coordinates")
        .ok_or("region has no coordinates")?;
    let positions = match geometry_type {
        "Polygon" => polygon_positions(coordinates)?,
        "MultiPolygon" => {
            let polygons = coordinates
                .as_array()
                .ok_or("region coordinates are not a multipolygon")?;
            if polygons.is_empty() {
                return Err("region carries no polygon");
            }
            let mut total = 0;
            for polygon in polygons {
                total += polygon_positions(polygon)?;
            }
            total
        }
        _ => return Err("region must be a Polygon or a MultiPolygon"),
    };
    if positions > MAX_REGION_POSITIONS {
        return Err("region carries too many positions");
    }
    Ok(())
}

/// A webhook url has to be one agora can post to. The scheme and host are
/// checked here, and where it resolves to is checked again at delivery time.
fn valid_webhook_url(url: &str) -> Result<reqwest::Url, &'static str> {
    if url.len() > MAX_WEBHOOK_URL_BYTES {
        return Err("webhook url too long");
    }
    let parsed = reqwest::Url::parse(url).map_err(|_| "webhook url is not a url")?;
    if !matches!(parsed.scheme(), "http" | "https") {
        return Err("webhook url must be http or https");
    }
    if parsed.host().is_none() {
        return Err("webhook url has no host");
    }
    Ok(parsed)
}

/// No `Debug`: `webhook_secret` is a signing key and must never reach a log
/// line.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CreateWatchRequest {
    name: String,
    layer: String,
    region: Value,
    reducer: Reducer,
    interval_seconds: i32,
    #[serde(default)]
    threshold_op: Option<ThresholdOp>,
    #[serde(default)]
    threshold_value: Option<f64>,
    #[serde(default)]
    webhook_url: Option<String>,
    #[serde(default)]
    webhook_secret: Option<String>,
}

/// One watch as an editor sees it: what everyone gets plus the webhook, which
/// is absent rather than null for anyone who cannot edit.
///
/// No `Debug`, for the same reason the request has none.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WatchSummary {
    #[serde(flatten)]
    state: WatchState,
    #[serde(skip_serializing_if = "Option::is_none")]
    webhook_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    webhook_secret: Option<String>,
}

/// One watch row, with the webhook kept only when the caller may see it.
fn watch_summary(row: &sqlx::postgres::PgRow, can_edit: bool) -> Result<WatchSummary, sqlx::Error> {
    let reducer: String = row.try_get("reducer")?;
    let threshold_op: Option<String> = row.try_get("threshold_op")?;
    let webhook_url: Option<String> = row.try_get("webhook_url")?;
    let webhook_secret: Option<String> = row.try_get("webhook_secret")?;
    let state = WatchState {
        id: row.try_get("id")?,
        name: row.try_get("name")?,
        layer: row.try_get("layer")?,
        region: row.try_get("region")?,
        reducer: Reducer::parse(&reducer)
            .ok_or_else(|| sqlx::Error::Decode("unknown reducer".into()))?,
        interval_seconds: row.try_get("interval_seconds")?,
        threshold_op: threshold_op.as_deref().and_then(ThresholdOp::parse),
        threshold_value: row.try_get("threshold_value")?,
        created_by: row.try_get("created_by")?,
        created_at: row.try_get("created_at")?,
        last_run_at: row.try_get("last_run_at")?,
        last_error: row.try_get("last_error")?,
    };
    Ok(WatchSummary {
        state,
        webhook_url: can_edit.then_some(webhook_url).flatten(),
        webhook_secret: can_edit.then_some(webhook_secret).flatten(),
    })
}

/// The columns every watch read selects, in the order [`watch_summary`] and
/// [`watch_states`] expect to find them.
const WATCH_COLUMNS: &str = "id, doc_id, name, layer, region, reducer, interval_seconds,
     threshold_op, threshold_value, webhook_url, webhook_secret, created_by, created_at,
     last_run_at, last_error";

/// Every watch on a document as the room relays them, webhooks left behind.
pub async fn watch_states(
    pool: &PgPool,
    document_id: Uuid,
) -> Result<Vec<WatchState>, sqlx::Error> {
    let rows = sqlx::query(&format!(
        "select {WATCH_COLUMNS} from watches where doc_id = $1 order by created_at, id"
    ))
    .bind(document_id)
    .fetch_all(pool)
    .await?;
    rows.iter()
        .map(|row| watch_summary(row, false).map(|summary| summary.state))
        .collect()
}

/// Register a watch over a region. Edit role, the same lookup an op write goes
/// through.
///
/// The layer is checked against geoplumb here rather than at the first run, so
/// a typo is a refusal a person is looking at instead of a `last_error` nobody
/// reads.
pub async fn create_watch(
    State(state): State<AppState>,
    caller: Caller,
    Path(document_id): Path<Uuid>,
    Json(request): Json<CreateWatchRequest>,
) -> Result<(StatusCode, Json<WatchSummary>), ApiError> {
    let grant = project_grant(&state, document_id, &caller).await?;
    require_editor(&state.pool, document_id, &caller.user_id, grant).await?;

    let Some(geoplumb) = state.geoplumb.as_deref() else {
        return Err(ApiError::bad_request("region watches are not enabled"));
    };

    let name = request.name.trim().to_string();
    if !valid_name(&name) {
        return Err(ApiError::bad_request("invalid watch name"));
    }
    if !valid_layer_name(&request.layer) {
        return Err(ApiError::bad_request("invalid layer name"));
    }
    valid_region(&request.region).map_err(ApiError::bad_request)?;
    if request.interval_seconds < MIN_WATCH_INTERVAL_SECONDS {
        return Err(ApiError::bad_request("watch interval too short"));
    }
    if request.threshold_op.is_some() != request.threshold_value.is_some() {
        return Err(ApiError::bad_request(
            "a threshold needs both an operator and a value",
        ));
    }
    if request
        .threshold_value
        .is_some_and(|value| !value.is_finite())
    {
        return Err(ApiError::bad_request(
            "threshold value is not a finite number",
        ));
    }
    if let Some(url) = request.webhook_url.as_deref() {
        valid_webhook_url(url).map_err(ApiError::bad_request)?;
    }
    if request
        .webhook_secret
        .as_ref()
        .is_some_and(|secret| secret.is_empty() || secret.len() > MAX_WEBHOOK_SECRET_BYTES)
    {
        return Err(ApiError::bad_request("invalid webhook secret"));
    }

    if !geoplumb.serves_layer(&request.layer).await? {
        return Err(ApiError::unprocessable_entity(format!(
            "geoplumb serves no layer {}",
            request.layer
        )));
    }

    let watch_id = Uuid::new_v4();
    let row = sqlx::query(&format!(
        "insert into watches
             (id, doc_id, name, layer, region, reducer, interval_seconds, threshold_op,
              threshold_value, webhook_url, webhook_secret, created_by)
         values ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
         returning {WATCH_COLUMNS}"
    ))
    .bind(watch_id)
    .bind(document_id)
    .bind(&name)
    .bind(&request.layer)
    .bind(&request.region)
    .bind(request.reducer.as_str())
    .bind(request.interval_seconds)
    .bind(request.threshold_op.map(ThresholdOp::as_str))
    .bind(request.threshold_value)
    .bind(&request.webhook_url)
    .bind(&request.webhook_secret)
    .bind(&caller.user_id)
    .fetch_one(&state.pool)
    .await?;

    Ok((StatusCode::CREATED, Json(watch_summary(&row, true)?)))
}

pub async fn list_watches(
    State(state): State<AppState>,
    caller: Caller,
    Path(document_id): Path<Uuid>,
) -> Result<Json<Vec<WatchSummary>>, ApiError> {
    let grant = project_grant(&state, document_id, &caller).await?;
    let role = require_member(&state.pool, document_id, &caller.user_id, grant).await?;

    let rows = sqlx::query(&format!(
        "select {WATCH_COLUMNS} from watches where doc_id = $1 order by created_at, id"
    ))
    .bind(document_id)
    .fetch_all(&state.pool)
    .await?;
    let summaries = rows
        .iter()
        .map(|row| watch_summary(row, role.can_edit()))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(Json(summaries))
}

/// Delete a watch. Its readings and its notifications cascade away with it.
pub async fn delete_watch(
    State(state): State<AppState>,
    caller: Caller,
    Path((document_id, watch_id)): Path<(Uuid, Uuid)>,
) -> Result<StatusCode, ApiError> {
    let grant = project_grant(&state, document_id, &caller).await?;
    require_editor(&state.pool, document_id, &caller.user_id, grant).await?;

    let deleted = sqlx::query("delete from watches where id = $1 and doc_id = $2")
        .bind(watch_id)
        .bind(document_id)
        .execute(&state.pool)
        .await?
        .rows_affected();
    if deleted == 0 {
        return Err(ApiError::not_found("no such watch"));
    }
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReadingsQuery {
    since: Option<String>,
    limit: Option<i64>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WatchReadingEntry {
    #[serde(with = "time::serde::rfc3339")]
    at: OffsetDateTime,
    value: f64,
    count: i64,
}

/// One watch's history, oldest first, from `since` onwards.
pub async fn list_watch_readings(
    State(state): State<AppState>,
    caller: Caller,
    Path((document_id, watch_id)): Path<(Uuid, Uuid)>,
    Query(query): Query<ReadingsQuery>,
) -> Result<Json<Vec<WatchReadingEntry>>, ApiError> {
    let grant = project_grant(&state, document_id, &caller).await?;
    require_member(&state.pool, document_id, &caller.user_id, grant).await?;

    let since = match query.since.as_deref() {
        Some(since) => Some(
            OffsetDateTime::parse(since, &Rfc3339)
                .map_err(|_| ApiError::bad_request("since must be an rfc 3339 time"))?,
        ),
        None => None,
    };
    let limit = match query.limit {
        Some(limit) if !(1..=MAX_WATCH_READINGS_PAGE).contains(&limit) => {
            return Err(ApiError::bad_request("limit out of range"));
        }
        Some(limit) => limit,
        None => MAX_WATCH_READINGS_PAGE,
    };

    let belongs: Option<Uuid> =
        sqlx::query_scalar("select id from watches where id = $1 and doc_id = $2")
            .bind(watch_id)
            .bind(document_id)
            .fetch_optional(&state.pool)
            .await?;
    if belongs.is_none() {
        return Err(ApiError::not_found("no such watch"));
    }

    let rows = sqlx::query(
        "select at, value, count from watch_readings
         where watch_id = $1 and ($2::timestamptz is null or at > $2)
         order by at limit $3",
    )
    .bind(watch_id)
    .bind(since)
    .bind(limit)
    .fetch_all(&state.pool)
    .await?;

    let mut readings = Vec::with_capacity(rows.len());
    for row in rows {
        readings.push(WatchReadingEntry {
            at: row.try_get("at")?,
            value: row.try_get("value")?,
            count: row.try_get("count")?,
        });
    }
    Ok(Json(readings))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;
    use serde_json::json;

    fn square() -> Value {
        json!({
            "type": "Polygon",
            "coordinates": [[[0.0, 0.0], [1.0, 0.0], [1.0, 1.0], [0.0, 0.0]]]
        })
    }

    #[test]
    fn a_polygon_and_a_multipolygon_are_both_regions() {
        assert_eq!(valid_region(&square()), Ok(()));
        assert_eq!(
            valid_region(&json!({
                "type": "MultiPolygon",
                "coordinates": [[[[0.0, 0.0], [1.0, 0.0], [1.0, 1.0], [0.0, 0.0]]]]
            })),
            Ok(())
        );
        // a geojson geometry may carry keys nothing here reads
        assert_eq!(
            valid_region(&json!({
                "type": "Polygon",
                "bbox": [0.0, 0.0, 1.0, 1.0],
                "coordinates": [[[0.0, 0.0], [1.0, 0.0], [1.0, 1.0], [0.0, 0.0]]]
            })),
            Ok(())
        );
    }

    #[test]
    fn a_region_that_is_not_a_polygon_is_refused() {
        for region in [
            json!({}),
            json!({"type": "Point", "coordinates": [0.0, 0.0]}),
            json!({"type": "Polygon"}),
            json!({"type": "Polygon", "coordinates": []}),
            json!({"type": "Polygon", "coordinates": [[]]}),
            json!({"type": "Polygon", "coordinates": [[[0.0, 0.0], [1.0, 0.0]]]}),
            json!({"type": "Polygon", "coordinates": "here"}),
            json!({"type": "MultiPolygon", "coordinates": []}),
            json!({"type": "MultiPolygon", "coordinates": [[[[0.0, 0.0], [1.0, 0.0]]]]}),
            json!([]),
            json!("Polygon"),
        ] {
            assert!(valid_region(&region).is_err(), "{region}");
        }
    }

    #[test]
    fn a_position_off_the_earth_or_not_a_number_is_refused() {
        for position in [
            json!([181.0, 0.0]),
            json!([0.0, 91.0]),
            json!([-181.0, 0.0]),
            json!(["0.0", "0.0"]),
            json!([0.0]),
            json!([]),
            json!({"lon": 0.0, "lat": 0.0}),
        ] {
            let region = json!({
                "type": "Polygon",
                "coordinates": [[position, [1.0, 0.0], [1.0, 1.0], [0.0, 0.0]]]
            });
            assert!(valid_region(&region).is_err(), "{region}");
        }
    }

    #[test]
    fn a_region_past_the_position_cap_is_refused() {
        let ring: Vec<Value> = (0..=MAX_REGION_POSITIONS)
            .map(|index| json!([(index % 90) as f64, 0.0]))
            .collect();
        let region = json!({"type": "Polygon", "coordinates": [ring]});
        assert_eq!(
            valid_region(&region),
            Err("region carries too many positions")
        );
    }

    #[test]
    fn a_layer_name_stays_one_url_path_segment() {
        assert!(valid_layer_name("hillshade"));
        assert!(valid_layer_name("ndvi-2026_v2"));
        for layer in [
            "",
            "../secrets",
            "a/b",
            "a b",
            "a.b",
            "a%2fb",
            "a?b",
            "a#b",
            &"a".repeat(MAX_LAYER_NAME_BYTES + 1),
        ] {
            assert!(!valid_layer_name(layer), "{layer:?}");
        }
    }

    #[test]
    fn a_webhook_url_must_be_http_with_a_host() {
        assert!(valid_webhook_url("https://example.test/hook").is_ok());
        assert!(valid_webhook_url("http://example.test:9000/hook").is_ok());
        for url in [
            "file:///etc/passwd",
            "ftp://example.test/hook",
            "gopher://example.test",
            "javascript:alert(1)",
            "data:text/plain,hi",
            "not a url",
            "",
        ] {
            assert!(valid_webhook_url(url).is_err(), "{url:?}");
        }
        let long = format!("https://example.test/{}", "a".repeat(MAX_WEBHOOK_URL_BYTES));
        assert_eq!(valid_webhook_url(&long), Err("webhook url too long"));
    }

    #[test]
    fn reducers_and_threshold_operators_parse_exactly() {
        for reducer in [
            Reducer::Mean,
            Reducer::Min,
            Reducer::Max,
            Reducer::Sum,
            Reducer::Count,
        ] {
            assert_eq!(Reducer::parse(reducer.as_str()), Some(reducer));
        }
        for reducer in ["", "MEAN", "average", "median", " sum"] {
            assert_eq!(Reducer::parse(reducer), None, "{reducer:?}");
        }

        assert_eq!(ThresholdOp::parse("gt"), Some(ThresholdOp::Gt));
        assert_eq!(ThresholdOp::parse("lt"), Some(ThresholdOp::Lt));
        for op in ["", "GT", ">", "ge", "eq"] {
            assert_eq!(ThresholdOp::parse(op), None, "{op:?}");
        }
    }

    #[test]
    fn a_threshold_is_satisfied_only_on_its_own_side() {
        assert!(ThresholdOp::Gt.satisfied(2.0, 1.0));
        assert!(!ThresholdOp::Gt.satisfied(1.0, 1.0));
        assert!(!ThresholdOp::Gt.satisfied(0.0, 1.0));
        assert!(ThresholdOp::Lt.satisfied(0.0, 1.0));
        assert!(!ThresholdOp::Lt.satisfied(1.0, 1.0));
        assert!(!ThresholdOp::Lt.satisfied(2.0, 1.0));
    }
}
