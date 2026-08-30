#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used, clippy::expect_used)]

pub mod assets;
pub mod attachments;
pub mod auth;
pub mod documents;
pub mod error;
pub mod feeds;
pub mod limits;
pub mod links;
pub mod notifications;
pub mod projects;
pub mod protocol;
pub mod role;
pub mod room;
pub mod state;
pub mod watches;
pub mod webhooks;
pub mod ws;

use std::sync::Arc;

use axum::Router;
use axum::extract::FromRef;
use axum::routing::{delete, get, post, put};
use sqlx::PgPool;
use sqlx::migrate::MigrateError;
use tower_http::cors::CorsLayer;

use crate::auth::AuthConfig;
use crate::projects::ProjectAccess;
use crate::room::RoomRegistry;
use crate::watches::Geoplumb;
use crate::webhooks::Webhooks;

pub const DATABASE_URL_ENV: &str = "DATABASE_URL";
pub const PORT_ENV: &str = "PORT";

/// Internal port the platform's nginx routes `/agora/` to, the same one
/// interiora and geoplumb listen on.
pub const DEFAULT_PORT: u16 = 3000;

#[derive(Clone)]
pub struct AppState {
    pub pool: PgPool,
    pub auth: AuthConfig,
    pub rooms: Arc<RoomRegistry>,
    /// `None` leaves the members table as the only authority on every document,
    /// which is where a build with no [`projects::PTOLEMY_URL_ENV`] lands.
    pub projects: Option<Arc<ProjectAccess>>,
    /// `None` turns region watches off, which is where a build with no
    /// [`watches::GEOPLUMB_URL_ENV`] lands.
    pub geoplumb: Option<Arc<Geoplumb>>,
    /// How a tripped watch's alerts are delivered. Refuses the platform's own
    /// network unless [`AppState::with_webhooks`] says otherwise.
    pub webhooks: Webhooks,
}

impl AppState {
    /// Project role resolution off. Turn it on with
    /// [`AppState::with_projects`], so a state built without thinking about it
    /// cannot widen access by accident.
    pub fn new(pool: PgPool, auth: AuthConfig) -> Self {
        Self {
            pool,
            auth,
            rooms: Arc::new(RoomRegistry::new()),
            projects: None,
            geoplumb: None,
            webhooks: Webhooks::refusing_private_hosts(),
        }
    }

    pub fn with_projects(mut self, projects: ProjectAccess) -> Self {
        self.projects = Some(Arc::new(projects));
        self
    }

    pub fn with_geoplumb(mut self, geoplumb: Geoplumb) -> Self {
        self.geoplumb = Some(Arc::new(geoplumb));
        self
    }

    pub fn with_webhooks(mut self, webhooks: Webhooks) -> Self {
        self.webhooks = webhooks;
        self
    }
}

impl FromRef<AppState> for AuthConfig {
    fn from_ref(state: &AppState) -> Self {
        state.auth.clone()
    }
}

/// Every route except `/health`, resolving a share link and reading an
/// attachment needs a token.
///
/// CORS is open because the only credential is an `Authorization` header or an
/// explicit query param, so a foreign origin gains nothing it did not already
/// hold.
pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/health", get(health))
        .route(
            "/documents",
            post(documents::create_document).get(documents::list_documents),
        )
        .route("/documents/{id}", get(documents::get_document))
        .route(
            "/documents/{id}/project",
            put(documents::set_document_project),
        )
        .route(
            "/documents/{id}/members/{user_id}",
            put(documents::set_member).delete(documents::remove_member),
        )
        .route("/documents/{id}/links", post(links::create_link))
        .route(
            "/documents/{id}/feeds",
            post(feeds::create_feed).get(feeds::list_feeds),
        )
        .route(
            "/documents/{id}/feeds/{feed_id}",
            delete(feeds::delete_feed),
        )
        .route(
            "/documents/{id}/watches",
            post(watches::create_watch).get(watches::list_watches),
        )
        .route(
            "/documents/{id}/watches/{watch_id}",
            delete(watches::delete_watch),
        )
        .route(
            "/documents/{id}/watches/{watch_id}/readings",
            get(watches::list_watch_readings),
        )
        .route("/documents/{id}/assets", get(assets::list_assets))
        .route("/documents/{id}/assets/at", get(assets::list_assets_at))
        .route("/feeds/ws", get(feeds::ingest))
        .route(
            "/documents/{id}/attachments",
            post(attachments::create_attachment),
        )
        .route("/attachments/{token}", get(attachments::get_attachment))
        .route("/notifications", get(notifications::list_notifications))
        .route(
            "/notifications/read",
            post(notifications::mark_notifications_read),
        )
        .route(
            "/links/{token}",
            get(links::resolve_link).delete(links::revoke_link),
        )
        .route("/ws", get(ws::websocket))
        .layer(CorsLayer::permissive())
        .with_state(state)
}

async fn health() -> &'static str {
    "ok"
}

pub async fn connect_pool(database_url: &str) -> Result<PgPool, sqlx::Error> {
    PgPool::connect(database_url).await
}

pub async fn migrate(pool: &PgPool) -> Result<(), MigrateError> {
    sqlx::migrate!("./migrations").run(pool).await
}
