#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used, clippy::expect_used)]

pub mod attachments;
pub mod auth;
pub mod documents;
pub mod error;
pub mod limits;
pub mod links;
pub mod notifications;
pub mod projects;
pub mod protocol;
pub mod role;
pub mod room;
pub mod state;
pub mod ws;

use std::sync::Arc;

use axum::Router;
use axum::extract::FromRef;
use axum::routing::{get, post, put};
use sqlx::PgPool;
use sqlx::migrate::MigrateError;
use tower_http::cors::CorsLayer;

use crate::auth::AuthConfig;
use crate::projects::ProjectAccess;
use crate::room::RoomRegistry;

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
        }
    }

    pub fn with_projects(mut self, projects: ProjectAccess) -> Self {
        self.projects = Some(Arc::new(projects));
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
