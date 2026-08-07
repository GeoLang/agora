use agora_server::auth::AuthConfig;
use agora_server::{
    AppState, BIND_ENV, DATABASE_URL_ENV, DEFAULT_BIND, connect_pool, migrate, router,
};

#[tokio::main]
async fn main() {
    if let Err(message) = start().await {
        eprintln!("{message}");
        std::process::exit(1);
    }
}

async fn start() -> Result<(), String> {
    let auth = AuthConfig::from_env()?;
    let database_url =
        std::env::var(DATABASE_URL_ENV).map_err(|_| format!("{DATABASE_URL_ENV} is not set"))?;

    let pool = connect_pool(&database_url)
        .await
        .map_err(|error| format!("could not reach the database: {error}"))?;
    migrate(&pool)
        .await
        .map_err(|error| format!("could not apply migrations: {error}"))?;

    let bind = std::env::var(BIND_ENV).unwrap_or_else(|_| DEFAULT_BIND.to_string());
    let listener = tokio::net::TcpListener::bind(&bind)
        .await
        .map_err(|error| format!("could not bind {bind}: {error}"))?;
    println!("agora listening on {bind}");

    axum::serve(listener, router(AppState::new(pool, auth)))
        .await
        .map_err(|error| format!("server stopped: {error}"))
}
