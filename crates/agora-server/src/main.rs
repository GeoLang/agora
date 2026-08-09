use agora_server::attachments::sweep_periodically;
use agora_server::auth::AuthConfig;
use agora_server::{
    AppState, DATABASE_URL_ENV, DEFAULT_PORT, PORT_ENV, connect_pool, migrate, router,
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

    tokio::spawn(sweep_periodically(pool.clone()));

    let port = match std::env::var(PORT_ENV) {
        Ok(value) => value
            .parse::<u16>()
            .map_err(|_| format!("{PORT_ENV} is not a port number: {value}"))?,
        Err(_) => DEFAULT_PORT,
    };
    let bind = format!("0.0.0.0:{port}");
    let listener = tokio::net::TcpListener::bind(&bind)
        .await
        .map_err(|error| format!("could not bind {bind}: {error}"))?;
    println!("agora listening on {bind}");

    axum::serve(listener, router(AppState::new(pool, auth)))
        .await
        .map_err(|error| format!("server stopped: {error}"))
}
