use std::sync::Arc;

use agora_server::auth::AuthConfig;
use agora_server::projects::{PTOLEMY_URL_ENV, ProjectAccess};
use agora_server::watches::{GEOPLUMB_URL_ENV, Geoplumb};
use agora_server::{
    AppState, DATABASE_URL_ENV, DEFAULT_PORT, PORT_ENV, assets, attachments, connect_pool, migrate,
    router, watches,
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
    let projects = ProjectAccess::from_env()?;
    let geoplumb = Geoplumb::from_env()?;
    let database_url =
        std::env::var(DATABASE_URL_ENV).map_err(|_| format!("{DATABASE_URL_ENV} is not set"))?;

    let pool = connect_pool(&database_url)
        .await
        .map_err(|error| format!("could not reach the database: {error}"))?;
    migrate(&pool)
        .await
        .map_err(|error| format!("could not apply migrations: {error}"))?;

    tokio::spawn(attachments::sweep_periodically(pool.clone()));
    tokio::spawn(assets::sweep_periodically(pool.clone()));

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

    let mut state = AppState::new(pool, auth);
    match projects {
        Some(projects) => state = state.with_projects(projects),
        None => println!(
            "{PTOLEMY_URL_ENV} is not set: project roles grant nothing and only agora's own \
             members reach a document"
        ),
    }
    match geoplumb {
        Some(geoplumb) => state = state.with_geoplumb(geoplumb),
        None => println!("{GEOPLUMB_URL_ENV} is not set: region watches are off"),
    }
    tokio::spawn(assets::mark_stale_periodically(Arc::clone(&state.rooms)));
    tokio::spawn(watches::run_periodically(state.clone()));

    axum::serve(listener, router(state))
        .await
        .map_err(|error| format!("server stopped: {error}"))
}
