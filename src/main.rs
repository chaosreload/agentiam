mod api;
mod audit;
#[allow(dead_code)]
mod auth;
mod cedar;
mod config;
mod error;
#[allow(dead_code)]
mod models;
#[allow(dead_code)]
mod session;
#[allow(dead_code)]
mod token;

use std::sync::{Arc, RwLock};

use sqlx::sqlite::SqlitePoolOptions;
use tracing_subscriber::EnvFilter;

use crate::api::router::{AppState, build_router};
use crate::audit::logger::AuditLogger;
use crate::cedar::engine::CedarEngine;
use crate::cedar::entities::EntityStore;
use crate::config::AppConfig;
use crate::session::manager::SessionManager;

async fn shutdown_signal() {
    tokio::signal::ctrl_c()
        .await
        .expect("failed to install CTRL+C signal handler");
    tracing::info!("shutdown signal received");
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env().add_directive("agentiam=info".parse()?))
        .init();

    let config = AppConfig::from_env();
    tracing::info!("starting AgentIAM on port {}", config.port);

    // Database
    let db = SqlitePoolOptions::new()
        .max_connections(5)
        .connect(&config.db_path)
        .await?;

    // Cedar engine
    let engine = CedarEngine::new(&config.schema_file, &config.policy_dir)?;
    let policy_count = engine.list_policies().len();
    tracing::info!("loaded {policy_count} Cedar policies");

    // Entity store (shares schema with engine)
    let entity_store = EntityStore::new(engine.schema().clone());

    // Session manager
    let session_manager =
        SessionManager::new(db.clone(), config.jwt_secret.as_bytes().to_vec()).await?;

    // Audit logger
    let audit_logger = AuditLogger::new(db.clone()).await?;

    // API key table
    crate::token::apikey::ensure_table(&db).await?;

    let state = Arc::new(AppState {
        cedar_engine: RwLock::new(engine),
        entity_store: RwLock::new(entity_store),
        session_manager,
        audit_logger,
        config: config.clone(),
        db,
    });

    let app = build_router(state.clone());
    let listener = tokio::net::TcpListener::bind(format!("0.0.0.0:{}", config.port)).await?;
    tracing::info!("listening on 0.0.0.0:{}", config.port);
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;

    // Flush remaining audit logs before exit
    tracing::info!("flushing audit logs...");
    state.audit_logger.flush_and_close().await;

    Ok(())
}
