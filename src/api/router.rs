use std::sync::{Arc, RwLock};

use axum::Router;
use axum::middleware;
use axum::routing::{delete, get, post};
use sqlx::SqlitePool;

use crate::api::handlers::{audit, authorize, entities, health, policies, sessions};
use crate::api::middleware::api_key_auth;
use crate::audit::logger::AuditLogger;
use crate::cedar::engine::CedarEngine;
use crate::cedar::entities::EntityStore;
use crate::config::AppConfig;
use crate::session::manager::SessionManager;

pub struct AppState {
    pub cedar_engine: RwLock<CedarEngine>,
    pub entity_store: RwLock<EntityStore>,
    pub session_manager: SessionManager,
    pub audit_logger: AuditLogger,
    pub config: AppConfig,
    pub db: SqlitePool,
}

pub fn build_router(state: Arc<AppState>) -> Router {
    // Routes that require API key auth
    let authed = Router::new()
        // Authorization
        .route("/v1/authorize", post(authorize::authorize))
        .route("/v1/authorize/batch", post(authorize::authorize_batch))
        // Sessions
        .route("/v1/sessions", post(sessions::create_session))
        .route("/v1/sessions", get(sessions::list_sessions))
        .route("/v1/sessions/{session_id}", get(sessions::get_session))
        .route(
            "/v1/sessions/{session_id}",
            delete(sessions::delete_session),
        )
        .route(
            "/v1/sessions/{session_id}/budget",
            post(sessions::update_budget),
        )
        // Entities
        .route("/v1/entities", post(entities::create_entities))
        .route("/v1/entities", get(entities::list_entities))
        .route(
            "/v1/entities/{entity_type}/{entity_id}",
            get(entities::get_entity),
        )
        .route(
            "/v1/entities/{entity_type}/{entity_id}",
            delete(entities::delete_entity),
        )
        // Policies
        .route("/v1/policies", get(policies::list_policies))
        .route("/v1/policies/validate", post(policies::validate_policy))
        .route("/v1/policies/reload", post(policies::reload_policies))
        // Audit
        .route("/v1/audit/decisions", get(audit::list_decisions))
        .route("/v1/audit/decisions/{id}", get(audit::get_decision))
        .route("/v1/audit/stats", get(audit::get_stats))
        // Config
        .route("/v1/config", get(get_config))
        .layer(middleware::from_fn_with_state(state.clone(), api_key_auth));

    // Health — no auth, but still needs state
    Router::<Arc<AppState>>::new()
        .route("/health", get(health::health))
        .merge(authed)
        .with_state(state)
}

async fn get_config(
    axum::extract::State(state): axum::extract::State<Arc<AppState>>,
) -> axum::Json<serde_json::Value> {
    let rid = crate::api::error::new_request_id();
    crate::api::error::success_response(
        &rid,
        serde_json::json!({
            "policy_directory": state.config.policy_dir.to_string_lossy(),
            "schema_file": state.config.schema_file.to_string_lossy(),
            "auth_mode": "api_key",
            "audit_backend": "sqlite",
        }),
    )
}
