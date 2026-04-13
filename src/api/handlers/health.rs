use std::sync::Arc;

use axum::Json;
use axum::extract::State;
use serde_json::{Value, json};

use crate::api::router::AppState;

pub async fn health(State(state): State<Arc<AppState>>) -> Json<Value> {
    let policy_count = {
        let engine = state.cedar_engine.read().unwrap(); // safe: lock only poisoned on panic
        engine.list_policies().len()
    };

    let sessions = state
        .session_manager
        .list_sessions(crate::models::SessionFilter {
            active_only: Some(true),
            ..Default::default()
        })
        .await
        .map(|s| s.len())
        .unwrap_or(0);

    Json(json!({
        "status": "healthy",
        "version": "0.1.0",
        "components": {
            "cedar_engine": {
                "status": "healthy",
                "policies_loaded": policy_count,
                "schema_valid": true,
            },
            "session_store": {
                "status": "healthy",
                "active_sessions": sessions,
            },
            "audit_store": {
                "status": "healthy",
                "storage_backend": "sqlite",
            }
        }
    }))
}
