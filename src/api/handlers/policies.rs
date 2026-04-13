use std::sync::Arc;
use std::time::Instant;

use axum::Json;
use axum::extract::State;
use axum::response::IntoResponse;
use serde::Deserialize;
use serde_json::json;

use crate::api::error::{ApiError, new_request_id, success_response};
use crate::api::router::AppState;

pub async fn list_policies(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let rid = new_request_id();
    let engine = state.cedar_engine.read().unwrap(); // safe: lock only poisoned on panic
    let policies = engine.list_policies();
    let items: Vec<_> = policies
        .iter()
        .map(|p| {
            json!({
                "id": p.id,
            })
        })
        .collect();

    success_response(
        &rid,
        json!({
            "policies": items,
            "total": items.len(),
            "schema_valid": true,
        }),
    )
    .into_response()
}

#[derive(Deserialize)]
pub struct ValidateBody {
    pub policy_text: String,
}

pub async fn validate_policy(
    State(state): State<Arc<AppState>>,
    Json(body): Json<ValidateBody>,
) -> impl IntoResponse {
    let rid = new_request_id();
    let engine = state.cedar_engine.read().unwrap(); // safe: lock only poisoned on panic

    match engine.validate_policy(&body.policy_text) {
        Ok(result) => {
            if result.validation_passed() {
                success_response(
                    &rid,
                    json!({
                        "valid": true,
                        "policies_parsed": 1,
                        "warnings": [],
                    }),
                )
                .into_response()
            } else {
                let errors: Vec<_> = result
                    .validation_errors()
                    .map(|e| json!({ "message": e.to_string() }))
                    .collect();
                success_response(
                    &rid,
                    json!({
                        "valid": false,
                        "errors": errors,
                    }),
                )
                .into_response()
            }
        }
        Err(e) => success_response(
            &rid,
            json!({
                "valid": false,
                "errors": [{ "message": e.to_string() }],
            }),
        )
        .into_response(),
    }
}

pub async fn reload_policies(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let rid = new_request_id();
    let start = Instant::now();

    let mut engine = state.cedar_engine.write().unwrap(); // safe: lock only poisoned on panic
    match engine.reload(&state.config.policy_dir) {
        Ok(()) => {
            let count = engine.list_policies().len();
            let elapsed = start.elapsed().as_millis();
            success_response(
                &rid,
                json!({
                    "reloaded": true,
                    "policies_loaded": count,
                    "schema_valid": true,
                    "reload_time_ms": elapsed,
                }),
            )
            .into_response()
        }
        Err(e) => ApiError::bad_request(format!("reload failed: {e}"), &rid).into_response(),
    }
}
