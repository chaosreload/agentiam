use std::sync::Arc;

use axum::body::Body;
use axum::extract::State;
use axum::http::{Request, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use serde_json::json;

use crate::api::router::AppState;

pub async fn api_key_auth(
    State(state): State<Arc<AppState>>,
    req: Request<Body>,
    next: Next,
) -> Response {
    let auth_header = req
        .headers()
        .get("authorization")
        .and_then(|v| v.to_str().ok());

    let key = match auth_header {
        Some(h) if h.starts_with("Bearer ") => &h[7..],
        _ => {
            return (
                StatusCode::UNAUTHORIZED,
                axum::Json(json!({
                    "request_id": "",
                    "error": { "code": "Unauthorized", "message": "Missing or invalid Authorization header" }
                })),
            )
                .into_response();
        }
    };

    match crate::token::apikey::verify_api_key(key, &state.db).await {
        Ok(_info) => next.run(req).await,
        Err(_) => (
            StatusCode::UNAUTHORIZED,
            axum::Json(json!({
                "request_id": "",
                "error": { "code": "Unauthorized", "message": "Invalid API key" }
            })),
        )
            .into_response(),
    }
}
