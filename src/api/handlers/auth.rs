//! OAuth client management and token issuance handlers.

use std::sync::Arc;

use axum::Json;
use axum::extract::{Form, Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde::Deserialize;
use serde_json::json;

use crate::api::error::{ApiError, new_request_id, success_response};
use crate::api::router::AppState;
use crate::token::oauth;

// ─── Request / Response types ────────────────────────────────────────

#[derive(Deserialize)]
pub struct RegisterClientBody {
    pub name: String,
    pub scopes: Vec<String>,
}

#[derive(Deserialize)]
pub struct TokenRequest {
    pub grant_type: Option<String>,
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
    pub scope: Option<String>,
}

// ─── OAuth error helper (RFC 6749 format, no request_id) ─────────────

fn oauth_error(status: StatusCode, error: &str, description: &str) -> Response {
    let body = json!({
        "error": error,
        "error_description": description,
    });
    (status, Json(body)).into_response()
}

// ─── Handlers ────────────────────────────────────────────────────────

/// POST /v1/oauth/clients — Register a new OAuth client (admin, API Key auth).
pub async fn register_oauth_client(
    State(state): State<Arc<AppState>>,
    Json(body): Json<RegisterClientBody>,
) -> Result<Response, ApiError> {
    let rid = new_request_id();
    let (client, secret) = oauth::register_client(&state.db, &body.name, body.scopes)
        .await
        .map_err(|e| ApiError::from_err(e, &rid))?;

    let resp = json!({
        "client_id": client.client_id,
        "client_secret": secret,
        "name": client.name,
        "scopes": client.scopes,
        "created_at": client.created_at,
    });
    Ok((StatusCode::CREATED, success_response(&rid, resp)).into_response())
}

/// GET /v1/oauth/clients — List all OAuth clients (admin, API Key auth).
pub async fn list_oauth_clients(
    State(state): State<Arc<AppState>>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let rid = new_request_id();
    let clients = oauth::list_clients(&state.db)
        .await
        .map_err(|e| ApiError::from_err(e, &rid))?;

    let list: Vec<serde_json::Value> = clients
        .iter()
        .map(|c| {
            json!({
                "client_id": c.client_id,
                "name": c.name,
                "scopes": c.scopes,
                "created_at": c.created_at,
                "revoked": c.revoked,
            })
        })
        .collect();

    Ok(success_response(&rid, json!({ "clients": list })))
}

/// DELETE /v1/oauth/clients/{client_id} — Revoke an OAuth client (admin, API Key auth).
pub async fn delete_oauth_client(
    State(state): State<Arc<AppState>>,
    Path(client_id): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let rid = new_request_id();
    let found = oauth::revoke_client(&state.db, &client_id)
        .await
        .map_err(|e| ApiError::from_err(e, &rid))?;

    if !found {
        return Err(ApiError::not_found(
            format!("client '{client_id}' not found"),
            &rid,
        ));
    }

    Ok(success_response(&rid, json!({ "revoked": true })))
}

/// POST /v1/oauth/token — Client Credentials grant (public endpoint).
pub async fn oauth_token(
    State(state): State<Arc<AppState>>,
    Form(form): Form<TokenRequest>,
) -> Response {
    // Validate required fields
    let (grant_type, client_id, client_secret) =
        match (&form.grant_type, &form.client_id, &form.client_secret) {
            (Some(gt), Some(cid), Some(cs)) => (gt.clone(), cid.clone(), cs.clone()),
            _ => {
                return oauth_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_request",
                    "missing required fields: grant_type, client_id, client_secret",
                );
            }
        };

    // Check grant_type
    if grant_type != "client_credentials" {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "unsupported_grant_type",
            &format!("grant_type '{grant_type}' is not supported"),
        );
    }

    // Authenticate client
    let client = match oauth::authenticate_client(&state.db, &client_id, &client_secret).await {
        Ok(c) => c,
        Err(_) => {
            return oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_client",
                "client authentication failed",
            );
        }
    };

    // Determine scopes
    let scopes: Vec<String> = match &form.scope {
        Some(s) if !s.is_empty() => s.split_whitespace().map(|x| x.to_string()).collect(),
        _ => client.scopes.clone(),
    };

    // Validate scopes are known
    if oauth::validate_scopes(&scopes).is_err() {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_scope",
            "one or more requested scopes are invalid",
        );
    }

    // Issue token (checks scope subset)
    let token = match oauth::issue_access_token(
        &client,
        &scopes,
        state.config.jwt_secret.as_bytes(),
        oauth::OAUTH_ACCESS_TOKEN_TTL_SECONDS,
    ) {
        Ok(t) => t,
        Err(_) => {
            return oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_scope",
                "requested scope exceeds client grant",
            );
        }
    };

    let body = json!({
        "access_token": token,
        "token_type": "Bearer",
        "expires_in": oauth::OAUTH_ACCESS_TOKEN_TTL_SECONDS,
        "scope": scopes.join(" "),
    });
    (StatusCode::OK, Json(body)).into_response()
}
