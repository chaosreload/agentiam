use std::sync::Arc;

use axum::Json;
use axum::extract::{Path, Query, State};
use axum::response::IntoResponse;
use chrono::{DateTime, Utc};
use serde::Deserialize;
use serde_json::json;

use crate::api::error::{ApiError, new_request_id, success_response};
use crate::api::router::AppState;
use crate::models::{Budget, BudgetUsage, CreateSessionRequest, Session, SessionFilter};

#[derive(Deserialize)]
pub struct CreateSessionBody {
    pub delegator: DelegatorRef,
    pub agent: AgentRef,
    pub scope: Vec<String>,
    pub ttl_seconds: Option<i64>,
    pub budget: Option<BudgetInput>,
    pub max_chain_depth: Option<i32>,
    pub metadata: Option<std::collections::HashMap<String, String>>,
}

#[derive(Deserialize)]
pub struct DelegatorRef {
    #[serde(rename = "type")]
    pub entity_type: String,
    pub id: String,
}

#[derive(Deserialize)]
pub struct AgentRef {
    #[serde(rename = "type")]
    pub entity_type: String,
    pub id: String,
}

#[derive(Deserialize)]
pub struct BudgetInput {
    pub max_tokens: Option<i64>,
    pub max_cost_cents: Option<i64>,
    pub max_calls: Option<i64>,
}

#[derive(Deserialize)]
pub struct ListSessionsQuery {
    pub agent: Option<String>,
    pub delegator: Option<String>,
    pub status: Option<String>,
}

#[derive(Deserialize)]
pub struct BudgetUpdateBody {
    pub tokens_used: i64,
    pub cost_cents: i64,
    pub calls_used: i64,
}

fn session_to_json(s: &Session) -> serde_json::Value {
    let status = if s.revoked {
        "revoked"
    } else if s.expires_at <= Utc::now().timestamp() {
        "expired"
    } else {
        "active"
    };
    json!({
        "session_id": s.session_id,
        "delegator": s.delegator,
        "agent": s.agent,
        "scope": s.scope,
        "budget": {
            "max_tokens": s.budget.max_tokens,
            "max_cost_cents": s.budget.max_cost_cents,
            "max_calls": s.budget.max_calls,
            "remaining_tokens": s.budget.remaining_tokens(),
            "remaining_cost_cents": s.budget.remaining_cost_cents(),
            "remaining_calls": s.budget.remaining_calls(),
        },
        "max_chain_depth": s.max_chain_depth,
        "status": status,
        "created_at": DateTime::from_timestamp(s.created_at, 0).map(|d| d.to_rfc3339()),
        "expires_at": DateTime::from_timestamp(s.expires_at, 0).map(|d| d.to_rfc3339()),
    })
}

pub async fn create_session(
    State(state): State<Arc<AppState>>,
    Json(body): Json<CreateSessionBody>,
) -> impl IntoResponse {
    let rid = new_request_id();
    let budget = body.budget.unwrap_or(BudgetInput {
        max_tokens: Some(-1),
        max_cost_cents: Some(-1),
        max_calls: Some(-1),
    });

    let req = CreateSessionRequest {
        delegator: format!("{}::\"{}\"", body.delegator.entity_type, body.delegator.id),
        agent: format!("{}::\"{}\"", body.agent.entity_type, body.agent.id),
        scope: body.scope,
        budget: Budget {
            max_tokens: budget.max_tokens.unwrap_or(-1),
            max_cost_cents: budget.max_cost_cents.unwrap_or(-1),
            max_calls: budget.max_calls.unwrap_or(-1),
            used_tokens: 0,
            used_cost_cents: 0,
            used_calls: 0,
        },
        max_chain_depth: body.max_chain_depth,
        delegation_chain: None,
        metadata: body.metadata,
        ttl_seconds: body.ttl_seconds,
    };

    match state.session_manager.create_session(req).await {
        Ok(session) => {
            let mut data = session_to_json(&session);
            data["token"] = json!(session.token);
            (
                axum::http::StatusCode::CREATED,
                success_response(&rid, data),
            )
                .into_response()
        }
        Err(e) => ApiError::from_err(e, &rid).into_response(),
    }
}

pub async fn list_sessions(
    State(state): State<Arc<AppState>>,
    Query(q): Query<ListSessionsQuery>,
) -> impl IntoResponse {
    let rid = new_request_id();
    let active_only = match q.status.as_deref() {
        Some("active") | None => Some(true),
        Some("revoked") | Some("expired") => Some(false),
        _ => None,
    };
    let filter = SessionFilter {
        delegator: q.delegator,
        agent: q.agent,
        active_only,
    };

    match state.session_manager.list_sessions(filter).await {
        Ok(sessions) => {
            let items: Vec<_> = sessions.iter().map(session_to_json).collect();
            success_response(
                &rid,
                json!({
                    "sessions": items,
                    "total": items.len(),
                }),
            )
            .into_response()
        }
        Err(e) => ApiError::from_err(e, &rid).into_response(),
    }
}

pub async fn get_session(
    State(state): State<Arc<AppState>>,
    Path(session_id): Path<String>,
) -> impl IntoResponse {
    let rid = new_request_id();
    match state.session_manager.get_session(&session_id).await {
        Ok(session) => success_response(&rid, session_to_json(&session)).into_response(),
        Err(e) => ApiError::from_err(e, &rid).into_response(),
    }
}

pub async fn delete_session(
    State(state): State<Arc<AppState>>,
    Path(session_id): Path<String>,
) -> impl IntoResponse {
    let rid = new_request_id();
    match state.session_manager.revoke_session(&session_id).await {
        Ok(()) => success_response(
            &rid,
            json!({
                "session_id": session_id,
                "status": "revoked",
                "revoked_at": chrono::Utc::now().to_rfc3339(),
            }),
        )
        .into_response(),
        Err(e) => ApiError::from_err(e, &rid).into_response(),
    }
}

pub async fn update_budget(
    State(state): State<Arc<AppState>>,
    Path(session_id): Path<String>,
    Json(body): Json<BudgetUpdateBody>,
) -> impl IntoResponse {
    let rid = new_request_id();
    let usage = BudgetUsage {
        tokens: body.tokens_used,
        cost_cents: body.cost_cents,
        calls: body.calls_used,
    };

    match state
        .session_manager
        .update_budget(&session_id, usage)
        .await
    {
        Ok(status) => success_response(
            &rid,
            json!({
                "session_id": session_id,
                "budget": {
                    "remaining_tokens": status.budget.remaining_tokens(),
                    "remaining_cost_cents": status.budget.remaining_cost_cents(),
                    "remaining_calls": status.budget.remaining_calls(),
                },
                "budget_exhausted": status.exhausted,
            }),
        )
        .into_response(),
        Err(e) => ApiError::from_err(e, &rid).into_response(),
    }
}
