use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::response::IntoResponse;
use serde_json::json;

use crate::api::error::{ApiError, new_request_id, success_response};
use crate::api::router::AppState;
use crate::audit::query::{self, AuditQuery, StatsQuery};

pub async fn list_decisions(
    State(state): State<Arc<AppState>>,
    Query(q): Query<AuditQuery>,
) -> impl IntoResponse {
    let rid = new_request_id();
    match query::query_decisions(state.audit_logger.pool(), &q).await {
        Ok(records) => {
            let items: Vec<_> = records
                .iter()
                .map(|r| {
                    json!({
                        "id": r.id,
                        "timestamp": r.timestamp,
                        "session_id": r.session_id,
                        "principal": r.principal,
                        "action": r.action,
                        "resource": { "type": r.resource_type, "id": r.resource_id },
                        "decision": r.decision,
                        "reason": r.reason,
                        "policies_evaluated": r.policies_evaluated,
                        "evaluation_time_us": r.evaluation_time_us,
                    })
                })
                .collect();
            let total = items.len();
            success_response(&rid, json!({ "records": items, "total": total })).into_response()
        }
        Err(e) => ApiError::from_err(e, &rid).into_response(),
    }
}

pub async fn get_decision(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let rid = new_request_id();
    match query::get_decision(state.audit_logger.pool(), &id).await {
        Ok(r) => success_response(
            &rid,
            json!({
                "id": r.id,
                "timestamp": r.timestamp,
                "session_id": r.session_id,
                "principal": r.principal,
                "action": r.action,
                "resource": { "type": r.resource_type, "id": r.resource_id },
                "decision": r.decision,
                "reason": r.reason,
                "policies_evaluated": r.policies_evaluated,
                "evaluation_time_us": r.evaluation_time_us,
            }),
        )
        .into_response(),
        Err(e) => ApiError::from_err(e, &rid).into_response(),
    }
}

pub async fn get_stats(
    State(state): State<Arc<AppState>>,
    Query(q): Query<StatsQuery>,
) -> impl IntoResponse {
    let rid = new_request_id();
    match query::get_stats(state.audit_logger.pool(), &q).await {
        Ok(stats) => success_response(
            &rid,
            json!({
                "total_decisions": stats.total_decisions,
                "allow_count": stats.allow_count,
                "deny_count": stats.deny_count,
            }),
        )
        .into_response(),
        Err(e) => ApiError::from_err(e, &rid).into_response(),
    }
}
