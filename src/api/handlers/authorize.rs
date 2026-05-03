use std::sync::Arc;

use axum::Json;
use axum::extract::State;
use axum::response::IntoResponse;
use cedar_policy::{Context, Decision, Entity, EntityUid, Request};
use serde::Deserialize;
use serde_json::{Value, json};
use std::str::FromStr;
use std::time::Instant;

use crate::api::error::{ApiError, new_request_id, success_response};
use crate::api::router::AppState;
use crate::audit::logger::{AuditLogger, AuditRecord};

#[derive(Deserialize)]
pub struct AuthorizeRequest {
    pub session_token: String,
    pub action: String,
    pub resource: ResourceRef,
    pub context: Option<Value>,
}

#[derive(Deserialize)]
pub struct ResourceRef {
    #[serde(rename = "type")]
    pub entity_type: String,
    pub id: String,
    pub attrs: Option<Value>,
}

#[derive(Deserialize)]
pub struct BatchAuthorizeRequest {
    pub session_token: String,
    pub requests: Vec<BatchItem>,
}

#[derive(Deserialize)]
pub struct BatchItem {
    pub action: String,
    pub resource: ResourceRef,
    pub context: Option<Value>,
}

pub async fn authorize(
    State(state): State<Arc<AppState>>,
    Json(body): Json<AuthorizeRequest>,
) -> impl IntoResponse {
    let rid = new_request_id();

    let mut claims = match state.session_manager.validate_token(&body.session_token) {
        Ok(c) => c,
        Err(e) => return ApiError::from_err(e, &rid).into_response(),
    };

    // Fetch fresh budget from DB (not the stale JWT snapshot)
    match state.session_manager.get_budget(&claims.jti).await {
        Ok(budget) => claims.budget = budget,
        Err(e) => return ApiError::from_err(e, &rid).into_response(),
    }

    // Check scope
    if !claims.scope.contains(&body.action) {
        return success_response(
            &rid,
            json!({
                "decision": "DENY",
                "diagnostics": {
                    "reason": "Action not in session scope",
                    "scope_violation": true,
                    "requested_action": body.action,
                    "allowed_scope": claims.scope,
                }
            }),
        )
        .into_response();
    }

    let result = evaluate_single(
        &state,
        &claims.sub,
        &body.action,
        &body.resource,
        &claims,
        body.context.as_ref(),
    )
    .await;

    match result {
        Ok(eval) => {
            log_decision(
                &state,
                &claims.jti,
                &claims.sub,
                &body.action,
                &body.resource,
                &eval,
            )
            .await;
            success_response(&rid, eval.to_json()).into_response()
        }
        Err(msg) => ApiError::bad_request(msg, &rid).into_response(),
    }
}

pub async fn authorize_batch(
    State(state): State<Arc<AppState>>,
    Json(body): Json<BatchAuthorizeRequest>,
) -> impl IntoResponse {
    let rid = new_request_id();

    let mut claims = match state.session_manager.validate_token(&body.session_token) {
        Ok(c) => c,
        Err(e) => return ApiError::from_err(e, &rid).into_response(),
    };

    // Fetch fresh budget from DB (not the stale JWT snapshot)
    match state.session_manager.get_budget(&claims.jti).await {
        Ok(budget) => claims.budget = budget,
        Err(e) => return ApiError::from_err(e, &rid).into_response(),
    }

    let mut results = Vec::new();
    for item in &body.requests {
        if !claims.scope.contains(&item.action) {
            results.push(json!({
                "decision": "DENY",
                "diagnostics": {
                    "reason": "Action not in session scope",
                    "scope_violation": true,
                }
            }));
            continue;
        }

        match evaluate_single(
            &state,
            &claims.sub,
            &item.action,
            &item.resource,
            &claims,
            item.context.as_ref(),
        )
        .await
        {
            Ok(eval) => {
                log_decision(
                    &state,
                    &claims.jti,
                    &claims.sub,
                    &item.action,
                    &item.resource,
                    &eval,
                )
                .await;
                results.push(eval.to_json());
            }
            Err(msg) => {
                results.push(json!({
                    "decision": "DENY",
                    "diagnostics": { "reason": msg }
                }));
            }
        }
    }

    success_response(&rid, json!({ "results": results })).into_response()
}

struct EvalResult {
    decision: String,
    reason: String,
    policies_evaluated: usize,
    evaluation_time_us: u128,
}

impl EvalResult {
    fn to_json(&self) -> Value {
        json!({
            "decision": self.decision,
            "diagnostics": {
                "reason": self.reason,
                "policies_evaluated": self.policies_evaluated,
                "evaluation_time_us": self.evaluation_time_us,
            }
        })
    }
}

async fn evaluate_single(
    state: &AppState,
    principal_str: &str,
    action_str: &str,
    resource: &ResourceRef,
    claims: &crate::models::SessionTokenClaims,
    extra_context: Option<&Value>,
) -> Result<EvalResult, String> {
    let engine = state.cedar_engine.read().unwrap(); // safe: lock only poisoned on panic
    let entity_store = state.entity_store.read().unwrap(); // safe: lock only poisoned on panic

    let principal =
        EntityUid::from_str(principal_str).map_err(|e| format!("invalid principal: {e}"))?;
    let action = EntityUid::from_str(action_str).map_err(|e| format!("invalid action: {e}"))?;
    let resource_uid_str = format!("{}::\"{}\"", resource.entity_type, resource.id);
    let resource_uid =
        EntityUid::from_str(&resource_uid_str).map_err(|e| format!("invalid resource: {e}"))?;

    // Build context from session claims + extra
    let mut ctx_json = json!({
        "session_id": claims.jti,
        "session_valid": true,
        "delegator_id": claims.delegator,
        "scope": claims.scope,
        "remaining_tokens": claims.budget.remaining_tokens(),
        "remaining_cost_cents": claims.budget.remaining_cost_cents(),
        "remaining_calls": claims.budget.remaining_calls(),
        "chain_depth": extra_context.and_then(|c| c.get("chain_depth")).and_then(|v| v.as_i64()).unwrap_or(1),
        "max_chain_depth": claims.max_chain_depth,
    });
    // Merge extra context fields
    if let Some(extra) = extra_context
        && let Some(obj) = extra.as_object()
    {
        for (k, v) in obj {
            if k != "chain_depth" {
                ctx_json[k] = v.clone();
            }
        }
    }

    let context = Context::from_json_value(ctx_json, Some((engine.schema(), &action)))
        .map_err(|e| format!("invalid context: {e}"))?;

    // Build entities: start from store, add inline resource if attrs provided
    let mut entities_vec: Vec<Entity> = Vec::new();
    if let Some(attrs) = &resource.attrs {
        let entity_json = json!({
            "uid": { "type": resource.entity_type, "id": resource.id },
            "attrs": attrs,
            "parents": []
        });
        if let Ok(e) = Entity::from_json_value(entity_json, Some(engine.schema())) {
            entities_vec.push(e);
        }
    }

    let entities = if entities_vec.is_empty() {
        entity_store.entities().clone()
    } else {
        entity_store
            .entities()
            .clone()
            .upsert_entities(entities_vec, Some(engine.schema()))
            .unwrap_or_else(|_| entity_store.entities().clone())
    };

    let request = Request::new(
        principal,
        action,
        resource_uid,
        context,
        Some(engine.schema()),
    )
    .map_err(|e| format!("invalid request: {e}"))?;

    let start = Instant::now();
    let response = engine.is_authorized(&request, &entities);
    let elapsed = start.elapsed().as_micros();

    let policy_count = engine.list_policies().len();
    let decision_str = match response.decision() {
        Decision::Allow => "ALLOW",
        Decision::Deny => "DENY",
    };

    let reason = response
        .diagnostics()
        .reason()
        .map(|p| format!("Matched policy: {p}"))
        .next()
        .unwrap_or_else(|| {
            if decision_str == "DENY" {
                "No matching permit policy".to_string()
            } else {
                "Permitted".to_string()
            }
        });

    Ok(EvalResult {
        decision: decision_str.to_string(),
        reason,
        policies_evaluated: policy_count,
        evaluation_time_us: elapsed,
    })
}

async fn log_decision(
    state: &AppState,
    session_id: &str,
    principal: &str,
    action: &str,
    resource: &ResourceRef,
    eval: &EvalResult,
) {
    let record = AuditRecord {
        id: AuditLogger::new_record_id(),
        timestamp: AuditLogger::now_iso(),
        session_id: session_id.to_string(),
        principal: principal.to_string(),
        action: action.to_string(),
        resource_type: resource.entity_type.clone(),
        resource_id: resource.id.clone(),
        decision: eval.decision.clone(),
        reason: eval.reason.clone(),
        policies_evaluated: eval.policies_evaluated as i64,
        evaluation_time_us: eval.evaluation_time_us as i64,
        context_snapshot: None,
    };
    let _ = state.audit_logger.log(&record).await;
}
