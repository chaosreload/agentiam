use std::sync::Arc;

use axum::Json;
use axum::extract::{Path, Query, State};
use axum::response::IntoResponse;
use cedar_policy::{Entity, EntityUid};
use serde::Deserialize;
use serde_json::{Value, json};
use std::str::FromStr;

use crate::api::error::{ApiError, new_request_id, success_response};
use crate::api::router::AppState;

#[derive(Deserialize)]
pub struct CreateEntitiesBody {
    pub entities: Vec<EntityInput>,
}

#[derive(Deserialize)]
pub struct EntityInput {
    #[serde(rename = "type")]
    pub entity_type: String,
    pub id: String,
    pub attrs: Option<Value>,
    pub parents: Option<Vec<ParentRef>>,
}

#[derive(Deserialize)]
pub struct ParentRef {
    #[serde(rename = "type")]
    pub entity_type: String,
    pub id: String,
}

#[derive(Deserialize)]
pub struct ListEntitiesQuery {
    #[serde(rename = "type")]
    pub entity_type: Option<String>,
}

pub async fn create_entities(
    State(state): State<Arc<AppState>>,
    Json(body): Json<CreateEntitiesBody>,
) -> impl IntoResponse {
    let rid = new_request_id();
    let mut store = state.entity_store.write().unwrap(); // safe: lock only poisoned on panic
    let engine = state.cedar_engine.read().unwrap(); // safe: lock only poisoned on panic

    let mut results = Vec::new();
    let mut cedar_entities = Vec::new();

    for input in &body.entities {
        let parents_json: Vec<Value> = input
            .parents
            .as_ref()
            .map(|ps| {
                ps.iter()
                    .map(|p| json!({"type": p.entity_type, "id": p.id}))
                    .collect()
            })
            .unwrap_or_default();

        let entity_json = json!({
            "uid": { "type": input.entity_type, "id": input.id },
            "attrs": input.attrs.clone().unwrap_or(json!({})),
            "parents": parents_json,
        });

        match Entity::from_json_value(entity_json, Some(engine.schema())) {
            Ok(entity) => {
                let uid_str = format!("{}::\"{}\"", input.entity_type, input.id);
                let existed = EntityUid::from_str(&uid_str)
                    .ok()
                    .and_then(|uid| store.get(&uid))
                    .is_some();
                cedar_entities.push(entity);
                results.push(json!({
                    "type": input.entity_type,
                    "id": input.id,
                    "status": if existed { "updated" } else { "created" },
                }));
            }
            Err(e) => {
                return ApiError::bad_request(
                    format!("invalid entity {}::{}: {e}", input.entity_type, input.id),
                    &rid,
                )
                .into_response();
            }
        }
    }

    if let Err(e) = store.upsert(cedar_entities) {
        return ApiError::bad_request(format!("upsert error: {e}"), &rid).into_response();
    }

    let created = results.iter().filter(|r| r["status"] == "created").count();
    let updated = results.iter().filter(|r| r["status"] == "updated").count();

    success_response(
        &rid,
        json!({
            "created": created,
            "updated": updated,
            "entities": results,
        }),
    )
    .into_response()
}

pub async fn list_entities(
    State(state): State<Arc<AppState>>,
    Query(q): Query<ListEntitiesQuery>,
) -> impl IntoResponse {
    let rid = new_request_id();
    let store = state.entity_store.read().unwrap(); // safe: lock only poisoned on panic

    let entities: Vec<Value> = store
        .entities()
        .iter()
        .filter(|e| {
            if let Some(ref t) = q.entity_type {
                e.uid().type_name().to_string() == *t
            } else {
                true
            }
        })
        .map(|e| {
            json!({
                "type": e.uid().type_name().to_string(),
                "id": AsRef::<str>::as_ref(e.uid().id()),
            })
        })
        .collect();

    success_response(
        &rid,
        json!({
            "entities": entities,
            "total": entities.len(),
        }),
    )
    .into_response()
}

pub async fn get_entity(
    State(state): State<Arc<AppState>>,
    Path((entity_type, entity_id)): Path<(String, String)>,
) -> impl IntoResponse {
    let rid = new_request_id();
    let store = state.entity_store.read().unwrap(); // safe: lock only poisoned on panic
    let uid_str = format!("{entity_type}::\"{entity_id}\"");

    let uid = match EntityUid::from_str(&uid_str) {
        Ok(u) => u,
        Err(e) => {
            return ApiError::bad_request(format!("invalid entity UID: {e}"), &rid).into_response();
        }
    };

    match store.get(&uid) {
        Some(entity) => success_response(
            &rid,
            json!({
                "type": entity.uid().type_name().to_string(),
                "id": AsRef::<str>::as_ref(entity.uid().id()),
            }),
        )
        .into_response(),
        None => ApiError::not_found(format!("entity not found: {uid_str}"), &rid).into_response(),
    }
}

pub async fn delete_entity(
    State(state): State<Arc<AppState>>,
    Path((entity_type, entity_id)): Path<(String, String)>,
) -> impl IntoResponse {
    let rid = new_request_id();
    let mut store = state.entity_store.write().unwrap(); // safe: lock only poisoned on panic
    let uid_str = format!("{entity_type}::\"{entity_id}\"");

    let uid = match EntityUid::from_str(&uid_str) {
        Ok(u) => u,
        Err(e) => {
            return ApiError::bad_request(format!("invalid entity UID: {e}"), &rid).into_response();
        }
    };

    match store.delete(uid) {
        Ok(()) => success_response(
            &rid,
            json!({
                "deleted": true,
                "type": entity_type,
                "id": entity_id,
            }),
        )
        .into_response(),
        Err(e) => ApiError::bad_request(format!("delete error: {e}"), &rid).into_response(),
    }
}
