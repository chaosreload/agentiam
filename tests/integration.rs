use std::sync::{Arc, RwLock};

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use serde_json::{Value, json};
use sqlx::sqlite::SqlitePoolOptions;
use tower::ServiceExt;

use agentiam::api::router::{AppState, build_router};
use agentiam::audit::logger::AuditLogger;
use agentiam::cedar::engine::CedarEngine;
use agentiam::cedar::entities::EntityStore;
use agentiam::config::AppConfig;
use agentiam::session::manager::SessionManager;
use agentiam::token::apikey;

const TEST_SECRET: &str = "test-jwt-secret-for-integration";

struct TestHarness {
    app: axum::Router,
    key: String,
}

impl TestHarness {
    fn auth(&self) -> String {
        format!("Bearer {}", self.key)
    }
}

async fn setup() -> TestHarness {
    let db = SqlitePoolOptions::new()
        .connect("sqlite::memory:")
        .await
        .unwrap();

    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let config = AppConfig {
        port: 0,
        policy_dir: format!("{manifest_dir}/policies").into(),
        schema_file: format!("{manifest_dir}/schemas/agentiam.cedarschema").into(),
        jwt_secret: TEST_SECRET.to_string(),
        db_path: "sqlite::memory:".to_string(),
    };

    let engine = CedarEngine::new(&config.schema_file, &config.policy_dir).unwrap();
    let entity_store = EntityStore::new(engine.schema().clone());
    let session_manager = SessionManager::new(db.clone(), TEST_SECRET.as_bytes().to_vec())
        .await
        .unwrap();
    let audit_logger = AuditLogger::new(db.clone()).await.unwrap();
    apikey::ensure_table(&db).await.unwrap();

    let (key, hash) = apikey::create_api_key("test");
    apikey::store_api_key(&db, "test-key-id", "test-key", &hash, "test")
        .await
        .unwrap();

    let state = Arc::new(AppState {
        cedar_engine: RwLock::new(engine),
        entity_store: RwLock::new(entity_store),
        session_manager,
        audit_logger,
        config,
        db,
    });

    TestHarness {
        app: build_router(state),
        key,
    }
}

async fn body_json(body: Body) -> Value {
    let bytes = body.collect().await.unwrap().to_bytes();
    serde_json::from_slice(&bytes).unwrap()
}

async fn create_test_session(h: &TestHarness) -> Value {
    let body = json!({
        "delegator": { "type": "AgentIAM::User", "id": "alice" },
        "agent": { "type": "AgentIAM::Agent", "id": "research-scout" },
        "scope": [r#"AgentIAM::Action::"read""#, r#"AgentIAM::Action::"list""#],
        "ttl_seconds": 3600,
        "budget": { "max_tokens": 10000, "max_cost_cents": 500, "max_calls": 100 },
        "max_chain_depth": 5,
    });
    let req = Request::builder()
        .method("POST")
        .uri("/v1/sessions")
        .header("authorization", h.auth())
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();
    let resp = h.app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    body_json(resp.into_body()).await
}

// ─── Health ───

#[tokio::test]
async fn test_health_no_auth() {
    let h = setup().await;
    let req = Request::builder()
        .uri("/health")
        .body(Body::empty())
        .unwrap();
    let resp = h.app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let json = body_json(resp.into_body()).await;
    assert_eq!(json["status"], "healthy");
    assert!(
        json["components"]["cedar_engine"]["policies_loaded"]
            .as_i64()
            .unwrap()
            > 0
    );
}

// ─── Auth middleware ───

#[tokio::test]
async fn test_v1_without_auth_returns_401() {
    let h = setup().await;
    let req = Request::builder()
        .uri("/v1/policies")
        .body(Body::empty())
        .unwrap();
    let resp = h.app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_v1_with_bad_key_returns_401() {
    let h = setup().await;
    let req = Request::builder()
        .uri("/v1/policies")
        .header("authorization", "Bearer ak_bad_key")
        .body(Body::empty())
        .unwrap();
    let resp = h.app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

// ─── Policies ───

#[tokio::test]
async fn test_list_policies() {
    let h = setup().await;
    let req = Request::builder()
        .uri("/v1/policies")
        .header("authorization", h.auth())
        .body(Body::empty())
        .unwrap();
    let resp = h.app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let json = body_json(resp.into_body()).await;
    assert!(json["data"]["total"].as_i64().unwrap() > 0);
}

#[tokio::test]
async fn test_validate_policy_good() {
    let h = setup().await;
    let body = json!({
        "policy_text": r#"@id("test") permit(principal is AgentIAM::Agent, action == AgentIAM::Action::"read", resource is AgentIAM::Resource) when { resource.sensitivity == "public" };"#
    });
    let req = Request::builder()
        .method("POST")
        .uri("/v1/policies/validate")
        .header("authorization", h.auth())
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();
    let resp = h.app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let json = body_json(resp.into_body()).await;
    assert_eq!(json["data"]["valid"], true);
}

#[tokio::test]
async fn test_validate_policy_bad() {
    let h = setup().await;
    let body = json!({ "policy_text": "not valid cedar {{" });
    let req = Request::builder()
        .method("POST")
        .uri("/v1/policies/validate")
        .header("authorization", h.auth())
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();
    let resp = h.app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let json = body_json(resp.into_body()).await;
    assert_eq!(json["data"]["valid"], false);
}

#[tokio::test]
async fn test_reload_policies() {
    let h = setup().await;
    let req = Request::builder()
        .method("POST")
        .uri("/v1/policies/reload")
        .header("authorization", h.auth())
        .body(Body::empty())
        .unwrap();
    let resp = h.app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let json = body_json(resp.into_body()).await;
    assert_eq!(json["data"]["reloaded"], true);
}

// ─── Sessions ───

#[tokio::test]
async fn test_create_and_get_session() {
    let h = setup().await;
    let created = create_test_session(&h).await;
    let session_id = created["data"]["session_id"].as_str().unwrap();
    assert!(!session_id.is_empty());
    assert!(created["data"]["token"].as_str().is_some());

    let req = Request::builder()
        .uri(format!("/v1/sessions/{session_id}"))
        .header("authorization", h.auth())
        .body(Body::empty())
        .unwrap();
    let resp = h.app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let json = body_json(resp.into_body()).await;
    assert_eq!(json["data"]["session_id"], session_id);
}

#[tokio::test]
async fn test_list_sessions() {
    let h = setup().await;
    create_test_session(&h).await;

    let req = Request::builder()
        .uri("/v1/sessions")
        .header("authorization", h.auth())
        .body(Body::empty())
        .unwrap();
    let resp = h.app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let json = body_json(resp.into_body()).await;
    assert!(json["data"]["total"].as_i64().unwrap() >= 1);
}

#[tokio::test]
async fn test_revoke_session() {
    let h = setup().await;
    let created = create_test_session(&h).await;
    let session_id = created["data"]["session_id"].as_str().unwrap();

    let req = Request::builder()
        .method("DELETE")
        .uri(format!("/v1/sessions/{session_id}"))
        .header("authorization", h.auth())
        .body(Body::empty())
        .unwrap();
    let resp = h.app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let json = body_json(resp.into_body()).await;
    assert_eq!(json["data"]["status"], "revoked");
}

#[tokio::test]
async fn test_update_budget() {
    let h = setup().await;
    let created = create_test_session(&h).await;
    let session_id = created["data"]["session_id"].as_str().unwrap();

    let body = json!({ "tokens_used": 500, "cost_cents": 10, "calls_used": 1 });
    let req = Request::builder()
        .method("POST")
        .uri(format!("/v1/sessions/{session_id}/budget"))
        .header("authorization", h.auth())
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();
    let resp = h.app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let json = body_json(resp.into_body()).await;
    assert_eq!(json["data"]["budget"]["remaining_tokens"], 9500);
    assert_eq!(json["data"]["budget_exhausted"], false);
}

// ─── Entities ───

#[tokio::test]
async fn test_create_and_get_entity() {
    let h = setup().await;
    let body = json!({
        "entities": [{
            "type": "AgentIAM::User",
            "id": "test-user",
            "attrs": { "email": "test@example.com", "role": "admin", "mfa_enabled": true, "suspended": false },
            "parents": []
        }]
    });
    let req = Request::builder()
        .method("POST")
        .uri("/v1/entities")
        .header("authorization", h.auth())
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();
    let resp = h.app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let json = body_json(resp.into_body()).await;
    assert_eq!(json["data"]["created"], 1);

    let req = Request::builder()
        .uri("/v1/entities/AgentIAM::User/test-user")
        .header("authorization", h.auth())
        .body(Body::empty())
        .unwrap();
    let resp = h.app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_list_entities() {
    let h = setup().await;
    let req = Request::builder()
        .uri("/v1/entities")
        .header("authorization", h.auth())
        .body(Body::empty())
        .unwrap();
    let resp = h.app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_delete_entity() {
    let h = setup().await;
    let body = json!({
        "entities": [{
            "type": "AgentIAM::User", "id": "to-delete",
            "attrs": { "email": "del@example.com", "role": "viewer", "mfa_enabled": false, "suspended": false },
            "parents": []
        }]
    });
    let req = Request::builder()
        .method("POST")
        .uri("/v1/entities")
        .header("authorization", h.auth())
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();
    h.app.clone().oneshot(req).await.unwrap();

    let req = Request::builder()
        .method("DELETE")
        .uri("/v1/entities/AgentIAM::User/to-delete")
        .header("authorization", h.auth())
        .body(Body::empty())
        .unwrap();
    let resp = h.app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

// ─── Authorize ───

#[tokio::test]
async fn test_authorize_allow() {
    let h = setup().await;

    let entities_body = json!({
        "entities": [
            {
                "type": "AgentIAM::User", "id": "alice",
                "attrs": { "email": "alice@example.com", "role": "admin", "mfa_enabled": true, "suspended": false },
                "parents": []
            },
            {
                "type": "AgentIAM::Agent", "id": "research-scout",
                "attrs": {
                    "delegator": { "__entity": { "type": "AgentIAM::User", "id": "alice" } },
                    "framework": "langchain", "risk_level": "low", "banned": false, "sandbox_only": false
                },
                "parents": []
            }
        ]
    });
    let req = Request::builder()
        .method("POST")
        .uri("/v1/entities")
        .header("authorization", h.auth())
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&entities_body).unwrap()))
        .unwrap();
    h.app.clone().oneshot(req).await.unwrap();

    let session_json = create_test_session(&h).await;
    let token = session_json["data"]["token"].as_str().unwrap();

    let auth_body = json!({
        "session_token": token,
        "action": r#"AgentIAM::Action::"read""#,
        "resource": {
            "type": "AgentIAM::Resource", "id": "public-doc",
            "attrs": { "sensitivity": "public", "environment": "development", "sandbox": false, "private": false }
        },
        "context": { "chain_depth": 1 }
    });
    let req = Request::builder()
        .method("POST")
        .uri("/v1/authorize")
        .header("authorization", h.auth())
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&auth_body).unwrap()))
        .unwrap();
    let resp = h.app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let json = body_json(resp.into_body()).await;
    assert_eq!(json["data"]["decision"], "ALLOW");
}

#[tokio::test]
async fn test_authorize_scope_deny() {
    let h = setup().await;
    let session_json = create_test_session(&h).await;
    let token = session_json["data"]["token"].as_str().unwrap();

    let auth_body = json!({
        "session_token": token,
        "action": r#"AgentIAM::Action::"delete""#,
        "resource": { "type": "AgentIAM::Resource", "id": "file-1" },
        "context": {}
    });
    let req = Request::builder()
        .method("POST")
        .uri("/v1/authorize")
        .header("authorization", h.auth())
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&auth_body).unwrap()))
        .unwrap();
    let resp = h.app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let json = body_json(resp.into_body()).await;
    assert_eq!(json["data"]["decision"], "DENY");
    assert_eq!(json["data"]["diagnostics"]["scope_violation"], true);
}

// ─── Batch Authorize ───

#[tokio::test]
async fn test_authorize_batch() {
    let h = setup().await;
    let session_json = create_test_session(&h).await;
    let token = session_json["data"]["token"].as_str().unwrap();

    let batch_body = json!({
        "session_token": token,
        "requests": [
            {
                "action": r#"AgentIAM::Action::"read""#,
                "resource": {
                    "type": "AgentIAM::Resource", "id": "public-doc",
                    "attrs": { "sensitivity": "public", "environment": "dev", "sandbox": false, "private": false }
                }
            },
            {
                "action": r#"AgentIAM::Action::"delete""#,
                "resource": { "type": "AgentIAM::Resource", "id": "file-1" }
            }
        ]
    });
    let req = Request::builder()
        .method("POST")
        .uri("/v1/authorize/batch")
        .header("authorization", h.auth())
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&batch_body).unwrap()))
        .unwrap();
    let resp = h.app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let json = body_json(resp.into_body()).await;
    let results = json["data"]["results"].as_array().unwrap();
    assert_eq!(results.len(), 2);
    assert_eq!(results[1]["decision"], "DENY");
}

// ─── Audit ───

#[tokio::test]
async fn test_audit_decisions_empty() {
    let h = setup().await;
    let req = Request::builder()
        .uri("/v1/audit/decisions")
        .header("authorization", h.auth())
        .body(Body::empty())
        .unwrap();
    let resp = h.app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let json = body_json(resp.into_body()).await;
    assert_eq!(json["data"]["total"], 0);
}

#[tokio::test]
async fn test_audit_stats() {
    let h = setup().await;
    let req = Request::builder()
        .uri("/v1/audit/stats")
        .header("authorization", h.auth())
        .body(Body::empty())
        .unwrap();
    let resp = h.app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let json = body_json(resp.into_body()).await;
    assert_eq!(json["data"]["total_decisions"], 0);
}

// ─── Config ───

#[tokio::test]
async fn test_config() {
    let h = setup().await;
    let req = Request::builder()
        .uri("/v1/config")
        .header("authorization", h.auth())
        .body(Body::empty())
        .unwrap();
    let resp = h.app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let json = body_json(resp.into_body()).await;
    assert_eq!(json["data"]["auth_mode"], "api_key");
}
