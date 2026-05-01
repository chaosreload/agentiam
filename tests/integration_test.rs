//! Week 4.2 — End-to-end integration tests (13 scenarios)
//!
//! Uses tower::ServiceExt::oneshot (no real TCP server) for speed and isolation.

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

const TEST_SECRET: &str = "integration-test-jwt-secret-week4";

// ─── Test Harness ───────────────────────────────────────────────────

struct Harness {
    app: axum::Router,
    state: Arc<AppState>,
    key: String,
}

impl Harness {
    fn auth(&self) -> String {
        format!("Bearer {}", self.key)
    }

    async fn post(&self, uri: &str, body: Value) -> (StatusCode, Value) {
        let req = Request::builder()
            .method("POST")
            .uri(uri)
            .header("authorization", self.auth())
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(&body).unwrap()))
            .unwrap();
        let resp = self.app.clone().oneshot(req).await.unwrap();
        let status = resp.status();
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        (status, serde_json::from_slice(&bytes).unwrap())
    }

    async fn get(&self, uri: &str) -> (StatusCode, Value) {
        let req = Request::builder()
            .uri(uri)
            .header("authorization", self.auth())
            .body(Body::empty())
            .unwrap();
        let resp = self.app.clone().oneshot(req).await.unwrap();
        let status = resp.status();
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        (status, serde_json::from_slice(&bytes).unwrap())
    }

    async fn delete(&self, uri: &str) -> (StatusCode, Value) {
        let req = Request::builder()
            .method("DELETE")
            .uri(uri)
            .header("authorization", self.auth())
            .body(Body::empty())
            .unwrap();
        let resp = self.app.clone().oneshot(req).await.unwrap();
        let status = resp.status();
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        (status, serde_json::from_slice(&bytes).unwrap())
    }

    /// Register the standard User + Agent + Resource entities for authorize tests
    async fn register_standard_entities(&self) {
        let body = json!({
            "entities": [
                {
                    "type": "AgentIAM::User", "id": "alice",
                    "attrs": { "email": "alice@test.com", "role": "admin", "mfa_enabled": true, "suspended": false },
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
        let (status, _) = self.post("/v1/entities", body).await;
        assert_eq!(status, StatusCode::OK);
    }

    /// Create a session and return (session_id, jwt_token)
    async fn create_session_with(
        &self,
        scope: Vec<&str>,
        ttl: Option<i64>,
        budget_tokens: i64,
    ) -> (String, String) {
        let body = json!({
            "delegator": { "type": "AgentIAM::User", "id": "alice" },
            "agent": { "type": "AgentIAM::Agent", "id": "research-scout" },
            "scope": scope,
            "ttl_seconds": ttl.unwrap_or(3600),
            "budget": { "max_tokens": budget_tokens, "max_cost_cents": 500, "max_calls": 100 },
            "max_chain_depth": 5,
        });
        let (status, json) = self.post("/v1/sessions", body).await;
        assert_eq!(status, StatusCode::CREATED);
        let sid = json["data"]["session_id"].as_str().unwrap().to_string();
        let token = json["data"]["token"].as_str().unwrap().to_string();
        (sid, token)
    }

    /// Create a standard session with read+list scope and 10000 token budget
    async fn create_standard_session(&self) -> (String, String) {
        self.create_session_with(
            vec![r#"AgentIAM::Action::"read""#, r#"AgentIAM::Action::"list""#],
            None,
            10000,
        )
        .await
    }
}

async fn setup() -> Harness {
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

    Harness {
        app: build_router(state.clone()),
        state,
        key,
    }
}

// ═══════════════════════════════════════════════════════════════════
// Scenario 1: Server Startup + Health
// ═══════════════════════════════════════════════════════════════════

#[tokio::test]
async fn s01_server_startup_and_health() {
    let h = setup().await;
    let req = Request::builder()
        .uri("/health")
        .body(Body::empty())
        .unwrap();
    let resp = h.app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let json: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(json["status"], "healthy");
    assert!(
        json["components"]["cedar_engine"]["policies_loaded"]
            .as_i64()
            .unwrap()
            > 0
    );
}

// ═══════════════════════════════════════════════════════════════════
// Scenario 2: API Key Authentication
// ═══════════════════════════════════════════════════════════════════

#[tokio::test]
async fn s02_api_key_auth() {
    let h = setup().await;

    // Valid key → 200
    let (status, json) = h.get("/v1/policies").await;
    assert_eq!(status, StatusCode::OK);
    assert!(json["data"]["total"].as_i64().unwrap() > 0);

    // Invalid key → 401
    let req = Request::builder()
        .uri("/v1/policies")
        .header("authorization", "Bearer ak_invalid_key_12345")
        .body(Body::empty())
        .unwrap();
    let resp = h.app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    // No auth header → 401
    let req = Request::builder()
        .uri("/v1/policies")
        .body(Body::empty())
        .unwrap();
    let resp = h.app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

// ═══════════════════════════════════════════════════════════════════
// Scenario 3: OAuth Client Credentials Flow
// (OAuth HTTP endpoints not exposed in current router — test module directly)
// ═══════════════════════════════════════════════════════════════════

#[tokio::test]
async fn s03_oauth_client_credentials() {
    use agentiam::token::oauth;

    // OAuth endpoints are not exposed via HTTP yet — test the module directly.
    let db = SqlitePoolOptions::new()
        .connect("sqlite::memory:")
        .await
        .unwrap();
    oauth::ensure_table(&db).await.unwrap();

    // Register client
    let scopes = vec!["authorize".to_string(), "sessions:read".to_string()];
    let (client, secret) = oauth::register_client(&db, "test-app", scopes)
        .await
        .unwrap();
    assert!(client.client_id.starts_with("iam_"));

    // Authenticate with correct credentials
    let authed = oauth::authenticate_client(&db, &client.client_id, &secret)
        .await
        .unwrap();
    assert_eq!(authed.client_id, client.client_id);

    // Wrong credentials → error
    let bad = oauth::authenticate_client(&db, &client.client_id, "wrong-secret").await;
    assert!(bad.is_err());

    // Issue access token
    let requested = vec!["authorize".to_string()];
    let token =
        oauth::issue_access_token(&authed, &requested, TEST_SECRET.as_bytes(), 3600).unwrap();
    assert!(!token.is_empty());
}

// ═══════════════════════════════════════════════════════════════════
// Scenario 4: Entity CRUD (User + Agent + Resource)
// ═══════════════════════════════════════════════════════════════════

#[tokio::test]
async fn s04_entity_crud() {
    let h = setup().await;

    // Create 3 entities: User, Agent, Resource
    let body = json!({
        "entities": [
            {
                "type": "AgentIAM::User", "id": "bob",
                "attrs": { "email": "bob@test.com", "role": "developer", "mfa_enabled": false, "suspended": false },
                "parents": []
            },
            {
                "type": "AgentIAM::Agent", "id": "code-bot",
                "attrs": {
                    "delegator": { "__entity": { "type": "AgentIAM::User", "id": "bob" } },
                    "framework": "autogen", "risk_level": "medium", "banned": false, "sandbox_only": false
                },
                "parents": []
            },
            {
                "type": "AgentIAM::Resource", "id": "doc-1",
                "attrs": { "sensitivity": "public", "environment": "development", "sandbox": false, "private": false },
                "parents": []
            }
        ]
    });
    let (status, json) = h.post("/v1/entities", body).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["data"]["created"], 3);

    // GET each entity
    let (status, _) = h.get("/v1/entities/AgentIAM::User/bob").await;
    assert_eq!(status, StatusCode::OK);

    let (status, _) = h.get("/v1/entities/AgentIAM::Agent/code-bot").await;
    assert_eq!(status, StatusCode::OK);

    let (status, _) = h.get("/v1/entities/AgentIAM::Resource/doc-1").await;
    assert_eq!(status, StatusCode::OK);
}

// ═══════════════════════════════════════════════════════════════════
// Scenario 5: Session Creation
// ═══════════════════════════════════════════════════════════════════

#[tokio::test]
async fn s05_session_creation() {
    let h = setup().await;

    let body = json!({
        "delegator": { "type": "AgentIAM::User", "id": "alice" },
        "agent": { "type": "AgentIAM::Agent", "id": "research-scout" },
        "scope": [r#"AgentIAM::Action::"read""#, r#"AgentIAM::Action::"list""#],
        "ttl_seconds": 3600,
        "budget": { "max_tokens": 10000, "max_cost_cents": 500, "max_calls": 100 },
        "max_chain_depth": 5,
    });
    let (status, json) = h.post("/v1/sessions", body).await;
    assert_eq!(status, StatusCode::CREATED);

    let session_id = json["data"]["session_id"].as_str().unwrap();
    let token = json["data"]["token"].as_str().unwrap();
    assert!(!session_id.is_empty());
    assert!(!token.is_empty());

    // Verify scope and budget in response
    assert_eq!(json["data"]["scope"].as_array().unwrap().len(), 2);
    assert_eq!(json["data"]["budget"]["max_tokens"], 10000);
    assert_eq!(json["data"]["budget"]["remaining_tokens"], 10000);

    // GET the session
    let (status, get_json) = h.get(&format!("/v1/sessions/{session_id}")).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(get_json["data"]["session_id"], session_id);
    assert_eq!(get_json["data"]["status"], "active");
}

// ═══════════════════════════════════════════════════════════════════
// Scenario 6: Authorize PERMIT
// ═══════════════════════════════════════════════════════════════════

#[tokio::test]
async fn s06_authorize_permit() {
    let h = setup().await;
    h.register_standard_entities().await;
    let (_sid, token) = h.create_standard_session().await;

    let body = json!({
        "session_token": token,
        "action": r#"AgentIAM::Action::"read""#,
        "resource": {
            "type": "AgentIAM::Resource", "id": "public-doc",
            "attrs": { "sensitivity": "public", "environment": "development", "sandbox": false, "private": false }
        },
        "context": { "chain_depth": 1 }
    });
    let (status, json) = h.post("/v1/authorize", body).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["data"]["decision"], "ALLOW");
}

// ═══════════════════════════════════════════════════════════════════
// Scenario 7: Authorize Guardrail FORBID (banned agent)
// ═══════════════════════════════════════════════════════════════════

#[tokio::test]
async fn s07_authorize_guardrail_forbid() {
    let h = setup().await;

    // Register a BANNED agent
    let body = json!({
        "entities": [
            {
                "type": "AgentIAM::User", "id": "alice",
                "attrs": { "email": "alice@test.com", "role": "admin", "mfa_enabled": true, "suspended": false },
                "parents": []
            },
            {
                "type": "AgentIAM::Agent", "id": "research-scout",
                "attrs": {
                    "delegator": { "__entity": { "type": "AgentIAM::User", "id": "alice" } },
                    "framework": "langchain", "risk_level": "high", "banned": true, "sandbox_only": false
                },
                "parents": []
            }
        ]
    });
    let (status, _) = h.post("/v1/entities", body).await;
    assert_eq!(status, StatusCode::OK);

    let (_sid, token) = h.create_standard_session().await;

    let body = json!({
        "session_token": token,
        "action": r#"AgentIAM::Action::"read""#,
        "resource": {
            "type": "AgentIAM::Resource", "id": "public-doc",
            "attrs": { "sensitivity": "public", "environment": "development", "sandbox": false, "private": false }
        },
        "context": { "chain_depth": 1 }
    });
    let (status, json) = h.post("/v1/authorize", body).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["data"]["decision"], "DENY");
    // Guardrail forbid fires — reason is "Matched policy: <id>" or "No matching permit policy"
    // The key assertion is that a banned agent gets DENY despite having a permit policy match
    let reason = json["data"]["diagnostics"]["reason"].as_str().unwrap();
    assert!(
        reason.contains("policy") || reason.contains("No matching"),
        "expected policy-based reason, got: {reason}"
    );
}

// ═══════════════════════════════════════════════════════════════════
// Scenario 8: Authorize Scope Violation
// ═══════════════════════════════════════════════════════════════════

#[tokio::test]
async fn s08_authorize_scope_violation() {
    let h = setup().await;
    let (_sid, token) = h.create_standard_session().await;

    // "delete" is NOT in scope (session has read + list only)
    let body = json!({
        "session_token": token,
        "action": r#"AgentIAM::Action::"delete""#,
        "resource": { "type": "AgentIAM::Resource", "id": "some-file" },
        "context": {}
    });
    let (status, json) = h.post("/v1/authorize", body).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["data"]["decision"], "DENY");
    assert_eq!(json["data"]["diagnostics"]["scope_violation"], true);
}

// ═══════════════════════════════════════════════════════════════════
// Scenario 9: Authorize Expired Session
// ═══════════════════════════════════════════════════════════════════

#[tokio::test]
async fn s09_authorize_expired_session() {
    let h = setup().await;

    // Create session with TTL=1s
    let (_sid, token) = h
        .create_session_with(vec![r#"AgentIAM::Action::"read""#], Some(1), 10000)
        .await;

    // Wait for expiry
    tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;

    let body = json!({
        "session_token": token,
        "action": r#"AgentIAM::Action::"read""#,
        "resource": { "type": "AgentIAM::Resource", "id": "doc" },
        "context": {}
    });
    let (status, json) = h.post("/v1/authorize", body).await;
    // Expired JWT → 401 Unauthorized
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let msg = json["error"]["message"].as_str().unwrap_or("");
    assert!(
        msg.to_lowercase().contains("expired") || msg.to_lowercase().contains("exp"),
        "expected expiry error, got: {msg}"
    );
}

// ═══════════════════════════════════════════════════════════════════
// Scenario 10: Authorize Revoked Session
// ═══════════════════════════════════════════════════════════════════

#[tokio::test]
async fn s10_authorize_revoked_session() {
    let h = setup().await;
    let (sid, token) = h.create_standard_session().await;

    // Revoke the session
    let (status, _) = h.delete(&format!("/v1/sessions/{sid}")).await;
    assert_eq!(status, StatusCode::OK);

    // Attempt authorize with revoked session token
    let body = json!({
        "session_token": token,
        "action": r#"AgentIAM::Action::"read""#,
        "resource": { "type": "AgentIAM::Resource", "id": "doc" },
        "context": {}
    });
    let (status, json) = h.post("/v1/authorize", body).await;
    // Revoked → 403 Forbidden
    assert_eq!(status, StatusCode::FORBIDDEN);
    let msg = json["error"]["message"].as_str().unwrap_or("");
    assert!(
        msg.to_lowercase().contains("revoked"),
        "expected revoked error, got: {msg}"
    );
}

// ═══════════════════════════════════════════════════════════════════
// Scenario 11: Authorize Batch
// ═══════════════════════════════════════════════════════════════════

#[tokio::test]
async fn s11_authorize_batch() {
    let h = setup().await;
    h.register_standard_entities().await;
    let (_sid, token) = h.create_standard_session().await;

    let body = json!({
        "session_token": token,
        "requests": [
            {
                "action": r#"AgentIAM::Action::"read""#,
                "resource": {
                    "type": "AgentIAM::Resource", "id": "pub-1",
                    "attrs": { "sensitivity": "public", "environment": "dev", "sandbox": false, "private": false }
                },
                "context": { "chain_depth": 1 }
            },
            {
                "action": r#"AgentIAM::Action::"list""#,
                "resource": {
                    "type": "AgentIAM::Resource", "id": "pub-2",
                    "attrs": { "sensitivity": "public", "environment": "dev", "sandbox": false, "private": false }
                },
                "context": { "chain_depth": 1 }
            },
            {
                "action": r#"AgentIAM::Action::"delete""#,
                "resource": { "type": "AgentIAM::Resource", "id": "x" }
            }
        ]
    });
    let (status, json) = h.post("/v1/authorize/batch", body).await;
    assert_eq!(status, StatusCode::OK);
    let results = json["data"]["results"].as_array().unwrap();
    assert_eq!(results.len(), 3);
    assert_eq!(results[0]["decision"], "ALLOW");
    assert_eq!(results[1]["decision"], "ALLOW");
    assert_eq!(results[2]["decision"], "DENY"); // delete out of scope
}

// ═══════════════════════════════════════════════════════════════════
// Scenario 12: Budget Tracking + Exhaustion
// ═══════════════════════════════════════════════════════════════════

#[tokio::test]
async fn s12_budget_tracking() {
    let h = setup().await;

    // Create session with 1000 tokens
    let (sid, _token) = h
        .create_session_with(vec![r#"AgentIAM::Action::"read""#], None, 1000)
        .await;

    // Consume 900 → remaining 100, not exhausted
    let body = json!({ "tokens_used": 900, "cost_cents": 0, "calls_used": 0 });
    let (status, json) = h.post(&format!("/v1/sessions/{sid}/budget"), body).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["data"]["budget"]["remaining_tokens"], 100);
    assert_eq!(json["data"]["budget_exhausted"], false);

    // Consume 200 more → remaining ≤ 0, exhausted
    let body = json!({ "tokens_used": 200, "cost_cents": 0, "calls_used": 0 });
    let (status, json) = h.post(&format!("/v1/sessions/{sid}/budget"), body).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["data"]["budget_exhausted"], true);
    assert!(json["data"]["budget"]["remaining_tokens"].as_i64().unwrap() <= 0);
}

// ═══════════════════════════════════════════════════════════════════
// Scenario 13: Audit Query + Stats
// ═══════════════════════════════════════════════════════════════════

#[tokio::test]
async fn s13_audit_query_and_stats() {
    let h = setup().await;
    h.register_standard_entities().await;
    let (_sid, token) = h.create_standard_session().await;

    // Make 3 authorize calls: 2 ALLOW + 1 DENY (scope violation)
    let allow_body = json!({
        "session_token": token,
        "action": r#"AgentIAM::Action::"read""#,
        "resource": {
            "type": "AgentIAM::Resource", "id": "pub",
            "attrs": { "sensitivity": "public", "environment": "dev", "sandbox": false, "private": false }
        },
        "context": { "chain_depth": 1 }
    });
    let (s, j) = h.post("/v1/authorize", allow_body.clone()).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(j["data"]["decision"], "ALLOW");

    let (s, j) = h.post("/v1/authorize", allow_body).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(j["data"]["decision"], "ALLOW");

    // This one goes through Cedar (action is in scope: read), but resource is "secret" → guardrail DENY
    let deny_body = json!({
        "session_token": token,
        "action": r#"AgentIAM::Action::"read""#,
        "resource": {
            "type": "AgentIAM::Resource", "id": "classified",
            "attrs": { "sensitivity": "secret", "environment": "production", "sandbox": false, "private": true }
        },
        "context": { "chain_depth": 1 }
    });
    let (s, j) = h.post("/v1/authorize", deny_body).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(j["data"]["decision"], "DENY");

    // Flush audit logs (async batch writer)
    h.state.audit_logger.flush_and_close().await;

    // GET audit decisions
    let (status, json) = h.get("/v1/audit/decisions").await;
    assert_eq!(status, StatusCode::OK);
    let total = json["data"]["total"].as_i64().unwrap();
    assert!(total >= 3, "expected >= 3 audit records, got {total}");

    // GET audit stats
    let (status, json) = h.get("/v1/audit/stats").await;
    assert_eq!(status, StatusCode::OK);
    let total_decisions = json["data"]["total_decisions"].as_i64().unwrap();
    let allow_count = json["data"]["allow_count"].as_i64().unwrap();
    let deny_count = json["data"]["deny_count"].as_i64().unwrap();
    assert!(total_decisions >= 3);
    assert!(allow_count >= 2);
    assert!(deny_count >= 1);
}
