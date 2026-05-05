//! Integration tests for OAuth HTTP endpoints.

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
use agentiam::token::{apikey, oauth};

const TEST_SECRET: &str = "oauth-http-test-jwt-secret-32chr";

struct Harness {
    app: axum::Router,
    key: String,
}

impl Harness {
    fn auth(&self) -> String {
        format!("Bearer {}", self.key)
    }

    async fn post_json(&self, uri: &str, body: Value) -> (StatusCode, Value) {
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

    async fn post_form(&self, uri: &str, form_body: &str) -> (StatusCode, Value) {
        let req = Request::builder()
            .method("POST")
            .uri(uri)
            .header("content-type", "application/x-www-form-urlencoded")
            .body(Body::from(form_body.to_string()))
            .unwrap();
        let resp = self.app.clone().oneshot(req).await.unwrap();
        let status = resp.status();
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        (status, serde_json::from_slice(&bytes).unwrap())
    }

    /// Register an OAuth client via the API and return (client_id, client_secret).
    async fn register_client(&self, name: &str, scopes: Vec<&str>) -> (String, String) {
        let body = json!({ "name": name, "scopes": scopes });
        let (status, json) = self.post_json("/v1/oauth/clients", body).await;
        assert_eq!(status, StatusCode::CREATED);
        let cid = json["data"]["client_id"].as_str().unwrap().to_string();
        let cs = json["data"]["client_secret"].as_str().unwrap().to_string();
        (cid, cs)
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
    oauth::ensure_table(&db).await.unwrap();

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
        app: build_router(state),
        key,
    }
}

// ─── Tests ───────────────────────────────────────────────────────────

#[tokio::test]
async fn test_oauth_register_and_list() {
    let h = setup().await;
    let (cid, secret) = h
        .register_client("my-app", vec!["authorize", "sessions:read"])
        .await;
    assert!(cid.starts_with("iam_"));
    assert!(secret.starts_with("secret_"));

    let (status, json) = h.get("/v1/oauth/clients").await;
    assert_eq!(status, StatusCode::OK);
    let clients = json["data"]["clients"].as_array().unwrap();
    assert_eq!(clients.len(), 1);
    assert_eq!(clients[0]["client_id"], cid);
    assert_eq!(clients[0]["name"], "my-app");
    // Secret hash must not appear
    assert!(clients[0].get("client_secret_hash").is_none());
    assert!(clients[0].get("client_secret").is_none());
}

#[tokio::test]
async fn test_oauth_register_unauthorized() {
    let h = setup().await;
    let req = Request::builder()
        .method("POST")
        .uri("/v1/oauth/clients")
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::to_vec(&json!({"name":"x","scopes":["authorize"]})).unwrap(),
        ))
        .unwrap();
    let resp = h.app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_oauth_delete_then_list_shows_revoked() {
    let h = setup().await;
    let (cid, _) = h.register_client("del-app", vec!["authorize"]).await;

    let (status, json) = h.delete(&format!("/v1/oauth/clients/{cid}")).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["data"]["revoked"], true);

    let (_, json) = h.get("/v1/oauth/clients").await;
    let clients = json["data"]["clients"].as_array().unwrap();
    assert_eq!(clients[0]["revoked"], true);
}

#[tokio::test]
async fn test_oauth_delete_nonexistent() {
    let h = setup().await;
    let (status, json) = h.delete("/v1/oauth/clients/iam_nonexistent").await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(json["error"]["code"], "NotFound");
}

#[tokio::test]
async fn test_oauth_token_success() {
    let h = setup().await;
    let (cid, secret) = h
        .register_client("token-app", vec!["authorize", "sessions:read"])
        .await;

    let form = format!(
        "grant_type=client_credentials&client_id={}&client_secret={}&scope=authorize",
        cid, secret
    );
    let (status, json) = h.post_form("/v1/oauth/token", &form).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["token_type"], "Bearer");
    assert_eq!(json["expires_in"], 3600);
    assert_eq!(json["scope"], "authorize");
    assert!(json["access_token"].as_str().unwrap().len() > 10);
}

#[tokio::test]
async fn test_oauth_token_invalid_client() {
    let h = setup().await;
    let form =
        "grant_type=client_credentials&client_id=iam_bad&client_secret=secret_bad&scope=authorize";
    let (status, json) = h.post_form("/v1/oauth/token", form).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(json["error"], "invalid_client");
}

#[tokio::test]
async fn test_oauth_token_revoked_client() {
    let h = setup().await;
    let (cid, secret) = h.register_client("rev-app", vec!["authorize"]).await;
    h.delete(&format!("/v1/oauth/clients/{cid}")).await;

    let form = format!(
        "grant_type=client_credentials&client_id={}&client_secret={}",
        cid, secret
    );
    let (status, json) = h.post_form("/v1/oauth/token", &form).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(json["error"], "invalid_client");
}

#[tokio::test]
async fn test_oauth_token_scope_escalation() {
    let h = setup().await;
    let (cid, secret) = h.register_client("esc-app", vec!["authorize"]).await;

    let form = format!(
        "grant_type=client_credentials&client_id={}&client_secret={}&scope=admin",
        cid, secret
    );
    let (status, json) = h.post_form("/v1/oauth/token", &form).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(json["error"], "invalid_scope");
}

#[tokio::test]
async fn test_oauth_token_unsupported_grant() {
    let h = setup().await;
    let form = "grant_type=authorization_code&client_id=x&client_secret=y";
    let (status, json) = h.post_form("/v1/oauth/token", form).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(json["error"], "unsupported_grant_type");
}

#[tokio::test]
async fn test_oauth_token_missing_fields() {
    let h = setup().await;
    let form = "grant_type=client_credentials";
    let (status, json) = h.post_form("/v1/oauth/token", form).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(json["error"], "invalid_request");
}
