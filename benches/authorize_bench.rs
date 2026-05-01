//! Week 4.3 — Performance benchmark for authorize endpoint
//!
//! Run with: cargo test --release --test authorize_bench
//! (This lives in tests/ as a pseudo-bench to avoid criterion dependency.)
//!
//! Actual file lives in benches/ but is compiled as a test binary via [[test]] in Cargo.toml.

use std::sync::{Arc, RwLock};
use std::time::Instant;

use axum::body::Body;
use axum::http::Request;
use http_body_util::BodyExt;
use serde_json::json;
use sqlx::sqlite::SqlitePoolOptions;
use tower::ServiceExt;

use agentiam::api::router::{AppState, build_router};
use agentiam::audit::logger::AuditLogger;
use agentiam::cedar::engine::CedarEngine;
use agentiam::cedar::entities::EntityStore;
use agentiam::config::AppConfig;
use agentiam::session::manager::SessionManager;
use agentiam::token::apikey;

const TEST_SECRET: &str = "bench-jwt-secret-week4-perf";

async fn setup_bench() -> (axum::Router, String) {
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

    let (key, hash) = apikey::create_api_key("bench");
    apikey::store_api_key(&db, "bench-key-id", "bench-key", &hash, "bench")
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

    // Register entities
    let app = build_router(state);
    let entities_body = json!({
        "entities": [
            {
                "type": "AgentIAM::User", "id": "alice",
                "attrs": { "email": "a@t.com", "role": "admin", "mfa_enabled": true, "suspended": false },
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
        .header("authorization", format!("Bearer {key}"))
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&entities_body).unwrap()))
        .unwrap();
    app.clone().oneshot(req).await.unwrap();

    // Create session
    let session_body = json!({
        "delegator": { "type": "AgentIAM::User", "id": "alice" },
        "agent": { "type": "AgentIAM::Agent", "id": "research-scout" },
        "scope": [r#"AgentIAM::Action::"read""#, r#"AgentIAM::Action::"list""#],
        "ttl_seconds": 3600,
        "budget": { "max_tokens": -1, "max_cost_cents": -1, "max_calls": -1 },
        "max_chain_depth": 5,
    });
    let req = Request::builder()
        .method("POST")
        .uri("/v1/sessions")
        .header("authorization", format!("Bearer {key}"))
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&session_body).unwrap()))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    let token = json["data"]["token"].as_str().unwrap().to_string();

    // Build the authorize request body as a reusable string
    let auth_body = json!({
        "session_token": token,
        "action": r#"AgentIAM::Action::"read""#,
        "resource": {
            "type": "AgentIAM::Resource", "id": "bench-doc",
            "attrs": { "sensitivity": "public", "environment": "development", "sandbox": false, "private": false }
        },
        "context": { "chain_depth": 1 }
    });
    let auth_bytes = serde_json::to_vec(&auth_body).unwrap();
    let auth_payload = String::from_utf8(auth_bytes).unwrap();

    (app, format!("{key}\n{auth_payload}"))
}

fn make_authorize_request(key: &str, auth_payload: &str) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri("/v1/authorize")
        .header("authorization", format!("Bearer {key}"))
        .header("content-type", "application/json")
        .body(Body::from(auth_payload.to_string()))
        .unwrap()
}

#[tokio::test]
async fn bench_authorize_concurrent() {
    let (app, setup_data) = setup_bench().await;
    let parts: Vec<&str> = setup_data.splitn(2, '\n').collect();
    let key = parts[0];
    let auth_payload = parts[1];

    const TOTAL_REQUESTS: usize = 100;

    // Warm up
    for _ in 0..5 {
        let req = make_authorize_request(key, auth_payload);
        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), axum::http::StatusCode::OK);
    }

    // Concurrent benchmark: 100 requests via tokio::spawn + join_all
    let mut handles = Vec::with_capacity(TOTAL_REQUESTS);
    let start = Instant::now();

    for _ in 0..TOTAL_REQUESTS {
        let app_clone = app.clone();
        let req = make_authorize_request(key, auth_payload);
        handles.push(tokio::spawn(async move {
            let t0 = Instant::now();
            let resp = app_clone.oneshot(req).await.unwrap();
            let latency = t0.elapsed();
            assert_eq!(resp.status(), axum::http::StatusCode::OK);
            latency
        }));
    }

    let results = futures::future::join_all(handles).await;
    let total_elapsed = start.elapsed();

    let mut latencies: Vec<f64> = results
        .into_iter()
        .map(|r| r.unwrap().as_secs_f64() * 1000.0) // ms
        .collect();
    latencies.sort_by(|a, b| a.partial_cmp(b).unwrap());

    let p50 = latencies[latencies.len() / 2];
    let p95 = latencies[(latencies.len() as f64 * 0.95) as usize];
    let p99 = latencies[(latencies.len() as f64 * 0.99) as usize];
    let throughput = TOTAL_REQUESTS as f64 / total_elapsed.as_secs_f64();

    eprintln!("\n═══════════════════════════════════════════");
    eprintln!(" Authorize Benchmark ({TOTAL_REQUESTS} concurrent requests)");
    eprintln!("═══════════════════════════════════════════");
    eprintln!("  p50:  {p50:.3} ms");
    eprintln!("  p95:  {p95:.3} ms");
    eprintln!("  p99:  {p99:.3} ms");
    eprintln!("  Throughput: {throughput:.0} req/s");
    eprintln!(
        "  Total wall time: {:.3} ms",
        total_elapsed.as_secs_f64() * 1000.0
    );
    eprintln!("═══════════════════════════════════════════\n");

    // Soft assertions — don't hard-fail (environment-dependent)
    if p95 > 10.0 {
        eprintln!("  WARNING: p95 > 10ms target ({p95:.3}ms)");
    }
    if throughput < 1000.0 {
        eprintln!("  WARNING: throughput < 1000 req/s ({throughput:.0})");
    }
}
