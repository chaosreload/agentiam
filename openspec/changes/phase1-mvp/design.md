# Phase 1 MVP — Technical Design

## Architecture

```
┌──────────────────────────────────────────────────────┐
│                 AgentIAM Server (Rust)                  │
│                                                        │
│  ┌────────────┐  ┌──────────────┐  ┌──────────────┐  │
│  │  REST API   │  │   Session    │  │    Audit     │  │
│  │  Handler    │  │   Manager    │  │    Logger    │  │
│  │             │  │  (JWT+Store) │  │   (SQLite)   │  │
│  └─────┬──────┘  └──────┬───────┘  └──────┬───────┘  │
│        │                │                  │           │
│        ▼                ▼                  ▼           │
│  ┌────────────────────────────────────────────────┐   │
│  │            Authorization Service                │   │
│  │  1. Validate session (JWT + scope)              │   │
│  │  2. Build Cedar Request                         │   │
│  │  3. Call Cedar Engine → ALLOW/DENY              │   │
│  │  4. Write audit log                             │   │
│  └────────────────────┬───────────────────────────┘   │
│                       │                                │
│                       ▼                                │
│  ┌────────────────────────────────────────────────┐   │
│  │          Cedar Engine (native Rust crate)        │   │
│  │  - cedar-policy = "4.10" (direct dependency)    │   │
│  │  - PolicySet, Authorizer, Entities — native API │   │
│  │  - Schema Validation via Validator              │   │
│  └────────────────────────────────────────────────┘   │
└──────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────┐
│                  Python SDK (agentiam)                 │
│  AgentIAM(endpoint) → check() / create_session()     │
│                        audit.query()                  │
└──────────────────────────────────────────────────────┘
```

## Technology Choices

| Component | Choice | Rationale |
|-----------|--------|-----------|
| **Language** | Rust | Cedar is Rust-native; zero FFI overhead, direct API access |
| **HTTP Server** | axum (tokio) | Async, ergonomic, tokio ecosystem |
| **Cedar** | `cedar-policy` crate (native) | Direct dependency, no FFI/WASM bridge needed |
| **Session tokens** | JWT (HS256 for MVP) | Industry standard, `jsonwebtoken` crate |
| **Session store** | DashMap (in-memory) + SQLite | Lock-free concurrent map + persistence |
| **Audit store** | SQLite via sqlx | Async, compile-time query checking |
| **Python SDK** | httpx-based thin client | Minimal deps, async-ready |
| **Config** | YAML + env vars | `config` + `serde` crates |
| **Logging** | tracing + tracing-subscriber | Structured, async-aware |
| **Error handling** | thiserror + anyhow | Ergonomic error types |

## Key Rust Crates

```toml
[dependencies]
cedar-policy = "4.10"       # Policy engine (NATIVE!)
axum = "0.8"                # HTTP framework
tokio = { version = "1", features = ["full"] }
serde = { version = "1", features = ["derive"] }
serde_json = "1"
jsonwebtoken = "9"          # JWT signing/verification
sqlx = { version = "0.8", features = ["runtime-tokio", "sqlite"] }
dashmap = "6"               # Concurrent HashMap
uuid = { version = "1", features = ["v4"] }
tracing = "0.1"
tracing-subscriber = "0.3"
config = "0.14"
thiserror = "2"
anyhow = "1"
chrono = { version = "0.4", features = ["serde"] }
tower-http = { version = "0.6", features = ["cors", "trace"] }
sha2 = "0.10"               # API Key hashing
rand = "0.8"                # Random key generation
```

## Directory Structure

```
agentiam/
├── Cargo.toml
├── src/
│   ├── main.rs                 # Server entry point
│   ├── config.rs               # Configuration loading
│   ├── models.rs               # Shared data models
│   ├── error.rs                # Global error types
│   ├── cedar/
│   │   ├── mod.rs
│   │   ├── engine.rs           # Cedar engine wrapper (native API)
│   │   └── entities.rs         # Entity store management
│   ├── auth/
│   │   ├── mod.rs
│   │   ├── service.rs          # Core authorization logic
│   │   └── context.rs          # Cedar Context construction
│   ├── session/
│   │   ├── mod.rs
│   │   ├── manager.rs          # Session CRUD + budget
│   │   └── jwt.rs              # JWT issue/verify
│   ├── token/
│   │   ├── mod.rs
│   │   ├── apikey.rs           # API Key auth
│   │   ├── oauth.rs            # OAuth 2.0 CC
│   │   └── middleware.rs       # Auth middleware (axum)
│   ├── audit/
│   │   ├── mod.rs
│   │   ├── logger.rs           # Async SQLite writer
│   │   └── query.rs            # Audit query + stats
│   └── api/
│       ├── mod.rs
│       ├── router.rs           # axum Router definition
│       ├── error.rs            # API error responses
│       ├── middleware.rs        # Request ID, logging
│       └── handlers/
│           ├── authorize.rs    # POST /v1/authorize
│           ├── sessions.rs     # Session CRUD
│           ├── entities.rs     # Entity CRUD
│           ├── policies.rs     # Policy operations
│           ├── audit.rs        # Audit queries
│           ├── auth.rs         # API Key + OAuth endpoints
│           └── health.rs       # GET /health
├── sdk/
│   └── python/                 # Python SDK (httpx)
├── policies/                   # Cedar policies
├── schemas/                    # Cedar schema
├── configs/
│   └── agentiam.yaml           # Server configuration
├── tests/
│   └── integration_test.rs     # End-to-end tests
├── Makefile
└── Dockerfile
```

## API Design

### POST /v1/check

```
Request:
{
  "session_token": "eyJ...",
  "action": "tool:web_search",
  "resource": {
    "url": "https://example.com",
    "sensitivity": "public"
  },
  "context": {                    // optional
    "chain_depth": 1,
    "ip": "10.0.0.1"
  }
}

Response (200):
{
  "decision": "ALLOW" | "DENY",
  "reason": "policy: research-agent-read",
  "diagnostics": {
    "policies_satisfied": ["research-agent-read"],
    "policies_denied": [],
    "errors": [],
    "evaluation_time_us": 42
  }
}
```

### POST /v1/sessions

```
Request:
{
  "delegator": "user:weichao",
  "agent": "agent:research-scout",
  "scope": ["tool:web_search", "tool:web_fetch", "tool:feishu_doc:read"],
  "ttl_seconds": 3600
}

Response (201):
{
  "session_id": "sess_abc123",
  "token": "eyJ...",
  "expires_at": "2026-04-10T13:00:00Z",
  "scope": ["tool:web_search", "tool:web_fetch", "tool:feishu_doc:read"]
}
```

### GET /v1/sessions

```
Response (200):
{
  "sessions": [
    {
      "session_id": "sess_abc123",
      "delegator": "user:weichao",
      "agent": "agent:research-scout",
      "scope": ["tool:web_search", "tool:web_fetch"],
      "created_at": "2026-04-10T12:00:00Z",
      "expires_at": "2026-04-10T13:00:00Z"
    }
  ]
}
```

### GET /v1/audit

```
Query params: agent, action, decision, from, to, limit, offset

Response (200):
{
  "records": [
    {
      "id": 1,
      "timestamp": "2026-04-10T12:01:00Z",
      "session_id": "sess_abc123",
      "principal": "agent:research-scout",
      "action": "tool:web_search",
      "resource": {"url": "https://example.com"},
      "decision": "ALLOW",
      "reason": "policy: research-agent-read",
      "latency_us": 42
    }
  ],
  "total": 150
}
```

### GET /health

```
Response (200):
{
  "status": "healthy",
  "version": "0.1.0",
  "cedar": {
    "policies_loaded": 12,
    "schema_valid": true
  },
  "sessions": {
    "active": 3
  },
  "audit": {
    "total_records": 1523
  }
}
```

## Cedar Integration Detail

### Entity Mapping

```
Authorization Request:
  principal = Agent::"research-scout"
  action = Action::"tool:web_search"
  resource = Resource::"https://example.com"
  context = { "chain_depth": 1, "session_valid": true, "remaining_budget": 500000 }

Entity Store (loaded at startup):
  - User::"weichao" { email: "...", role: "admin" } in [Group::"admins"]
  - Agent::"research-scout" { delegator: User::"weichao", banned: false } in [AgentGroup::"research"]
  - Tool::"web_search" { risk: "low", reversible: true } in [Service::"web"]
```

### Policy Loading Flow

```
1. Server starts
2. Load *.cedarschema from schemas/ directory
3. Validate schema
4. Load *.cedar from policies/ directory
5. Validate policies against schema
6. Build PolicySet
7. Load entities from entities.json (or API-registered)
8. Ready to serve check() requests
```

## Database Schema (SQLite via sqlx)

```sql
-- Sessions table
CREATE TABLE sessions (
    session_id TEXT PRIMARY KEY,
    delegator TEXT NOT NULL,
    agent TEXT NOT NULL,
    scope TEXT NOT NULL,          -- JSON array
    budget_max TEXT NOT NULL,     -- JSON {max_tokens, max_cost_cents, max_calls}
    budget_remaining TEXT NOT NULL, -- JSON {remaining_tokens, ...}
    max_chain_depth INTEGER NOT NULL DEFAULT 10,
    metadata TEXT,               -- JSON
    created_at TEXT NOT NULL,     -- ISO 8601
    expires_at TEXT NOT NULL,
    revoked INTEGER DEFAULT 0,
    revoked_at TEXT
);

-- Audit log table (append-only)
CREATE TABLE audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    session_id TEXT,
    principal TEXT NOT NULL,
    action TEXT NOT NULL,
    resource TEXT,                -- JSON
    context TEXT,                 -- JSON
    decision TEXT NOT NULL,       -- ALLOW | DENY
    reason TEXT,
    policies_evaluated INTEGER,
    latency_us INTEGER,
    FOREIGN KEY (session_id) REFERENCES sessions(session_id)
);

CREATE INDEX idx_audit_agent ON audit_log(principal, timestamp);
CREATE INDEX idx_audit_decision ON audit_log(decision, timestamp);
CREATE INDEX idx_audit_session ON audit_log(session_id);
```

## Testing Strategy

| Level | Scope | Tool |
|-------|-------|------|
| Unit | Cedar engine, JWT utils, session CRUD | `#[cfg(test)]` + `cargo test` |
| Integration | API endpoints with real Cedar + SQLite | axum::test + reqwest |
| E2E | Python SDK → REST API → Cedar → audit | pytest |
| Benchmark | Policy evaluation latency | criterion |
