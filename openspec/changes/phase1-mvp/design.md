# Phase 1 MVP — Technical Design

## Architecture

```
┌──────────────────────────────────────────────────────┐
│                  AgentIAM Server (Go)                  │
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
│  │          Cedar Engine (Rust via FFI/WASM)       │   │
│  │  - PolicySet (loaded from .cedar files)         │   │
│  │  - Entity Store (loaded from JSON)              │   │
│  │  - Schema Validation                            │   │
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
| **Server** | Go (with Rust FFI for Cedar) | Go for HTTP ergonomics + ecosystem; Rust for Cedar native performance |
| **Cedar integration** | cedar-policy crate via C FFI (cgo) | Direct Rust integration; alternatively cedar-wasm if FFI is too complex |
| **Session tokens** | JWT (HS256 for MVP) | Industry standard, stateless validation, easy to inspect |
| **Session store** | In-memory map + SQLite backup | Simple for MVP, Redis in Phase 2 |
| **Audit store** | SQLite | Zero-dependency, good enough for 1M+ records |
| **Python SDK** | httpx-based thin client | Minimal dependencies, async-ready |
| **Config** | YAML + env vars | Standard for Go services |

## Alternative: Cedar WASM vs FFI

If Rust FFI via cgo proves complex, fallback to:
1. **Cedar WASM**: Compile cedar-policy to WASM, call from Go via wazero runtime
2. **Cedar subprocess**: Run cedar-policy-cli as subprocess (highest latency, simplest integration)

Decision criteria: If FFI prototype takes > 3 days in Week 1, switch to WASM.

## Directory Structure

```
agentiam/
├── cmd/
│   └── agentiam-server/        # Server entry point
│       └── main.go
├── internal/
│   ├── auth/                   # Authorization service
│   │   ├── service.go          # Core auth logic
│   │   └── service_test.go
│   ├── cedar/                  # Cedar engine wrapper
│   │   ├── engine.go           # Cedar FFI/WASM bridge
│   │   ├── engine_test.go
│   │   └── bridge/             # Rust FFI code (if using cgo)
│   ├── session/                # Session management
│   │   ├── manager.go          # Create/validate/list sessions
│   │   ├── jwt.go              # JWT issuance and validation
│   │   └── manager_test.go
│   ├── audit/                  # Audit logging
│   │   ├── logger.go           # SQLite audit writer
│   │   ├── query.go            # Audit query logic
│   │   └── logger_test.go
│   └── api/                    # REST API handlers
│       ├── handler.go          # HTTP handlers
│       ├── middleware.go        # Auth, logging, CORS
│       └── router.go           # Route definitions
├── sdk/
│   └── python/
│       ├── agentiam/
│       │   ├── __init__.py
│       │   ├── client.py       # AgentIAM class
│       │   ├── models.py       # Decision, Session, AuditRecord
│       │   └── audit.py        # Audit query client
│       ├── pyproject.toml
│       └── tests/
├── policies/                   # Default policies (already exists)
├── schemas/                    # Cedar schemas (already exists)
├── configs/
│   └── agentiam.yaml           # Server configuration
├── go.mod
├── go.sum
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

## Database Schema (SQLite)

```sql
-- Sessions table
CREATE TABLE sessions (
    session_id TEXT PRIMARY KEY,
    delegator TEXT NOT NULL,
    agent TEXT NOT NULL,
    scope TEXT NOT NULL,          -- JSON array
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    expires_at DATETIME NOT NULL,
    revoked BOOLEAN DEFAULT FALSE
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
| Unit | Cedar engine wrapper, JWT utils, session CRUD | Go testing |
| Integration | API endpoints with real Cedar + SQLite | Go httptest |
| E2E | Python SDK → REST API → Cedar → audit | pytest |
| Benchmark | Policy evaluation latency | Go benchmark |
