# Phase 1 MVP — Implementation Tasks

## Week 1: Project Setup + Cedar Integration

- [ ] **1.1** Initialize Go module (`go mod init github.com/chaosreload/agentiam`)
- [ ] **1.2** Set up directory structure (`cmd/`, `internal/`, `sdk/`, `configs/`)
- [ ] **1.3** Create Makefile with targets: `build`, `test`, `run`, `lint`
- [ ] **1.4** Research Cedar-Go integration approach (FFI vs WASM vs subprocess)
- [ ] **1.5** Implement Cedar engine wrapper (`internal/cedar/engine.go`)
  - [ ] Load `.cedarschema` file
  - [ ] Load `.cedar` policy files
  - [ ] Validate policies against schema
  - [ ] Expose `Evaluate(principal, action, resource, context) → Decision` method
- [ ] **1.6** Write unit tests for Cedar engine wrapper
  - [ ] Test permit evaluation
  - [ ] Test forbid overrides permit
  - [ ] Test default deny (no matching policy)
  - [ ] Test schema validation (reject ill-typed policies)
- [ ] **1.7** Benchmark Cedar evaluation latency (target: < 5ms P99)

## Week 2: Policy Loading + Entity Management

- [ ] **2.1** Implement policy file loader (watch `policies/` directory)
  - [ ] Parse all `.cedar` files in directory
  - [ ] Atomic policy reload (swap PolicySet)
  - [ ] Log policy count and validation results
- [ ] **2.2** Implement entity store (`internal/cedar/entities.go`)
  - [ ] Load entities from JSON file
  - [ ] Support entity hierarchy (User in Group, Agent in AgentGroup)
  - [ ] API to add/update entities at runtime
- [ ] **2.3** Extend Cedar schema for AgentIAM types
  - [ ] Validate `schemas/agentiam.cedarschema` works with Cedar engine
  - [ ] Test with example policies from `policies/examples/`
- [ ] **2.4** Implement `POST /v1/policies/reload` endpoint
- [ ] **2.5** Write integration tests: load policies → evaluate → assert decision

## Week 3: Session Management

- [ ] **3.1** Implement JWT utility (`internal/session/jwt.go`)
  - [ ] Issue JWT with claims: session_id, delegator, agent, scope, exp
  - [ ] Validate JWT signature and expiration
  - [ ] Extract session data from token
  - [ ] Use HS256 for MVP (configurable secret)
- [ ] **3.2** Implement Session Manager (`internal/session/manager.go`)
  - [ ] `CreateSession(delegator, agent, scope, ttl) → Session`
  - [ ] `ValidateSession(token) → Session`
  - [ ] `ListSessions() → []Session`
  - [ ] `RevokeSession(session_id)`
  - [ ] In-memory store with optional SQLite persistence
- [ ] **3.3** Implement scope enforcement
  - [ ] Pre-check: is requested action in session scope?
  - [ ] Return fast DENY before Cedar evaluation if out of scope
- [ ] **3.4** Implement `POST /v1/sessions` endpoint
- [ ] **3.5** Implement `GET /v1/sessions` endpoint
- [ ] **3.6** Implement `DELETE /v1/sessions/{id}` endpoint (revoke)
- [ ] **3.7** Write tests for session lifecycle (create → use → expire → deny)

## Week 4: REST API + Authorization Service

- [ ] **4.1** Implement Authorization Service (`internal/auth/service.go`)
  - [ ] `Check(sessionToken, action, resource, context) → Decision`
  - [ ] Flow: validate session → check scope → build Cedar request → evaluate → return decision
  - [ ] Attach diagnostics (policies evaluated, satisfied, errors)
- [ ] **4.2** Implement REST API router (`internal/api/router.go`)
  - [ ] `POST /v1/check`
  - [ ] `POST /v1/sessions`
  - [ ] `GET /v1/sessions`
  - [ ] `DELETE /v1/sessions/{id}`
  - [ ] `GET /health`
  - [ ] `POST /v1/policies/reload`
- [ ] **4.3** Implement middleware
  - [ ] Request logging (structured JSON)
  - [ ] CORS
  - [ ] Request ID
  - [ ] Panic recovery
- [ ] **4.4** Implement server configuration (`configs/agentiam.yaml`)
  - [ ] Listen address
  - [ ] JWT secret
  - [ ] Policy directory path
  - [ ] Schema file path
  - [ ] Entity file path
  - [ ] SQLite path
- [ ] **4.5** Implement `cmd/agentiam-server/main.go` (server entry point)
- [ ] **4.6** Write integration tests: full HTTP request → Cedar → response
- [ ] **4.7** Add Dockerfile (multi-stage build)

## Week 5: Python SDK + Audit Logging

- [ ] **5.1** Implement audit logger (`internal/audit/logger.go`)
  - [ ] SQLite table creation (auto-migrate)
  - [ ] `Log(record AuditRecord)` — async write with channel buffer
  - [ ] Record: timestamp, session_id, principal, action, resource, decision, reason, latency_us
- [ ] **5.2** Implement audit query (`internal/audit/query.go`)
  - [ ] Filter by: agent, action, decision, time range
  - [ ] Pagination (limit + offset)
  - [ ] Order by timestamp desc
- [ ] **5.3** Implement `GET /v1/audit` endpoint
- [ ] **5.4** Wire audit logging into Authorization Service (log every check() result)
- [ ] **5.5** Implement Python SDK (`sdk/python/agentiam/`)
  - [ ] `AgentIAM(endpoint)` — client initialization
  - [ ] `check(session, action, resource)` → `Decision`
  - [ ] `create_session(delegator, agent, scope, ttl)` → `Session`
  - [ ] `audit.query(agent, decision, time_range)` → `List[AuditRecord]`
  - [ ] `health()` → `HealthStatus`
- [ ] **5.6** Write Python SDK tests (pytest + httpx mock)
- [ ] **5.7** Set up `pyproject.toml` for pip packaging

## Week 6: Integration Tests + Demo + Documentation

- [ ] **6.1** Write end-to-end test
  - [ ] Start server with example policies
  - [ ] Python SDK: create session → check (allow) → check (deny) → query audit
  - [ ] Verify all audit records
- [ ] **6.2** Create demo script (`demo/run_demo.sh`)
  - [ ] Start server
  - [ ] Create session for "research-scout" agent
  - [ ] Run 5 authorization checks (mix of allow/deny)
  - [ ] Query and display audit log
  - [ ] Print summary
- [ ] **6.3** Create demo Python script (`demo/demo.py`)
  - [ ] Same flow as bash demo but using Python SDK
- [ ] **6.4** Write `docs/quickstart.md`
  - [ ] Installation
  - [ ] Configuration
  - [ ] First policy
  - [ ] First session
  - [ ] First check
- [ ] **6.5** Write `docs/api.md` — full REST API reference
- [ ] **6.6** Update README.md with quickstart badge, install instructions
- [ ] **6.7** Performance benchmark report
  - [ ] check() latency distribution (P50, P95, P99)
  - [ ] Concurrent session handling (100 sessions)
  - [ ] Audit log write throughput
- [ ] **6.8** Tag v0.1.0 release
