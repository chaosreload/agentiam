# Phase 1 MVP — Delta Spec (Updated)

> 基于 Cedar Schema v0.2.0 + API v0.2.0 + Token Service v0.2.0

## ADDED Requirements

### Requirement: R1-MVP — Cedar Policy Engine (Core)

The system MUST load Cedar policies from `.cedar` files within the `AgentIAM` namespace and evaluate authorization requests.

#### Scenario: Load policies from file
- GIVEN a `schemas/agentiam.cedarschema` and a `policies/` directory with `.cedar` files
- WHEN the server starts
- THEN all policies are parsed, validated against the AgentIAM namespace schema, and loaded into a PolicySet

#### Scenario: Evaluate authorization request
- GIVEN a loaded PolicySet and entity store
- WHEN a request with principal (`AgentIAM::Agent::"research-scout"`), action (`AgentIAM::Action::"read"`), resource (`AgentIAM::Resource::"file-1"`), and context (SessionContext) is submitted
- THEN Cedar engine evaluates all matching policies and returns `{decision: ALLOW|DENY, diagnostics}`

#### Scenario: Entity store management
- GIVEN entities registered via `POST /v1/entities`
- WHEN entities include hierarchy (Agent in AgentGroup, User in UserGroup)
- THEN Cedar evaluates policies respecting entity hierarchy (`principal in AgentIAM::AgentGroup::"research"`)

#### Scenario: Policy hot-reload
- GIVEN policies updated on disk
- WHEN `POST /v1/policies/reload` is called
- THEN new policies replace old PolicySet atomically with zero downtime

---

### Requirement: R2-MVP — Session Management (Core)

The system MUST manage delegation sessions with JWT Session Tokens.

#### Scenario: Create session
- GIVEN delegator (User entity), agent (Agent entity), scope (action list), TTL, budget, max_chain_depth
- WHEN `POST /v1/sessions` is called
- THEN return a JWT Session Token with:
  - `typ: "session+jwt"`, `alg: "HS256"`
  - `sub`: Cedar entity UID of Agent
  - `delegator`: Cedar entity UID of User
  - `scope`: array of Cedar action UIDs
  - `budget`: initial budget values
  - `exp`: created_at + TTL
- AND session state is stored (in-memory + SQLite)

#### Scenario: Scope pre-check
- GIVEN session with scope `["AgentIAM::Action::\"read\"", "AgentIAM::Action::\"list\""]`
- WHEN `authorize()` is called with action `AgentIAM::Action::"delete"`
- THEN return DENY immediately with reason `"action_not_in_scope"` (before Cedar evaluation)

#### Scenario: Budget tracking
- GIVEN session with `max_tokens=1,000,000`
- WHEN `POST /v1/sessions/{id}/budget` reports `tokens_used=2500`
- THEN `remaining_tokens` decreases to 997,500
- WHEN `remaining_tokens` reaches 0
- THEN all subsequent `authorize()` calls return DENY via guardrail

#### Scenario: Session revocation
- GIVEN an active session
- WHEN `DELETE /v1/sessions/{id}` is called
- THEN the session is marked revoked
- AND all subsequent token validations fail with "session_revoked"

---

### Requirement: R3-MVP — Authorization API + Authentication

The system MUST provide REST API with API Key and OAuth 2.0 Client Credentials authentication.

#### Scenario: API Key authentication
- GIVEN a valid API Key (`ak_dev_xxx`)
- WHEN included as `Authorization: Bearer ak_dev_xxx`
- THEN the request is authenticated

#### Scenario: OAuth 2.0 Client Credentials
- GIVEN a registered OAuth client
- WHEN `POST /v1/oauth/token` with `grant_type=client_credentials`
- THEN return JWT Access Token with `typ: "at+jwt"` and requested scopes

#### Scenario: Authorization endpoint
- GIVEN a valid session token
- WHEN `POST /v1/authorize` with `{session_token, action, resource}`
- THEN return `{decision, diagnostics}` with HTTP 200 (decision in body, not status code)

#### Scenario: Batch authorization
- GIVEN a valid session token and 3 requests
- WHEN `POST /v1/authorize/batch`
- THEN return array of 3 decisions

#### Scenario: Entity management
- GIVEN entity data in Cedar JSON format
- WHEN `POST /v1/entities` with entities array
- THEN entities are upserted into the entity store
- AND immediately available for Cedar evaluation

#### Scenario: OAuth scope enforcement
- GIVEN an Access Token with scope `"agentiam:authorize"`
- WHEN the client calls `POST /v1/sessions` (requires `agentiam:session:create`)
- THEN return 403 with error code `"InsufficientScope"`

---

### Requirement: R7-MVP — Audit Logging

The system MUST log all authorization decisions to SQLite with query capabilities.

#### Scenario: Log every decision
- GIVEN any `authorize()` call completes
- THEN an audit record is inserted asynchronously:
  `id, timestamp, session_id, principal, action, resource_type, resource_id, resource_attrs, context, decision, reason, policies_evaluated, evaluation_time_us`

#### Scenario: Query with filters
- GIVEN audit records exist
- WHEN `GET /v1/audit/decisions?agent=research-scout&decision=DENY&limit=50`
- THEN return matching records with cursor pagination

#### Scenario: Statistics
- GIVEN audit records exist
- WHEN `GET /v1/audit/stats?from=2026-04-10T00:00:00Z`
- THEN return `{total_decisions, allow_count, deny_count, deny_by_reason, avg_evaluation_time_us, p99_evaluation_time_us}`
