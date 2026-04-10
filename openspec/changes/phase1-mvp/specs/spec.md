# Phase 1 MVP — Delta Spec

## ADDED Requirements

### Requirement: R1-MVP — Cedar Policy Engine (Core)

The system MUST load Cedar policies from `.cedar` files and evaluate authorization requests.

#### Scenario: Load policies from file
- GIVEN a directory containing `.cedar` policy files and a `.cedarschema` file
- WHEN the server starts
- THEN all policies are parsed, validated against the schema, and loaded into a PolicySet

#### Scenario: Evaluate authorization request
- GIVEN a loaded PolicySet and entity store
- WHEN a request {principal, action, resource, context} is submitted
- THEN Cedar engine evaluates all matching policies
- AND returns {decision: ALLOW|DENY, diagnostics: {reasons, errors}}

#### Scenario: Policy reload
- GIVEN policies have been updated on disk
- WHEN a reload is triggered (API call or file watcher)
- THEN the new policies replace the old PolicySet atomically

---

### Requirement: R2-MVP — Session Management (Core)

The system MUST manage delegation sessions with JWT tokens.

#### Scenario: Create session
- GIVEN delegator (User ID), agent (Agent ID), scope (action list), TTL
- WHEN POST /v1/sessions is called
- THEN return a JWT containing {session_id, delegator, agent, scope, exp}

#### Scenario: Validate session token
- GIVEN a JWT session token
- WHEN it is included in a check() request
- THEN the server validates signature, expiration, and extracts session data

#### Scenario: Session scope check
- GIVEN a session with scope ["tool:web_search", "tool:web_fetch"]
- WHEN check() is called with action "tool:exec"
- THEN DENY immediately with reason "action_not_in_scope" (before Cedar evaluation)

#### Scenario: List active sessions
- GIVEN multiple active sessions exist
- WHEN GET /v1/sessions is called
- THEN return all non-expired sessions with metadata

---

### Requirement: R3-MVP — Authorization Check API

The system MUST provide REST API and Python SDK for authorization checks.

#### Scenario: REST check endpoint
- GIVEN the server is running at :8080
- WHEN POST /v1/check with body:
  ```json
  {
    "session_token": "eyJ...",
    "action": "tool:web_search",
    "resource": {"url": "https://example.com", "sensitivity": "public"}
  }
  ```
- THEN return:
  ```json
  {
    "decision": "ALLOW",
    "reason": "policy: research-agent-read",
    "diagnostics": {"policies_satisfied": ["research-agent-read"], "policies_evaluated": 5}
  }
  ```

#### Scenario: Python SDK check
- GIVEN `from agentiam import AgentIAM`
- WHEN `iam.check(session=token, action="tool:exec", resource={"sandbox": False})`
- THEN return `Decision(decision="DENY", reason="guardrail: sandbox_only_exec")`

#### Scenario: Health check
- GIVEN the server is running
- WHEN GET /health is called
- THEN return 200 with {"status": "healthy", "policies_loaded": N, "active_sessions": M}

---

### Requirement: R7-MVP — Basic Audit Logging

The system MUST log all authorization decisions to SQLite.

#### Scenario: Log every decision
- GIVEN any check() call completes
- THEN an audit record is inserted:
  - timestamp, session_id, principal (agent), action, resource (JSON), decision, reason, latency_us

#### Scenario: Query audit log
- GIVEN audit records exist
- WHEN GET /v1/audit?agent=research-scout&decision=DENY&limit=50
- THEN return matching records ordered by timestamp descending

#### Scenario: Python SDK audit query
- GIVEN `iam.audit.query(agent="research-scout", decision="DENY", time_range="last_24h")`
- THEN return a list of AuditRecord objects
