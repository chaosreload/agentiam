# AgentIAM — Main Specification

> The authorization layer for AI Agents. Control what your agents can do, before they do it.

## System Overview

AgentIAM is a purpose-built IAM system for AI Agent scenarios, built on Cedar policy engine. It provides delegation-aware, session-scoped, budget-enforced authorization for AI agents invoking tools and services.

## Requirements

### Requirement: R1 — Policy Engine (Cedar Integration)

The system MUST integrate Cedar policy engine as the core authorization decision engine.

#### Scenario: Basic policy evaluation
- GIVEN a PolicySet loaded from Cedar policy files
- WHEN an authorization request (principal, action, resource, context) is submitted
- THEN the engine evaluates all matching policies and returns ALLOW or DENY

#### Scenario: Forbid overrides permit
- GIVEN a permit policy and a forbid policy both matching the same request
- THEN the decision MUST be DENY (forbid always wins)

#### Scenario: Default deny
- GIVEN no policies match the request
- THEN the decision MUST be DENY (implicit deny)

#### Scenario: Custom Cedar Schema
- GIVEN a Cedar Schema defining Agent, Tool, Session, and Service entity types
- WHEN policies reference these custom types
- THEN the validator MUST accept well-typed policies and reject ill-typed ones

#### Scenario: Policy evaluation performance
- GIVEN a PolicySet with up to 1000 policies
- WHEN evaluating a single authorization request
- THEN the evaluation latency MUST be < 1ms (P99)

---

### Requirement: R2 — Session Management

The system MUST support delegation sessions where a User delegates scoped permissions to an Agent.

#### Scenario: Create delegation session
- GIVEN a User, an Agent, a scope (list of allowed actions), TTL, and budget
- WHEN create_session() is called
- THEN a JWT session token is issued containing session_id, delegator, agent, scope, ttl, and budget

#### Scenario: Session expiration
- GIVEN a session with TTL of 1 hour
- WHEN the session is used after 1 hour
- THEN all check() calls MUST return DENY with reason "session_expired"

#### Scenario: Scope enforcement
- GIVEN a session with scope ["tool:web_search", "tool:web_fetch"]
- WHEN check() is called with action "tool:exec"
- THEN the decision MUST be DENY with reason "action_not_in_scope"

#### Scenario: Budget exhaustion
- GIVEN a session with max_tokens budget of 1,000,000
- WHEN cumulative token usage reaches 1,000,000
- THEN all subsequent check() calls MUST return DENY with reason "budget_exhausted"

---

### Requirement: R3 — Authorization Check API

The system MUST provide a check() API as the primary authorization entry point.

#### Scenario: Allow decision
- GIVEN a valid session and a matching permit policy with no forbid
- WHEN check(session, action, resource) is called
- THEN return Decision.ALLOW with diagnostics listing the satisfied policies

#### Scenario: Deny decision
- GIVEN a request matching a forbid policy
- WHEN check(session, action, resource) is called
- THEN return Decision.DENY with reason and the forbid policy id

#### Scenario: Pending approval decision
- GIVEN a request matching a permit policy but the action requires human approval
- WHEN check(session, action, resource) is called
- THEN return Decision.PENDING_APPROVAL with an approval_request_id

#### Scenario: REST API
- GIVEN the AgentIAM server is running
- WHEN POST /v1/check is called with JSON body {session_token, action, resource}
- THEN return JSON {decision, reason, diagnostics}

#### Scenario: SDK call
- GIVEN the Python SDK is initialized with endpoint
- WHEN iam.check(session=token, action="tool:exec", resource={...}) is called
- THEN return a Decision object with decision, reason, and diagnostics attributes

---

### Requirement: R4 — Guardrail Enforcement

The system MUST support unforgeable guardrail policies that cannot be overridden.

#### Scenario: Guardrail forbid overrides all permits
- GIVEN a guardrail forbid policy for "delete_production_db"
- AND a permit policy granting admin full access
- WHEN an admin Agent requests delete_production_db
- THEN the decision MUST be DENY

#### Scenario: Sandbox enforcement
- GIVEN a guardrail requiring sandbox=true for code execution
- WHEN an Agent requests execute_code on a resource with sandbox=false
- THEN the decision MUST be DENY with reason "guardrail: sandbox_only_exec"

#### Scenario: Banned agent enforcement
- GIVEN a guardrail forbidding all actions for banned agents
- WHEN a banned Agent (banned=true) requests any action
- THEN the decision MUST be DENY regardless of other permits

#### Scenario: Custom guardrails
- GIVEN a user-defined guardrail Cedar policy
- WHEN the policy is loaded as a guardrail
- THEN it MUST be evaluated with the same forbid-overrides-permit semantics

---

### Requirement: R5 — Delegation Chain

The system MUST enforce that Agent permissions never exceed the delegator's permissions.

#### Scenario: Permission boundary
- GIVEN User has permissions [A, B, C, D]
- AND Agent is delegated scope [B, C]
- WHEN Agent requests action A
- THEN the decision MUST be DENY (not in delegated scope)

#### Scenario: Tool-level narrowing
- GIVEN Agent has scope [B, C]
- AND Tool invocation narrows to [C]
- WHEN the Tool attempts action B
- THEN the decision MUST be DENY

#### Scenario: Chain depth limiting
- GIVEN max_chain_depth is set to 5
- WHEN a request arrives with chain_depth=6
- THEN the decision MUST be DENY with reason "max_chain_depth_exceeded"

---

### Requirement: R6 — Budget Tracking

The system MUST track and enforce resource consumption budgets per session.

#### Scenario: Token counting
- GIVEN a session with max_tokens=1,000,000
- WHEN the session has consumed 999,000 tokens
- AND a new request reports 2,000 tokens used
- THEN the budget is exceeded and subsequent check() calls return DENY

#### Scenario: Cost tracking
- GIVEN a session with max_cost_usd=5.00
- WHEN cumulative cost reaches $5.00
- THEN subsequent check() calls return DENY with reason "budget_exhausted"

#### Scenario: Call counting
- GIVEN a session with max_tool_calls=100
- WHEN the 101st tool call is attempted
- THEN check() returns DENY with reason "max_tool_calls_exceeded"

#### Scenario: Budget query
- GIVEN an active session
- WHEN budget status is queried
- THEN return remaining tokens, cost, calls, and wall time

---

### Requirement: R7 — Audit Logging

The system MUST record all authorization decisions for audit and compliance.

#### Scenario: Decision logging
- GIVEN any check() call
- THEN an audit record MUST be created with: timestamp, session_id, principal, action, resource, decision, reason, policies_evaluated

#### Scenario: Query by agent
- GIVEN audit records exist
- WHEN querying by agent="research-scout" and decision="DENY"
- THEN return all matching audit records ordered by timestamp

#### Scenario: Query by time range
- GIVEN audit records exist
- WHEN querying with time_range="last_24h"
- THEN return only records from the past 24 hours

#### Scenario: Immutability
- GIVEN an audit record has been written
- THEN it MUST NOT be modifiable or deletable through the API

---

### Requirement: R8 — Human-in-the-Loop Approval

The system MUST support human approval workflows for high-risk operations.

#### Scenario: Approval trigger
- GIVEN an action marked as requires_approval=true
- WHEN check() is called for that action
- THEN return PENDING_APPROVAL and create an approval request

#### Scenario: Approval notification
- GIVEN an approval request is created
- THEN a notification MUST be sent to the configured channel (Slack/Feishu webhook)

#### Scenario: Approval grant
- GIVEN a pending approval request
- WHEN the delegator approves it
- THEN subsequent check() for the same action+resource returns ALLOW

#### Scenario: Approval timeout
- GIVEN an approval request with default timeout of 5 minutes
- WHEN 5 minutes pass without approval
- THEN the request is auto-denied

---

### Requirement: R9 — Tool Capability Registration

The system MUST support MCP Server/Tool capability registration.

#### Scenario: Register capabilities
- GIVEN an MCP Server starting up
- WHEN it calls register_tool(tool_id, capabilities)
- THEN the capabilities (action, risk, reversible) are stored and available for policy evaluation

#### Scenario: Auto-approval policy
- GIVEN a tool capability with risk="low" and reversible=true
- THEN check() for that capability SHOULD auto-allow (no human approval needed)

#### Scenario: High-risk auto-escalation
- GIVEN a tool capability with risk="critical" and reversible=false
- THEN check() for that capability MUST return PENDING_APPROVAL

---

### Requirement: R10 — SDK and Integration

The system MUST provide SDKs and integration points for Agent frameworks.

#### Scenario: Python SDK
- GIVEN the Python SDK is installed (pip install agentiam)
- WHEN AgentIAM(endpoint=...) is instantiated
- THEN check(), create_session(), and audit.query() methods are available

#### Scenario: YAML configuration
- GIVEN an Agent framework configuration file
- WHEN the agentiam provider is configured with endpoint, agent_id, default_scope
- THEN the framework integrates with AgentIAM transparently

#### Scenario: Sidecar mode
- GIVEN AgentIAM runs as a sidecar container
- WHEN an Agent in the same pod calls localhost:8080/v1/check
- THEN authorization is performed with < 1ms network overhead

## Technical Constraints

- Policy engine: Cedar (Rust) — embedded via FFI or subprocess
- Primary language: Go or Rust
- Storage: SQLite (MVP) → PostgreSQL (production)
- Session state: In-memory + optional Redis
- API: REST (JSON), gRPC (future)
- Auth: JWT session tokens
- Audit: Append-only SQLite/PostgreSQL table → S3 archival (future)

## Phased Delivery

| Phase | Scope | Timeline |
|-------|-------|----------|
| Phase 1 (MVP) | R1 + R2 + R3 + R7 (basic) | 6 weeks |
| Phase 2 (Usable) | R4 + R5 + R6 + R8 + R9 | 6 weeks |
| Phase 3 (Production) | Web Console + Multi-tenant + OPAL | 8 weeks |
| Phase 4 (Ecosystem) | Framework plugins + MCP standard | Ongoing |
