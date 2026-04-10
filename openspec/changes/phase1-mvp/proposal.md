# Phase 1: MVP — Core Authorization Engine

## Summary

Build the minimum viable AgentIAM that can authorize a single Agent's tool invocations using Cedar policies, with session-based delegation and basic audit logging.

## Goal

**能用 Python SDK 对 1 个 Agent 做权限控制。**

Specifically, a developer can:
1. Start the AgentIAM server
2. Define Cedar policies for their Agent
3. Create a delegation session (User → Agent)
4. Call `iam.check()` before every tool invocation
5. Get ALLOW/DENY decisions with reasons
6. Query audit logs to see what happened

## Scope

### In Scope (Phase 1)
- **R1**: Cedar policy engine integration (eval + validate)
- **R2**: Session management (create + JWT token + TTL + scope)
- **R3**: Authorization check API (REST + Python SDK)
- **R7**: Basic audit logging (SQLite, query by agent/time)

### Out of Scope (Phase 2+)
- R4: Guardrail enforcement (hardcoded basic guardrails only in Phase 1)
- R5: Full delegation chain + chain depth limiting
- R6: Budget tracking and enforcement
- R8: Human-in-the-loop approval
- R9: Tool capability registration
- R10: YAML config integration, sidecar mode

## Timeline

| Week | Focus |
|------|-------|
| Week 1 | Project setup + Cedar SDK integration + entity schema |
| Week 2 | Policy loading + evaluation API + basic tests |
| Week 3 | Session management (JWT issuance + validation + scope) |
| Week 4 | REST API server + authorization check endpoint |
| Week 5 | Python SDK + audit logging (SQLite) |
| Week 6 | Integration tests + demo + documentation |

## Success Criteria

1. `POST /v1/check` returns correct ALLOW/DENY based on Cedar policies
2. Sessions enforce scope and TTL
3. All decisions are logged to SQLite
4. Python SDK works: `iam.check()`, `iam.create_session()`, `iam.audit.query()`
5. End-to-end demo: Agent → check → allow/deny → audit log

## Risks & Mitigations

| Risk | Impact | Mitigation |
|------|--------|-----------|
| Cedar Rust FFI complexity | High | Use cedar-policy crate directly if building in Rust; or use WASM bridge for Go |
| Performance overhead | Medium | Benchmark early (Week 2), optimize if needed |
| Schema design changes | Low | Keep schema minimal, extend in Phase 2 |

## Non-functional Requirements

- Authorization check latency: < 5ms P99 (relaxed from 1ms for MVP)
- Support up to 100 concurrent sessions
- SQLite audit log: up to 1M records before archival needed
