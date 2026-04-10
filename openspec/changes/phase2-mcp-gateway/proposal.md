# Phase 2: MCP Gateway — Tool Proxy + Budget + Approval

## Summary

Build the MCP Gateway layer that sits between Agents and Tools/MCP Servers, intercepting every tool invocation for authorization, budget enforcement, and human approval workflows.

## Goal

**Agent 框架调用 Tool 时，透明经过 AgentIAM 授权检查，无需修改 Tool 代码。**

## Scope

### In Scope (Phase 2)
- **R4**: Full guardrail enforcement (custom guardrail policies)
- **R5**: Delegation chain + chain depth limiting
- **R6**: Budget tracking and enforcement (real-time)
- **R8**: Human-in-the-loop approval (Slack/Feishu webhook)
- **R9**: Tool capability registration
- **MCP Gateway**: Transparent proxy for MCP protocol
- **OAuth 2.0**: Auth Code + PKCE, OIDC Token Exchange
- **RS256**: JWT signing with JWKS endpoint

### Out of Scope (Phase 3+)
- Web Console
- Multi-tenant
- OPAL real-time policy distribution
- mTLS / AWS SigV4

## Architecture

```
Agent Framework                MCP Gateway              MCP Server / Tool
      │                           │                           │
      ├── MCP tool_call ────────▶│                           │
      │                          │ 1. Extract session token   │
      │                          │ 2. Map tool → Cedar entity │
      │                          │ 3. POST /v1/authorize      │
      │                          │    (internal)              │
      │                          │                            │
      │                          │ ALLOW?                     │
      │                          │ ├─ Yes → forward ─────────▶│
      │                          │ │        call              │
      │                          │ │◀─ response ─────────────┤
      │                          │ │  deduct budget           │
      │◀── response ─────────────│ │  audit log               │
      │                          │ │                           │
      │                          │ ├─ No → return error       │
      │◀── DENY error ──────────│ │                           │
      │                          │ │                           │
      │                          │ └─ PENDING_APPROVAL        │
      │                          │    → notify Slack/Feishu    │
      │                          │    → wait/timeout           │
      │◀── PENDING/TIMEOUT ──────│                            │
```

### Gateway 部署模式

| 模式 | 说明 | 适用场景 |
|------|------|---------|
| **Sidecar** | 与 Agent 同 Pod | Kubernetes |
| **Standalone Proxy** | 独立服务，Agent 配置 proxy endpoint | 通用 |
| **SDK Middleware** | 嵌入 Agent 框架（Python/TS decorator） | 最轻量 |

### MCP Protocol Interception

Gateway 实现 MCP Server 接口（对 Agent 来说是一个 MCP Server），内部转发到真实 MCP Server：

```
Agent ──MCP──▶ Gateway (fake MCP Server) ──MCP──▶ Real MCP Server
                    │
              AgentIAM authorize
              Budget deduct
              Audit log
```

### Tool Capability Registration

```
POST /v1/tools/register
{
  "tool_id": "mcp:github",
  "mcp_endpoint": "http://localhost:3001",
  "capabilities": [
    {"action": "gh:read_repo", "risk": "low", "reversible": true},
    {"action": "gh:create_pr", "risk": "medium", "reversible": true},
    {"action": "gh:merge_pr", "risk": "high", "reversible": false},
    {"action": "gh:delete_repo", "risk": "critical", "reversible": false}
  ]
}
```

### Human Approval Flow

```
1. check() returns PENDING_APPROVAL
2. Gateway sends webhook to Slack/Feishu:
   "[AgentIAM] 🔔 research-scout wants to merge PR #42
    Action: gh:merge_pr | Risk: high | Irreversible
    [Approve] [Deny] [Approve + Remember]"
3. User clicks Approve/Deny
4. Gateway receives callback → update approval status
5. If approved: retry check() with approval_status="approved" → ALLOW
6. If denied or timeout (5min): DENY
```

## Timeline

| Week | Focus |
|------|-------|
| Week 7-8 | MCP Gateway proxy + tool registration |
| Week 9-10 | Budget real-time tracking + chain depth |
| Week 11 | Human approval workflow (Slack/Feishu) |
| Week 12 | OAuth 2.0 Auth Code + PKCE + OIDC + RS256 |

## Success Criteria

1. Agent calls Tool through Gateway, authorization is transparent
2. Budget is deducted in real-time, exhaustion blocks further calls
3. High-risk tool calls trigger Slack notification for approval
4. Tool capabilities auto-registered and affect authorization decisions
