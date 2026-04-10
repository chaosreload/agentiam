# AgentIAM API 设计文档

> 版本：v0.2.0 | 更新日期：2026-04-10
> 基于 Cedar Schema v0.2.0

## 设计原则

1. **AWS IAM 风格** — API 命名和概念对标 AWS IAM/STS，社区零学习成本
2. **RESTful** — 标准 HTTP 方法 + JSON，Phase 2 加 gRPC
3. **最小权限** — API 本身也需要认证（API Key 或 JWT）
4. **幂等** — GET/PUT/DELETE 幂等，POST 非幂等但带 idempotency key
5. **一致的错误格式** — 所有错误返回统一结构

## 基础约定

### Base URL

```
http://localhost:8080/v1
```

### 认证

Phase 1 MVP 使用 API Key（Header）：
```
Authorization: Bearer <api_key>
```

Phase 2+ 支持 mTLS 和 OIDC token。

### 通用响应格式

**成功：**
```json
{
  "request_id": "req_abc123",
  "data": { ... }
}
```

**错误：**
```json
{
  "request_id": "req_abc123",
  "error": {
    "code": "SessionExpired",
    "message": "Session sess_xyz has expired",
    "details": {
      "session_id": "sess_xyz",
      "expired_at": "2026-04-10T13:00:00Z"
    }
  }
}
```

### 错误码

| HTTP | Code | 说明 |
|------|------|------|
| 400 | InvalidRequest | 请求格式错误 |
| 401 | Unauthorized | API Key 无效或缺失 |
| 403 | AccessDenied | 授权拒绝（Cedar 评估结果为 DENY） |
| 404 | NotFound | 资源不存在 |
| 409 | Conflict | 资源已存在（幂等冲突） |
| 422 | ValidationError | 策略/Schema 验证失败 |
| 429 | RateLimited | 请求频率超限 |
| 500 | InternalError | 服务端错误 |

---

## 核心 API：Authorization

### POST /v1/authorize

**核心端点**——评估一个授权请求。对标 AWS `sts:AssumeRole` + Cedar `is_authorized`。

**Request:**
```json
{
  "session_token": "eyJhbGciOiJIUzI1NiJ9...",
  "action": "AgentIAM::Action::\"read\"",
  "resource": {
    "type": "AgentIAM::Resource",
    "id": "production-db",
    "attrs": {
      "sensitivity": "confidential",
      "environment": "production",
      "sandbox": false,
      "private": true
    }
  },
  "context": {
    "chain_depth": 1,
    "request_ip": "10.0.0.1"
  }
}
```

**说明：**
- `session_token` — 服务端自动提取 session 信息，构造完整的 Cedar Context（合并 session 数据 + 请求级 context）
- `resource.attrs` — 可选。如果实体已在 entity store 中注册，可以只传 type+id；否则传 attrs 做 inline entity
- `context` — 请求级上下文（chain_depth、request_ip 等），会与 session context 合并

**Response (200) — ALLOW:**
```json
{
  "request_id": "req_abc123",
  "data": {
    "decision": "ALLOW",
    "diagnostics": {
      "reason": "Matched policy: rbac-research-agent-read",
      "policies_satisfied": ["rbac-research-agent-read"],
      "policies_denied": [],
      "policies_evaluated": 22,
      "errors": [],
      "evaluation_time_us": 42
    }
  }
}
```

**Response (200) — DENY:**
```json
{
  "request_id": "req_abc123",
  "data": {
    "decision": "DENY",
    "diagnostics": {
      "reason": "Matched guardrail: guardrail-no-production-delete",
      "policies_satisfied": [],
      "policies_denied": ["guardrail-no-production-delete"],
      "policies_evaluated": 22,
      "errors": [],
      "evaluation_time_us": 38
    }
  }
}
```

**Response (200) — DENY (scope):**
```json
{
  "request_id": "req_abc123",
  "data": {
    "decision": "DENY",
    "diagnostics": {
      "reason": "Action not in session scope",
      "scope_violation": true,
      "requested_action": "AgentIAM::Action::\"delete\"",
      "allowed_scope": ["AgentIAM::Action::\"read\"", "AgentIAM::Action::\"list\""]
    }
  }
}
```

> **设计说明**：决策始终返回 200。HTTP status 表示 API 调用是否成功，不表示授权结果。`decision` 字段是授权结果。这和 AWS Verified Permissions 的 `IsAuthorized` API 设计一致。

### POST /v1/authorize/batch

**批量授权**——一次检查多个请求。对标 AWS `BatchIsAuthorized`。

**Request:**
```json
{
  "session_token": "eyJ...",
  "requests": [
    {
      "action": "AgentIAM::Action::\"read\"",
      "resource": { "type": "AgentIAM::Resource", "id": "file-1" }
    },
    {
      "action": "AgentIAM::Action::\"write\"",
      "resource": { "type": "AgentIAM::Resource", "id": "file-1" }
    },
    {
      "action": "AgentIAM::Action::\"delete\"",
      "resource": { "type": "AgentIAM::Resource", "id": "file-1" }
    }
  ]
}
```

**Response (200):**
```json
{
  "request_id": "req_abc123",
  "data": {
    "results": [
      { "decision": "ALLOW", "diagnostics": { "reason": "..." } },
      { "decision": "ALLOW", "diagnostics": { "reason": "..." } },
      { "decision": "DENY", "diagnostics": { "reason": "..." } }
    ]
  }
}
```

---

## Session API

### POST /v1/sessions

**创建委托会话**——用户将权限委托给 Agent。对标 AWS `sts:AssumeRole`。

**Request:**
```json
{
  "delegator": {
    "type": "AgentIAM::User",
    "id": "weichao"
  },
  "agent": {
    "type": "AgentIAM::Agent",
    "id": "research-scout"
  },
  "scope": [
    "AgentIAM::Action::\"read\"",
    "AgentIAM::Action::\"list\"",
    "AgentIAM::Action::\"search\"",
    "AgentIAM::Action::\"invoke_tool\""
  ],
  "ttl_seconds": 3600,
  "budget": {
    "max_tokens": 1000000,
    "max_cost_cents": 500,
    "max_calls": 1000
  },
  "max_chain_depth": 5,
  "metadata": {
    "purpose": "Daily research scan",
    "channel": "slack:#openclaw-research"
  }
}
```

**Response (201):**
```json
{
  "request_id": "req_abc123",
  "data": {
    "session_id": "sess_a1b2c3d4",
    "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
    "delegator": "AgentIAM::User::\"weichao\"",
    "agent": "AgentIAM::Agent::\"research-scout\"",
    "scope": ["AgentIAM::Action::\"read\"", "..."],
    "budget": {
      "max_tokens": 1000000,
      "max_cost_cents": 500,
      "max_calls": 1000,
      "remaining_tokens": 1000000,
      "remaining_cost_cents": 500,
      "remaining_calls": 1000
    },
    "max_chain_depth": 5,
    "created_at": "2026-04-10T12:00:00Z",
    "expires_at": "2026-04-10T13:00:00Z"
  }
}
```

### GET /v1/sessions

**列出活跃会话。**

**Query params:**

| Param | Type | Description |
|-------|------|-------------|
| agent | string | 按 Agent ID 过滤 |
| delegator | string | 按委托人 ID 过滤 |
| status | string | `active` \| `expired` \| `revoked` (default: `active`) |
| limit | int | 分页大小 (default: 50, max: 200) |
| cursor | string | 分页游标 |

**Response (200):**
```json
{
  "request_id": "req_abc123",
  "data": {
    "sessions": [
      {
        "session_id": "sess_a1b2c3d4",
        "delegator": "AgentIAM::User::\"weichao\"",
        "agent": "AgentIAM::Agent::\"research-scout\"",
        "scope": ["..."],
        "budget": {
          "max_tokens": 1000000,
          "remaining_tokens": 850000,
          "max_cost_cents": 500,
          "remaining_cost_cents": 420,
          "max_calls": 1000,
          "remaining_calls": 873
        },
        "status": "active",
        "created_at": "2026-04-10T12:00:00Z",
        "expires_at": "2026-04-10T13:00:00Z"
      }
    ],
    "next_cursor": "cur_xyz789",
    "total": 3
  }
}
```

### GET /v1/sessions/{session_id}

**获取会话详情。**

**Response (200):** 同上单个 session 对象。

### DELETE /v1/sessions/{session_id}

**吊销会话。** 吊销后所有后续 authorize 调用返回 DENY。

**Response (200):**
```json
{
  "request_id": "req_abc123",
  "data": {
    "session_id": "sess_a1b2c3d4",
    "status": "revoked",
    "revoked_at": "2026-04-10T12:30:00Z"
  }
}
```

### POST /v1/sessions/{session_id}/budget

**更新会话预算消耗。** Agent 框架在每次工具调用后上报消耗。

**Request:**
```json
{
  "tokens_used": 2500,
  "cost_cents": 3,
  "calls_used": 1
}
```

**Response (200):**
```json
{
  "request_id": "req_abc123",
  "data": {
    "session_id": "sess_a1b2c3d4",
    "budget": {
      "remaining_tokens": 847500,
      "remaining_cost_cents": 417,
      "remaining_calls": 872
    },
    "budget_exhausted": false
  }
}
```

---

## Entity API

### POST /v1/entities

**注册/更新实体。** 用于注册 User、Agent、Tool、Resource。

**Request:**
```json
{
  "entities": [
    {
      "type": "AgentIAM::Agent",
      "id": "research-scout",
      "attrs": {
        "delegator": { "__entity": { "type": "AgentIAM::User", "id": "weichao" } },
        "framework": "openclaw",
        "version": "1.0",
        "model": "claude-4",
        "risk_level": "low",
        "banned": false,
        "sandbox_only": false
      },
      "parents": [
        { "type": "AgentIAM::AgentGroup", "id": "research-agents" }
      ]
    }
  ]
}
```

**Response (200):**
```json
{
  "request_id": "req_abc123",
  "data": {
    "created": 0,
    "updated": 1,
    "entities": [
      { "type": "AgentIAM::Agent", "id": "research-scout", "status": "updated" }
    ]
  }
}
```

### GET /v1/entities

**列出实体。**

**Query params:**

| Param | Type | Description |
|-------|------|-------------|
| type | string | 实体类型过滤 (e.g. `AgentIAM::Agent`) |
| parent | string | 按父实体过滤 |
| limit | int | 分页大小 |
| cursor | string | 分页游标 |

### GET /v1/entities/{type}/{id}

**获取单个实体。**

**Response (200):**
```json
{
  "request_id": "req_abc123",
  "data": {
    "type": "AgentIAM::Agent",
    "id": "research-scout",
    "attrs": { "..." },
    "parents": [
      { "type": "AgentIAM::AgentGroup", "id": "research-agents" }
    ]
  }
}
```

### DELETE /v1/entities/{type}/{id}

**删除实体。**

---

## Policy API

### GET /v1/policies

**列出已加载的策略。**

**Response (200):**
```json
{
  "request_id": "req_abc123",
  "data": {
    "policies": [
      {
        "id": "guardrail-banned-agent",
        "effect": "forbid",
        "source_file": "policies/guardrails.cedar",
        "annotations": { "id": "guardrail-banned-agent" }
      },
      {
        "id": "rbac-admin-full-access",
        "effect": "permit",
        "source_file": "policies/examples/basic-rbac.cedar",
        "annotations": { "id": "rbac-admin-full-access" }
      }
    ],
    "total": 22,
    "schema_valid": true
  }
}
```

### POST /v1/policies/validate

**验证策略文本（不加载）。** 用于 CI/CD 中策略变更的预检查。

**Request:**
```json
{
  "policy_text": "permit(principal == AgentIAM::Agent::\"new-agent\", action, resource);",
  "validate_against_schema": true
}
```

**Response (200) — 验证通过：**
```json
{
  "request_id": "req_abc123",
  "data": {
    "valid": true,
    "policies_parsed": 1,
    "warnings": []
  }
}
```

**Response (200) — 验证失败：**
```json
{
  "request_id": "req_abc123",
  "data": {
    "valid": false,
    "errors": [
      {
        "message": "attribute `nonexistent` on entity type `AgentIAM::Agent` not found",
        "location": { "line": 1, "column": 45 }
      }
    ]
  }
}
```

### POST /v1/policies/reload

**热重载策略文件。** 从磁盘重新加载所有 `.cedar` 文件。

**Response (200):**
```json
{
  "request_id": "req_abc123",
  "data": {
    "reloaded": true,
    "policies_loaded": 22,
    "schema_valid": true,
    "reload_time_ms": 12
  }
}
```

---

## Audit API

### GET /v1/audit/decisions

**查询授权决策日志。**

**Query params:**

| Param | Type | Description |
|-------|------|-------------|
| agent | string | Agent ID 过滤 |
| action | string | Action 过滤（支持通配符 `read*`） |
| decision | string | `ALLOW` \| `DENY` |
| session_id | string | 会话 ID |
| from | datetime | 开始时间 (ISO 8601) |
| to | datetime | 结束时间 |
| limit | int | 分页大小 (default: 50, max: 500) |
| cursor | string | 分页游标 |

**Response (200):**
```json
{
  "request_id": "req_abc123",
  "data": {
    "records": [
      {
        "id": "aud_001",
        "timestamp": "2026-04-10T12:01:00.042Z",
        "session_id": "sess_a1b2c3d4",
        "principal": "AgentIAM::Agent::\"research-scout\"",
        "action": "AgentIAM::Action::\"read\"",
        "resource": {
          "type": "AgentIAM::Resource",
          "id": "production-db"
        },
        "decision": "DENY",
        "reason": "Matched guardrail: guardrail-no-secret-access",
        "policies_evaluated": 22,
        "evaluation_time_us": 38,
        "context_snapshot": {
          "chain_depth": 1,
          "remaining_tokens": 999000,
          "session_valid": true
        }
      }
    ],
    "next_cursor": "cur_002",
    "total": 1523
  }
}
```

### GET /v1/audit/decisions/{id}

**获取单条审计记录。**

### GET /v1/audit/stats

**审计统计摘要。**

**Query params:** `from`, `to`, `agent`, `session_id`

**Response (200):**
```json
{
  "request_id": "req_abc123",
  "data": {
    "period": { "from": "2026-04-10T00:00:00Z", "to": "2026-04-10T23:59:59Z" },
    "total_decisions": 1523,
    "allow_count": 1200,
    "deny_count": 323,
    "deny_by_reason": {
      "scope_violation": 120,
      "guardrail": 85,
      "no_matching_permit": 68,
      "budget_exhausted": 30,
      "session_expired": 20
    },
    "avg_evaluation_time_us": 45,
    "p99_evaluation_time_us": 180,
    "top_denied_actions": [
      { "action": "AgentIAM::Action::\"delete\"", "count": 85 },
      { "action": "AgentIAM::Action::\"execute\"", "count": 62 }
    ],
    "top_denied_agents": [
      { "agent": "research-scout", "count": 150 },
      { "agent": "coding-agent", "count": 173 }
    ]
  }
}
```

---

## Health & Operational API

### GET /health

**健康检查（无认证）。**

**Response (200):**
```json
{
  "status": "healthy",
  "version": "0.1.0",
  "uptime_seconds": 86400,
  "components": {
    "cedar_engine": {
      "status": "healthy",
      "policies_loaded": 22,
      "schema_valid": true,
      "last_reload": "2026-04-10T12:00:00Z"
    },
    "session_store": {
      "status": "healthy",
      "active_sessions": 3
    },
    "audit_store": {
      "status": "healthy",
      "total_records": 15230,
      "storage_backend": "sqlite"
    }
  }
}
```

### GET /v1/config

**获取当前服务配置（脱敏）。**

**Response (200):**
```json
{
  "request_id": "req_abc123",
  "data": {
    "policy_directory": "policies/",
    "schema_file": "schemas/agentiam.cedarschema",
    "session_ttl_default": 3600,
    "session_ttl_max": 86400,
    "budget_defaults": {
      "max_tokens": -1,
      "max_cost_cents": -1,
      "max_calls": -1
    },
    "max_chain_depth_default": 10,
    "audit_backend": "sqlite",
    "auth_mode": "api_key"
  }
}
```

---

## Tool Registration API (Phase 2 预留)

### POST /v1/tools/register

**MCP Server 启动时注册工具能力。**

**Request:**
```json
{
  "tool_id": "web-search",
  "display_name": "Web Search",
  "description": "Search the web using Brave API",
  "service": "AgentIAM::Service::\"web\"",
  "capabilities": [
    {
      "action": "search",
      "risk": "low",
      "reversible": true,
      "requires_approval": false
    }
  ]
}
```

**Response (201):**
```json
{
  "request_id": "req_abc123",
  "data": {
    "tool": {
      "type": "AgentIAM::Tool",
      "id": "web-search",
      "registered": true,
      "capabilities_count": 1
    }
  }
}
```

---

## Approval API (Phase 2 预留)

### GET /v1/approvals

**列出待审批请求。**

### POST /v1/approvals/{id}/approve

**批准请求。**

### POST /v1/approvals/{id}/deny

**拒绝请求。**

---

## Python SDK 接口设计

```python
from agentiam import AgentIAM, Decision

# ─── 初始化 ───
iam = AgentIAM(
    endpoint="http://localhost:8080",
    api_key="ak_xxx",                  # 或从环境变量 AGENTIAM_API_KEY
)

# ─── 创建委托会话 ───
session = iam.create_session(
    delegator="weichao",               # User ID
    agent="research-scout",            # Agent ID
    scope=["read", "list", "search", "invoke_tool"],
    ttl=3600,                          # seconds
    budget={
        "max_tokens": 1_000_000,
        "max_cost_cents": 500,
        "max_calls": 1000,
    },
    max_chain_depth=5,
    metadata={"purpose": "Daily research scan"},
)
# session.token → JWT string
# session.session_id → "sess_a1b2c3d4"
# session.expires_at → datetime

# ─── 授权检查 ───
decision = iam.authorize(
    session=session.token,
    action="read",
    resource={"type": "AgentIAM::Resource", "id": "production-db"},
    context={"chain_depth": 1},
)
# decision.decision → "ALLOW" | "DENY"
# decision.reason → "Matched policy: ..."
# decision.is_allowed → True | False

# 简写形式
if iam.is_allowed(session.token, "read", resource_id="file-1"):
    do_read()

# ─── 批量授权 ───
results = iam.authorize_batch(
    session=session.token,
    requests=[
        {"action": "read", "resource_id": "file-1"},
        {"action": "write", "resource_id": "file-1"},
        {"action": "delete", "resource_id": "file-1"},
    ],
)
# results → [Decision(ALLOW), Decision(ALLOW), Decision(DENY)]

# ─── 上报预算消耗 ───
iam.report_usage(
    session_id=session.session_id,
    tokens_used=2500,
    cost_cents=3,
    calls_used=1,
)

# ─── 审计查询 ───
records = iam.audit.query(
    agent="research-scout",
    decision="DENY",
    from_time="2026-04-10T00:00:00Z",
    limit=50,
)
# records → [AuditRecord(...), ...]

stats = iam.audit.stats(
    agent="research-scout",
    from_time="2026-04-10T00:00:00Z",
)
# stats.total_decisions → 1523
# stats.deny_count → 323

# ─── 实体管理 ───
iam.entities.upsert([
    {
        "type": "AgentIAM::Agent",
        "id": "new-agent",
        "attrs": {"delegator": {"__entity": {"type": "AgentIAM::User", "id": "weichao"}}, ...},
        "parents": [{"type": "AgentIAM::AgentGroup", "id": "research-agents"}],
    }
])

agent = iam.entities.get("AgentIAM::Agent", "research-scout")

# ─── 策略操作 ───
result = iam.policies.validate("permit(principal, action, resource);")
# result.valid → True

iam.policies.reload()

policies = iam.policies.list()
# policies → [PolicyInfo(...), ...]

# ─── 会话管理 ───
sessions = iam.sessions.list(agent="research-scout", status="active")
session_detail = iam.sessions.get("sess_a1b2c3d4")
iam.sessions.revoke("sess_a1b2c3d4")

# ─── 健康检查 ───
health = iam.health()
# health.status → "healthy"
# health.components.cedar_engine.policies_loaded → 22
```

### SDK 数据模型

```python
@dataclass
class Decision:
    decision: str           # "ALLOW" | "DENY"
    reason: str
    diagnostics: dict
    is_allowed: bool        # convenience: decision == "ALLOW"

@dataclass
class Session:
    session_id: str
    token: str              # JWT
    delegator: str
    agent: str
    scope: list[str]
    budget: BudgetStatus
    max_chain_depth: int
    created_at: datetime
    expires_at: datetime
    status: str             # "active" | "expired" | "revoked"

@dataclass
class BudgetStatus:
    max_tokens: int
    remaining_tokens: int
    max_cost_cents: int
    remaining_cost_cents: int
    max_calls: int
    remaining_calls: int
    budget_exhausted: bool

@dataclass
class AuditRecord:
    id: str
    timestamp: datetime
    session_id: str
    principal: str
    action: str
    resource: dict
    decision: str
    reason: str
    evaluation_time_us: int

@dataclass
class AuditStats:
    total_decisions: int
    allow_count: int
    deny_count: int
    deny_by_reason: dict
    avg_evaluation_time_us: int
    p99_evaluation_time_us: int
```

---

## API 端点汇总

### Phase 1 (MVP)

| Method | Path | 说明 |
|--------|------|------|
| `POST` | `/v1/authorize` | 🔑 核心：授权检查 |
| `POST` | `/v1/authorize/batch` | 批量授权检查 |
| `POST` | `/v1/sessions` | 创建委托会话 |
| `GET` | `/v1/sessions` | 列出会话 |
| `GET` | `/v1/sessions/{id}` | 会话详情 |
| `DELETE` | `/v1/sessions/{id}` | 吊销会话 |
| `POST` | `/v1/sessions/{id}/budget` | 上报预算消耗 |
| `POST` | `/v1/entities` | 注册/更新实体 |
| `GET` | `/v1/entities` | 列出实体 |
| `GET` | `/v1/entities/{type}/{id}` | 实体详情 |
| `DELETE` | `/v1/entities/{type}/{id}` | 删除实体 |
| `GET` | `/v1/policies` | 列出策略 |
| `POST` | `/v1/policies/validate` | 验证策略 |
| `POST` | `/v1/policies/reload` | 热重载策略 |
| `GET` | `/v1/audit/decisions` | 查询审计日志 |
| `GET` | `/v1/audit/decisions/{id}` | 审计记录详情 |
| `GET` | `/v1/audit/stats` | 审计统计 |
| `GET` | `/health` | 健康检查 |
| `GET` | `/v1/config` | 服务配置 |

### Phase 2 (预留)

| Method | Path | 说明 |
|--------|------|------|
| `POST` | `/v1/tools/register` | 工具能力注册 |
| `GET` | `/v1/approvals` | 列出待审批 |
| `POST` | `/v1/approvals/{id}/approve` | 批准 |
| `POST` | `/v1/approvals/{id}/deny` | 拒绝 |

---

## 与 AWS API 的对应关系

| AgentIAM | AWS 对标 |
|----------|---------|
| `POST /v1/authorize` | Verified Permissions `IsAuthorized` / IAM 策略评估 |
| `POST /v1/authorize/batch` | Verified Permissions `BatchIsAuthorized` |
| `POST /v1/sessions` | STS `AssumeRole` |
| `DELETE /v1/sessions/{id}` | 类似 STS token revocation |
| `POST /v1/entities` | Verified Permissions Entity Store |
| `GET /v1/policies` | IAM `ListPolicies` |
| `POST /v1/policies/validate` | IAM `SimulateCustomPolicy` |
| `GET /v1/audit/decisions` | CloudTrail |
