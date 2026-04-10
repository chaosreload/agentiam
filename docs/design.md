# AgentIAM — AI Agent 场景权限管理系统设计

> 一句话定位：**AgentIAM — The authorization layer for AI Agents. Control what your agents can do, before they do it.**

## 一、为什么 AI Agent 需要专门的 IAM？

传统 IAM 是 "人 → 服务" 模型，但 Agent 场景有本质不同：

```
传统 IAM:    User → Action → Resource
Agent IAM:   User → Agent → Tool → Action → Resource
                ↑       ↑       ↑
              委托    自主决策   链式调用
```

### Agent 场景的 5 个独特挑战

1. **委托问题** — Agent 代表用户行事，但不应拥有用户全部权限（传统 IAM 无原生支持）
2. **工具控制** — Agent 能调用哪些 Tool/MCP Server（传统 IAM 无此概念）
3. **自主决策** — Agent 可能在无人监督下连续执行多步操作（传统 IAM 假设人在循环中）
4. **爆炸半径** — 一次 hallucination 可能触发危险操作链（传统 IAM 支持有限）
5. **上下文感知** — 同一个 Agent，不同对话/任务应有不同权限（传统 IAM 是静态策略）

## 二、核心概念模型

### Principal（身份）

| 类型 | 说明 |
|------|------|
| User | 人类用户 |
| Agent | AI Agent 实例 |
| Tool | MCP Server / Function |
| Service | 被调用的后端服务 |

### Delegation Chain（委托链）

```
User ──delegates──▶ Agent ──invokes──▶ Tool ──calls──▶ Service
```

### Session（会话）

| 字段 | 说明 |
|------|------|
| session_id | 唯一标识 |
| delegator | 委托人（User） |
| agent | 被委托的 Agent |
| scope | 本次会话允许的最大权限范围 |
| ttl | 会话有效期 |
| budget | 资源消耗上限（tokens / API calls / cost） |

### Policy 类型

| 策略类型 | 说明 |
|---------|------|
| AgentPolicy | Agent 自身能力边界 |
| DelegationPolicy | 用户→Agent 的委托策略 |
| ToolPolicy | Tool 级别的调用权限 |
| GuardrailPolicy | 安全护栏（不可覆盖） |
| SessionPolicy | 会话级动态策略 |

## 三、策略语言设计

基于 Cedar 扩展，增加 Agent 专属概念。

### 1. Agent 能力策略

```cedar
// 定义 "research-agent" 能做什么
permit(
  principal == Agent::"research-agent",
  action in [Tool::"web_search", Tool::"web_fetch", Tool::"read_file"],
  resource
) when {
  resource.sensitivity != "secret"
};
```

### 2. 委托策略

```cedar
// Agent 的权限不能超过委托人（weichao）的权限
permit(
  principal is Agent,
  action,
  resource
) when {
  principal.delegator == User::"weichao" &&
  principal.delegator in resource.allowed_users &&
  principal.session.scope has action
};
```

### 3. 护栏策略（最高优先级，不可覆盖）

```cedar
// Agent 永远不能删生产库或转账
forbid(
  principal is Agent,
  action in [Action::"delete_production_db", Action::"send_money"],
  resource
);

// 只能在沙箱执行代码
forbid(
  principal is Agent,
  action == Action::"execute_code",
  resource
) unless {
  resource.sandbox == true
};
```

### 4. 会话级策略

```cedar
// 这次对话只允许读 GitHub
permit(
  principal == Agent::"coding-agent",
  action in [Action::"gh_read", Action::"gh_list"],
  resource
) when {
  context.session_id == "sess_abc123" &&
  context.remaining_budget > 0
};
```

### 5. Tool 调用链策略

```cedar
// Agent 调用 exec 工具时，限制命令白名单
permit(
  principal is Agent,
  action == Tool::"exec",
  resource
) when {
  resource.command.matches("^(ls|cat|grep|find) ") &&
  context.chain_depth < 5
};
```

## 四、系统架构

```
┌─────────────────────────────────────────────────────────┐
│                    AgentIAM 架构                         │
│                                                         │
│  用户/开发者 ──▶ Agent Host ──▶ AgentIAM Gateway        │
│               (OpenClaw,       ┌─────────────────┐      │
│                LangChain,      │ Session Manager  │      │
│                CrewAI...)      │ Policy Engine    │      │
│                    │           │  (Cedar)         │      │
│              AgentIAM          │ Guardrail        │      │
│              SDK/Sidecar       │  Enforcer        │      │
│              ┌──────────┐      │ Audit Log +      │      │
│              │ check()  │◀────▶│  Budget Tracker  │      │
│              │delegate()│      └─────────────────┘      │
│              │ audit()  │                                │
│              └────┬─────┘                                │
│                   ▼                                      │
│              Tools / MCP / APIs                          │
└─────────────────────────────────────────────────────────┘
```

### 关键组件

| 组件 | 说明 |
|------|------|
| **Policy Engine** | 策略评估核心，基于 Cedar (Rust)，扩展 Agent 实体类型 |
| **Session Manager** | 管理委托会话，维护 scope + budget（Go/Rust + Redis） |
| **Guardrail Enforcer** | 不可覆盖的安全护栏，最高优先级（硬编码 + 策略双重保障） |
| **SDK/Sidecar** | Agent 框架接入点，一行代码集成（Python/TS/Go SDK） |
| **Audit Logger** | 全量决策日志，支持回放分析（PostgreSQL + S3） |
| **Budget Tracker** | Token/API 调用/成本追踪与限额（Redis + 异步统计） |

## 五、核心 API 设计

### Python SDK 用法

```python
from agentiam import AgentIAM

iam = AgentIAM(endpoint="http://localhost:8080")

# 1. 创建委托会话（用户 → Agent）
session = iam.create_session(
    delegator="user:weichao",
    agent="agent:research-scout",
    scope=["tool:web_search", "tool:web_fetch", "tool:feishu_doc:read"],
    ttl="1h",
    budget={"max_tokens": 1_000_000, "max_cost_usd": 5.0}
)

# 2. Agent 执行前检查权限
decision = iam.check(
    session=session.token,
    action="tool:exec",
    resource={"command": "rm -rf /", "sandbox": False}
)
# => Decision.DENY, reason: "guardrail: exec only allowed in sandbox"

# 3. 审计查询
iam.audit.query(
    agent="agent:research-scout",
    action="tool:*",
    decision="DENY",
    time_range="last_24h"
)

# 4. Human-in-the-loop 审批
decision = iam.check(
    session=session.token,
    action="tool:send_email",
    resource={"to": "client@example.com"}
)
# => Decision.PENDING_APPROVAL
# => 推送审批请求给用户（Slack/飞书/Web）
```

### Agent 框架集成配置示例

```yaml
# agent.yaml (OpenClaw 示例)
permissions:
  provider: agentiam
  endpoint: http://localhost:8080
  agent_id: research-scout
  default_scope:
    - "tool:web_search"
    - "tool:web_fetch"
    - "tool:read_file"
    - "tool:feishu_doc:read"
  guardrails:
    - no_production_writes
    - sandbox_only_exec
    - max_chain_depth: 10
  approval_channel: slack:#openclaw-1
```

## 六、AI Agent 专属功能

### 1. Delegation Scoping（委托范围缩小）

```
User 权限:    [A, B, C, D, E, F, G]
                    ↓ delegate(scope=[B,C,D])
Agent 权限:   [B, C, D]              ← 永远 ≤ User 权限
                    ↓ invoke tool
Tool 权限:    [C]                    ← 进一步缩小
```

类比 AWS 的 Permission Boundary，但应用在 Agent 委托链上。

### 2. Chain Depth Limiting（调用链深度限制）

```
Agent → Tool A → Tool B → Tool C → ...
  depth=0    1        2        3
                              ↑ 超过 max_depth? → DENY
```

防止 Agent 无限递归调用工具。

### 3. Budget Enforcement（预算强制执行）

会话级预算控制：

| 预算维度 | 说明 |
|---------|------|
| max_llm_tokens | LLM token 上限 |
| max_tool_calls | 工具调用次数上限 |
| max_cost_usd | 成本上限（美元） |
| max_wall_time | 最大执行时间 |

超预算 → 所有后续 `check()` 返回 DENY。

### 4. Conditional Human Approval（条件审批）

| 风险等级 | 处理方式 |
|---------|---------|
| 低风险 | 自动放行（读取类） |
| 中风险 | 自动放行但增强审计（写入类） |
| 高风险 | 需要人类审批（删除/转账/发邮件等） |

### 5. Tool Capability Registration（工具能力注册）

MCP Server 启动时向 AgentIAM 注册自己的能力：

```json
{
  "tool_id": "mcp:github",
  "capabilities": [
    {"action": "gh:read_repo", "risk": "low", "reversible": true},
    {"action": "gh:create_pr", "risk": "medium", "reversible": true},
    {"action": "gh:merge_pr", "risk": "high", "reversible": false},
    {"action": "gh:delete_repo", "risk": "critical", "reversible": false}
  ]
}
```

## 七、分阶段实施路线

### Phase 1：MVP（6 周）

- Cedar 集成 + Agent/Session 实体扩展
- Python SDK：`check()` / `create_session()`
- 基础委托策略评估
- SQLite 审计日志

🎯 目标：能用 SDK 对 1 个 Agent 做权限控制

### Phase 2：可用（6 周）

- MCP Gateway 模式（作为 Tool proxy 拦截所有调用）
- Budget tracking + enforcement
- Human approval workflow（Slack webhook）
- Guardrail 策略库（预置 20+ 通用护栏）

🎯 目标：可以接入 LangChain / CrewAI / OpenClaw

### Phase 3：生产级（8 周）

- Web Console（策略管理 + 审计查看 + 会话监控）
- OPAL 实时策略分发
- Multi-tenant 支持
- OpenTelemetry 集成

🎯 目标：可以作为独立产品发布

### Phase 4：生态（持续）

- Agent 框架原生集成（LangChain plugin / CrewAI middleware）
- MCP Protocol 扩展提案（权限声明标准）
- Policy-as-Code（Git 管理策略）

🎯 目标：成为 AI Agent 权限管理事实标准

## 八、差异化定位

**做什么：**

- ✅ 第一个 AI Agent 专用 IAM
- ✅ 借鉴 AWS IAM 概念，为 Agent 场景重新设计
- ✅ 与现有 IdP 集成，专注授权层
- ✅ Framework-agnostic，SDK + Sidecar + Gateway

**不做什么：**

- ❌ 又一个通用 IAM 系统
- ❌ 完整复刻 AWS IAM
- ❌ 替代 Keycloak / Auth0
- ❌ 锁定特定 Agent 框架

## 九、技术选型

| 组件 | 选型 | 理由 |
|------|------|------|
| 策略引擎 | Cedar（原生 Rust crate） | 直接依赖，零 FFI 开销，API 原生调用 |
| 身份管理 | Keycloak / Casdoor | 成熟的 SSO/OIDC/MFA |
| 策略分发 | OPAL | 实时推送策略+数据变更到分布式 PDP |
| 存储 | SQLite (MVP) → PostgreSQL | 策略、角色映射、审计日志 |
| 开发语言 | Rust (axum + tokio) | Cedar 原生语言，零集成成本，性能极致 |

## 十、竞品风险评估

- ✅ **市场真实存在** — MinIO 靠 S3 兼容成为 $1B 公司，IAM 兼容同样有需求
- ⚠️ **无人完整做过** — 说明难度大，但也说明机会空白
- ⚠️ **Cedar 可能成为事实标准** — AWS 开源 Cedar 可能就是在布局这件事
- ⚠️ **需要生态** — IAM 必须有服务来绑定，选 AI Agent 场景切入是正确策略
