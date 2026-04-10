# AgentIAM Cedar Schema 设计文档

> 版本：v0.2.0 | 更新日期：2026-04-10
> Schema 文件：[`schemas/agentiam.cedarschema`](../schemas/agentiam.cedarschema)

## 设计决策

### 1. Session 数据 → Context（不是 Entity）

| 方案 | 优点 | 缺点 |
|------|------|------|
| **Session as Context** ✅ | 每次请求携带最新状态；无需维护实体存储；budget 实时反映 | 服务端需要构造 context |
| Session as Entity | 可在策略中直接引用 `Session::"xxx"` | 需要实时同步 budget 到实体存储；过期处理复杂 |

**决策：Session 放在 Context。** 原因：session 的 budget、chain_depth 每次请求都在变，放在 context 最自然——服务端构造 context 传入 Cedar，不需要额外的实体同步。

### 2. 委托关系 → Agent 的 `delegator` 属性

```
Agent::"research-scout" {
    delegator: User::"weichao",    ← 实体引用
    ...
}
```

在策略中可以直接写：
```cedar
when { principal.delegator == User::"weichao" }
when { principal.delegator.role == "admin" }
when { principal.delegator.suspended == true }
```

这比把委托关系放在 Context 或单独的 Delegation Entity 更直观。

### 3. Action 分组

使用 Cedar 的 action group 特性，便于策略编写：

```
readActions ──── read, list, search
writeActions ─── write, create, update
dangerousActions ── delete, execute, send_email, send_money
toolActions ──── invoke_tool, configure_tool
adminActions ─── manage_policy, manage_session, view_audit, configure_tool
```

策略中可以写：
```cedar
action in [AgentIAM::Action::"readActions"]    // 匹配所有读操作
action in [AgentIAM::Action::"dangerousActions"] // 匹配所有危险操作
```

### 4. Namespace: `AgentIAM`

所有类型放在 `AgentIAM` namespace 下，避免与其他 Cedar 应用冲突。策略中引用：
- `AgentIAM::User::"alice"`
- `AgentIAM::Action::"read"`
- `AgentIAM::Resource::"my-file"`

## 实体类型一览

### Principal Types（谁在请求？）

```
┌──────────────────┐
│  Organization    │
│  plan, max_agents│
└────────┬─────────┘
         │ in
┌────────┴─────────┐     ┌──────────────┐
│  UserGroup       │     │  AgentGroup   │
│  description     │     │  description  │
└────────┬─────────┘     │  max_chain_   │
         │ in            │   depth       │
┌────────┴─────────┐     └──────┬───────┘
│  User            │            │ in
│  email           │     ┌──────┴───────┐
│  role            │◄────│  Agent       │
│  mfa_enabled     │ ref │  delegator   │──▶ User
│  suspended       │     │  framework   │
└──────────────────┘     │  risk_level  │
                         │  banned      │
                         │  sandbox_only│
                         └──────────────┘
```

| Entity | 属性 | 层级关系 |
|--------|------|---------|
| **User** | email, role, mfa_enabled, suspended | in [UserGroup, Organization] |
| **UserGroup** | description? | in [Organization] |
| **Organization** | plan, max_agents | — |
| **Agent** | delegator(→User), framework, version?, model?, risk_level, banned, sandbox_only | in [AgentGroup] |
| **AgentGroup** | description?, max_chain_depth | — |

### Resource Types（操作的目标？）

```
┌──────────────────┐
│  Service         │
│  owner?, sensi-  │
│  tivity, environ-│
│  ment            │
└───┬──────┬───────┘
    │      │
    │ in   │ in
┌───┴───┐ ┌┴──────────┐
│ Tool  │ │ Resource   │
│ Group │ │ Group      │
└───┬───┘ └──┬────────┘
    │ in     │ in
┌───┴────┐ ┌─┴──────────┐
│ Tool   │ │ Resource    │
│ capa-  │ │ owner?,     │
│ bility │ │ sensitivity,│
└────────┘ │ environment,│
           │ sandbox,    │
           │ private     │
           └─────────────┘
```

| Entity | 属性 | 层级关系 |
|--------|------|---------|
| **Service** | owner?, sensitivity, environment | — |
| **Tool** | capability{risk, reversible, requires_approval}, description? | in [ToolGroup, Service] |
| **ToolGroup** | description? | in [Service] |
| **Resource** | owner?, sensitivity, environment, sandbox, private | in [ResourceGroup, Service] |
| **ResourceGroup** | description? | in [Service] |

### Context Type: SessionContext

每次 `check()` 请求携带的上下文：

| 字段 | 类型 | 说明 |
|------|------|------|
| session_id | String | 会话唯一 ID |
| session_valid | Bool | 会话是否有效（服务端预验证） |
| delegator_id | String | 委托人 User ID |
| scope | Set\<String\> | 允许的 action 列表 |
| remaining_tokens | Long | 剩余 token 预算（-1=无限） |
| remaining_cost_cents | Long | 剩余成本预算（分，-1=无限） |
| remaining_calls | Long | 剩余调用次数（-1=无限） |
| chain_depth | Long | 当前调用链深度 |
| max_chain_depth | Long | 最大调用链深度 |
| request_ip? | ipaddr | 请求来源 IP（可选） |
| user_consent? | Bool | 用户是否显式同意（可选） |
| approval_status? | String | 审批状态（可选） |

## Action 分类

| 分组 | Actions | 风险等级 | 典型使用者 |
|------|---------|---------|-----------|
| **readActions** | read, list, search | 低 | Agent + User |
| **writeActions** | write, create, update | 中 | Agent（需 consent）+ User |
| **dangerousActions** | delete, execute, send_email, send_money | 高/极高 | 受限 Agent + Admin User |
| **toolActions** | invoke_tool, configure_tool | 视 tool 而定 | Agent / Admin User |
| **adminActions** | manage_policy, manage_session, view_audit, configure_tool | 高 | Admin User only |
| **delegate** | delegate | — | User only |

## 策略编写指南

### 基本模式

```cedar
// 1. 精确匹配 Agent
permit (
  principal == AgentIAM::Agent::"my-agent",
  action == AgentIAM::Action::"read",
  resource is AgentIAM::Resource
) when { ... };

// 2. 按 Agent 组授权
permit (
  principal in AgentIAM::AgentGroup::"research-agents",
  action in [AgentIAM::Action::"readActions"],
  resource in AgentIAM::Service::"web"
);

// 3. 按 Tool 风险等级授权
permit (
  principal is AgentIAM::Agent,
  action == AgentIAM::Action::"invoke_tool",
  resource is AgentIAM::Tool
) when {
  resource.capability.risk == "low"
};

// 4. 委托人关系检查
permit (
  principal is AgentIAM::Agent,
  action,
  resource is AgentIAM::Resource
) when {
  resource has owner && principal.delegator == resource.owner
};

// 5. 会话上下文检查
permit ( ... ) when {
  context.session_valid == true &&
  context.remaining_calls != 0 &&
  context.chain_depth <= context.max_chain_depth
};
```

### 护栏模式

```cedar
// 护栏 = forbid 策略，不可被任何 permit 覆盖

// 绝对禁止（无例外）
forbid (principal is AgentIAM::Agent, action == AgentIAM::Action::"send_money", resource);

// 条件禁止（有例外）
forbid (principal is AgentIAM::Agent, action == AgentIAM::Action::"execute", resource is AgentIAM::Resource)
unless { resource.sandbox == true };
```

## 实体数据示例

```json
[
  {
    "uid": { "__entity": { "type": "AgentIAM::User", "id": "weichao" } },
    "attrs": {
      "email": "weichao@example.com",
      "role": "admin",
      "mfa_enabled": true,
      "suspended": false
    },
    "parents": [
      { "__entity": { "type": "AgentIAM::UserGroup", "id": "admins" } },
      { "__entity": { "type": "AgentIAM::Organization", "id": "acme" } }
    ]
  },
  {
    "uid": { "__entity": { "type": "AgentIAM::Agent", "id": "research-scout" } },
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
      { "__entity": { "type": "AgentIAM::AgentGroup", "id": "research-agents" } }
    ]
  },
  {
    "uid": { "__entity": { "type": "AgentIAM::Tool", "id": "web-search" } },
    "attrs": {
      "capability": {
        "risk": "low",
        "reversible": true,
        "requires_approval": false
      },
      "description": "Search the web"
    },
    "parents": [
      { "__entity": { "type": "AgentIAM::Service", "id": "web" } }
    ]
  },
  {
    "uid": { "__entity": { "type": "AgentIAM::Resource", "id": "production-db" } },
    "attrs": {
      "owner": { "__entity": { "type": "AgentIAM::User", "id": "weichao" } },
      "sensitivity": "confidential",
      "environment": "production",
      "sandbox": false,
      "private": true
    },
    "parents": [
      { "__entity": { "type": "AgentIAM::Service", "id": "database" } }
    ]
  }
]
```

## 下一步

- [ ] API 详细设计（基于 Schema 定义请求/响应格式）
- [ ] 实体管理 API（CRUD for Users, Agents, Tools, Resources）
- [ ] Cedar Schema 自动生成（从 Tool registration 自动扩展 schema）
