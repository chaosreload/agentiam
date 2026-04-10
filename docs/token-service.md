# AgentIAM Token Service 设计文档

> 版本：v0.2.0 | 更新日期：2026-04-10
> 基于 Cedar Schema v0.2.0 + API Design v0.2.0

## 定位

Token Service 是 AgentIAM 的"身份层"——连接外部身份认证（OAuth 2.0、API Key 等）和内部授权决策（Cedar）的桥梁。

```
外部世界                      AgentIAM 内部
                              
OAuth 2.0 ─────┐              
API Key ───────┤              
mTLS ──────────┼──▶ Token Service ──▶ Session Token (JWT)
OIDC ──────────┤       │                    │
Custom ────────┘       │              ┌─────┴──────┐
                       │              │ Cedar      │
                  身份验证 +           │ Authorize  │
                  身份映射             │ Engine     │
                                      └────────────┘
```

**核心原则：**
1. **认证与授权分离** — Token Service 只管"你是谁"，Cedar 管"你能做什么"
2. **不替代 IdP** — 不做用户注册/密码管理，对接现有 IdP（Keycloak、Cognito、Auth0）
3. **STS 风格** — 委托会话的 token 签发对标 AWS STS
4. **JWT 标准化** — 遵循 RFC 9068（OAuth 2.0 JWT Access Token Profile）

---

## 一、认证方式支持

### 支持矩阵

| 认证方式 | 适用场景 | Phase | 说明 |
|---------|---------|-------|------|
| **API Key** | 开发/测试、简单集成 | Phase 1 | 静态密钥，最简单 |
| **OAuth 2.0 Client Credentials** | 服务间认证（Agent→AgentIAM） | Phase 1 | 机器对机器，无用户参与 |
| **OAuth 2.0 Authorization Code + PKCE** | 用户授权 Agent（Web UI） | Phase 2 | 用户在浏览器中授权 |
| **OIDC ID Token** | 接入外部 IdP（Cognito/Keycloak/Auth0） | Phase 2 | 验证外部 JWT，映射到内部 User |
| **mTLS** | 高安全环境、服务网格 | Phase 3 | 证书级认证 |
| **AWS IAM (SigV4)** | AWS 原生集成 | Phase 3 | 用 IAM Role 认证 |

### Phase 1 详细设计

#### 1. API Key 认证

最简单的认证方式，适合开发和单租户部署。

```
Authorization: Bearer ak_live_abc123def456
```

**API Key 结构：**
```
ak_{environment}_{random_32_chars}

环境前缀：
  ak_live_  — 生产环境
  ak_test_  — 测试环境
  ak_dev_   — 开发环境
```

**存储：** 只存 hash（SHA-256），不存明文。创建时返回一次明文，之后不可查看。

**API Key 管理端点：**

```
POST   /v1/api-keys              创建 API Key
GET    /v1/api-keys              列出 API Key（只显示前缀 + 后4位）
DELETE /v1/api-keys/{key_id}     吊销 API Key
```

#### 2. OAuth 2.0 Client Credentials

Agent 框架（如 LangChain、CrewAI）以 OAuth 2.0 Client 身份认证。

**注册 Client：**
```
POST /v1/oauth/clients
{
  "name": "research-scout-agent",
  "grant_types": ["client_credentials"],
  "scope": ["agentiam:authorize", "agentiam:session:create"],
  "agent_id": "research-scout"        // 绑定到哪个 Agent
}

Response:
{
  "client_id": "cli_abc123",
  "client_secret": "cs_xxx...xxx",     // 只显示一次
  "grant_types": ["client_credentials"],
  "scope": ["agentiam:authorize", "agentiam:session:create"]
}
```

**获取 Access Token：**
```
POST /v1/oauth/token
Content-Type: application/x-www-form-urlencoded

grant_type=client_credentials
&client_id=cli_abc123
&client_secret=cs_xxx...xxx
&scope=agentiam:authorize agentiam:session:create

Response:
{
  "access_token": "eyJ...",            // JWT
  "token_type": "Bearer",
  "expires_in": 3600,
  "scope": "agentiam:authorize agentiam:session:create"
}
```

**OAuth 2.0 Scope 定义：**

| Scope | 说明 | 允许的 API |
|-------|------|-----------|
| `agentiam:authorize` | 授权检查 | POST /v1/authorize, /v1/authorize/batch |
| `agentiam:session:create` | 创建会话 | POST /v1/sessions |
| `agentiam:session:read` | 读取会话 | GET /v1/sessions |
| `agentiam:session:revoke` | 吊销会话 | DELETE /v1/sessions/{id} |
| `agentiam:entity:write` | 管理实体 | POST/DELETE /v1/entities |
| `agentiam:entity:read` | 读取实体 | GET /v1/entities |
| `agentiam:policy:read` | 读取策略 | GET /v1/policies |
| `agentiam:policy:manage` | 管理策略 | POST /v1/policies/* |
| `agentiam:audit:read` | 读取审计 | GET /v1/audit/* |
| `agentiam:admin` | 全部权限 | 所有端点 |

---

## 二、JWT Token 设计

AgentIAM 使用两种 JWT Token：

| Token 类型 | 用途 | 签发方 | 有效期 |
|-----------|------|--------|--------|
| **Access Token** | API 认证（调用 AgentIAM API） | Token Service | 1 小时 |
| **Session Token** | 委托会话凭证（Agent 持有） | Session Manager | 用户指定（最长 24h） |

### Access Token（API 认证）

遵循 RFC 9068 JWT Access Token Profile。

**Header:**
```json
{
  "alg": "RS256",
  "typ": "at+jwt",
  "kid": "agentiam-2026-04-10"
}
```

**Payload:**
```json
{
  // RFC 9068 标准 claims
  "iss": "https://agentiam.example.com",
  "sub": "cli_abc123",                      // client_id 或 user_id
  "aud": "https://agentiam.example.com/v1", // AgentIAM API
  "exp": 1744300800,
  "iat": 1744297200,
  "jti": "at_unique_id_123",

  // OAuth 2.0 scope
  "scope": "agentiam:authorize agentiam:session:create",

  // AgentIAM 自定义 claims
  "agentiam": {
    "client_type": "agent",                  // "agent" | "user" | "service"
    "agent_id": "research-scout",            // 绑定的 Agent（如果是 agent client）
    "org_id": "acme"                         // 所属组织
  }
}
```

**签名算法：**

| Phase | 算法 | 密钥管理 |
|-------|------|---------|
| Phase 1 (MVP) | HS256 | 配置文件中的 secret |
| Phase 2 | RS256 | JWKS 端点（本地 key pair） |
| Phase 3 | RS256 + KMS | AWS KMS / Vault 托管密钥 |

### Session Token（委托会话）

Session Token 是 AgentIAM 的核心创新——对标 AWS STS 的临时凭证。

**Header:**
```json
{
  "alg": "RS256",
  "typ": "session+jwt",
  "kid": "agentiam-2026-04-10"
}
```

**Payload:**
```json
{
  // 标准 claims
  "iss": "https://agentiam.example.com",
  "sub": "AgentIAM::Agent::\"research-scout\"",  // Cedar entity UID
  "aud": "https://agentiam.example.com/v1",
  "exp": 1744300800,
  "iat": 1744297200,
  "jti": "sess_a1b2c3d4",                       // = session_id

  // 委托信息
  "delegator": "AgentIAM::User::\"weichao\"",   // Cedar entity UID
  "delegation_chain": [
    "AgentIAM::User::\"weichao\"",
    "AgentIAM::Agent::\"research-scout\""
  ],

  // 权限范围
  "scope": [
    "AgentIAM::Action::\"read\"",
    "AgentIAM::Action::\"list\"",
    "AgentIAM::Action::\"search\"",
    "AgentIAM::Action::\"invoke_tool\""
  ],

  // 预算
  "budget": {
    "max_tokens": 1000000,
    "max_cost_cents": 500,
    "max_calls": 1000
  },

  // 约束
  "max_chain_depth": 5,

  // 元数据
  "metadata": {
    "purpose": "Daily research scan",
    "channel": "slack:#openclaw-research"
  }
}
```

**关键设计点：**

1. **`sub` 使用 Cedar Entity UID** — 直接映射到 Cedar 的 principal，不需要额外转换
2. **`scope` 使用 Cedar Action 格式** — 授权检查时直接对比，无需映射
3. **`budget` 是初始预算** — 实际剩余预算在服务端维护（Redis/内存），Token 中不更新
4. **Token 不可修改** — 预算消耗不修改 Token，而是服务端扣减。Token 只是"身份证"

### Token 生命周期

```
创建会话                 Agent 使用                     过期/吊销
   │                       │                              │
   ▼                       ▼                              ▼
POST /v1/sessions    POST /v1/authorize              Token 过期
   │                   │                             DELETE /v1/sessions/{id}
   ├─ 签发 JWT         ├─ 验证签名                        │
   ├─ 存储 session     ├─ 检查过期                        ├─ 标记 session revoked
   ├─ 初始化 budget    ├─ 检查是否 revoked                ├─ 后续请求返回 DENY
   └─ 返回 token       ├─ 检查 scope
                       ├─ 构造 Cedar Context
                       ├─ Cedar 评估
                       ├─ 扣减 budget
                       └─ 记录审计
```

---

## 三、Token 验证流程

### 快速路径（本地验证）

```
收到请求
  │
  ▼
1. 解析 JWT Header → 确定 typ（at+jwt 或 session+jwt）
  │
  ▼
2. 验证签名（HS256/RS256，使用本地密钥）
  │  ❌ 签名无效 → 401 Unauthorized
  │
  ▼
3. 检查 exp（过期时间）
  │  ❌ 过期 → 401 Token expired
  │
  ▼
4. 检查 jti 是否在吊销列表中
  │  ❌ 已吊销 → 401 Token revoked
  │
  ▼
5. [Session Token] 检查 session 服务端状态
  │  ❌ 预算耗尽 → 构造 budget_exhausted context → Cedar 评估 → DENY
  │
  ▼
6. ✅ 验证通过，提取 claims → 继续处理
```

### Token 吊销机制

| 方案 | 说明 | 适用场景 |
|------|------|---------|
| **吊销列表（Revocation List）** | 内存中维护已吊销 token 的 jti 集合 | Phase 1 默认 |
| **短生命周期 + Refresh** | Token 有效期短（5min），频繁 refresh | 高安全场景 |
| **Token Introspection（RFC 7662）** | 每次验证都查询 Token Service | 分布式场景（Phase 3） |

Phase 1 使用内存吊销列表，配合 TTL 自动清理过期条目。

---

## 四、外部 IdP 集成（Phase 2）

### OIDC Token 交换

用户通过外部 IdP（Cognito/Keycloak/Auth0）登录后，将 OIDC ID Token 交换为 AgentIAM 的 Access Token。

**流程：**
```
用户浏览器                外部 IdP              AgentIAM
    │                      │                     │
    ├──── Login ──────────▶│                     │
    │◀── ID Token ─────────┤                     │
    │                      │                     │
    ├──── POST /v1/oauth/token ─────────────────▶│
    │     grant_type=urn:ietf:params:            │
    │       oauth:grant-type:token-exchange      │
    │     subject_token={id_token}               │
    │     subject_token_type=                    │
    │       urn:ietf:params:oauth:               │
    │         token-type:id_token                │
    │                                            │
    │                                  验证 ID Token
    │                                  查找/创建 User 映射
    │                                  签发 Access Token
    │                                            │
    │◀── Access Token ──────────────────────────┤
```

**Token Exchange 端点（RFC 8693）：**
```
POST /v1/oauth/token
Content-Type: application/x-www-form-urlencoded

grant_type=urn:ietf:params:oauth:grant-type:token-exchange
&subject_token=eyJ...                    // 外部 ID Token
&subject_token_type=urn:ietf:params:oauth:token-type:id_token
&scope=agentiam:authorize agentiam:session:create

Response:
{
  "access_token": "eyJ...",              // AgentIAM Access Token
  "token_type": "Bearer",
  "expires_in": 3600,
  "issued_token_type": "urn:ietf:params:oauth:token-type:access_token"
}
```

### IdP 身份映射

外部 IdP 的用户身份需要映射到 AgentIAM 的 Cedar Entity：

```yaml
# configs/identity-mapping.yaml
providers:
  - name: cognito
    issuer: "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_xxxxx"
    jwks_uri: "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_xxxxx/.well-known/jwks.json"
    mapping:
      user_id: "sub"                     # JWT claim → AgentIAM User ID
      email: "email"
      role: "custom:role"                # 自定义 claim
      groups: "cognito:groups"
    auto_create_user: true               # 首次登录自动创建 User entity
    default_role: "developer"

  - name: keycloak
    issuer: "https://keycloak.example.com/realms/myapp"
    jwks_uri: "https://keycloak.example.com/realms/myapp/protocol/openid-connect/certs"
    mapping:
      user_id: "preferred_username"
      email: "email"
      role: "realm_access.roles[0]"
      groups: "groups"
    auto_create_user: true
    default_role: "viewer"

  - name: auth0
    issuer: "https://myapp.auth0.com/"
    jwks_uri: "https://myapp.auth0.com/.well-known/jwks.json"
    mapping:
      user_id: "sub"
      email: "email"
      role: "https://agentiam.example.com/role"
```

---

## 五、JWKS 端点（Phase 2+）

当使用 RS256 签名时，发布公钥供外部验证：

```
GET /.well-known/jwks.json

Response:
{
  "keys": [
    {
      "kty": "RSA",
      "kid": "agentiam-2026-04-10",
      "use": "sig",
      "alg": "RS256",
      "n": "0vx7agoebGcQSuu...",
      "e": "AQAB"
    }
  ]
}
```

**密钥轮换：**
- 新密钥生成后，旧密钥保留 24h（同时发布两个 key）
- JWT header 的 `kid` 指定使用哪个密钥
- 验证时按 `kid` 查找对应公钥

---

## 六、Agent 认证流程（完整）

### 场景 1：开发环境（API Key）

```
Agent Framework                    AgentIAM
      │                               │
      ├── POST /v1/sessions ──────────▶│  Header: Authorization: Bearer ak_dev_xxx
      │   {delegator, agent, scope}    │
      │                                ├── 验证 API Key
      │                                ├── 创建 session
      │◀── {session_token} ────────────┤
      │                                │
      ├── POST /v1/authorize ─────────▶│  Body: {session_token, action, resource}
      │                                ├── 验证 session JWT
      │                                ├── Cedar 评估
      │◀── {decision: ALLOW} ─────────┤
```

### 场景 2：生产环境（OAuth 2.0 Client Credentials）

```
Agent Framework                    AgentIAM
      │                               │
      ├── POST /v1/oauth/token ──────▶│  client_id + client_secret
      │   grant_type=client_credentials│
      │◀── {access_token} ────────────┤
      │                                │
      ├── POST /v1/sessions ──────────▶│  Header: Authorization: Bearer {access_token}
      │   {delegator, agent, scope}    │
      │◀── {session_token} ────────────┤
      │                                │
      ├── POST /v1/authorize ─────────▶│  Body: {session_token, action, resource}
      │◀── {decision: ALLOW} ─────────┤
```

### 场景 3：用户授权 Agent（OAuth 2.0 Auth Code + PKCE）

```
用户浏览器      Agent Web UI         AgentIAM         外部 IdP
    │               │                   │                │
    ├── 点击授权 ──▶│                   │                │
    │               ├── GET /v1/oauth/  │                │
    │               │   authorize ─────▶│                │
    │               │                   ├── 302 ────────▶│
    │◀── 302 Redirect ──────────────────│                │
    ├── 登录 ──────────────────────────────────────────▶│
    │◀── code ─────────────────────────────────────────┤
    │               │                   │                │
    │               ├── POST /v1/oauth/ │                │
    │               │   token ─────────▶│                │
    │               │   code + verifier │                │
    │               │                   ├── 验证 code    │
    │               │                   ├── 签发 token   │
    │               │◀── {access_token}─┤                │
    │               │                   │                │
    │               ├── POST /v1/       │                │
    │               │   sessions ──────▶│                │
    │               │   (代表用户创建    │                │
    │               │    委托会话)       │                │
    │◀── 授权完成 ──┤                   │                │
```

---

## 七、Token Service API 端点

### 新增端点（Phase 1）

| Method | Path | 说明 |
|--------|------|------|
| POST | /v1/api-keys | 创建 API Key |
| GET | /v1/api-keys | 列出 API Key |
| DELETE | /v1/api-keys/{id} | 吊销 API Key |
| POST | /v1/oauth/token | 获取 Access Token（Client Credentials） |

### 新增端点（Phase 2）

| Method | Path | 说明 |
|--------|------|------|
| POST | /v1/oauth/clients | 注册 OAuth Client |
| GET | /v1/oauth/clients | 列出 OAuth Clients |
| DELETE | /v1/oauth/clients/{id} | 删除 OAuth Client |
| GET | /v1/oauth/authorize | OAuth 2.0 授权端点（Auth Code flow） |
| GET | /.well-known/jwks.json | 公钥发布 |
| GET | /.well-known/openid-configuration | OIDC Discovery |
| POST | /v1/oauth/token (token exchange) | OIDC Token 交换 |

### Discovery 端点（Phase 2+）

```
GET /.well-known/openid-configuration

Response:
{
  "issuer": "https://agentiam.example.com",
  "token_endpoint": "https://agentiam.example.com/v1/oauth/token",
  "authorization_endpoint": "https://agentiam.example.com/v1/oauth/authorize",
  "jwks_uri": "https://agentiam.example.com/.well-known/jwks.json",
  "token_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post"],
  "grant_types_supported": [
    "client_credentials",
    "authorization_code",
    "urn:ietf:params:oauth:grant-type:token-exchange"
  ],
  "scopes_supported": [
    "agentiam:authorize",
    "agentiam:session:create",
    "agentiam:session:read",
    "agentiam:admin"
  ],
  "response_types_supported": ["code"],
  "code_challenge_methods_supported": ["S256"]
}
```

---

## 八、安全考量

### Token 安全

| 威胁 | 防御 |
|------|------|
| Token 泄露 | 短有效期（Access: 1h, Session: 用户指定 max 24h） |
| Token 重放 | jti claim 唯一性 + 吊销列表 |
| Token 篡改 | JWT 签名（HS256→RS256） |
| 密钥泄露 | 密钥轮换 + KMS 托管（Phase 3） |
| 中间人攻击 | 强制 HTTPS（生产环境） |

### Session Token 特殊安全

| 机制 | 说明 |
|------|------|
| **Scope 预绑定** | Token 创建时 scope 已固定，不可运行时扩大 |
| **Budget 服务端管理** | 预算在服务端实时扣减，Token 中的 budget 仅为初始值 |
| **委托链审计** | delegation_chain claim 记录完整委托路径 |
| **强制 Cedar 评估** | 即使 Token 有效，每次操作仍经过 Cedar 策略评估 |
| **吊销即生效** | 吊销后所有持有该 Token 的 Agent 立即失效 |

### 最佳实践

```yaml
# 推荐的安全配置
security:
  # Token 有效期
  access_token_ttl: 3600         # 1 小时
  session_token_ttl_max: 86400   # 最长 24 小时
  session_token_ttl_default: 3600 # 默认 1 小时

  # 签名
  jwt_algorithm: RS256            # 生产环境用 RS256
  key_rotation_days: 90           # 90 天轮换密钥

  # 吊销
  revocation_check: true          # 每次验证检查吊销列表
  revocation_list_cleanup: 3600   # 每小时清理过期条目

  # 传输
  require_https: true             # 生产环境强制 HTTPS
  cors_origins: ["https://app.example.com"]

  # 限流
  rate_limit:
    token_endpoint: 100/min       # Token 签发限流
    authorize_endpoint: 1000/min  # 授权检查限流
```

---

## 九、与 AWS STS 的对标

| AgentIAM | AWS STS | 说明 |
|----------|---------|------|
| POST /v1/sessions | AssumeRole | 获取临时凭证 |
| Session Token | STS Temporary Credentials | 有时限、有范围的凭证 |
| scope | RolePolicy | 权限范围 |
| budget | 无（AgentIAM 独有） | 资源消耗限制 |
| max_chain_depth | 无（AgentIAM 独有） | 调用链深度限制 |
| delegation_chain | AssumeRole chaining | 委托链路 |
| POST /v1/oauth/token | GetSessionToken | 获取 Access Token |
| DELETE /v1/sessions/{id} | 无（STS token 不可吊销） | AgentIAM 支持主动吊销 |
| /.well-known/jwks.json | STS 证书 | 公钥发布 |

**AgentIAM 的 3 个 STS 没有的特性：**
1. **Budget** — STS 没有资源消耗限制
2. **Chain Depth** — STS 限制 AssumeRole 链最多 2 层，AgentIAM 支持可配置深度
3. **主动吊销** — STS 的临时凭证不可吊销（只能等过期），AgentIAM 支持立即吊销

---

## 十、实施优先级

### Phase 1 (MVP) — 6 周内

```
✅ API Key 认证
✅ OAuth 2.0 Client Credentials
✅ JWT Session Token（HS256）
✅ Token 验证 + 吊销列表
✅ Session 创建/验证/吊销
```

### Phase 2 — 12 周内

```
○ RS256 签名 + JWKS 端点
○ OAuth 2.0 Authorization Code + PKCE
○ OIDC Token Exchange（接入外部 IdP）
○ IdP 身份映射配置
○ OpenID Discovery 端点
○ OAuth Client 管理
```

### Phase 3 — 生产级

```
○ KMS 密钥托管（AWS KMS / Vault）
○ mTLS 认证
○ AWS IAM SigV4 认证
○ Token Introspection（RFC 7662）
○ 密钥自动轮换
○ Multi-tenant 隔离
```
