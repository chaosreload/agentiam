# Phase 1 MVP — Implementation Tasks (Updated)

> 基于：Cedar Schema v0.2.0 + API Design v0.2.0 + Token Service Design v0.2.0
> 目标：**能用 Python SDK 对 1 个 Agent 做权限控制**

## Week 1: 项目骨架 + Cedar 引擎集成

### 1.1 项目初始化
- [ ] 初始化 Go module（`go mod init github.com/chaosreload/agentiam`）
- [ ] 创建目录结构：
  ```
  cmd/agentiam-server/main.go
  internal/cedar/          # Cedar 引擎
  internal/auth/           # 授权服务
  internal/session/         # 会话管理
  internal/token/           # Token 验证
  internal/audit/           # 审计日志
  internal/api/             # REST API
  internal/config/          # 配置加载
  sdk/python/               # Python SDK
  configs/                  # 配置文件
  ```
- [ ] 创建 Makefile：`build`, `test`, `run`, `lint`, `docker`
- [ ] 创建 `.gitignore`、`.golangci.yml`

### 1.2 Cedar 引擎集成
- [ ] 调研 Cedar-Go 集成方案（3 选 1）：
  - A) cedar-policy crate via CGo FFI
  - B) cedar-wasm via wazero runtime
  - C) cedar-policy-cli 子进程
  - 决策标准：如果 A 超过 3 天未搞定 → 切换到 B
- [ ] 实现 `internal/cedar/engine.go`：
  - `NewEngine(schemaPath, policiesDir) → Engine`
  - `Engine.IsAuthorized(principal, action, resource, context) → Decision`
  - `Engine.Reload() → error`（热重载策略）
  - `Engine.ValidatePolicy(text) → ValidationResult`
  - `Engine.ListPolicies() → []PolicyInfo`
- [ ] 加载 `schemas/agentiam.cedarschema`（AgentIAM namespace）
- [ ] 加载 `policies/*.cedar`（guardrails + examples）
- [ ] 实现 Entity Store：
  - `EntityStore.Load(jsonPath)` — 从 JSON 文件加载
  - `EntityStore.Upsert(entities)` — 运行时添加/更新
  - `EntityStore.Get(type, id)` — 查询单个实体
  - `EntityStore.Delete(type, id)` — 删除

### 1.3 Cedar 引擎测试
- [ ] 测试用例（全部使用 `AgentIAM::` namespace）：
  - permit 评估：Agent read public resource → ALLOW
  - forbid 覆盖 permit：banned Agent → DENY（即使有 permit）
  - 默认 deny：无匹配策略 → DENY
  - Schema 验证：错误策略拒绝加载
  - 实体层级：Agent in AgentGroup → 策略继承
  - Context 条件：chain_depth > max → DENY
  - Budget 条件：remaining_tokens == 0 → DENY
- [ ] 性能基准：1000 条策略下 P99 < 5ms

## Week 2: Token 验证 + 会话管理

### 2.1 JWT 工具
- [ ] 实现 `internal/token/jwt.go`：
  - `SignAccessToken(claims) → string`（Phase 1: HS256）
  - `SignSessionToken(session) → string`
  - `VerifyToken(tokenString) → Claims`（验证签名 + 过期 + 类型）
  - `ParseUnverified(tokenString) → Header`（解析 header 确定 typ）
- [ ] JWT Claims 结构体：
  ```go
  type AccessTokenClaims struct {
      jwt.RegisteredClaims
      Scope   string         `json:"scope"`
      AgentIAM AgentIAMClaims `json:"agentiam"`
  }
  type SessionTokenClaims struct {
      jwt.RegisteredClaims
      Delegator       string   `json:"delegator"`        // Cedar entity UID
      DelegationChain []string `json:"delegation_chain"`
      Scope           []string `json:"scope"`            // Cedar action UIDs
      Budget          Budget   `json:"budget"`
      MaxChainDepth   int      `json:"max_chain_depth"`
      Metadata        map[string]string `json:"metadata,omitempty"`
  }
  ```
- [ ] 测试：签发 → 验证 → 过期 → 篡改检测

### 2.2 API Key 认证
- [ ] 实现 `internal/token/apikey.go`：
  - `CreateAPIKey(env) → (key, hash)`
  - `VerifyAPIKey(key) → bool`
  - API Key 格式：`ak_{env}_{random32}`
  - 存储：SQLite（hash + 创建时间 + 名称）
- [ ] API Key 管理端点：
  - `POST /v1/api-keys` → 创建
  - `GET /v1/api-keys` → 列出（只显示前缀+后4位）
  - `DELETE /v1/api-keys/{id}` → 吊销

### 2.3 OAuth 2.0 Client Credentials
- [ ] 实现 `internal/token/oauth.go`：
  - `RegisterClient(name, grantTypes, scopes, agentId) → Client`
  - `AuthenticateClient(clientId, clientSecret) → Client`
  - `IssueAccessToken(client, requestedScopes) → AccessToken`
- [ ] `POST /v1/oauth/token` 端点：
  - grant_type=client_credentials
  - 验证 client_id + client_secret
  - 签发 Access Token（JWT, HS256）
- [ ] 10 个 OAuth scope 定义（agentiam:authorize, agentiam:session:* 等）

### 2.4 会话管理
- [ ] 实现 `internal/session/manager.go`：
  - `CreateSession(req) → Session`
    - 验证 delegator 和 agent 实体存在
    - 初始化 budget（remaining = max）
    - 签发 Session Token (JWT)
    - 存储到内存 map + SQLite
  - `GetSession(sessionId) → Session`
  - `ListSessions(filters) → []Session`
  - `RevokeSession(sessionId)`
  - `UpdateBudget(sessionId, usage) → BudgetStatus`
  - `ValidateSessionToken(token) → Session`
    - 验证 JWT 签名 + 过期
    - 检查吊销列表
    - 从存储加载最新 budget
- [ ] 吊销列表（内存 map，TTL 自动清理）
- [ ] Scope 预检查：请求 action 是否在 session scope 中

### 2.5 测试
- [ ] Session 生命周期：create → use → expire → deny
- [ ] Scope 违规：请求不在 scope 中 → DENY（不走 Cedar）
- [ ] 吊销：revoke → 后续请求 DENY
- [ ] Budget 消耗 + 耗尽 → DENY

## Week 3: 授权服务 + REST API

### 3.1 授权服务
- [ ] 实现 `internal/auth/service.go`：
  - `Authorize(req AuthorizeRequest) → AuthorizeResponse`
  - 完整流程：
    1. 验证 session token（JWT 签名 + 过期 + 吊销）
    2. 检查 scope（action 在 session scope 中？）
    3. 从 session 构造 Cedar Context（合并 session 数据 + 请求 context）
    4. 构造 Cedar Request（principal, action, resource）
    5. 调用 Cedar Engine.IsAuthorized()
    6. 写审计日志（异步）
    7. 返回 Decision + diagnostics
  - `AuthorizeBatch(req) → BatchResponse`

### 3.2 Context 构造
- [ ] 实现 `internal/auth/context.go`：
  - 从 Session 提取：session_id, session_valid, delegator_id, scope, remaining_*, max_chain_depth
  - 从请求合并：chain_depth, request_ip, user_consent, approval_status
  - 输出 Cedar Context（匹配 `SessionContext` schema type）

### 3.3 REST API
- [ ] 实现 `internal/api/router.go`（使用 chi 或 gin）
- [ ] 中间件：
  - `AuthMiddleware` — 验证 API Key 或 Access Token
  - `RequestIDMiddleware` — 生成 request_id
  - `LoggingMiddleware` — 结构化 JSON 日志
  - `CORSMiddleware`
  - `RecoveryMiddleware` — panic 恢复
  - `ScopeMiddleware` — 检查 OAuth scope（对应端点权限）
- [ ] 端点实现：
  - `POST /v1/authorize` — 核心授权检查
  - `POST /v1/authorize/batch` — 批量授权
  - `POST /v1/sessions` — 创建委托会话
  - `GET /v1/sessions` — 列出会话（分页 + cursor）
  - `GET /v1/sessions/{id}` — 会话详情
  - `DELETE /v1/sessions/{id}` — 吊销会话
  - `POST /v1/sessions/{id}/budget` — 上报预算消耗
  - `POST /v1/entities` — 注册/更新实体（upsert）
  - `GET /v1/entities` — 列出实体
  - `GET /v1/entities/{type}/{id}` — 实体详情
  - `DELETE /v1/entities/{type}/{id}` — 删除实体
  - `GET /v1/policies` — 列出策略
  - `POST /v1/policies/validate` — 验证策略文本
  - `POST /v1/policies/reload` — 热重载策略
  - `POST /v1/api-keys` / `GET` / `DELETE` — API Key 管理
  - `POST /v1/oauth/token` — OAuth token 签发
  - `GET /health` — 健康检查（无认证）
  - `GET /v1/config` — 服务配置

### 3.4 Server 入口
- [ ] 实现 `cmd/agentiam-server/main.go`
- [ ] 配置加载（`configs/agentiam.yaml` + env vars）：
  ```yaml
  server:
    addr: ":8080"
  cedar:
    schema: "schemas/agentiam.cedarschema"
    policies_dir: "policies/"
    entities_file: "entities.json"   # optional
  token:
    jwt_secret: "${AGENTIAM_JWT_SECRET}"
    access_token_ttl: 3600
    session_token_ttl_max: 86400
  audit:
    backend: "sqlite"
    sqlite_path: "data/audit.db"
  ```
- [ ] Dockerfile（multi-stage build）

## Week 4: 审计日志 + 集成测试

### 4.1 审计日志
- [ ] 实现 `internal/audit/logger.go`：
  - SQLite 表自动创建（auto-migrate）
  - `Log(record AuditRecord)` — 异步写入（buffered channel）
  - 表结构：
    ```sql
    CREATE TABLE audit_log (
        id TEXT PRIMARY KEY,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
        session_id TEXT,
        principal TEXT NOT NULL,
        action TEXT NOT NULL,
        resource_type TEXT,
        resource_id TEXT,
        resource_attrs TEXT,    -- JSON
        context TEXT,           -- JSON snapshot
        decision TEXT NOT NULL, -- ALLOW | DENY
        reason TEXT,
        policies_evaluated INTEGER,
        evaluation_time_us INTEGER
    );
    CREATE INDEX idx_audit_principal ON audit_log(principal, timestamp);
    CREATE INDEX idx_audit_decision ON audit_log(decision, timestamp);
    CREATE INDEX idx_audit_session ON audit_log(session_id);
    ```
- [ ] 实现 `internal/audit/query.go`：
  - 按 agent/action/decision/session_id/time 过滤
  - cursor 分页
  - 统计聚合（total/allow/deny/deny_by_reason/avg_latency/p99_latency）
- [ ] 端点：
  - `GET /v1/audit/decisions` — 查询
  - `GET /v1/audit/decisions/{id}` — 详情
  - `GET /v1/audit/stats` — 统计

### 4.2 集成测试
- [ ] 完整 HTTP 集成测试（Go httptest）：
  - 启动 server → 加载策略 → 创建 API Key
  - 创建 OAuth Client → 获取 Access Token
  - 注册实体（User + Agent + Resource）
  - 创建 Session（委托 User → Agent）
  - authorize: 匹配 permit → ALLOW
  - authorize: 匹配 guardrail forbid → DENY
  - authorize: scope 外 action → DENY (scope_violation)
  - authorize: 过期 session → DENY
  - authorize: 吊销 session → DENY
  - authorize batch: 3 个请求混合 → [ALLOW, ALLOW, DENY]
  - budget: 上报消耗 → 耗尽 → DENY
  - audit: 查询上述所有决策记录
  - audit stats: 验证统计数据正确
- [ ] 性能测试：100 并发 authorize 请求

## Week 5: Python SDK

### 5.1 SDK 实现
- [ ] 项目结构：
  ```
  sdk/python/
  ├── agentiam/
  │   ├── __init__.py         # 导出 AgentIAM, Decision, Session
  │   ├── client.py           # AgentIAM 主类
  │   ├── models.py           # Decision, Session, BudgetStatus, AuditRecord
  │   ├── auth.py             # 认证（API Key / OAuth）
  │   ├── sessions.py         # SessionManager
  │   ├── entities.py         # EntityManager
  │   ├── policies.py         # PolicyManager
  │   ├── audit.py            # AuditClient
  │   └── exceptions.py       # AgentIAMError, AuthError, DeniedError
  ├── pyproject.toml
  ├── tests/
  │   ├── test_client.py
  │   ├── test_authorize.py
  │   └── conftest.py
  └── README.md
  ```
- [ ] `AgentIAM` 主类：
  - `__init__(endpoint, api_key=None, client_id=None, client_secret=None)`
  - `authorize(session, action, resource, context=None) → Decision`
  - `is_allowed(session, action, resource_id=None, **kwargs) → bool`
  - `authorize_batch(session, requests) → list[Decision]`
  - `create_session(...) → Session`
  - `report_usage(session_id, tokens_used, cost_cents, calls_used)`
  - `health() → HealthStatus`
  - `.sessions` — SessionManager (list, get, revoke)
  - `.entities` — EntityManager (upsert, list, get, delete)
  - `.policies` — PolicyManager (list, validate, reload)
  - `.audit` — AuditClient (query, stats)
- [ ] HTTP 客户端：httpx（同步 + 异步）
- [ ] 自动重试 + 指数退避（429/5xx）
- [ ] pyproject.toml 配置（pip install agentiam）

### 5.2 SDK 测试
- [ ] Unit tests（httpx mock）
- [ ] Integration test（需要运行的 server）：
  - 完整流程：create session → authorize → report usage → query audit

## Week 6: Demo + 文档 + 发布

### 6.1 Demo
- [ ] `demo/demo.py` — Python SDK 演示脚本：
  ```python
  # 1. 连接 AgentIAM
  # 2. 注册实体（User weichao, Agent research-scout, Resources）
  # 3. 创建委托会话
  # 4. 执行 5 个授权检查（3 ALLOW + 2 DENY）
  # 5. 上报预算消耗
  # 6. 查询审计日志
  # 7. 打印总结
  ```
- [ ] `demo/run_demo.sh` — 一键启动 server + 运行 demo
- [ ] `demo/docker-compose.yaml` — Docker 方式运行

### 6.2 文档
- [ ] `docs/quickstart.md` — 5 分钟快速开始
- [ ] `docs/api.md` — 更新（确保和实现一致）
- [ ] `docs/configuration.md` — 配置参考
- [ ] `docs/policies-guide.md` — 策略编写指南
- [ ] README.md — 更新安装说明、badges

### 6.3 发布
- [ ] CI/CD：GitHub Actions（build + test + lint）
- [ ] 性能报告：authorize P50/P95/P99、100 并发 session
- [ ] Tag v0.1.0 release
- [ ] Python SDK 发布到 PyPI（agentiam）
- [ ] Docker image 发布到 GHCR
