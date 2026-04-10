# Phase 1 MVP — Implementation Tasks

> 技术栈：Rust + axum + cedar-policy + sqlx/sqlite + jsonwebtoken
> 目标：**能用 Python SDK 对 1 个 Agent 做权限控制**

## Week 1: 项目骨架 + Cedar 引擎集成

### 1.1 项目初始化
- [ ] 初始化 Rust 项目（`cargo init --name agentiam`）
- [ ] 设置 workspace（如需拆 crate）：
  ```
  Cargo.toml (workspace)
  crates/
    agentiam-server/      # HTTP server 入口
    agentiam-core/        # Cedar 引擎 + 授权逻辑
    agentiam-sdk-python/  # Python binding (PyO3, Phase 1 可选)
  ```
  或者 Phase 1 先用单 crate，后续再拆。
- [ ] 添加核心依赖（Cargo.toml）：
  ```toml
  [dependencies]
  cedar-policy = "4.10"
  axum = "0.8"
  tokio = { version = "1", features = ["full"] }
  serde = { version = "1", features = ["derive"] }
  serde_json = "1"
  jsonwebtoken = "9"
  sqlx = { version = "0.8", features = ["runtime-tokio", "sqlite"] }
  uuid = { version = "1", features = ["v4"] }
  tracing = "0.1"
  tracing-subscriber = "0.3"
  config = "0.14"
  thiserror = "2"
  anyhow = "1"
  chrono = { version = "0.4", features = ["serde"] }
  tower-http = { version = "0.6", features = ["cors", "trace"] }
  ```
- [ ] 创建目录结构：
  ```
  src/
    main.rs               # 入口
    config.rs             # 配置加载
    cedar/
      engine.rs           # Cedar 引擎封装
      entities.rs         # Entity Store
      mod.rs
    auth/
      service.rs          # 授权服务（核心）
      context.rs          # Cedar Context 构造
      mod.rs
    session/
      manager.rs          # 会话管理
      jwt.rs              # JWT 签发/验证
      mod.rs
    token/
      apikey.rs           # API Key 认证
      oauth.rs            # OAuth 2.0 Client Credentials
      middleware.rs        # 认证中间件
      mod.rs
    audit/
      logger.rs           # 审计日志写入
      query.rs            # 审计查询
      mod.rs
    api/
      router.rs           # 路由定义
      handlers/
        authorize.rs      # POST /v1/authorize
        sessions.rs       # Session CRUD
        entities.rs       # Entity CRUD
        policies.rs       # Policy 操作
        audit.rs          # 审计查询
        auth.rs           # API Key + OAuth
        health.rs         # 健康检查
      middleware.rs        # 中间件
      error.rs            # 统一错误处理
      mod.rs
    models.rs             # 共享数据模型
    error.rs              # 全局错误类型
  ```
- [ ] 创建 Makefile / justfile：`build`, `test`, `run`, `lint`, `docker`
- [ ] 配置 `clippy` + `rustfmt`

### 1.2 Cedar 引擎集成（原生！）
- [ ] 实现 `src/cedar/engine.rs`：
  ```rust
  pub struct CedarEngine {
      policy_set: PolicySet,
      schema: Schema,
      entities: Entities,
      authorizer: Authorizer,
  }

  impl CedarEngine {
      pub fn new(schema_path: &Path, policies_dir: &Path) -> Result<Self>;
      pub fn is_authorized(&self, request: &Request, entities: &Entities) -> Response;
      pub fn reload(&mut self, policies_dir: &Path) -> Result<()>;
      pub fn validate_policy(&self, policy_text: &str) -> ValidationResult;
      pub fn list_policies(&self) -> Vec<PolicyInfo>;
  }
  ```
- [ ] 加载 `schemas/agentiam.cedarschema`（直接用 `Schema::from_cedarschema_str`）
- [ ] 加载 `policies/*.cedar`（遍历目录，`PolicySet::from_str`）
- [ ] 实现 Entity Store（`src/cedar/entities.rs`）：
  - `EntityStore::load_from_json(path)` — 从 JSON 加载
  - `EntityStore::upsert(entities)` — 运行时添加/更新
  - `EntityStore::get(entity_uid)` — 查询
  - `EntityStore::delete(entity_uid)` — 删除
  - 内部存储为 `cedar_policy::Entities`，修改时重建

### 1.3 Cedar 引擎测试
- [ ] 测试用例（`#[cfg(test)]` 模块）：
  - permit 评估：Agent read public resource → ALLOW
  - forbid 覆盖 permit：banned Agent → DENY
  - 默认 deny：无匹配策略 → DENY
  - Schema 验证：错误策略被 Validator 拒绝
  - 实体层级：Agent in AgentGroup → 策略继承
  - Context 条件：chain_depth > max_chain_depth → DENY
  - Budget 条件：remaining_tokens == 0 → DENY
  - 多策略交叉：guardrail forbid + rbac permit → DENY
- [ ] 性能基准（`#[bench]` 或 criterion）：
  - 1000 条策略下单次评估 P99 < 1ms（Rust 原生应该远低于此）

## Week 2: Token 验证 + 会话管理

### 2.1 JWT 工具
- [ ] 实现 `src/session/jwt.rs`：
  ```rust
  pub fn sign_access_token(claims: &AccessTokenClaims, secret: &[u8]) -> Result<String>;
  pub fn sign_session_token(claims: &SessionTokenClaims, secret: &[u8]) -> Result<String>;
  pub fn verify_token<T: DeserializeOwned>(token: &str, secret: &[u8]) -> Result<TokenData<T>>;
  ```
- [ ] Claims 结构体（`src/models.rs`）：
  ```rust
  #[derive(Serialize, Deserialize)]
  pub struct AccessTokenClaims {
      pub iss: String,
      pub sub: String,           // client_id or user_id
      pub aud: String,
      pub exp: i64,
      pub iat: i64,
      pub jti: String,
      pub scope: String,
      pub agentiam: AgentIAMClaims,
  }

  #[derive(Serialize, Deserialize)]
  pub struct SessionTokenClaims {
      pub iss: String,
      pub sub: String,           // Cedar entity UID
      pub aud: String,
      pub exp: i64,
      pub iat: i64,
      pub jti: String,           // = session_id
      pub delegator: String,     // Cedar entity UID
      pub delegation_chain: Vec<String>,
      pub scope: Vec<String>,    // Cedar action UIDs
      pub budget: Budget,
      pub max_chain_depth: i32,
      pub metadata: Option<HashMap<String, String>>,
  }
  ```
- [ ] 测试：签发 → 验证 → 过期拒绝 → 篡改检测

### 2.2 API Key 认证
- [ ] 实现 `src/token/apikey.rs`：
  - `create_api_key(env: &str) → (key_string, key_hash)`
  - `verify_api_key(key: &str, store: &db) → Result<ApiKeyInfo>`
  - 格式：`ak_{env}_{random32}`，存储 SHA-256 hash
- [ ] SQLite 表：`api_keys (id, name, key_hash, env, created_at, revoked)`
- [ ] 端点：POST / GET / DELETE `/v1/api-keys`

### 2.3 OAuth 2.0 Client Credentials
- [ ] 实现 `src/token/oauth.rs`：
  - `register_client(req) → OAuthClient`
  - `authenticate_client(client_id, client_secret) → OAuthClient`
  - `issue_access_token(client, scopes) → AccessToken`
- [ ] `POST /v1/oauth/token`（grant_type=client_credentials）
- [ ] 10 个 OAuth scope 定义 + scope 验证

### 2.4 会话管理
- [ ] 实现 `src/session/manager.rs`：
  ```rust
  pub struct SessionManager {
      sessions: DashMap<String, Session>,  // 内存缓存
      db: SqlitePool,                      // 持久化
      jwt_secret: Vec<u8>,
  }

  impl SessionManager {
      pub async fn create_session(&self, req: CreateSessionRequest) -> Result<Session>;
      pub async fn get_session(&self, session_id: &str) -> Result<Session>;
      pub async fn list_sessions(&self, filters: SessionFilter) -> Result<Vec<Session>>;
      pub async fn revoke_session(&self, session_id: &str) -> Result<()>;
      pub async fn update_budget(&self, session_id: &str, usage: BudgetUsage) -> Result<BudgetStatus>;
      pub fn validate_token(&self, token: &str) -> Result<SessionTokenClaims>;
  }
  ```
- [ ] 吊销列表（`DashMap<String, Instant>`，定期清理过期条目）
- [ ] Scope 预检查逻辑
- [ ] SQLite 表：`sessions (session_id, delegator, agent, scope, budget, ..., revoked)`

### 2.5 测试
- [ ] Session 生命周期测试
- [ ] Scope 违规 → DENY
- [ ] 吊销 → DENY
- [ ] Budget 消耗 + 耗尽 → DENY

## Week 3: 授权服务 + REST API

### 3.1 授权服务
- [ ] 实现 `src/auth/service.rs`：
  ```rust
  pub struct AuthorizationService {
      cedar: Arc<RwLock<CedarEngine>>,
      sessions: Arc<SessionManager>,
      audit: Arc<AuditLogger>,
  }

  impl AuthorizationService {
      pub async fn authorize(&self, req: AuthorizeRequest) -> Result<AuthorizeResponse>;
      pub async fn authorize_batch(&self, req: BatchRequest) -> Result<BatchResponse>;
  }
  ```
- [ ] `authorize` 完整流程：
  1. 验证 session token
  2. 检查 scope
  3. 构造 Cedar Context（`src/auth/context.rs`）
  4. 构造 Cedar Request（EntityUid 解析）
  5. `cedar_engine.is_authorized()`
  6. 异步写审计日志
  7. 返回 Decision + diagnostics

### 3.2 REST API（axum）
- [ ] 实现 `src/api/router.rs`：
  ```rust
  pub fn create_router(state: AppState) -> Router {
      Router::new()
          // Authorization
          .route("/v1/authorize", post(authorize))
          .route("/v1/authorize/batch", post(authorize_batch))
          // Sessions
          .route("/v1/sessions", post(create_session).get(list_sessions))
          .route("/v1/sessions/:id", get(get_session).delete(revoke_session))
          .route("/v1/sessions/:id/budget", post(report_usage))
          // Entities
          .route("/v1/entities", post(upsert_entities).get(list_entities))
          .route("/v1/entities/:type/:id", get(get_entity).delete(delete_entity))
          // Policies
          .route("/v1/policies", get(list_policies))
          .route("/v1/policies/validate", post(validate_policy))
          .route("/v1/policies/reload", post(reload_policies))
          // Auth
          .route("/v1/api-keys", post(create_api_key).get(list_api_keys))
          .route("/v1/api-keys/:id", delete(revoke_api_key))
          .route("/v1/oauth/token", post(oauth_token))
          // Audit
          .route("/v1/audit/decisions", get(query_audit))
          .route("/v1/audit/decisions/:id", get(get_audit_record))
          .route("/v1/audit/stats", get(audit_stats))
          // Operational
          .route("/health", get(health_check))
          .route("/v1/config", get(get_config))
          // Middleware
          .layer(TraceLayer::new_for_http())
          .layer(CorsLayer::permissive())
          .with_state(state)
  }
  ```
- [ ] 认证中间件（`src/token/middleware.rs`）：
  - 从 Authorization header 提取 token
  - API Key → 验证 hash
  - Bearer JWT → 验证 Access Token → 提取 scopes
  - 检查 scope 匹配端点要求
- [ ] 统一错误处理（`src/api/error.rs`）：
  ```rust
  pub struct ApiError {
      pub code: String,       // "SessionExpired", "AccessDenied", etc.
      pub message: String,
      pub details: Option<Value>,
      pub status: StatusCode,
  }
  impl IntoResponse for ApiError { ... }
  ```
- [ ] 请求 ID 中间件

### 3.3 配置
- [ ] 实现 `src/config.rs`：
  ```rust
  #[derive(Deserialize)]
  pub struct AppConfig {
      pub server: ServerConfig,    // addr
      pub cedar: CedarConfig,      // schema, policies_dir, entities_file
      pub token: TokenConfig,      // jwt_secret, ttl
      pub audit: AuditConfig,      // sqlite_path
  }
  ```
- [ ] 支持 YAML + env var override（`AGENTIAM_JWT_SECRET` 等）
- [ ] `cmd/agentiam-server` 入口（或 `src/main.rs`）

### 3.4 Dockerfile
- [ ] Multi-stage build（builder + runtime）
- [ ] 最终镜像基于 `debian:bookworm-slim`（或 `alpine` + musl）

## Week 4: 审计日志 + 集成测试

### 4.1 审计日志
- [ ] 实现 `src/audit/logger.rs`：
  - SQLite 表自动创建（sqlx migrate）
  - `AuditLogger::log(record)` — 通过 `tokio::mpsc` channel 异步写入
  - 批量写入（每 100 条或 1 秒 flush 一次）
- [ ] 实现 `src/audit/query.rs`：
  - 按 principal/action/decision/session_id/time 过滤
  - cursor 分页（基于 id）
  - 统计聚合 SQL
- [ ] 端点：GET /v1/audit/decisions, /v1/audit/decisions/{id}, /v1/audit/stats

### 4.2 集成测试
- [ ] `tests/integration_test.rs`（使用 `axum::test` 或 `reqwest`）：
  - 启动 server（in-memory SQLite）→ 加载策略
  - 创建 API Key → 认证
  - 创建 OAuth Client → 获取 Access Token → 认证
  - 注册实体（User + Agent + Resource）
  - 创建 Session → 获取 Session Token
  - authorize: permit → ALLOW
  - authorize: guardrail forbid → DENY
  - authorize: scope 外 → DENY (scope_violation)
  - authorize: 过期 session → DENY
  - authorize: 吊销 session → DENY
  - authorize batch: [ALLOW, ALLOW, DENY]
  - budget: 上报消耗 → 耗尽 → DENY
  - audit: 查询所有决策 → 验证记录正确
  - audit stats: 验证统计
- [ ] 性能基准：100 并发 authorize 请求（criterion 或自定义 benchmark）

## Week 5: Python SDK

### 5.1 SDK 实现
- [ ] 项目结构：
  ```
  sdk/python/
  ├── agentiam/
  │   ├── __init__.py
  │   ├── client.py          # AgentIAM 主类
  │   ├── models.py          # Decision, Session, BudgetStatus, AuditRecord
  │   ├── auth.py            # API Key / OAuth 认证
  │   ├── sessions.py        # SessionManager
  │   ├── entities.py        # EntityManager
  │   ├── policies.py        # PolicyManager
  │   ├── audit.py           # AuditClient
  │   └── exceptions.py      # AgentIAMError, AuthError, DeniedError
  ├── pyproject.toml
  ├── tests/
  │   ├── test_client.py
  │   ├── test_authorize.py
  │   └── conftest.py
  └── README.md
  ```
- [ ] HTTP 客户端：httpx（同步 + 异步支持）
- [ ] 自动重试 + 指数退避（429/5xx）
- [ ] `AgentIAM` 主类完整 API（同 api.md 中的 SDK 设计）
- [ ] pyproject.toml（pip install agentiam）

### 5.2 SDK 测试
- [ ] Unit tests（httpx mock / respx）
- [ ] Integration test：启动 Rust server → SDK 端到端测试

## Week 6: Demo + 文档 + 发布

### 6.1 Demo
- [ ] `demo/demo.py`：完整演示脚本
- [ ] `demo/run_demo.sh`：一键启动 server + 运行 demo
- [ ] `demo/docker-compose.yaml`

### 6.2 文档
- [ ] `docs/quickstart.md` — 5 分钟快速开始
- [ ] `docs/api.md` — 确保和实现一致
- [ ] `docs/configuration.md` — 配置参考
- [ ] `docs/policies-guide.md` — 策略编写指南
- [ ] README.md — 更新安装说明、badges

### 6.3 发布
- [ ] GitHub Actions CI：`cargo build`, `cargo test`, `cargo clippy`, `cargo fmt --check`
- [ ] 性能报告
- [ ] Tag v0.1.0 release
- [ ] Python SDK → PyPI
- [ ] Docker image → GHCR
