# Code Review Checklist

对当前变更做一轮完整的代码审核。按顺序检查以下 7 项，每项给出 ✅/❌/⚠️ 和具体发现。

## 1. Error Handling
- 生产代码中不允许 `.unwrap()` / `.expect()`（`unwrap_or` / `unwrap_or_default` 除外）
- 所有错误必须通过 `Result<T, AgentIAMError>` 传播
- 检查是否有吞掉错误（`let _ = xxx`）的情况

## 2. Security
- **SQL**: 全部使用 sqlx 参数化查询，不允许 `format!` 拼接 SQL
- **Secrets**: JWT secret / API key / OAuth secret 不允许硬编码
- **Hash**: API Key 和 OAuth client_secret 必须存 hash，不存明文
- **Timing**: 密码/token 比较是否有 timing attack 风险
- **Input validation**: 公开 API 的输入是否有长度/格式验证

## 3. Concurrency Safety
- `DashMap` 的使用是否正确（不要 get 后 insert 的 TOCTOU）
- 数据库操作是否用原子 SQL 避免 read-modify-write race
- `Arc` / `Clone` 是否合理

## 4. Test Coverage
- 新增代码的每个公开方法是否有测试
- 边界条件是否覆盖：空输入、超大输入、过期、已吊销、并发
- happy path + error path 都要有

## 5. API Design
- 端点命名是否符合 RESTful 规范
- 错误响应格式是否统一
- HTTP status code 是否合适

## 6. Code Quality
- 是否有重复代码可以提取
- 函数是否过长（> 50 行建议拆分）
- 命名是否清晰
- 注释是否有价值（解释 why，不是 what）

## 7. Dependencies
- 新增依赖是否必要
- 是否使用了最新稳定版

---

**输出格式：**

```
## Review Summary

| 检查项 | 状态 | 发现 |
|--------|------|------|
| Error Handling | ✅/❌ | ... |
| Security | ✅/❌ | ... |
| ... | ... | ... |

## 需要修复的问题
1. ...
2. ...

## 建议改进（非阻塞）
1. ...
```

如果发现问题，直接修复并说明改了什么。修复后运行 `cargo test` + `cargo clippy -- -D warnings` 确认通过。
