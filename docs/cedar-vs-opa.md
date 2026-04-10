# Cedar vs OPA：策略引擎深度对比

> 整理日期：2026-04-10
> 基于：[Cedar 入门](/tools/cedar.html) | [OPA 入门](/tools/opa.html)

## 为什么要对比这两个？

在 "Policy-as-Code" 领域，Cedar 和 OPA 是两个最值得关注的开源项目，但它们的设计哲学截然不同：

- **OPA**（CNCF 毕业项目，2016 年开源）= 通用策略引擎，能回答任何 JSON 结构上的策略问题
- **Cedar**（AWS 开源，2023 年发布）= 专用授权引擎，只做一件事——判断"谁能对什么做什么"

选哪个？取决于你的问题是"我需要一个通用的策略决策层"还是"我需要一个安全、可验证的授权系统"。

## 一张表看全貌

| 维度 | Cedar | OPA |
|------|-------|-----|
| **定位** | 专用授权引擎 | 通用策略引擎 |
| **策略语言** | Cedar（自有 DSL） | Rego（Datalog 启发） |
| **语言范式** | 声明式，极度受限 | 声明式，表达力强 |
| **核心模型** | PARC（Principal-Action-Resource-Context） | 任意 JSON input → 任意 JSON output |
| **决策输出** | Allow / Deny（二元） | 任意 JSON（可以是布尔、对象、数组） |
| **默认行为** | 默认 Deny | 无内置默认（需自己写 `default`） |
| **forbid 覆盖** | ✅ 内置：forbid 永远覆盖 permit | ❌ 需自己实现优先级逻辑 |
| **类型系统** | ✅ Schema + 编译时验证 | ⚠️ 有类型检查但非强制 |
| **形式化验证** | ✅ Automated Reasoning（可证明策略性质） | ❌ 无（可测试但不可证明） |
| **实现语言** | Rust | Go |
| **WASM 支持** | ✅ | ✅ |
| **K8s 集成** | ❌ 无原生支持 | ✅ Gatekeeper（成熟生态） |
| **云托管** | AWS Verified Permissions | Styra DAS |
| **CNCF 状态** | 无 | Graduated |
| **开源时间** | 2023 | 2016 |
| **社区规模** | ~4.5K stars | ~10K+ stars |
| **学习曲线** | 低（语法简单，概念少） | 中高（Rego 思维转换成本大） |

## 策略语言对比：写同一个需求

### 需求：管理员可以做任何操作；普通用户只能读取自己拥有的资源

**Cedar 写法：**

```cedar
// 管理员全权限
permit (
  principal in Group::"admins",
  action,
  resource
);

// 用户读取自己的资源
permit (
  principal,
  action == Action::"read",
  resource
)
when {
  principal == resource.owner
};
```

**Rego 写法：**

```rego
package authz

import rego.v1

default allow := false

# 管理员全权限
allow if {
    input.principal.role == "admin"
}

# 用户读取自己的资源
allow if {
    input.action == "read"
    input.principal.id == input.resource.owner
}
```

**对比分析：**

| 方面 | Cedar | Rego |
|------|-------|------|
| 可读性 | 非常直观，接近自然语言 | 需要理解声明式 + 隐式 AND |
| 默认拒绝 | 内置，不需要写 | 需要显式声明 `default allow := false` |
| 实体模型 | 内置层级关系（`in Group::"admins"`） | 需要自己在 input/data 中建模 |
| 属性引用 | `resource.owner` 直接引用实体属性 | `input.resource.owner` 从 JSON 路径引用 |

### 需求升级：封禁用户不能访问任何资源（即使是管理员）

**Cedar 写法：** 加一条 forbid 就行

```cedar
// 之前的 permit 策略不需要改动

// 封禁用户 — forbid 自动覆盖所有 permit
forbid (
  principal,
  action,
  resource
)
when {
  principal.banned == true
};
```

**Rego 写法：** 需要修改原有逻辑

```rego
# 方案 1：在 allow 中加条件
allow if {
    input.principal.role == "admin"
    not input.principal.banned        # 每条规则都要加
}

# 方案 2：用独立的 deny 规则 + 修改最终决策
deny if {
    input.principal.banned
}

final_allow if {
    allow
    not deny        # 需要自己组合 allow 和 deny
}
```

**这是两个引擎最关键的设计差异。** Cedar 的 forbid 覆盖 permit 是内置语义，写策略时不需要考虑策略间的交互——任何 forbid 命中就是 Deny，不可能被绕过。OPA 则把这个逻辑留给策略编写者自己实现，灵活但容易出错。

## 安全模型对比

### Cedar：保守到极致

```
决策流程：
1. 收集所有匹配的策略
2. 如果任何 forbid 匹配 → DENY（不可覆盖）
3. 如果至少一个 permit 匹配 → ALLOW
4. 否则 → DENY（默认拒绝）
```

- **空策略集 = 全部拒绝**
- **一条 forbid 胜过一千条 permit**
- 策略评估出错（比如引用不存在的属性）→ 跳过该策略，不影响其他
- 引擎不可能因为 bug 意外放行

### OPA：灵活但自负责

```
决策流程：
1. 评估 Rego 查询
2. 返回查询结果（true/false/undefined/任意值）
3. 调用方自行解读结果
```

- **无内置的 allow/deny 语义**——你可以输出任何东西
- 需要自己实现 default deny、deny 覆盖 allow 等逻辑
- undefined（规则不匹配）和 false（规则拒绝）是不同的概念
- 更灵活，但安全保证依赖于策略编写者的水平

### 形式化验证：Cedar 的杀手级特性

Cedar 刻意限制语言表达能力（无循环、无副作用、有界执行），使得 Automated Reasoning 成为可能：

```
你可以问 Cedar 的分析工具：
- "是否存在某个请求能同时被两条策略允许？"（策略冲突检测）
- "策略 A 的覆盖范围是否是策略 B 的子集？"（策略包含关系）
- "是否所有管理员操作都需要 MFA？"（安全性质证明）
```

这不是测试——是**数学证明**。在合规要求严格的场景（金融、医疗、政府），这是决定性优势。

OPA 支持单元测试（`opa test`），可以验证已知场景的正确性，但无法证明"所有可能的输入都满足某个安全性质"。

## 适用场景对比

### Cedar 更适合的场景

| 场景 | 原因 |
|------|------|
| **应用级细粒度授权** | PARC 模型天然匹配"谁能对什么做什么" |
| **多租户 SaaS** | 实体层级 + Schema 验证，策略安全可证明 |
| **合规敏感行业** | Automated Reasoning 可出具形式化证明 |
| **AWS 生态** | Verified Permissions 一键托管 |
| **安全优先的场景** | forbid 覆盖机制保证不会意外放行 |

### OPA 更适合的场景

| 场景 | 原因 |
|------|------|
| **Kubernetes 准入控制** | Gatekeeper 生态成熟，CNCF 原生 |
| **IaC 合规检查** | Conftest 可直接检查 Terraform/K8s YAML |
| **API Gateway 授权** | 与 Envoy/Kong/Istio 有成熟集成 |
| **多系统统一策略** | 通用引擎，一套 Rego 管理多种策略类型 |
| **非授权类策略** | 数据过滤、配置验证、审计规则等 |

### 关键洞察

> **Cedar 回答的问题是：这个请求是否被允许？**
> **OPA 回答的问题是：基于这些规则，这个数据的策略评估结果是什么？**

Cedar 是**授权引擎**，OPA 是**策略引擎**。授权是策略的子集，但 Cedar 在这个子集上做到了极致。

## 架构集成对比

### Cedar 的集成模式

```
应用代码（Rust/其他语言）
    │
    ├─ Rust SDK（原生嵌入，零开销）
    │    └─ cedar-policy crate
    │
    ├─ WASM（浏览器/边缘/非 Rust 环境）
    │    └─ cedar-wasm
    │
    └─ AWS Verified Permissions（托管 API）
         └─ IsAuthorized / BatchIsAuthorized
```

Cedar 没有独立的 Server 模式——它被设计为**嵌入式引擎**。如果需要服务化，要么自己包一层 HTTP，要么用 Verified Permissions。

### OPA 的集成模式

```
                    ┌─ REST API Server（opa run --server）
                    │
应用 ────────── OPA ─┼─ Go Library（嵌入式）
                    │
                    ├─ Sidecar（K8s Pod 级别）
                    │
                    └─ WASM（编译策略为 wasm 模块）
```

OPA 原生支持 Server 模式，天然适合微服务架构。

### Bundle vs 策略加载

| 方面 | Cedar | OPA |
|------|-------|-----|
| 策略存储 | 代码中加载 / Verified Permissions | Bundle（tar.gz via HTTP/S3） |
| 热更新 | 重新加载 PolicySet | Bundle 轮询自动热加载 |
| 签名验证 | Schema 验证 | Bundle 签名（防篡改） |
| GitOps | 自行实现 | Bundle + CI/CD 天然适配 |

## 性能对比

| 指标 | Cedar | OPA |
|------|-------|-----|
| **评估延迟** | 微秒级（Rust 原生） | 微秒级（Go 编译后） |
| **策略索引** | ✅ 按 principal/action/resource 索引 | ⚠️ 依赖策略结构 |
| **策略数量扩展** | 索引过滤，非线性增长 | 可能随策略量线性增长 |
| **WASM 性能** | 接近原生 | 接近原生 |
| **内存占用** | 较小（专用数据结构） | 较大（通用 JSON 存储） |
| **冷启动** | 快（策略解析简单） | 取决于策略和数据量 |

两者在常见场景下性能都足够好，不是选型的决定性因素。但在超大规模场景（百万级策略），Cedar 的索引机制理论上更有优势。

## Rego vs Cedar 语法：心智模型

### Rego 的思维方式

```
我有一坨 JSON 数据（input + data），
我用逻辑规则在上面做查询，
能查到结果 = true / 有值，
查不到 = undefined。
```

Rego 本质上是**数据查询语言**，和 SQL、Datalog 一脉相承。写 Rego 更像写数据库查询而非写程序。

### Cedar 的思维方式

```
我有一组实体（用户、资源、组），
它们之间有层级关系，
我写 permit/forbid 规则描述谁能做什么，
引擎自动判断 Allow/Deny。
```

Cedar 更像填表——你在声明权限矩阵，而不是编程。

### 学习曲线

- **Cedar**：如果你理解 RBAC/ABAC 概念，10 分钟能上手写策略
- **Rego**：需要从命令式思维切换到声明式，理解 "多个 rule body 是 OR、body 内表达式是 AND、undefined ≠ false" 等概念，通常需要几天

## 生态系统对比

### OPA 生态（成熟）

| 工具 | 用途 |
|------|------|
| **Gatekeeper** | K8s 准入控制 |
| **Conftest** | IaC 策略测试 |
| **Regal** | Rego linter |
| **Styra DAS** | 商业托管平台 |
| **OPA Playground** | 在线测试 |
| **Envoy/Istio 插件** | 服务网格集成 |
| **Terraform 集成** | IaC 合规 |

### Cedar 生态（新兴但有 AWS 背书）

| 工具 | 用途 |
|------|------|
| **Verified Permissions** | AWS 托管授权服务 |
| **Cedar Playground** | 在线测试 |
| **cedar-examples** | 官方示例（TinyTodo 等） |
| **Language Server** | IDE 支持（LSP） |
| **Formatter** | 代码格式化 |

OPA 生态明显更成熟（7 年积累 + CNCF 加持），Cedar 较新但有 AWS 企业级背书。

## 选型建议

### 选 Cedar 如果：

- ✅ 你的核心需求是**应用级授权**（谁能对什么做什么）
- ✅ 你在 **AWS 生态**中，想用 Verified Permissions
- ✅ 你的场景需要**形式化安全证明**（合规/审计）
- ✅ 你希望策略**简单可读**，降低维护门槛
- ✅ 你需要**保证安全**——forbid 永远不能被绕过

### 选 OPA 如果：

- ✅ 你需要**K8s 准入控制**
- ✅ 你需要**统一管理多种策略**（授权 + 合规 + 配置验证）
- ✅ 你的团队有**Go 技术栈**
- ✅ 你需要**成熟的社区生态**和广泛的第三方集成
- ✅ 你的策略决策不只是 Allow/Deny，需要**复杂的 JSON 输出**

### 能不能一起用？

可以。在实际架构中，两者可以互补：

```
K8s 准入控制 → OPA Gatekeeper（基础设施层）
    │
应用授权 → Cedar / Verified Permissions（应用层）
    │
IaC 合规 → OPA Conftest（CI/CD 层）
```

OPA 管"基础设施应该长什么样"，Cedar 管"用户能做什么"——各司其职。

## 总结

| | Cedar | OPA |
|---|---|---|
| **一句话** | 为授权而生的安全引擎 | 为一切策略而生的通用引擎 |
| **核心优势** | 安全保证 + 形式化验证 + 简单 | 通用性 + 成熟生态 + K8s |
| **核心代价** | 只能做授权，生态较新 | 学习曲线高，安全逻辑需自行实现 |
| **适合团队** | 做 SaaS 产品 / AWS 用户 / 安全优先 | 平台工程 / 云原生 / 多策略类型 |

**最后一个观察**：Cedar 的出现不是要取代 OPA，而是 AWS 认为"通用策略引擎做授权，太重了"。OPA 什么都能做，但 Cedar 把授权这一件事做到了极致——更安全、更简单、可证明。这跟 "用 PostgreSQL 做消息队列 vs 用 Kafka" 是同一个道理：通用 vs 专用的取舍。

## 参考资源

- [Cedar 官方文档](https://docs.cedarpolicy.com) | [Cedar GitHub](https://github.com/cedar-policy/cedar)
- [OPA 官方文档](https://www.openpolicyagent.org/docs) | [OPA GitHub](https://github.com/open-policy-agent/opa)
- [Cedar 入门笔记](/tools/cedar.html)
- [OPA 入门笔记](/tools/opa.html)
- [Rego Playground](https://play.openpolicyagent.org) | [Cedar Playground](https://www.cedarpolicy.com/en/playground)
