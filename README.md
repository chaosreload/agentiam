# AgentIAM

> **The authorization layer for AI Agents. Control what your agents can do, before they do it.**

AgentIAM is a purpose-built identity and access management system for AI Agent scenarios. Built on [Cedar](https://www.cedarpolicy.com/) policy language, it brings AWS IAM-style authorization to the world of autonomous AI agents.

## Quickstart

### Docker (recommended)

```bash
# Build
docker build -t agentiam:dev .

# Run (SQLite + policies stored in ./data on the host)
docker run -d -p 8080:8080 -v $PWD/data:/var/lib/agentiam --name agentiam agentiam:dev

# Bootstrap the first API key
docker exec agentiam agentiam-bootstrap --db-path /var/lib/agentiam/agentiam.db --name admin --scope '*'
# => prints ak_bootstrap_... to stdout — copy it

# Test
curl -H "Authorization: Bearer <APIKEY>" http://localhost:8080/health
```

### From source

```bash
cargo run --release --bin agentiam-server
# In another terminal:
cargo run --bin agentiam-bootstrap -- --db-path agentiam.db --name admin --scope '*'
```

### REST API (19 endpoints)

| Method | Path | Description |
|--------|------|-------------|
| GET | `/health` | Health check (no auth) |
| POST | `/v1/authorize` | Evaluate a single authorization request |
| POST | `/v1/authorize/batch` | Evaluate multiple authorization requests |
| POST | `/v1/sessions` | Create a delegation session |
| GET | `/v1/sessions` | List sessions (with optional filters) |
| GET | `/v1/sessions/{id}` | Get session by ID |
| DELETE | `/v1/sessions/{id}` | Revoke / delete a session |
| POST | `/v1/sessions/{id}/budget` | Record budget usage for a session |
| POST | `/v1/entities` | Create Cedar entities |
| GET | `/v1/entities` | List all entities |
| GET | `/v1/entities/{type}/{id}` | Get a single entity |
| DELETE | `/v1/entities/{type}/{id}` | Delete an entity |
| GET | `/v1/policies` | List loaded Cedar policies |
| POST | `/v1/policies/validate` | Validate a Cedar policy |
| POST | `/v1/policies/reload` | Hot-reload policies from disk |
| GET | `/v1/audit/decisions` | Query audit decision log |
| GET | `/v1/audit/decisions/{id}` | Get a single audit record |
| GET | `/v1/audit/stats` | Aggregated audit statistics |
| GET | `/v1/config` | View runtime configuration |

All endpoints except `/health` require an API key via `Authorization: Bearer <key>`.

### Performance

Benchmark results (`cargo bench --bench authorize_bench`):

| Metric | Value |
|--------|-------|
| p50 latency | 8.1 ms |
| Throughput | 6 211 req/s |

### Testing

```bash
# Unit + integration tests
cargo test --all

# Performance benchmark
cargo bench --bench authorize_bench
```

---

## Why AgentIAM?

Traditional IAM handles **Human → Service** authorization. But AI Agents introduce a fundamentally different model:

```
Traditional IAM:    User → Action → Resource
Agent IAM:          User → Agent → Tool → Action → Resource
                      ↑       ↑       ↑
                   Delegate  Autonomous  Chained
```

**5 challenges that existing IAM doesn't solve:**

1. **Delegation** — Agents act on behalf of users, but shouldn't inherit full permissions
2. **Tool Control** — Which MCP servers/tools can an agent invoke?
3. **Autonomous Decisions** — Agents operate without human-in-the-loop
4. **Blast Radius** — One hallucination can trigger a chain of dangerous operations
5. **Context-Aware** — Same agent, different conversations = different permissions

## Core Concepts

| Concept | Description |
|---------|-------------|
| **Principal** | User, Agent, Tool, or Service identity |
| **Delegation Chain** | User → Agent → Tool → Service permission flow |
| **Session** | Time-bounded, budget-limited delegation scope |
| **Guardrail** | Unforgeable safety policies (forbid always wins) |
| **Policy Types** | AgentPolicy, DelegationPolicy, ToolPolicy, GuardrailPolicy, SessionPolicy |

## Policy Examples (Cedar)

```cedar
// Agent can read calendar
permit (
  principal == Agent::"research-agent",
  action in [Action::"calendar:read", Action::"calendar:list"],
  resource in Service::"calendar"
);

// Agents can NEVER delete production data (guardrail)
forbid (
  principal is Agent,
  action == Action::"delete_production_db",
  resource
);

// Code execution only in sandbox
forbid (
  principal is Agent,
  action == Action::"execute_code",
  resource
) unless {
  resource.sandbox == true
};

// Write requires user consent
permit (
  principal == Agent::"research-agent",
  action == Action::"calendar:write",
  resource in Service::"calendar"
) when {
  context.user_consent == true
};
```

## Architecture

```
┌──────────────┐     ┌─────────────────────┐
│  Agent Host  │────▶│   AgentIAM Gateway   │
│  (OpenClaw,  │     │  ┌───────────────┐   │
│   LangChain, │     │  │ Policy Engine │   │──▶ Allow / Deny
│   CrewAI...) │     │  │   (Cedar)     │   │
│      │       │     │  ├───────────────┤   │
│  AgentIAM    │     │  │ Session Mgr   │   │
│  SDK/Sidecar │◀───▶│  │ Guardrails    │   │
│  check()     │     │  │ Audit + Budget│   │
└──────────────┘     │  └───────────────┘   │
       │             └─────────────────────┘
       ▼
  Tools / MCP / APIs
```

## Quick Start (Python SDK — coming soon)

```python
from agentiam import AgentIAM

iam = AgentIAM(endpoint="http://localhost:8080")

# Create delegation session
session = iam.create_session(
    delegator="user:weichao",
    agent="agent:research-scout",
    scope=["tool:web_search", "tool:web_fetch"],
    ttl="1h",
    budget={"max_tokens": 1_000_000, "max_cost_usd": 5.0}
)

# Check permission before action
decision = iam.check(
    session=session.token,
    action="tool:exec",
    resource={"command": "rm -rf /", "sandbox": False}
)
# => Decision.DENY, reason: "guardrail: exec only in sandbox"
```

## Why Cedar over OPA?

AgentIAM chose Cedar as its policy engine. See [Cedar vs OPA analysis](docs/cedar-vs-opa.md) for the full comparison.

**TL;DR:**
- Cedar's PARC model maps 1:1 to IAM concepts (zero learning curve for AWS users)
- `forbid` always overrides `permit` — guardrails can never be bypassed
- Automated Reasoning can **prove** safety properties (not just test them)
- Rust-native, embeddable, WASM-ready

## Documentation

- [Design Document](docs/design.md) — Full system design
- [Cedar vs OPA](docs/cedar-vs-opa.md) — Policy engine selection analysis
- [Cedar Schema](schemas/agentiam.cedarschema) — Entity type definitions
- [Example Policies](policies/examples/) — Ready-to-use policy templates

## Roadmap

| Phase | Focus | Timeline |
|-------|-------|----------|
| Phase 1 | MVP — Cedar + SDK + basic delegation | 6 weeks |
| Phase 2 | MCP Gateway + Budget + Human approval | 6 weeks |
| Phase 3 | Web Console + Multi-tenant + OPAL | 8 weeks |
| Phase 4 | Ecosystem — Framework plugins + MCP standard | Ongoing |

## License

Apache License 2.0
