# AgentIAM

> **The authorization layer for AI Agents. Control what your agents can do, before they do it.**

AgentIAM is a purpose-built identity and access management system for AI Agent scenarios. Built on [Cedar](https://www.cedarpolicy.com/) policy language, it brings AWS IAM-style authorization to the world of autonomous AI agents.

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
