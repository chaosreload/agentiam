// AgentIAM Guardrail Policies
// These policies have the HIGHEST priority and CANNOT be overridden.
// forbid always wins over permit — this is Cedar's core safety guarantee.

// ─── Critical Operation Protection ───

// Agents can NEVER delete production databases
@id("guardrail-no-production-delete")
forbid (
  principal is Agent,
  action == Action::"delete",
  resource
)
when {
  resource.sensitivity == "secret" ||
  resource.sensitivity == "internal"
};

// Agents can NEVER send money
@id("guardrail-no-send-money")
forbid (
  principal is Agent,
  action == Action::"send_money",
  resource
);

// ─── Sandbox Enforcement ───

// Code execution ONLY in sandbox environments
@id("guardrail-sandbox-only-exec")
forbid (
  principal is Agent,
  action == Action::"execute_code",
  resource
)
unless {
  resource.sandbox == true
};

// ─── Banned Agent Enforcement ───

// Banned agents cannot do ANYTHING (overrides all permits)
@id("guardrail-banned-agent")
forbid (
  principal is Agent,
  action,
  resource
)
when {
  principal.banned == true
};

// ─── Chain Depth Protection ───

// Prevent infinite tool call recursion
@id("guardrail-max-chain-depth")
forbid (
  principal is Agent,
  action,
  resource
)
when {
  context.chain_depth > 10
};

// ─── Budget Enforcement ───

// Deny all actions when session budget is exhausted
@id("guardrail-budget-exhausted")
forbid (
  principal is Agent,
  action,
  resource
)
when {
  context.remaining_budget <= 0
};
