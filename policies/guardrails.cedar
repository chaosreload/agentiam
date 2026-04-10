// ═══════════════════════════════════════════════════════════════════
// AgentIAM Guardrail Policies — v0.2.0
// These policies have the HIGHEST priority and CANNOT be overridden.
// forbid always wins over permit — this is Cedar's core safety guarantee.
// ═══════════════════════════════════════════════════════════════════

// ─── Banned Agent: Zero Tolerance ───
@id("guardrail-banned-agent")
forbid (
  principal is AgentIAM::Agent,
  action,
  resource
)
when {
  principal.banned == true
};

// ─── Suspended User's Agents ───
@id("guardrail-suspended-delegator")
forbid (
  principal is AgentIAM::Agent,
  action,
  resource
)
when {
  principal.delegator.suspended == true
};

// ─── Production Protection ───
// Agents can NEVER delete production resources
@id("guardrail-no-production-delete")
forbid (
  principal is AgentIAM::Agent,
  action == AgentIAM::Action::"delete",
  resource is AgentIAM::Resource
)
when {
  resource.environment == "production"
};

// ─── Sandbox Enforcement ───
// Code execution ONLY in sandbox resources
@id("guardrail-sandbox-only-exec")
forbid (
  principal is AgentIAM::Agent,
  action == AgentIAM::Action::"execute",
  resource is AgentIAM::Resource
)
unless {
  resource.sandbox == true
};

// ─── Financial Protection ───
@id("guardrail-no-send-money")
forbid (
  principal is AgentIAM::Agent,
  action == AgentIAM::Action::"send_money",
  resource
);

// ─── Chain Depth Protection ───
@id("guardrail-max-chain-depth")
forbid (
  principal is AgentIAM::Agent,
  action,
  resource
)
when {
  context.chain_depth > context.max_chain_depth
};

// ─── Budget Enforcement ───
@id("guardrail-budget-tokens")
forbid (
  principal is AgentIAM::Agent,
  action,
  resource
)
when {
  context.remaining_tokens == 0
};

@id("guardrail-budget-cost")
forbid (
  principal is AgentIAM::Agent,
  action,
  resource
)
when {
  context.remaining_cost_cents == 0
};

@id("guardrail-budget-calls")
forbid (
  principal is AgentIAM::Agent,
  action,
  resource
)
when {
  context.remaining_calls == 0
};

// ─── Session Validity ───
@id("guardrail-session-invalid")
forbid (
  principal,
  action,
  resource
)
when {
  context.session_valid == false
};

// ─── Secret Data Protection ───
@id("guardrail-no-secret-access")
forbid (
  principal is AgentIAM::Agent,
  action,
  resource is AgentIAM::Resource
)
when {
  resource.sensitivity == "secret"
};
