// ═══════════════════════════════════════════════════════════════════
// AgentIAM Example: Delegation Policies
// Controls how users delegate permissions to agents
// ═══════════════════════════════════════════════════════════════════

// ─── Delegation Scope Enforcement ───
// Agent can only perform actions within the session scope
// (Note: scope is pre-checked by server; this is defense-in-depth)
@id("delegation-scope-enforcement")
permit (
  principal is AgentIAM::Agent,
  action,
  resource
)
when {
  context.session_valid == true &&
  context.remaining_tokens != 0 &&
  context.remaining_calls != 0
};

// ─── Delegator Must Have Access ───
// Agent's delegator must be in the resource's allowed hierarchy
// (The agent can only access what its delegator can access)
@id("delegation-delegator-access")
permit (
  principal is AgentIAM::Agent,
  action in [AgentIAM::Action::"read", AgentIAM::Action::"list"],
  resource is AgentIAM::Resource
)
when {
  resource has owner &&
  principal.delegator == resource.owner
};

// ─── Conditional Write Delegation ───
// Agent can write ONLY with explicit user consent
@id("delegation-write-with-consent")
permit (
  principal is AgentIAM::Agent,
  action in [AgentIAM::Action::"write", AgentIAM::Action::"create", AgentIAM::Action::"update"],
  resource
)
when {
  context has user_consent &&
  context.user_consent == true &&
  context.session_valid == true
};

// ─── Email Requires Approval ───
// Email sending requires human approval to have been granted
@id("delegation-email-approved")
permit (
  principal is AgentIAM::Agent,
  action == AgentIAM::Action::"send_email",
  resource
)
when {
  context has approval_status &&
  context.approval_status == "approved"
};

// ─── Sandbox-Only Agents ───
// Agents marked as sandbox_only can ONLY access sandbox resources
@id("delegation-sandbox-only-agent")
forbid (
  principal is AgentIAM::Agent,
  action,
  resource is AgentIAM::Resource
)
when {
  principal.sandbox_only == true &&
  resource.sandbox == false
};
