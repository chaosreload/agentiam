// Example: Delegation policies for AgentIAM
// Controls how users delegate permissions to agents

// ─── Basic Delegation ───

// Agent's permissions cannot exceed delegator's permissions
@id("delegation-scope-limit")
permit (
  principal is Agent,
  action,
  resource
)
when {
  principal.delegator in resource.allowed_users &&
  context.session_scope has action
};

// ─── Scoped Delegation — Research tasks ───

// weichao delegates web research capabilities to scout
@id("weichao-delegates-to-scout")
permit (
  principal == Agent::"research-scout",
  action in [Action::"read", Action::"list"],
  resource in Service::"web"
)
when {
  principal.delegator == User::"weichao" &&
  context.session_valid == true
};

// ─── Conditional Write Delegation ───

// Agent can write only with explicit user consent
@id("write-with-consent")
permit (
  principal is Agent,
  action in [Action::"write", Action::"create"],
  resource
)
when {
  context.user_consent == true &&
  context.session_valid == true &&
  context.remaining_budget > 0
};

// ─── High-risk requires approval ───

// Email sending requires human-in-the-loop approval
@id("email-needs-approval")
permit (
  principal is Agent,
  action == Action::"send_email",
  resource
)
when {
  context.approval_status == "approved" &&
  context.approver == principal.delegator
};
