// Example: Basic RBAC policies for AgentIAM
// Role-based access control for agents and users

// ─── Admin Full Access ───

@id("admin-full-access")
permit (
  principal in Group::"admins",
  action,
  resource
);

// ─── Research Agent — Read-only access ───

@id("research-agent-read")
permit (
  principal == Agent::"research-scout",
  action in [Action::"read", Action::"list"],
  resource
)
when {
  resource.sensitivity != "secret"
};

// ─── Coding Agent — Read + Write in sandbox ───

@id("coding-agent-sandbox")
permit (
  principal == Agent::"coding-agent",
  action in [Action::"read", Action::"list", Action::"write", Action::"create", Action::"execute_code"],
  resource
)
when {
  resource.sandbox == true
};

// ─── User owns resource — full access ───

@id("owner-full-access")
permit (
  principal is User,
  action,
  resource
)
when {
  principal == resource.owner
};
