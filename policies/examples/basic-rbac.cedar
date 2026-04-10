// ═══════════════════════════════════════════════════════════════════
// AgentIAM Example: Basic RBAC Policies
// ═══════════════════════════════════════════════════════════════════

// ─── Admin Full Access ───
@id("rbac-admin-full-access")
permit (
  principal is AgentIAM::User,
  action,
  resource
)
when {
  principal.role == "admin"
};

// ─── Research Agent: Read Non-Confidential Resources ───
@id("rbac-research-agent-read")
permit (
  principal == AgentIAM::Agent::"research-scout",
  action in [AgentIAM::Action::"read", AgentIAM::Action::"list", AgentIAM::Action::"search"],
  resource is AgentIAM::Resource
)
when {
  resource.sensitivity == "public" || resource.sensitivity == "internal"
};

// ─── Research Agent: Low/Medium Risk Tool Invocation ───
@id("rbac-research-agent-tools")
permit (
  principal == AgentIAM::Agent::"research-scout",
  action == AgentIAM::Action::"invoke_tool",
  resource is AgentIAM::Tool
)
when {
  resource.capability.risk == "low" || resource.capability.risk == "medium"
};

// ─── Coding Agent: Sandbox Full Access ───
@id("rbac-coding-agent-sandbox")
permit (
  principal == AgentIAM::Agent::"coding-agent",
  action,
  resource is AgentIAM::Resource
)
when {
  resource.sandbox == true
};

// ─── Resource Owner: Full Access ───
@id("rbac-owner-full-access")
permit (
  principal is AgentIAM::User,
  action,
  resource is AgentIAM::Resource
)
when {
  resource has owner && principal == resource.owner
};

// ─── Developer: Read + Write (non-production) ───
@id("rbac-developer-readwrite")
permit (
  principal is AgentIAM::User,
  action in [
    AgentIAM::Action::"read",
    AgentIAM::Action::"list",
    AgentIAM::Action::"write",
    AgentIAM::Action::"create",
    AgentIAM::Action::"update"
  ],
  resource is AgentIAM::Resource
)
when {
  principal.role == "developer" &&
  resource.environment != "production"
};
