use std::path::Path;
use std::str::FromStr;

use anyhow::{Context, Result};
use cedar_policy::{
    Authorizer, Entities, EntityUid, PolicySet, Request, Schema, ValidationMode,
    ValidationResult, Validator,
};

// Used in Week 2+ when axum handlers list policies
#[allow(dead_code)]
pub struct PolicyInfo {
    pub id: String,
}

// Used in Week 2+ as the core authorization engine behind axum handlers.
// Thread safety: is_authorized takes &self (concurrent reads OK), but reload takes &mut self.
// Week 3 axum integration should wrap in Arc<RwLock<CedarEngine>>.
#[allow(dead_code)]
pub struct CedarEngine {
    policy_set: PolicySet,
    schema: Schema,
    authorizer: Authorizer,
    validator: Validator,
}

#[allow(dead_code)]
impl CedarEngine {
    pub fn new(schema_path: &Path, policies_dir: &Path) -> Result<Self> {
        let schema_src =
            std::fs::read_to_string(schema_path).context("failed to read Cedar schema")?;
        let (schema, _warnings) = Schema::from_cedarschema_str(&schema_src)
            .map_err(|e| anyhow::anyhow!("schema parse error: {e}"))?;

        let policy_set = Self::load_policies(policies_dir)?;
        let validator = Validator::new(schema.clone());
        let authorizer = Authorizer::new();

        Ok(Self {
            policy_set,
            schema,
            authorizer,
            validator,
        })
    }

    pub fn schema(&self) -> &Schema {
        &self.schema
    }

    pub fn is_authorized(&self, request: &Request, entities: &Entities) -> cedar_policy::Response {
        self.authorizer
            .is_authorized(request, &self.policy_set, entities)
    }

    pub fn reload(&mut self, policies_dir: &Path) -> Result<()> {
        let new_policies = Self::load_policies(policies_dir)?;
        self.policy_set = new_policies;
        Ok(())
    }

    pub fn validate_policy(&self, policy_text: &str) -> Result<ValidationResult> {
        let pset: PolicySet = policy_text
            .parse()
            .map_err(|e| anyhow::anyhow!("policy parse error: {e}"))?;
        Ok(self.validator.validate(&pset, ValidationMode::Strict))
    }

    pub fn list_policies(&self) -> Vec<PolicyInfo> {
        self.policy_set
            .policies()
            .map(|p| PolicyInfo {
                id: p.id().to_string(),
            })
            .collect()
    }

    fn load_policies(dir: &Path) -> Result<PolicySet> {
        let mut combined = String::new();
        Self::collect_cedar_files(dir, &mut combined)?;
        let pset: PolicySet = combined
            .parse()
            .map_err(|e| anyhow::anyhow!("policy parse error: {e}"))?;
        Ok(pset)
    }

    fn collect_cedar_files(dir: &Path, buf: &mut String) -> Result<()> {
        if !dir.is_dir() {
            return Ok(());
        }
        let mut entries: Vec<_> = std::fs::read_dir(dir)
            .with_context(|| format!("failed to read dir: {}", dir.display()))?
            .filter_map(|e| e.ok())
            .collect();
        entries.sort_by_key(|e| e.file_name());

        for entry in entries {
            let path = entry.path();
            if path.is_dir() {
                Self::collect_cedar_files(&path, buf)?;
            } else if path.extension().is_some_and(|ext| ext == "cedar") {
                let content =
                    std::fs::read_to_string(&path).with_context(|| {
                        format!("failed to read policy: {}", path.display())
                    })?;
                buf.push_str(&content);
                buf.push('\n');
            }
        }
        Ok(())
    }
}

// Used in Week 2+ by request handlers to parse entity UIDs from API input
#[allow(dead_code)]
pub fn parse_entity_uid(s: &str) -> Result<EntityUid> {
    EntityUid::from_str(s).map_err(|e| anyhow::anyhow!("invalid entity UID '{s}': {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use cedar_policy::{Context, Decision};
    use std::path::PathBuf;

    fn project_root() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
    }

    fn make_engine() -> CedarEngine {
        CedarEngine::new(
            &project_root().join("schemas/agentiam.cedarschema"),
            &project_root().join("policies"),
        )
        .expect("failed to create engine")
    }

    fn make_context(json: serde_json::Value, action: &EntityUid, schema: &Schema) -> Context {
        Context::from_json_value(json, Some((schema, action))).expect("failed to create context")
    }

    fn valid_session_context() -> serde_json::Value {
        serde_json::json!({
            "session_id": "sess-001",
            "session_valid": true,
            "delegator_id": "user-alice",
            "scope": ["AgentIAM::Action::\"read\"", "AgentIAM::Action::\"list\""],
            "remaining_tokens": 1000,
            "remaining_cost_cents": 5000,
            "remaining_calls": 100,
            "chain_depth": 1,
            "max_chain_depth": 5
        })
    }

    fn make_entities(schema: &Schema) -> Entities {
        let json = serde_json::json!([
            {
                "uid": { "type": "AgentIAM::User", "id": "alice" },
                "attrs": {
                    "email": "alice@example.com",
                    "role": "admin",
                    "mfa_enabled": true,
                    "suspended": false
                },
                "parents": []
            },
            {
                "uid": { "type": "AgentIAM::Agent", "id": "research-scout" },
                "attrs": {
                    "delegator": { "__entity": { "type": "AgentIAM::User", "id": "alice" } },
                    "framework": "langchain",
                    "risk_level": "low",
                    "banned": false,
                    "sandbox_only": false
                },
                "parents": []
            },
            {
                "uid": { "type": "AgentIAM::Agent", "id": "banned-agent" },
                "attrs": {
                    "delegator": { "__entity": { "type": "AgentIAM::User", "id": "alice" } },
                    "framework": "custom",
                    "risk_level": "high",
                    "banned": true,
                    "sandbox_only": false
                },
                "parents": []
            },
            {
                "uid": { "type": "AgentIAM::Resource", "id": "public-doc" },
                "attrs": {
                    "sensitivity": "public",
                    "environment": "development",
                    "sandbox": false,
                    "private": false
                },
                "parents": []
            },
            {
                "uid": { "type": "AgentIAM::Resource", "id": "secret-doc" },
                "attrs": {
                    "sensitivity": "secret",
                    "environment": "production",
                    "sandbox": false,
                    "private": true
                },
                "parents": []
            }
        ]);
        Entities::from_json_value(json, Some(schema)).expect("failed to create entities")
    }

    #[test]
    fn test_engine_loads_schema_and_policies() {
        let engine = make_engine();
        let policies = engine.list_policies();
        assert!(!policies.is_empty(), "should load at least one policy");
    }

    #[test]
    fn test_permit_agent_read_public_resource() {
        let engine = make_engine();
        let entities = make_entities(engine.schema());
        let action = parse_entity_uid(r#"AgentIAM::Action::"read""#).unwrap();
        let ctx = make_context(valid_session_context(), &action, engine.schema());
        let request = Request::new(
            parse_entity_uid(r#"AgentIAM::Agent::"research-scout""#).unwrap(),
            action,
            parse_entity_uid(r#"AgentIAM::Resource::"public-doc""#).unwrap(),
            ctx,
            Some(engine.schema()),
        )
        .unwrap();

        let response = engine.is_authorized(&request, &entities);
        assert_eq!(
            response.decision(),
            Decision::Allow,
            "research-scout should be allowed to read public resource"
        );
    }

    #[test]
    fn test_forbid_banned_agent() {
        let engine = make_engine();
        let entities = make_entities(engine.schema());
        let action = parse_entity_uid(r#"AgentIAM::Action::"read""#).unwrap();
        let ctx = make_context(valid_session_context(), &action, engine.schema());
        let request = Request::new(
            parse_entity_uid(r#"AgentIAM::Agent::"banned-agent""#).unwrap(),
            action,
            parse_entity_uid(r#"AgentIAM::Resource::"public-doc""#).unwrap(),
            ctx,
            Some(engine.schema()),
        )
        .unwrap();

        let response = engine.is_authorized(&request, &entities);
        assert_eq!(
            response.decision(),
            Decision::Deny,
            "banned agent must be denied (guardrail-banned-agent)"
        );
    }

    #[test]
    fn test_default_deny_no_matching_policy() {
        let engine = make_engine();
        let _entities = make_entities(engine.schema());
        let action = parse_entity_uid(r#"AgentIAM::Action::"read""#).unwrap();
        // Use an agent that has no permit policies matching
        let unknown_agent_json = serde_json::json!([
            {
                "uid": { "type": "AgentIAM::Agent", "id": "unknown-agent" },
                "attrs": {
                    "delegator": { "__entity": { "type": "AgentIAM::User", "id": "alice" } },
                    "framework": "custom",
                    "risk_level": "low",
                    "banned": false,
                    "sandbox_only": false
                },
                "parents": []
            },
            {
                "uid": { "type": "AgentIAM::User", "id": "alice" },
                "attrs": {
                    "email": "alice@example.com",
                    "role": "viewer",
                    "mfa_enabled": false,
                    "suspended": false
                },
                "parents": []
            },
            {
                "uid": { "type": "AgentIAM::Resource", "id": "internal-doc" },
                "attrs": {
                    "sensitivity": "confidential",
                    "environment": "production",
                    "sandbox": false,
                    "private": true
                },
                "parents": []
            }
        ]);
        // Use invalid session so the delegation-scope-enforcement permit doesn't fire
        let mut ctx_json = valid_session_context();
        ctx_json["session_valid"] = serde_json::json!(false);
        let entities =
            Entities::from_json_value(unknown_agent_json, Some(engine.schema())).unwrap();
        let ctx = make_context(ctx_json, &action, engine.schema());
        let request = Request::new(
            parse_entity_uid(r#"AgentIAM::Agent::"unknown-agent""#).unwrap(),
            action,
            parse_entity_uid(r#"AgentIAM::Resource::"internal-doc""#).unwrap(),
            ctx,
            Some(engine.schema()),
        )
        .unwrap();

        let response = engine.is_authorized(&request, &entities);
        assert_eq!(
            response.decision(),
            Decision::Deny,
            "unknown agent with invalid session should be denied by default"
        );
    }

    #[test]
    fn test_schema_validation_rejects_bad_policy() {
        let engine = make_engine();
        // This policy references a non-existent attribute
        let bad_policy = r#"
        permit(
            principal is AgentIAM::Agent,
            action == AgentIAM::Action::"read",
            resource is AgentIAM::Resource
        ) when {
            principal.nonexistent_attr == "foo"
        };
        "#;
        let result = engine.validate_policy(bad_policy).unwrap();
        assert!(
            !result.validation_passed(),
            "policy referencing nonexistent attribute should fail validation"
        );
    }

    #[test]
    fn test_schema_validation_accepts_good_policy() {
        let engine = make_engine();
        let good_policy = r#"
        @id("test-good")
        permit(
            principal is AgentIAM::Agent,
            action == AgentIAM::Action::"read",
            resource is AgentIAM::Resource
        ) when {
            resource.sensitivity == "public"
        };
        "#;
        let result = engine.validate_policy(good_policy).unwrap();
        assert!(
            result.validation_passed(),
            "valid policy should pass validation: {:?}",
            result
                .validation_errors()
                .map(|e| e.to_string())
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn test_chain_depth_exceeded_deny() {
        let engine = make_engine();
        let entities = make_entities(engine.schema());
        let action = parse_entity_uid(r#"AgentIAM::Action::"read""#).unwrap();
        let mut ctx_json = valid_session_context();
        ctx_json["chain_depth"] = serde_json::json!(10);
        ctx_json["max_chain_depth"] = serde_json::json!(5);
        let ctx = make_context(ctx_json, &action, engine.schema());
        let request = Request::new(
            parse_entity_uid(r#"AgentIAM::Agent::"research-scout""#).unwrap(),
            action,
            parse_entity_uid(r#"AgentIAM::Resource::"public-doc""#).unwrap(),
            ctx,
            Some(engine.schema()),
        )
        .unwrap();

        let response = engine.is_authorized(&request, &entities);
        assert_eq!(
            response.decision(),
            Decision::Deny,
            "chain_depth > max_chain_depth should be denied"
        );
    }

    #[test]
    fn test_budget_tokens_exhausted_deny() {
        let engine = make_engine();
        let entities = make_entities(engine.schema());
        let action = parse_entity_uid(r#"AgentIAM::Action::"read""#).unwrap();
        let mut ctx_json = valid_session_context();
        ctx_json["remaining_tokens"] = serde_json::json!(0);
        let ctx = make_context(ctx_json, &action, engine.schema());
        let request = Request::new(
            parse_entity_uid(r#"AgentIAM::Agent::"research-scout""#).unwrap(),
            action,
            parse_entity_uid(r#"AgentIAM::Resource::"public-doc""#).unwrap(),
            ctx,
            Some(engine.schema()),
        )
        .unwrap();

        let response = engine.is_authorized(&request, &entities);
        assert_eq!(
            response.decision(),
            Decision::Deny,
            "remaining_tokens == 0 should be denied"
        );
    }

    #[test]
    fn test_guardrail_forbid_overrides_permit() {
        // Even though delegation-scope-enforcement would permit,
        // the guardrail for secret data should deny
        let engine = make_engine();
        let entities = make_entities(engine.schema());
        let action = parse_entity_uid(r#"AgentIAM::Action::"read""#).unwrap();
        let ctx = make_context(valid_session_context(), &action, engine.schema());
        let request = Request::new(
            parse_entity_uid(r#"AgentIAM::Agent::"research-scout""#).unwrap(),
            action,
            parse_entity_uid(r#"AgentIAM::Resource::"secret-doc""#).unwrap(),
            ctx,
            Some(engine.schema()),
        )
        .unwrap();

        let response = engine.is_authorized(&request, &entities);
        assert_eq!(
            response.decision(),
            Decision::Deny,
            "guardrail-no-secret-access should deny even when other policies permit"
        );
    }

    #[test]
    fn test_reload_policies() {
        let mut engine = make_engine();
        let count_before = engine.list_policies().len();
        // Reload should succeed and maintain policy count
        engine
            .reload(&project_root().join("policies"))
            .expect("reload should succeed");
        let count_after = engine.list_policies().len();
        assert_eq!(count_before, count_after);
    }

    #[test]
    fn test_is_authorized_empty_entities_invalid_session_denies() {
        let engine = make_engine();
        let action = parse_entity_uid(r#"AgentIAM::Action::"read""#).unwrap();
        let mut ctx_json = valid_session_context();
        ctx_json["session_valid"] = serde_json::json!(false);
        let ctx = make_context(ctx_json, &action, engine.schema());
        let request = Request::new(
            parse_entity_uid(r#"AgentIAM::Agent::"ghost""#).unwrap(),
            action,
            parse_entity_uid(r#"AgentIAM::Resource::"nothing""#).unwrap(),
            ctx,
            Some(engine.schema()),
        )
        .unwrap();

        let response = engine.is_authorized(&request, &Entities::empty());
        assert_eq!(
            response.decision(),
            Decision::Deny,
            "empty entity store with invalid session should deny"
        );
    }

    #[test]
    fn test_parse_entity_uid_valid() {
        let uid = parse_entity_uid(r#"AgentIAM::User::"alice""#);
        assert!(uid.is_ok());
    }

    #[test]
    fn test_parse_entity_uid_invalid() {
        let uid = parse_entity_uid("not a valid uid!!!");
        assert!(uid.is_err());
    }

    #[test]
    fn test_validate_policy_unparseable() {
        let engine = make_engine();
        let result = engine.validate_policy("this is not cedar policy syntax {{{");
        assert!(result.is_err(), "unparseable policy text should return Err");
    }

    #[test]
    fn test_reload_nonexistent_dir_is_empty() {
        let mut engine = make_engine();
        // Reloading from a non-existent directory yields an empty policy set
        engine
            .reload(Path::new("/tmp/nonexistent_policies_dir_agentiam"))
            .expect("reload from nonexistent dir should succeed (empty)");
        assert!(
            engine.list_policies().is_empty(),
            "reloading from nonexistent dir should yield empty policy set"
        );
    }
}
