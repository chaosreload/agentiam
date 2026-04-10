use std::path::Path;
use std::str::FromStr;

use anyhow::{Context, Result};
use cedar_policy::{
    Authorizer, Entities, EntityUid, PolicySet, Request, Schema, ValidationMode,
    ValidationResult, Validator,
};

pub struct PolicyInfo {
    pub id: String,
}

pub struct CedarEngine {
    policy_set: PolicySet,
    schema: Schema,
    authorizer: Authorizer,
    validator: Validator,
}

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

pub fn parse_entity_uid(s: &str) -> Result<EntityUid> {
    EntityUid::from_str(s).map_err(|e| anyhow::anyhow!("invalid entity UID '{s}': {e}"))
}
