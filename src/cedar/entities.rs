use std::path::Path;

use anyhow::{Context, Result};
use cedar_policy::{Entities, Entity, EntityUid, Schema};

// Used in Week 2+ when axum handlers call into cedar authorization
#[allow(dead_code)]
pub struct EntityStore {
    entities: Entities,
    schema: Schema,
}

#[allow(dead_code)]
impl EntityStore {
    pub fn new(schema: Schema) -> Self {
        Self {
            entities: Entities::empty(),
            schema,
        }
    }

    pub fn load_from_json(schema: Schema, path: &Path) -> Result<Self> {
        let json_str =
            std::fs::read_to_string(path).context("failed to read entities JSON file")?;
        let entities = Entities::from_json_str(&json_str, Some(&schema))
            .map_err(|e| anyhow::anyhow!("entities parse error: {e}"))?;
        Ok(Self { entities, schema })
    }

    pub fn entities(&self) -> &Entities {
        &self.entities
    }

    pub fn upsert(&mut self, new_entities: impl IntoIterator<Item = Entity>) -> Result<()> {
        self.entities = self
            .entities
            .clone()
            .upsert_entities(new_entities, Some(&self.schema))
            .map_err(|e| anyhow::anyhow!("upsert error: {e}"))?;
        Ok(())
    }

    pub fn get(&self, uid: &EntityUid) -> Option<&Entity> {
        self.entities.get(uid)
    }

    pub fn delete(&mut self, uid: EntityUid) -> Result<()> {
        self.entities = self
            .entities
            .clone()
            .remove_entities([uid])
            .map_err(|e| anyhow::anyhow!("delete error: {e}"))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cedar_policy::EntityUid;
    use std::path::PathBuf;
    use std::str::FromStr;

    fn project_root() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
    }

    fn load_schema() -> Schema {
        let schema_src =
            std::fs::read_to_string(project_root().join("schemas/agentiam.cedarschema"))
                .expect("failed to read schema");
        let (schema, _) =
            Schema::from_cedarschema_str(&schema_src).expect("failed to parse schema");
        schema
    }

    fn make_user_entity(id: &str) -> Entity {
        let json = serde_json::json!({
            "uid": { "type": "AgentIAM::User", "id": id },
            "attrs": {
                "email": format!("{id}@example.com"),
                "role": "admin",
                "mfa_enabled": true,
                "suspended": false
            },
            "parents": []
        });
        Entity::from_json_value(json, Some(&load_schema())).expect("failed to create entity")
    }

    fn uid(entity_type: &str, id: &str) -> EntityUid {
        EntityUid::from_str(&format!("AgentIAM::{entity_type}::\"{id}\""))
            .expect("failed to parse uid")
    }

    #[test]
    fn test_new_creates_empty_store() {
        let store = EntityStore::new(load_schema());
        assert!(store.entities().is_empty());
    }

    #[test]
    fn test_upsert_adds_entity() {
        let mut store = EntityStore::new(load_schema());
        store.upsert([make_user_entity("alice")]).unwrap();
        assert!(store.get(&uid("User", "alice")).is_some());
    }

    #[test]
    fn test_get_returns_none_for_missing() {
        let store = EntityStore::new(load_schema());
        assert!(store.get(&uid("User", "nonexistent")).is_none());
    }

    #[test]
    fn test_get_returns_entity() {
        let mut store = EntityStore::new(load_schema());
        store.upsert([make_user_entity("bob")]).unwrap();
        let entity = store.get(&uid("User", "bob")).unwrap();
        assert_eq!(entity.uid(), uid("User", "bob"));
    }

    #[test]
    fn test_upsert_overwrites_existing() {
        let schema = load_schema();
        let mut store = EntityStore::new(schema.clone());
        store.upsert([make_user_entity("alice")]).unwrap();

        // Upsert same uid with different attrs
        let updated = serde_json::json!({
            "uid": { "type": "AgentIAM::User", "id": "alice" },
            "attrs": {
                "email": "newalice@example.com",
                "role": "viewer",
                "mfa_enabled": false,
                "suspended": true
            },
            "parents": []
        });
        let updated_entity =
            Entity::from_json_value(updated, Some(&schema)).expect("failed to create entity");
        store.upsert([updated_entity]).unwrap();

        // Should still have the entity (overwritten)
        assert!(store.get(&uid("User", "alice")).is_some());
    }

    #[test]
    fn test_upsert_multiple_entities() {
        let mut store = EntityStore::new(load_schema());
        store
            .upsert([make_user_entity("alice"), make_user_entity("bob")])
            .unwrap();
        assert!(store.get(&uid("User", "alice")).is_some());
        assert!(store.get(&uid("User", "bob")).is_some());
    }

    #[test]
    fn test_delete_removes_entity() {
        let mut store = EntityStore::new(load_schema());
        store.upsert([make_user_entity("alice")]).unwrap();
        store.delete(uid("User", "alice")).unwrap();
        assert!(store.get(&uid("User", "alice")).is_none());
    }

    #[test]
    fn test_delete_nonexistent_succeeds() {
        let mut store = EntityStore::new(load_schema());
        // Deleting a non-existent entity should not error
        let result = store.delete(uid("User", "ghost"));
        assert!(result.is_ok());
    }

    #[test]
    fn test_entities_returns_full_collection() {
        let mut store = EntityStore::new(load_schema());
        assert!(store.entities().is_empty());

        store
            .upsert([make_user_entity("alice"), make_user_entity("bob")])
            .unwrap();
        // Entities collection should not be empty
        assert!(!store.entities().is_empty());
    }

    #[test]
    fn test_upsert_then_delete_then_upsert() {
        let mut store = EntityStore::new(load_schema());
        store.upsert([make_user_entity("alice")]).unwrap();
        store.delete(uid("User", "alice")).unwrap();
        assert!(store.get(&uid("User", "alice")).is_none());

        // Re-add
        store.upsert([make_user_entity("alice")]).unwrap();
        assert!(store.get(&uid("User", "alice")).is_some());
    }

    #[test]
    fn test_load_from_json() {
        let schema = load_schema();
        let entities_path = project_root().join("test_entities.json");
        let json = serde_json::json!([
            {
                "uid": { "type": "AgentIAM::User", "id": "test-user" },
                "attrs": {
                    "email": "test@example.com",
                    "role": "admin",
                    "mfa_enabled": true,
                    "suspended": false
                },
                "parents": []
            }
        ]);
        std::fs::write(&entities_path, serde_json::to_string_pretty(&json).unwrap()).unwrap();
        let store = EntityStore::load_from_json(schema, &entities_path).unwrap();
        assert!(store.get(&uid("User", "test-user")).is_some());
        std::fs::remove_file(&entities_path).unwrap();
    }

    #[test]
    fn test_load_from_json_invalid_path() {
        let schema = load_schema();
        let result = EntityStore::load_from_json(schema, std::path::Path::new("/nonexistent.json"));
        assert!(result.is_err());
    }
}
