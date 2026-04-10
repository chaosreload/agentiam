use std::path::Path;

use anyhow::{Context, Result};
use cedar_policy::{Entities, Entity, EntityUid, Schema};

pub struct EntityStore {
    entities: Entities,
    schema: Schema,
}

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
