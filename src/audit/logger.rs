use chrono::Utc;
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;

use crate::error::AgentIAMError;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditRecord {
    pub id: String,
    pub timestamp: String,
    pub session_id: String,
    pub principal: String,
    pub action: String,
    pub resource_type: String,
    pub resource_id: String,
    pub decision: String,
    pub reason: String,
    pub policies_evaluated: i64,
    pub evaluation_time_us: i64,
    pub context_snapshot: Option<serde_json::Value>,
}

pub struct AuditLogger {
    db: SqlitePool,
}

impl AuditLogger {
    pub async fn new(db: SqlitePool) -> Result<Self, AgentIAMError> {
        Self::ensure_table(&db).await?;
        Ok(Self { db })
    }

    async fn ensure_table(db: &SqlitePool) -> Result<(), AgentIAMError> {
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS audit_decisions (
                id TEXT PRIMARY KEY,
                timestamp TEXT NOT NULL,
                session_id TEXT NOT NULL,
                principal TEXT NOT NULL,
                action TEXT NOT NULL,
                resource_type TEXT NOT NULL,
                resource_id TEXT NOT NULL,
                decision TEXT NOT NULL,
                reason TEXT NOT NULL,
                policies_evaluated INTEGER NOT NULL,
                evaluation_time_us INTEGER NOT NULL,
                context_snapshot TEXT
            )",
        )
        .execute(db)
        .await?;
        Ok(())
    }

    pub async fn log(&self, record: &AuditRecord) -> Result<(), AgentIAMError> {
        let ctx_json = record.context_snapshot.as_ref().map(|v| v.to_string());

        sqlx::query(
            "INSERT INTO audit_decisions (id, timestamp, session_id, principal, action, resource_type, resource_id, decision, reason, policies_evaluated, evaluation_time_us, context_snapshot)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(&record.id)
        .bind(&record.timestamp)
        .bind(&record.session_id)
        .bind(&record.principal)
        .bind(&record.action)
        .bind(&record.resource_type)
        .bind(&record.resource_id)
        .bind(&record.decision)
        .bind(&record.reason)
        .bind(record.policies_evaluated)
        .bind(record.evaluation_time_us)
        .bind(&ctx_json)
        .execute(&self.db)
        .await?;
        Ok(())
    }

    pub fn new_record_id() -> String {
        format!("aud_{}", uuid::Uuid::new_v4())
    }

    pub fn now_iso() -> String {
        Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
    }

    pub fn pool(&self) -> &SqlitePool {
        &self.db
    }
}
