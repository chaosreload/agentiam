use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;

use crate::audit::logger::AuditRecord;
use crate::error::AgentIAMError;

#[derive(Debug, Default, Deserialize)]
pub struct AuditQuery {
    pub agent: Option<String>,
    pub action: Option<String>,
    pub decision: Option<String>,
    pub session_id: Option<String>,
    pub from: Option<String>,
    pub to: Option<String>,
    pub limit: Option<i64>,
    pub cursor: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct AuditStats {
    pub total_decisions: i64,
    pub allow_count: i64,
    pub deny_count: i64,
}

pub async fn query_decisions(
    db: &SqlitePool,
    q: &AuditQuery,
) -> Result<Vec<AuditRecord>, AgentIAMError> {
    let limit = q.limit.unwrap_or(50).min(500);
    let mut sql = String::from(
        "SELECT id, timestamp, session_id, principal, action, resource_type, resource_id, decision, reason, policies_evaluated, evaluation_time_us, context_snapshot FROM audit_decisions WHERE 1=1",
    );
    let mut binds: Vec<String> = Vec::new();

    if let Some(ref agent) = q.agent {
        sql.push_str(" AND principal LIKE ?");
        binds.push(format!("%{agent}%"));
    }
    if let Some(ref action) = q.action {
        sql.push_str(" AND action LIKE ?");
        binds.push(action.replace('*', "%"));
    }
    if let Some(ref decision) = q.decision {
        sql.push_str(" AND decision = ?");
        binds.push(decision.clone());
    }
    if let Some(ref sid) = q.session_id {
        sql.push_str(" AND session_id = ?");
        binds.push(sid.clone());
    }
    if let Some(ref from) = q.from {
        sql.push_str(" AND timestamp >= ?");
        binds.push(from.clone());
    }
    if let Some(ref to) = q.to {
        sql.push_str(" AND timestamp <= ?");
        binds.push(to.clone());
    }
    if let Some(ref cursor) = q.cursor {
        sql.push_str(" AND id > ?");
        binds.push(cursor.clone());
    }
    sql.push_str(" ORDER BY timestamp DESC LIMIT ?");

    let mut query = sqlx::query_as::<
        _,
        (
            String,
            String,
            String,
            String,
            String,
            String,
            String,
            String,
            String,
            i64,
            i64,
            Option<String>,
        ),
    >(&sql);
    for b in &binds {
        query = query.bind(b);
    }
    query = query.bind(limit);

    let rows = query.fetch_all(db).await?;
    Ok(rows
        .into_iter()
        .map(|r| AuditRecord {
            id: r.0,
            timestamp: r.1,
            session_id: r.2,
            principal: r.3,
            action: r.4,
            resource_type: r.5,
            resource_id: r.6,
            decision: r.7,
            reason: r.8,
            policies_evaluated: r.9,
            evaluation_time_us: r.10,
            context_snapshot: r.11.and_then(|s| serde_json::from_str(&s).ok()),
        })
        .collect())
}

pub async fn get_decision(db: &SqlitePool, id: &str) -> Result<AuditRecord, AgentIAMError> {
    let row = sqlx::query_as::<
        _,
        (
            String,
            String,
            String,
            String,
            String,
            String,
            String,
            String,
            String,
            i64,
            i64,
            Option<String>,
        ),
    >(
        "SELECT id, timestamp, session_id, principal, action, resource_type, resource_id, decision, reason, policies_evaluated, evaluation_time_us, context_snapshot FROM audit_decisions WHERE id = ?",
    )
    .bind(id)
    .fetch_optional(db)
    .await?;

    match row {
        None => Err(AgentIAMError::Internal(format!(
            "audit record not found: {id}"
        ))),
        Some(r) => Ok(AuditRecord {
            id: r.0,
            timestamp: r.1,
            session_id: r.2,
            principal: r.3,
            action: r.4,
            resource_type: r.5,
            resource_id: r.6,
            decision: r.7,
            reason: r.8,
            policies_evaluated: r.9,
            evaluation_time_us: r.10,
            context_snapshot: r.11.and_then(|s| serde_json::from_str(&s).ok()),
        }),
    }
}

#[derive(Debug, Default, Deserialize)]
pub struct StatsQuery {
    pub from: Option<String>,
    pub to: Option<String>,
    pub agent: Option<String>,
    pub session_id: Option<String>,
}

pub async fn get_stats(db: &SqlitePool, q: &StatsQuery) -> Result<AuditStats, AgentIAMError> {
    let mut sql = String::from(
        "SELECT COUNT(*), COALESCE(SUM(CASE WHEN decision='ALLOW' THEN 1 ELSE 0 END),0), COALESCE(SUM(CASE WHEN decision='DENY' THEN 1 ELSE 0 END),0) FROM audit_decisions WHERE 1=1",
    );
    let mut binds: Vec<String> = Vec::new();

    if let Some(ref agent) = q.agent {
        sql.push_str(" AND principal LIKE ?");
        binds.push(format!("%{agent}%"));
    }
    if let Some(ref sid) = q.session_id {
        sql.push_str(" AND session_id = ?");
        binds.push(sid.clone());
    }
    if let Some(ref from) = q.from {
        sql.push_str(" AND timestamp >= ?");
        binds.push(from.clone());
    }
    if let Some(ref to) = q.to {
        sql.push_str(" AND timestamp <= ?");
        binds.push(to.clone());
    }

    let mut query = sqlx::query_as::<_, (i64, i64, i64)>(&sql);
    for b in &binds {
        query = query.bind(b);
    }

    let (total, allow, deny) = query.fetch_one(db).await?;
    Ok(AuditStats {
        total_decisions: total,
        allow_count: allow,
        deny_count: deny,
    })
}
