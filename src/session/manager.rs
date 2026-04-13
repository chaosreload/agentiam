use chrono::Utc;
use dashmap::DashMap;
use sqlx::SqlitePool;

use crate::error::AgentIAMError;
use crate::models::{
    Budget, BudgetStatus, BudgetUsage, CreateSessionRequest, Session, SessionFilter,
    SessionTokenClaims,
};
use crate::session::jwt;

const DEFAULT_SESSION_TTL_SECS: i64 = 3600;
const DEFAULT_MAX_CHAIN_DEPTH: i32 = 5;

pub struct SessionManager {
    sessions: DashMap<String, Session>,
    revocation_list: DashMap<String, i64>, // session_id -> revoked_at timestamp
    db: SqlitePool,
    jwt_secret: Vec<u8>,
}

impl SessionManager {
    pub async fn new(db: SqlitePool, jwt_secret: Vec<u8>) -> Result<Self, AgentIAMError> {
        Self::ensure_table(&db).await?;
        Ok(Self {
            sessions: DashMap::new(),
            revocation_list: DashMap::new(),
            db,
            jwt_secret,
        })
    }

    async fn ensure_table(db: &SqlitePool) -> Result<(), AgentIAMError> {
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS sessions (
                session_id TEXT PRIMARY KEY,
                delegator TEXT NOT NULL,
                agent TEXT NOT NULL,
                scope TEXT NOT NULL,
                budget TEXT NOT NULL,
                max_chain_depth INTEGER NOT NULL,
                delegation_chain TEXT NOT NULL,
                metadata TEXT,
                created_at INTEGER NOT NULL,
                expires_at INTEGER NOT NULL,
                revoked INTEGER NOT NULL DEFAULT 0
            )",
        )
        .execute(db)
        .await?;
        Ok(())
    }

    pub async fn create_session(
        &self,
        req: CreateSessionRequest,
    ) -> Result<Session, AgentIAMError> {
        let session_id = uuid::Uuid::new_v4().to_string();
        let now = Utc::now().timestamp();
        let ttl = req.ttl_seconds.unwrap_or(DEFAULT_SESSION_TTL_SECS);
        let expires_at = now + ttl;
        let max_chain_depth = req.max_chain_depth.unwrap_or(DEFAULT_MAX_CHAIN_DEPTH);
        let delegation_chain = req.delegation_chain.unwrap_or_default();

        // Sign session token
        let claims = SessionTokenClaims {
            iss: "agentiam".to_string(),
            sub: req.agent.clone(),
            aud: "agentiam".to_string(),
            exp: expires_at,
            iat: now,
            jti: session_id.clone(),
            delegator: req.delegator.clone(),
            delegation_chain: delegation_chain.clone(),
            scope: req.scope.clone(),
            budget: req.budget.clone(),
            max_chain_depth,
            metadata: req.metadata.clone(),
        };
        let token = jwt::sign_session_token(&claims, &self.jwt_secret)?;

        let session = Session {
            session_id: session_id.clone(),
            delegator: req.delegator,
            agent: req.agent,
            scope: req.scope,
            budget: req.budget,
            max_chain_depth,
            delegation_chain,
            metadata: req.metadata,
            token: Some(token),
            created_at: now,
            expires_at,
            revoked: false,
        };

        // Persist to SQLite
        self.persist_session(&session).await?;

        // Cache in DashMap
        self.sessions.insert(session_id, session.clone());

        Ok(session)
    }

    pub async fn get_session(&self, session_id: &str) -> Result<Session, AgentIAMError> {
        // Check cache first
        if let Some(s) = self.sessions.get(session_id) {
            return Ok(s.value().clone());
        }

        // Fall back to DB
        let row = sqlx::query_as::<_, (String, String, String, String, String, i32, String, Option<String>, i64, i64, i64)>(
            "SELECT session_id, delegator, agent, scope, budget, max_chain_depth, delegation_chain, metadata, created_at, expires_at, revoked FROM sessions WHERE session_id = ?",
        )
        .bind(session_id)
        .fetch_optional(&self.db)
        .await?;

        match row {
            None => Err(AgentIAMError::SessionNotFound(session_id.to_string())),
            Some(r) => {
                let session = Self::row_to_session(r);
                self.sessions
                    .insert(session_id.to_string(), session.clone());
                Ok(session)
            }
        }
    }

    pub async fn list_sessions(
        &self,
        filters: SessionFilter,
    ) -> Result<Vec<Session>, AgentIAMError> {
        let mut sql = "SELECT session_id, delegator, agent, scope, budget, max_chain_depth, delegation_chain, metadata, created_at, expires_at, revoked FROM sessions WHERE 1=1".to_string();
        let mut binds: Vec<String> = Vec::new();

        if let Some(ref d) = filters.delegator {
            sql.push_str(" AND delegator = ?");
            binds.push(d.clone());
        }
        if let Some(ref a) = filters.agent {
            sql.push_str(" AND agent = ?");
            binds.push(a.clone());
        }
        if filters.active_only == Some(true) {
            sql.push_str(" AND revoked = 0");
        }
        sql.push_str(" ORDER BY created_at DESC");

        let mut query = sqlx::query_as::<
            _,
            (
                String,
                String,
                String,
                String,
                String,
                i32,
                String,
                Option<String>,
                i64,
                i64,
                i64,
            ),
        >(&sql);
        for b in &binds {
            query = query.bind(b);
        }

        let rows = query.fetch_all(&self.db).await?;
        Ok(rows.into_iter().map(Self::row_to_session).collect())
    }

    pub async fn revoke_session(&self, session_id: &str) -> Result<(), AgentIAMError> {
        let result = sqlx::query("UPDATE sessions SET revoked = 1 WHERE session_id = ?")
            .bind(session_id)
            .execute(&self.db)
            .await?;

        if result.rows_affected() == 0 {
            return Err(AgentIAMError::SessionNotFound(session_id.to_string()));
        }

        // Update cache
        if let Some(mut s) = self.sessions.get_mut(session_id) {
            s.revoked = true;
        }

        // Add to revocation list
        self.revocation_list
            .insert(session_id.to_string(), Utc::now().timestamp());

        Ok(())
    }

    pub async fn update_budget(
        &self,
        session_id: &str,
        usage: BudgetUsage,
    ) -> Result<BudgetStatus, AgentIAMError> {
        let session = self.get_session(session_id).await?;

        if session.revoked {
            return Err(AgentIAMError::SessionRevoked(session_id.to_string()));
        }

        let now = Utc::now().timestamp();
        if session.expires_at <= now {
            return Err(AgentIAMError::SessionExpired(session_id.to_string()));
        }

        // Atomic SQL update: add usage to existing budget values in a single statement
        // This avoids the read-modify-write race condition on concurrent updates.
        let updated_budget_row = sqlx::query_as::<_, (String,)>(
            "UPDATE sessions SET budget = json_set(budget,
                '$.used_tokens', json_extract(budget, '$.used_tokens') + ?,
                '$.used_cost_cents', json_extract(budget, '$.used_cost_cents') + ?,
                '$.used_calls', json_extract(budget, '$.used_calls') + ?
            ) WHERE session_id = ? RETURNING budget",
        )
        .bind(usage.tokens)
        .bind(usage.cost_cents)
        .bind(usage.calls)
        .bind(session_id)
        .fetch_one(&self.db)
        .await?;

        let budget: Budget = serde_json::from_str(&updated_budget_row.0)
            .map_err(|e| AgentIAMError::Internal(e.to_string()))?;
        let exhausted = budget.is_exhausted();

        // Update cache with the authoritative DB value
        if let Some(mut s) = self.sessions.get_mut(session_id) {
            s.budget = budget.clone();
        }

        Ok(BudgetStatus { budget, exhausted })
    }

    pub fn validate_token(&self, token: &str) -> Result<SessionTokenClaims, AgentIAMError> {
        let data = jwt::verify_token::<SessionTokenClaims>(token, &self.jwt_secret)?;
        let claims = data.claims;

        // Check revocation list
        if self.revocation_list.contains_key(&claims.jti) {
            return Err(AgentIAMError::SessionRevoked(claims.jti));
        }

        Ok(claims)
    }

    /// Clean up expired entries from the revocation list.
    pub fn cleanup_revocation_list(&self, max_age_secs: i64) {
        let cutoff = Utc::now().timestamp() - max_age_secs;
        self.revocation_list.retain(|_, ts| *ts > cutoff);
    }

    #[allow(clippy::type_complexity)]
    fn row_to_session(
        r: (
            String,
            String,
            String,
            String,
            String,
            i32,
            String,
            Option<String>,
            i64,
            i64,
            i64,
        ),
    ) -> Session {
        let scope: Vec<String> = serde_json::from_str(&r.3).unwrap_or_default();
        let budget: Budget = serde_json::from_str(&r.4).unwrap_or(Budget {
            max_tokens: 0,
            max_cost_cents: 0,
            max_calls: 0,
            used_tokens: 0,
            used_cost_cents: 0,
            used_calls: 0,
        });
        let delegation_chain: Vec<String> = serde_json::from_str(&r.6).unwrap_or_default();
        let metadata: Option<std::collections::HashMap<String, String>> =
            r.7.as_deref().and_then(|s| serde_json::from_str(s).ok());

        Session {
            session_id: r.0,
            delegator: r.1,
            agent: r.2,
            scope,
            budget,
            max_chain_depth: r.5,
            delegation_chain,
            metadata,
            token: None, // never return token from DB reads
            created_at: r.8,
            expires_at: r.9,
            revoked: r.10 != 0,
        }
    }

    async fn persist_session(&self, session: &Session) -> Result<(), AgentIAMError> {
        let scope_json = serde_json::to_string(&session.scope)
            .map_err(|e| AgentIAMError::Internal(e.to_string()))?;
        let budget_json = serde_json::to_string(&session.budget)
            .map_err(|e| AgentIAMError::Internal(e.to_string()))?;
        let chain_json = serde_json::to_string(&session.delegation_chain)
            .map_err(|e| AgentIAMError::Internal(e.to_string()))?;
        let meta_json = session
            .metadata
            .as_ref()
            .map(serde_json::to_string)
            .transpose()
            .map_err(|e| AgentIAMError::Internal(e.to_string()))?;

        sqlx::query(
            "INSERT INTO sessions (session_id, delegator, agent, scope, budget, max_chain_depth, delegation_chain, metadata, created_at, expires_at, revoked) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0)",
        )
        .bind(&session.session_id)
        .bind(&session.delegator)
        .bind(&session.agent)
        .bind(&scope_json)
        .bind(&budget_json)
        .bind(session.max_chain_depth)
        .bind(&chain_json)
        .bind(&meta_json)
        .bind(session.created_at)
        .bind(session.expires_at)
        .execute(&self.db)
        .await?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::Budget;
    use sqlx::sqlite::SqlitePoolOptions;

    const TEST_SECRET: &[u8] = b"session-manager-test-secret-key!";

    async fn setup() -> SessionManager {
        let pool = SqlitePoolOptions::new()
            .connect("sqlite::memory:")
            .await
            .unwrap();
        SessionManager::new(pool, TEST_SECRET.to_vec())
            .await
            .unwrap()
    }

    fn make_request() -> CreateSessionRequest {
        CreateSessionRequest {
            delegator: r#"AgentIAM::User::"alice""#.to_string(),
            agent: r#"AgentIAM::Agent::"scout""#.to_string(),
            scope: vec![
                r#"AgentIAM::Action::"read""#.to_string(),
                r#"AgentIAM::Action::"list""#.to_string(),
            ],
            budget: Budget {
                max_tokens: 10000,
                max_cost_cents: 5000,
                max_calls: 100,
                used_tokens: 0,
                used_cost_cents: 0,
                used_calls: 0,
            },
            max_chain_depth: Some(5),
            delegation_chain: None,
            metadata: None,
            ttl_seconds: Some(3600),
        }
    }

    #[tokio::test]
    async fn test_create_session() {
        let mgr = setup().await;
        let session = mgr.create_session(make_request()).await.unwrap();
        assert!(!session.session_id.is_empty());
        assert!(session.token.is_some());
        assert!(!session.revoked);
        assert_eq!(session.scope.len(), 2);
    }

    #[tokio::test]
    async fn test_get_session() {
        let mgr = setup().await;
        let created = mgr.create_session(make_request()).await.unwrap();
        let fetched = mgr.get_session(&created.session_id).await.unwrap();
        assert_eq!(fetched.session_id, created.session_id);
        assert_eq!(fetched.delegator, created.delegator);
        assert_eq!(fetched.agent, created.agent);
    }

    #[tokio::test]
    async fn test_get_session_not_found() {
        let mgr = setup().await;
        let result = mgr.get_session("nonexistent").await;
        assert!(matches!(result, Err(AgentIAMError::SessionNotFound(_))));
    }

    #[tokio::test]
    async fn test_list_sessions() {
        let mgr = setup().await;
        mgr.create_session(make_request()).await.unwrap();
        mgr.create_session(make_request()).await.unwrap();

        let sessions = mgr.list_sessions(SessionFilter::default()).await.unwrap();
        assert_eq!(sessions.len(), 2);
    }

    #[tokio::test]
    async fn test_list_sessions_filter_by_agent() {
        let mgr = setup().await;
        mgr.create_session(make_request()).await.unwrap();

        let mut req2 = make_request();
        req2.agent = r#"AgentIAM::Agent::"other""#.to_string();
        mgr.create_session(req2).await.unwrap();

        let filter = SessionFilter {
            agent: Some(r#"AgentIAM::Agent::"scout""#.to_string()),
            ..Default::default()
        };
        let sessions = mgr.list_sessions(filter).await.unwrap();
        assert_eq!(sessions.len(), 1);
    }

    #[tokio::test]
    async fn test_revoke_session() {
        let mgr = setup().await;
        let session = mgr.create_session(make_request()).await.unwrap();
        mgr.revoke_session(&session.session_id).await.unwrap();

        let fetched = mgr.get_session(&session.session_id).await.unwrap();
        assert!(fetched.revoked);
    }

    #[tokio::test]
    async fn test_revoke_nonexistent_session() {
        let mgr = setup().await;
        let result = mgr.revoke_session("nonexistent").await;
        assert!(matches!(result, Err(AgentIAMError::SessionNotFound(_))));
    }

    #[tokio::test]
    async fn test_validate_token() {
        let mgr = setup().await;
        let session = mgr.create_session(make_request()).await.unwrap();
        let token = session.token.unwrap();

        let claims = mgr.validate_token(&token).unwrap();
        assert_eq!(claims.jti, session.session_id);
        assert_eq!(claims.delegator, r#"AgentIAM::User::"alice""#);
    }

    #[tokio::test]
    async fn test_validate_revoked_token() {
        let mgr = setup().await;
        let session = mgr.create_session(make_request()).await.unwrap();
        let token = session.token.clone().unwrap();

        mgr.revoke_session(&session.session_id).await.unwrap();
        let result = mgr.validate_token(&token);
        assert!(matches!(result, Err(AgentIAMError::SessionRevoked(_))));
    }

    #[tokio::test]
    async fn test_update_budget() {
        let mgr = setup().await;
        let session = mgr.create_session(make_request()).await.unwrap();

        let usage = BudgetUsage {
            tokens: 500,
            cost_cents: 100,
            calls: 5,
        };
        let status = mgr.update_budget(&session.session_id, usage).await.unwrap();
        assert!(!status.exhausted);
        assert_eq!(status.budget.used_tokens, 500);
        assert_eq!(status.budget.used_cost_cents, 100);
        assert_eq!(status.budget.used_calls, 5);
    }

    #[tokio::test]
    async fn test_budget_exhaustion() {
        let mgr = setup().await;
        let session = mgr.create_session(make_request()).await.unwrap();

        let usage = BudgetUsage {
            tokens: 10000,
            cost_cents: 0,
            calls: 0,
        };
        let status = mgr.update_budget(&session.session_id, usage).await.unwrap();
        assert!(status.exhausted);
    }

    #[tokio::test]
    async fn test_update_budget_revoked_session() {
        let mgr = setup().await;
        let session = mgr.create_session(make_request()).await.unwrap();
        mgr.revoke_session(&session.session_id).await.unwrap();

        let usage = BudgetUsage {
            tokens: 1,
            cost_cents: 1,
            calls: 1,
        };
        let result = mgr.update_budget(&session.session_id, usage).await;
        assert!(matches!(result, Err(AgentIAMError::SessionRevoked(_))));
    }

    #[tokio::test]
    async fn test_list_active_only() {
        let mgr = setup().await;
        let s1 = mgr.create_session(make_request()).await.unwrap();
        mgr.create_session(make_request()).await.unwrap();
        mgr.revoke_session(&s1.session_id).await.unwrap();

        let filter = SessionFilter {
            active_only: Some(true),
            ..Default::default()
        };
        let sessions = mgr.list_sessions(filter).await.unwrap();
        assert_eq!(sessions.len(), 1);
    }

    #[tokio::test]
    async fn test_cleanup_revocation_list() {
        let mgr = setup().await;
        let session = mgr.create_session(make_request()).await.unwrap();
        mgr.revoke_session(&session.session_id).await.unwrap();
        assert!(mgr.revocation_list.contains_key(&session.session_id));

        // Cleanup with max_age=0 should remove everything
        mgr.cleanup_revocation_list(0);
        assert!(mgr.revocation_list.is_empty());
    }

    #[tokio::test]
    async fn test_session_persists_to_db() {
        let mgr = setup().await;
        let session = mgr.create_session(make_request()).await.unwrap();

        // Remove from cache
        mgr.sessions.remove(&session.session_id);
        assert!(mgr.sessions.get(&session.session_id).is_none());

        // Should fetch from DB
        let fetched = mgr.get_session(&session.session_id).await.unwrap();
        assert_eq!(fetched.session_id, session.session_id);
    }
}
