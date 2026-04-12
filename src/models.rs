use std::collections::HashMap;

use serde::{Deserialize, Serialize};

// ── JWT Claims ──────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessTokenClaims {
    pub iss: String,
    pub sub: String,
    pub aud: String,
    pub exp: i64,
    pub iat: i64,
    pub jti: String,
    pub scope: String,
    pub agentiam: AgentIAMClaims,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentIAMClaims {
    pub client_id: String,
    pub env: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionTokenClaims {
    pub iss: String,
    pub sub: String, // Cedar entity UID of the agent
    pub aud: String,
    pub exp: i64,
    pub iat: i64,
    pub jti: String, // = session_id
    pub delegator: String,
    pub delegation_chain: Vec<String>,
    pub scope: Vec<String>,
    pub budget: Budget,
    pub max_chain_depth: i32,
    pub metadata: Option<HashMap<String, String>>,
}

// ── Budget ──────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Budget {
    pub max_tokens: i64,
    pub max_cost_cents: i64,
    pub max_calls: i64,
    pub used_tokens: i64,
    pub used_cost_cents: i64,
    pub used_calls: i64,
}

impl Budget {
    pub fn remaining_tokens(&self) -> i64 {
        self.max_tokens - self.used_tokens
    }

    pub fn remaining_cost_cents(&self) -> i64 {
        self.max_cost_cents - self.used_cost_cents
    }

    pub fn remaining_calls(&self) -> i64 {
        self.max_calls - self.used_calls
    }

    pub fn is_exhausted(&self) -> bool {
        self.remaining_tokens() <= 0
            || self.remaining_cost_cents() <= 0
            || self.remaining_calls() <= 0
    }
}

// ── Budget Usage ────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BudgetUsage {
    pub tokens: i64,
    pub cost_cents: i64,
    pub calls: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BudgetStatus {
    pub budget: Budget,
    pub exhausted: bool,
}

// ── Session ─────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    pub session_id: String,
    pub delegator: String,
    pub agent: String,
    pub scope: Vec<String>,
    pub budget: Budget,
    pub max_chain_depth: i32,
    pub delegation_chain: Vec<String>,
    pub metadata: Option<HashMap<String, String>>,
    pub token: Option<String>,
    pub created_at: i64,
    pub expires_at: i64,
    pub revoked: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateSessionRequest {
    pub delegator: String,
    pub agent: String,
    pub scope: Vec<String>,
    pub budget: Budget,
    pub max_chain_depth: Option<i32>,
    pub delegation_chain: Option<Vec<String>>,
    pub metadata: Option<HashMap<String, String>>,
    pub ttl_seconds: Option<i64>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SessionFilter {
    pub delegator: Option<String>,
    pub agent: Option<String>,
    pub active_only: Option<bool>,
}

// ── API Key ─────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiKeyInfo {
    pub id: String,
    pub name: String,
    pub env: String,
    pub created_at: i64,
    pub revoked: bool,
}

// ── OAuth ───────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuthClient {
    pub client_id: String,
    pub client_secret_hash: String,
    pub name: String,
    pub scopes: Vec<String>,
    pub created_at: i64,
    pub revoked: bool,
}

pub const OAUTH_SCOPES: &[&str] = &[
    "authorize",
    "sessions:read",
    "sessions:write",
    "entities:read",
    "entities:write",
    "policies:read",
    "policies:write",
    "audit:read",
    "api-keys:manage",
    "admin",
];
