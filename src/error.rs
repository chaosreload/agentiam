use thiserror::Error;

#[derive(Debug, Error)]
#[allow(dead_code)]
pub enum AgentIAMError {
    #[error("JWT error: {0}")]
    Jwt(#[from] jsonwebtoken::errors::Error),

    #[error("token expired")]
    TokenExpired,

    #[error("invalid token: {0}")]
    InvalidToken(String),

    #[error("invalid API key")]
    InvalidApiKey,

    #[error("API key revoked")]
    ApiKeyRevoked,

    #[error("OAuth error: {0}")]
    OAuthError(String),

    #[error("invalid client credentials")]
    InvalidClientCredentials,

    #[error("invalid scope: {0}")]
    InvalidScope(String),

    #[error("session not found: {0}")]
    SessionNotFound(String),

    #[error("session revoked: {0}")]
    SessionRevoked(String),

    #[error("session expired: {0}")]
    SessionExpired(String),

    #[error("budget exhausted: {0}")]
    BudgetExhausted(String),

    #[error("scope violation: {0}")]
    ScopeViolation(String),

    #[error("database error: {0}")]
    Database(#[from] sqlx::Error),

    #[error("{0}")]
    Internal(String),
}
