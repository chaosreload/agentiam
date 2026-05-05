use chrono::Utc;
use rand::Rng;
use sha2::{Digest, Sha256};
use sqlx::SqlitePool;

use crate::error::AgentIAMError;
use crate::models::{AccessTokenClaims, AgentIAMClaims, OAUTH_SCOPES, OAuthClient};
use crate::session::jwt;

/// Access token TTL in seconds (1 hour).
pub const OAUTH_ACCESS_TOKEN_TTL_SECONDS: i64 = 3600;

/// Create the oauth_clients table if it doesn't exist.
pub async fn ensure_table(db: &SqlitePool) -> Result<(), AgentIAMError> {
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS oauth_clients (
            client_id TEXT PRIMARY KEY,
            client_secret_hash TEXT NOT NULL,
            name TEXT NOT NULL,
            scopes TEXT NOT NULL,
            created_at INTEGER NOT NULL,
            revoked INTEGER NOT NULL DEFAULT 0
        )",
    )
    .execute(db)
    .await?;
    Ok(())
}

fn random_hex(len: usize) -> String {
    let bytes: Vec<u8> = (0..len).map(|_| rand::rng().random()).collect();
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn hash_secret(secret: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(secret.as_bytes());
    format!("{:x}", hasher.finalize())
}

/// Validate that all requested scopes are in the allowed set.
pub fn validate_scopes(scopes: &[String]) -> Result<(), AgentIAMError> {
    for s in scopes {
        if !OAUTH_SCOPES.contains(&s.as_str()) {
            return Err(AgentIAMError::InvalidScope(s.clone()));
        }
    }
    Ok(())
}

/// Register a new OAuth client. Returns the client with the plaintext secret.
pub async fn register_client(
    db: &SqlitePool,
    name: &str,
    scopes: Vec<String>,
) -> Result<(OAuthClient, String), AgentIAMError> {
    validate_scopes(&scopes)?;

    let client_id = format!("iam_{}", random_hex(16));
    let client_secret = format!("secret_{}", random_hex(24));
    let secret_hash = hash_secret(&client_secret);
    let now = Utc::now().timestamp();
    let scopes_json =
        serde_json::to_string(&scopes).map_err(|e| AgentIAMError::Internal(e.to_string()))?;

    sqlx::query(
        "INSERT INTO oauth_clients (client_id, client_secret_hash, name, scopes, created_at, revoked) VALUES (?, ?, ?, ?, ?, 0)",
    )
    .bind(&client_id)
    .bind(&secret_hash)
    .bind(name)
    .bind(&scopes_json)
    .bind(now)
    .execute(db)
    .await?;

    let client = OAuthClient {
        client_id,
        client_secret_hash: secret_hash,
        name: name.to_string(),
        scopes,
        created_at: now,
        revoked: false,
    };
    Ok((client, client_secret))
}

/// Authenticate a client using client_id + client_secret.
pub async fn authenticate_client(
    db: &SqlitePool,
    client_id: &str,
    client_secret: &str,
) -> Result<OAuthClient, AgentIAMError> {
    let secret_hash = hash_secret(client_secret);

    let row = sqlx::query_as::<_, (String, String, String, i64, i64)>(
        "SELECT client_id, name, scopes, created_at, revoked FROM oauth_clients WHERE client_id = ? AND client_secret_hash = ?",
    )
    .bind(client_id)
    .bind(&secret_hash)
    .fetch_optional(db)
    .await?;

    match row {
        None => Err(AgentIAMError::InvalidClientCredentials),
        Some((cid, name, scopes_json, created_at, revoked)) => {
            if revoked != 0 {
                return Err(AgentIAMError::OAuthError("client revoked".to_string()));
            }
            let scopes: Vec<String> = serde_json::from_str(&scopes_json)
                .map_err(|e| AgentIAMError::Internal(e.to_string()))?;
            Ok(OAuthClient {
                client_id: cid,
                client_secret_hash: secret_hash,
                name,
                scopes,
                created_at,
                revoked: false,
            })
        }
    }
}

/// Issue an access token for the authenticated client.
/// `requested_scopes` must be a subset of the client's registered scopes.
pub fn issue_access_token(
    client: &OAuthClient,
    requested_scopes: &[String],
    jwt_secret: &[u8],
    ttl_seconds: i64,
) -> Result<String, AgentIAMError> {
    // Validate requested scopes are a subset of client's scopes
    for s in requested_scopes {
        if !client.scopes.contains(s) {
            return Err(AgentIAMError::InvalidScope(format!(
                "scope '{s}' not granted to client"
            )));
        }
    }

    let now = Utc::now().timestamp();
    let claims = AccessTokenClaims {
        iss: "agentiam".to_string(),
        sub: client.client_id.clone(),
        aud: "agentiam".to_string(),
        exp: now + ttl_seconds,
        iat: now,
        jti: uuid::Uuid::new_v4().to_string(),
        scope: requested_scopes.join(" "),
        agentiam: AgentIAMClaims {
            client_id: client.client_id.clone(),
            env: "production".to_string(),
        },
    };

    jwt::sign_access_token(&claims, jwt_secret)
}

/// List all OAuth clients (without exposing secret hashes).
pub async fn list_clients(db: &SqlitePool) -> Result<Vec<OAuthClient>, AgentIAMError> {
    let rows = sqlx::query_as::<_, (String, String, String, i64, i64)>(
        "SELECT client_id, name, scopes, created_at, revoked FROM oauth_clients ORDER BY created_at DESC",
    )
    .fetch_all(db)
    .await?;

    let mut clients = Vec::with_capacity(rows.len());
    for (client_id, name, scopes_json, created_at, revoked) in rows {
        let scopes: Vec<String> = serde_json::from_str(&scopes_json)
            .map_err(|e| AgentIAMError::Internal(e.to_string()))?;
        clients.push(OAuthClient {
            client_id,
            client_secret_hash: String::new(),
            name,
            scopes,
            created_at,
            revoked: revoked != 0,
        });
    }
    Ok(clients)
}

/// Revoke an OAuth client. Returns true if a row was updated, false if not found.
pub async fn revoke_client(db: &SqlitePool, client_id: &str) -> Result<bool, AgentIAMError> {
    let result = sqlx::query("UPDATE oauth_clients SET revoked = 1 WHERE client_id = ?")
        .bind(client_id)
        .execute(db)
        .await?;
    Ok(result.rows_affected() > 0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::AccessTokenClaims;
    use sqlx::sqlite::SqlitePoolOptions;

    const JWT_SECRET: &[u8] = b"test-oauth-jwt-secret-agentiam00";

    async fn setup_db() -> SqlitePool {
        let pool = SqlitePoolOptions::new()
            .connect("sqlite::memory:")
            .await
            .unwrap();
        ensure_table(&pool).await.unwrap();
        pool
    }

    #[test]
    fn test_validate_scopes_valid() {
        let scopes = vec!["authorize".to_string(), "sessions:read".to_string()];
        assert!(validate_scopes(&scopes).is_ok());
    }

    #[test]
    fn test_validate_scopes_invalid() {
        let scopes = vec!["authorize".to_string(), "nonexistent".to_string()];
        let result = validate_scopes(&scopes);
        assert!(matches!(result, Err(AgentIAMError::InvalidScope(_))));
    }

    #[test]
    fn test_validate_scopes_all_ten() {
        let scopes: Vec<String> = OAUTH_SCOPES.iter().map(|s| s.to_string()).collect();
        assert_eq!(scopes.len(), 10);
        assert!(validate_scopes(&scopes).is_ok());
    }

    #[tokio::test]
    async fn test_register_client() {
        let db = setup_db().await;
        let scopes = vec!["authorize".to_string(), "sessions:read".to_string()];
        let (client, secret) = register_client(&db, "test-app", scopes.clone())
            .await
            .unwrap();

        assert!(client.client_id.starts_with("iam_"));
        assert!(secret.starts_with("secret_"));
        assert_eq!(client.name, "test-app");
        assert_eq!(client.scopes, scopes);
        assert!(!client.revoked);
    }

    #[tokio::test]
    async fn test_register_client_invalid_scope() {
        let db = setup_db().await;
        let scopes = vec!["bad-scope".to_string()];
        let result = register_client(&db, "bad-app", scopes).await;
        assert!(matches!(result, Err(AgentIAMError::InvalidScope(_))));
    }

    #[tokio::test]
    async fn test_authenticate_client_success() {
        let db = setup_db().await;
        let scopes = vec!["authorize".to_string()];
        let (client, secret) = register_client(&db, "auth-app", scopes).await.unwrap();

        let authed = authenticate_client(&db, &client.client_id, &secret)
            .await
            .unwrap();
        assert_eq!(authed.client_id, client.client_id);
        assert_eq!(authed.name, "auth-app");
    }

    #[tokio::test]
    async fn test_authenticate_client_wrong_secret() {
        let db = setup_db().await;
        let scopes = vec!["authorize".to_string()];
        let (client, _) = register_client(&db, "auth-app", scopes).await.unwrap();

        let result = authenticate_client(&db, &client.client_id, "wrong-secret").await;
        assert!(matches!(
            result,
            Err(AgentIAMError::InvalidClientCredentials)
        ));
    }

    #[tokio::test]
    async fn test_authenticate_client_wrong_id() {
        let db = setup_db().await;
        let result = authenticate_client(&db, "nonexistent", "secret").await;
        assert!(matches!(
            result,
            Err(AgentIAMError::InvalidClientCredentials)
        ));
    }

    #[tokio::test]
    async fn test_issue_access_token() {
        let db = setup_db().await;
        let scopes = vec!["authorize".to_string(), "sessions:read".to_string()];
        let (client, _) = register_client(&db, "token-app", scopes).await.unwrap();

        let requested = vec!["authorize".to_string()];
        let token = issue_access_token(&client, &requested, JWT_SECRET, 3600).unwrap();
        assert!(!token.is_empty());

        // Verify the token
        let data: jsonwebtoken::TokenData<AccessTokenClaims> =
            jwt::verify_token(&token, JWT_SECRET).unwrap();
        assert_eq!(data.claims.sub, client.client_id);
        assert_eq!(data.claims.scope, "authorize");
    }

    #[tokio::test]
    async fn test_issue_access_token_scope_not_granted() {
        let db = setup_db().await;
        let scopes = vec!["authorize".to_string()];
        let (client, _) = register_client(&db, "limited-app", scopes).await.unwrap();

        let requested = vec!["admin".to_string()];
        let result = issue_access_token(&client, &requested, JWT_SECRET, 3600);
        assert!(matches!(result, Err(AgentIAMError::InvalidScope(_))));
    }

    #[tokio::test]
    async fn test_full_oauth_flow() {
        let db = setup_db().await;
        let scopes = vec![
            "authorize".to_string(),
            "sessions:read".to_string(),
            "sessions:write".to_string(),
        ];

        // 1. Register
        let (client, secret) = register_client(&db, "full-flow", scopes).await.unwrap();

        // 2. Authenticate
        let authed = authenticate_client(&db, &client.client_id, &secret)
            .await
            .unwrap();

        // 3. Issue token with subset of scopes
        let requested = vec!["authorize".to_string(), "sessions:read".to_string()];
        let token = issue_access_token(&authed, &requested, JWT_SECRET, 3600).unwrap();

        let data: jsonwebtoken::TokenData<AccessTokenClaims> =
            jwt::verify_token(&token, JWT_SECRET).unwrap();
        assert_eq!(data.claims.scope, "authorize sessions:read");
        assert_eq!(data.claims.agentiam.client_id, client.client_id);
    }

    #[tokio::test]
    async fn test_list_clients() {
        let db = setup_db().await;
        let scopes = vec!["authorize".to_string()];
        register_client(&db, "app-a", scopes.clone()).await.unwrap();
        register_client(&db, "app-b", scopes).await.unwrap();

        let clients = list_clients(&db).await.unwrap();
        assert_eq!(clients.len(), 2);
        let names: Vec<&str> = clients.iter().map(|c| c.name.as_str()).collect();
        assert!(names.contains(&"app-a"));
        assert!(names.contains(&"app-b"));
        // Secret hash must not be exposed
        assert!(clients[0].client_secret_hash.is_empty());
        assert!(clients[1].client_secret_hash.is_empty());
    }

    #[tokio::test]
    async fn test_revoke_client() {
        let db = setup_db().await;
        let scopes = vec!["authorize".to_string()];
        let (client, _) = register_client(&db, "revoke-me", scopes).await.unwrap();

        let revoked = revoke_client(&db, &client.client_id).await.unwrap();
        assert!(revoked);

        // Not found case
        let revoked2 = revoke_client(&db, "nonexistent").await.unwrap();
        assert!(!revoked2);

        // Verify it shows as revoked in list
        let clients = list_clients(&db).await.unwrap();
        assert!(clients[0].revoked);
    }
}
