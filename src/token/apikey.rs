use rand::Rng;
use sha2::{Digest, Sha256};
use sqlx::SqlitePool;

use crate::error::AgentIAMError;
use crate::models::ApiKeyInfo;

/// Create the api_keys table if it doesn't exist.
pub async fn ensure_table(db: &SqlitePool) -> Result<(), AgentIAMError> {
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS api_keys (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            key_hash TEXT NOT NULL,
            env TEXT NOT NULL,
            created_at INTEGER NOT NULL,
            revoked INTEGER NOT NULL DEFAULT 0
        )",
    )
    .execute(db)
    .await?;
    Ok(())
}

/// Generate a new API key. Returns (plaintext_key, key_hash).
/// Format: `ak_{env}_{random32hex}`
pub fn create_api_key(env: &str) -> (String, String) {
    let random_bytes: [u8; 16] = rand::rng().random();
    let random_hex: String = random_bytes.iter().map(|b| format!("{b:02x}")).collect();
    let key = format!("ak_{env}_{random_hex}");
    let hash = hash_key(&key);
    (key, hash)
}

/// SHA-256 hash of a key string, returned as hex.
pub fn hash_key(key: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(key.as_bytes());
    format!("{:x}", hasher.finalize())
}

/// Store a newly created API key in the database.
pub async fn store_api_key(
    db: &SqlitePool,
    id: &str,
    name: &str,
    key_hash: &str,
    env: &str,
) -> Result<ApiKeyInfo, AgentIAMError> {
    let now = chrono::Utc::now().timestamp();
    sqlx::query(
        "INSERT INTO api_keys (id, name, key_hash, env, created_at, revoked) VALUES (?, ?, ?, ?, ?, 0)",
    )
    .bind(id)
    .bind(name)
    .bind(key_hash)
    .bind(env)
    .bind(now)
    .execute(db)
    .await?;

    Ok(ApiKeyInfo {
        id: id.to_string(),
        name: name.to_string(),
        env: env.to_string(),
        created_at: now,
        revoked: false,
    })
}

/// Verify an API key against the database. Returns the key info if valid.
pub async fn verify_api_key(key: &str, db: &SqlitePool) -> Result<ApiKeyInfo, AgentIAMError> {
    let key_hash = hash_key(key);

    let row = sqlx::query_as::<_, (String, String, String, i64, i64)>(
        "SELECT id, name, env, created_at, revoked FROM api_keys WHERE key_hash = ?",
    )
    .bind(&key_hash)
    .fetch_optional(db)
    .await?;

    match row {
        None => Err(AgentIAMError::InvalidApiKey),
        Some((id, name, env, created_at, revoked)) => {
            if revoked != 0 {
                return Err(AgentIAMError::ApiKeyRevoked);
            }
            Ok(ApiKeyInfo {
                id,
                name,
                env,
                created_at,
                revoked: false,
            })
        }
    }
}

/// Revoke an API key by ID.
pub async fn revoke_api_key(db: &SqlitePool, id: &str) -> Result<(), AgentIAMError> {
    let result = sqlx::query("UPDATE api_keys SET revoked = 1 WHERE id = ?")
        .bind(id)
        .execute(db)
        .await?;
    if result.rows_affected() == 0 {
        return Err(AgentIAMError::InvalidApiKey);
    }
    Ok(())
}

/// List all API keys (without exposing hashes).
pub async fn list_api_keys(db: &SqlitePool) -> Result<Vec<ApiKeyInfo>, AgentIAMError> {
    let rows = sqlx::query_as::<_, (String, String, String, i64, i64)>(
        "SELECT id, name, env, created_at, revoked FROM api_keys ORDER BY created_at DESC",
    )
    .fetch_all(db)
    .await?;

    Ok(rows
        .into_iter()
        .map(|(id, name, env, created_at, revoked)| ApiKeyInfo {
            id,
            name,
            env,
            created_at,
            revoked: revoked != 0,
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use sqlx::sqlite::SqlitePoolOptions;

    async fn setup_db() -> SqlitePool {
        let pool = SqlitePoolOptions::new()
            .connect("sqlite::memory:")
            .await
            .unwrap();
        ensure_table(&pool).await.unwrap();
        pool
    }

    #[test]
    fn test_create_api_key_format() {
        let (key, hash) = create_api_key("dev");
        assert!(key.starts_with("ak_dev_"));
        assert_eq!(key.len(), 3 + 4 + 32); // "ak_" + "dev_" + 32 hex chars
        assert_eq!(hash.len(), 64); // SHA-256 hex
    }

    #[test]
    fn test_create_api_key_different_envs() {
        let (key_dev, _) = create_api_key("dev");
        let (key_prod, _) = create_api_key("prod");
        assert!(key_dev.starts_with("ak_dev_"));
        assert!(key_prod.starts_with("ak_prod_"));
    }

    #[test]
    fn test_hash_key_deterministic() {
        let h1 = hash_key("ak_dev_abc123");
        let h2 = hash_key("ak_dev_abc123");
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_hash_key_different_for_different_keys() {
        let h1 = hash_key("ak_dev_abc123");
        let h2 = hash_key("ak_dev_xyz789");
        assert_ne!(h1, h2);
    }

    #[tokio::test]
    async fn test_store_and_verify_api_key() {
        let db = setup_db().await;
        let (key, hash) = create_api_key("dev");
        let id = uuid::Uuid::new_v4().to_string();
        store_api_key(&db, &id, "test-key", &hash, "dev")
            .await
            .unwrap();

        let info = verify_api_key(&key, &db).await.unwrap();
        assert_eq!(info.id, id);
        assert_eq!(info.name, "test-key");
        assert_eq!(info.env, "dev");
        assert!(!info.revoked);
    }

    #[tokio::test]
    async fn test_verify_invalid_key() {
        let db = setup_db().await;
        let result = verify_api_key("ak_dev_nonexistent0000000000000000", &db).await;
        assert!(matches!(result, Err(AgentIAMError::InvalidApiKey)));
    }

    #[tokio::test]
    async fn test_revoke_api_key() {
        let db = setup_db().await;
        let (key, hash) = create_api_key("dev");
        let id = uuid::Uuid::new_v4().to_string();
        store_api_key(&db, &id, "to-revoke", &hash, "dev")
            .await
            .unwrap();

        revoke_api_key(&db, &id).await.unwrap();
        let result = verify_api_key(&key, &db).await;
        assert!(matches!(result, Err(AgentIAMError::ApiKeyRevoked)));
    }

    #[tokio::test]
    async fn test_revoke_nonexistent_key() {
        let db = setup_db().await;
        let result = revoke_api_key(&db, "nonexistent-id").await;
        assert!(matches!(result, Err(AgentIAMError::InvalidApiKey)));
    }

    #[tokio::test]
    async fn test_list_api_keys() {
        let db = setup_db().await;
        let (_, hash1) = create_api_key("dev");
        let (_, hash2) = create_api_key("prod");
        store_api_key(&db, "id-1", "key-1", &hash1, "dev")
            .await
            .unwrap();
        store_api_key(&db, "id-2", "key-2", &hash2, "prod")
            .await
            .unwrap();

        let keys = list_api_keys(&db).await.unwrap();
        assert_eq!(keys.len(), 2);
    }

    #[tokio::test]
    async fn test_list_shows_revoked_status() {
        let db = setup_db().await;
        let (_, hash) = create_api_key("dev");
        store_api_key(&db, "id-r", "key-r", &hash, "dev")
            .await
            .unwrap();
        revoke_api_key(&db, "id-r").await.unwrap();

        let keys = list_api_keys(&db).await.unwrap();
        assert_eq!(keys.len(), 1);
        assert!(keys[0].revoked);
    }
}
