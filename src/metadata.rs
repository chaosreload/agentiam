use sqlx::SqlitePool;

use crate::error::AgentIAMError;

/// Create the system_metadata table if it doesn't exist.
pub async fn ensure_table(db: &SqlitePool) -> Result<(), AgentIAMError> {
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS system_metadata (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL,
            updated_at INTEGER NOT NULL
        )",
    )
    .execute(db)
    .await?;
    Ok(())
}

/// Get a metadata value by key.
pub async fn get(db: &SqlitePool, key: &str) -> Result<Option<String>, AgentIAMError> {
    let row = sqlx::query_as::<_, (String,)>("SELECT value FROM system_metadata WHERE key = ?")
        .bind(key)
        .fetch_optional(db)
        .await?;
    Ok(row.map(|(v,)| v))
}

/// Set a metadata key-value pair (upsert).
pub async fn set(db: &SqlitePool, key: &str, value: &str) -> Result<(), AgentIAMError> {
    let now = chrono::Utc::now().timestamp();
    sqlx::query(
        "INSERT INTO system_metadata (key, value, updated_at) VALUES (?, ?, ?)
         ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at",
    )
    .bind(key)
    .bind(value)
    .bind(now)
    .execute(db)
    .await?;
    Ok(())
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

    #[tokio::test]
    async fn get_missing_key_returns_none() {
        let db = setup_db().await;
        let result = get(&db, "nonexistent").await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn set_and_get_roundtrip() {
        let db = setup_db().await;
        set(&db, "test_key", "test_value").await.unwrap();
        let result = get(&db, "test_key").await.unwrap();
        assert_eq!(result.as_deref(), Some("test_value"));
    }

    #[tokio::test]
    async fn set_upserts_existing_key() {
        let db = setup_db().await;
        set(&db, "k", "v1").await.unwrap();
        set(&db, "k", "v2").await.unwrap();
        let result = get(&db, "k").await.unwrap();
        assert_eq!(result.as_deref(), Some("v2"));
    }
}
