use clap::Parser;
use sqlx::sqlite::SqlitePoolOptions;

use agentiam::audit::logger::AuditLogger;
use agentiam::token::apikey;

#[derive(Parser)]
#[command(name = "agentiam-bootstrap", about = "Bootstrap the first API key")]
struct Cli {
    /// SQLite database path (e.g. /var/lib/agentiam/agentiam.db)
    #[arg(long)]
    db_path: String,

    /// Human-readable name for this key
    #[arg(long, default_value = "bootstrap")]
    name: String,

    /// Scope for the key (e.g. '*' for all)
    #[arg(long, default_value = "*")]
    scope: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    let db_url = if cli.db_path.starts_with("sqlite:") {
        cli.db_path.clone()
    } else {
        format!("sqlite:{}?mode=rwc", cli.db_path)
    };

    let db = SqlitePoolOptions::new()
        .max_connections(1)
        .connect(&db_url)
        .await?;

    // Ensure tables exist
    apikey::ensure_table(&db).await?;

    // Check if a bootstrap key already exists
    let existing = apikey::list_api_keys(&db).await?;
    let has_bootstrap = existing
        .iter()
        .any(|k| k.name.starts_with("bootstrap") || k.name == cli.name);

    if has_bootstrap {
        eprintln!("ERROR: A bootstrap API key already exists. Refusing to create another.");
        std::process::exit(1);
    }

    // Generate and store
    let id = uuid::Uuid::new_v4().to_string();
    let (plaintext_key, key_hash) = apikey::create_api_key("bootstrap");
    apikey::store_api_key(&db, &id, &cli.name, &key_hash, "bootstrap").await?;

    // Write audit log
    let audit = AuditLogger::new(db.clone()).await?;
    audit
        .log(&agentiam::audit::logger::AuditRecord {
            id: AuditLogger::new_record_id(),
            timestamp: AuditLogger::now_iso(),
            session_id: "N/A".into(),
            principal: "system:bootstrap".into(),
            action: "bootstrap_api_key_created".into(),
            resource_type: "api_key".into(),
            resource_id: id.clone(),
            decision: "ALLOW".into(),
            reason: format!("bootstrap key '{}' scope={}", cli.name, cli.scope),
            policies_evaluated: 0,
            evaluation_time_us: 0,
            context_snapshot: None,
        })
        .await?;
    audit.flush_and_close().await;

    println!("{plaintext_key}");
    eprintln!(
        "Bootstrap API key created (id={id}, name={}, scope={})",
        cli.name, cli.scope
    );

    Ok(())
}

#[cfg(test)]
mod tests {
    use sqlx::sqlite::SqlitePoolOptions;

    use agentiam::token::apikey;

    async fn setup_db() -> sqlx::SqlitePool {
        let pool = SqlitePoolOptions::new()
            .connect("sqlite::memory:")
            .await
            .unwrap();
        apikey::ensure_table(&pool).await.unwrap();
        pool
    }

    #[tokio::test]
    async fn bootstrap_creates_key() {
        let db = setup_db().await;
        let id = uuid::Uuid::new_v4().to_string();
        let (_, hash) = apikey::create_api_key("bootstrap");
        apikey::store_api_key(&db, &id, "bootstrap", &hash, "bootstrap")
            .await
            .unwrap();

        let keys = apikey::list_api_keys(&db).await.unwrap();
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0].name, "bootstrap");
    }

    #[tokio::test]
    async fn bootstrap_idempotency_rejects_second() {
        let db = setup_db().await;

        // First key
        let id1 = uuid::Uuid::new_v4().to_string();
        let (_, hash1) = apikey::create_api_key("bootstrap");
        apikey::store_api_key(&db, &id1, "bootstrap", &hash1, "bootstrap")
            .await
            .unwrap();

        // Simulate the idempotency check
        let existing = apikey::list_api_keys(&db).await.unwrap();
        let has_bootstrap = existing.iter().any(|k| k.name.starts_with("bootstrap"));
        assert!(has_bootstrap, "should detect existing bootstrap key");
    }
}
