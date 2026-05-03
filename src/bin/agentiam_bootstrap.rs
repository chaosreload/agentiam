use clap::Parser;
use sqlx::sqlite::SqlitePoolOptions;

use agentiam::audit::logger::AuditLogger;
use agentiam::metadata;
use agentiam::token::apikey;

const BOOTSTRAP_SEEDED_KEY: &str = "bootstrap_seeded";

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

    /// Force re-bootstrap even if already seeded
    #[arg(long)]
    force: bool,
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
    metadata::ensure_table(&db).await?;

    // Check DB marker for prior bootstrap
    if let Some(prev) = metadata::get(&db, BOOTSTRAP_SEEDED_KEY).await? {
        if cli.force {
            eprintln!("WARNING: overriding previous bootstrap (seeded at {prev})");
        } else {
            eprintln!(
                "ERROR: System already bootstrapped (seeded at {prev}). Use --force to override."
            );
            std::process::exit(1);
        }
    }

    // Generate and store
    let id = uuid::Uuid::new_v4().to_string();
    let (plaintext_key, key_hash) = apikey::create_api_key("bootstrap");
    apikey::store_api_key(&db, &id, &cli.name, &key_hash, "bootstrap").await?;

    // Mark bootstrap as done
    let timestamp = chrono::Utc::now().to_rfc3339();
    metadata::set(&db, BOOTSTRAP_SEEDED_KEY, &timestamp).await?;

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

    use agentiam::metadata;
    use agentiam::token::apikey;

    const BOOTSTRAP_SEEDED_KEY: &str = "bootstrap_seeded";

    async fn setup_db() -> sqlx::SqlitePool {
        let pool = SqlitePoolOptions::new()
            .connect("sqlite::memory:")
            .await
            .unwrap();
        apikey::ensure_table(&pool).await.unwrap();
        metadata::ensure_table(&pool).await.unwrap();
        pool
    }

    #[tokio::test]
    async fn bootstrap_creates_key_and_sets_marker() {
        let db = setup_db().await;

        // No marker yet
        assert!(
            metadata::get(&db, BOOTSTRAP_SEEDED_KEY)
                .await
                .unwrap()
                .is_none()
        );

        // Simulate bootstrap
        let id = uuid::Uuid::new_v4().to_string();
        let (_, hash) = apikey::create_api_key("bootstrap");
        apikey::store_api_key(&db, &id, "bootstrap", &hash, "bootstrap")
            .await
            .unwrap();
        metadata::set(&db, BOOTSTRAP_SEEDED_KEY, "2025-01-01T00:00:00Z")
            .await
            .unwrap();

        let keys = apikey::list_api_keys(&db).await.unwrap();
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0].name, "bootstrap");

        // Marker is set
        let marker = metadata::get(&db, BOOTSTRAP_SEEDED_KEY).await.unwrap();
        assert!(marker.is_some());
    }

    #[tokio::test]
    async fn bootstrap_idempotency_rejects_second() {
        let db = setup_db().await;

        // Simulate first bootstrap
        metadata::set(&db, BOOTSTRAP_SEEDED_KEY, "2025-01-01T00:00:00Z")
            .await
            .unwrap();

        // Idempotency check: marker exists → should be rejected
        let existing = metadata::get(&db, BOOTSTRAP_SEEDED_KEY).await.unwrap();
        assert!(
            existing.is_some(),
            "should detect existing bootstrap marker"
        );
    }

    #[tokio::test]
    async fn bootstrap_force_overrides_marker() {
        let db = setup_db().await;

        // Simulate first bootstrap
        metadata::set(&db, BOOTSTRAP_SEEDED_KEY, "2025-01-01T00:00:00Z")
            .await
            .unwrap();

        // With --force, we update the marker
        metadata::set(&db, BOOTSTRAP_SEEDED_KEY, "2025-06-01T00:00:00Z")
            .await
            .unwrap();

        let marker = metadata::get(&db, BOOTSTRAP_SEEDED_KEY).await.unwrap();
        assert_eq!(marker.as_deref(), Some("2025-06-01T00:00:00Z"));
    }
}
