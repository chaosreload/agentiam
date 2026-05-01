use chrono::Utc;
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;
use tokio::sync::mpsc;

use crate::error::AgentIAMError;

const BATCH_SIZE: usize = 100;
const FLUSH_INTERVAL_MS: u64 = 1_000;
const CHANNEL_CAPACITY: usize = 4_096;

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
    tx: std::sync::Mutex<Option<mpsc::Sender<AuditRecord>>>,
    consumer_handle: tokio::sync::Mutex<Option<tokio::task::JoinHandle<()>>>,
}

impl AuditLogger {
    pub async fn new(db: SqlitePool) -> Result<Self, AgentIAMError> {
        Self::ensure_table(&db).await?;
        let (tx, rx) = mpsc::channel(CHANNEL_CAPACITY);
        let consumer_db = db.clone();
        let handle = tokio::spawn(Self::consumer_loop(consumer_db, rx));
        Ok(Self {
            db,
            tx: std::sync::Mutex::new(Some(tx)),
            consumer_handle: tokio::sync::Mutex::new(Some(handle)),
        })
    }

    #[cfg(test)]
    pub async fn new_with_config(
        db: SqlitePool,
        batch_size: usize,
        flush_interval_ms: u64,
    ) -> Result<Self, AgentIAMError> {
        Self::ensure_table(&db).await?;
        let (tx, rx) = mpsc::channel(CHANNEL_CAPACITY);
        let consumer_db = db.clone();
        let handle = tokio::spawn(Self::consumer_loop_with_config(
            consumer_db,
            rx,
            batch_size,
            flush_interval_ms,
        ));
        Ok(Self {
            db,
            tx: std::sync::Mutex::new(Some(tx)),
            consumer_handle: tokio::sync::Mutex::new(Some(handle)),
        })
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
        let send_result = {
            let guard = self.tx.lock().unwrap_or_else(|e| e.into_inner());
            guard.as_ref().map(|tx| tx.try_send(record.clone()))
        };

        match send_result {
            Some(Ok(())) => Ok(()),
            Some(Err(mpsc::error::TrySendError::Full(_))) => {
                tracing::warn!("audit channel full, falling back to synchronous write");
                Self::insert_one(&self.db, record).await
            }
            Some(Err(mpsc::error::TrySendError::Closed(_))) | None => {
                tracing::warn!("audit channel closed, falling back to synchronous write");
                Self::insert_one(&self.db, record).await
            }
        }
    }

    pub async fn flush_and_close(&self) {
        // Drop the sender so the consumer sees channel closed and drains remaining records.
        {
            let mut guard = self.tx.lock().unwrap_or_else(|e| e.into_inner());
            guard.take();
        }
        if let Some(handle) = self.consumer_handle.lock().await.take() {
            let _ = handle.await;
        }
    }

    async fn consumer_loop(db: SqlitePool, rx: mpsc::Receiver<AuditRecord>) {
        Self::consumer_loop_with_config(db, rx, BATCH_SIZE, FLUSH_INTERVAL_MS).await;
    }

    async fn consumer_loop_with_config(
        db: SqlitePool,
        mut rx: mpsc::Receiver<AuditRecord>,
        batch_size: usize,
        flush_interval_ms: u64,
    ) {
        let mut buffer: Vec<AuditRecord> = Vec::with_capacity(batch_size);
        let flush_duration = tokio::time::Duration::from_millis(flush_interval_ms);

        loop {
            let deadline = tokio::time::sleep(flush_duration);
            tokio::pin!(deadline);

            // Fill buffer up to batch_size or until timer fires
            loop {
                tokio::select! {
                    biased;
                    msg = rx.recv() => {
                        match msg {
                            Some(record) => {
                                buffer.push(record);
                                if buffer.len() >= batch_size {
                                    break; // flush
                                }
                            }
                            None => {
                                // Channel closed — flush remaining and exit
                                if !buffer.is_empty() {
                                    Self::flush_batch(&db, &buffer).await;
                                }
                                return;
                            }
                        }
                    }
                    () = &mut deadline => {
                        break; // timer fired — flush whatever we have
                    }
                }
            }

            if !buffer.is_empty() {
                Self::flush_batch(&db, &buffer).await;
                buffer.clear();
            }
        }
    }

    async fn flush_batch(db: &SqlitePool, records: &[AuditRecord]) {
        // Use a transaction for the batch
        let mut tx = match db.begin().await {
            Ok(tx) => tx,
            Err(e) => {
                tracing::error!("audit batch: failed to begin transaction: {e}");
                return;
            }
        };

        for record in records {
            if let Err(e) = Self::insert_one_tx(&mut tx, record).await {
                tracing::error!("audit batch insert error: {e}");
            }
        }

        if let Err(e) = tx.commit().await {
            tracing::error!("audit batch: failed to commit transaction: {e}");
        }
    }

    async fn insert_one(db: &SqlitePool, record: &AuditRecord) -> Result<(), AgentIAMError> {
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
        .execute(db)
        .await?;
        Ok(())
    }

    async fn insert_one_tx(
        tx: &mut sqlx::SqliteConnection,
        record: &AuditRecord,
    ) -> Result<(), AgentIAMError> {
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
        .execute(&mut *tx)
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

#[cfg(test)]
mod tests {
    use super::*;
    use sqlx::sqlite::SqlitePoolOptions;

    async fn test_pool() -> SqlitePool {
        SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .unwrap()
    }

    fn make_record(id: &str) -> AuditRecord {
        AuditRecord {
            id: id.to_string(),
            timestamp: AuditLogger::now_iso(),
            session_id: "sess_1".into(),
            principal: "Agent::\"bot\"".into(),
            action: "Action::\"read\"".into(),
            resource_type: "Doc".into(),
            resource_id: "d1".into(),
            decision: "ALLOW".into(),
            reason: "test".into(),
            policies_evaluated: 1,
            evaluation_time_us: 42,
            context_snapshot: None,
        }
    }

    async fn count_rows(db: &SqlitePool) -> i64 {
        sqlx::query_as::<_, (i64,)>("SELECT COUNT(*) FROM audit_decisions")
            .fetch_one(db)
            .await
            .unwrap()
            .0
    }

    #[tokio::test]
    async fn batch_flush_at_size() {
        let pool = test_pool().await;
        // batch_size=10, very long flush interval so only size triggers flush
        let logger = AuditLogger::new_with_config(pool.clone(), 10, 60_000)
            .await
            .unwrap();

        // Send exactly 10 records to trigger a batch flush
        for i in 0..10 {
            logger
                .log(&make_record(&format!("batch_{i}")))
                .await
                .unwrap();
        }

        // Give consumer a moment to flush
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
        assert_eq!(count_rows(&pool).await, 10);

        logger.flush_and_close().await;
    }

    #[tokio::test]
    async fn timer_flush_below_batch_size() {
        let pool = test_pool().await;
        // batch_size=100, flush interval=200ms
        let logger = AuditLogger::new_with_config(pool.clone(), 100, 200)
            .await
            .unwrap();

        // Send 5 records (below batch size)
        for i in 0..5 {
            logger
                .log(&make_record(&format!("timer_{i}")))
                .await
                .unwrap();
        }

        // Wait for timer flush
        tokio::time::sleep(tokio::time::Duration::from_millis(400)).await;
        assert_eq!(count_rows(&pool).await, 5);

        logger.flush_and_close().await;
    }

    #[tokio::test]
    async fn flush_and_close_drains_remaining() {
        let pool = test_pool().await;
        // Large batch & long timer so nothing auto-flushes
        let logger = AuditLogger::new_with_config(pool.clone(), 1_000, 60_000)
            .await
            .unwrap();

        for i in 0..7 {
            logger
                .log(&make_record(&format!("drain_{i}")))
                .await
                .unwrap();
        }

        // Nothing should be flushed yet
        assert_eq!(count_rows(&pool).await, 0);

        // Now close — remaining 7 must land
        logger.flush_and_close().await;
        assert_eq!(count_rows(&pool).await, 7);
    }
}
