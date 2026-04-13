use std::path::PathBuf;

#[derive(Debug, Clone)]
pub struct AppConfig {
    pub port: u16,
    pub policy_dir: PathBuf,
    pub schema_file: PathBuf,
    pub jwt_secret: String,
    pub db_path: String,
}

impl AppConfig {
    pub fn from_env() -> Self {
        Self {
            port: std::env::var("AGENTIAM_PORT")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(8080),
            policy_dir: PathBuf::from(
                std::env::var("AGENTIAM_POLICY_DIR").unwrap_or_else(|_| "policies".to_string()),
            ),
            schema_file: PathBuf::from(
                std::env::var("AGENTIAM_SCHEMA_FILE")
                    .unwrap_or_else(|_| "schemas/agentiam.cedarschema".to_string()),
            ),
            jwt_secret: std::env::var("AGENTIAM_JWT_SECRET")
                .unwrap_or_else(|_| "agentiam-dev-secret-change-in-production".to_string()),
            db_path: std::env::var("AGENTIAM_DB_PATH")
                .unwrap_or_else(|_| "sqlite:agentiam.db?mode=rwc".to_string()),
        }
    }
}
