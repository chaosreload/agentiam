use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde_json::json;

use crate::error::AgentIAMError;

pub struct ApiError {
    pub status: StatusCode,
    pub code: &'static str,
    pub message: String,
    pub request_id: String,
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let body = json!({
            "request_id": self.request_id,
            "error": {
                "code": self.code,
                "message": self.message,
            }
        });
        (self.status, axum::Json(body)).into_response()
    }
}

impl ApiError {
    pub fn from_err(err: AgentIAMError, request_id: &str) -> Self {
        let (status, code) = match &err {
            AgentIAMError::InvalidApiKey | AgentIAMError::ApiKeyRevoked => {
                (StatusCode::UNAUTHORIZED, "Unauthorized")
            }
            AgentIAMError::InvalidToken(_)
            | AgentIAMError::TokenExpired
            | AgentIAMError::Jwt(_)
            | AgentIAMError::InvalidClientCredentials => (StatusCode::UNAUTHORIZED, "Unauthorized"),
            AgentIAMError::SessionNotFound(_) => (StatusCode::NOT_FOUND, "NotFound"),
            AgentIAMError::SessionRevoked(_) => (StatusCode::FORBIDDEN, "AccessDenied"),
            AgentIAMError::SessionExpired(_) => (StatusCode::FORBIDDEN, "AccessDenied"),
            AgentIAMError::BudgetExhausted(_) => (StatusCode::FORBIDDEN, "AccessDenied"),
            AgentIAMError::ScopeViolation(_) => (StatusCode::FORBIDDEN, "AccessDenied"),
            AgentIAMError::InvalidScope(_) => (StatusCode::BAD_REQUEST, "InvalidRequest"),
            AgentIAMError::OAuthError(_) => (StatusCode::BAD_REQUEST, "InvalidRequest"),
            AgentIAMError::Database(_) | AgentIAMError::Internal(_) => {
                (StatusCode::INTERNAL_SERVER_ERROR, "InternalError")
            }
        };
        Self {
            status,
            code,
            message: err.to_string(),
            request_id: request_id.to_string(),
        }
    }

    pub fn bad_request(msg: impl Into<String>, request_id: &str) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            code: "InvalidRequest",
            message: msg.into(),
            request_id: request_id.to_string(),
        }
    }

    pub fn not_found(msg: impl Into<String>, request_id: &str) -> Self {
        Self {
            status: StatusCode::NOT_FOUND,
            code: "NotFound",
            message: msg.into(),
            request_id: request_id.to_string(),
        }
    }
}

pub fn new_request_id() -> String {
    format!("req_{}", uuid::Uuid::new_v4())
}

pub fn success_response(
    request_id: &str,
    data: serde_json::Value,
) -> axum::Json<serde_json::Value> {
    axum::Json(json!({
        "request_id": request_id,
        "data": data,
    }))
}
