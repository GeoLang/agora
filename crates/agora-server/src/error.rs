use std::borrow::Cow;

use axum::Json;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};

/// A refusal a client is allowed to see. Nothing here echoes back a database
/// error or a token.
#[derive(Debug)]
pub struct ApiError {
    status: StatusCode,
    message: Cow<'static, str>,
}

impl ApiError {
    pub fn unauthorized(message: &'static str) -> Self {
        Self {
            status: StatusCode::UNAUTHORIZED,
            message: Cow::Borrowed(message),
        }
    }

    pub fn forbidden(message: &'static str) -> Self {
        Self {
            status: StatusCode::FORBIDDEN,
            message: Cow::Borrowed(message),
        }
    }

    pub fn not_found(message: &'static str) -> Self {
        Self {
            status: StatusCode::NOT_FOUND,
            message: Cow::Borrowed(message),
        }
    }

    pub fn bad_request(message: &'static str) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            message: Cow::Borrowed(message),
        }
    }

    pub fn payload_too_large(message: &'static str) -> Self {
        Self {
            status: StatusCode::PAYLOAD_TOO_LARGE,
            message: Cow::Borrowed(message),
        }
    }

    pub fn internal(message: &'static str) -> Self {
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            message: Cow::Borrowed(message),
        }
    }

    pub fn service_unavailable(message: &'static str) -> Self {
        Self {
            status: StatusCode::SERVICE_UNAVAILABLE,
            message: Cow::Borrowed(message),
        }
    }

    /// The one refusal that names something the caller sent back to them, so it
    /// takes an owned message. It travels as a json string and reaches no
    /// markup, so what it echoes stays data.
    pub fn unprocessable_entity(message: String) -> Self {
        Self {
            status: StatusCode::UNPROCESSABLE_ENTITY,
            message: Cow::Owned(message),
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (
            self.status,
            Json(serde_json::json!({ "error": self.message })),
        )
            .into_response()
    }
}

impl From<sqlx::Error> for ApiError {
    fn from(_: sqlx::Error) -> Self {
        ApiError::internal("database error")
    }
}
