use serde::{Deserialize, Serialize};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Bad request: {0}")]
    BadRequest(String),

    #[error("Invalid argument: {0}")]
    InvalidArgument(String),

    #[error("Resource not available yet")]
    NotAvailableYet,

    #[error("Content search query is not selective enough")]
    UnselectiveContentQuery,

    #[error("Unsupported content search query")]
    UnsupportedContentQuery,

    #[error("Authentication required")]
    AuthenticationRequired,

    #[error("User account is not active")]
    UserNotActive,

    #[error("Wrong credentials provided")]
    WrongCredentials,

    #[error("Forbidden: You are not allowed to perform this operation")]
    Forbidden,

    #[error("Resource not found")]
    NotFound,

    #[error("Resource already exists")]
    AlreadyExists,

    #[error("Failed dependency")]
    FailedDependency,

    #[error("Quota exceeded: {0}")]
    QuotaExceeded(String),

    #[error("Too many requests")]
    TooManyRequests,

    #[error("Transient server error")]
    TransientError,

    #[error("Operation deadline exceeded")]
    DeadlineExceeded,

    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),

    #[error("JSON parsing error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("Rate limit error: {0}")]
    RateLimit(#[from] crate::rate_limit::RateLimitError),

    #[error("Unknown error: {0}")]
    Unknown(String),
}

#[derive(Debug, Deserialize, Serialize)]
pub struct ApiErrorResponse {
    pub error: ApiError,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct ApiError {
    pub code: String,
    pub message: String,
}

impl Error {
    pub fn from_response(status: reqwest::StatusCode, error: ApiError) -> Self {
        match (status.as_u16(), error.code.as_str()) {
            (400, "BadRequestError") => Error::BadRequest(error.message),
            (400, "InvalidArgumentError") => Error::InvalidArgument(error.message),
            (400, "NotAvailableYet") => Error::NotAvailableYet,
            (400, "UnselectiveContentQueryError") => Error::UnselectiveContentQuery,
            (400, "UnsupportedContentQueryError") => Error::UnsupportedContentQuery,
            (401, "AuthenticationRequiredError") => Error::AuthenticationRequired,
            (401, "UserNotActiveError") => Error::UserNotActive,
            (401, "WrongCredentialsError") => Error::WrongCredentials,
            (403, "ForbiddenError") => Error::Forbidden,
            (404, "NotFoundError") => Error::NotFound,
            (409, "AlreadyExistsError") => Error::AlreadyExists,
            (424, "FailedDependencyError") => Error::FailedDependency,
            (429, "QuotaExceededError") => Error::QuotaExceeded(error.message),
            (429, "TooManyRequestsError") => Error::TooManyRequests,
            (503, "TransientError") => Error::TransientError,
            (504, "DeadlineExceededError") => Error::DeadlineExceeded,
            _ => Error::Unknown(format!("{}: {}", error.code, error.message)),
        }
    }

    pub fn is_retryable(&self) -> bool {
        matches!(
            self,
            Error::TooManyRequests | Error::TransientError | Error::DeadlineExceeded
        )
    }
}

pub type Result<T> = std::result::Result<T, Error>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_from_response() {
        let error = ApiError {
            code: "BadRequestError".to_string(),
            message: "Invalid request".to_string(),
        };

        let err = Error::from_response(reqwest::StatusCode::BAD_REQUEST, error);
        match err {
            Error::BadRequest(msg) => assert_eq!(msg, "Invalid request"),
            _ => panic!("Expected BadRequest error"),
        }
    }

    #[test]
    fn test_retryable_errors() {
        assert!(Error::TooManyRequests.is_retryable());
        assert!(Error::TransientError.is_retryable());
        assert!(Error::DeadlineExceeded.is_retryable());
        assert!(!Error::NotFound.is_retryable());
        assert!(!Error::Forbidden.is_retryable());
    }
}
