//! Core error types and enumerations

use serde::{Deserialize, Serialize};

/// Enhanced Error enum with better categorization
#[allow(clippy::result_large_err)] // Allow large error variants for enhanced error handling
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

    // Enhanced error types
    #[error("Configuration error: {message}")]
    Configuration { message: String },

    #[error("Validation error: {message}")]
    Validation {
        message: String,
        field: Option<String>,
    },

    #[error("IO error: {message}")]
    Io { message: String },
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

/// Error categories for classification
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ErrorCategory {
    /// Authentication and authorization errors
    Authentication,
    /// Client-side errors (bad requests, validation, etc.)
    Client,
    /// Network and communication errors
    Network,
    /// Server-side errors
    Server,
    /// Rate limiting and quota errors
    RateLimit,
    /// Configuration errors
    Configuration,
    /// Data parsing and serialization errors
    Serialization,
    /// Unknown or uncategorized errors
    Unknown,
}

/// Error severity levels
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum ErrorSeverity {
    /// Low severity - typically recoverable
    Low,
    /// Medium severity - may require user intervention
    Medium,
    /// High severity - likely requires immediate attention
    High,
    /// Critical severity - system or security critical
    Critical,
}

pub type Result<T> = std::result::Result<T, Error>;
