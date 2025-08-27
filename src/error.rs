use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::error::Error as StdError;
use std::fmt;

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

/// Context information for errors to help with debugging and error reporting
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorContext {
    /// The operation that was being performed when the error occurred
    pub operation: Option<String>,
    /// The endpoint or resource being accessed
    pub resource: Option<String>,
    /// Additional key-value pairs for context
    pub metadata: HashMap<String, String>,
    /// Timestamp when the error occurred
    pub timestamp: Option<String>,
    /// Request ID if available
    pub request_id: Option<String>,
}

impl ErrorContext {
    /// Create a new empty error context
    pub fn new() -> Self {
        Self {
            operation: None,
            resource: None,
            metadata: HashMap::new(),
            timestamp: None,
            request_id: None,
        }
    }

    /// Create error context with an operation
    pub fn with_operation(operation: impl Into<String>) -> Self {
        Self {
            operation: Some(operation.into()),
            resource: None,
            metadata: HashMap::new(),
            timestamp: Some(chrono::Utc::now().to_rfc3339()),
            request_id: None,
        }
    }

    /// Add a resource to the context
    pub fn with_resource(mut self, resource: impl Into<String>) -> Self {
        self.resource = Some(resource.into());
        self
    }

    /// Add metadata to the context
    pub fn with_metadata(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.metadata.insert(key.into(), value.into());
        self
    }

    /// Add a request ID to the context
    pub fn with_request_id(mut self, request_id: impl Into<String>) -> Self {
        self.request_id = Some(request_id.into());
        self
    }
}

impl Default for ErrorContext {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for ErrorContext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ErrorContext {{")?;
        if let Some(op) = &self.operation {
            write!(f, " operation: {}", op)?;
        }
        if let Some(res) = &self.resource {
            write!(f, " resource: {}", res)?;
        }
        if let Some(req_id) = &self.request_id {
            write!(f, " request_id: {}", req_id)?;
        }
        if !self.metadata.is_empty() {
            write!(f, " metadata: {:?}", self.metadata)?;
        }
        write!(f, " }}")
    }
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

    /// Check if the error is retryable
    pub fn is_retryable(&self) -> bool {
        matches!(
            self,
            Error::TooManyRequests | Error::TransientError | Error::DeadlineExceeded
        )
    }

    /// Check if the error is due to authentication issues
    pub fn is_authentication_error(&self) -> bool {
        matches!(
            self,
            Error::AuthenticationRequired | Error::WrongCredentials | Error::UserNotActive
        )
    }

    /// Check if the error is a client error (4xx)
    pub fn is_client_error(&self) -> bool {
        matches!(
            self,
            Error::BadRequest(_)
                | Error::InvalidArgument(_)
                | Error::NotAvailableYet
                | Error::UnselectiveContentQuery
                | Error::UnsupportedContentQuery
                | Error::AuthenticationRequired
                | Error::UserNotActive
                | Error::WrongCredentials
                | Error::Forbidden
                | Error::NotFound
                | Error::AlreadyExists
                | Error::FailedDependency
                | Error::Validation { .. }
        )
    }

    /// Check if the error is a server error (5xx)
    pub fn is_server_error(&self) -> bool {
        matches!(self, Error::TransientError | Error::DeadlineExceeded)
    }

    /// Check if the error is a rate limit error
    pub fn is_rate_limit_error(&self) -> bool {
        matches!(
            self,
            Error::TooManyRequests | Error::QuotaExceeded(_) | Error::RateLimit(_)
        )
    }

    /// Get the error category
    pub fn category(&self) -> ErrorCategory {
        match self {
            Error::AuthenticationRequired
            | Error::WrongCredentials
            | Error::UserNotActive
            | Error::Forbidden => ErrorCategory::Authentication,
            Error::BadRequest(_)
            | Error::InvalidArgument(_)
            | Error::NotFound
            | Error::AlreadyExists
            | Error::Validation { .. } => ErrorCategory::Client,
            Error::Http(_) => ErrorCategory::Network,
            Error::TransientError | Error::DeadlineExceeded => ErrorCategory::Server,
            Error::TooManyRequests | Error::QuotaExceeded(_) | Error::RateLimit(_) => {
                ErrorCategory::RateLimit
            }
            Error::Configuration { .. } => ErrorCategory::Configuration,
            Error::Json(_) => ErrorCategory::Serialization,
            Error::Io { .. } => ErrorCategory::Network,
            _ => ErrorCategory::Unknown,
        }
    }

    /// Get the error severity
    pub fn severity(&self) -> ErrorSeverity {
        match self {
            Error::NotAvailableYet | Error::TooManyRequests | Error::TransientError => {
                ErrorSeverity::Low
            }
            Error::BadRequest(_)
            | Error::InvalidArgument(_)
            | Error::NotFound
            | Error::QuotaExceeded(_)
            | Error::Validation { .. }
            | Error::Json(_) => ErrorSeverity::Medium,
            Error::AuthenticationRequired
            | Error::WrongCredentials
            | Error::Forbidden
            | Error::DeadlineExceeded
            | Error::Http(_) => ErrorSeverity::High,
            Error::UserNotActive | Error::Configuration { .. } => ErrorSeverity::Critical,
            _ => ErrorSeverity::Medium,
        }
    }

    /// Create a chain of error information for debugging
    pub fn error_chain(&self) -> Vec<String> {
        let mut chain = vec![self.to_string()];
        let mut source = StdError::source(self);
        while let Some(err) = source {
            chain.push(err.to_string());
            source = err.source();
        }
        chain
    }

    /// Get a detailed error report for debugging
    pub fn detailed_report(&self) -> String {
        let mut report = String::new();
        report.push_str(&format!("Error: {}\n", self));
        report.push_str(&format!("Category: {:?}\n", self.category()));
        report.push_str(&format!("Severity: {:?}\n", self.severity()));
        report.push_str(&format!("Retryable: {}\n", self.is_retryable()));

        let chain = self.error_chain();
        if chain.len() > 1 {
            report.push_str("Error Chain:\n");
            for (i, err) in chain.iter().enumerate() {
                report.push_str(&format!("  {}: {}\n", i, err));
            }
        }

        report
    }

    /// Create BadRequest error
    pub fn bad_request(message: impl Into<String>) -> Self {
        Error::BadRequest(message.into())
    }

    /// Create InvalidArgument error
    pub fn invalid_argument(message: impl Into<String>) -> Self {
        Error::InvalidArgument(message.into())
    }

    /// Create Forbidden error
    pub fn forbidden(message: impl Into<String>) -> Self {
        // The base enum doesn't take a message, so we use Unknown with a descriptive message
        Error::Unknown(format!("Forbidden: {}", message.into()))
    }

    /// Create NotFound error
    pub fn not_found(message: impl Into<String>) -> Self {
        // The base enum doesn't take a message, so we use Unknown with a descriptive message
        Error::Unknown(format!("Not found: {}", message.into()))
    }

    /// Create QuotaExceeded error
    pub fn quota_exceeded(message: impl Into<String>) -> Self {
        Error::QuotaExceeded(message.into())
    }

    /// Create Unknown error
    pub fn unknown(message: impl Into<String>) -> Self {
        Error::Unknown(message.into())
    }

    /// Create Configuration error
    pub fn configuration(message: impl Into<String>) -> Self {
        Error::Configuration {
            message: message.into(),
        }
    }

    /// Create Validation error
    pub fn validation(message: impl Into<String>, field: Option<String>) -> Self {
        Error::Validation {
            message: message.into(),
            field,
        }
    }

    /// Create IO error
    pub fn io_error(message: impl Into<String>) -> Self {
        Error::Io {
            message: message.into(),
        }
    }
}

pub type Result<T> = std::result::Result<T, Error>;

/// Error handling utilities and helper functions
pub mod utils {
    use super::*;
    use std::time::Duration;

    /// Common error conversion utilities
    pub trait ErrorConversion {
        /// Convert to BadRequest error with message
        fn to_bad_request(self, message: impl Into<String>) -> Error;
        /// Convert to Configuration error with message
        fn to_config_error(self, message: impl Into<String>) -> Error;
        /// Convert to Validation error with message and optional field
        fn to_validation_error(self, message: impl Into<String>, field: Option<String>) -> Error;
        /// Convert to IO error with message
        fn to_io_error(self, message: impl Into<String>) -> Error;
    }

    impl<E: std::error::Error> ErrorConversion for E {
        fn to_bad_request(self, message: impl Into<String>) -> Error {
            Error::bad_request(format!("{}: {}", message.into(), self))
        }

        fn to_config_error(self, message: impl Into<String>) -> Error {
            Error::configuration(format!("{}: {}", message.into(), self))
        }

        fn to_validation_error(self, message: impl Into<String>, field: Option<String>) -> Error {
            Error::validation(format!("{}: {}", message.into(), self), field)
        }

        fn to_io_error(self, message: impl Into<String>) -> Error {
            Error::io_error(format!("{}: {}", message.into(), self))
        }
    }

    /// API-specific error detection utilities
    pub struct ApiErrorDetector;

    impl ApiErrorDetector {
        /// Detect if response indicates rate limiting
        pub fn is_rate_limited(status: reqwest::StatusCode, body: &str) -> bool {
            status == 429
                || body.contains("rate limit")
                || body.contains("too many requests")
                || body.contains("quota exceeded")
        }

        /// Detect if response indicates quota exceeded
        pub fn is_quota_exceeded(status: reqwest::StatusCode, body: &str) -> bool {
            status == 429
                || body.contains("quota exceeded")
                || body.contains("limit exceeded")
                || body.contains("usage limit")
        }

        /// Detect if response indicates authentication issues
        pub fn is_auth_error(status: reqwest::StatusCode, body: &str) -> bool {
            status == 401
                || status == 403
                || body.contains("unauthorized")
                || body.contains("forbidden")
                || body.contains("invalid api key")
                || body.contains("authentication")
        }

        /// Detect if error is temporary/transient
        pub fn is_temporary(status: reqwest::StatusCode, body: &str) -> bool {
            matches!(status.as_u16(), 502..=504)
                || body.contains("temporary")
                || body.contains("transient")
                || body.contains("try again")
        }

        /// Extract retry-after header value
        pub fn extract_retry_after(headers: &reqwest::header::HeaderMap) -> Option<u64> {
            headers
                .get(reqwest::header::RETRY_AFTER)
                .and_then(|v| v.to_str().ok())
                .and_then(|s| s.parse().ok())
        }

        /// Determine appropriate retry delay based on error type
        pub fn suggest_retry_delay(error: &Error) -> Option<Duration> {
            match error {
                Error::TooManyRequests => Some(Duration::from_secs(60)),
                Error::QuotaExceeded(_) => Some(Duration::from_secs(3600)), // 1 hour default
                Error::TransientError => Some(Duration::from_secs(30)),
                Error::DeadlineExceeded => Some(Duration::from_secs(10)),
                _ => None,
            }
        }
    }

    /// Retry policy utilities
    pub struct RetryPolicy {
        max_attempts: usize,
        base_delay: Duration,
        max_delay: Duration,
        backoff_multiplier: f64,
    }

    impl RetryPolicy {
        /// Create a new retry policy
        pub fn new(
            max_attempts: usize,
            base_delay: Duration,
            max_delay: Duration,
            backoff_multiplier: f64,
        ) -> Self {
            Self {
                max_attempts,
                base_delay,
                max_delay,
                backoff_multiplier,
            }
        }

        /// Default retry policy for API calls
        pub fn default_api() -> Self {
            Self {
                max_attempts: 3,
                base_delay: Duration::from_millis(100),
                max_delay: Duration::from_secs(60),
                backoff_multiplier: 2.0,
            }
        }

        /// Aggressive retry policy for critical operations
        pub fn aggressive() -> Self {
            Self {
                max_attempts: 5,
                base_delay: Duration::from_millis(50),
                max_delay: Duration::from_secs(30),
                backoff_multiplier: 1.5,
            }
        }

        /// Conservative retry policy for rate-limited operations
        pub fn conservative() -> Self {
            Self {
                max_attempts: 2,
                base_delay: Duration::from_secs(1),
                max_delay: Duration::from_secs(300), // 5 minutes
                backoff_multiplier: 3.0,
            }
        }

        /// Check if error should be retried based on this policy
        pub fn should_retry(&self, error: &Error, attempt: usize) -> bool {
            attempt < self.max_attempts && error.is_retryable()
        }

        /// Calculate delay for the given attempt number
        pub fn delay_for_attempt(&self, attempt: usize, error: &Error) -> Duration {
            // Use error-specific delay if available
            if let Some(suggested) = ApiErrorDetector::suggest_retry_delay(error) {
                return suggested.min(self.max_delay);
            }

            // Calculate exponential backoff
            let delay_ms =
                self.base_delay.as_millis() as f64 * self.backoff_multiplier.powi(attempt as i32);
            let delay = Duration::from_millis(delay_ms as u64);
            delay.min(self.max_delay)
        }
    }
}

/// Error handling macros for reducing boilerplate
#[macro_export]
macro_rules! bail_if {
    ($condition:expr, $error:expr) => {
        if $condition {
            return Err($error);
        }
    };
}

/// Ensure condition is true or return error
#[macro_export]
macro_rules! ensure {
    ($condition:expr, $error:expr) => {
        if !$condition {
            return Err($error);
        }
    };
}

/// Add context to a result
#[macro_export]
macro_rules! context {
    ($result:expr, $message:expr) => {
        $result.map_err(|e| $crate::Error::unknown(format!("{}: {}", $message, e)))
    };
}

/// Map error with context
#[macro_export]
macro_rules! map_err_context {
    ($result:expr, $message:expr) => {
        $result.map_err(|e| $crate::Error::unknown(format!("{}: {}", $message, e)))
    };
}

// Add chrono dependency for timestamps
use chrono;

#[cfg(test)]
mod tests {
    use super::*;

    use std::time::Duration;

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

    #[test]
    fn test_error_categorization() {
        let auth_error = Error::AuthenticationRequired;
        assert_eq!(auth_error.category(), ErrorCategory::Authentication);
        assert!(auth_error.is_authentication_error());

        let client_error = Error::bad_request("test");
        assert_eq!(client_error.category(), ErrorCategory::Client);
        assert!(client_error.is_client_error());

        let server_error = Error::TransientError;
        assert_eq!(server_error.category(), ErrorCategory::Server);
        assert!(server_error.is_server_error());

        let rate_limit_error = Error::TooManyRequests;
        assert_eq!(rate_limit_error.category(), ErrorCategory::RateLimit);
        assert!(rate_limit_error.is_rate_limit_error());
    }

    #[test]
    fn test_error_severity() {
        let low_error = Error::NotAvailableYet;
        assert_eq!(low_error.severity(), ErrorSeverity::Low);

        let medium_error = Error::bad_request("test");
        assert_eq!(medium_error.severity(), ErrorSeverity::Medium);

        let high_error = Error::AuthenticationRequired;
        assert_eq!(high_error.severity(), ErrorSeverity::High);

        let critical_error = Error::UserNotActive;
        assert_eq!(critical_error.severity(), ErrorSeverity::Critical);
    }

    #[test]
    fn test_error_context() {
        let context = ErrorContext::with_operation("test_op")
            .with_resource("/api/test")
            .with_metadata("key", "value")
            .with_request_id("req-123");

        assert_eq!(context.operation.as_ref().unwrap(), "test_op");
        assert_eq!(context.resource.as_ref().unwrap(), "/api/test");
        assert_eq!(context.metadata.get("key").unwrap(), "value");
        assert_eq!(context.request_id.as_ref().unwrap(), "req-123");
    }

    #[test]
    fn test_error_chain() {
        let json_error = serde_json::from_str::<i32>("invalid").unwrap_err();
        let error = Error::Json(json_error);
        let chain = error.error_chain();
        assert!(chain.len() > 1);
        assert!(chain[0].contains("JSON parsing error"));
    }

    #[test]
    fn test_detailed_report() {
        let error = Error::bad_request("test error");
        let report = error.detailed_report();
        assert!(report.contains("Error: Bad request: test error"));
        assert!(report.contains("Category: Client"));
        assert!(report.contains("Severity: Medium"));
        assert!(report.contains("Retryable: false"));
    }

    #[test]
    fn test_api_error_detector() {
        use utils::ApiErrorDetector;

        assert!(ApiErrorDetector::is_rate_limited(
            reqwest::StatusCode::TOO_MANY_REQUESTS,
            ""
        ));
        assert!(ApiErrorDetector::is_rate_limited(
            reqwest::StatusCode::OK,
            "rate limit exceeded"
        ));

        assert!(ApiErrorDetector::is_quota_exceeded(
            reqwest::StatusCode::TOO_MANY_REQUESTS,
            ""
        ));
        assert!(ApiErrorDetector::is_quota_exceeded(
            reqwest::StatusCode::OK,
            "quota exceeded"
        ));

        assert!(ApiErrorDetector::is_auth_error(
            reqwest::StatusCode::UNAUTHORIZED,
            ""
        ));
        assert!(ApiErrorDetector::is_auth_error(
            reqwest::StatusCode::OK,
            "unauthorized"
        ));

        assert!(ApiErrorDetector::is_temporary(
            reqwest::StatusCode::SERVICE_UNAVAILABLE,
            ""
        ));
        assert!(ApiErrorDetector::is_temporary(
            reqwest::StatusCode::OK,
            "temporary error"
        ));
    }

    #[test]
    fn test_retry_policy() {
        use utils::RetryPolicy;

        let policy = RetryPolicy::default_api();
        let error = Error::TooManyRequests;

        assert!(policy.should_retry(&error, 0));
        assert!(policy.should_retry(&error, 1));
        assert!(policy.should_retry(&error, 2));
        assert!(!policy.should_retry(&error, 3));

        let non_retryable = Error::bad_request("test");
        assert!(!policy.should_retry(&non_retryable, 0));

        let delay = policy.delay_for_attempt(1, &error);
        assert!(delay >= Duration::from_millis(100));
        assert!(delay <= Duration::from_secs(60));
    }

    #[test]
    fn test_error_macros() {
        use crate::{bail_if, ensure};

        // Test bail_if macro
        fn test_bail_if(should_fail: bool) -> Result<()> {
            bail_if!(should_fail, Error::bad_request("test error"));
            Ok(())
        }

        assert!(test_bail_if(true).is_err());
        assert!(test_bail_if(false).is_ok());

        // Test ensure macro
        fn test_ensure(condition: bool) -> Result<()> {
            ensure!(condition, Error::bad_request("condition failed"));
            Ok(())
        }

        assert!(test_ensure(true).is_ok());
        assert!(test_ensure(false).is_err());
    }

    #[test]
    fn test_error_constructor_methods() {
        let error = Error::bad_request("test message");
        match error {
            Error::BadRequest(msg) => assert_eq!(msg, "test message"),
            _ => panic!("Expected BadRequest error"),
        }

        let error = Error::quota_exceeded("quota limit reached");
        match error {
            Error::QuotaExceeded(msg) => assert_eq!(msg, "quota limit reached"),
            _ => panic!("Expected QuotaExceeded error"),
        }

        let error = Error::configuration("config error");
        match error {
            Error::Configuration { message } => assert_eq!(message, "config error"),
            _ => panic!("Expected Configuration error"),
        }

        let error = Error::validation("validation error", Some("field".to_string()));
        match error {
            Error::Validation { message, field } => {
                assert_eq!(message, "validation error");
                assert_eq!(field.unwrap(), "field");
            }
            _ => panic!("Expected Validation error"),
        }

        let error = Error::io_error("IO error");
        match error {
            Error::Io { message } => assert_eq!(message, "IO error"),
            _ => panic!("Expected IO error"),
        }
    }

    #[test]
    fn test_error_conversion_trait() {
        use utils::ErrorConversion;

        let io_error = std::io::Error::new(std::io::ErrorKind::NotFound, "File not found");
        let vt_error = io_error.to_bad_request("Failed to read config");
        match vt_error {
            Error::BadRequest(msg) => assert!(msg.contains("Failed to read config")),
            _ => panic!("Expected BadRequest error"),
        }

        let io_error = std::io::Error::new(std::io::ErrorKind::PermissionDenied, "Access denied");
        let vt_error = io_error.to_config_error("Configuration access failed");
        match vt_error {
            Error::Configuration { message } => {
                assert!(message.contains("Configuration access failed"))
            }
            _ => panic!("Expected Configuration error"),
        }

        let io_error = std::io::Error::new(std::io::ErrorKind::InvalidInput, "Invalid input");
        let vt_error =
            io_error.to_validation_error("Validation failed", Some("input_field".to_string()));
        match vt_error {
            Error::Validation { message, field } => {
                assert!(message.contains("Validation failed"));
                assert_eq!(field.unwrap(), "input_field");
            }
            _ => panic!("Expected Validation error"),
        }

        let io_error = std::io::Error::new(std::io::ErrorKind::BrokenPipe, "Broken pipe");
        let vt_error = io_error.to_io_error("Network operation failed");
        match vt_error {
            Error::Io { message } => assert!(message.contains("Network operation failed")),
            _ => panic!("Expected IO error"),
        }
    }
}
