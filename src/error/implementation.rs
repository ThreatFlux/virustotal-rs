//! Error implementation with methods for analysis and conversion

use super::types::{ApiError, Error, ErrorCategory, ErrorSeverity};
use std::error::Error as StdError;

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
