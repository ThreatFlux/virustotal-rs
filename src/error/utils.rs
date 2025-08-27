//! Error handling utilities and helper functions

use super::types::Error;
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
