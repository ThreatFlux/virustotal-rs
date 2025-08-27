//! Retry configuration and utilities

use super::constants::{DEFAULT_RETRY_ATTEMPTS, DEFAULT_RETRY_DELAY, MAX_RETRY_DELAY};
use crate::error::{Error, Result};
use std::time::Duration;
use tokio::time::sleep;

/// Retry configuration for failed requests
#[derive(Debug, Clone)]
pub struct RetryConfig {
    pub max_attempts: u32,
    pub initial_delay: Duration,
    pub max_delay: Duration,
    pub backoff_multiplier: f64,
    pub jitter: bool,
}

impl Default for RetryConfig {
    fn default() -> Self {
        Self {
            max_attempts: DEFAULT_RETRY_ATTEMPTS,
            initial_delay: DEFAULT_RETRY_DELAY,
            max_delay: MAX_RETRY_DELAY,
            backoff_multiplier: 2.0,
            jitter: true,
        }
    }
}

impl RetryConfig {
    /// Create a new retry configuration
    pub fn new(max_attempts: u32, initial_delay: Duration) -> Self {
        Self {
            max_attempts,
            initial_delay,
            ..Default::default()
        }
    }

    /// Set the maximum delay between retries
    pub fn with_max_delay(mut self, max_delay: Duration) -> Self {
        self.max_delay = max_delay;
        self
    }

    /// Set the backoff multiplier
    pub fn with_backoff_multiplier(mut self, multiplier: f64) -> Self {
        self.backoff_multiplier = multiplier;
        self
    }

    /// Enable or disable jitter
    pub fn with_jitter(mut self, jitter: bool) -> Self {
        self.jitter = jitter;
        self
    }

    /// Calculate delay for a given attempt
    pub fn calculate_delay(&self, attempt: u32) -> Duration {
        if attempt == 0 {
            return Duration::ZERO;
        }

        let delay = self.initial_delay.as_millis() as f64
            * self.backoff_multiplier.powi(attempt as i32 - 1);

        let delay = Duration::from_millis(delay as u64);
        let delay = std::cmp::min(delay, self.max_delay);

        if self.jitter {
            // Add random jitter (±25%)
            use std::collections::hash_map::DefaultHasher;
            use std::hash::{Hash, Hasher};

            let mut hasher = DefaultHasher::new();
            attempt.hash(&mut hasher);
            std::thread::current().id().hash(&mut hasher);

            let hash = hasher.finish();
            let jitter_factor = 0.75 + (hash as f64 / u64::MAX as f64) * 0.5;

            Duration::from_millis((delay.as_millis() as f64 * jitter_factor) as u64)
        } else {
            delay
        }
    }
}

/// Retry utilities
pub struct RetryUtils;

impl RetryUtils {
    /// Retry a request operation with exponential backoff
    pub async fn retry_request<F, Fut, T>(mut operation: F, config: &RetryConfig) -> Result<T>
    where
        F: FnMut() -> Fut,
        Fut: std::future::Future<Output = Result<T>>,
    {
        let mut last_error = None;

        for attempt in 0..config.max_attempts {
            match operation().await {
                Ok(result) => return Ok(result),
                Err(e) if e.is_retryable() && attempt < config.max_attempts - 1 => {
                    let delay = config.calculate_delay(attempt + 1);
                    #[cfg(feature = "mcp")]
                    tracing::debug!(
                        "Retrying request after error: {} (attempt {}/{}, delay: {:?})",
                        e,
                        attempt + 1,
                        config.max_attempts,
                        delay
                    );
                    sleep(delay).await;
                    last_error = Some(e);
                }
                Err(e) => return Err(e),
            }
        }

        Err(last_error.unwrap_or_else(|| Error::unknown("All retry attempts failed")))
    }
}
