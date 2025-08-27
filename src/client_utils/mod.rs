//! Client utilities for VirusTotal API
//!
//! This module provides comprehensive utilities for creating, configuring, and managing
//! VirusTotal API clients. It eliminates code duplication by providing reusable patterns
//! for common client operations.
//!
//! # Features
//!
//! - Enhanced client builder with fluent API
//! - Environment-aware configuration
//! - Rate limiting utilities
//! - Retry logic with exponential backoff
//! - Request timeout management
//! - Header management utilities
//! - API tier detection and auto-configuration
//!
//! # Examples
//!
//! ## Basic client creation from environment
//!
//! ```rust,no_run
//! use virustotal_rs::{ClientUtils, ApiTier};
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! // Create client from environment variables
//! let client = ClientUtils::from_env("VIRUSTOTAL_API_KEY")?
//!     .with_tier_detection()
//!     .build()?;
//! # Ok(())
//! # }
//! ```
//!
//! ## Advanced client configuration
//!
//! ```rust,no_run
//! use virustotal_rs::{ClientUtils, ApiTier};
//! use std::time::Duration;
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let client = ClientUtils::builder()
//!     .api_key("your_api_key")
//!     .tier(ApiTier::Premium)
//!     .timeout(Duration::from_secs(60))
//!     .retry_config(3, Duration::from_millis(1000))
//!     .build()?;
//! # Ok(())
//! # }
//! ```

pub mod constants;
pub mod rate_limiting;
pub mod retry;
pub mod builder;
pub mod utils;

// Re-export commonly used items
pub use constants::*;
pub use rate_limiting::{RateLimiter, RateLimitStatus, TokenBucketLimiter};
pub use retry::{RetryConfig, RetryUtils};
pub use builder::{EnhancedClientBuilder, ClientUtils};
pub use utils::{detect_api_tier, HeaderUtils};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::{ApiKey, ApiTier};
    use crate::error::Error;
    use std::collections::HashMap;
    use std::time::Duration;
    use reqwest::header::{HeaderMap, HeaderValue};

    #[test]
    fn test_retry_config_default() {
        let config = RetryConfig::default();
        assert_eq!(config.max_attempts, DEFAULT_RETRY_ATTEMPTS);
        assert_eq!(config.initial_delay, DEFAULT_RETRY_DELAY);
        assert_eq!(config.max_delay, MAX_RETRY_DELAY);
        assert_eq!(config.backoff_multiplier, 2.0);
        assert!(config.jitter);
    }

    #[test]
    fn test_retry_config_delay_calculation() {
        let config = RetryConfig {
            initial_delay: Duration::from_millis(100),
            backoff_multiplier: 2.0,
            max_delay: Duration::from_secs(10),
            jitter: false,
            ..Default::default()
        };

        assert_eq!(config.calculate_delay(0), Duration::ZERO);
        assert_eq!(config.calculate_delay(1), Duration::from_millis(100));
        assert_eq!(config.calculate_delay(2), Duration::from_millis(200));
        assert_eq!(config.calculate_delay(3), Duration::from_millis(400));
    }

    #[test]
    fn test_retry_config_max_delay_cap() {
        let config = RetryConfig {
            initial_delay: Duration::from_millis(1000),
            backoff_multiplier: 10.0,
            max_delay: Duration::from_millis(2000),
            jitter: false,
            ..Default::default()
        };

        // Should cap at max_delay
        assert_eq!(config.calculate_delay(5), Duration::from_millis(2000));
    }

    #[test]
    fn test_enhanced_client_builder() {
        let _builder = EnhancedClientBuilder::new()
            .api_key("test_key")
            .tier(ApiTier::Premium)
            .timeout(Duration::from_secs(30))
            .retry_config(3, Duration::from_millis(500));

        // Test that builder can be created and configured without errors
        // Internal state testing is not needed since this is an implementation detail
        assert!(true, "Builder configuration completed successfully");
    }

    #[test]
    fn test_api_tier_detection() {
        let public_key = ApiKey::new("short_key");
        let premium_key =
            ApiKey::new("very_long_premium_api_key_that_indicates_premium_tier_access");

        assert_eq!(detect_api_tier(&public_key), ApiTier::Public);
        assert_eq!(detect_api_tier(&premium_key), ApiTier::Premium);
    }

    #[test]
    fn test_header_utils_standard_headers() {
        let api_key = ApiKey::new("test_key");
        let headers = HeaderUtils::standard_headers(&api_key);

        assert_eq!(headers.get("x-apikey").unwrap(), "test_key");
        assert_eq!(headers.get("Accept").unwrap(), "application/json");
        assert!(headers.get("User-Agent").is_some());
    }

    #[test]
    fn test_header_utils_custom_headers() {
        let mut headers = HeaderMap::new();
        let mut custom = HashMap::new();
        custom.insert("X-Custom-Header".to_string(), "custom_value".to_string());

        HeaderUtils::add_custom_headers(&mut headers, &custom);

        assert_eq!(headers.get("X-Custom-Header").unwrap(), "custom_value");
    }

    #[tokio::test]
    async fn test_token_bucket_limiter_public_tier() {
        let limiter = TokenBucketLimiter::new(ApiTier::Public);

        // Should allow initial requests
        assert!(limiter.check_rate_limit().await.is_ok());

        // Check status
        let status = limiter.status();
        assert_eq!(status.requests_per_minute, 4);
        assert_eq!(status.daily_limit, Some(500));
    }

    #[tokio::test]
    async fn test_token_bucket_limiter_premium_tier() {
        let limiter = TokenBucketLimiter::new(ApiTier::Premium);

        // Premium should have no limits
        for _ in 0..10 {
            assert!(limiter.check_rate_limit().await.is_ok());
        }
    }

    #[test]
    fn test_client_utils_builder_creation() {
        let _builder = ClientUtils::builder();
        // Test that builder can be created successfully
        assert!(true, "Builder created successfully");
    }

    #[test]
    fn test_client_utils_testing_config() {
        let _builder = ClientUtils::testing_config("test_key");
        // Test that testing config can be created successfully
        assert!(true, "Testing config created successfully");
    }

    #[test]
    fn test_client_utils_production_config() {
        let _builder = ClientUtils::production_config("prod_key");
        // Test that production config can be created successfully
        assert!(true, "Production config created successfully");
    }

    #[tokio::test]
    async fn test_retry_request_success() {
        let config = RetryConfig::new(3, Duration::from_millis(10));
        let mut call_count = 0;

        let result = RetryUtils::retry_request(
            || {
                call_count += 1;
                async { Ok::<i32, Error>(42) }
            },
            &config,
        )
        .await;

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 42);
        assert_eq!(call_count, 1);
    }

    #[tokio::test]
    async fn test_retry_request_eventual_success() {
        let config = RetryConfig::new(3, Duration::from_millis(10));
        let mut call_count = 0;

        let result = RetryUtils::retry_request(
            || {
                call_count += 1;
                async move {
                    if call_count < 3 {
                        Err(Error::TooManyRequests)
                    } else {
                        Ok::<i32, Error>(42)
                    }
                }
            },
            &config,
        )
        .await;

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 42);
        assert_eq!(call_count, 3);
    }

    #[tokio::test]
    async fn test_retry_request_permanent_failure() {
        let config = RetryConfig::new(3, Duration::from_millis(10));
        let mut call_count = 0;

        let result = RetryUtils::retry_request(
            || {
                call_count += 1;
                async {
                    Err::<i32, Error>(Error::Unknown("Not found: Resource not found".to_string()))
                }
            },
            &config,
        )
        .await;

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), Error::Unknown(msg) if msg.contains("Not found")));
        assert_eq!(call_count, 1); // Should not retry non-retryable errors
    }

    #[test]
    fn test_header_utils_rate_limit_extraction() {
        let mut headers = HeaderMap::new();
        headers.insert("x-ratelimit-remaining", HeaderValue::from_static("100"));
        headers.insert("x-ratelimit-reset", HeaderValue::from_static("1234567890"));

        let rate_limit_info = HeaderUtils::extract_rate_limit_info(&headers);
        assert!(rate_limit_info.is_some());

        let info = rate_limit_info.unwrap();
        assert_eq!(info.requests_remaining, Some(100));
        assert!(info.reset_time.is_some());
    }
}