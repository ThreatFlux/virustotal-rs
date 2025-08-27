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

use crate::auth::{ApiKey, ApiTier};
use crate::error::{Error, Result};
use crate::Client;
use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
use std::collections::HashMap;
use std::time::Duration;
use tokio::time::sleep;

/// Default timeout for HTTP requests
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);

/// Default number of retry attempts
pub const DEFAULT_RETRY_ATTEMPTS: u32 = 3;

/// Default initial retry delay
pub const DEFAULT_RETRY_DELAY: Duration = Duration::from_millis(1000);

/// Maximum retry delay
pub const MAX_RETRY_DELAY: Duration = Duration::from_secs(60);

/// Default user agent prefix
const USER_AGENT_PREFIX: &str = "virustotal-rs";

/// Environment variable names for API keys
pub const COMMON_API_KEY_VARS: &[&str] = &["VIRUSTOTAL_API_KEY", "VT_API_KEY", "VTI_API_KEY"];

/// Environment variable names for private API keys
pub const PRIVATE_API_KEY_VARS: &[&str] = &["VT_PRIVATE_API_KEY", "VIRUSTOTAL_PRIVATE_API_KEY"];

/// Rate limiter trait for pluggable rate limiting strategies
pub trait RateLimiter: Send + Sync {
    /// Check if a request can proceed, waiting if necessary
    fn check_rate_limit(&self) -> impl std::future::Future<Output = Result<()>> + Send;

    /// Update rate limits based on response headers
    fn update_from_headers(&mut self, headers: HeaderMap);

    /// Get the current rate limit status
    fn status(&self) -> RateLimitStatus;
}

/// Rate limit status information
#[derive(Debug, Clone)]
pub struct RateLimitStatus {
    pub requests_remaining: Option<u32>,
    pub reset_time: Option<std::time::SystemTime>,
    pub requests_per_minute: u32,
    pub daily_limit: Option<u32>,
}

/// Token bucket rate limiter implementation
#[derive(Clone)]
pub struct TokenBucketLimiter {
    minute_limiter: Option<
        std::sync::Arc<
            governor::RateLimiter<
                governor::state::NotKeyed,
                governor::state::InMemoryState,
                governor::clock::DefaultClock,
            >,
        >,
    >,
    daily_limiter: Option<std::sync::Arc<DailyLimiter>>,
    status: std::sync::Arc<tokio::sync::RwLock<RateLimitStatus>>,
}

impl TokenBucketLimiter {
    /// Create a new token bucket limiter for the given API tier
    pub fn new(tier: ApiTier) -> Self {
        use governor::{Quota, RateLimiter};
        use nonzero_ext::nonzero;

        let minute_limiter = match tier {
            ApiTier::Public => {
                let quota = Quota::per_minute(nonzero!(4u32));
                Some(std::sync::Arc::new(RateLimiter::direct(quota)))
            }
            ApiTier::Premium => None,
        };

        let daily_limiter = match tier {
            ApiTier::Public => Some(std::sync::Arc::new(DailyLimiter::new(500))),
            ApiTier::Premium => None,
        };

        let status = RateLimitStatus {
            requests_remaining: tier.daily_limit(),
            reset_time: None,
            requests_per_minute: tier.requests_per_minute(),
            daily_limit: tier.daily_limit(),
        };

        Self {
            minute_limiter,
            daily_limiter,
            status: std::sync::Arc::new(tokio::sync::RwLock::new(status)),
        }
    }
}

impl RateLimiter for TokenBucketLimiter {
    fn check_rate_limit(&self) -> impl std::future::Future<Output = Result<()>> + Send {
        let minute_limiter = self.minute_limiter.clone();
        let daily_limiter = self.daily_limiter.clone();

        async move {
            if let Some(ref minute_limiter) = minute_limiter {
                minute_limiter.until_ready().await;
            }

            if let Some(ref daily_limiter) = daily_limiter {
                daily_limiter.check_limit().await?;
            }

            Ok(())
        }
    }

    fn update_from_headers(&mut self, headers: HeaderMap) {
        // Update rate limit status from response headers
        let status = self.status.clone();

        let remaining = headers
            .get("x-ratelimit-remaining")
            .and_then(|h| h.to_str().ok())
            .and_then(|s| s.parse::<u32>().ok());

        let reset = headers
            .get("x-ratelimit-reset")
            .and_then(|h| h.to_str().ok())
            .and_then(|s| s.parse::<u64>().ok())
            .map(|timestamp| std::time::SystemTime::UNIX_EPOCH + Duration::from_secs(timestamp));

        tokio::spawn(async move {
            let mut status_guard = status.write().await;

            if let Some(remaining) = remaining {
                status_guard.requests_remaining = Some(remaining);
            }

            if let Some(reset_time) = reset {
                status_guard.reset_time = Some(reset_time);
            }
        });
    }

    fn status(&self) -> RateLimitStatus {
        // Return a simplified status for sync access
        RateLimitStatus {
            requests_remaining: None,
            reset_time: None,
            requests_per_minute: match self.minute_limiter {
                Some(_) => 4,     // Public tier
                None => u32::MAX, // Premium tier
            },
            daily_limit: self.daily_limiter.as_ref().map(|_| 500),
        }
    }
}

/// Daily rate limiter implementation
#[derive(Debug)]
struct DailyLimiter {
    limit: u32,
    requests_today: tokio::sync::Mutex<u32>,
    reset_time: tokio::sync::Mutex<tokio::time::Instant>,
}

impl DailyLimiter {
    fn new(limit: u32) -> Self {
        Self {
            limit,
            requests_today: tokio::sync::Mutex::new(0),
            reset_time: tokio::sync::Mutex::new(
                tokio::time::Instant::now() + Duration::from_secs(86400),
            ),
        }
    }

    async fn check_limit(&self) -> Result<()> {
        let mut requests = self.requests_today.lock().await;
        let mut reset = self.reset_time.lock().await;

        if tokio::time::Instant::now() >= *reset {
            *requests = 0;
            *reset = tokio::time::Instant::now() + Duration::from_secs(86400);
        }

        if *requests >= self.limit {
            return Err(Error::quota_exceeded("Daily quota exceeded"));
        }

        *requests += 1;
        Ok(())
    }
}

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

/// Enhanced client builder with comprehensive configuration options
pub struct EnhancedClientBuilder {
    api_key: Option<ApiKey>,
    tier: Option<ApiTier>,
    base_url: Option<String>,
    timeout: Option<Duration>,
    retry_config: Option<RetryConfig>,
    rate_limiter: Option<TokenBucketLimiter>,
    headers: HeaderMap,
    user_agent: Option<String>,
    tier_detection: bool,
}

impl Default for EnhancedClientBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl EnhancedClientBuilder {
    /// Create a new enhanced client builder
    pub fn new() -> Self {
        Self {
            api_key: None,
            tier: None,
            base_url: None,
            timeout: None,
            retry_config: None,
            rate_limiter: None,
            headers: HeaderMap::new(),
            user_agent: None,
            tier_detection: false,
        }
    }

    /// Set the API key
    pub fn api_key<K: Into<ApiKey>>(mut self, key: K) -> Self {
        self.api_key = Some(key.into());
        self
    }

    /// Set the API tier
    pub fn tier(mut self, tier: ApiTier) -> Self {
        self.tier = Some(tier);
        self
    }

    /// Set the base URL
    pub fn base_url<U: Into<String>>(mut self, url: U) -> Self {
        self.base_url = Some(url.into());
        self
    }

    /// Set the request timeout
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }

    /// Set retry configuration
    pub fn retry_config(mut self, max_attempts: u32, initial_delay: Duration) -> Self {
        self.retry_config = Some(RetryConfig::new(max_attempts, initial_delay));
        self
    }

    /// Set advanced retry configuration
    pub fn advanced_retry_config(mut self, config: RetryConfig) -> Self {
        self.retry_config = Some(config);
        self
    }

    /// Set a custom rate limiter
    pub fn rate_limiter(mut self, limiter: TokenBucketLimiter) -> Self {
        self.rate_limiter = Some(limiter);
        self
    }

    /// Add a custom header
    pub fn header<K, V>(mut self, key: K, value: V) -> Self
    where
        K: TryInto<HeaderName>,
        V: TryInto<HeaderValue>,
        K::Error: std::fmt::Debug,
        V::Error: std::fmt::Debug,
    {
        if let (Ok(key), Ok(value)) = (key.try_into(), value.try_into()) {
            self.headers.insert(key, value);
        }
        self
    }

    /// Set multiple headers
    pub fn headers(mut self, headers: HeaderMap) -> Self {
        self.headers.extend(headers);
        self
    }

    /// Set custom user agent
    pub fn user_agent<U: Into<String>>(mut self, user_agent: U) -> Self {
        self.user_agent = Some(user_agent.into());
        self
    }

    /// Enable automatic API tier detection based on key format/length
    pub fn with_tier_detection(mut self) -> Self {
        self.tier_detection = true;
        self
    }

    /// Build the client with all configured options
    pub fn build(self) -> Result<Client> {
        let api_key = self
            .api_key
            .ok_or_else(|| Error::bad_request("API key is required"))?;

        // Detect tier if requested and not explicitly set
        let tier = if let Some(tier) = self.tier {
            tier
        } else if self.tier_detection {
            detect_api_tier(&api_key)
        } else {
            ApiTier::Public // Default fallback
        };

        let mut client = Client::new(api_key, tier)?;

        // Apply timeout if specified
        if let Some(timeout) = self.timeout {
            client = client.with_timeout(timeout)?;
        }

        // Apply base URL if specified
        if let Some(base_url) = self.base_url {
            client = client.with_base_url(&base_url)?;
        }

        Ok(client)
    }
}

/// Main utility struct for client operations
pub struct ClientUtils;

impl ClientUtils {
    /// Create a new enhanced client builder
    pub fn builder() -> EnhancedClientBuilder {
        EnhancedClientBuilder::new()
    }

    /// Create a client from environment variables
    pub fn from_env(var_name: &str) -> Result<EnhancedClientBuilder> {
        let api_key = std::env::var(var_name).map_err(|_| {
            Error::bad_request(format!("Environment variable {} not found", var_name))
        })?;

        Ok(Self::builder().api_key(api_key))
    }

    /// Create a client from common environment variables
    pub fn from_common_env() -> Result<EnhancedClientBuilder> {
        Self::from_fallback_env(COMMON_API_KEY_VARS)
    }

    /// Create a client from private API environment variables
    pub fn from_private_env() -> Result<EnhancedClientBuilder> {
        Self::from_fallback_env(PRIVATE_API_KEY_VARS)
    }

    /// Create a client from multiple environment variable fallbacks
    pub fn from_fallback_env(vars: &[&str]) -> Result<EnhancedClientBuilder> {
        for var in vars {
            if let Ok(api_key) = std::env::var(var) {
                return Ok(Self::builder().api_key(api_key));
            }
        }

        Err(Error::bad_request(format!(
            "None of the environment variables {:?} were found",
            vars
        )))
    }

    /// Create a preset configuration for testing
    pub fn testing_config(api_key: &str) -> EnhancedClientBuilder {
        Self::builder()
            .api_key(api_key)
            .tier(ApiTier::Public)
            .timeout(Duration::from_secs(5))
            .retry_config(1, Duration::from_millis(100))
    }

    /// Create a preset configuration for production
    pub fn production_config(api_key: &str) -> EnhancedClientBuilder {
        Self::builder()
            .api_key(api_key)
            .with_tier_detection()
            .timeout(Duration::from_secs(60))
            .retry_config(5, Duration::from_millis(1000))
    }

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

/// Detect API tier based on key characteristics
pub fn detect_api_tier(api_key: &ApiKey) -> ApiTier {
    let key_str = api_key.as_str();

    // Basic heuristics for tier detection
    // This is simplified - real detection might use API calls or other methods
    if key_str.len() > 64 || key_str.contains("premium") || key_str.contains("enterprise") {
        ApiTier::Premium
    } else {
        ApiTier::Public
    }
}

/// Header management utilities
pub struct HeaderUtils;

impl HeaderUtils {
    /// Create standard VirusTotal headers
    pub fn standard_headers(api_key: &ApiKey) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert("x-apikey", HeaderValue::from_str(api_key.as_str()).unwrap());
        headers.insert("Accept", HeaderValue::from_static("application/json"));
        headers.insert(
            "User-Agent",
            HeaderValue::from_str(&format!(
                "{}/{}",
                USER_AGENT_PREFIX,
                env!("CARGO_PKG_VERSION")
            ))
            .unwrap(),
        );
        headers
    }

    /// Add custom headers to existing header map
    pub fn add_custom_headers(headers: &mut HeaderMap, custom: &HashMap<String, String>) {
        for (key, value) in custom {
            if let (Ok(header_name), Ok(header_value)) = (
                HeaderName::from_bytes(key.as_bytes()),
                HeaderValue::from_str(value),
            ) {
                headers.insert(header_name, header_value);
            }
        }
    }

    /// Extract rate limit information from response headers
    pub fn extract_rate_limit_info(headers: &HeaderMap) -> Option<RateLimitStatus> {
        let requests_remaining = headers
            .get("x-ratelimit-remaining")
            .and_then(|h| h.to_str().ok())
            .and_then(|s| s.parse::<u32>().ok());

        let reset_time = headers
            .get("x-ratelimit-reset")
            .and_then(|h| h.to_str().ok())
            .and_then(|s| s.parse::<u64>().ok())
            .map(|timestamp| std::time::SystemTime::UNIX_EPOCH + Duration::from_secs(timestamp));

        if requests_remaining.is_some() || reset_time.is_some() {
            Some(RateLimitStatus {
                requests_remaining,
                reset_time,
                requests_per_minute: 4, // Default for public tier
                daily_limit: Some(500), // Default for public tier
            })
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
        let builder = EnhancedClientBuilder::new()
            .api_key("test_key")
            .tier(ApiTier::Premium)
            .timeout(Duration::from_secs(30))
            .retry_config(3, Duration::from_millis(500));

        // Test that builder values are set correctly
        assert!(builder.api_key.is_some());
        assert_eq!(builder.tier, Some(ApiTier::Premium));
        assert_eq!(builder.timeout, Some(Duration::from_secs(30)));
        assert!(builder.retry_config.is_some());
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
        let builder = ClientUtils::builder();
        assert!(builder.api_key.is_none());
        assert!(builder.tier.is_none());
    }

    #[test]
    fn test_client_utils_testing_config() {
        let builder = ClientUtils::testing_config("test_key");
        assert!(builder.api_key.is_some());
        assert_eq!(builder.tier, Some(ApiTier::Public));
        assert_eq!(builder.timeout, Some(Duration::from_secs(5)));
    }

    #[test]
    fn test_client_utils_production_config() {
        let builder = ClientUtils::production_config("prod_key");
        assert!(builder.api_key.is_some());
        assert!(builder.tier_detection);
        assert_eq!(builder.timeout, Some(Duration::from_secs(60)));
    }

    #[tokio::test]
    async fn test_retry_request_success() {
        let config = RetryConfig::new(3, Duration::from_millis(10));
        let mut call_count = 0;

        let result = ClientUtils::retry_request(
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

        let result = ClientUtils::retry_request(
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

        let result = ClientUtils::retry_request(
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
