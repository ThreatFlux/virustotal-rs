//! Enhanced client builder for VirusTotal API

use super::constants::{COMMON_API_KEY_VARS, PRIVATE_API_KEY_VARS};
use super::rate_limiting::TokenBucketLimiter;
use super::retry::RetryConfig;
use super::utils::detect_api_tier;
use crate::Client;
use crate::auth::{ApiKey, ApiTier};
use crate::error::{Error, Result};
use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
use std::time::Duration;

/// Compatibility builder for client and standalone utility configuration.
///
/// [`Self::build`] applies the API key, API tier, timeout, and base URL. Retry
/// configuration, a custom rate limiter, custom headers, and a custom user agent are
/// currently retained by this builder but are not installed on the returned [`Client`].
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

    /// Determine the API tier to use (either explicit or detected)
    fn determine_api_tier(&self) -> Result<ApiTier> {
        if let Some(tier) = self.tier {
            Ok(tier)
        } else if self.tier_detection {
            let api_key = self
                .api_key
                .as_ref()
                .ok_or_else(|| Error::bad_request("API key is required"))?;
            Ok(detect_api_tier(api_key))
        } else {
            Ok(ApiTier::Public) // Default fallback
        }
    }

    /// Apply client configuration options
    fn apply_client_config(&self, mut client: Client) -> Result<Client> {
        // Apply timeout if specified
        if let Some(timeout) = self.timeout {
            client = client.with_timeout(timeout)?;
        }

        // Apply base URL if specified
        if let Some(base_url) = &self.base_url {
            client = client.with_base_url(base_url)?;
        }

        Ok(client)
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

    /// Record retry configuration for compatibility.
    ///
    /// This setting is not applied to the [`Client`] returned by [`Self::build`]. Use
    /// [`super::RetryUtils::retry_request`] explicitly for operations that are safe to retry.
    pub fn retry_config(mut self, max_attempts: u32, initial_delay: Duration) -> Self {
        self.retry_config = Some(RetryConfig::new(max_attempts, initial_delay));
        self
    }

    /// Record advanced retry configuration for compatibility.
    ///
    /// This setting is not applied to the [`Client`] returned by [`Self::build`].
    pub fn advanced_retry_config(mut self, config: RetryConfig) -> Self {
        self.retry_config = Some(config);
        self
    }

    /// Record a custom rate limiter for compatibility.
    ///
    /// This setting is not applied to the [`Client`] returned by [`Self::build`]. The
    /// returned client uses its core limiter selected by [`ApiTier`].
    pub fn rate_limiter(mut self, limiter: TokenBucketLimiter) -> Self {
        self.rate_limiter = Some(limiter);
        self
    }

    /// Record a custom header for compatibility.
    ///
    /// Headers recorded here are not applied to the [`Client`] returned by [`Self::build`].
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

    /// Record custom headers for compatibility.
    ///
    /// Headers recorded here are not applied to the [`Client`] returned by [`Self::build`].
    pub fn headers(mut self, headers: HeaderMap) -> Self {
        self.headers.extend(headers);
        self
    }

    /// Record a custom user agent for compatibility.
    ///
    /// This setting is not applied to the [`Client`] returned by [`Self::build`].
    pub fn user_agent<U: Into<String>>(mut self, user_agent: U) -> Self {
        self.user_agent = Some(user_agent.into());
        self
    }

    /// Enable heuristic API tier detection based on key format and length.
    ///
    /// This does not query VirusTotal or verify account privileges. Prefer [`Self::tier`]
    /// when the account tier is known.
    pub fn with_tier_detection(mut self) -> Self {
        self.tier_detection = true;
        self
    }

    /// Build a client, applying the API key, tier, timeout, and base URL.
    ///
    /// See the type-level documentation for settings retained but not applied.
    pub fn build(self) -> Result<Client> {
        let api_key = self
            .api_key
            .as_ref()
            .ok_or_else(|| Error::bad_request("API key is required"))?
            .clone();

        let tier = self.determine_api_tier()?;
        let client = Client::new(api_key, tier)?;

        self.apply_client_config(client)
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

    /// Create a preset configuration for testing.
    ///
    /// The returned client uses the public tier and a five-second timeout. The recorded
    /// retry configuration is not applied automatically.
    pub fn testing_config(api_key: &str) -> EnhancedClientBuilder {
        Self::builder()
            .api_key(api_key)
            .tier(ApiTier::Public)
            .timeout(Duration::from_secs(5))
            .retry_config(1, Duration::from_millis(100))
    }

    /// Create a preset configuration for production.
    ///
    /// The returned client uses heuristic tier detection and a 60-second timeout. The
    /// recorded retry configuration is not applied automatically.
    pub fn production_config(api_key: &str) -> EnhancedClientBuilder {
        Self::builder()
            .api_key(api_key)
            .with_tier_detection()
            .timeout(Duration::from_secs(60))
            .retry_config(5, Duration::from_millis(1000))
    }
}
