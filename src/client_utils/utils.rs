//! Utility functions for client management

use super::constants::USER_AGENT_PREFIX;
use super::rate_limiting::RateLimitStatus;
use crate::auth::{ApiKey, ApiTier};
use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
use std::collections::HashMap;
use std::time::Duration;

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
