//! Rate limiting implementations for VirusTotal API

use crate::auth::ApiTier;
use crate::error::{Error, Result};
use reqwest::header::HeaderMap;
use std::time::Duration;

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
pub(crate) struct DailyLimiter {
    limit: u32,
    requests_today: tokio::sync::Mutex<u32>,
    reset_time: tokio::sync::Mutex<tokio::time::Instant>,
}

impl DailyLimiter {
    pub fn new(limit: u32) -> Self {
        Self {
            limit,
            requests_today: tokio::sync::Mutex::new(0),
            reset_time: tokio::sync::Mutex::new(
                tokio::time::Instant::now() + Duration::from_secs(86400),
            ),
        }
    }

    pub async fn check_limit(&self) -> Result<()> {
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