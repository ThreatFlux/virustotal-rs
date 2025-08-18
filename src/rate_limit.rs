use crate::auth::ApiTier;
use governor::clock::DefaultClock;
use governor::state::{InMemoryState, NotKeyed};
use governor::{Quota, RateLimiter as GovernorRateLimiter};
use nonzero_ext::nonzero;
use std::sync::Arc;
use tokio::time::{Duration, Instant};

#[derive(Clone)]
pub struct RateLimiter {
    minute_limiter: Option<Arc<GovernorRateLimiter<NotKeyed, InMemoryState, DefaultClock>>>,
    daily_limiter: Option<Arc<DailyLimiter>>,
}

impl RateLimiter {
    pub fn new(tier: ApiTier) -> Self {
        let minute_limiter = match tier {
            ApiTier::Public => {
                let quota = Quota::per_minute(nonzero!(4u32));
                Some(Arc::new(GovernorRateLimiter::direct(quota)))
            }
            ApiTier::Premium => None,
        };

        let daily_limiter = match tier {
            ApiTier::Public => Some(Arc::new(DailyLimiter::new(500))),
            ApiTier::Premium => None,
        };

        Self {
            minute_limiter,
            daily_limiter,
        }
    }

    pub async fn check_rate_limit(&self) -> Result<(), RateLimitError> {
        if let Some(ref minute_limiter) = self.minute_limiter {
            minute_limiter.until_ready().await;
        }

        if let Some(ref daily_limiter) = self.daily_limiter {
            daily_limiter.check_limit().await?;
        }

        Ok(())
    }
}

struct DailyLimiter {
    limit: u32,
    requests_today: tokio::sync::Mutex<u32>,
    reset_time: tokio::sync::Mutex<Instant>,
}

impl DailyLimiter {
    fn new(limit: u32) -> Self {
        Self {
            limit,
            requests_today: tokio::sync::Mutex::new(0),
            reset_time: tokio::sync::Mutex::new(Instant::now() + Duration::from_secs(86400)),
        }
    }

    async fn check_limit(&self) -> Result<(), RateLimitError> {
        let mut requests = self.requests_today.lock().await;
        let mut reset = self.reset_time.lock().await;

        if Instant::now() >= *reset {
            *requests = 0;
            *reset = Instant::now() + Duration::from_secs(86400);
        }

        if *requests >= self.limit {
            return Err(RateLimitError::DailyQuotaExceeded);
        }

        *requests += 1;
        Ok(())
    }
}

#[derive(Debug, thiserror::Error)]
pub enum RateLimitError {
    #[error("Daily quota exceeded")]
    DailyQuotaExceeded,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_public_rate_limiter() {
        let limiter = RateLimiter::new(ApiTier::Public);

        for _ in 0..4 {
            assert!(limiter.check_rate_limit().await.is_ok());
        }
    }

    #[tokio::test]
    async fn test_premium_rate_limiter() {
        let limiter = RateLimiter::new(ApiTier::Premium);

        for _ in 0..100 {
            assert!(limiter.check_rate_limit().await.is_ok());
        }
    }
}
