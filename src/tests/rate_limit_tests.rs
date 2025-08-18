use crate::auth::ApiTier;
use crate::rate_limit::RateLimiter;
use std::time::Duration;

#[tokio::test]
async fn test_rate_limiter_public_tier() {
    let limiter = RateLimiter::new(ApiTier::Public);

    // Public tier should allow 4 requests per minute
    for _ in 0..4 {
        limiter.check_rate_limit().await.unwrap();
    }
    // All 4 requests should complete quickly
}

#[tokio::test]
async fn test_rate_limiter_premium_tier() {
    let limiter = RateLimiter::new(ApiTier::Premium);

    // Premium tier should have no rate limiting
    for _ in 0..100 {
        limiter.check_rate_limit().await.unwrap();
    }
    // All requests should complete immediately
}

#[test]
fn test_rate_limiter_creation() {
    let _limiter_public = RateLimiter::new(ApiTier::Public);
    let _limiter_premium = RateLimiter::new(ApiTier::Premium);
}

#[tokio::test]
async fn test_rate_limiter_public_timing() {
    let limiter = RateLimiter::new(ApiTier::Public);

    let start = std::time::Instant::now();

    // Make 2 quick requests
    limiter.check_rate_limit().await.unwrap();
    limiter.check_rate_limit().await.unwrap();

    // Should complete quickly (within 1 second)
    let elapsed = start.elapsed();
    assert!(elapsed < Duration::from_secs(1));
}

#[tokio::test]
async fn test_rate_limiter_clone() {
    let limiter1 = RateLimiter::new(ApiTier::Public);
    let limiter2 = limiter1.clone();

    // Both should share the same rate limit
    limiter1.check_rate_limit().await.unwrap();
    limiter2.check_rate_limit().await.unwrap();
}
