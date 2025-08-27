//! Example demonstrating the new client utilities
//!
//! This example shows how to use the enhanced ClientUtils for various
//! client creation and configuration scenarios.
//!
//! Usage:
//!   VT_API_KEY=your_key cargo run --example test_client_utilities

use std::time::Duration;
use virustotal_rs::{ApiTier, ClientUtils, RateLimiter, RetryConfig, TokenBucketLimiter};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== VirusTotal Client Utilities Demo ===\n");

    // Example 1: Basic client creation from environment
    println!("1. Creating client from environment variable:");
    match ClientUtils::from_env("VT_API_KEY") {
        Ok(builder) => {
            let _client = builder.with_tier_detection().build()?;
            println!("   ✓ Client created successfully with tier detection");
            println!(
                "   API Key: {}",
                _client.api_key().chars().take(8).collect::<String>() + "..."
            );
        }
        Err(e) => {
            println!("   ⚠️  {}", e);
            println!("   Using fallback demonstration...");
        }
    }

    // Example 2: Using common environment variables
    println!("\n2. Trying common environment variables:");
    match ClientUtils::from_common_env() {
        Ok(builder) => {
            let _client = builder
                .tier(ApiTier::Public)
                .timeout(Duration::from_secs(45))
                .build()?;
            println!("   ✓ Client created from common environment variables");
        }
        Err(e) => {
            println!("   ⚠️  {}", e);
        }
    }

    // Example 3: Advanced client configuration
    println!("\n3. Advanced client configuration:");
    let _client = ClientUtils::builder()
        .api_key("demo_api_key_12345")
        .tier(ApiTier::Premium)
        .timeout(Duration::from_secs(60))
        .retry_config(5, Duration::from_millis(2000))
        .header("X-Custom-Header", "custom-value")
        .user_agent("my-custom-app/1.0")
        .build()?;

    println!("   ✓ Advanced client configured with:");
    println!("     - Premium tier");
    println!("     - 60-second timeout");
    println!("     - 5 retry attempts with 2s initial delay");
    println!("     - Custom headers and user agent");

    // Example 4: Preset configurations
    println!("\n4. Using preset configurations:");

    // Testing configuration
    let _test_client = ClientUtils::testing_config("test_key_123").build()?;
    println!("   ✓ Testing client created with optimized settings");

    // Production configuration
    let _prod_client = ClientUtils::production_config("prod_key_456").build()?;
    println!("   ✓ Production client created with robust settings");

    // Example 5: Rate limiter demonstration
    println!("\n5. Rate limiter demonstration:");
    let rate_limiter = TokenBucketLimiter::new(ApiTier::Public);
    let status = rate_limiter.status();
    println!("   Rate limiter status:");
    println!("     - Requests per minute: {}", status.requests_per_minute);
    println!("     - Daily limit: {:?}", status.daily_limit);
    println!("     - Requests remaining: {:?}", status.requests_remaining);

    // Example 6: Retry configuration
    println!("\n6. Retry configuration examples:");

    let basic_retry = RetryConfig::new(3, Duration::from_millis(1000));
    println!(
        "   Basic retry config: {} attempts, {}ms initial delay",
        basic_retry.max_attempts,
        basic_retry.initial_delay.as_millis()
    );

    let advanced_retry = RetryConfig::new(5, Duration::from_millis(500))
        .with_max_delay(Duration::from_secs(30))
        .with_backoff_multiplier(1.5)
        .with_jitter(true);

    println!("   Advanced retry config:");
    println!("     - Max attempts: {}", advanced_retry.max_attempts);
    println!(
        "     - Initial delay: {}ms",
        advanced_retry.initial_delay.as_millis()
    );
    println!("     - Max delay: {}s", advanced_retry.max_delay.as_secs());
    println!(
        "     - Backoff multiplier: {}",
        advanced_retry.backoff_multiplier
    );
    println!("     - Jitter enabled: {}", advanced_retry.jitter);

    // Example 7: Delay calculation demonstration
    println!("\n7. Retry delay calculation:");
    for attempt in 1..=5 {
        let delay = advanced_retry.calculate_delay(attempt);
        println!("   Attempt {}: {}ms delay", attempt, delay.as_millis());
    }

    // Example 8: Environment variable constants
    println!("\n8. Available environment variable constants:");
    println!(
        "   Common API key vars: {:?}",
        virustotal_rs::COMMON_API_KEY_VARS
    );
    println!(
        "   Private API key vars: {:?}",
        virustotal_rs::PRIVATE_API_KEY_VARS
    );

    // Example 9: API tier detection
    println!("\n9. API tier detection demonstration:");
    let public_key = virustotal_rs::ApiKey::new("short_key");
    let premium_key =
        virustotal_rs::ApiKey::new("very_long_premium_api_key_that_indicates_premium_access_level");

    println!(
        "   Short key detected as: {:?}",
        virustotal_rs::detect_api_tier(&public_key)
    );
    println!(
        "   Long key detected as: {:?}",
        virustotal_rs::detect_api_tier(&premium_key)
    );

    println!("\n✅ Client utilities demonstration completed!");
    println!("   All utilities are ready for use in your VirusTotal applications.");

    Ok(())
}
