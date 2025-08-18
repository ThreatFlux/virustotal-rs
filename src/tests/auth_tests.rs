use crate::auth::{ApiKey, ApiTier};

#[test]
fn test_api_key_creation() {
    let key = ApiKey::new("test_key");
    assert_eq!(key.as_str(), "test_key");
}

#[test]
fn test_api_key_from_string() {
    let key: ApiKey = String::from("test_key").into();
    assert_eq!(key.as_str(), "test_key");
}

#[test]
fn test_api_key_from_str() {
    let key: ApiKey = "test_key".into();
    assert_eq!(key.as_str(), "test_key");
}

#[test]
fn test_api_tier_public_limits() {
    let tier = ApiTier::Public;
    assert_eq!(tier.daily_limit(), Some(500));
    assert_eq!(tier.requests_per_minute(), 4);
}

#[test]
fn test_api_tier_premium_limits() {
    let tier = ApiTier::Premium;
    assert_eq!(tier.daily_limit(), None);
    assert_eq!(tier.requests_per_minute(), u32::MAX);
}

#[test]
fn test_api_tier_variants() {
    // Test each variant exists and can be created
    let public = ApiTier::Public;
    let premium = ApiTier::Premium;

    assert!(matches!(public, ApiTier::Public));
    assert!(matches!(premium, ApiTier::Premium));
}

#[test]
fn test_api_tier_clone() {
    let tier1 = ApiTier::Premium;
    let tier2 = tier1;
    assert!(matches!(tier2, ApiTier::Premium));
}

#[test]
fn test_api_tier_debug() {
    let tier = ApiTier::Public;
    let debug_str = format!("{:?}", tier);
    assert!(debug_str.contains("Public"));
}
