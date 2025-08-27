#[cfg(test)]
/// Common test data constants for consistent testing
pub mod constants {
    pub const SAMPLE_MD5: &str = "44d88612fea8a8f36de82e1278abb02f";
    pub const SAMPLE_SHA1: &str = "3395856ce81f2b7382dee72602f798b642f14140";
    pub const SAMPLE_SHA256: &str =
        "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f";
    pub const SAMPLE_DOMAIN: &str = "example.com";
    pub const SAMPLE_IP: &str = "8.8.8.8";
    pub const SAMPLE_URL: &str = "https://example.com/test";
    pub const TEST_API_KEY: &str = "test_api_key_123";
    pub const MALICIOUS_HASH: &str =
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    pub const CLEAN_HASH: &str =
        "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9";

    /// Common timestamp for consistent test data
    pub const SAMPLE_TIMESTAMP: i64 = 1609459200; // 2021-01-01 00:00:00 UTC
}