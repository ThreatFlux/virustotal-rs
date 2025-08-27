#[cfg(test)]
pub mod test_utilities {
    use crate::auth::ApiTier;
    use crate::client::{Client, ClientBuilder};
    use crate::common::AnalysisStats;
    use crate::error::Result;
    use serde_json::{json, Value};
    use std::collections::HashMap;
    use std::time::Duration;
    use wiremock::{MockServer, ResponseTemplate};

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

    /// Test environment setup and cleanup utilities
    pub struct TestEnvironment;

    impl TestEnvironment {
        /// Setup consistent test environment
        pub fn setup() {
            std::env::set_var("RUST_LOG", "debug");
            // Initialize other test environment variables if needed
        }

        /// Cleanup test environment
        pub fn cleanup() {
            // Cleanup any temporary files or state if needed
        }

        /// Execute a test with proper setup and cleanup
        pub async fn with_test_env<F, Fut, R>(test: F) -> R
        where
            F: FnOnce() -> Fut,
            Fut: std::future::Future<Output = R>,
        {
            Self::setup();
            let result = test().await;
            Self::cleanup();
            result
        }

        /// Execute a test with a temporary file
        pub async fn with_temp_file<F, Fut, R>(content: &[u8], test: F) -> R
        where
            F: FnOnce(std::path::PathBuf) -> Fut,
            Fut: std::future::Future<Output = R>,
        {
            use std::io::Write;
            let mut temp_file = tempfile::NamedTempFile::new().expect("Failed to create temp file");
            temp_file
                .write_all(content)
                .expect("Failed to write to temp file");
            let path = temp_file.path().to_path_buf();
            let result = test(path).await;
            result
        }
    }

    /// Mock API client for testing without real API calls
    pub struct MockApiClient {
        mock_server: MockServer,
        client: Client,
    }

    impl MockApiClient {
        /// Create a new mock API client
        pub async fn new() -> Result<Self> {
            let mock_server = MockServer::start().await;
            let client = ClientBuilder::new()
                .api_key(constants::TEST_API_KEY)
                .tier(ApiTier::Premium)
                .base_url(mock_server.uri())
                .timeout(Duration::from_secs(30))
                .build()?;

            Ok(Self {
                mock_server,
                client,
            })
        }

        /// Create a mock client with custom API key
        pub async fn with_api_key(api_key: &str) -> Result<Self> {
            let mock_server = MockServer::start().await;
            let client = ClientBuilder::new()
                .api_key(api_key)
                .tier(ApiTier::Premium)
                .base_url(mock_server.uri())
                .timeout(Duration::from_secs(30))
                .build()?;

            Ok(Self {
                mock_server,
                client,
            })
        }

        /// Create a public tier mock client
        pub async fn with_public_tier() -> Result<Self> {
            let mock_server = MockServer::start().await;
            let client = ClientBuilder::new()
                .api_key(constants::TEST_API_KEY)
                .tier(ApiTier::Public)
                .base_url(mock_server.uri())
                .timeout(Duration::from_secs(30))
                .build()?;

            Ok(Self {
                mock_server,
                client,
            })
        }

        /// Get reference to the mock server
        pub fn mock_server(&self) -> &MockServer {
            &self.mock_server
        }

        /// Get reference to the client
        pub fn client(&self) -> &Client {
            &self.client
        }
    }

    /// Builder pattern for creating test AnalysisStats
    #[derive(Debug, Clone)]
    pub struct AnalysisStatsBuilder {
        harmless: u32,
        malicious: u32,
        suspicious: u32,
        undetected: u32,
        timeout: u32,
        confirmed_timeout: Option<u32>,
        failure: Option<u32>,
        type_unsupported: Option<u32>,
    }

    impl AnalysisStatsBuilder {
        pub fn new() -> Self {
            Self {
                harmless: 70,
                malicious: 0,
                suspicious: 0,
                undetected: 3,
                timeout: 0,
                confirmed_timeout: Some(0),
                failure: Some(0),
                type_unsupported: Some(2),
            }
        }

        pub fn clean() -> Self {
            Self::new().with_malicious(0).with_suspicious(0)
        }

        pub fn malicious() -> Self {
            Self::new()
                .with_malicious(15)
                .with_suspicious(5)
                .with_harmless(50)
        }

        pub fn suspicious() -> Self {
            Self::new()
                .with_suspicious(20)
                .with_malicious(2)
                .with_harmless(50)
        }

        pub fn with_harmless(mut self, count: u32) -> Self {
            self.harmless = count;
            self
        }

        pub fn with_malicious(mut self, count: u32) -> Self {
            self.malicious = count;
            self
        }

        pub fn with_suspicious(mut self, count: u32) -> Self {
            self.suspicious = count;
            self
        }

        pub fn with_undetected(mut self, count: u32) -> Self {
            self.undetected = count;
            self
        }

        pub fn with_timeout(mut self, count: u32) -> Self {
            self.timeout = count;
            self
        }

        pub fn with_confirmed_timeout(mut self, count: Option<u32>) -> Self {
            self.confirmed_timeout = count;
            self
        }

        pub fn with_failure(mut self, count: Option<u32>) -> Self {
            self.failure = count;
            self
        }

        pub fn with_type_unsupported(mut self, count: Option<u32>) -> Self {
            self.type_unsupported = count;
            self
        }

        pub fn build(self) -> AnalysisStats {
            AnalysisStats {
                harmless: self.harmless,
                malicious: self.malicious,
                suspicious: self.suspicious,
                undetected: self.undetected,
                timeout: self.timeout,
                confirmed_timeout: self.confirmed_timeout,
                failure: self.failure,
                type_unsupported: self.type_unsupported,
            }
        }
    }

    impl Default for AnalysisStatsBuilder {
        fn default() -> Self {
            Self::new()
        }
    }

    /// Builder pattern for creating test File objects
    #[derive(Debug, Clone)]
    pub struct FileResponseBuilder {
        id: String,
        md5: Option<String>,
        sha1: Option<String>,
        sha256: Option<String>,
        size: Option<u64>,
        type_description: Option<String>,
        type_tag: Option<String>,
        names: Option<Vec<String>>,
        reputation: Option<i32>,
        stats: Option<AnalysisStats>,
        tags: Option<Vec<String>>,
        creation_date: Option<i64>,
        last_analysis_date: Option<i64>,
    }

    impl FileResponseBuilder {
        pub fn new(id: impl Into<String>) -> Self {
            Self {
                id: id.into(),
                md5: Some(constants::SAMPLE_MD5.to_string()),
                sha1: Some(constants::SAMPLE_SHA1.to_string()),
                sha256: Some(constants::SAMPLE_SHA256.to_string()),
                size: Some(1024),
                type_description: Some("ASCII text".to_string()),
                type_tag: Some("text".to_string()),
                names: Some(vec!["test.txt".to_string()]),
                reputation: Some(0),
                stats: Some(AnalysisStatsBuilder::clean().build()),
                tags: None,
                creation_date: Some(constants::SAMPLE_TIMESTAMP),
                last_analysis_date: Some(constants::SAMPLE_TIMESTAMP),
            }
        }

        pub fn clean_file() -> Self {
            Self::new(constants::CLEAN_HASH)
        }

        pub fn malicious_file() -> Self {
            Self::new(constants::MALICIOUS_HASH)
                .with_stats(AnalysisStatsBuilder::malicious().build())
                .with_reputation(-50)
                .with_tags(vec!["malware".to_string(), "trojan".to_string()])
        }

        pub fn with_md5(mut self, md5: impl Into<String>) -> Self {
            self.md5 = Some(md5.into());
            self
        }

        pub fn with_sha1(mut self, sha1: impl Into<String>) -> Self {
            self.sha1 = Some(sha1.into());
            self
        }

        pub fn with_sha256(mut self, sha256: impl Into<String>) -> Self {
            self.sha256 = Some(sha256.into());
            self
        }

        pub fn with_size(mut self, size: u64) -> Self {
            self.size = Some(size);
            self
        }

        pub fn with_type_description(mut self, desc: impl Into<String>) -> Self {
            self.type_description = Some(desc.into());
            self
        }

        pub fn with_reputation(mut self, reputation: i32) -> Self {
            self.reputation = Some(reputation);
            self
        }

        pub fn with_stats(mut self, stats: AnalysisStats) -> Self {
            self.stats = Some(stats);
            self
        }

        pub fn with_tags(mut self, tags: Vec<String>) -> Self {
            self.tags = Some(tags);
            self
        }

        pub fn with_names(mut self, names: Vec<String>) -> Self {
            self.names = Some(names);
            self
        }

        pub fn build(self) -> Value {
            json!({
                "type": "file",
                "id": self.id,
                "attributes": {
                    "md5": self.md5,
                    "sha1": self.sha1,
                    "sha256": self.sha256,
                    "size": self.size,
                    "type_description": self.type_description,
                    "type_tag": self.type_tag,
                    "names": self.names,
                    "reputation": self.reputation,
                    "last_analysis_stats": self.stats,
                    "tags": self.tags,
                    "creation_date": self.creation_date,
                    "last_analysis_date": self.last_analysis_date
                }
            })
        }
    }

    /// Builder pattern for creating test Domain objects
    #[derive(Debug, Clone)]
    pub struct DomainResponseBuilder {
        id: String,
        reputation: Option<i32>,
        stats: Option<AnalysisStats>,
        tags: Option<Vec<String>>,
        creation_date: Option<i64>,
        last_analysis_date: Option<i64>,
        whois: Option<String>,
        categories: Option<HashMap<String, String>>,
    }

    impl DomainResponseBuilder {
        pub fn new(id: impl Into<String>) -> Self {
            let mut categories = HashMap::new();
            categories.insert(
                "Forcepoint ThreatSeeker".to_string(),
                "search engines and portals".to_string(),
            );

            Self {
                id: id.into(),
                reputation: Some(0),
                stats: Some(AnalysisStatsBuilder::clean().build()),
                tags: None,
                creation_date: Some(820454400), // 1996-01-01
                last_analysis_date: Some(constants::SAMPLE_TIMESTAMP),
                whois: Some(
                    "Domain Name: EXAMPLE.COM\\nRegistry Domain ID: 2336799_DOMAIN_COM-VRSN"
                        .to_string(),
                ),
                categories: Some(categories),
            }
        }

        pub fn clean_domain() -> Self {
            Self::new(constants::SAMPLE_DOMAIN)
        }

        pub fn malicious_domain() -> Self {
            Self::new("malicious-example.com")
                .with_stats(AnalysisStatsBuilder::malicious().build())
                .with_reputation(-80)
                .with_tags(vec!["malware".to_string(), "phishing".to_string()])
        }

        pub fn with_reputation(mut self, reputation: i32) -> Self {
            self.reputation = Some(reputation);
            self
        }

        pub fn with_stats(mut self, stats: AnalysisStats) -> Self {
            self.stats = Some(stats);
            self
        }

        pub fn with_tags(mut self, tags: Vec<String>) -> Self {
            self.tags = Some(tags);
            self
        }

        pub fn with_whois(mut self, whois: impl Into<String>) -> Self {
            self.whois = Some(whois.into());
            self
        }

        pub fn build(self) -> Value {
            json!({
                "type": "domain",
                "id": self.id,
                "attributes": {
                    "reputation": self.reputation,
                    "last_analysis_stats": self.stats,
                    "tags": self.tags,
                    "creation_date": self.creation_date,
                    "last_analysis_date": self.last_analysis_date,
                    "whois": self.whois,
                    "categories": self.categories
                }
            })
        }
    }

    /// Builder pattern for creating test IP Address objects
    #[derive(Debug, Clone)]
    pub struct IpResponseBuilder {
        id: String,
        country: Option<String>,
        as_owner: Option<String>,
        asn: Option<u32>,
        network: Option<String>,
        reputation: Option<i32>,
        stats: Option<AnalysisStats>,
        tags: Option<Vec<String>>,
        last_analysis_date: Option<i64>,
        whois: Option<String>,
    }

    impl IpResponseBuilder {
        pub fn new(id: impl Into<String>) -> Self {
            Self {
                id: id.into(),
                country: Some("US".to_string()),
                as_owner: Some("Google LLC".to_string()),
                asn: Some(15169),
                network: Some("8.8.8.0/24".to_string()),
                reputation: Some(0),
                stats: Some(AnalysisStatsBuilder::clean().build()),
                tags: None,
                last_analysis_date: Some(constants::SAMPLE_TIMESTAMP),
                whois: Some("NetRange: 8.8.8.0 - 8.8.8.255".to_string()),
            }
        }

        pub fn clean_ip() -> Self {
            Self::new(constants::SAMPLE_IP)
        }

        pub fn malicious_ip() -> Self {
            Self::new("192.168.1.100")
                .with_stats(AnalysisStatsBuilder::malicious().build())
                .with_reputation(-60)
                .with_tags(vec!["malware".to_string(), "botnet".to_string()])
                .with_country("RU".to_string())
        }

        pub fn with_country(mut self, country: impl Into<String>) -> Self {
            self.country = Some(country.into());
            self
        }

        pub fn with_as_owner(mut self, as_owner: impl Into<String>) -> Self {
            self.as_owner = Some(as_owner.into());
            self
        }

        pub fn with_asn(mut self, asn: u32) -> Self {
            self.asn = Some(asn);
            self
        }

        pub fn with_reputation(mut self, reputation: i32) -> Self {
            self.reputation = Some(reputation);
            self
        }

        pub fn with_stats(mut self, stats: AnalysisStats) -> Self {
            self.stats = Some(stats);
            self
        }

        pub fn with_tags(mut self, tags: Vec<String>) -> Self {
            self.tags = Some(tags);
            self
        }

        pub fn build(self) -> Value {
            json!({
                "type": "ip_address",
                "id": self.id,
                "attributes": {
                    "country": self.country,
                    "as_owner": self.as_owner,
                    "asn": self.asn,
                    "network": self.network,
                    "reputation": self.reputation,
                    "last_analysis_stats": self.stats,
                    "tags": self.tags,
                    "last_analysis_date": self.last_analysis_date,
                    "whois": self.whois
                }
            })
        }
    }

    /// Response factory for creating various mock responses
    pub struct ResponseFactory;

    impl ResponseFactory {
        /// Create a successful response with data
        pub fn success_response(data: Value) -> Value {
            json!({ "data": data })
        }

        /// Create a collection response with pagination
        pub fn collection_response(items: Vec<Value>, cursor: Option<&str>) -> Value {
            let mut response = json!({
                "data": items,
                "meta": {
                    "count": items.len()
                }
            });

            if let Some(cursor_value) = cursor {
                response["links"] = json!({
                    "next": format!("https://www.virustotal.com/api/v3/files?cursor={}", cursor_value)
                });
            }

            response
        }

        /// Create an error response
        pub fn error_response(status_code: u16, error_code: &str, message: &str) -> (u16, Value) {
            (
                status_code,
                json!({
                    "error": {
                        "code": error_code,
                        "message": message
                    }
                }),
            )
        }

        /// Create a rate limit error response
        pub fn rate_limit_error() -> (u16, Value) {
            Self::error_response(429, "QuotaExceededError", "Request rate limit exceeded")
        }

        /// Create a not found error response
        pub fn not_found_error() -> (u16, Value) {
            Self::error_response(404, "NotFoundError", "The requested resource was not found")
        }

        /// Create an unauthorized error response
        pub fn unauthorized_error() -> (u16, Value) {
            Self::error_response(401, "AuthenticationRequiredError", "API key is required")
        }

        /// Create a forbidden error response
        pub fn forbidden_error() -> (u16, Value) {
            Self::error_response(403, "ForbiddenError", "Access to the resource is forbidden")
        }
    }

    /// Mock response template with common VirusTotal headers
    pub fn create_mock_response(status: u16) -> ResponseTemplate {
        ResponseTemplate::new(status)
            .append_header("Content-Type", "application/json")
            .append_header("X-RateLimit-Remaining", "999")
            .append_header("X-RateLimit-Reset", "3600")
    }

    /// Mock response with JSON body
    pub fn create_json_response(status: u16, body: &Value) -> ResponseTemplate {
        create_mock_response(status).set_body_json(body)
    }
}

/// Custom assertion macros for common test patterns
#[cfg(test)]
pub mod assertions {

    /// Assert that analysis statistics indicate clean results
    #[macro_export]
    macro_rules! assert_analysis_clean {
        ($stats:expr) => {
            assert_eq!($stats.malicious, 0, "Expected no malicious detections");
            assert_eq!($stats.suspicious, 0, "Expected no suspicious detections");
            assert!($stats.harmless > 0, "Expected some harmless detections");
        };
    }

    /// Assert that analysis statistics indicate malicious results
    #[macro_export]
    macro_rules! assert_analysis_malicious {
        ($stats:expr) => {
            assert!(
                $stats.malicious > 0 || $stats.suspicious > 0,
                "Expected malicious or suspicious detections"
            );
        };
    }

    /// Assert that a result has a specific error type
    #[macro_export]
    macro_rules! assert_error_type {
        ($result:expr, $error_type:pat) => {
            match $result {
                Err($error_type) => {}
                Ok(_) => panic!("Expected error, got success"),
                Err(other) => panic!("Expected specific error type, got: {:?}", other),
            }
        };
    }

    /// Assert that a value is within a specific range
    #[macro_export]
    macro_rules! assert_in_range {
        ($value:expr, $min:expr, $max:expr) => {
            assert!(
                ($min..=$max).contains(&$value),
                "Expected {} to be between {} and {}",
                $value,
                $min,
                $max
            );
        };
    }

    /// Assert that a string contains a substring
    #[macro_export]
    macro_rules! assert_contains_substring {
        ($haystack:expr, $needle:expr) => {
            assert!(
                $haystack.contains($needle),
                "Expected '{}' to contain '{}'",
                $haystack,
                $needle
            );
        };
    }

    /// Assert that an HTTP status code is successful
    #[macro_export]
    macro_rules! assert_http_success {
        ($status:expr) => {
            assert!(
                $status >= 200 && $status < 300,
                "Expected successful HTTP status, got: {}",
                $status
            );
        };
    }

    /// Assert that an HTTP status code indicates an error
    #[macro_export]
    macro_rules! assert_http_error {
        ($status:expr) => {
            assert!(
                $status >= 400,
                "Expected HTTP error status, got: {}",
                $status
            );
        };
    }
}

#[cfg(test)]
mod tests {
    use super::test_utilities::*;
    use crate::{
        assert_analysis_clean, assert_analysis_malicious, assert_contains_substring,
        assert_in_range,
    };
    use wiremock::{
        matchers::{header, method, path},
        Mock,
    };

    #[tokio::test]
    async fn test_mock_api_client_creation() {
        let mock_client = MockApiClient::new().await.unwrap();
        assert_eq!(mock_client.client().api_key(), constants::TEST_API_KEY);
    }

    #[tokio::test]
    async fn test_analysis_stats_builder() {
        let stats = AnalysisStatsBuilder::clean().build();
        assert_analysis_clean!(stats);

        let malicious_stats = AnalysisStatsBuilder::malicious().build();
        assert_analysis_malicious!(malicious_stats);
    }

    #[tokio::test]
    async fn test_file_response_builder() {
        let file_response = FileResponseBuilder::clean_file().build();
        assert_eq!(file_response["type"], "file");
        assert_eq!(file_response["id"], constants::CLEAN_HASH);

        let malicious_file = FileResponseBuilder::malicious_file().build();
        assert_eq!(malicious_file["id"], constants::MALICIOUS_HASH);
        assert!(malicious_file["attributes"]["reputation"].as_i64().unwrap() < 0);
    }

    #[tokio::test]
    async fn test_domain_response_builder() {
        let domain_response = DomainResponseBuilder::clean_domain().build();
        assert_eq!(domain_response["type"], "domain");
        assert_eq!(domain_response["id"], constants::SAMPLE_DOMAIN);
    }

    #[tokio::test]
    async fn test_ip_response_builder() {
        let ip_response = IpResponseBuilder::clean_ip().build();
        assert_eq!(ip_response["type"], "ip_address");
        assert_eq!(ip_response["id"], constants::SAMPLE_IP);
    }

    #[tokio::test]
    async fn test_response_factory() {
        let data = serde_json::json!({"test": "data"});
        let success = ResponseFactory::success_response(data.clone());
        assert_eq!(success["data"], data);

        let collection =
            ResponseFactory::collection_response(vec![data.clone()], Some("cursor123"));
        assert_eq!(collection["data"][0], data);
        assert!(collection["links"]["next"]
            .as_str()
            .unwrap()
            .contains("cursor123"));

        let (status, error) = ResponseFactory::rate_limit_error();
        assert_eq!(status, 429);
        assert_eq!(error["error"]["code"], "QuotaExceededError");
    }

    #[tokio::test]
    async fn test_mock_integration() {
        let mock_client = MockApiClient::new().await.unwrap();
        let file_data = FileResponseBuilder::clean_file().build();
        let response_data = ResponseFactory::success_response(file_data);

        Mock::given(method("GET"))
            .and(path("/files/test"))
            .and(header("x-apikey", constants::TEST_API_KEY))
            .respond_with(create_json_response(200, &response_data))
            .mount(mock_client.mock_server())
            .await;

        let result: crate::Result<serde_json::Value> = mock_client.client().get("files/test").await;
        assert!(result.is_ok());

        let response = result.unwrap();
        assert_eq!(response["data"]["type"], "file");
        assert_eq!(response["data"]["id"], constants::CLEAN_HASH);
    }

    #[tokio::test]
    async fn test_custom_assertions() {
        // Test analysis clean assertion
        let clean_stats = AnalysisStatsBuilder::clean().build();
        assert_analysis_clean!(clean_stats);

        // Test analysis malicious assertion
        let malicious_stats = AnalysisStatsBuilder::malicious().build();
        assert_analysis_malicious!(malicious_stats);

        // Test range assertion
        let value = 50;
        assert_in_range!(value, 40, 60);

        // Test substring assertion
        let text = "Hello world";
        assert_contains_substring!(text, "world");
    }

    #[test]
    #[allow(clippy::const_is_empty, clippy::assertions_on_constants)]
    fn test_constants() {
        assert!(!constants::SAMPLE_MD5.is_empty());
        assert!(!constants::SAMPLE_SHA1.is_empty());
        assert!(!constants::SAMPLE_SHA256.is_empty());
        assert!(!constants::SAMPLE_DOMAIN.is_empty());
        assert!(!constants::SAMPLE_IP.is_empty());
        assert!(constants::SAMPLE_TIMESTAMP > 0);
    }

    #[tokio::test]
    async fn test_with_temp_file() {
        let content = b"test file content";
        TestEnvironment::with_temp_file(content, |path| async move {
            assert!(path.exists());
            let file_content = std::fs::read(&path).expect("Failed to read temp file");
            assert_eq!(file_content, content);
        })
        .await;
    }

    #[tokio::test]
    async fn test_error_responses() {
        let (status, error) = ResponseFactory::not_found_error();
        assert_eq!(status, 404);
        assert_eq!(error["error"]["code"], "NotFoundError");

        let (status, error) = ResponseFactory::unauthorized_error();
        assert_eq!(status, 401);
        assert_eq!(error["error"]["code"], "AuthenticationRequiredError");

        let (status, error) = ResponseFactory::forbidden_error();
        assert_eq!(status, 403);
        assert_eq!(error["error"]["code"], "ForbiddenError");
    }
}
