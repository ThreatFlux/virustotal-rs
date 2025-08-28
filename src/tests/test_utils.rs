// Re-export the main test utilities to maintain backward compatibility
#[allow(unused_imports)]
pub use crate::test_utils::test_utilities::*;

use crate::auth::ApiTier;
use crate::client::{Client, ClientBuilder};
use crate::error::Result;
use serde_json::json;
use std::time::Duration;
use wiremock::{MockServer, ResponseTemplate};

/// Legacy test utilities for backward compatibility
/// Use the new test_utilities module for new tests
pub struct TestUtils;

impl TestUtils {
    /// Create a mock server for testing
    pub async fn create_mock_server() -> MockServer {
        MockServer::start().await
    }

    /// Convenience helper that returns both a mock server and a connected test client.
    pub async fn create_mock_server_and_client() -> (MockServer, Client) {
        Self::create_client_with_tier(ApiTier::Premium).await
    }

    /// Create a test client with specified tier
    pub async fn create_client_with_tier(tier: ApiTier) -> (MockServer, Client) {
        Self::create_client_with_key_and_tier("test_api_key", tier).await
    }

    /// Create a test client with custom API key and tier
    pub async fn create_client_with_key_and_tier(api_key: &str, tier: ApiTier) -> (MockServer, Client) {
        let mock_server = Self::create_mock_server().await;
        let client = ClientBuilder::new()
            .api_key(api_key)
            .tier(tier)
            .base_url(mock_server.uri())
            .timeout(Duration::from_secs(5))
            .build()
            .expect("failed to create test client");
        (mock_server, client)
    }

    /// Create a test client that connects to the mock server  
    pub async fn create_test_client(mock_server: &MockServer) -> Result<Client> {
        Self::create_test_client_with_tier(mock_server, ApiTier::Premium).await
    }

    /// Create a test client with public tier limits
    pub async fn create_public_test_client(mock_server: &MockServer) -> Result<Client> {
        Self::create_test_client_with_tier(mock_server, ApiTier::Public).await
    }

    /// Create a test client with custom API key
    pub async fn create_test_client_with_key(
        mock_server: &MockServer,
        api_key: &str,
    ) -> Result<Client> {
        Self::create_test_client_with_key_and_tier(mock_server, api_key, ApiTier::Premium).await
    }

    /// Internal helper to create client with tier
    async fn create_test_client_with_tier(mock_server: &MockServer, tier: ApiTier) -> Result<Client> {
        Self::create_test_client_with_key_and_tier(mock_server, "test_api_key", tier).await
    }

    /// Internal helper to create client with key and tier  
    async fn create_test_client_with_key_and_tier(
        mock_server: &MockServer, 
        api_key: &str, 
        tier: ApiTier
    ) -> Result<Client> {
        ClientBuilder::new()
            .api_key(api_key)
            .tier(tier)
            .base_url(mock_server.uri())
            .timeout(Duration::from_secs(5))
            .build()
    }

    /// Setup a mock with common `VirusTotal` response headers
    #[allow(dead_code)]
    pub fn setup_mock_with_headers() -> ResponseTemplate {
        Self::create_response_template(200)
    }

    /// Create a response template with standard headers
    pub fn create_response_template(status: u16) -> ResponseTemplate {
        ResponseTemplate::new(status)
            .append_header("Content-Type", "application/json")
            .append_header("X-RateLimit-Remaining", "999")
            .append_header("X-RateLimit-Reset", "3600")
    }

    /// Common setup for test scenarios
    pub async fn setup_test_scenario() -> (MockServer, Client) {
        let mock_server = Self::create_mock_server().await;
        let client = Self::create_test_client(&mock_server).await.unwrap();
        (mock_server, client)
    }

    /// Execute HTTP request by method with common error handling
    pub async fn execute_http_request(
        client: &Client,
        method: &str,
        endpoint_path: &str,
    ) -> Result<serde_json::Value> {
        match method {
            "GET" => client.get(endpoint_path).await,
            "POST" => client.post(endpoint_path, &serde_json::json!({})).await,
            "PUT" => client.put(endpoint_path, &serde_json::json!({})).await,
            _ => panic!("Unsupported method: {}", method),
        }
    }
}

/// Macro to create basic mock response tests
#[macro_export]
macro_rules! test_mock_response {
    ($test_name:ident, $method:expr, $endpoint:expr, $expected_status:expr) => {
        #[tokio::test]
        async fn $test_name() {
            use wiremock::{
                matchers::{header, method, path},
                Mock,
            };
            use $crate::tests::mock_data::{sample_error_response, MockResponseBuilder};
            use $crate::tests::test_utils::TestUtils;

            let mock_server = TestUtils::create_mock_server().await;
            let client = TestUtils::create_test_client(&mock_server).await.unwrap();

            let (status, response_data) = sample_error_response($expected_status);
            let response = MockResponseBuilder::new()
                .with_status(status)
                .build()
                .set_body_json(&response_data);

            Mock::given(method($method))
                .and(path($endpoint))
                .and(header("x-apikey", "test_api_key"))
                .respond_with(response)
                .mount(&mock_server)
                .await;

            // Test that the client handles the response appropriately
            let endpoint_path = $endpoint.trim_start_matches('/');
            let result: Result<serde_json::Value, _> = match $method {
                "GET" => client.get(endpoint_path).await,
                "POST" => client.post(endpoint_path, &serde_json::json!({})).await,
                "PUT" => client.put(endpoint_path, &serde_json::json!({})).await,
                _ => panic!("Unsupported method in test macro"),
            };

            if $expected_status >= 400 {
                assert!(
                    result.is_err(),
                    "Expected error for status {}",
                    $expected_status
                );
            } else {
                assert!(
                    result.is_ok(),
                    "Expected success for status {}",
                    $expected_status
                );
            }
        }
    };
}

/// Macro to create success response tests
#[macro_export]
macro_rules! test_success_response {
    ($test_name:ident, $method:expr, $endpoint:expr, $sample_data_fn:expr) => {
        #[tokio::test]
        async fn $test_name() {
            use wiremock::{
                matchers::{header, method, path},
                Mock,
            };
            use $crate::tests::mock_data::MockResponseBuilder;
            use $crate::tests::test_utils::TestUtils;

            let mock_server = TestUtils::create_mock_server().await;
            let client = TestUtils::create_test_client(&mock_server).await.unwrap();

            let sample_data = $sample_data_fn();
            let response = MockResponseBuilder::new()
                .with_data(sample_data.clone())
                .build();

            Mock::given(method($method))
                .and(path($endpoint))
                .and(header("x-apikey", "test_api_key"))
                .respond_with(response)
                .mount(&mock_server)
                .await;

            let endpoint_path = $endpoint.trim_start_matches('/');
            let result: Result<serde_json::Value, _> = match $method {
                "GET" => client.get(endpoint_path).await,
                "POST" => client.post(endpoint_path, &serde_json::json!({})).await,
                "PUT" => client.put(endpoint_path, &serde_json::json!({})).await,
                _ => panic!("Unsupported method in test macro"),
            };

            assert!(result.is_ok(), "Expected successful response");
            let response_data = result.unwrap();
            assert_eq!(response_data, sample_data);
        }
    };
}

/// Macro to test collection responses with pagination
#[macro_export]
macro_rules! test_collection_response {
    ($test_name:ident, $endpoint:expr, $sample_item_fn:expr) => {
        #[tokio::test]
        async fn $test_name() {
            use wiremock::{
                matchers::{header, method, path},
                Mock,
            };
            use $crate::tests::mock_data::{sample_collection_data, MockResponseBuilder};
            use $crate::tests::test_utils::TestUtils;

            let mock_server = TestUtils::create_mock_server().await;
            let client = TestUtils::create_test_client(&mock_server).await.unwrap();

            let sample_item = $sample_item_fn();
            let collection_data = sample_collection_data(vec![sample_item], Some("next_cursor"));
            let response = MockResponseBuilder::new()
                .build()
                .set_body_json(&collection_data);

            Mock::given(method("GET"))
                .and(path($endpoint))
                .and(header("x-apikey", "test_api_key"))
                .respond_with(response)
                .mount(&mock_server)
                .await;

            let endpoint_path = $endpoint.trim_start_matches('/');
            let result: Result<serde_json::Value, _> = client.get(endpoint_path).await;

            assert!(result.is_ok(), "Expected successful collection response");
            let response_data = result.unwrap();
            assert!(response_data["data"].is_array());
            assert_eq!(response_data["data"].as_array().unwrap().len(), 1);
            assert!(response_data["links"]["next"].is_string());
        }
    };
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::mock_data::{sample_file_data, MockResponseBuilder};
    use wiremock::{
        matchers::{header, method, path},
        Mock,
    };

    #[tokio::test]
    async fn test_create_mock_server() {
        let server = TestUtils::create_mock_server().await;
        assert!(!server.uri().is_empty());
        assert!(server.uri().starts_with("http://"));
    }

    #[tokio::test]
    async fn test_create_test_client() {
        let server = TestUtils::create_mock_server().await;
        let client = TestUtils::create_test_client(&server).await;
        assert!(client.is_ok());

        let client = client.unwrap();
        assert_eq!(client.api_key(), "test_api_key");
        assert!(client.base_url().starts_with("http://"));
    }

    #[tokio::test]
    async fn test_create_public_test_client() {
        let server = TestUtils::create_mock_server().await;
        let client = TestUtils::create_public_test_client(&server).await;
        assert!(client.is_ok());
    }

    #[tokio::test]
    async fn test_create_test_client_with_key() {
        let server = TestUtils::create_mock_server().await;
        let client = TestUtils::create_test_client_with_key(&server, "custom_key").await;
        assert!(client.is_ok());

        let client = client.unwrap();
        assert_eq!(client.api_key(), "custom_key");
    }

    #[tokio::test]
    async fn test_mock_integration() {
        let mock_server = TestUtils::create_mock_server().await;
        let client = TestUtils::create_test_client(&mock_server).await.unwrap();

        let sample_data = sample_file_data();
        let response = MockResponseBuilder::new()
            .with_data(sample_data.clone())
            .build();

        Mock::given(method("GET"))
            .and(path("/files/test"))
            .and(header("x-apikey", "test_api_key"))
            .respond_with(response)
            .mount(&mock_server)
            .await;

        let result: Result<serde_json::Value> = client.get("files/test").await;
        assert!(result.is_ok());

        let response_data = result.unwrap();
        let expected_response = json!({"data": sample_data});
        assert_eq!(response_data, expected_response);
    }
}
