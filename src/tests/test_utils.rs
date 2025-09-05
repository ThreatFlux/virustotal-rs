// Re-export the main test utilities to maintain backward compatibility
#[allow(unused_imports)]
pub use crate::test_utils::test_utilities::*;

use crate::auth::ApiTier;
use crate::client::{Client, ClientBuilder};
use crate::error::Result;
use std::time::Duration;
use wiremock::MockServer;

/// Legacy test utilities for backward compatibility - DEPRECATED
/// Use the new `MockApiClient` from `test_utilities` module for new tests
///
/// This struct is kept only for backward compatibility with existing tests.
/// New tests should use `MockApiClient::new()` directly.
#[deprecated(
    since = "0.4.0",
    note = "Use MockApiClient from test_utilities instead"
)]
pub struct TestUtils;

#[allow(deprecated)]
impl TestUtils {
    /// Create a mock server for testing - DEPRECATED
    /// Use `MockApiClient::new()` instead
    #[deprecated(since = "0.4.0", note = "Use MockApiClient::new() instead")]
    pub async fn create_mock_server() -> MockServer {
        MockServer::start().await
    }

    /// Create a test client that connects to the mock server - DEPRECATED
    /// Use `MockApiClient::new()` instead  
    #[deprecated(since = "0.4.0", note = "Use MockApiClient::new() instead")]
    pub async fn create_test_client(mock_server: &MockServer) -> Result<Client> {
        ClientBuilder::new()
            .api_key("test_api_key")
            .tier(ApiTier::Premium)
            .base_url(mock_server.uri())
            .timeout(Duration::from_secs(5))
            .build()
    }
}

// Deprecated macros - use the builders and utilities from test_utilities instead
// These macros create more boilerplate than they save and are not type-safe

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::test_utilities::create_json_response;

    #[tokio::test]
    #[allow(deprecated)]
    async fn test_legacy_create_mock_server() {
        // Test that legacy API still works for backward compatibility
        let server = TestUtils::create_mock_server().await;
        assert!(!server.uri().is_empty());
        assert!(server.uri().starts_with("http://"));
    }

    #[tokio::test]
    #[allow(deprecated)]
    async fn test_legacy_create_test_client() {
        // Test that legacy API still works for backward compatibility
        let server = TestUtils::create_mock_server().await;
        let client = TestUtils::create_test_client(&server).await;
        assert!(client.is_ok());

        let client = client.unwrap();
        assert_eq!(client.api_key(), "test_api_key");
        assert!(client.base_url().starts_with("http://"));
    }

    #[test]
    fn test_response_template() {
        let test_data = serde_json::json!({"test": "value"});
        let template = create_json_response(200, &test_data);
        // Just verify it can be created - detailed testing is in main test_utils
        // Note: ResponseTemplate doesn't expose status_code() method, but we can verify it was created
        assert!(!format!("{:?}", template).is_empty());
    }
}
