#[cfg(test)]
pub mod assertions;
#[cfg(test)]
pub mod builders;
#[cfg(test)]
pub mod constants;
#[cfg(test)]
pub mod environment;
#[cfg(test)]
pub mod mock_client;
#[cfg(test)]
pub mod responses;

#[cfg(test)]
//pub use assertions::*;
/// Re-exports for backward compatibility
pub mod test_utilities {
    pub use super::builders::{
        AnalysisStatsBuilder, DomainResponseBuilder, FileResponseBuilder, IpResponseBuilder,
    };
    pub use super::constants;
    pub use super::environment::TestEnvironment;
    pub use super::mock_client::MockApiClient;
    pub use super::responses::{
        create_json_response, create_mock_response, MockSetup, ResponseFactory,
    };
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
