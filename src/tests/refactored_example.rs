/// Example of refactoring existing tests to use the new utilities
/// Shows before and after comparisons
#[cfg(test)]
mod refactored_tests {
    use crate::test_utils::test_utilities::*;
    use crate::{assert_analysis_clean, assert_analysis_malicious};
    use serde_json::json;
    use wiremock::{
        matchers::{header, method, path},
        Mock,
    };

    // BEFORE: Lots of repetitive boilerplate
    #[tokio::test]
    async fn old_style_file_test() {
        use crate::auth::ApiTier;
        use crate::client::ClientBuilder;
        use std::time::Duration;
        use wiremock::{MockServer, ResponseTemplate};

        // Manual setup - lots of boilerplate
        let mock_server = MockServer::start().await;
        let client = ClientBuilder::new()
            .api_key("test_api_key")
            .tier(ApiTier::Premium)
            .base_url(mock_server.uri())
            .timeout(Duration::from_secs(5))
            .build()
            .unwrap();

        // Manual JSON construction - error-prone and verbose
        let sample_data = json!({
            "type": "file",
            "id": "44d88612fea8a8f36de82e1278abb02f",
            "attributes": {
                "md5": "44d88612fea8a8f36de82e1278abb02f",
                "sha1": "3395856ce81f2b7382dee72602f798b642f14140",
                "sha256": "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
                "size": 68,
                "type_description": "ASCII text",
                "names": ["hello.txt"],
                "last_analysis_stats": {
                    "harmless": 70,
                    "malicious": 0,
                    "suspicious": 0,
                    "undetected": 3,
                    "timeout": 0
                }
            }
        });

        let response = ResponseTemplate::new(200)
            .append_header("Content-Type", "application/json")
            .set_body_json(json!({"data": sample_data}));

        Mock::given(method("GET"))
            .and(path("/files/test"))
            .and(header("x-apikey", "test_api_key"))
            .respond_with(response)
            .mount(&mock_server)
            .await;

        let result: crate::Result<serde_json::Value> = client.get("files/test").await;
        assert!(result.is_ok());

        let file_data = result.unwrap()["data"].clone();
        // Manual assertion checking
        let stats = file_data["attributes"]["last_analysis_stats"].clone();
        assert_eq!(stats["malicious"], 0);
        assert_eq!(stats["suspicious"], 0);
        assert!(stats["harmless"].as_u64().unwrap() > 0);
    }

    // AFTER: Clean, readable, maintainable
    #[tokio::test]
    async fn new_style_file_test() {
        // Simple, one-line client setup
        let mock_client = MockApiClient::new().await.unwrap();

        // Expressive, type-safe data builders
        let file_data = FileResponseBuilder::clean_file()
            .with_names(vec!["hello.txt".to_string()])
            .with_size(68)
            .build();

        let response = ResponseFactory::success_response(file_data);

        Mock::given(method("GET"))
            .and(path("/files/test"))
            .and(header("x-apikey", constants::TEST_API_KEY))
            .respond_with(create_json_response(200, &response))
            .mount(mock_client.mock_server())
            .await;

        let result: crate::Result<serde_json::Value> = mock_client.client().get("files/test").await;
        assert!(result.is_ok());

        let file_data = result.unwrap()["data"].clone();
        let stats: crate::common::AnalysisStats =
            serde_json::from_value(file_data["attributes"]["last_analysis_stats"].clone()).unwrap();

        // Clear, expressive assertion
        assert_analysis_clean!(stats);
    }

    // BEFORE: Repetitive error testing
    #[tokio::test]
    async fn old_style_error_test() {
        use crate::auth::ApiTier;
        use crate::client::ClientBuilder;
        use std::time::Duration;
        use wiremock::{MockServer, ResponseTemplate};

        let mock_server = MockServer::start().await;
        let client = ClientBuilder::new()
            .api_key("test_api_key")
            .tier(ApiTier::Premium)
            .base_url(mock_server.uri())
            .timeout(Duration::from_secs(5))
            .build()
            .unwrap();

        // Manual error response construction
        let error_response = json!({
            "error": {
                "code": "NotFoundError",
                "message": "Resource not found"
            }
        });

        let response = ResponseTemplate::new(404)
            .append_header("Content-Type", "application/json")
            .set_body_json(&error_response);

        Mock::given(method("GET"))
            .and(path("/not-found"))
            .and(header("x-apikey", "test_api_key"))
            .respond_with(response)
            .mount(&mock_server)
            .await;

        let result: crate::Result<serde_json::Value> = client.get("not-found").await;
        assert!(result.is_err());
    }

    // AFTER: Simple, reusable error testing
    #[tokio::test]
    async fn new_style_error_test() {
        let mock_client = MockApiClient::new().await.unwrap();

        // Pre-built error response
        let (status, error_response) = ResponseFactory::not_found_error();

        Mock::given(method("GET"))
            .and(path("/not-found"))
            .and(header("x-apikey", constants::TEST_API_KEY))
            .respond_with(create_json_response(status, &error_response))
            .mount(mock_client.mock_server())
            .await;

        let result: crate::Result<serde_json::Value> = mock_client.client().get("not-found").await;
        assert!(result.is_err());
    }

    // BEFORE: Complex collection testing
    #[tokio::test]
    async fn old_style_collection_test() {
        use crate::auth::ApiTier;
        use crate::client::ClientBuilder;
        use std::time::Duration;
        use wiremock::{MockServer, ResponseTemplate};

        let mock_server = MockServer::start().await;
        let client = ClientBuilder::new()
            .api_key("test_api_key")
            .tier(ApiTier::Premium)
            .base_url(mock_server.uri())
            .timeout(Duration::from_secs(5))
            .build()
            .unwrap();

        // Manual collection construction - lots of repetition
        let file1 = json!({
            "type": "file",
            "id": "hash1",
            "attributes": {
                "md5": "hash1md5",
                "names": ["file1.txt"],
                "size": 1024
            }
        });

        let file2 = json!({
            "type": "file",
            "id": "hash2",
            "attributes": {
                "md5": "hash2md5",
                "names": ["file2.txt"],
                "size": 2048
            }
        });

        let collection_response = json!({
            "data": [file1, file2],
            "meta": { "count": 2 },
            "links": { "next": "https://api.example.com/files?cursor=next123" }
        });

        let response = ResponseTemplate::new(200)
            .append_header("Content-Type", "application/json")
            .set_body_json(&collection_response);

        Mock::given(method("GET"))
            .and(path("/files"))
            .and(header("x-apikey", "test_api_key"))
            .respond_with(response)
            .mount(&mock_server)
            .await;

        let result: crate::Result<serde_json::Value> = client.get("files").await;
        assert!(result.is_ok());

        let response_data = result.unwrap();
        assert_eq!(response_data["data"].as_array().unwrap().len(), 2);
        assert_eq!(response_data["meta"]["count"], 2);
        assert!(response_data["links"]["next"]
            .as_str()
            .unwrap()
            .contains("next123"));
    }

    // AFTER: Elegant collection testing
    #[tokio::test]
    async fn new_style_collection_test() {
        let mock_client = MockApiClient::new().await.unwrap();

        // Expressive builders for each item
        let file1 = FileResponseBuilder::new("hash1")
            .with_names(vec!["file1.txt".to_string()])
            .with_size(1024)
            .build();

        let file2 = FileResponseBuilder::new("hash2")
            .with_names(vec!["file2.txt".to_string()])
            .with_size(2048)
            .build();

        // Simple collection factory
        let collection_response =
            ResponseFactory::collection_response(vec![file1, file2], Some("next123"));

        Mock::given(method("GET"))
            .and(path("/files"))
            .and(header("x-apikey", constants::TEST_API_KEY))
            .respond_with(create_json_response(200, &collection_response))
            .mount(mock_client.mock_server())
            .await;

        let result: crate::Result<serde_json::Value> = mock_client.client().get("files").await;
        assert!(result.is_ok());

        let response_data = result.unwrap();
        assert_eq!(response_data["data"].as_array().unwrap().len(), 2);
        assert_eq!(response_data["meta"]["count"], 2);
        assert!(response_data["links"]["next"]
            .as_str()
            .unwrap()
            .contains("next123"));
    }

    // Test helper functions for different analysis scenarios
    async fn setup_clean_file_mock(mock_client: &MockApiClient) {
        let clean_file = FileResponseBuilder::clean_file().build();
        let clean_response = ResponseFactory::success_response(clean_file);

        Mock::given(method("GET"))
            .and(path("/files/clean"))
            .and(header("x-apikey", constants::TEST_API_KEY))
            .respond_with(create_json_response(200, &clean_response))
            .mount(mock_client.mock_server())
            .await;
    }

    async fn setup_malicious_file_mock(mock_client: &MockApiClient) {
        let malicious_file = FileResponseBuilder::malicious_file().build();
        let malicious_response = ResponseFactory::success_response(malicious_file);

        Mock::given(method("GET"))
            .and(path("/files/malicious"))
            .and(header("x-apikey", constants::TEST_API_KEY))
            .respond_with(create_json_response(200, &malicious_response))
            .mount(mock_client.mock_server())
            .await;
    }

    async fn setup_custom_analysis_mock(mock_client: &MockApiClient) {
        let custom_stats = AnalysisStatsBuilder::new()
            .with_harmless(60)
            .with_malicious(3)
            .with_suspicious(1)
            .with_undetected(2)
            .build();

        let custom_file = FileResponseBuilder::new("custom-hash")
            .with_stats(custom_stats)
            .build();

        let custom_response = ResponseFactory::success_response(custom_file);

        Mock::given(method("GET"))
            .and(path("/files/custom"))
            .and(header("x-apikey", constants::TEST_API_KEY))
            .respond_with(create_json_response(200, &custom_response))
            .mount(mock_client.mock_server())
            .await;
    }

    // Clean file analysis test
    #[tokio::test]
    async fn test_clean_file_analysis() {
        let mock_client = MockApiClient::new().await.unwrap();
        setup_clean_file_mock(&mock_client).await;

        let result: crate::Result<serde_json::Value> =
            mock_client.client().get("files/clean").await;
        let clean_stats: crate::common::AnalysisStats = serde_json::from_value(
            result.unwrap()["data"]["attributes"]["last_analysis_stats"].clone(),
        )
        .unwrap();
        assert_analysis_clean!(clean_stats);
    }

    // Malicious file analysis test
    #[tokio::test]
    async fn test_malicious_file_analysis() {
        let mock_client = MockApiClient::new().await.unwrap();
        setup_malicious_file_mock(&mock_client).await;

        let result: crate::Result<serde_json::Value> =
            mock_client.client().get("files/malicious").await;
        let malicious_stats: crate::common::AnalysisStats = serde_json::from_value(
            result.unwrap()["data"]["attributes"]["last_analysis_stats"].clone(),
        )
        .unwrap();
        assert_analysis_malicious!(malicious_stats);
    }

    // Custom analysis with specific numbers test
    #[tokio::test]
    async fn test_custom_analysis_scenario() {
        let mock_client = MockApiClient::new().await.unwrap();
        setup_custom_analysis_mock(&mock_client).await;

        let result: crate::Result<serde_json::Value> =
            mock_client.client().get("files/custom").await;
        let returned_stats: crate::common::AnalysisStats = serde_json::from_value(
            result.unwrap()["data"]["attributes"]["last_analysis_stats"].clone(),
        )
        .unwrap();

        assert_eq!(returned_stats.harmless, 60);
        assert_eq!(returned_stats.malicious, 3);
        assert_eq!(returned_stats.suspicious, 1);
        assert_analysis_malicious!(returned_stats);
    }
}
