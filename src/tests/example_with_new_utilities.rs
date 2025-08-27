/// Example tests demonstrating the new test utilities
/// This shows how the test utilities eliminate duplication and make tests more readable
#[cfg(test)]
mod example_tests {
    use crate::error::Error;
    use crate::test_utils::test_utilities::*;
    use crate::{
        assert_analysis_clean, assert_analysis_malicious, assert_contains_substring,
        assert_in_range,
    };
    use wiremock::{
        matchers::{header, method, path},
        Mock,
    };

    #[tokio::test]
    async fn test_file_analysis_clean() {
        // Before: Lots of boilerplate setup
        // After: Simple builder pattern with sensible defaults
        let mock_client = MockApiClient::new().await.unwrap();

        let clean_file_data = FileResponseBuilder::clean_file()
            .with_names(vec!["document.pdf".to_string()])
            .with_size(2048)
            .build();

        let response = ResponseFactory::success_response(clean_file_data);

        Mock::given(method("GET"))
            .and(path("/files/test-hash"))
            .and(header("x-apikey", constants::TEST_API_KEY))
            .respond_with(create_json_response(200, &response))
            .mount(mock_client.mock_server())
            .await;

        let result: Result<serde_json::Value, _> =
            mock_client.client().get("files/test-hash").await;
        assert!(result.is_ok());

        let file_data = result.unwrap()["data"].clone();
        let stats: crate::common::AnalysisStats =
            serde_json::from_value(file_data["attributes"]["last_analysis_stats"].clone()).unwrap();

        // Custom assertion macro makes intent clear
        assert_analysis_clean!(stats);
        assert_eq!(file_data["attributes"]["size"], 2048);
        assert_contains_substring!(
            file_data["attributes"]["names"][0].as_str().unwrap(),
            "document"
        );
    }

    #[tokio::test]
    async fn test_file_analysis_malicious() {
        let mock_client = MockApiClient::new().await.unwrap();

        // Builder pattern makes it easy to create different test scenarios
        let malicious_file_data = FileResponseBuilder::malicious_file()
            .with_names(vec!["suspicious.exe".to_string()])
            .with_type_description("PE32 executable".to_string())
            .build();

        let response = ResponseFactory::success_response(malicious_file_data);

        Mock::given(method("GET"))
            .and(path("/files/malicious-hash"))
            .and(header("x-apikey", constants::TEST_API_KEY))
            .respond_with(create_json_response(200, &response))
            .mount(mock_client.mock_server())
            .await;

        let result: Result<serde_json::Value, _> =
            mock_client.client().get("files/malicious-hash").await;
        assert!(result.is_ok());

        let file_data = result.unwrap()["data"].clone();
        let stats: crate::common::AnalysisStats =
            serde_json::from_value(file_data["attributes"]["last_analysis_stats"].clone()).unwrap();

        assert_analysis_malicious!(stats);
        assert!(file_data["attributes"]["reputation"].as_i64().unwrap() < 0);
    }

    #[tokio::test]
    async fn test_domain_analysis() {
        let mock_client = MockApiClient::new().await.unwrap();

        let domain_data = DomainResponseBuilder::new("test-domain.com")
            .with_reputation(25)
            .with_tags(vec!["legitimate".to_string(), "business".to_string()])
            .build();

        let response = ResponseFactory::success_response(domain_data);

        Mock::given(method("GET"))
            .and(path("/domains/test-domain.com"))
            .and(header("x-apikey", constants::TEST_API_KEY))
            .respond_with(create_json_response(200, &response))
            .mount(mock_client.mock_server())
            .await;

        let result: Result<serde_json::Value, _> =
            mock_client.client().get("domains/test-domain.com").await;
        assert!(result.is_ok());

        let domain_data = result.unwrap()["data"].clone();
        let reputation = domain_data["attributes"]["reputation"].as_i64().unwrap();
        assert_in_range!(reputation, 0, 100);

        let tags = domain_data["attributes"]["tags"].as_array().unwrap();
        assert_eq!(tags.len(), 2);
    }

    #[tokio::test]
    async fn test_ip_analysis() {
        let mock_client = MockApiClient::new().await.unwrap();

        let ip_data = IpResponseBuilder::new("1.1.1.1")
            .with_country("US".to_string())
            .with_as_owner("Cloudflare".to_string())
            .with_reputation(50)
            .build();

        let response = ResponseFactory::success_response(ip_data);

        Mock::given(method("GET"))
            .and(path("/ip_addresses/1.1.1.1"))
            .and(header("x-apikey", constants::TEST_API_KEY))
            .respond_with(create_json_response(200, &response))
            .mount(mock_client.mock_server())
            .await;

        let result: Result<serde_json::Value, _> =
            mock_client.client().get("ip_addresses/1.1.1.1").await;
        assert!(result.is_ok());

        let ip_data = result.unwrap()["data"].clone();
        assert_eq!(ip_data["id"], "1.1.1.1");
        assert_eq!(ip_data["attributes"]["country"], "US");
        assert_contains_substring!(
            ip_data["attributes"]["as_owner"].as_str().unwrap(),
            "Cloudflare"
        );
    }

    #[tokio::test]
    async fn test_collection_response() {
        let mock_client = MockApiClient::new().await.unwrap();

        // Easy to create collection responses with multiple items
        let file1 = FileResponseBuilder::new("hash1")
            .with_names(vec!["file1.txt".to_string()])
            .build();
        let file2 = FileResponseBuilder::new("hash2")
            .with_names(vec!["file2.txt".to_string()])
            .build();

        let collection_response =
            ResponseFactory::collection_response(vec![file1, file2], Some("next-cursor-123"));

        Mock::given(method("GET"))
            .and(path("/files"))
            .and(header("x-apikey", constants::TEST_API_KEY))
            .respond_with(create_json_response(200, &collection_response))
            .mount(mock_client.mock_server())
            .await;

        let result: Result<serde_json::Value, _> = mock_client.client().get("files").await;
        assert!(result.is_ok());

        let response = result.unwrap();
        assert_eq!(response["data"].as_array().unwrap().len(), 2);
        assert_contains_substring!(
            response["links"]["next"].as_str().unwrap(),
            "next-cursor-123"
        );
        assert_eq!(response["meta"]["count"], 2);
    }

    #[tokio::test]
    async fn test_error_scenarios() {
        let mock_client = MockApiClient::new().await.unwrap();

        // Test rate limit error
        let (status, error_response) = ResponseFactory::rate_limit_error();
        Mock::given(method("GET"))
            .and(path("/rate-limited"))
            .and(header("x-apikey", constants::TEST_API_KEY))
            .respond_with(create_json_response(status, &error_response))
            .mount(mock_client.mock_server())
            .await;

        let result: Result<serde_json::Value, _> = mock_client.client().get("rate-limited").await;
        assert!(result.is_err());
        match result {
            Err(Error::QuotaExceeded(_)) => {} // Expected rate limit error
            _ => panic!("Expected quota exceeded error"),
        }

        // Test not found error
        let (status, error_response) = ResponseFactory::not_found_error();
        Mock::given(method("GET"))
            .and(path("/not-found"))
            .and(header("x-apikey", constants::TEST_API_KEY))
            .respond_with(create_json_response(status, &error_response))
            .mount(mock_client.mock_server())
            .await;

        let result: Result<serde_json::Value, _> = mock_client.client().get("not-found").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_different_api_tiers() {
        // Test public tier client with different rate limits
        let public_client = MockApiClient::with_public_tier().await.unwrap();

        let file_data = FileResponseBuilder::clean_file().build();
        let response = ResponseFactory::success_response(file_data);

        Mock::given(method("GET"))
            .and(path("/files/test"))
            .and(header("x-apikey", constants::TEST_API_KEY))
            .respond_with(create_json_response(200, &response))
            .mount(public_client.mock_server())
            .await;

        let result: Result<serde_json::Value, _> = public_client.client().get("files/test").await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_custom_analysis_stats() {
        // Test builder pattern for creating custom analysis statistics
        let custom_stats = AnalysisStatsBuilder::new()
            .with_harmless(45)
            .with_malicious(5)
            .with_suspicious(2)
            .with_undetected(1)
            .with_timeout(0)
            .build();

        assert_eq!(custom_stats.harmless, 45);
        assert_eq!(custom_stats.malicious, 5);
        assert_eq!(custom_stats.suspicious, 2);
        assert_analysis_malicious!(custom_stats);
    }

    #[tokio::test]
    async fn test_with_temp_file_utility() {
        let test_content = b"This is test file content for analysis";

        TestEnvironment::with_temp_file(test_content, |temp_path| async move {
            assert!(temp_path.exists());

            let content = std::fs::read(&temp_path).unwrap();
            assert_eq!(content, test_content);

            // Simulate file analysis test
            let file_size = content.len() as u64;
            assert_in_range!(file_size, 30, 50);
        })
        .await;
    }

    #[tokio::test]
    async fn test_multiple_assertion_types() {
        // Demonstrate various custom assertion macros
        let test_string = "VirusTotal API Response";
        assert_contains_substring!(test_string, "API");
        assert_contains_substring!(test_string, "VirusTotal");

        let reputation_score = 75;
        assert_in_range!(reputation_score, 0, 100);

        let clean_stats = AnalysisStatsBuilder::clean().build();
        assert_analysis_clean!(clean_stats);

        let suspicious_stats = AnalysisStatsBuilder::suspicious().build();
        assert_analysis_malicious!(suspicious_stats);
    }
}
