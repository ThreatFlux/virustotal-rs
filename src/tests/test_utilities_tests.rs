/// Comprehensive tests for the test utilities themselves
/// This ensures our test infrastructure is solid and reliable
#[cfg(test)]
#[allow(clippy::module_inception)]
mod test_utilities_tests {
    use crate::test_utils::test_utilities::*;
    use crate::{
        assert_analysis_clean, assert_analysis_malicious, assert_contains_substring,
        assert_in_range,
    };
    use serde_json::json;

    #[test]
    #[allow(clippy::const_is_empty, clippy::assertions_on_constants)]
    fn test_constants_are_valid() {
        // Ensure all test constants are properly formatted
        assert_eq!(constants::SAMPLE_MD5.len(), 32);
        assert_eq!(constants::SAMPLE_SHA1.len(), 40);
        assert_eq!(constants::SAMPLE_SHA256.len(), 64);
        assert!(!constants::SAMPLE_DOMAIN.is_empty());
        assert!(!constants::SAMPLE_IP.is_empty());
        assert!(constants::SAMPLE_URL.starts_with("http"));
        assert!(constants::SAMPLE_TIMESTAMP > 0);

        // Test that hashes are hexadecimal
        assert!(constants::SAMPLE_MD5.chars().all(|c| c.is_ascii_hexdigit()));
        assert!(constants::SAMPLE_SHA1
            .chars()
            .all(|c| c.is_ascii_hexdigit()));
        assert!(constants::SAMPLE_SHA256
            .chars()
            .all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_analysis_stats_builder_defaults() {
        let default_stats = AnalysisStatsBuilder::new().build();
        assert_eq!(default_stats.harmless, 70);
        assert_eq!(default_stats.malicious, 0);
        assert_eq!(default_stats.suspicious, 0);
        assert_eq!(default_stats.undetected, 3);
        assert_analysis_clean!(default_stats);
    }

    #[test]
    fn test_analysis_stats_builder_presets() {
        // Test clean preset
        let clean_stats = AnalysisStatsBuilder::clean().build();
        assert_analysis_clean!(clean_stats);

        // Test malicious preset
        let malicious_stats = AnalysisStatsBuilder::malicious().build();
        assert_analysis_malicious!(malicious_stats);

        // Test suspicious preset
        let suspicious_stats = AnalysisStatsBuilder::suspicious().build();
        assert_analysis_malicious!(suspicious_stats);
        assert!(suspicious_stats.suspicious > 0);
    }

    #[test]
    fn test_analysis_stats_builder_custom_values() {
        let custom_stats = AnalysisStatsBuilder::new()
            .with_harmless(100)
            .with_malicious(5)
            .with_suspicious(3)
            .with_undetected(2)
            .with_timeout(1)
            .with_confirmed_timeout(Some(1))
            .with_failure(Some(0))
            .with_type_unsupported(Some(1))
            .build();

        assert_eq!(custom_stats.harmless, 100);
        assert_eq!(custom_stats.malicious, 5);
        assert_eq!(custom_stats.suspicious, 3);
        assert_eq!(custom_stats.undetected, 2);
        assert_eq!(custom_stats.timeout, 1);
        assert_eq!(custom_stats.confirmed_timeout, Some(1));
        assert_eq!(custom_stats.failure, Some(0));
        assert_eq!(custom_stats.type_unsupported, Some(1));
    }

    #[test]
    fn test_file_response_builder_defaults() {
        let file_response = FileResponseBuilder::new("test-id").build();

        assert_eq!(file_response["type"], "file");
        assert_eq!(file_response["id"], "test-id");
        assert_eq!(file_response["attributes"]["md5"], constants::SAMPLE_MD5);
        assert_eq!(file_response["attributes"]["sha1"], constants::SAMPLE_SHA1);
        assert_eq!(
            file_response["attributes"]["sha256"],
            constants::SAMPLE_SHA256
        );
        assert_eq!(file_response["attributes"]["size"], 1024);
        assert_eq!(
            file_response["attributes"]["type_description"],
            "ASCII text"
        );
    }

    #[test]
    fn test_file_response_builder_presets() {
        // Test clean file preset
        let clean_file = FileResponseBuilder::clean_file().build();
        assert_eq!(clean_file["id"], constants::CLEAN_HASH);
        let stats: crate::common::AnalysisStats =
            serde_json::from_value(clean_file["attributes"]["last_analysis_stats"].clone())
                .unwrap();
        assert_analysis_clean!(stats);

        // Test malicious file preset
        let malicious_file = FileResponseBuilder::malicious_file().build();
        assert_eq!(malicious_file["id"], constants::MALICIOUS_HASH);
        let reputation = malicious_file["attributes"]["reputation"].as_i64().unwrap();
        assert!(reputation < 0);

        let tags = malicious_file["attributes"]["tags"].as_array().unwrap();
        assert!(!tags.is_empty());
        assert!(tags.contains(&json!("malware")));
    }

    #[test]
    fn test_file_response_builder_custom_values() {
        let custom_file = FileResponseBuilder::new("custom-id")
            .with_md5("custom-md5")
            .with_sha1("custom-sha1")
            .with_sha256("custom-sha256")
            .with_size(2048)
            .with_type_description("PE32 executable")
            .with_reputation(50)
            .with_tags(vec!["test".to_string(), "custom".to_string()])
            .with_names(vec!["test.exe".to_string()])
            .build();

        assert_eq!(custom_file["id"], "custom-id");
        assert_eq!(custom_file["attributes"]["md5"], "custom-md5");
        assert_eq!(custom_file["attributes"]["sha1"], "custom-sha1");
        assert_eq!(custom_file["attributes"]["sha256"], "custom-sha256");
        assert_eq!(custom_file["attributes"]["size"], 2048);
        assert_eq!(
            custom_file["attributes"]["type_description"],
            "PE32 executable"
        );
        assert_eq!(custom_file["attributes"]["reputation"], 50);

        let tags = custom_file["attributes"]["tags"].as_array().unwrap();
        assert_eq!(tags.len(), 2);
        assert!(tags.contains(&json!("test")));
        assert!(tags.contains(&json!("custom")));
    }

    #[test]
    fn test_domain_response_builder_defaults() {
        let domain_response = DomainResponseBuilder::new("test-domain.com").build();

        assert_eq!(domain_response["type"], "domain");
        assert_eq!(domain_response["id"], "test-domain.com");
        assert_eq!(domain_response["attributes"]["reputation"], 0);
        assert!(domain_response["attributes"]["whois"].is_string());
        assert!(domain_response["attributes"]["categories"].is_object());
    }

    #[test]
    fn test_domain_response_builder_presets() {
        // Test clean domain preset
        let clean_domain = DomainResponseBuilder::clean_domain().build();
        assert_eq!(clean_domain["id"], constants::SAMPLE_DOMAIN);

        // Test malicious domain preset
        let malicious_domain = DomainResponseBuilder::malicious_domain().build();
        assert_eq!(malicious_domain["id"], "malicious-example.com");
        let reputation = malicious_domain["attributes"]["reputation"]
            .as_i64()
            .unwrap();
        assert!(reputation < 0);
    }

    #[test]
    fn test_ip_response_builder_defaults() {
        let ip_response = IpResponseBuilder::new("192.168.1.1").build();

        assert_eq!(ip_response["type"], "ip_address");
        assert_eq!(ip_response["id"], "192.168.1.1");
        assert_eq!(ip_response["attributes"]["country"], "US");
        assert_eq!(ip_response["attributes"]["as_owner"], "Google LLC");
        assert_eq!(ip_response["attributes"]["asn"], 15169);
    }

    #[test]
    fn test_ip_response_builder_presets() {
        // Test clean IP preset
        let clean_ip = IpResponseBuilder::clean_ip().build();
        assert_eq!(clean_ip["id"], constants::SAMPLE_IP);

        // Test malicious IP preset
        let malicious_ip = IpResponseBuilder::malicious_ip().build();
        let reputation = malicious_ip["attributes"]["reputation"].as_i64().unwrap();
        assert!(reputation < 0);
        assert_eq!(malicious_ip["attributes"]["country"], "RU");
    }

    #[test]
    fn test_response_factory_success() {
        let test_data = json!({"test": "data"});
        let response = ResponseFactory::success_response(test_data.clone());

        assert_eq!(response["data"], test_data);
        assert!(response["data"]["test"] == "data");
    }

    #[test]
    fn test_response_factory_collection() {
        let item1 = json!({"id": "1", "name": "item1"});
        let item2 = json!({"id": "2", "name": "item2"});
        let items = vec![item1.clone(), item2.clone()];

        // Test without cursor
        let collection = ResponseFactory::collection_response(items.clone(), None);
        assert_eq!(collection["data"].as_array().unwrap().len(), 2);
        assert_eq!(collection["meta"]["count"], 2);
        assert!(collection["links"].is_null());

        // Test with cursor
        let collection_with_cursor = ResponseFactory::collection_response(items, Some("next-123"));
        assert!(collection_with_cursor["links"]["next"]
            .as_str()
            .unwrap()
            .contains("next-123"));
    }

    #[test]
    fn test_response_factory_errors() {
        // Test various error types
        let (status, error) = ResponseFactory::rate_limit_error();
        assert_eq!(status, 429);
        assert_eq!(error["error"]["code"], "QuotaExceededError");

        let (status, error) = ResponseFactory::not_found_error();
        assert_eq!(status, 404);
        assert_eq!(error["error"]["code"], "NotFoundError");

        let (status, error) = ResponseFactory::unauthorized_error();
        assert_eq!(status, 401);
        assert_eq!(error["error"]["code"], "AuthenticationRequiredError");

        let (status, error) = ResponseFactory::forbidden_error();
        assert_eq!(status, 403);
        assert_eq!(error["error"]["code"], "ForbiddenError");

        // Test custom error
        let (status, error) =
            ResponseFactory::error_response(500, "InternalError", "Something went wrong");
        assert_eq!(status, 500);
        assert_eq!(error["error"]["code"], "InternalError");
        assert_eq!(error["error"]["message"], "Something went wrong");
    }

    #[tokio::test]
    async fn test_mock_api_client_creation() {
        let mock_client = MockApiClient::new().await.unwrap();
        assert_eq!(mock_client.client().api_key(), constants::TEST_API_KEY);
        assert!(!mock_client.mock_server().uri().is_empty());

        // Test custom API key
        let custom_client = MockApiClient::with_api_key("custom-key").await.unwrap();
        assert_eq!(custom_client.client().api_key(), "custom-key");

        // Test public tier
        let public_client = MockApiClient::with_public_tier().await.unwrap();
        assert_eq!(public_client.client().api_key(), constants::TEST_API_KEY);
    }

    #[test]
    fn test_create_mock_response_helpers() {
        let _response = create_mock_response(200);
        // We can't directly test the headers without sending a request,
        // but we can verify the response is created successfully

        let test_data = json!({"test": "data"});
        let _json_response = create_json_response(200, &test_data);
        // Similarly, we can verify it's created without errors
    }

    #[tokio::test]
    async fn test_environment_utilities() {
        // Test environment setup/cleanup
        TestEnvironment::setup();
        TestEnvironment::cleanup();

        // Test with_test_env wrapper
        let result = TestEnvironment::with_test_env(|| async { "test_result" }).await;
        assert_eq!(result, "test_result");

        // Test with_temp_file
        let test_content = b"test file content";
        TestEnvironment::with_temp_file(test_content, |path| async move {
            assert!(path.exists());
            let content = std::fs::read(&path).unwrap();
            assert_eq!(content, test_content);
            "file_test_result"
        })
        .await;
    }

    #[test]
    fn test_assertion_macros() {
        // Test analysis clean assertion
        let clean_stats = AnalysisStatsBuilder::clean().build();
        assert_analysis_clean!(clean_stats);

        // Test analysis malicious assertion
        let malicious_stats = AnalysisStatsBuilder::malicious().build();
        assert_analysis_malicious!(malicious_stats);

        // Test range assertion
        let value = 50;
        assert_in_range!(value, 40, 60);
        assert_in_range!(value, 50, 50); // Edge case: exact match

        // Test substring assertion
        let text = "Hello, world!";
        assert_contains_substring!(text, "Hello");
        assert_contains_substring!(text, "world");
        assert_contains_substring!(text, "ell"); // Partial match
    }

    #[test]
    #[should_panic(expected = "Expected no malicious detections")]
    fn test_analysis_clean_assertion_failure() {
        let malicious_stats = AnalysisStatsBuilder::malicious().build();
        assert_analysis_clean!(malicious_stats);
    }

    #[test]
    #[should_panic(expected = "Expected malicious or suspicious detections")]
    fn test_analysis_malicious_assertion_failure() {
        let clean_stats = AnalysisStatsBuilder::clean().build();
        assert_analysis_malicious!(clean_stats);
    }

    #[test]
    #[should_panic(expected = "to be between")]
    fn test_range_assertion_failure() {
        let value = 150;
        assert_in_range!(value, 0, 100);
    }

    #[test]
    #[should_panic(expected = "to contain")]
    fn test_substring_assertion_failure() {
        let text = "Hello, world!";
        assert_contains_substring!(text, "goodbye");
    }

    #[test]
    fn test_builder_pattern_fluent_api() {
        // Test that all builders support fluent API chaining
        let stats = AnalysisStatsBuilder::new()
            .with_harmless(80)
            .with_malicious(2)
            .with_suspicious(1)
            .with_undetected(0)
            .with_timeout(0)
            .build();

        assert_eq!(stats.harmless, 80);
        assert_eq!(stats.malicious, 2);
        assert_eq!(stats.suspicious, 1);

        let file = FileResponseBuilder::new("test-hash")
            .with_size(4096)
            .with_reputation(25)
            .with_tags(vec!["test".to_string()])
            .build();

        assert_eq!(file["attributes"]["size"], 4096);
        assert_eq!(file["attributes"]["reputation"], 25);

        let domain = DomainResponseBuilder::new("example.org")
            .with_reputation(75)
            .with_tags(vec!["legitimate".to_string()])
            .build();

        assert_eq!(domain["attributes"]["reputation"], 75);

        let ip = IpResponseBuilder::new("10.0.0.1")
            .with_country("CA")
            .with_asn(123)
            .with_reputation(30)
            .build();

        assert_eq!(ip["attributes"]["country"], "CA");
        assert_eq!(ip["attributes"]["asn"], 123);
        assert_eq!(ip["attributes"]["reputation"], 30);
    }
}
