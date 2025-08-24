use crate::error::Error;
use crate::tests::mock_data::{
    mock_delete, mock_get, mock_post, mock_put, sample_analysis_data, sample_collection_data,
    sample_comment_data, sample_domain_data, sample_error_response, sample_file_data,
    sample_ip_data, sample_sigma_rule_data, sample_vote_data, sample_yara_ruleset_data,
    with_api_key, MockResponseBuilder,
};
use crate::tests::test_utils::TestUtils;
use serde_json::{json, Value};
use std::time::Duration;
use wiremock::matchers::body_json;

/// Core client HTTP method tests
mod client_http_tests {
    use super::*;

    #[tokio::test]
    async fn test_client_get_success() {
        let (mock_server, client) = TestUtils::create_mock_server_and_client().await;

        let sample_data = sample_file_data();
        let response = MockResponseBuilder::new()
            .with_data(sample_data.clone())
            .build();

        with_api_key(mock_get("/files/test"), "test_api_key")
            .respond_with(response)
            .mount(&mock_server)
            .await;

        let result: Result<Value, Error> = client.get("files/test").await;
        assert!(result.is_ok());
        let response_data = result.unwrap();
        // The client returns the full response structure, so we need to compare with the wrapped data
        let expected_response = json!({"data": sample_data});
        assert_eq!(response_data, expected_response);
    }

    #[tokio::test]
    async fn test_client_post_success() {
        let (mock_server, client) = TestUtils::create_mock_server_and_client().await;

        let request_body = json!({"test": "data"});
        let sample_data = sample_analysis_data();
        let response = MockResponseBuilder::new()
            .with_data(sample_data.clone())
            .build();

        with_api_key(mock_post("/analyses"), "test_api_key")
            .and(body_json(&request_body))
            .respond_with(response)
            .mount(&mock_server)
            .await;

        let result: Result<Value, Error> = client.post("analyses", &request_body).await;
        assert!(result.is_ok());
        let response_data = result.unwrap();
        let expected_response = json!({"data": sample_data});
        assert_eq!(response_data, expected_response);
    }

    #[tokio::test]
    async fn test_client_put_success() {
        let (mock_server, client) = TestUtils::create_mock_server_and_client().await;

        let request_body = json!({"verdict": "harmless"});
        let sample_data = sample_vote_data();
        let response = MockResponseBuilder::new()
            .with_data(sample_data.clone())
            .build();

        with_api_key(mock_put("/files/test/votes"), "test_api_key")
            .and(body_json(&request_body))
            .respond_with(response)
            .mount(&mock_server)
            .await;

        let result: Result<Value, Error> = client.put("files/test/votes", &request_body).await;
        assert!(result.is_ok());
        let response_data = result.unwrap();
        let expected_response = json!({"data": sample_data});
        assert_eq!(response_data, expected_response);
    }

    #[tokio::test]
    async fn test_client_delete_success() {
        let (mock_server, client) = TestUtils::create_mock_server_and_client().await;

        let response = MockResponseBuilder::new()
            .with_status(204)
            .build()
            .set_body_string("");

        with_api_key(mock_delete("/files/test/comments/123"), "test_api_key")
            .respond_with(response)
            .mount(&mock_server)
            .await;

        let result = client.delete("files/test/comments/123").await;
        assert!(result.is_ok());
    }
}

/// Error handling tests for different HTTP status codes
mod error_handling_tests {
    use super::*;

    #[tokio::test]
    async fn test_bad_request_error() {
        let (mock_server, client) = TestUtils::create_mock_server_and_client().await;

        let (status, error_response) = sample_error_response(400);
        let response = MockResponseBuilder::new()
            .with_status(status)
            .build()
            .set_body_json(&error_response);

        with_api_key(mock_get("/files/invalid"), "test_api_key")
            .respond_with(response)
            .mount(&mock_server)
            .await;

        let result: Result<Value, Error> = client.get("files/invalid").await;
        assert!(result.is_err());
        match result.unwrap_err() {
            Error::BadRequest(_) => {}
            e => panic!("Expected BadRequest error, got: {:?}", e),
        }
    }

    #[tokio::test]
    async fn test_unauthorized_error() {
        let (mock_server, client) = TestUtils::create_mock_server_and_client().await;

        let (status, error_response) = sample_error_response(401);
        let response = MockResponseBuilder::new()
            .with_status(status)
            .build()
            .set_body_json(&error_response);

        with_api_key(mock_get("/files/test"), "test_api_key")
            .respond_with(response)
            .mount(&mock_server)
            .await;

        let result: Result<Value, Error> = client.get("files/test").await;
        assert!(result.is_err());
        match result.unwrap_err() {
            Error::AuthenticationRequired => {}
            e => panic!("Expected AuthenticationRequired error, got: {:?}", e),
        }
    }

    #[tokio::test]
    async fn test_forbidden_error() {
        let (mock_server, client) = TestUtils::create_mock_server_and_client().await;

        let (status, error_response) = sample_error_response(403);
        let response = MockResponseBuilder::new()
            .with_status(status)
            .build()
            .set_body_json(&error_response);

        with_api_key(mock_get("/files/test"), "test_api_key")
            .respond_with(response)
            .mount(&mock_server)
            .await;

        let result: Result<Value, Error> = client.get("files/test").await;
        assert!(result.is_err());
        match result.unwrap_err() {
            Error::Forbidden => {}
            e => panic!("Expected Forbidden error, got: {:?}", e),
        }
    }

    #[tokio::test]
    async fn test_not_found_error() {
        let (mock_server, client) = TestUtils::create_mock_server_and_client().await;

        let (status, error_response) = sample_error_response(404);
        let response = MockResponseBuilder::new()
            .with_status(status)
            .build()
            .set_body_json(&error_response);

        with_api_key(mock_get("/files/nonexistent"), "test_api_key")
            .respond_with(response)
            .mount(&mock_server)
            .await;

        let result: Result<Value, Error> = client.get("files/nonexistent").await;
        assert!(result.is_err());
        match result.unwrap_err() {
            Error::NotFound => {}
            e => panic!("Expected NotFound error, got: {:?}", e),
        }
    }

    #[tokio::test]
    async fn test_rate_limit_error() {
        let (mock_server, client) = TestUtils::create_mock_server_and_client().await;

        let (status, error_response) = sample_error_response(429);
        let response = MockResponseBuilder::new()
            .with_status(status)
            .build()
            .set_body_json(&error_response);

        with_api_key(mock_get("/files/test"), "test_api_key")
            .respond_with(response)
            .mount(&mock_server)
            .await;

        let result: Result<Value, Error> = client.get("files/test").await;
        assert!(result.is_err());
        match result.unwrap_err() {
            Error::QuotaExceeded(_) => {}
            e => panic!("Expected QuotaExceeded error, got: {:?}", e),
        }
    }

    #[tokio::test]
    async fn test_internal_server_error() {
        let (mock_server, client) = TestUtils::create_mock_server_and_client().await;

        let (status, error_response) = sample_error_response(500);
        let response = MockResponseBuilder::new()
            .with_status(status)
            .build()
            .set_body_json(&error_response);

        with_api_key(mock_get("/files/test"), "test_api_key")
            .respond_with(response)
            .mount(&mock_server)
            .await;

        let result: Result<Value, Error> = client.get("files/test").await;
        assert!(result.is_err());
        match result.unwrap_err() {
            Error::Unknown(_) => {}
            e => panic!("Expected Unknown error, got: {:?}", e),
        }
    }
}

/// Network and timeout failure tests
mod network_failure_tests {
    use super::*;

    #[tokio::test]
    async fn test_timeout_error() {
        let (mock_server, mut client) = TestUtils::create_mock_server_and_client().await;
        client = client.with_timeout(Duration::from_millis(1)).unwrap();

        let response = MockResponseBuilder::new()
            .with_data(sample_file_data())
            .build()
            .set_delay(Duration::from_millis(100));

        with_api_key(mock_get("/files/test"), "test_api_key")
            .respond_with(response)
            .mount(&mock_server)
            .await;

        let result: Result<Value, Error> = client.get("files/test").await;
        assert!(result.is_err());
        match result.unwrap_err() {
            Error::Http(_) => {}
            e => panic!("Expected Http (timeout) error, got: {:?}", e),
        }
    }

    #[tokio::test]
    async fn test_invalid_json_response() {
        let (mock_server, client) = TestUtils::create_mock_server_and_client().await;

        let response = MockResponseBuilder::new()
            .build()
            .set_body_string("invalid json");

        with_api_key(mock_get("/files/test"), "test_api_key")
            .respond_with(response)
            .mount(&mock_server)
            .await;

        let result: Result<Value, Error> = client.get("files/test").await;
        assert!(result.is_err());
        match result.unwrap_err() {
            Error::Json(_) => {}
            e => panic!("Expected Json error, got: {:?}", e),
        }
    }
}

/// Files module comprehensive tests
mod files_module_tests {
    use super::*;

    #[tokio::test]
    async fn test_file_get_by_hash() {
        let (mock_server, client) = TestUtils::create_mock_server_and_client().await;
        let file_client = client.files();

        let hash = "44d88612fea8a8f36de82e1278abb02f";
        let sample_data = sample_file_data();
        let response = MockResponseBuilder::new()
            .with_data(sample_data.clone())
            .build();

        with_api_key(mock_get(&format!("/files/{}", hash)), "test_api_key")
            .respond_with(response)
            .mount(&mock_server)
            .await;

        let result = file_client.get(hash).await;
        assert!(result.is_ok());
        let file = result.unwrap();
        assert_eq!(file.object.id, hash);
    }

    #[tokio::test]
    async fn test_file_analyse() {
        let (mock_server, client) = TestUtils::create_mock_server_and_client().await;
        let file_client = client.files();

        let hash = "44d88612fea8a8f36de82e1278abb02f";
        let sample_data = sample_analysis_data();
        let response = MockResponseBuilder::new()
            .with_data(sample_data.clone())
            .build();

        with_api_key(
            mock_post(&format!("/files/{}/analyse", hash)),
            "test_api_key",
        )
        .respond_with(response)
        .mount(&mock_server)
        .await;

        let result = file_client.analyse(hash).await;
        assert!(result.is_ok());
        let analysis = result.unwrap();
        assert_eq!(analysis.data.object_type, "analysis");
    }

    #[tokio::test]
    async fn test_file_comments() {
        let (mock_server, client) = TestUtils::create_mock_server_and_client().await;
        let file_client = client.files();

        let hash = "44d88612fea8a8f36de82e1278abb02f";
        let comment_data = sample_comment_data();
        let collection_data = sample_collection_data(vec![comment_data], None);

        with_api_key(
            mock_get(&format!("/files/{}/comments", hash)),
            "test_api_key",
        )
        .respond_with(
            MockResponseBuilder::new()
                .build()
                .set_body_json(&collection_data),
        )
        .mount(&mock_server)
        .await;

        let result = file_client.get_comments(hash).await;
        assert!(result.is_ok());
        let comments = result.unwrap();
        assert_eq!(comments.data.len(), 1);
    }

    #[tokio::test]
    async fn test_file_votes() {
        let (mock_server, client) = TestUtils::create_mock_server_and_client().await;
        let file_client = client.files();

        let hash = "44d88612fea8a8f36de82e1278abb02f";
        let vote_data = sample_vote_data();
        let collection_data = sample_collection_data(vec![vote_data], None);

        with_api_key(mock_get(&format!("/files/{}/votes", hash)), "test_api_key")
            .respond_with(
                MockResponseBuilder::new()
                    .build()
                    .set_body_json(&collection_data),
            )
            .mount(&mock_server)
            .await;

        let result = file_client.get_votes(hash).await;
        assert!(result.is_ok());
        let votes = result.unwrap();
        assert_eq!(votes.data.len(), 1);
    }

    #[tokio::test]
    async fn test_file_add_comment() {
        let (mock_server, client) = TestUtils::create_mock_server_and_client().await;
        let file_client = client.files();

        let hash = "44d88612fea8a8f36de82e1278abb02f";
        let comment_text = "Test comment";
        let sample_data = sample_comment_data();
        let response = MockResponseBuilder::new()
            .with_data(sample_data.clone())
            .build();

        with_api_key(
            mock_post(&format!("/files/{}/comments", hash)),
            "test_api_key",
        )
        .and(body_json(
            json!({"data": {"type": "comment", "attributes": {"text": comment_text}}}),
        ))
        .respond_with(response)
        .mount(&mock_server)
        .await;

        let result = file_client.add_comment(hash, comment_text).await;
        assert!(result.is_ok());
        let comment = result.unwrap();
        assert_eq!(comment.object.object_type, "comment");
    }

    #[tokio::test]
    async fn test_file_get_download_url() {
        let (mock_server, client) = TestUtils::create_mock_server_and_client().await;
        let file_client = client.files();

        let hash = "44d88612fea8a8f36de82e1278abb02f";
        let download_url = "https://www.virustotal.com/api/v3/files/download/test";
        let response_data = json!({"data": download_url});

        with_api_key(
            mock_get(&format!("/files/{}/download_url", hash)),
            "test_api_key",
        )
        .respond_with(
            MockResponseBuilder::new()
                .build()
                .set_body_json(&response_data),
        )
        .mount(&mock_server)
        .await;

        let result = file_client.get_download_url(hash).await;
        assert!(result.is_ok());
        let url = result.unwrap();
        assert_eq!(url, download_url);
    }

    #[tokio::test]
    async fn test_file_relationships() {
        let (mock_server, client) = TestUtils::create_mock_server_and_client().await;
        let file_client = client.files();

        let hash = "44d88612fea8a8f36de82e1278abb02f";
        let related_file = sample_file_data();
        let collection_data = sample_collection_data(vec![related_file], None);

        with_api_key(
            mock_get(&format!("/files/{}/similar_files", hash)),
            "test_api_key",
        )
        .respond_with(
            MockResponseBuilder::new()
                .build()
                .set_body_json(&collection_data),
        )
        .mount(&mock_server)
        .await;

        let result = file_client.get_similar_files(hash).await;
        assert!(result.is_ok());
        let relationships = result.unwrap();
        assert_eq!(relationships.data.len(), 1);
    }

    // Note: Skipping relationships_with_limit test as the API endpoints don't support query parameters in this version
}

/// Domains module comprehensive tests
mod domains_module_tests {
    use super::*;

    #[tokio::test]
    async fn test_domain_get() {
        let (mock_server, client) = TestUtils::create_mock_server_and_client().await;
        let domain_client = client.domains();

        let domain_name = "example.com";
        let sample_data = sample_domain_data();
        let response = MockResponseBuilder::new()
            .with_data(sample_data.clone())
            .build();

        with_api_key(
            mock_get(&format!("/domains/{}", domain_name)),
            "test_api_key",
        )
        .respond_with(response)
        .mount(&mock_server)
        .await;

        let result = domain_client.get(domain_name).await;
        assert!(result.is_ok());
        let domain = result.unwrap();
        assert_eq!(domain.object.id, domain_name);
    }

    #[tokio::test]
    async fn test_domain_analyse() {
        let (mock_server, client) = TestUtils::create_mock_server_and_client().await;
        let domain_client = client.domains();

        let domain_name = "example.com";
        let sample_data = sample_analysis_data();
        let response = MockResponseBuilder::new()
            .with_data(sample_data.clone())
            .build();

        with_api_key(
            mock_post(&format!("/domains/{}/analyse", domain_name)),
            "test_api_key",
        )
        .respond_with(response)
        .mount(&mock_server)
        .await;

        let result = domain_client.analyse(domain_name).await;
        assert!(result.is_ok());
        let analysis = result.unwrap();
        assert_eq!(analysis.data.object_type, "analysis");
    }

    #[tokio::test]
    async fn test_domain_comments() {
        let (mock_server, client) = TestUtils::create_mock_server_and_client().await;
        let domain_client = client.domains();

        let domain_name = "example.com";
        let comment_data = sample_comment_data();
        let collection_data = sample_collection_data(vec![comment_data], None);

        with_api_key(
            mock_get(&format!("/domains/{}/comments", domain_name)),
            "test_api_key",
        )
        .respond_with(
            MockResponseBuilder::new()
                .build()
                .set_body_json(&collection_data),
        )
        .mount(&mock_server)
        .await;

        let result = domain_client.get_comments(domain_name).await;
        assert!(result.is_ok());
        let comments = result.unwrap();
        assert_eq!(comments.data.len(), 1);
    }

    #[tokio::test]
    async fn test_domain_relationships() {
        let (mock_server, client) = TestUtils::create_mock_server_and_client().await;
        let domain_client = client.domains();

        let domain_name = "example.com";
        let related_ip = sample_ip_data();
        let collection_data = sample_collection_data(vec![related_ip], None);

        with_api_key(
            mock_get(&format!("/domains/{}/resolutions", domain_name)),
            "test_api_key",
        )
        .respond_with(
            MockResponseBuilder::new()
                .build()
                .set_body_json(&collection_data),
        )
        .mount(&mock_server)
        .await;

        let result: Result<crate::objects::Collection<serde_json::Value>, _> = domain_client
            .get_relationship(domain_name, "resolutions")
            .await;
        assert!(result.is_ok());
        let relationships = result.unwrap();
        assert_eq!(relationships.data.len(), 1);
    }

    #[tokio::test]
    async fn test_domain_subdomains() {
        let (mock_server, client) = TestUtils::create_mock_server_and_client().await;
        let domain_client = client.domains();

        let domain_name = "example.com";
        let subdomain_data = json!({
            "type": "domain",
            "id": "sub.example.com",
            "attributes": {
                "last_analysis_stats": {
                    "harmless": 82,
                    "malicious": 0,
                    "suspicious": 0,
                    "undetected": 1,
                    "timeout": 0
                }
            }
        });
        let collection_data = sample_collection_data(vec![subdomain_data], None);

        with_api_key(
            mock_get(&format!("/domains/{}/subdomains", domain_name)),
            "test_api_key",
        )
        .respond_with(
            MockResponseBuilder::new()
                .build()
                .set_body_json(&collection_data),
        )
        .mount(&mock_server)
        .await;

        let result: Result<crate::objects::Collection<serde_json::Value>, _> = domain_client
            .get_relationship(domain_name, "subdomains")
            .await;
        assert!(result.is_ok());
        let subdomains = result.unwrap();
        assert_eq!(subdomains.data.len(), 1);
    }
}

/// IP addresses module comprehensive tests
mod ip_addresses_module_tests {
    use super::*;

    #[tokio::test]
    async fn test_ip_address_get() {
        let (mock_server, client) = TestUtils::create_mock_server_and_client().await;
        let ip_client = client.ip_addresses();

        let ip_address = "8.8.8.8";
        let sample_data = sample_ip_data();
        let response = MockResponseBuilder::new()
            .with_data(sample_data.clone())
            .build();

        with_api_key(
            mock_get(&format!("/ip_addresses/{}", ip_address)),
            "test_api_key",
        )
        .respond_with(response)
        .mount(&mock_server)
        .await;

        let result = ip_client.get(ip_address).await;
        assert!(result.is_ok());
        let ip = result.unwrap();
        assert_eq!(ip.object.id, ip_address);
    }

    #[tokio::test]
    async fn test_ip_address_analyse() {
        let (mock_server, client) = TestUtils::create_mock_server_and_client().await;
        let ip_client = client.ip_addresses();

        let ip_address = "8.8.8.8";
        let sample_data = sample_analysis_data();
        let response = MockResponseBuilder::new()
            .with_data(sample_data.clone())
            .build();

        with_api_key(
            mock_post(&format!("/ip_addresses/{}/analyse", ip_address)),
            "test_api_key",
        )
        .respond_with(response)
        .mount(&mock_server)
        .await;

        let result = ip_client.analyse(ip_address).await;
        assert!(result.is_ok());
        let analysis = result.unwrap();
        assert_eq!(analysis.data.object_type, "analysis");
    }

    #[tokio::test]
    async fn test_ip_address_comments() {
        let (mock_server, client) = TestUtils::create_mock_server_and_client().await;
        let ip_client = client.ip_addresses();

        let ip_address = "8.8.8.8";
        let comment_data = sample_comment_data();
        let collection_data = sample_collection_data(vec![comment_data], None);

        with_api_key(
            mock_get(&format!("/ip_addresses/{}/comments", ip_address)),
            "test_api_key",
        )
        .respond_with(
            MockResponseBuilder::new()
                .build()
                .set_body_json(&collection_data),
        )
        .mount(&mock_server)
        .await;

        let result = ip_client.get_comments(ip_address).await;
        assert!(result.is_ok());
        let comments = result.unwrap();
        assert_eq!(comments.data.len(), 1);
    }

    #[tokio::test]
    async fn test_ip_address_relationships() {
        let (mock_server, client) = TestUtils::create_mock_server_and_client().await;
        let ip_client = client.ip_addresses();

        let ip_address = "8.8.8.8";
        let related_domain = sample_domain_data();
        let collection_data = sample_collection_data(vec![related_domain], None);

        with_api_key(
            mock_get(&format!("/ip_addresses/{}/resolutions", ip_address)),
            "test_api_key",
        )
        .respond_with(
            MockResponseBuilder::new()
                .build()
                .set_body_json(&collection_data),
        )
        .mount(&mock_server)
        .await;

        let result: Result<crate::objects::Collection<serde_json::Value>, _> =
            ip_client.get_relationship(ip_address, "resolutions").await;
        assert!(result.is_ok());
        let relationships = result.unwrap();
        assert_eq!(relationships.data.len(), 1);
    }
}

/// Sigma rules and YARA rulesets tests
mod rules_module_tests {
    use super::*;

    #[tokio::test]
    async fn test_sigma_rules_get() {
        let (mock_server, client) = TestUtils::create_mock_server_and_client().await;
        let sigma_client = client.sigma_rules();

        let rule_id = "sigma-rule-123";
        let sample_data = sample_sigma_rule_data();
        let response = MockResponseBuilder::new()
            .with_data(sample_data.clone())
            .build();

        with_api_key(
            mock_get(&format!("/sigma_rules/{}", rule_id)),
            "test_api_key",
        )
        .respond_with(response)
        .mount(&mock_server)
        .await;

        let result = sigma_client.get(rule_id).await;
        assert!(result.is_ok());
        let rule_response = result.unwrap();
        assert_eq!(rule_response.data.object.id, rule_id);
    }

    #[tokio::test]
    async fn test_yara_rulesets_get() {
        let (mock_server, client) = TestUtils::create_mock_server_and_client().await;
        let yara_client = client.yara_rulesets();

        let ruleset_id = "yara-ruleset-456";
        let sample_data = sample_yara_ruleset_data();
        let response = MockResponseBuilder::new()
            .with_data(sample_data.clone())
            .build();

        with_api_key(
            mock_get(&format!("/yara_rulesets/{}", ruleset_id)),
            "test_api_key",
        )
        .respond_with(response)
        .mount(&mock_server)
        .await;

        let result = yara_client.get(ruleset_id).await;
        assert!(result.is_ok());
        let ruleset_response = result.unwrap();
        assert_eq!(ruleset_response.data.object.id, ruleset_id);
    }

    // Note: Removed list tests as the API doesn't support listing these resources

    // Note: Removed list tests as the API doesn't support listing these resources
}
