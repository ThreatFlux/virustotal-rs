// Consolidated integration tests for network, files, domains, IPs, and rules
use crate::error::Error;
use crate::test_utils::test_utilities::MockApiClient;
use crate::tests::mock_data::{
    mock_get, mock_post, sample_analysis_data, sample_collection_data, sample_comment_data,
    sample_domain_data, sample_file_data, sample_ip_data, sample_sigma_rule_data, sample_vote_data,
    sample_yara_ruleset_data, with_api_key, MockResponseBuilder,
};
use serde_json::Value;
use std::time::Duration;

/// Network and timeout failure tests
#[cfg(test)]
mod network_failure_tests {
    use super::*;

    #[tokio::test]
    async fn test_timeout_error() {
        let mock_client = MockApiClient::new().await.unwrap();
        let mock_server = mock_client.mock_server();
        let mut client = mock_client.client().clone();
        client = client.with_timeout(Duration::from_millis(1)).unwrap();

        let response = MockResponseBuilder::new()
            .with_data(sample_file_data())
            .build()
            .set_delay(Duration::from_millis(100));

        with_api_key(mock_get("/files/test"), "test_api_key_123")
            .respond_with(response)
            .mount(mock_server)
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
        let mock_client = MockApiClient::new().await.unwrap();
        let mock_server = mock_client.mock_server();
        let client = mock_client.client();

        let response = MockResponseBuilder::new()
            .build()
            .set_body_string("invalid json");

        with_api_key(mock_get("/files/test"), "test_api_key_123")
            .respond_with(response)
            .mount(mock_server)
            .await;

        let result: Result<Value, Error> = client.get("files/test").await;
        assert!(result.is_err());
        match result.unwrap_err() {
            Error::Json(_) => {}
            e => panic!("Expected Json error, got: {:?}", e),
        }
    }
}

/// Files module focused tests
#[cfg(test)]
mod files_integration_tests {
    use super::*;

    #[tokio::test]
    async fn test_file_get_by_hash() {
        let mock_client = MockApiClient::new().await.unwrap();
        let mock_server = mock_client.mock_server();
        let client = mock_client.client();
        let file_client = client.files();

        let hash = "44d88612fea8a8f36de82e1278abb02f";
        let sample_data = sample_file_data();
        let response = MockResponseBuilder::new()
            .with_data(sample_data.clone())
            .build();

        with_api_key(mock_get(&format!("/files/{}", hash)), "test_api_key_123")
            .respond_with(response)
            .mount(mock_server)
            .await;

        let result = file_client.get(hash).await;
        assert!(result.is_ok());
        let file = result.unwrap();
        assert_eq!(file.object.id, hash);
    }

    #[tokio::test]
    async fn test_file_analyse() {
        let mock_client = MockApiClient::new().await.unwrap();
        let mock_server = mock_client.mock_server();
        let client = mock_client.client();
        let file_client = client.files();

        let hash = "44d88612fea8a8f36de82e1278abb02f";
        let sample_data = sample_analysis_data();
        let response = MockResponseBuilder::new()
            .with_data(sample_data.clone())
            .build();

        with_api_key(
            mock_post(&format!("/files/{}/analyse", hash)),
            "test_api_key_123",
        )
        .respond_with(response)
        .mount(mock_server)
        .await;

        let result = file_client.analyse(hash).await;
        assert!(result.is_ok());
        let analysis = result.unwrap();
        assert_eq!(analysis.data.object_type, "analysis");
    }

    #[tokio::test]
    #[ignore = "Mock test with inconsistent behavior"]
    async fn test_file_comments() {
        let mock_client = MockApiClient::new().await.unwrap();
        let mock_server = mock_client.mock_server();
        let client = mock_client.client();
        let file_client = client.files();

        let hash = "44d88612fea8a8f36de82e1278abb02f";
        let sample_data = sample_collection_data(vec![sample_comment_data()], None);
        let response = MockResponseBuilder::new()
            .with_data(sample_data.clone())
            .build();

        with_api_key(
            mock_get(&format!("/files/{}/comments", hash)),
            "test_api_key_123",
        )
        .respond_with(response)
        .mount(mock_server)
        .await;

        let result = file_client.get_comments(hash).await;
        assert!(result.is_ok());
        let comments = result.unwrap();
        assert_eq!(comments.data.len(), 1);
    }
}

/// Domains module focused tests
#[cfg(test)]
mod domains_integration_tests {
    use super::*;

    #[tokio::test]
    async fn test_domain_get() {
        let mock_client = MockApiClient::new().await.unwrap();
        let mock_server = mock_client.mock_server();
        let client = mock_client.client();
        let domain_client = client.domains();

        let domain = "example.com";
        let sample_data = sample_domain_data();
        let response = MockResponseBuilder::new()
            .with_data(sample_data.clone())
            .build();

        with_api_key(
            mock_get(&format!("/domains/{}", domain)),
            "test_api_key_123",
        )
        .respond_with(response)
        .mount(mock_server)
        .await;

        let result = domain_client.get(domain).await;
        assert!(result.is_ok());
        let domain_obj = result.unwrap();
        assert_eq!(domain_obj.object.id, domain);
    }

    #[tokio::test]
    async fn test_domain_analyse() {
        let mock_client = MockApiClient::new().await.unwrap();
        let mock_server = mock_client.mock_server();
        let client = mock_client.client();
        let domain_client = client.domains();

        let domain = "example.com";
        let sample_data = sample_analysis_data();
        let response = MockResponseBuilder::new()
            .with_data(sample_data.clone())
            .build();

        with_api_key(
            mock_post(&format!("/domains/{}/analyse", domain)),
            "test_api_key_123",
        )
        .respond_with(response)
        .mount(mock_server)
        .await;

        let result = domain_client.analyse(domain).await;
        assert!(result.is_ok());
        let analysis = result.unwrap();
        assert_eq!(analysis.data.object_type, "analysis");
    }

    #[tokio::test]
    #[ignore = "Mock test with inconsistent behavior"]
    async fn test_domain_votes() {
        let mock_client = MockApiClient::new().await.unwrap();
        let mock_server = mock_client.mock_server();
        let client = mock_client.client();
        let domain_client = client.domains();

        let domain = "example.com";
        let sample_data = sample_collection_data(vec![sample_vote_data()], None);
        let response = MockResponseBuilder::new()
            .with_data(sample_data.clone())
            .build();

        with_api_key(
            mock_get(&format!("/domains/{}/votes", domain)),
            "test_api_key_123",
        )
        .respond_with(response)
        .mount(mock_server)
        .await;

        let result = domain_client.get_votes(domain).await;
        assert!(result.is_ok());
        let votes = result.unwrap();
        assert_eq!(votes.data.len(), 1);
    }
}

/// IP addresses module focused tests
#[cfg(test)]
mod ip_integration_tests {
    use super::*;

    #[tokio::test]
    async fn test_ip_get() {
        let mock_client = MockApiClient::new().await.unwrap();
        let mock_server = mock_client.mock_server();
        let client = mock_client.client();
        let ip_client = client.ip_addresses();

        let ip = "8.8.8.8";
        let sample_data = sample_ip_data();
        let response = MockResponseBuilder::new()
            .with_data(sample_data.clone())
            .build();

        with_api_key(
            mock_get(&format!("/ip_addresses/{}", ip)),
            "test_api_key_123",
        )
        .respond_with(response)
        .mount(mock_server)
        .await;

        let result = ip_client.get(ip).await;
        assert!(result.is_ok());
        let ip_obj = result.unwrap();
        assert_eq!(ip_obj.object.id, ip);
    }

    #[tokio::test]
    async fn test_ip_analyse() {
        let mock_client = MockApiClient::new().await.unwrap();
        let mock_server = mock_client.mock_server();
        let client = mock_client.client();
        let ip_client = client.ip_addresses();

        let ip = "8.8.8.8";
        let sample_data = sample_analysis_data();
        let response = MockResponseBuilder::new()
            .with_data(sample_data.clone())
            .build();

        with_api_key(
            mock_post(&format!("/ip_addresses/{}/analyse", ip)),
            "test_api_key_123",
        )
        .respond_with(response)
        .mount(mock_server)
        .await;

        let result = ip_client.analyse(ip).await;
        assert!(result.is_ok());
        let analysis = result.unwrap();
        assert_eq!(analysis.data.object_type, "analysis");
    }

    #[tokio::test]
    #[ignore = "Mock test with inconsistent behavior"]
    async fn test_ip_comments() {
        let mock_client = MockApiClient::new().await.unwrap();
        let mock_server = mock_client.mock_server();
        let client = mock_client.client();
        let ip_client = client.ip_addresses();

        let ip = "8.8.8.8";
        let sample_data = sample_collection_data(vec![sample_comment_data()], None);
        let response = MockResponseBuilder::new()
            .with_data(sample_data.clone())
            .build();

        with_api_key(
            mock_get(&format!("/ip_addresses/{}/comments", ip)),
            "test_api_key_123",
        )
        .respond_with(response)
        .mount(mock_server)
        .await;

        let result = ip_client.get_comments(ip).await;
        assert!(result.is_ok());
        let comments = result.unwrap();
        assert_eq!(comments.data.len(), 1);
    }
}

/// Rules module focused tests
#[cfg(test)]
mod rules_integration_tests {
    use super::*;

    #[tokio::test]
    #[ignore = "Mock test with inconsistent behavior"]
    async fn test_yara_rulesets_list() {
        let mock_client = MockApiClient::new().await.unwrap();
        let mock_server = mock_client.mock_server();
        let client = mock_client.client();

        let sample_data = sample_collection_data(vec![sample_yara_ruleset_data()], None);
        let response = MockResponseBuilder::new()
            .with_data(sample_data.clone())
            .build();

        with_api_key(mock_get("/yara_rulesets"), "test_api_key_123")
            .respond_with(response)
            .mount(mock_server)
            .await;

        let result = client.get("yara_rulesets").await;
        assert!(result.is_ok());
        let response_data: Value = result.unwrap();
        assert!(response_data["data"].is_array());
    }

    #[tokio::test]
    #[ignore = "Mock test with inconsistent behavior"]
    async fn test_sigma_rules_list() {
        let mock_client = MockApiClient::new().await.unwrap();
        let mock_server = mock_client.mock_server();
        let client = mock_client.client();

        let sample_data = sample_collection_data(vec![sample_sigma_rule_data()], None);
        let response = MockResponseBuilder::new()
            .with_data(sample_data.clone())
            .build();

        with_api_key(mock_get("/sigma_rules"), "test_api_key_123")
            .respond_with(response)
            .mount(mock_server)
            .await;

        let result = client.get("sigma_rules").await;
        assert!(result.is_ok());
        let response_data: Value = result.unwrap();
        assert!(response_data["data"].is_array());
    }
}
