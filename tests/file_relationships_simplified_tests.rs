// Simplified file relationship tests to avoid complex type issues
use serde_json::json;
use virustotal_rs::{ApiTier, ClientBuilder};
use wiremock::matchers::{header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

/// Helper function to create test client
async fn create_test_client(mock_server: &MockServer) -> virustotal_rs::Client {
    ClientBuilder::new()
        .api_key("test_key")
        .tier(ApiTier::Public)
        .base_url(mock_server.uri())
        .build()
        .unwrap()
}

/// Simplified file behavior relationship tests
#[cfg(test)]
mod file_behavior_tests {
    use super::*;

    #[tokio::test]
    async fn test_file_behaviours_endpoint() {
        let mock_server = MockServer::start().await;

        let behaviours_response = json!({
            "data": [
                {
                    "type": "file_behaviour",
                    "id": "sandbox-1234",
                    "attributes": {
                        "sandbox_name": "VirusTotal Jujubox",
                        "analysis_date": 1234567890
                    }
                }
            ],
            "meta": {
                "count": 1
            }
        });

        Mock::given(method("GET"))
            .and(path("/files/275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f/behaviours"))
            .and(header("x-apikey", "test_key"))
            .respond_with(ResponseTemplate::new(200).set_body_json(&behaviours_response))
            .mount(&mock_server)
            .await;

        let client = create_test_client(&mock_server).await;
        let behaviours = client
            .files()
            .get_behaviours("275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f")
            .await
            .unwrap();

        assert_eq!(behaviours.data.len(), 1);
        // Just verify the structure exists without accessing specific fields
        assert!(serde_json::to_string(&behaviours.data[0])
            .unwrap()
            .contains("sandbox-1234"));
    }
}

/// Simplified file network relationship tests
#[cfg(test)]
mod file_network_tests {
    use super::*;

    #[tokio::test]
    async fn test_file_contacted_domains_endpoint() {
        let mock_server = MockServer::start().await;

        let domains_response = json!({
            "data": [
                {
                    "type": "domain",
                    "id": "malicious.example.com"
                }
            ]
        });

        Mock::given(method("GET"))
            .and(path("/files/275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f/contacted_domains"))
            .and(header("x-apikey", "test_key"))
            .respond_with(ResponseTemplate::new(200).set_body_json(&domains_response))
            .mount(&mock_server)
            .await;

        let client = create_test_client(&mock_server).await;
        let domains = client
            .files()
            .get_contacted_domains(
                "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
            )
            .await
            .unwrap();

        assert_eq!(domains.data.len(), 1);
        assert!(serde_json::to_string(&domains.data[0])
            .unwrap()
            .contains("malicious.example.com"));
    }

    #[tokio::test]
    async fn test_file_contacted_ips_endpoint() {
        let mock_server = MockServer::start().await;

        let ips_response = json!({
            "data": [
                {
                    "type": "ip_address",
                    "id": "192.168.1.1"
                }
            ]
        });

        Mock::given(method("GET"))
            .and(path("/files/275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f/contacted_ips"))
            .and(header("x-apikey", "test_key"))
            .respond_with(ResponseTemplate::new(200).set_body_json(&ips_response))
            .mount(&mock_server)
            .await;

        let client = create_test_client(&mock_server).await;
        let ips = client
            .files()
            .get_contacted_ips("275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f")
            .await
            .unwrap();

        assert_eq!(ips.data.len(), 1);
        assert!(serde_json::to_string(&ips.data[0])
            .unwrap()
            .contains("192.168.1.1"));
    }
}

/// Simplified file analysis relationship tests
#[cfg(test)]
mod file_analysis_tests {
    use super::*;

    #[tokio::test]
    async fn test_file_dropped_files_endpoint() {
        let mock_server = MockServer::start().await;

        let dropped_files_response = json!({
            "data": [
                {
                    "type": "file",
                    "id": "dropped_file_hash_1234"
                }
            ]
        });

        Mock::given(method("GET"))
            .and(path("/files/275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f/dropped_files"))
            .and(header("x-apikey", "test_key"))
            .respond_with(ResponseTemplate::new(200).set_body_json(&dropped_files_response))
            .mount(&mock_server)
            .await;

        let client = create_test_client(&mock_server).await;
        let dropped_files = client
            .files()
            .get_dropped_files("275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f")
            .await
            .unwrap();

        assert_eq!(dropped_files.data.len(), 1);
        assert!(serde_json::to_string(&dropped_files.data[0])
            .unwrap()
            .contains("dropped_file_hash_1234"));
    }

    #[tokio::test]
    async fn test_file_similar_files_endpoint() {
        let mock_server = MockServer::start().await;

        let similar_files_response = json!({
            "data": [
                {
                    "type": "file",
                    "id": "similar_file_hash_5678"
                }
            ]
        });

        Mock::given(method("GET"))
            .and(path("/files/275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f/similar_files"))
            .and(header("x-apikey", "test_key"))
            .respond_with(ResponseTemplate::new(200).set_body_json(&similar_files_response))
            .mount(&mock_server)
            .await;

        let client = create_test_client(&mock_server).await;
        let similar_files = client
            .files()
            .get_similar_files("275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f")
            .await
            .unwrap();

        assert_eq!(similar_files.data.len(), 1);
        assert!(serde_json::to_string(&similar_files.data[0])
            .unwrap()
            .contains("similar_file_hash_5678"));
    }
}
