// File basic operations tests (get, analyse, upload/download URLs)
use serde_json::json;
// use virustotal_rs::objects::ObjectOperations; // Not needed
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

/// File retrieval tests
#[cfg(test)]
mod file_retrieval_tests {
    use super::*;

    #[tokio::test]
    async fn test_file_get() {
        let mock_server = MockServer::start().await;

        let file_response = create_sample_file_response();

        Mock::given(method("GET"))
            .and(path(
                "/files/275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
            ))
            .and(header("x-apikey", "test_key"))
            .respond_with(ResponseTemplate::new(200).set_body_json(&file_response))
            .mount(&mock_server)
            .await;

        let client = create_test_client(&mock_server).await;
        let file = client
            .files()
            .get("275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f")
            .await
            .unwrap();

        assert_eq!(
            file.object.id,
            "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
        );
        assert_eq!(file.object.object_type, "file");
        assert_eq!(
            file.object.attributes.meaningful_name,
            Some("eicar.txt".to_string())
        );
        assert_eq!(file.object.attributes.size, Some(68));
        assert_eq!(file.object.attributes.reputation, Some(-958));
    }

    #[tokio::test]
    async fn test_file_analyse() {
        let mock_server = MockServer::start().await;

        let analysis_response = json!({
            "data": {
                "type": "analysis",
                "id": "u-275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f-1234567890",
                "links": {
                    "self": "https://www.virustotal.com/api/v3/analyses/u-275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f-1234567890"
                }
            }
        });

        Mock::given(method("POST"))
            .and(path(
                "/files/275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f/analyse",
            ))
            .and(header("x-apikey", "test_key"))
            .respond_with(ResponseTemplate::new(200).set_body_json(&analysis_response))
            .mount(&mock_server)
            .await;

        let client = create_test_client(&mock_server).await;
        let analysis = client
            .files()
            .analyse("275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f")
            .await
            .unwrap();

        assert_eq!(analysis.data.object_type, "analysis");
        assert!(analysis
            .data
            .id
            .contains("275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"));
    }
}

/// File URL operations tests
#[cfg(test)]
mod file_url_tests {
    use super::*;

    #[tokio::test]
    async fn test_file_get_upload_url() {
        let mock_server = MockServer::start().await;

        let upload_url_response = json!({
            "data": "https://www.virustotal.com/_ah/upload/AMmfu6b-_DXUeFe36Sb3b0F4B8mH9Nb-CHbRoUNVOPmG/"
        });

        Mock::given(method("GET"))
            .and(path("/files/upload_url"))
            .and(header("x-apikey", "test_key"))
            .respond_with(ResponseTemplate::new(200).set_body_json(&upload_url_response))
            .mount(&mock_server)
            .await;

        let client = create_test_client(&mock_server).await;
        let upload_url = client.files().get_upload_url().await.unwrap();

        assert!(upload_url.contains("virustotal.com"));
        assert!(upload_url.contains("upload"));
    }

    #[tokio::test]
    async fn test_file_get_download_url() {
        let mock_server = MockServer::start().await;

        let download_url_response = json!({
            "data": "https://www.virustotal.com/api/v3/files/275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f/download?x-apikey=test_key"
        });

        Mock::given(method("GET"))
            .and(path("/files/275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f/download_url"))
            .and(header("x-apikey", "test_key"))
            .respond_with(ResponseTemplate::new(200).set_body_json(&download_url_response))
            .mount(&mock_server)
            .await;

        let client = create_test_client(&mock_server).await;
        let download_url = client
            .files()
            .get_download_url("275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f")
            .await
            .unwrap();

        assert!(download_url.contains("virustotal.com"));
        assert!(download_url.contains("download"));
    }
}

/// Helper function to create sample file response
fn create_sample_file_response() -> serde_json::Value {
    json!({
        "data": {
            "type": "file",
            "id": "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
            "links": {
                "self": "https://www.virustotal.com/api/v3/files/275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
            },
            "attributes": {
                "type_description": "ASCII text",
                "type_tag": "text",
                "type_extension": "txt",
                "meaningful_name": "eicar.txt",
                "size": 68,
                "sha256": "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
                "sha1": "3395856ce81f2b7382dee72602f798b642f14140",
                "md5": "44d88612fea8a8f36de82e1278abb02f",
                "magic": "ASCII text, with no line terminators",
                "last_analysis_date": 1234567890,
                "last_analysis_stats": {
                    "harmless": 0,
                    "malicious": 58,
                    "suspicious": 0,
                    "undetected": 12,
                    "timeout": 0
                },
                "reputation": -958
            }
        }
    })
}
