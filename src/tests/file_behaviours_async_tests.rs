// Async file behaviour tests focused on sandbox analysis operations
use crate::test_utils::test_utilities::*;
use serde_json::json;
use wiremock::matchers::{header, method, path};
use wiremock::{Mock, ResponseTemplate};

/// Test file behaviour client basic operations
#[cfg(test)]
mod file_behaviour_client_tests {
    use super::*;

    #[tokio::test]
    async fn test_file_behaviour_client_get() {
        let mock_client = MockApiClient::new().await.unwrap();
        let response_body = json!({
            "data": {
                "type": "file_behaviour",
                "id": "test_sandbox_id",
                "attributes": {
                    "analysis_date": constants::SAMPLE_TIMESTAMP,
                    "sandbox": "VirusTotal Jujubox",
                    "has_html_report": true,
                    "has_evtx": false,
                    "has_pcap": true,
                    "has_memdump": false
                }
            }
        });

        Mock::given(method("GET"))
            .and(path("/file_behaviours/test_sandbox_id"))
            .and(header("x-apikey", constants::TEST_API_KEY))
            .respond_with(create_json_response(200, &response_body))
            .mount(mock_client.mock_server())
            .await;

        let behaviour_client = mock_client.client().file_behaviours();
        let result = behaviour_client.get("test_sandbox_id").await;

        assert!(result.is_ok());
        let behaviour = result.unwrap();
        assert_eq!(behaviour.object.id, "test_sandbox_id");
    }

    #[tokio::test]
    async fn test_file_behaviour_get_relationship() {
        let mock_client = MockApiClient::new().await.unwrap();
        let domain_data = DomainResponseBuilder::clean_domain().build();
        let response_data = ResponseFactory::collection_response(vec![domain_data], None);

        Mock::given(method("GET"))
            .and(path("/file_behaviours/test_sandbox_id/contacted_domains"))
            .and(header("x-apikey", constants::TEST_API_KEY))
            .respond_with(create_json_response(200, &response_data))
            .mount(mock_client.mock_server())
            .await;

        let behaviour_client = mock_client.client().file_behaviours();
        let result = behaviour_client
            .get_contacted_domains("test_sandbox_id")
            .await;

        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_file_behaviour_get_relationship_descriptors() {
        let mock_client = MockApiClient::new().await.unwrap();
        let domain_data = DomainResponseBuilder::clean_domain().build();
        let response_data = ResponseFactory::success_response(json!([domain_data]));

        Mock::given(method("GET"))
            .and(path(
                "/file_behaviours/test_sandbox_id/relationships/contacted_domains",
            ))
            .and(header("x-apikey", constants::TEST_API_KEY))
            .respond_with(create_json_response(200, &response_data))
            .mount(mock_client.mock_server())
            .await;

        let behaviour_client = mock_client.client().file_behaviours();
        let result = behaviour_client
            .get_relationship_descriptors("test_sandbox_id", "contacted_domains")
            .await;

        assert!(result.is_ok());
    }
}

/// Test file behaviour report operations
#[cfg(test)]
mod file_behaviour_report_tests {
    use super::*;

    #[tokio::test]
    async fn test_file_behaviour_get_html_report() {
        let mock_client = MockApiClient::new().await.unwrap();
        let html_report = "<html><body><h1>Sandbox Report</h1></body></html>";

        Mock::given(method("GET"))
            .and(path("/file_behaviours/test_sandbox_id/html"))
            .and(header("x-apikey", constants::TEST_API_KEY))
            .respond_with(ResponseTemplate::new(200).set_body_string(html_report))
            .mount(mock_client.mock_server())
            .await;

        let behaviour_client = mock_client.client().file_behaviours();
        let result = behaviour_client.get_html_report("test_sandbox_id").await;

        assert!(result.is_ok());
        let html = result.unwrap();
        assert!(html.contains("Sandbox Report"));
    }

    #[tokio::test]
    async fn test_file_behaviour_get_evtx() {
        let mock_client = MockApiClient::new().await.unwrap();
        let evtx_data = create_mock_evtx_data();

        Mock::given(method("GET"))
            .and(path("/file_behaviours/test_sandbox_id/evtx"))
            .and(header("x-apikey", constants::TEST_API_KEY))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(evtx_data.clone()))
            .mount(mock_client.mock_server())
            .await;

        let behaviour_client = mock_client.client().file_behaviours();
        let result = behaviour_client.get_evtx("test_sandbox_id").await;

        assert!(result.is_ok());
        let data = result.unwrap();
        assert_eq!(data, evtx_data);
    }

    #[tokio::test]
    async fn test_file_behaviour_get_pcap() {
        let mock_client = MockApiClient::new().await.unwrap();
        let pcap_data = create_mock_pcap_data();

        Mock::given(method("GET"))
            .and(path("/file_behaviours/test_sandbox_id/pcap"))
            .and(header("x-apikey", constants::TEST_API_KEY))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(pcap_data.clone()))
            .mount(mock_client.mock_server())
            .await;

        let behaviour_client = mock_client.client().file_behaviours();
        let result = behaviour_client.get_pcap("test_sandbox_id").await;

        assert!(result.is_ok());
        let data = result.unwrap();
        assert_eq!(data, pcap_data);
        // Verify PCAP magic number
        assert_eq!(&data[0..4], &[0xD4, 0xC3, 0xB2, 0xA1]);
    }

    #[tokio::test]
    async fn test_file_behaviour_get_memdump() {
        let mock_client = MockApiClient::new().await.unwrap();
        let memdump_data = create_mock_memdump_data();

        Mock::given(method("GET"))
            .and(path("/file_behaviours/test_sandbox_id/memdump"))
            .and(header("x-apikey", constants::TEST_API_KEY))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(memdump_data.clone()))
            .mount(mock_client.mock_server())
            .await;

        let behaviour_client = mock_client.client().file_behaviours();
        let result = behaviour_client.get_memdump("test_sandbox_id").await;

        assert!(result.is_ok());
        let data = result.unwrap();
        assert_eq!(data, memdump_data);
        // Verify PE signature
        assert_eq!(&data[0..2], &[0x4D, 0x5A]); // "MZ" signature
    }
}

/// Test file behaviour error scenarios
#[cfg(test)]
mod file_behaviour_error_tests {
    use super::*;

    #[tokio::test]
    async fn test_file_behaviour_special_privileges_endpoints() {
        let mock_client = MockApiClient::new().await.unwrap();
        let (status, error_response) = ResponseFactory::forbidden_error();

        let endpoints = ["evtx", "pcap", "memdump"];

        for endpoint in &endpoints {
            Mock::given(method("GET"))
                .and(path(format!(
                    "/file_behaviours/test_sandbox_id/{}",
                    endpoint
                )))
                .and(header("x-apikey", constants::TEST_API_KEY))
                .respond_with(create_json_response(status, &error_response))
                .mount(mock_client.mock_server())
                .await;
        }

        let behaviour_client = mock_client.client().file_behaviours();

        // Test that all privileged endpoints return appropriate errors
        let evtx_result = behaviour_client.get_evtx("test_sandbox_id").await;
        assert!(evtx_result.is_err());

        let pcap_result = behaviour_client.get_pcap("test_sandbox_id").await;
        assert!(pcap_result.is_err());

        let memdump_result = behaviour_client.get_memdump("test_sandbox_id").await;
        assert!(memdump_result.is_err());
    }
}

/// Test file behaviour convenience methods
#[cfg(test)]
mod file_behaviour_convenience_tests {
    use super::*;

    #[tokio::test]
    async fn test_file_behaviour_convenience_methods() {
        let mock_client = MockApiClient::new().await.unwrap();
        let response_data = ResponseFactory::collection_response(vec![], None);

        let endpoints = [
            "contacted_ips",
            "dropped_files",
            "contacted_urls",
            "attack_techniques",
            "sigma_analysis",
        ];

        for endpoint in &endpoints {
            Mock::given(method("GET"))
                .and(path(format!(
                    "/file_behaviours/test_sandbox_id/{}",
                    endpoint
                )))
                .and(header("x-apikey", constants::TEST_API_KEY))
                .respond_with(create_json_response(200, &response_data))
                .mount(mock_client.mock_server())
                .await;
        }

        let behaviour_client = mock_client.client().file_behaviours();

        // Test all convenience methods
        assert!(behaviour_client
            .get_contacted_ips("test_sandbox_id")
            .await
            .is_ok());
        assert!(behaviour_client
            .get_dropped_files("test_sandbox_id")
            .await
            .is_ok());
        assert!(behaviour_client
            .get_contacted_urls("test_sandbox_id")
            .await
            .is_ok());
        assert!(behaviour_client
            .get_attack_techniques("test_sandbox_id")
            .await
            .is_ok());
        assert!(behaviour_client
            .get_sigma_analysis("test_sandbox_id")
            .await
            .is_ok());
    }

    #[tokio::test]
    async fn test_file_behaviour_relationship_iterator() {
        let mock_client = MockApiClient::new().await.unwrap();
        let response_data =
            ResponseFactory::collection_response(vec![json!("item1"), json!("item2")], None);

        Mock::given(method("GET"))
            .and(path("/file_behaviours/test_sandbox_id/contacted_domains"))
            .and(header("x-apikey", constants::TEST_API_KEY))
            .respond_with(create_json_response(200, &response_data))
            .mount(mock_client.mock_server())
            .await;

        let behaviour_client = mock_client.client().file_behaviours();
        let mut iterator = behaviour_client
            .get_relationship_iterator::<String>("test_sandbox_id", "contacted_domains");
        let batch = iterator.next_batch().await;

        assert!(batch.is_ok());
    }
}

/// Helper functions for creating mock binary data
fn create_mock_evtx_data() -> Vec<u8> {
    // Mock EVTX binary data
    vec![0x45, 0x6C, 0x66, 0x46, 0x69, 0x6C, 0x65]
}

fn create_mock_pcap_data() -> Vec<u8> {
    // Mock PCAP file header (libpcap format)
    vec![
        0xD4, 0xC3, 0xB2, 0xA1, // Magic number (little-endian)
        0x02, 0x00, 0x04, 0x00, // Version major/minor
        0x00, 0x00, 0x00, 0x00, // Timezone offset
        0x00, 0x00, 0x00, 0x00, // Timestamp accuracy
        0xFF, 0xFF, 0x00, 0x00, // Max packet length
        0x01, 0x00, 0x00, 0x00, // Data link type (Ethernet)
    ]
}

fn create_mock_memdump_data() -> Vec<u8> {
    // Mock memory dump data (simplified PE header)
    vec![
        0x4D, 0x5A, 0x90, 0x00, // PE header start (MZ signature)
        0x03, 0x00, 0x00, 0x00, // Bytes on last page
        0x04, 0x00, 0x00, 0x00, // Pages in file
        0x00, 0x00, 0x00, 0x00, // Relocations
    ]
}
