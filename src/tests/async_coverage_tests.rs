// Async tests to improve coverage by testing actual API client methods with mocks

use crate::*;
use serde_json::json;
use wiremock::matchers::{header, method, path, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

#[cfg(test)]
mod files_async_tests {
    use super::*;
    #[allow(unused_imports)]
    use crate::files::FileClient;
    // Removed unused imports

    #[tokio::test]
    async fn test_file_client_get() {
        let mock_server = MockServer::start().await;

        let response_body = json!({
            "data": {
                "type": "file",
                "id": "test_hash",
                "attributes": {
                    "sha256": "test_hash",
                    "size": 1024,
                    "type_description": "PE32 executable"
                }
            }
        });

        Mock::given(method("GET"))
            .and(path("/files/test_hash"))
            .and(header("x-apikey", "test_key"))
            .respond_with(ResponseTemplate::new(200).set_body_json(&response_body))
            .mount(&mock_server)
            .await;

        let client = Client::new_with_base_url("test_key", &mock_server.uri());
        let file_client = client.files();

        let result = file_client.get("test_hash").await;
        assert!(result.is_ok());
        let file = result.unwrap();
        assert_eq!(file.object.id, "test_hash");
    }

    #[tokio::test]
    async fn test_file_client_get_download_url() {
        let mock_server = MockServer::start().await;

        let response_body = json!({
            "data": "https://download.url/file"
        });

        Mock::given(method("GET"))
            .and(path("/files/test_hash/download_url"))
            .and(header("x-apikey", "test_key"))
            .respond_with(ResponseTemplate::new(200).set_body_json(&response_body))
            .mount(&mock_server)
            .await;

        let client = Client::new_with_base_url("test_key", &mock_server.uri());
        let file_client = client.files();

        let result = file_client.get_download_url("test_hash").await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "https://download.url/file");
    }

    #[tokio::test]
    async fn test_file_client_get_upload_url() {
        let mock_server = MockServer::start().await;

        let response_body = json!({
            "data": "https://upload.url/file"
        });

        Mock::given(method("GET"))
            .and(path("/files/upload_url"))
            .and(header("x-apikey", "test_key"))
            .respond_with(ResponseTemplate::new(200).set_body_json(&response_body))
            .mount(&mock_server)
            .await;

        let client = Client::new_with_base_url("test_key", &mock_server.uri());
        let file_client = client.files();

        let result = file_client.get_upload_url().await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "https://upload.url/file");
    }
}

#[cfg(test)]
mod domains_async_tests {
    use super::*;
    #[allow(unused_imports)]
    use crate::domains::DomainClient;

    #[tokio::test]
    async fn test_domain_client_get() {
        let mock_server = MockServer::start().await;

        let response_body = json!({
            "data": {
                "type": "domain",
                "id": "example.com",
                "attributes": {
                    "registrar": "Example Registrar",
                    "creation_date": 1234567890,
                    "reputation": 0
                }
            }
        });

        Mock::given(method("GET"))
            .and(path("/domains/example.com"))
            .and(header("x-apikey", "test_key"))
            .respond_with(ResponseTemplate::new(200).set_body_json(&response_body))
            .mount(&mock_server)
            .await;

        let client = Client::new_with_base_url("test_key", &mock_server.uri());
        let domain_client = client.domains();

        let result = domain_client.get("example.com").await;
        assert!(result.is_ok());
        let domain = result.unwrap();
        assert_eq!(domain.object.id, "example.com");
    }

    #[tokio::test]
    async fn test_domain_client_get_with_relationships() {
        let mock_server = MockServer::start().await;

        let response_body = json!({
            "data": {
                "type": "domain",
                "id": "example.com",
                "attributes": {
                    "registrar": "Example Registrar"
                },
                "relationships": {
                    "subdomains": {
                        "data": []
                    }
                }
            }
        });

        Mock::given(method("GET"))
            .and(path("/domains/example.com"))
            .and(header("x-apikey", "test_key"))
            .respond_with(ResponseTemplate::new(200).set_body_json(&response_body))
            .mount(&mock_server)
            .await;

        let client = Client::new_with_base_url("test_key", &mock_server.uri());
        let domain_client = client.domains();

        let result = domain_client
            .get_with_relationships("example.com", &["subdomains"])
            .await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_domain_get_subdomains() {
        let mock_server = MockServer::start().await;

        let response_body = json!({
            "data": [],
            "meta": {
                "count": 0
            }
        });

        Mock::given(method("GET"))
            .and(path("/domains/example.com/subdomains"))
            .and(header("x-apikey", "test_key"))
            .respond_with(ResponseTemplate::new(200).set_body_json(&response_body))
            .mount(&mock_server)
            .await;

        let client = Client::new_with_base_url("test_key", &mock_server.uri());
        let domain_client = client.domains();

        let result = domain_client.get_subdomains("example.com").await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_domain_get_urls() {
        let mock_server = MockServer::start().await;

        let response_body = json!({
            "data": [],
            "meta": {
                "count": 0
            }
        });

        Mock::given(method("GET"))
            .and(path("/domains/example.com/urls"))
            .and(header("x-apikey", "test_key"))
            .respond_with(ResponseTemplate::new(200).set_body_json(&response_body))
            .mount(&mock_server)
            .await;

        let client = Client::new_with_base_url("test_key", &mock_server.uri());
        let domain_client = client.domains();

        let result = domain_client.get_urls("example.com").await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_domain_get_resolutions() {
        let mock_server = MockServer::start().await;

        let response_body = json!({
            "data": [],
            "meta": {
                "count": 0
            }
        });

        Mock::given(method("GET"))
            .and(path("/domains/example.com/resolutions"))
            .and(header("x-apikey", "test_key"))
            .respond_with(ResponseTemplate::new(200).set_body_json(&response_body))
            .mount(&mock_server)
            .await;

        let client = Client::new_with_base_url("test_key", &mock_server.uri());
        let domain_client = client.domains();

        let result = domain_client.get_resolutions("example.com").await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_domain_get_communicating_files() {
        let mock_server = MockServer::start().await;

        let response_body = json!({
            "data": [],
            "meta": {
                "count": 0
            }
        });

        Mock::given(method("GET"))
            .and(path("/domains/example.com/communicating_files"))
            .and(header("x-apikey", "test_key"))
            .respond_with(ResponseTemplate::new(200).set_body_json(&response_body))
            .mount(&mock_server)
            .await;

        let client = Client::new_with_base_url("test_key", &mock_server.uri());
        let domain_client = client.domains();

        let result = domain_client.get_communicating_files("example.com").await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_domain_get_downloaded_files() {
        let mock_server = MockServer::start().await;

        let response_body = json!({
            "data": [],
            "meta": {
                "count": 0
            }
        });

        Mock::given(method("GET"))
            .and(path("/domains/example.com/downloaded_files"))
            .and(header("x-apikey", "test_key"))
            .respond_with(ResponseTemplate::new(200).set_body_json(&response_body))
            .mount(&mock_server)
            .await;

        let client = Client::new_with_base_url("test_key", &mock_server.uri());
        let domain_client = client.domains();

        let result = domain_client.get_downloaded_files("example.com").await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_domain_get_referrer_files() {
        let mock_server = MockServer::start().await;

        let response_body = json!({
            "data": [],
            "meta": {
                "count": 0
            }
        });

        Mock::given(method("GET"))
            .and(path("/domains/example.com/referrer_files"))
            .and(header("x-apikey", "test_key"))
            .respond_with(ResponseTemplate::new(200).set_body_json(&response_body))
            .mount(&mock_server)
            .await;

        let client = Client::new_with_base_url("test_key", &mock_server.uri());
        let domain_client = client.domains();

        let result = domain_client.get_referrer_files("example.com").await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_domain_get_parent() {
        let mock_server = MockServer::start().await;

        let response_body = json!({
            "data": {
                "type": "domain",
                "id": "parent.com"
            }
        });

        Mock::given(method("GET"))
            .and(path("/domains/example.com/parent"))
            .and(header("x-apikey", "test_key"))
            .respond_with(ResponseTemplate::new(200).set_body_json(&response_body))
            .mount(&mock_server)
            .await;

        let client = Client::new_with_base_url("test_key", &mock_server.uri());
        let domain_client = client.domains();

        let result = domain_client.get_parent("example.com").await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_domain_get_siblings() {
        let mock_server = MockServer::start().await;

        let response_body = json!({
            "data": [],
            "meta": {
                "count": 0
            }
        });

        Mock::given(method("GET"))
            .and(path("/domains/example.com/siblings"))
            .and(header("x-apikey", "test_key"))
            .respond_with(ResponseTemplate::new(200).set_body_json(&response_body))
            .mount(&mock_server)
            .await;

        let client = Client::new_with_base_url("test_key", &mock_server.uri());
        let domain_client = client.domains();

        let result = domain_client.get_siblings("example.com").await;
        assert!(result.is_ok());
    }
}

#[cfg(test)]
mod ip_addresses_async_tests {
    use super::*;
    #[allow(unused_imports)]
    use crate::ip_addresses::IpAddressClient;

    #[tokio::test]
    async fn test_ip_client_get() {
        let mock_server = MockServer::start().await;

        let response_body = json!({
            "data": {
                "type": "ip_address",
                "id": "192.168.1.1",
                "attributes": {
                    "country": "US",
                    "continent": "NA",
                    "asn": 12345
                }
            }
        });

        Mock::given(method("GET"))
            .and(path("/ip_addresses/192.168.1.1"))
            .and(header("x-apikey", "test_key"))
            .respond_with(ResponseTemplate::new(200).set_body_json(&response_body))
            .mount(&mock_server)
            .await;

        let client = Client::new_with_base_url("test_key", &mock_server.uri());
        let ip_client = client.ip_addresses();

        let result = ip_client.get("192.168.1.1").await;
        assert!(result.is_ok());
        let ip = result.unwrap();
        assert_eq!(ip.object.id, "192.168.1.1");
    }

    #[tokio::test]
    async fn test_ip_client_get_with_relationships() {
        let mock_server = MockServer::start().await;

        let response_body = json!({
            "data": {
                "type": "ip_address",
                "id": "192.168.1.1",
                "attributes": {
                    "country": "US"
                },
                "relationships": {
                    "urls": {
                        "data": []
                    }
                }
            }
        });

        Mock::given(method("GET"))
            .and(path("/ip_addresses/192.168.1.1"))
            .and(header("x-apikey", "test_key"))
            .respond_with(ResponseTemplate::new(200).set_body_json(&response_body))
            .mount(&mock_server)
            .await;

        let client = Client::new_with_base_url("test_key", &mock_server.uri());
        let ip_client = client.ip_addresses();

        let result = ip_client
            .get_with_relationships("192.168.1.1", &["urls"])
            .await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_ip_get_urls() {
        let mock_server = MockServer::start().await;

        let response_body = json!({
            "data": [],
            "meta": {
                "count": 0
            }
        });

        Mock::given(method("GET"))
            .and(path("/ip_addresses/192.168.1.1/urls"))
            .and(header("x-apikey", "test_key"))
            .respond_with(ResponseTemplate::new(200).set_body_json(&response_body))
            .mount(&mock_server)
            .await;

        let client = Client::new_with_base_url("test_key", &mock_server.uri());
        let ip_client = client.ip_addresses();

        let result = ip_client.get_urls("192.168.1.1").await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_ip_get_resolutions() {
        let mock_server = MockServer::start().await;

        let response_body = json!({
            "data": [],
            "meta": {
                "count": 0
            }
        });

        Mock::given(method("GET"))
            .and(path("/ip_addresses/192.168.1.1/resolutions"))
            .and(header("x-apikey", "test_key"))
            .respond_with(ResponseTemplate::new(200).set_body_json(&response_body))
            .mount(&mock_server)
            .await;

        let client = Client::new_with_base_url("test_key", &mock_server.uri());
        let ip_client = client.ip_addresses();

        let result = ip_client.get_resolutions("192.168.1.1").await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_ip_get_communicating_files() {
        let mock_server = MockServer::start().await;

        let response_body = json!({
            "data": [],
            "meta": {
                "count": 0
            }
        });

        Mock::given(method("GET"))
            .and(path("/ip_addresses/192.168.1.1/communicating_files"))
            .and(header("x-apikey", "test_key"))
            .respond_with(ResponseTemplate::new(200).set_body_json(&response_body))
            .mount(&mock_server)
            .await;

        let client = Client::new_with_base_url("test_key", &mock_server.uri());
        let ip_client = client.ip_addresses();

        let result = ip_client.get_communicating_files("192.168.1.1").await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_ip_get_downloaded_files() {
        let mock_server = MockServer::start().await;

        let response_body = json!({
            "data": [],
            "meta": {
                "count": 0
            }
        });

        Mock::given(method("GET"))
            .and(path("/ip_addresses/192.168.1.1/downloaded_files"))
            .and(header("x-apikey", "test_key"))
            .respond_with(ResponseTemplate::new(200).set_body_json(&response_body))
            .mount(&mock_server)
            .await;

        let client = Client::new_with_base_url("test_key", &mock_server.uri());
        let ip_client = client.ip_addresses();

        let result = ip_client.get_downloaded_files("192.168.1.1").await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_ip_get_referrer_files() {
        let mock_server = MockServer::start().await;

        let response_body = json!({
            "data": [],
            "meta": {
                "count": 0
            }
        });

        Mock::given(method("GET"))
            .and(path("/ip_addresses/192.168.1.1/referrer_files"))
            .and(header("x-apikey", "test_key"))
            .respond_with(ResponseTemplate::new(200).set_body_json(&response_body))
            .mount(&mock_server)
            .await;

        let client = Client::new_with_base_url("test_key", &mock_server.uri());
        let ip_client = client.ip_addresses();

        let result = ip_client.get_referrer_files("192.168.1.1").await;
        assert!(result.is_ok());
    }
}

#[cfg(test)]
mod collection_iterator_tests {
    use super::*;
    use crate::objects::CollectionIterator;

    #[tokio::test]
    async fn test_collection_iterator_next_batch() {
        let mock_server = MockServer::start().await;

        let response_body = json!({
            "data": ["item1", "item2"],
            "meta": {
                "cursor": "next_cursor"
            }
        });

        Mock::given(method("GET"))
            .and(path("/test_url"))
            .and(header("x-apikey", "test_key"))
            .respond_with(ResponseTemplate::new(200).set_body_json(&response_body))
            .mount(&mock_server)
            .await;

        let client = Client::new_with_base_url("test_key", &mock_server.uri());
        let mut iterator = CollectionIterator::<String>::new(&client, "/test_url");

        let batch = iterator.next_batch().await;
        assert!(batch.is_ok());
        let items = batch.unwrap();
        assert_eq!(items.len(), 2);
    }

    #[tokio::test]
    async fn test_collection_iterator_with_limit() {
        let mock_server = MockServer::start().await;

        let response_body = json!({
            "data": ["item1", "item2"],
            "meta": {
                "cursor": null
            }
        });

        Mock::given(method("GET"))
            .and(path("/test_url"))
            .and(header("x-apikey", "test_key"))
            .respond_with(ResponseTemplate::new(200).set_body_json(&response_body))
            .mount(&mock_server)
            .await;

        let client = Client::new_with_base_url("test_key", &mock_server.uri());
        let mut iterator = CollectionIterator::<String>::new(&client, "/test_url").with_limit(10);

        let batch = iterator.next_batch().await;
        assert!(batch.is_ok());
    }

    #[tokio::test]
    async fn test_collection_iterator_collect_all() {
        let mock_server = MockServer::start().await;

        // First response with cursor
        let response1 = json!({
            "data": ["item1", "item2"],
            "meta": {
                "cursor": "cursor1"
            }
        });

        // Second response without cursor (last page)
        let response2 = json!({
            "data": ["item3"],
            "meta": {
                "cursor": null
            }
        });

        // Mock for second request (with cursor parameter) - mount this first to avoid conflicts
        Mock::given(method("GET"))
            .and(path("/test_url"))
            .and(query_param("cursor", "cursor1"))
            .and(header("x-apikey", "test_key"))
            .respond_with(ResponseTemplate::new(200).set_body_json(&response2))
            .expect(1)
            .mount(&mock_server)
            .await;

        // Mock for first request (no cursor parameter)
        Mock::given(method("GET"))
            .and(path("/test_url"))
            .and(header("x-apikey", "test_key"))
            .respond_with(ResponseTemplate::new(200).set_body_json(&response1))
            .expect(1)
            .mount(&mock_server)
            .await;

        let client = Client::new_with_base_url("test_key", &mock_server.uri());
        let iterator = CollectionIterator::<String>::new(&client, "/test_url");

        let all_items = iterator.collect_all().await;
        assert!(all_items.is_ok());
        let items = all_items.unwrap();
        assert_eq!(items.len(), 3);
        assert_eq!(items, vec!["item1", "item2", "item3"]);
    }
}

#[cfg(test)]
mod file_behaviours_async_tests {
    use super::*;
    #[allow(unused_imports)]
    use crate::file_behaviours::FileBehaviourClient;

    #[tokio::test]
    async fn test_file_behaviour_client_get() {
        let mock_server = MockServer::start().await;

        let response_body = json!({
            "data": {
                "type": "file_behaviour",
                "id": "test_sandbox_id",
                "attributes": {
                    "analysis_date": 1234567890,
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
            .and(header("x-apikey", "test_key"))
            .respond_with(ResponseTemplate::new(200).set_body_json(&response_body))
            .mount(&mock_server)
            .await;

        let client = Client::new_with_base_url("test_key", &mock_server.uri());
        let behaviour_client = client.file_behaviours();

        let result = behaviour_client.get("test_sandbox_id").await;
        assert!(result.is_ok());
        let behaviour = result.unwrap();
        assert_eq!(behaviour.object.id, "test_sandbox_id");
    }

    #[tokio::test]
    async fn test_file_behaviour_get_relationship() {
        let mock_server = MockServer::start().await;

        let response_body = json!({
            "data": [
                {
                    "type": "domain",
                    "id": "example.com"
                }
            ],
            "meta": {
                "count": 1
            }
        });

        Mock::given(method("GET"))
            .and(path("/file_behaviours/test_sandbox_id/contacted_domains"))
            .and(header("x-apikey", "test_key"))
            .respond_with(ResponseTemplate::new(200).set_body_json(&response_body))
            .mount(&mock_server)
            .await;

        let client = Client::new_with_base_url("test_key", &mock_server.uri());
        let behaviour_client = client.file_behaviours();

        let result = behaviour_client
            .get_contacted_domains("test_sandbox_id")
            .await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_file_behaviour_get_relationship_descriptors() {
        let mock_server = MockServer::start().await;

        let response_body = json!({
            "data": [
                {
                    "type": "domain",
                    "id": "example.com"
                }
            ]
        });

        Mock::given(method("GET"))
            .and(path(
                "/file_behaviours/test_sandbox_id/relationships/contacted_domains",
            ))
            .and(header("x-apikey", "test_key"))
            .respond_with(ResponseTemplate::new(200).set_body_json(&response_body))
            .mount(&mock_server)
            .await;

        let client = Client::new_with_base_url("test_key", &mock_server.uri());
        let behaviour_client = client.file_behaviours();

        let result = behaviour_client
            .get_relationship_descriptors("test_sandbox_id", "contacted_domains")
            .await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_file_behaviour_get_html_report() {
        let mock_server = MockServer::start().await;

        let html_report = "<html><body><h1>Sandbox Report</h1></body></html>";

        Mock::given(method("GET"))
            .and(path("/file_behaviours/test_sandbox_id/html"))
            .and(header("x-apikey", "test_key"))
            .respond_with(ResponseTemplate::new(200).set_body_string(html_report))
            .mount(&mock_server)
            .await;

        let client = Client::new_with_base_url("test_key", &mock_server.uri());
        let behaviour_client = client.file_behaviours();

        let result = behaviour_client.get_html_report("test_sandbox_id").await;
        assert!(result.is_ok());
        let html = result.unwrap();
        assert!(html.contains("Sandbox Report"));
    }

    #[tokio::test]
    async fn test_file_behaviour_get_evtx() {
        let mock_server = MockServer::start().await;

        let evtx_data = vec![0x45, 0x6C, 0x66, 0x46, 0x69, 0x6C, 0x65]; // Mock EVTX binary data

        Mock::given(method("GET"))
            .and(path("/file_behaviours/test_sandbox_id/evtx"))
            .and(header("x-apikey", "test_key"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(evtx_data.clone()))
            .mount(&mock_server)
            .await;

        let client = Client::new_with_base_url("test_key", &mock_server.uri());
        let behaviour_client = client.file_behaviours();

        let result = behaviour_client.get_evtx("test_sandbox_id").await;
        assert!(result.is_ok());
        let data = result.unwrap();
        assert_eq!(data, evtx_data);
    }

    #[tokio::test]
    async fn test_file_behaviour_get_pcap() {
        let mock_server = MockServer::start().await;

        // Mock PCAP file header (libpcap format)
        let pcap_data = vec![
            0xD4, 0xC3, 0xB2, 0xA1, // Magic number (little-endian)
            0x02, 0x00, 0x04, 0x00, // Version major/minor
            0x00, 0x00, 0x00, 0x00, // Timezone offset
            0x00, 0x00, 0x00, 0x00, // Timestamp accuracy
            0xFF, 0xFF, 0x00, 0x00, // Max packet length
            0x01, 0x00, 0x00, 0x00, // Data link type (Ethernet)
        ];

        Mock::given(method("GET"))
            .and(path("/file_behaviours/test_sandbox_id/pcap"))
            .and(header("x-apikey", "test_key"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(pcap_data.clone()))
            .mount(&mock_server)
            .await;

        let client = Client::new_with_base_url("test_key", &mock_server.uri());
        let behaviour_client = client.file_behaviours();

        let result = behaviour_client.get_pcap("test_sandbox_id").await;
        assert!(result.is_ok());
        let data = result.unwrap();
        assert_eq!(data, pcap_data);
        // Verify PCAP magic number
        assert_eq!(&data[0..4], &[0xD4, 0xC3, 0xB2, 0xA1]);
    }

    #[tokio::test]
    async fn test_file_behaviour_get_memdump() {
        let mock_server = MockServer::start().await;

        // Mock memory dump data (simplified)
        let memdump_data = vec![
            0x4D, 0x5A, 0x90, 0x00, // PE header start (MZ signature)
            0x03, 0x00, 0x00, 0x00, // Bytes on last page
            0x04, 0x00, 0x00, 0x00, // Pages in file
            0x00, 0x00, 0x00, 0x00, // Relocations
        ];

        Mock::given(method("GET"))
            .and(path("/file_behaviours/test_sandbox_id/memdump"))
            .and(header("x-apikey", "test_key"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(memdump_data.clone()))
            .mount(&mock_server)
            .await;

        let client = Client::new_with_base_url("test_key", &mock_server.uri());
        let behaviour_client = client.file_behaviours();

        let result = behaviour_client.get_memdump("test_sandbox_id").await;
        assert!(result.is_ok());
        let data = result.unwrap();
        assert_eq!(data, memdump_data);
        // Verify PE signature
        assert_eq!(&data[0..2], &[0x4D, 0x5A]); // "MZ" signature
    }

    #[tokio::test]
    async fn test_file_behaviour_special_privileges_endpoints() {
        let mock_server = MockServer::start().await;

        // Test error response for endpoints requiring special privileges
        let error_response = json!({
            "error": {
                "code": "ForbiddenError",
                "message": "This endpoint requires special privileges"
            }
        });

        let endpoints = ["evtx", "pcap", "memdump"];

        for endpoint in &endpoints {
            Mock::given(method("GET"))
                .and(path(format!(
                    "/file_behaviours/test_sandbox_id/{}",
                    endpoint
                )))
                .and(header("x-apikey", "test_key"))
                .respond_with(ResponseTemplate::new(403).set_body_json(&error_response))
                .mount(&mock_server)
                .await;
        }

        let client = Client::new_with_base_url("test_key", &mock_server.uri());
        let behaviour_client = client.file_behaviours();

        // Test that all privileged endpoints return appropriate errors
        let evtx_result = behaviour_client.get_evtx("test_sandbox_id").await;
        assert!(evtx_result.is_err());

        let pcap_result = behaviour_client.get_pcap("test_sandbox_id").await;
        assert!(pcap_result.is_err());

        let memdump_result = behaviour_client.get_memdump("test_sandbox_id").await;
        assert!(memdump_result.is_err());
    }

    #[tokio::test]
    async fn test_file_behaviour_convenience_methods() {
        let mock_server = MockServer::start().await;

        let response_body = json!({
            "data": [],
            "meta": {
                "count": 0
            }
        });

        // Set up mocks for all convenience methods
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
                .and(header("x-apikey", "test_key"))
                .respond_with(ResponseTemplate::new(200).set_body_json(&response_body))
                .mount(&mock_server)
                .await;
        }

        let client = Client::new_with_base_url("test_key", &mock_server.uri());
        let behaviour_client = client.file_behaviours();

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
        let mock_server = MockServer::start().await;

        let response_body = json!({
            "data": ["item1", "item2"],
            "meta": {
                "cursor": null
            }
        });

        Mock::given(method("GET"))
            .and(path("/file_behaviours/test_sandbox_id/contacted_domains"))
            .and(header("x-apikey", "test_key"))
            .respond_with(ResponseTemplate::new(200).set_body_json(&response_body))
            .mount(&mock_server)
            .await;

        let client = Client::new_with_base_url("test_key", &mock_server.uri());
        let behaviour_client = client.file_behaviours();

        let mut iterator = behaviour_client
            .get_relationship_iterator::<String>("test_sandbox_id", "contacted_domains");
        let batch = iterator.next_batch().await;
        assert!(batch.is_ok());
    }
}

// Helper to create client with custom base URL
impl Client {
    fn new_with_base_url(api_key: &str, base_url: &str) -> Self {
        use crate::client::ClientBuilder;
        ClientBuilder::new()
            .api_key(api_key)
            .base_url(base_url)
            .build()
            .unwrap()
    }
}
