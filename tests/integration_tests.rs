use serde_json::json;
use virustotal_rs::{ApiTier, ClientBuilder};
use wiremock::matchers::{header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

#[tokio::test]
async fn test_ip_address_get() {
    let mock_server = MockServer::start().await;

    let ip_response = json!({
        "data": {
            "type": "ip_address",
            "id": "8.8.8.8",
            "links": {
                "self": "https://www.virustotal.com/api/v3/ip_addresses/8.8.8.8"
            },
            "attributes": {
                "asn": 15169,
                "as_owner": "Google LLC",
                "country": "US",
                "continent": "NA",
                "network": "8.8.8.0/24",
                "reputation": 0,
                "harmless": 85,
                "malicious": 0,
                "suspicious": 0,
                "undetected": 15,
                "last_analysis_stats": {
                    "harmless": 85,
                    "malicious": 0,
                    "suspicious": 0,
                    "undetected": 15,
                    "timeout": 0
                }
            }
        }
    });

    Mock::given(method("GET"))
        .and(path("/ip_addresses/8.8.8.8"))
        .and(header("x-apikey", "test_key"))
        .respond_with(ResponseTemplate::new(200).set_body_json(&ip_response))
        .mount(&mock_server)
        .await;

    let client = ClientBuilder::new()
        .api_key("test_key")
        .tier(ApiTier::Public)
        .base_url(mock_server.uri())
        .build()
        .unwrap();

    let ip = client.ip_addresses().get("8.8.8.8").await.unwrap();

    assert_eq!(ip.object.id, "8.8.8.8");
    assert_eq!(ip.object.object_type, "ip_address");
    assert_eq!(ip.object.attributes.asn, Some(15169));
    assert_eq!(
        ip.object.attributes.as_owner,
        Some("Google LLC".to_string())
    );
    assert_eq!(ip.object.attributes.country, Some("US".to_string()));
}

#[tokio::test]
async fn test_ip_address_with_relationships() {
    let mock_server = MockServer::start().await;

    let ip_response = json!({
        "data": {
            "type": "ip_address",
            "id": "8.8.8.8",
            "links": {
                "self": "https://www.virustotal.com/api/v3/ip_addresses/8.8.8.8"
            },
            "attributes": {
                "asn": 15169,
                "as_owner": "Google LLC"
            },
            "relationships": {
                "resolutions": {
                    "data": [
                        {
                            "type": "resolution",
                            "id": "8.8.8.8-dns.google"
                        }
                    ],
                    "links": {
                        "self": "https://www.virustotal.com/api/v3/ip_addresses/8.8.8.8/relationships/resolutions"
                    }
                }
            }
        }
    });

    Mock::given(method("GET"))
        .and(path("/ip_addresses/8.8.8.8"))
        .respond_with(ResponseTemplate::new(200).set_body_json(&ip_response))
        .mount(&mock_server)
        .await;

    let client = ClientBuilder::new()
        .api_key("test_key")
        .tier(ApiTier::Public)
        .base_url(mock_server.uri())
        .build()
        .unwrap();

    let ip = client
        .ip_addresses()
        .get_with_relationships("8.8.8.8", &["resolutions"])
        .await
        .unwrap();

    assert!(ip.object.relationships.is_some());
}

#[tokio::test]
async fn test_collection_pagination() {
    let mock_server = MockServer::start().await;

    let page1_response = json!({
        "data": [
            {"type": "url", "id": "url1"},
            {"type": "url", "id": "url2"}
        ],
        "meta": {
            "cursor": "next_cursor"
        },
        "links": {
            "self": "https://www.virustotal.com/api/v3/ip_addresses/8.8.8.8/urls",
            "next": "https://www.virustotal.com/api/v3/ip_addresses/8.8.8.8/urls?cursor=next_cursor"
        }
    });

    let page2_response = json!({
        "data": [
            {"type": "url", "id": "url3"}
        ],
        "meta": {},
        "links": {
            "self": "https://www.virustotal.com/api/v3/ip_addresses/8.8.8.8/urls?cursor=next_cursor"
        }
    });

    Mock::given(method("GET"))
        .and(path("/ip_addresses/8.8.8.8/urls"))
        .respond_with(ResponseTemplate::new(200).set_body_json(&page1_response))
        .mount(&mock_server)
        .await;

    Mock::given(method("GET"))
        .and(path("/ip_addresses/8.8.8.8/urls"))
        .respond_with(ResponseTemplate::new(200).set_body_json(&page2_response))
        .mount(&mock_server)
        .await;

    let client = ClientBuilder::new()
        .api_key("test_key")
        .tier(ApiTier::Public)
        .base_url(mock_server.uri())
        .build()
        .unwrap();

    let collection = client.ip_addresses().get_urls("8.8.8.8").await.unwrap();

    assert_eq!(collection.data.len(), 2);
}

#[tokio::test]
async fn test_add_vote() {
    let mock_server = MockServer::start().await;

    let vote_response = json!({
        "data": {
            "type": "vote",
            "id": "v-test",
            "attributes": {
                "verdict": "harmless"
            }
        }
    });

    Mock::given(method("POST"))
        .and(path("/ip_addresses/8.8.8.8/votes"))
        .and(header("x-apikey", "test_key"))
        .respond_with(ResponseTemplate::new(200).set_body_json(&vote_response))
        .mount(&mock_server)
        .await;

    let client = ClientBuilder::new()
        .api_key("test_key")
        .tier(ApiTier::Public)
        .base_url(mock_server.uri())
        .build()
        .unwrap();

    let result = client
        .ip_addresses()
        .add_vote("8.8.8.8", virustotal_rs::VoteVerdict::Harmless)
        .await;

    assert!(result.is_ok());
}

#[tokio::test]
async fn test_collection_iterator() {
    use virustotal_rs::CollectionIterator;

    let mock_server = MockServer::start().await;

    let response = json!({
        "data": [
            {"type": "file", "id": "file1"},
            {"type": "file", "id": "file2"}
        ],
        "meta": {
            "cursor": "cursor123"
        }
    });

    Mock::given(method("GET"))
        .and(path("/test"))
        .respond_with(ResponseTemplate::new(200).set_body_json(&response))
        .mount(&mock_server)
        .await;

    let client = ClientBuilder::new()
        .api_key("test_key")
        .tier(ApiTier::Public)
        .base_url(mock_server.uri())
        .build()
        .unwrap();

    let mut iterator = CollectionIterator::<serde_json::Value>::new(&client, "test").with_limit(10);

    let batch = iterator.next_batch().await.unwrap();
    assert_eq!(batch.len(), 2);
}
