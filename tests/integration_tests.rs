use serde_json::json;
use std::time::Duration;
use virustotal_rs::{ApiTier, ClientBuilder};
use wiremock::matchers::{header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

/// Helper function to create sample IP response
fn create_sample_ip_response() -> serde_json::Value {
    json!({
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
    })
}

/// Test configuration constants
const TEST_API_KEY: &str = "test_key";
const TEST_IP: &str = "8.8.8.8";

/// Helper function to create test client
async fn create_test_client(mock_server: &MockServer) -> virustotal_rs::Client {
    create_test_client_with_tier(mock_server, ApiTier::Public).await
}

/// Helper function to create test client with custom tier
async fn create_test_client_with_tier(
    mock_server: &MockServer,
    tier: ApiTier,
) -> virustotal_rs::Client {
    ClientBuilder::new()
        .api_key(TEST_API_KEY)
        .tier(tier)
        .base_url(mock_server.uri())
        .timeout(Duration::from_secs(10))
        .build()
        .unwrap()
}

/// Helper to setup basic mock server and client
async fn setup_test_environment() -> (MockServer, virustotal_rs::Client) {
    let mock_server = MockServer::start().await;
    let client = create_test_client(&mock_server).await;
    (mock_server, client)
}

/// Helper to create mock with standard response
fn create_mock_response(status: u16, body: &serde_json::Value) -> ResponseTemplate {
    ResponseTemplate::new(status)
        .set_body_json(body)
        .append_header("Content-Type", "application/json")
}

/// Helper to mount a GET mock for a specific path
async fn mount_get_mock(
    mock_server: &MockServer,
    endpoint_path: &str,
    response: serde_json::Value,
) {
    Mock::given(method("GET"))
        .and(path(endpoint_path))
        .and(header("x-apikey", TEST_API_KEY))
        .respond_with(create_mock_response(200, &response))
        .mount(mock_server)
        .await;
}

/// Helper to mount a POST mock for a specific path
async fn mount_post_mock(
    mock_server: &MockServer,
    endpoint_path: &str,
    response: serde_json::Value,
) {
    Mock::given(method("POST"))
        .and(path(endpoint_path))
        .and(header("x-apikey", TEST_API_KEY))
        .respond_with(create_mock_response(200, &response))
        .mount(mock_server)
        .await;
}

#[tokio::test]
async fn test_ip_address_get() {
    let (mock_server, client) = setup_test_environment().await;
    let ip_response = create_sample_ip_response();
    let endpoint = format!("/ip_addresses/{}", TEST_IP);

    mount_get_mock(&mock_server, &endpoint, ip_response).await;

    let ip = client.ip_addresses().get(TEST_IP).await.unwrap();

    assert_eq!(ip.object.id, TEST_IP);
    assert_eq!(ip.object.object_type, "ip_address");
    assert_eq!(ip.object.attributes.asn, Some(15169));
    assert_eq!(
        ip.object.attributes.as_owner,
        Some("Google LLC".to_string())
    );
    assert_eq!(ip.object.attributes.country, Some("US".to_string()));
}

/// Helper to create IP response with relationships
fn create_ip_response_with_relationships() -> serde_json::Value {
    json!({
        "data": {
            "type": "ip_address",
            "id": TEST_IP,
            "links": {
                "self": format!("https://www.virustotal.com/api/v3/ip_addresses/{}", TEST_IP)
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
                            "id": format!("{}-dns.google", TEST_IP)
                        }
                    ],
                    "links": {
                        "self": format!("https://www.virustotal.com/api/v3/ip_addresses/{}/relationships/resolutions", TEST_IP)
                    }
                }
            }
        }
    })
}

#[tokio::test]
async fn test_ip_address_with_relationships() {
    let (mock_server, client) = setup_test_environment().await;
    let ip_response = create_ip_response_with_relationships();
    let endpoint = format!("/ip_addresses/{}", TEST_IP);

    mount_get_mock(&mock_server, &endpoint, ip_response).await;

    let ip = client
        .ip_addresses()
        .get_with_relationships(TEST_IP, &["resolutions"])
        .await
        .unwrap();

    assert!(ip.object.relationships.is_some());
}

/// Helper to create paginated collection response
fn create_paginated_response(
    items: Vec<serde_json::Value>,
    cursor: Option<&str>,
) -> serde_json::Value {
    let mut response = json!({
        "data": items,
        "meta": {},
        "links": {
            "self": format!("https://www.virustotal.com/api/v3/ip_addresses/{}/urls", TEST_IP)
        }
    });

    if let Some(cursor_value) = cursor {
        response["meta"]["cursor"] = json!(cursor_value);
        response["links"]["next"] = json!(format!(
            "https://www.virustotal.com/api/v3/ip_addresses/{}/urls?cursor={}",
            TEST_IP, cursor_value
        ));
    }

    response
}

#[tokio::test]
async fn test_collection_pagination() {
    let (mock_server, client) = setup_test_environment().await;
    let endpoint = format!("/ip_addresses/{}/urls", TEST_IP);

    let page1_items = vec![
        json!({"type": "url", "id": "url1"}),
        json!({"type": "url", "id": "url2"}),
    ];
    let page1_response = create_paginated_response(page1_items, Some("next_cursor"));

    let page2_items = vec![json!({"type": "url", "id": "url3"})];
    let page2_response = create_paginated_response(page2_items, None);

    // Mount both responses (wiremock will handle the sequence)
    mount_get_mock(&mock_server, &endpoint, page1_response).await;
    mount_get_mock(&mock_server, &endpoint, page2_response).await;

    let collection = client.ip_addresses().get_urls(TEST_IP).await.unwrap();

    assert_eq!(collection.data.len(), 2);
}

/// Helper to create vote response
fn create_vote_response(verdict: &str) -> serde_json::Value {
    json!({
        "data": {
            "type": "vote",
            "id": "v-test",
            "attributes": {
                "verdict": verdict
            }
        }
    })
}

#[tokio::test]
async fn test_add_vote() {
    let (mock_server, client) = setup_test_environment().await;
    let vote_response = create_vote_response("harmless");
    let endpoint = format!("/ip_addresses/{}/votes", TEST_IP);

    mount_post_mock(&mock_server, &endpoint, vote_response).await;

    let result = client
        .ip_addresses()
        .add_vote(TEST_IP, virustotal_rs::VoteVerdict::Harmless)
        .await;

    assert!(result.is_ok());
}

/// Helper to create collection iterator response
fn create_iterator_response() -> serde_json::Value {
    json!({
        "data": [
            {"type": "file", "id": "file1"},
            {"type": "file", "id": "file2"}
        ],
        "meta": {
            "cursor": "cursor123"
        }
    })
}

#[tokio::test]
async fn test_collection_iterator() {
    use virustotal_rs::CollectionIterator;

    let (mock_server, client) = setup_test_environment().await;
    let response = create_iterator_response();

    mount_get_mock(&mock_server, "/test", response).await;

    let mut iterator = CollectionIterator::<serde_json::Value>::new(&client, "test").with_limit(10);

    let batch = iterator.next_batch().await.unwrap();
    assert_eq!(batch.len(), 2);
}
