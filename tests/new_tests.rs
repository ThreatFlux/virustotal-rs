use serde_json::json;
use std::time::Duration;
use virustotal_rs::{ApiTier, ClientBuilder};
use wiremock::matchers::{header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

// Test utility macros (defined in src/tests/test_macros.rs but not exported)
macro_rules! setup_test_client {
    () => {{
        setup_test_client!("test_key", virustotal_rs::ApiTier::Public)
    }};
    ($api_key:expr, $tier:expr) => {{
        let mock_server = MockServer::start().await;
        let client = ClientBuilder::new()
            .api_key($api_key)
            .tier($tier)
            .base_url(mock_server.uri())
            .timeout(Duration::from_secs(5))
            .build()
            .unwrap();
        (mock_server, client)
    }};
}

macro_rules! setup_mock_http {
    ($server:expr, $method:expr, $path:expr, $status:expr, $response:expr) => {{
        Mock::given(method($method))
            .and(path($path))
            .and(header("x-apikey", "test_key"))
            .respond_with(ResponseTemplate::new($status).set_body_json($response))
            .mount($server)
            .await;
    }};
}

macro_rules! create_analysis_response {
    ($id:expr) => {{
        serde_json::json!({
            "data": {
                "type": "analysis",
                "id": $id,
                "links": {
                    "self": format!("https://www.virustotal.com/api/v3/analyses/{}", $id)
                }
            }
        })
    }};
}

macro_rules! create_comment_response {
    ($id:expr, $text:expr) => {{
        serde_json::json!({
            "data": {
                "type": "comment",
                "id": $id,
                "attributes": {
                    "text": $text,
                    "date": 1234567890,
                    "votes": {
                        "positive": 5,
                        "negative": 1,
                        "abuse": 0
                    }
                }
            }
        })
    }};
}

macro_rules! create_collection_response {
    ($data:expr) => {{
        create_collection_response!($data, None::<String>)
    }};
    ($data:expr, $cursor:expr) => {{
        let data_json = serde_json::json!($data);
        let count = if let Some(arr) = data_json.as_array() { arr.len() } else { 1 };
        let mut response = serde_json::json!({
            "data": data_json,
            "meta": { "count": count }
        });

        if let Some(cursor) = $cursor {
            response["links"] = serde_json::json!({
                "self": "https://api.example.com/test",
                "next": format!("https://api.example.com/test?cursor={}", cursor)
            });
        } else {
            response["links"] = serde_json::json!({
                "self": "https://api.example.com/test"
            });
        }
        response
    }};
}

#[tokio::test]
async fn test_ip_address_analyse() {
    let (mock_server, client) = setup_test_client!();

    let analysis_response = create_analysis_response!("i-abc123-1234567890");

    setup_mock_http!(
        &mock_server,
        "POST",
        "/ip_addresses/8.8.8.8/analyse",
        200,
        &analysis_response
    );

    let result = client.ip_addresses().analyse("8.8.8.8").await.unwrap();
    assert_eq!(result.data.object_type, "analysis");
    assert_eq!(result.data.id, "i-abc123-1234567890");
}

#[tokio::test]
async fn test_ip_address_add_comment() {
    let (mock_server, client) = setup_test_client!();

    let comment_response = create_comment_response!("c-123456", "This IP looks suspicious");

    setup_mock_http!(
        &mock_server,
        "POST",
        "/ip_addresses/1.2.3.4/comments",
        200,
        &comment_response
    );

    let comment = client
        .ip_addresses()
        .add_comment("1.2.3.4", "This IP looks suspicious")
        .await
        .unwrap();

    assert_eq!(comment.object.object_type, "comment");
    assert_eq!(comment.object.attributes.text, "This IP looks suspicious");
}

#[tokio::test]
async fn test_ip_address_get_comments_with_pagination() {
    let (mock_server, client) = setup_test_client!();

    let comment1 = json!({
        "type": "comment",
        "id": "c-1",
        "attributes": {
            "text": "First comment",
            "date": 1234567890
        }
    });

    let comment2 = json!({
        "type": "comment",
        "id": "c-2",
        "attributes": {
            "text": "Second comment",
            "date": 1234567891
        }
    });

    let comments_response =
        create_collection_response!(vec![comment1, comment2], Some("next_page"));

    setup_mock_http!(
        &mock_server,
        "GET",
        "/ip_addresses/8.8.8.8/comments",
        200,
        &comments_response
    );

    let comments = client.ip_addresses().get_comments("8.8.8.8").await.unwrap();

    assert_eq!(comments.data.len(), 2);
    assert_eq!(comments.data[0].object.attributes.text, "First comment");
}

// Removed redundant helper functions - now using macros instead

#[tokio::test]
async fn test_comment_iterator() {
    let (mock_server, _client) = setup_test_client!();

    let comment1 = json!({"type": "comment", "id": "c-1", "attributes": {"text": "Comment 1", "date": 1234567890}});
    let comment2 = json!({"type": "comment", "id": "c-2", "attributes": {"text": "Comment 2", "date": 1234567891}});

    let page1 = create_collection_response!(vec![comment1], Some("page2"));
    let page2 = create_collection_response!(vec![comment2]);

    setup_mock_http!(
        &mock_server,
        "GET",
        "/ip_addresses/8.8.8.8/comments",
        200,
        &page1
    );

    use wiremock::{
        matchers::{header, method, path},
        Mock, ResponseTemplate,
    };
    Mock::given(method("GET"))
        .and(path("/ip_addresses/8.8.8.8/comments"))
        .respond_with(ResponseTemplate::new(200).set_body_json(&page2))
        .mount(&mock_server)
        .await;

    let client = ClientBuilder::new()
        .api_key("test_key")
        .tier(ApiTier::Public)
        .base_url(mock_server.uri())
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap();
    let ip_client = client.ip_addresses();
    let mut iterator = ip_client.get_comments_iterator("8.8.8.8").await;

    let batch1 = iterator.next_batch().await.unwrap();
    assert_eq!(batch1.len(), 1);
    assert_eq!(batch1[0].object.attributes.text, "Comment 1");
}
