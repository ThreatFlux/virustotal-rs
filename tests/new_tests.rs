use serde_json::json;
use virustotal_rs::{ApiTier, ClientBuilder};
use wiremock::matchers::{header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

#[tokio::test]
async fn test_ip_address_analyse() {
    let mock_server = MockServer::start().await;

    let analysis_response = json!({
        "data": {
            "type": "analysis",
            "id": "i-abc123-1234567890",
            "links": {
                "self": "https://www.virustotal.com/api/v3/analyses/i-abc123-1234567890"
            }
        }
    });

    Mock::given(method("POST"))
        .and(path("/ip_addresses/8.8.8.8/analyse"))
        .and(header("x-apikey", "test_key"))
        .respond_with(ResponseTemplate::new(200).set_body_json(&analysis_response))
        .mount(&mock_server)
        .await;

    let client = ClientBuilder::new()
        .api_key("test_key")
        .tier(ApiTier::Public)
        .base_url(mock_server.uri())
        .build()
        .unwrap();

    let result = client.ip_addresses().analyse("8.8.8.8").await.unwrap();
    assert_eq!(result.data.object_type, "analysis");
    assert_eq!(result.data.id, "i-abc123-1234567890");
}

#[tokio::test]
async fn test_ip_address_add_comment() {
    let mock_server = MockServer::start().await;

    let comment_response = json!({
        "data": {
            "type": "comment",
            "id": "c-123456",
            "attributes": {
                "text": "This IP looks suspicious",
                "date": 1234567890,
                "votes": {
                    "positive": 5,
                    "negative": 1,
                    "abuse": 0
                }
            }
        }
    });

    Mock::given(method("POST"))
        .and(path("/ip_addresses/1.2.3.4/comments"))
        .and(header("x-apikey", "test_key"))
        .respond_with(ResponseTemplate::new(200).set_body_json(&comment_response))
        .mount(&mock_server)
        .await;

    let client = ClientBuilder::new()
        .api_key("test_key")
        .tier(ApiTier::Public)
        .base_url(mock_server.uri())
        .build()
        .unwrap();

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
    let mock_server = MockServer::start().await;

    let comments_response = json!({
        "data": [
            {
                "type": "comment",
                "id": "c-1",
                "attributes": {
                    "text": "First comment",
                    "date": 1234567890
                }
            },
            {
                "type": "comment",
                "id": "c-2",
                "attributes": {
                    "text": "Second comment",
                    "date": 1234567891
                }
            }
        ],
        "meta": {
            "cursor": "next_page"
        }
    });

    Mock::given(method("GET"))
        .and(path("/ip_addresses/8.8.8.8/comments"))
        .respond_with(ResponseTemplate::new(200).set_body_json(&comments_response))
        .mount(&mock_server)
        .await;

    let client = ClientBuilder::new()
        .api_key("test_key")
        .tier(ApiTier::Public)
        .base_url(mock_server.uri())
        .build()
        .unwrap();

    let comments = client.ip_addresses().get_comments("8.8.8.8").await.unwrap();

    assert_eq!(comments.data.len(), 2);
    assert_eq!(comments.data[0].object.attributes.text, "First comment");
}

/// Helper function to create test comment data
fn create_comment_page(
    comment_id: &str,
    text: &str,
    date: i64,
    cursor: Option<&str>,
) -> serde_json::Value {
    let mut page = json!({
        "data": [{
            "type": "comment",
            "id": comment_id,
            "attributes": {
                "text": text,
                "date": date
            }
        }],
        "meta": {}
    });

    if let Some(cursor_value) = cursor {
        page["meta"]["cursor"] = json!(cursor_value);
    }

    page
}

/// Helper function to create test client
async fn create_test_client_for_comments(mock_server: &MockServer) -> virustotal_rs::Client {
    ClientBuilder::new()
        .api_key("test_key")
        .tier(ApiTier::Public)
        .base_url(mock_server.uri())
        .build()
        .unwrap()
}

#[tokio::test]
async fn test_comment_iterator() {
    let mock_server = MockServer::start().await;

    let page1 = create_comment_page("c-1", "Comment 1", 1234567890, Some("page2"));
    let page2 = create_comment_page("c-2", "Comment 2", 1234567891, None);

    Mock::given(method("GET"))
        .and(path("/ip_addresses/8.8.8.8/comments"))
        .respond_with(ResponseTemplate::new(200).set_body_json(&page1))
        .mount(&mock_server)
        .await;

    Mock::given(method("GET"))
        .and(path("/ip_addresses/8.8.8.8/comments"))
        .respond_with(ResponseTemplate::new(200).set_body_json(&page2))
        .mount(&mock_server)
        .await;

    let client = create_test_client_for_comments(&mock_server).await;
    let ip_client = client.ip_addresses();
    let mut iterator = ip_client.get_comments_iterator("8.8.8.8").await;

    let batch1 = iterator.next_batch().await.unwrap();
    assert_eq!(batch1.len(), 1);
    assert_eq!(batch1[0].object.attributes.text, "Comment 1");
}
