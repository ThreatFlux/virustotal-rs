use serde_json::json;
use virustotal_rs::{ApiTier, ClientBuilder, VoteVerdict};
use wiremock::matchers::{header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

#[tokio::test]
async fn test_get_votes() {
    let mock_server = MockServer::start().await;

    let votes_response = json!({
        "data": [
            {
                "type": "vote",
                "id": "v-123",
                "attributes": {
                    "verdict": "harmless",
                    "date": 1234567890,
                    "value": 1
                }
            },
            {
                "type": "vote",
                "id": "v-124",
                "attributes": {
                    "verdict": "malicious",
                    "date": 1234567891,
                    "value": -1
                }
            }
        ]
    });

    Mock::given(method("GET"))
        .and(path("/ip_addresses/8.8.8.8/votes"))
        .and(header("x-apikey", "test_key"))
        .respond_with(ResponseTemplate::new(200).set_body_json(&votes_response))
        .mount(&mock_server)
        .await;

    let client = ClientBuilder::new()
        .api_key("test_key")
        .tier(ApiTier::Public)
        .base_url(mock_server.uri())
        .build()
        .unwrap();

    let votes = client.ip_addresses().get_votes("8.8.8.8").await.unwrap();

    assert_eq!(votes.data.len(), 2);
    assert_eq!(
        votes.data[0].object.attributes.verdict,
        VoteVerdict::Harmless
    );
    assert_eq!(
        votes.data[1].object.attributes.verdict,
        VoteVerdict::Malicious
    );
}

#[tokio::test]
async fn test_add_vote_with_response() {
    let mock_server = MockServer::start().await;

    let vote_response = json!({
        "data": {
            "type": "vote",
            "id": "v-125",
            "attributes": {
                "verdict": "harmless",
                "date": 1234567892
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

    let vote = client
        .ip_addresses()
        .add_vote("8.8.8.8", VoteVerdict::Harmless)
        .await
        .unwrap();

    assert_eq!(vote.object.object_type, "vote");
    assert_eq!(vote.object.attributes.verdict, VoteVerdict::Harmless);
}

#[tokio::test]
async fn test_get_relationship() {
    let mock_server = MockServer::start().await;

    let relationship_response = json!({
        "data": [
            {
                "type": "url",
                "id": "url-1",
                "attributes": {
                    "url": "http://example.com"
                }
            },
            {
                "type": "url",
                "id": "url-2",
                "attributes": {
                    "url": "http://example.org"
                }
            }
        ],
        "meta": {
            "cursor": "next"
        }
    });

    Mock::given(method("GET"))
        .and(path("/ip_addresses/8.8.8.8/urls"))
        .and(header("x-apikey", "test_key"))
        .respond_with(ResponseTemplate::new(200).set_body_json(&relationship_response))
        .mount(&mock_server)
        .await;

    let client = ClientBuilder::new()
        .api_key("test_key")
        .tier(ApiTier::Public)
        .base_url(mock_server.uri())
        .build()
        .unwrap();

    let urls: virustotal_rs::Collection<serde_json::Value> = client
        .ip_addresses()
        .get_relationship("8.8.8.8", "urls")
        .await
        .unwrap();

    assert_eq!(urls.data.len(), 2);
}

#[tokio::test]
async fn test_get_relationship_descriptors() {
    let mock_server = MockServer::start().await;

    let descriptors_response = json!({
        "data": [
            {
                "type": "domain",
                "id": "example.com"
            },
            {
                "type": "domain",
                "id": "example.org"
            }
        ]
    });

    Mock::given(method("GET"))
        .and(path("/ip_addresses/8.8.8.8/relationships/resolutions"))
        .and(header("x-apikey", "test_key"))
        .respond_with(ResponseTemplate::new(200).set_body_json(&descriptors_response))
        .mount(&mock_server)
        .await;

    let client = ClientBuilder::new()
        .api_key("test_key")
        .tier(ApiTier::Public)
        .base_url(mock_server.uri())
        .build()
        .unwrap();

    let descriptors = client
        .ip_addresses()
        .get_relationship_descriptors("8.8.8.8", "resolutions")
        .await
        .unwrap();

    assert_eq!(descriptors.data.len(), 2);
    assert_eq!(descriptors.data[0].object_type, "domain");
    assert_eq!(descriptors.data[0].id, "example.com");
}

#[tokio::test]
async fn test_comment_with_tags() {
    let mock_server = MockServer::start().await;

    let comment_response = json!({
        "data": {
            "type": "comment",
            "id": "c-789",
            "attributes": {
                "text": "This is #suspicious and #malware related",
                "tags": ["suspicious", "malware"],
                "date": 1234567890
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
        .add_comment("1.2.3.4", "This is #suspicious and #malware related")
        .await
        .unwrap();

    assert_eq!(
        comment.object.attributes.text,
        "This is #suspicious and #malware related"
    );
    assert!(comment.object.attributes.tags.is_some());
    let tags = comment.object.attributes.tags.unwrap();
    assert_eq!(tags.len(), 2);
    assert!(tags.contains(&"suspicious".to_string()));
    assert!(tags.contains(&"malware".to_string()));
}
