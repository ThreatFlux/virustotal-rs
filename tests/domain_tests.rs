use serde_json::json;
use virustotal_rs::{ApiTier, ClientBuilder, VoteVerdict, setup_test_client, create_analysis_response, create_comment_response, setup_mock_http};
use wiremock::matchers::{header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

#[tokio::test]
async fn test_domain_get() {
    let (mock_server, client) = setup_test_client!();

    let domain_response = json!({
        "data": {
            "type": "domain",
            "id": "example.com",
            "attributes": {
                "registrar": "Example Registrar",
                "creation_date": 1234567890,
                "reputation": 0,
                "categories": {
                    "BitDefender": "business",
                    "Forcepoint ThreatSeeker": "information technology"
                },
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

    setup_mock_http!(&mock_server, "GET", "/domains/example.com", 200, &domain_response);

    let domain = client.domains().get("example.com").await.unwrap();

    assert_eq!(domain.object.id, "example.com");
    assert_eq!(domain.object.object_type, "domain");
    assert_eq!(
        domain.object.attributes.registrar,
        Some("Example Registrar".to_string())
    );
    assert_eq!(domain.object.attributes.reputation, Some(0));
}

#[tokio::test]
async fn test_domain_analyse() {
    let (mock_server, client) = setup_test_client!();

    let analysis_response = create_analysis_response!("d-abc123-1234567890");

    setup_mock_http!(&mock_server, "POST", "/domains/example.com/analyse", 200, &analysis_response);

    let result = client.domains().analyse("example.com").await.unwrap();
    assert_eq!(result.data.object_type, "analysis");
    assert_eq!(result.data.id, "d-abc123-1234567890");
}

#[tokio::test]
async fn test_domain_comments() {
    let mock_server = MockServer::start().await;

    let comments_response = json!({
        "data": [
            {
                "type": "comment",
                "id": "c-1",
                "attributes": {
                    "text": "This domain is safe",
                    "date": 1234567890,
                    "tags": ["safe", "verified"]
                }
            },
            {
                "type": "comment",
                "id": "c-2",
                "attributes": {
                    "text": "Known phishing domain #phishing",
                    "date": 1234567891,
                    "tags": ["phishing"]
                }
            }
        ]
    });

    Mock::given(method("GET"))
        .and(path("/domains/example.com/comments"))
        .and(header("x-apikey", "test_key"))
        .respond_with(ResponseTemplate::new(200).set_body_json(&comments_response))
        .mount(&mock_server)
        .await;

    let client = ClientBuilder::new()
        .api_key("test_key")
        .tier(ApiTier::Public)
        .base_url(mock_server.uri())
        .build()
        .unwrap();

    let comments = client.domains().get_comments("example.com").await.unwrap();

    assert_eq!(comments.data.len(), 2);
    assert_eq!(
        comments.data[0].object.attributes.text,
        "This domain is safe"
    );
    assert!(comments.data[1].object.attributes.tags.is_some());
}

#[tokio::test]
async fn test_domain_add_comment() {
    let mock_server = MockServer::start().await;

    let comment_response = json!({
        "data": {
            "type": "comment",
            "id": "c-new",
            "attributes": {
                "text": "Suspicious activity detected #suspicious",
                "date": 1234567892,
                "tags": ["suspicious"]
            }
        }
    });

    Mock::given(method("POST"))
        .and(path("/domains/example.com/comments"))
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
        .domains()
        .add_comment("example.com", "Suspicious activity detected #suspicious")
        .await
        .unwrap();

    assert_eq!(
        comment.object.attributes.text,
        "Suspicious activity detected #suspicious"
    );
    let tags = comment.object.attributes.tags.unwrap();
    assert!(tags.contains(&"suspicious".to_string()));
}

#[tokio::test]
async fn test_domain_votes() {
    let mock_server = MockServer::start().await;

    let votes_response = json!({
        "data": [
            {
                "type": "vote",
                "id": "v-1",
                "attributes": {
                    "verdict": "harmless",
                    "date": 1234567890
                }
            },
            {
                "type": "vote",
                "id": "v-2",
                "attributes": {
                    "verdict": "malicious",
                    "date": 1234567891
                }
            }
        ]
    });

    Mock::given(method("GET"))
        .and(path("/domains/example.com/votes"))
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

    let votes = client.domains().get_votes("example.com").await.unwrap();

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
async fn test_domain_add_vote() {
    let mock_server = MockServer::start().await;

    let vote_response = json!({
        "data": {
            "type": "vote",
            "id": "v-new",
            "attributes": {
                "verdict": "malicious",
                "date": 1234567892
            }
        }
    });

    Mock::given(method("POST"))
        .and(path("/domains/example.com/votes"))
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
        .domains()
        .add_vote("example.com", VoteVerdict::Malicious)
        .await
        .unwrap();

    assert_eq!(vote.object.attributes.verdict, VoteVerdict::Malicious);
}

#[tokio::test]
async fn test_domain_subdomains() {
    let mock_server = MockServer::start().await;

    let subdomains_response = json!({
        "data": [
            {
                "type": "domain",
                "id": "www.example.com",
                "attributes": {
                    "creation_date": 1234567890
                }
            },
            {
                "type": "domain",
                "id": "mail.example.com",
                "attributes": {
                    "creation_date": 1234567891
                }
            }
        ]
    });

    Mock::given(method("GET"))
        .and(path("/domains/example.com/subdomains"))
        .and(header("x-apikey", "test_key"))
        .respond_with(ResponseTemplate::new(200).set_body_json(&subdomains_response))
        .mount(&mock_server)
        .await;

    let client = ClientBuilder::new()
        .api_key("test_key")
        .tier(ApiTier::Public)
        .base_url(mock_server.uri())
        .build()
        .unwrap();

    let subdomains = client
        .domains()
        .get_subdomains("example.com")
        .await
        .unwrap();

    assert_eq!(subdomains.data.len(), 2);
}

#[tokio::test]
async fn test_domain_resolutions() {
    let mock_server = MockServer::start().await;

    let resolutions_response = json!({
        "data": [
            {
                "type": "resolution",
                "id": "192.168.1.1",
                "attributes": {
                    "ip_address": "192.168.1.1",
                    "date": 1234567890
                }
            }
        ]
    });

    Mock::given(method("GET"))
        .and(path("/domains/example.com/resolutions"))
        .and(header("x-apikey", "test_key"))
        .respond_with(ResponseTemplate::new(200).set_body_json(&resolutions_response))
        .mount(&mock_server)
        .await;

    let client = ClientBuilder::new()
        .api_key("test_key")
        .tier(ApiTier::Public)
        .base_url(mock_server.uri())
        .build()
        .unwrap();

    let resolutions = client
        .domains()
        .get_resolutions("example.com")
        .await
        .unwrap();

    assert_eq!(resolutions.data.len(), 1);
}

#[tokio::test]
async fn test_domain_relationship_descriptors() {
    let mock_server = MockServer::start().await;

    let descriptors_response = json!({
        "data": [
            {
                "type": "ip_address",
                "id": "8.8.8.8"
            },
            {
                "type": "ip_address",
                "id": "8.8.4.4"
            }
        ]
    });

    Mock::given(method("GET"))
        .and(path("/domains/example.com/relationships/resolutions"))
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
        .domains()
        .get_relationship_descriptors("example.com", "resolutions")
        .await
        .unwrap();

    assert_eq!(descriptors.data.len(), 2);
    assert_eq!(descriptors.data[0].object_type, "ip_address");
    assert_eq!(descriptors.data[0].id, "8.8.8.8");
}
