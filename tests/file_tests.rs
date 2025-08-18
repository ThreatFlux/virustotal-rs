use serde_json::json;
use virustotal_rs::objects::ObjectOperations;
use virustotal_rs::{ApiTier, ClientBuilder, File, VoteVerdict};
use wiremock::matchers::{header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

#[tokio::test]
async fn test_file_get() {
    let mock_server = MockServer::start().await;

    let file_response = json!({
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
    });

    Mock::given(method("GET"))
        .and(path(
            "/files/275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
        ))
        .and(header("x-apikey", "test_key"))
        .respond_with(ResponseTemplate::new(200).set_body_json(&file_response))
        .mount(&mock_server)
        .await;

    let client = ClientBuilder::new()
        .api_key("test_key")
        .tier(ApiTier::Public)
        .base_url(mock_server.uri())
        .build()
        .unwrap();

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

    let client = ClientBuilder::new()
        .api_key("test_key")
        .tier(ApiTier::Public)
        .base_url(mock_server.uri())
        .build()
        .unwrap();

    let result = client
        .files()
        .analyse("275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f")
        .await
        .unwrap();

    assert_eq!(result.data.object_type, "analysis");
    assert_eq!(
        result.data.id,
        "u-275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f-1234567890"
    );
}

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

    let client = ClientBuilder::new()
        .api_key("test_key")
        .tier(ApiTier::Public)
        .base_url(mock_server.uri())
        .build()
        .unwrap();

    let upload_url = client.files().get_upload_url().await.unwrap();

    assert!(upload_url.starts_with("https://www.virustotal.com/_ah/upload/"));
}

#[tokio::test]
async fn test_file_get_download_url() {
    let mock_server = MockServer::start().await;

    let download_url_response = json!({
        "data": "https://www.virustotal.com/api/v3/files/275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f/download?x-apikey=test_key"
    });

    Mock::given(method("GET"))
        .and(path(
            "/files/275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f/download_url",
        ))
        .and(header("x-apikey", "test_key"))
        .respond_with(ResponseTemplate::new(200).set_body_json(&download_url_response))
        .mount(&mock_server)
        .await;

    let client = ClientBuilder::new()
        .api_key("test_key")
        .tier(ApiTier::Premium) // Download requires Premium API
        .base_url(mock_server.uri())
        .build()
        .unwrap();

    let download_url = client
        .files()
        .get_download_url("275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f")
        .await
        .unwrap();

    assert!(download_url.contains("/download"));
}

#[tokio::test]
async fn test_file_comments() {
    let mock_server = MockServer::start().await;

    let comments_response = json!({
        "data": [
            {
                "type": "comment",
                "id": "f-275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f-1234567890",
                "attributes": {
                    "text": "EICAR test file",
                    "date": 1234567890,
                    "tags": ["test", "eicar"]
                }
            }
        ]
    });

    Mock::given(method("GET"))
        .and(path(
            "/files/275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f/comments",
        ))
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

    let comments = client
        .files()
        .get_comments("275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f")
        .await
        .unwrap();

    assert_eq!(comments.data.len(), 1);
    assert_eq!(comments.data[0].object.attributes.text, "EICAR test file");
}

#[tokio::test]
async fn test_file_add_comment() {
    let mock_server = MockServer::start().await;

    let comment_response = json!({
        "data": {
            "type": "comment",
            "id": "f-275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f-1234567891",
            "attributes": {
                "text": "Test malware sample #test",
                "date": 1234567891,
                "tags": ["test"]
            }
        }
    });

    Mock::given(method("POST"))
        .and(path(
            "/files/275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f/comments",
        ))
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
        .files()
        .add_comment(
            "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
            "Test malware sample #test",
        )
        .await
        .unwrap();

    assert_eq!(comment.object.attributes.text, "Test malware sample #test");
}

#[tokio::test]
async fn test_file_votes() {
    let mock_server = MockServer::start().await;

    let votes_response = json!({
        "data": [
            {
                "type": "vote",
                "id": "v-1",
                "attributes": {
                    "verdict": "malicious",
                    "date": 1234567890
                }
            }
        ]
    });

    Mock::given(method("GET"))
        .and(path(
            "/files/275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f/votes",
        ))
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

    let votes = client
        .files()
        .get_votes("275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f")
        .await
        .unwrap();

    assert_eq!(votes.data.len(), 1);
    assert_eq!(
        votes.data[0].object.attributes.verdict,
        VoteVerdict::Malicious
    );
}

#[tokio::test]
async fn test_file_add_vote() {
    let mock_server = MockServer::start().await;

    let vote_response = json!({
        "data": {
            "type": "vote",
            "id": "v-new",
            "attributes": {
                "verdict": "malicious",
                "date": 1234567891
            }
        }
    });

    Mock::given(method("POST"))
        .and(path(
            "/files/275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f/votes",
        ))
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
        .files()
        .add_vote(
            "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
            VoteVerdict::Malicious,
        )
        .await
        .unwrap();

    assert_eq!(vote.object.attributes.verdict, VoteVerdict::Malicious);
}

#[tokio::test]
async fn test_file_behaviours() {
    let mock_server = MockServer::start().await;

    let behaviours_response = json!({
        "data": [
            {
                "type": "behaviour",
                "id": "behavior1",
                "attributes": {
                    "verdict": "suspicious",
                    "sandbox_name": "Windows Sandbox"
                }
            }
        ]
    });

    Mock::given(method("GET"))
        .and(path(
            "/files/275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f/behaviours",
        ))
        .and(header("x-apikey", "test_key"))
        .respond_with(ResponseTemplate::new(200).set_body_json(&behaviours_response))
        .mount(&mock_server)
        .await;

    let client = ClientBuilder::new()
        .api_key("test_key")
        .tier(ApiTier::Public)
        .base_url(mock_server.uri())
        .build()
        .unwrap();

    let behaviours = client
        .files()
        .get_behaviours("275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f")
        .await
        .unwrap();

    assert_eq!(behaviours.data.len(), 1);
}

#[tokio::test]
async fn test_file_contacted_domains() {
    let mock_server = MockServer::start().await;

    let domains_response = json!({
        "data": [
            {
                "type": "domain",
                "id": "malware.example.com",
                "attributes": {
                    "creation_date": 1234567890
                }
            }
        ]
    });

    Mock::given(method("GET"))
        .and(path("/files/275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f/contacted_domains"))
        .and(header("x-apikey", "test_key"))
        .respond_with(ResponseTemplate::new(200).set_body_json(&domains_response))
        .mount(&mock_server)
        .await;

    let client = ClientBuilder::new()
        .api_key("test_key")
        .tier(ApiTier::Public)
        .base_url(mock_server.uri())
        .build()
        .unwrap();

    let domains = client
        .files()
        .get_contacted_domains("275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f")
        .await
        .unwrap();

    assert_eq!(domains.data.len(), 1);
}

#[tokio::test]
async fn test_file_contacted_ips() {
    let mock_server = MockServer::start().await;

    let ips_response = json!({
        "data": [
            {
                "type": "ip_address",
                "id": "192.168.1.100",
                "attributes": {
                    "asn": 12345,
                    "country": "US"
                }
            }
        ]
    });

    Mock::given(method("GET"))
        .and(path(
            "/files/275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f/contacted_ips",
        ))
        .and(header("x-apikey", "test_key"))
        .respond_with(ResponseTemplate::new(200).set_body_json(&ips_response))
        .mount(&mock_server)
        .await;

    let client = ClientBuilder::new()
        .api_key("test_key")
        .tier(ApiTier::Public)
        .base_url(mock_server.uri())
        .build()
        .unwrap();

    let ips = client
        .files()
        .get_contacted_ips("275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f")
        .await
        .unwrap();

    assert_eq!(ips.data.len(), 1);
}

#[tokio::test]
async fn test_file_dropped_files() {
    let mock_server = MockServer::start().await;

    let dropped_files_response = json!({
        "data": [
            {
                "type": "file",
                "id": "abc123",
                "attributes": {
                    "size": 1024,
                    "type_description": "PE32 executable"
                }
            }
        ]
    });

    Mock::given(method("GET"))
        .and(path(
            "/files/275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f/dropped_files",
        ))
        .and(header("x-apikey", "test_key"))
        .respond_with(ResponseTemplate::new(200).set_body_json(&dropped_files_response))
        .mount(&mock_server)
        .await;

    let client = ClientBuilder::new()
        .api_key("test_key")
        .tier(ApiTier::Public)
        .base_url(mock_server.uri())
        .build()
        .unwrap();

    let dropped = client
        .files()
        .get_dropped_files("275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f")
        .await
        .unwrap();

    assert_eq!(dropped.data.len(), 1);
}

#[tokio::test]
async fn test_file_similar_files() {
    let mock_server = MockServer::start().await;

    let similar_files_response = json!({
        "data": [
            {
                "type": "file",
                "id": "def456",
                "attributes": {
                    "size": 68,
                    "meaningful_name": "similar.txt"
                }
            }
        ]
    });

    Mock::given(method("GET"))
        .and(path(
            "/files/275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f/similar_files",
        ))
        .and(header("x-apikey", "test_key"))
        .respond_with(ResponseTemplate::new(200).set_body_json(&similar_files_response))
        .mount(&mock_server)
        .await;

    let client = ClientBuilder::new()
        .api_key("test_key")
        .tier(ApiTier::Public)
        .base_url(mock_server.uri())
        .build()
        .unwrap();

    let similar = client
        .files()
        .get_similar_files("275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f")
        .await
        .unwrap();

    assert_eq!(similar.data.len(), 1);
}

#[tokio::test]
#[ignore = "Multipart requests cannot be easily mocked with wiremock"]
async fn test_file_upload_bytes() {
    let mock_server = MockServer::start().await;

    let upload_response = json!({
        "data": {
            "type": "analysis",
            "id": "u-abc123-1234567890",
            "links": {
                "self": "https://www.virustotal.com/api/v3/analyses/u-abc123-1234567890"
            }
        }
    });

    Mock::given(method("POST"))
        .and(path("/files"))
        .and(header("x-apikey", "test_key"))
        .respond_with(ResponseTemplate::new(200).set_body_json(&upload_response))
        .mount(&mock_server)
        .await;

    let client = ClientBuilder::new()
        .api_key("test_key")
        .tier(ApiTier::Public)
        .base_url(mock_server.uri())
        .build()
        .unwrap();

    let test_content = b"test file content".to_vec();
    let result = client
        .files()
        .upload_bytes(test_content, "test.txt")
        .await
        .unwrap();

    assert_eq!(result.data.object_type, "analysis");
    assert!(result.data.id.starts_with("u-"));
}

#[tokio::test]
async fn test_file_relationship_with_limit() {
    let mock_server = MockServer::start().await;

    let response = json!({
        "data": [
            {
                "type": "file",
                "id": "file1"
            },
            {
                "type": "file",
                "id": "file2"
            }
        ],
        "meta": {
            "cursor": "next"
        }
    });

    Mock::given(method("GET"))
        .and(path(
            "/files/275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f/bundled_files",
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(&response))
        .mount(&mock_server)
        .await;

    let client = ClientBuilder::new()
        .api_key("test_key")
        .tier(ApiTier::Public)
        .base_url(mock_server.uri())
        .build()
        .unwrap();

    let bundled = client
        .files()
        .get_relationship_with_limit::<serde_json::Value>(
            "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
            "bundled_files",
            2,
        )
        .await
        .unwrap();

    assert_eq!(bundled.data.len(), 2);
    assert!(bundled.meta.is_some());
}

#[tokio::test]
async fn test_file_collection_name() {
    assert_eq!(File::collection_name(), "files");
}

#[tokio::test]
async fn test_file_url() {
    assert_eq!(
        File::object_url("275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"),
        "files/275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
    );
}

#[tokio::test]
async fn test_file_relationships_url() {
    assert_eq!(
        File::relationships_url("hash123", "bundled_files"),
        "files/hash123/relationships/bundled_files"
    );
}
