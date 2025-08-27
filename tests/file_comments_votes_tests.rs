// File comments and votes tests
use serde_json::json;
use virustotal_rs::{ApiTier, ClientBuilder, VoteVerdict};
use wiremock::matchers::{body_json, header, method, path};
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

/// File comments tests
#[cfg(test)]
mod file_comments_tests {
    use super::*;

    #[tokio::test]
    async fn test_file_comments() {
        let mock_server = MockServer::start().await;

        let comments_response = json!({
            "data": [
                {
                    "type": "comment",
                    "id": "comment-1234",
                    "attributes": {
                        "date": 1234567890,
                        "text": "This is a test comment",
                        "html": "<p>This is a test comment</p>",
                        "tags": ["malware", "test"],
                        "vote": "malicious"
                    }
                }
            ],
            "meta": {
                "count": 1
            }
        });

        Mock::given(method("GET"))
            .and(path(
                "/files/275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f/comments",
            ))
            .and(header("x-apikey", "test_key"))
            .respond_with(ResponseTemplate::new(200).set_body_json(&comments_response))
            .mount(&mock_server)
            .await;

        let client = create_test_client(&mock_server).await;
        let comments = client
            .files()
            .get_comments("275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f")
            .await
            .unwrap();

        assert_eq!(comments.data.len(), 1);
        assert_eq!(comments.data[0].object.id, "comment-1234");
        assert_eq!(comments.data[0].object.object_type, "comment");
    }

    #[tokio::test]
    async fn test_file_add_comment() {
        let mock_server = MockServer::start().await;

        let comment_request = json!({
            "data": {
                "type": "comment",
                "attributes": {
                    "text": "This file is suspicious"
                }
            }
        });

        let comment_response = json!({
            "data": {
                "type": "comment",
                "id": "comment-5678",
                "attributes": {
                    "date": 1234567890,
                    "text": "This file is suspicious"
                }
            }
        });

        Mock::given(method("POST"))
            .and(path(
                "/files/275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f/comments",
            ))
            .and(header("x-apikey", "test_key"))
            .and(body_json(&comment_request))
            .respond_with(ResponseTemplate::new(201).set_body_json(&comment_response))
            .mount(&mock_server)
            .await;

        let client = create_test_client(&mock_server).await;
        let comment = client
            .files()
            .add_comment(
                "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
                "This file is suspicious",
            )
            .await
            .unwrap();

        assert_eq!(comment.object.id, "comment-5678");
        assert_eq!(comment.object.object_type, "comment");
    }
}

/// File votes tests
#[cfg(test)]
mod file_votes_tests {
    use super::*;

    #[tokio::test]
    async fn test_file_votes() {
        let mock_server = MockServer::start().await;

        let votes_response = json!({
            "data": [
                {
                    "type": "vote",
                    "id": "vote-1234",
                    "attributes": {
                        "date": 1234567890,
                        "verdict": "harmless"
                    }
                }
            ],
            "meta": {
                "count": 1
            }
        });

        Mock::given(method("GET"))
            .and(path(
                "/files/275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f/votes",
            ))
            .and(header("x-apikey", "test_key"))
            .respond_with(ResponseTemplate::new(200).set_body_json(&votes_response))
            .mount(&mock_server)
            .await;

        let client = create_test_client(&mock_server).await;
        let votes = client
            .files()
            .get_votes("275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f")
            .await
            .unwrap();

        assert_eq!(votes.data.len(), 1);
        assert_eq!(votes.data[0].object.id, "vote-1234");
        assert_eq!(votes.data[0].object.object_type, "vote");
    }

    #[tokio::test]
    async fn test_file_add_vote() {
        let mock_server = MockServer::start().await;

        let vote_request = json!({
            "data": {
                "type": "vote",
                "attributes": {
                    "verdict": "harmless"
                }
            }
        });

        let vote_response = json!({
            "data": {
                "type": "vote",
                "id": "vote-5678",
                "attributes": {
                    "date": 1234567890,
                    "verdict": "harmless"
                }
            }
        });

        Mock::given(method("POST"))
            .and(path(
                "/files/275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f/votes",
            ))
            .and(header("x-apikey", "test_key"))
            .and(body_json(&vote_request))
            .respond_with(ResponseTemplate::new(201).set_body_json(&vote_response))
            .mount(&mock_server)
            .await;

        let client = create_test_client(&mock_server).await;
        let vote = client
            .files()
            .add_vote(
                "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
                VoteVerdict::Harmless,
            )
            .await
            .unwrap();

        assert_eq!(vote.object.id, "vote-5678");
        assert_eq!(vote.object.object_type, "vote");
    }
}
