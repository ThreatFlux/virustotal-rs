// Integration tests focused on HTTP client operations
use crate::error::Error;
use crate::tests::mock_data::{
    mock_delete, mock_get, mock_post, mock_put, sample_analysis_data, sample_file_data,
    sample_vote_data, with_api_key, MockResponseBuilder,
};
use crate::tests::test_utils::TestUtils;
use serde_json::{json, Value};
use wiremock::matchers::body_json;

/// Core client HTTP method tests
#[cfg(test)]
mod client_http_operations {
    use super::*;

    #[tokio::test]
    async fn test_client_get_success() {
        let (mock_server, client) = TestUtils::create_mock_server_and_client().await;

        let sample_data = sample_file_data();
        let response = MockResponseBuilder::new()
            .with_data(sample_data.clone())
            .build();

        with_api_key(mock_get("/files/test"), "test_api_key")
            .respond_with(response)
            .mount(&mock_server)
            .await;

        let result: Result<Value, Error> = client.get("files/test").await;
        assert!(result.is_ok());
        let response_data = result.unwrap();
        let expected_response = json!({"data": sample_data});
        assert_eq!(response_data, expected_response);
    }

    #[tokio::test]
    async fn test_client_post_success() {
        let (mock_server, client) = TestUtils::create_mock_server_and_client().await;

        let request_body = json!({"test": "data"});
        let sample_data = sample_analysis_data();
        let response = MockResponseBuilder::new()
            .with_data(sample_data.clone())
            .build();

        with_api_key(mock_post("/analyses"), "test_api_key")
            .and(body_json(&request_body))
            .respond_with(response)
            .mount(&mock_server)
            .await;

        let result: Result<Value, Error> = client.post("analyses", &request_body).await;
        assert!(result.is_ok());
        let response_data = result.unwrap();
        let expected_response = json!({"data": sample_data});
        assert_eq!(response_data, expected_response);
    }

    #[tokio::test]
    async fn test_client_put_success() {
        let (mock_server, client) = TestUtils::create_mock_server_and_client().await;

        let request_body = json!({"verdict": "harmless"});
        let sample_data = sample_vote_data();
        let response = MockResponseBuilder::new()
            .with_data(sample_data.clone())
            .build();

        with_api_key(mock_put("/files/test/votes"), "test_api_key")
            .and(body_json(&request_body))
            .respond_with(response)
            .mount(&mock_server)
            .await;

        let result: Result<Value, Error> = client.put("files/test/votes", &request_body).await;
        assert!(result.is_ok());
        let response_data = result.unwrap();
        let expected_response = json!({"data": sample_data});
        assert_eq!(response_data, expected_response);
    }

    #[tokio::test]
    async fn test_client_delete_success() {
        let (mock_server, client) = TestUtils::create_mock_server_and_client().await;

        let response = MockResponseBuilder::new()
            .with_status(204)
            .build()
            .set_body_string("");

        with_api_key(mock_delete("/files/test/comments/123"), "test_api_key")
            .respond_with(response)
            .mount(&mock_server)
            .await;

        let result = client.delete("files/test/comments/123").await;
        assert!(result.is_ok());
    }
}
