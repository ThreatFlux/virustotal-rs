// Integration tests focused on error handling scenarios
use crate::error::Error;
use crate::tests::mock_data::{mock_get, sample_error_response, with_api_key, MockResponseBuilder};
use crate::tests::test_utils::TestUtils;
use serde_json::Value;

/// HTTP error status code tests  
#[cfg(test)]
mod http_error_tests {
    use super::*;

    #[tokio::test]
    async fn test_bad_request_error() {
        let (mock_server, client) = TestUtils::create_mock_server_and_client().await;

        let (status, error_response) = sample_error_response(400);
        let response = MockResponseBuilder::new()
            .with_status(status)
            .build()
            .set_body_json(&error_response);

        with_api_key(mock_get("/files/invalid"), "test_api_key")
            .respond_with(response)
            .mount(&mock_server)
            .await;

        let result: Result<Value, Error> = client.get("files/invalid").await;
        assert!(result.is_err());
        match result.unwrap_err() {
            Error::BadRequest(_) => {}
            e => panic!("Expected BadRequest error, got: {:?}", e),
        }
    }

    #[tokio::test]
    async fn test_unauthorized_error() {
        let (mock_server, client) = TestUtils::create_mock_server_and_client().await;

        let (status, error_response) = sample_error_response(401);
        let response = MockResponseBuilder::new()
            .with_status(status)
            .build()
            .set_body_json(&error_response);

        with_api_key(mock_get("/files/test"), "test_api_key")
            .respond_with(response)
            .mount(&mock_server)
            .await;

        let result: Result<Value, Error> = client.get("files/test").await;
        assert!(result.is_err());
        match result.unwrap_err() {
            Error::AuthenticationRequired => {}
            e => panic!("Expected AuthenticationRequired error, got: {:?}", e),
        }
    }

    #[tokio::test]
    async fn test_forbidden_error() {
        let (mock_server, client) = TestUtils::create_mock_server_and_client().await;

        let (status, error_response) = sample_error_response(403);
        let response = MockResponseBuilder::new()
            .with_status(status)
            .build()
            .set_body_json(&error_response);

        with_api_key(mock_get("/files/test"), "test_api_key")
            .respond_with(response)
            .mount(&mock_server)
            .await;

        let result: Result<Value, Error> = client.get("files/test").await;
        assert!(result.is_err());
        match result.unwrap_err() {
            Error::Forbidden => {}
            e => panic!("Expected Forbidden error, got: {:?}", e),
        }
    }

    #[tokio::test]
    async fn test_not_found_error() {
        let (mock_server, client) = TestUtils::create_mock_server_and_client().await;

        let (status, error_response) = sample_error_response(404);
        let response = MockResponseBuilder::new()
            .with_status(status)
            .build()
            .set_body_json(&error_response);

        with_api_key(mock_get("/files/nonexistent"), "test_api_key")
            .respond_with(response)
            .mount(&mock_server)
            .await;

        let result: Result<Value, Error> = client.get("files/nonexistent").await;
        assert!(result.is_err());
        match result.unwrap_err() {
            Error::NotFound => {}
            e => panic!("Expected NotFound error, got: {:?}", e),
        }
    }

    #[tokio::test]
    async fn test_rate_limit_error() {
        let (mock_server, client) = TestUtils::create_mock_server_and_client().await;

        let (status, error_response) = sample_error_response(429);
        let response = MockResponseBuilder::new()
            .with_status(status)
            .build()
            .set_body_json(&error_response);

        with_api_key(mock_get("/files/test"), "test_api_key")
            .respond_with(response)
            .mount(&mock_server)
            .await;

        let result: Result<Value, Error> = client.get("files/test").await;
        assert!(result.is_err());
        match result.unwrap_err() {
            Error::QuotaExceeded(_) => {}
            e => panic!("Expected QuotaExceeded error, got: {:?}", e),
        }
    }

    #[tokio::test]
    async fn test_internal_server_error() {
        let (mock_server, client) = TestUtils::create_mock_server_and_client().await;

        let (status, error_response) = sample_error_response(500);
        let response = MockResponseBuilder::new()
            .with_status(status)
            .build()
            .set_body_json(&error_response);

        with_api_key(mock_get("/files/test"), "test_api_key")
            .respond_with(response)
            .mount(&mock_server)
            .await;

        let result: Result<Value, Error> = client.get("files/test").await;
        assert!(result.is_err());
        match result.unwrap_err() {
            Error::Unknown(_) => {}
            e => panic!("Expected Unknown error, got: {:?}", e),
        }
    }
}
