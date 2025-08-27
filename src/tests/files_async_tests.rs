// Async file tests focused on file-related API operations
use crate::test_utils::test_utilities::*;
use serde_json::json;
use wiremock::matchers::{header, method, path};
use wiremock::Mock;

/// Test file client basic operations
#[cfg(test)]
mod file_client_tests {
    use super::*;

    #[tokio::test]
    async fn test_file_client_get() {
        let mock_client = MockApiClient::new().await.unwrap();
        let file_data = FileResponseBuilder::clean_file().build();
        let response_data = ResponseFactory::success_response(file_data);

        Mock::given(method("GET"))
            .and(path("/files/test_hash"))
            .and(header("x-apikey", constants::TEST_API_KEY))
            .respond_with(create_json_response(200, &response_data))
            .mount(mock_client.mock_server())
            .await;

        let file_client = mock_client.client().files();
        let result = file_client.get("test_hash").await;

        assert!(result.is_ok());
        let file = result.unwrap();
        assert_eq!(file.object.id, constants::CLEAN_HASH);
    }

    #[tokio::test]
    async fn test_file_client_get_download_url() {
        let mock_client = MockApiClient::new().await.unwrap();
        let response_body = json!({"data": "https://download.url/file"});

        Mock::given(method("GET"))
            .and(path("/files/test_hash/download_url"))
            .and(header("x-apikey", constants::TEST_API_KEY))
            .respond_with(create_json_response(200, &response_body))
            .mount(mock_client.mock_server())
            .await;

        let file_client = mock_client.client().files();
        let result = file_client.get_download_url("test_hash").await;

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "https://download.url/file");
    }

    #[tokio::test]
    async fn test_file_client_get_upload_url() {
        let mock_client = MockApiClient::new().await.unwrap();
        let response_body = json!({"data": "https://upload.url/file"});

        Mock::given(method("GET"))
            .and(path("/files/upload_url"))
            .and(header("x-apikey", constants::TEST_API_KEY))
            .respond_with(create_json_response(200, &response_body))
            .mount(mock_client.mock_server())
            .await;

        let file_client = mock_client.client().files();
        let result = file_client.get_upload_url().await;

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "https://upload.url/file");
    }
}

/// Test file error handling scenarios
#[cfg(test)]
mod file_error_tests {
    use super::*;

    #[tokio::test]
    async fn test_file_not_found() {
        let mock_client = MockApiClient::new().await.unwrap();
        let (status, error_body) = ResponseFactory::not_found_error();

        Mock::given(method("GET"))
            .and(path("/files/nonexistent_hash"))
            .and(header("x-apikey", constants::TEST_API_KEY))
            .respond_with(create_json_response(status, &error_body))
            .mount(mock_client.mock_server())
            .await;

        let file_client = mock_client.client().files();
        let result = file_client.get("nonexistent_hash").await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_file_rate_limit_error() {
        let mock_client = MockApiClient::new().await.unwrap();
        let (status, error_body) = ResponseFactory::rate_limit_error();

        Mock::given(method("GET"))
            .and(path("/files/test_hash"))
            .and(header("x-apikey", constants::TEST_API_KEY))
            .respond_with(create_json_response(status, &error_body))
            .mount(mock_client.mock_server())
            .await;

        let file_client = mock_client.client().files();
        let result = file_client.get("test_hash").await;

        assert!(result.is_err());
    }
}
