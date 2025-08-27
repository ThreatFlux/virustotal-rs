// Async IP address tests focused on IP-related API operations
use crate::test_utils::test_utilities::*;
use serde_json::json;
use wiremock::matchers::{header, method, path};
use wiremock::Mock;

/// Test IP address client basic operations
#[cfg(test)]
mod ip_client_tests {
    use super::*;

    #[tokio::test]
    async fn test_ip_client_get() {
        let mock_client = MockApiClient::new().await.unwrap();
        let ip_data = IpResponseBuilder::clean_ip().build();
        let response_data = ResponseFactory::success_response(ip_data);

        Mock::given(method("GET"))
            .and(path("/ip_addresses/8.8.8.8"))
            .and(header("x-apikey", constants::TEST_API_KEY))
            .respond_with(create_json_response(200, &response_data))
            .mount(mock_client.mock_server())
            .await;

        let ip_client = mock_client.client().ip_addresses();
        let result = ip_client.get("8.8.8.8").await;

        assert!(result.is_ok());
        let ip = result.unwrap();
        assert_eq!(ip.object.id, constants::SAMPLE_IP);
    }

    #[tokio::test]
    async fn test_ip_client_get_with_relationships() {
        let mock_client = MockApiClient::new().await.unwrap();
        let mut ip_data = IpResponseBuilder::clean_ip().build();
        ip_data["relationships"] = json!({
            "urls": {"data": []}
        });
        let response_data = ResponseFactory::success_response(ip_data);

        Mock::given(method("GET"))
            .and(path("/ip_addresses/8.8.8.8"))
            .and(header("x-apikey", constants::TEST_API_KEY))
            .respond_with(create_json_response(200, &response_data))
            .mount(mock_client.mock_server())
            .await;

        let ip_client = mock_client.client().ip_addresses();
        let result = ip_client.get_with_relationships("8.8.8.8", &["urls"]).await;

        assert!(result.is_ok());
    }
}

/// Test IP address relationship operations
#[cfg(test)]
mod ip_relationship_tests {
    use super::*;

    #[tokio::test]
    async fn test_ip_get_urls() {
        let mock_client = MockApiClient::new().await.unwrap();
        let response_data = ResponseFactory::collection_response(vec![], None);

        Mock::given(method("GET"))
            .and(path("/ip_addresses/8.8.8.8/urls"))
            .and(header("x-apikey", constants::TEST_API_KEY))
            .respond_with(create_json_response(200, &response_data))
            .mount(mock_client.mock_server())
            .await;

        let ip_client = mock_client.client().ip_addresses();
        let result = ip_client.get_urls("8.8.8.8").await;

        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_ip_get_resolutions() {
        let mock_client = MockApiClient::new().await.unwrap();
        let response_data = ResponseFactory::collection_response(vec![], None);

        Mock::given(method("GET"))
            .and(path("/ip_addresses/8.8.8.8/resolutions"))
            .and(header("x-apikey", constants::TEST_API_KEY))
            .respond_with(create_json_response(200, &response_data))
            .mount(mock_client.mock_server())
            .await;

        let ip_client = mock_client.client().ip_addresses();
        let result = ip_client.get_resolutions("8.8.8.8").await;

        assert!(result.is_ok());
    }
}

/// Test IP address file relationship operations
#[cfg(test)]
mod ip_file_relationship_tests {
    use super::*;

    #[tokio::test]
    async fn test_ip_get_communicating_files() {
        let mock_client = MockApiClient::new().await.unwrap();
        let response_data = ResponseFactory::collection_response(vec![], None);

        Mock::given(method("GET"))
            .and(path("/ip_addresses/8.8.8.8/communicating_files"))
            .and(header("x-apikey", constants::TEST_API_KEY))
            .respond_with(create_json_response(200, &response_data))
            .mount(mock_client.mock_server())
            .await;

        let ip_client = mock_client.client().ip_addresses();
        let result = ip_client.get_communicating_files("8.8.8.8").await;

        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_ip_get_downloaded_files() {
        let mock_client = MockApiClient::new().await.unwrap();
        let response_data = ResponseFactory::collection_response(vec![], None);

        Mock::given(method("GET"))
            .and(path("/ip_addresses/8.8.8.8/downloaded_files"))
            .and(header("x-apikey", constants::TEST_API_KEY))
            .respond_with(create_json_response(200, &response_data))
            .mount(mock_client.mock_server())
            .await;

        let ip_client = mock_client.client().ip_addresses();
        let result = ip_client.get_downloaded_files("8.8.8.8").await;

        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_ip_get_referrer_files() {
        let mock_client = MockApiClient::new().await.unwrap();
        let response_data = ResponseFactory::collection_response(vec![], None);

        Mock::given(method("GET"))
            .and(path("/ip_addresses/8.8.8.8/referrer_files"))
            .and(header("x-apikey", constants::TEST_API_KEY))
            .respond_with(create_json_response(200, &response_data))
            .mount(mock_client.mock_server())
            .await;

        let ip_client = mock_client.client().ip_addresses();
        let result = ip_client.get_referrer_files("8.8.8.8").await;

        assert!(result.is_ok());
    }
}
