// Async domain tests focused on domain-related API operations
use crate::test_utils::test_utilities::*;
use serde_json::json;
use wiremock::matchers::{header, method, path};
use wiremock::Mock;

/// Test domain client basic operations
#[cfg(test)]
mod domain_client_tests {
    use super::*;

    #[tokio::test]
    async fn test_domain_client_get() {
        let mock_client = MockApiClient::new().await.unwrap();
        let domain_data = DomainResponseBuilder::clean_domain().build();
        let response_data = ResponseFactory::success_response(domain_data);

        Mock::given(method("GET"))
            .and(path("/domains/example.com"))
            .and(header("x-apikey", constants::TEST_API_KEY))
            .respond_with(create_json_response(200, &response_data))
            .mount(mock_client.mock_server())
            .await;

        let domain_client = mock_client.client().domains();
        let result = domain_client.get("example.com").await;

        assert!(result.is_ok());
        let domain = result.unwrap();
        assert_eq!(domain.object.id, constants::SAMPLE_DOMAIN);
    }

    #[tokio::test]
    async fn test_domain_client_get_with_relationships() {
        let mock_client = MockApiClient::new().await.unwrap();
        let mut domain_data = DomainResponseBuilder::clean_domain().build();
        domain_data["relationships"] = json!({
            "subdomains": {"data": []}
        });
        let response_data = ResponseFactory::success_response(domain_data);

        Mock::given(method("GET"))
            .and(path("/domains/example.com"))
            .and(header("x-apikey", constants::TEST_API_KEY))
            .respond_with(create_json_response(200, &response_data))
            .mount(mock_client.mock_server())
            .await;

        let domain_client = mock_client.client().domains();
        let result = domain_client
            .get_with_relationships("example.com", &["subdomains"])
            .await;

        assert!(result.is_ok());
    }
}

/// Test domain relationship operations
#[cfg(test)]
mod domain_relationship_tests {
    use super::*;

    #[tokio::test]
    async fn test_domain_get_subdomains() {
        let mock_client = MockApiClient::new().await.unwrap();
        let response_data = ResponseFactory::collection_response(vec![], None);

        Mock::given(method("GET"))
            .and(path("/domains/example.com/subdomains"))
            .and(header("x-apikey", constants::TEST_API_KEY))
            .respond_with(create_json_response(200, &response_data))
            .mount(mock_client.mock_server())
            .await;

        let domain_client = mock_client.client().domains();
        let result = domain_client.get_subdomains("example.com").await;

        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_domain_get_urls() {
        let mock_client = MockApiClient::new().await.unwrap();
        let response_data = ResponseFactory::collection_response(vec![], None);

        Mock::given(method("GET"))
            .and(path("/domains/example.com/urls"))
            .and(header("x-apikey", constants::TEST_API_KEY))
            .respond_with(create_json_response(200, &response_data))
            .mount(mock_client.mock_server())
            .await;

        let domain_client = mock_client.client().domains();
        let result = domain_client.get_urls("example.com").await;

        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_domain_get_resolutions() {
        let mock_client = MockApiClient::new().await.unwrap();
        let response_data = ResponseFactory::collection_response(vec![], None);

        Mock::given(method("GET"))
            .and(path("/domains/example.com/resolutions"))
            .and(header("x-apikey", constants::TEST_API_KEY))
            .respond_with(create_json_response(200, &response_data))
            .mount(mock_client.mock_server())
            .await;

        let domain_client = mock_client.client().domains();
        let result = domain_client.get_resolutions("example.com").await;

        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_domain_get_parent() {
        let mock_client = MockApiClient::new().await.unwrap();
        let parent_data = DomainResponseBuilder::new("parent.com").build();
        let response_data = ResponseFactory::success_response(parent_data);

        Mock::given(method("GET"))
            .and(path("/domains/example.com/parent"))
            .and(header("x-apikey", constants::TEST_API_KEY))
            .respond_with(create_json_response(200, &response_data))
            .mount(mock_client.mock_server())
            .await;

        let domain_client = mock_client.client().domains();
        let result = domain_client.get_parent("example.com").await;

        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_domain_get_siblings() {
        let mock_client = MockApiClient::new().await.unwrap();
        let response_data = ResponseFactory::collection_response(vec![], None);

        Mock::given(method("GET"))
            .and(path("/domains/example.com/siblings"))
            .and(header("x-apikey", constants::TEST_API_KEY))
            .respond_with(create_json_response(200, &response_data))
            .mount(mock_client.mock_server())
            .await;

        let domain_client = mock_client.client().domains();
        let result = domain_client.get_siblings("example.com").await;

        assert!(result.is_ok());
    }
}

/// Test domain file relationship operations
#[cfg(test)]
mod domain_file_relationship_tests {
    use super::*;

    #[tokio::test]
    async fn test_domain_get_communicating_files() {
        let mock_client = MockApiClient::new().await.unwrap();
        let response_data = ResponseFactory::collection_response(vec![], None);

        Mock::given(method("GET"))
            .and(path("/domains/example.com/communicating_files"))
            .and(header("x-apikey", constants::TEST_API_KEY))
            .respond_with(create_json_response(200, &response_data))
            .mount(mock_client.mock_server())
            .await;

        let domain_client = mock_client.client().domains();
        let result = domain_client.get_communicating_files("example.com").await;

        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_domain_get_downloaded_files() {
        let mock_client = MockApiClient::new().await.unwrap();
        let response_data = ResponseFactory::collection_response(vec![], None);

        Mock::given(method("GET"))
            .and(path("/domains/example.com/downloaded_files"))
            .and(header("x-apikey", constants::TEST_API_KEY))
            .respond_with(create_json_response(200, &response_data))
            .mount(mock_client.mock_server())
            .await;

        let domain_client = mock_client.client().domains();
        let result = domain_client.get_downloaded_files("example.com").await;

        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_domain_get_referrer_files() {
        let mock_client = MockApiClient::new().await.unwrap();
        let response_data = ResponseFactory::collection_response(vec![], None);

        Mock::given(method("GET"))
            .and(path("/domains/example.com/referrer_files"))
            .and(header("x-apikey", constants::TEST_API_KEY))
            .respond_with(create_json_response(200, &response_data))
            .mount(mock_client.mock_server())
            .await;

        let domain_client = mock_client.client().domains();
        let result = domain_client.get_referrer_files("example.com").await;

        assert!(result.is_ok());
    }
}
