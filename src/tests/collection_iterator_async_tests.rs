// Async collection iterator tests focused on pagination functionality
use crate::objects::CollectionIterator;
use crate::test_utils::test_utilities::*;
use serde_json::json;
use wiremock::matchers::{header, method, path, query_param};
use wiremock::Mock;

/// Test collection iterator basic functionality
#[cfg(test)]
mod collection_iterator_tests {
    use super::*;

    #[tokio::test]
    async fn test_collection_iterator_next_batch() {
        let mock_client = MockApiClient::new().await.unwrap();
        let response_body = json!({
            "data": ["item1", "item2"],
            "meta": {"cursor": "next_cursor"}
        });

        Mock::given(method("GET"))
            .and(path("/test_url"))
            .and(header("x-apikey", constants::TEST_API_KEY))
            .respond_with(create_json_response(200, &response_body))
            .mount(mock_client.mock_server())
            .await;

        let mut iterator = CollectionIterator::<String>::new(mock_client.client(), "/test_url");
        let batch = iterator.next_batch().await;

        assert!(batch.is_ok());
        let items = batch.unwrap();
        assert_eq!(items.len(), 2);
    }

    #[tokio::test]
    async fn test_collection_iterator_with_limit() {
        let mock_client = MockApiClient::new().await.unwrap();
        let response_body = json!({
            "data": ["item1", "item2"],
            "meta": {"cursor": null}
        });

        Mock::given(method("GET"))
            .and(path("/test_url"))
            .and(header("x-apikey", constants::TEST_API_KEY))
            .respond_with(create_json_response(200, &response_body))
            .mount(mock_client.mock_server())
            .await;

        let mut iterator =
            CollectionIterator::<String>::new(mock_client.client(), "/test_url").with_limit(10);
        let batch = iterator.next_batch().await;

        assert!(batch.is_ok());
    }
}

/// Test collection iterator pagination scenarios
#[cfg(test)]
mod pagination_tests {
    use super::*;

    #[tokio::test]
    async fn test_collection_iterator_collect_all() {
        let mock_client = MockApiClient::new().await.unwrap();

        // First response with cursor
        let response1 = json!({
            "data": ["item1", "item2"],
            "meta": {"cursor": "cursor1"}
        });

        // Second response without cursor (last page)
        let response2 = json!({
            "data": ["item3"],
            "meta": {"cursor": null}
        });

        // Mock for second request (with cursor parameter)
        Mock::given(method("GET"))
            .and(path("/test_url"))
            .and(query_param("cursor", "cursor1"))
            .and(header("x-apikey", constants::TEST_API_KEY))
            .respond_with(create_json_response(200, &response2))
            .expect(1)
            .mount(mock_client.mock_server())
            .await;

        // Mock for first request (no cursor parameter)
        Mock::given(method("GET"))
            .and(path("/test_url"))
            .and(header("x-apikey", constants::TEST_API_KEY))
            .respond_with(create_json_response(200, &response1))
            .expect(1)
            .mount(mock_client.mock_server())
            .await;

        let iterator = CollectionIterator::<String>::new(mock_client.client(), "/test_url");
        let all_items = iterator.collect_all().await;

        assert!(all_items.is_ok());
        let items = all_items.unwrap();
        assert_eq!(items.len(), 3);
        assert_eq!(items, vec!["item1", "item2", "item3"]);
    }

    #[tokio::test]
    async fn test_collection_iterator_empty_response() {
        let mock_client = MockApiClient::new().await.unwrap();
        let response_data = ResponseFactory::collection_response(vec![], None);

        Mock::given(method("GET"))
            .and(path("/test_url"))
            .and(header("x-apikey", constants::TEST_API_KEY))
            .respond_with(create_json_response(200, &response_data))
            .mount(mock_client.mock_server())
            .await;

        let mut iterator = CollectionIterator::<String>::new(mock_client.client(), "/test_url");
        let batch = iterator.next_batch().await;

        assert!(batch.is_ok());
        let items = batch.unwrap();
        assert_eq!(items.len(), 0);
    }

    #[tokio::test]
    async fn test_collection_iterator_error_handling() {
        let mock_client = MockApiClient::new().await.unwrap();
        let (status, error_body) = ResponseFactory::rate_limit_error();

        Mock::given(method("GET"))
            .and(path("/test_url"))
            .and(header("x-apikey", constants::TEST_API_KEY))
            .respond_with(create_json_response(status, &error_body))
            .mount(mock_client.mock_server())
            .await;

        let mut iterator = CollectionIterator::<String>::new(mock_client.client(), "/test_url");
        let batch = iterator.next_batch().await;

        assert!(batch.is_err());
    }
}
