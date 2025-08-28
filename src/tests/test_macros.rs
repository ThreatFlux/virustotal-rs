//! Test helper macros to reduce code duplication in tests

/// Creates a standard mock API test setup with a GET endpoint
#[macro_export]
macro_rules! setup_mock_get {
    ($path:expr, $response:expr) => {{
        let mock_client = MockApiClient::new().await.unwrap();
        Mock::given(method("GET"))
            .and(path($path))
            .and(header("x-apikey", constants::TEST_API_KEY))
            .respond_with(create_json_response(200, $response))
            .mount(mock_client.mock_server())
            .await;
        mock_client
    }};
}

/// Creates a client and mock server with custom configuration
#[macro_export]
macro_rules! setup_test_client {
    () => {{
        setup_test_client!("test_key", ApiTier::Public)
    }};
    ($api_key:expr) => {{
        setup_test_client!($api_key, ApiTier::Public)
    }};
    ($api_key:expr, $tier:expr) => {{
        use wiremock::MockServer;
        use crate::auth::ApiTier;
        use crate::client::ClientBuilder;
        use std::time::Duration;
        
        let mock_server = MockServer::start().await;
        let client = ClientBuilder::new()
            .api_key($api_key)
            .tier($tier)
            .base_url(mock_server.uri())
            .timeout(Duration::from_secs(5))
            .build()
            .unwrap();
        (mock_server, client)
    }};
}

/// Creates a mock with specific HTTP method, path, and response
#[macro_export] 
macro_rules! setup_mock_http {
    ($server:expr, $method:expr, $path:expr, $status:expr, $response:expr) => {{
        use wiremock::{Mock, ResponseTemplate};
        use wiremock::matchers::{method, path, header};
        Mock::given(method($method))
            .and(path($path))
            .and(header("x-apikey", "test_key"))
            .respond_with(ResponseTemplate::new($status).set_body_json($response))
            .mount($server)
            .await;
    }};
}

/// Creates a standard analysis response 
#[macro_export]
macro_rules! create_analysis_response {
    ($id:expr) => {{
        serde_json::json!({
            "data": {
                "type": "analysis",
                "id": $id,
                "links": {
                    "self": format!("https://www.virustotal.com/api/v3/analyses/{}", $id)
                }
            }
        })
    }};
}

/// Creates a standard comment response
#[macro_export]
macro_rules! create_comment_response {
    ($id:expr, $text:expr) => {{
        serde_json::json!({
            "data": {
                "type": "comment",
                "id": $id,
                "attributes": {
                    "text": $text,
                    "date": 1234567890,
                    "votes": {
                        "positive": 5,
                        "negative": 1,
                        "abuse": 0
                    }
                }
            }
        })
    }};
}

/// Creates a standard collection response with pagination
#[macro_export]
macro_rules! create_collection_response {
    ($data:expr) => {{
        create_collection_response!($data, None::<String>)
    }};
    ($data:expr, $cursor:expr) => {{
        let data = $data;
        let count = if let Some(arr) = data.as_array() { arr.len() } else { 1 };
        let mut response = ::serde_json::json!({
            "data": data,
            "meta": { "count": count }
        });
        
        if let Some(cursor) = $cursor {
            response["links"] = ::serde_json::json!({
                "next": format!("https://api.example.com/test?cursor={}", cursor)
            });
        }
        response
    }};
}

/// Creates a standard mock API test setup with a POST endpoint
#[macro_export]
macro_rules! setup_mock_post {
    ($path:expr, $response:expr) => {{
        let mock_client = MockApiClient::new().await.unwrap();
        Mock::given(method("POST"))
            .and(path($path))
            .and(header("x-apikey", constants::TEST_API_KEY))
            .respond_with(create_json_response(200, $response))
            .mount(mock_client.mock_server())
            .await;
        mock_client
    }};
}

/// Standard test assertion for successful API responses
#[macro_export]
macro_rules! assert_api_success {
    ($result:expr) => {{
        assert!($result.is_ok(), "API call should succeed");
        $result.unwrap()
    }};
    ($result:expr, $msg:expr) => {{
        assert!($result.is_ok(), $msg);
        $result.unwrap()
    }};
}

/// Standard test for collection endpoints
#[macro_export]
macro_rules! test_collection_endpoint {
    ($test_name:ident, $client_method:ident, $endpoint:expr, $resource:expr) => {
        #[tokio::test]
        async fn $test_name() {
            let response_data = ResponseFactory::collection_response(vec![], None);
            let mock_client = setup_mock_get!($endpoint, &response_data);
            let client = mock_client.client().$client_method();
            let result = client.$test_name($resource).await;
            assert_api_success!(result);
        }
    };
}

/// Standard test for resource getter endpoints
#[macro_export]
macro_rules! test_resource_get {
    ($test_name:ident, $client_type:ident, $path:expr, $resource_id:expr, $builder:expr) => {
        #[tokio::test]
        async fn $test_name() {
            let resource_data = $builder.build();
            let response_data = ResponseFactory::success_response(resource_data);
            let mock_client = setup_mock_get!($path, &response_data);
            let client = mock_client.client().$client_type();
            let result = client.get($resource_id).await;
            assert_api_success!(result);
        }
    };
}

/// Test helper for relationship endpoints
#[macro_export]
macro_rules! test_relationship {
    ($client_type:ident, $method:ident, $base:expr, $relationship:expr) => {{
        async {
            let response_data = ResponseFactory::collection_response(vec![], None);
            let path = format!("{}/{}", $base, $relationship);
            let mock_client = setup_mock_get!(&path, &response_data);
            let client = mock_client.client().$client_type();
            let result = client.$method($base.split('/').last().unwrap()).await;
            assert_api_success!(result)
        }
    }};
}

/// Common test setup for vote operations
#[macro_export]
macro_rules! test_vote_operation {
    ($client_type:ident, $resource:expr, $verdict:expr) => {{
        async {
            let vote_response = json!({
                "data": {
                    "type": "vote",
                    "id": "test-vote-id",
                    "attributes": {
                        "verdict": $verdict,
                        "value": 1
                    }
                }
            });
            let path = format!("/{}/{}/votes", stringify!($client_type), $resource);
            let mock_client = setup_mock_post!(&path, &vote_response);
            let client = mock_client.client().$client_type();
            let result = client.add_vote($resource, $verdict).await;
            assert_api_success!(result)
        }
    }};
}

/// Common test setup for comment operations
#[macro_export]
macro_rules! test_comment_operation {
    ($client_type:ident, $resource:expr, $text:expr) => {{
        async {
            let comment_response = json!({
                "data": {
                    "type": "comment",
                    "id": "test-comment-id",
                    "attributes": {
                        "text": $text,
                        "date": 1234567890
                    }
                }
            });
            let path = format!("/{}/{}/comments", stringify!($client_type), $resource);
            let mock_client = setup_mock_post!(&path, &comment_response);
            let client = mock_client.client().$client_type();
            let result = client.add_comment($resource, $text).await;
            assert_api_success!(result)
        }
    }};
}

/// Creates an error test with specific status code and message
#[macro_export]
macro_rules! test_error_response {
    ($test_name:ident, $endpoint:expr, $status:expr, $error_code:expr, $error_msg:expr, $expected_error:ident) => {
        #[tokio::test]
        async fn $test_name() {
            let (mock_server, client) = setup_test_client!();
            
            let error_response = serde_json::json!({
                "error": {
                    "code": $error_code,
                    "message": $error_msg
                }
            });
            
            setup_mock_http!(&mock_server, "GET", $endpoint, $status, &error_response);
            
            let result: crate::Result<serde_json::Value> = client.get($endpoint).await;
            assert!(result.is_err());
            
            if let Err(crate::Error::$expected_error(_)) = result {
                // Expected error type
            } else {
                panic!("Expected {} error", stringify!($expected_error));
            }
        }
    };
}

/// Test domain relationship endpoint  
#[macro_export]
macro_rules! test_domain_relationship {
    ($test_name:ident, $relationship:expr) => {
        #[tokio::test]
        async fn $test_name() {
            let (mock_server, client) = setup_test_client!();
            let response = create_collection_response!(serde_json::json!([]));
            let path_string = format!("/domains/example.com/{}", $relationship);
            
            setup_mock_http!(&mock_server, "GET", path_string.as_str(), 200, &response);
            
            let domain_client = client.domains();
            let result = match $relationship {
                "subdomains" => domain_client.get_subdomains("example.com").await,
                "urls" => domain_client.get_urls("example.com").await,
                "resolutions" => domain_client.get_resolutions("example.com").await,
                "siblings" => domain_client.get_siblings("example.com").await,
                "communicating_files" => domain_client.get_communicating_files("example.com").await,
                "downloaded_files" => domain_client.get_downloaded_files("example.com").await,
                "referrer_files" => domain_client.get_referrer_files("example.com").await,
                _ => panic!("Unknown relationship: {}", $relationship),
            };
            
            assert!(result.is_ok());
        }
    };
}

/// Test GET request
#[macro_export]
macro_rules! test_get_request {
    ($endpoint:expr) => {
        #[tokio::test]
        async fn test_get_request() {
            let (mock_server, client) = setup_test_client!();
            let response = serde_json::json!({"data": {"type": "test", "id": "test-id"}});
            
            setup_mock_http!(&mock_server, "GET", $endpoint, 200, &response);
            
            let result: crate::Result<serde_json::Value> = client.get($endpoint).await;
            assert!(result.is_ok());
        }
    };
}

/// Test POST request
#[macro_export]
macro_rules! test_post_request {
    ($endpoint:expr) => {
        #[tokio::test]
        async fn test_post_request() {
            let (mock_server, client) = setup_test_client!();
            let response = serde_json::json!({"data": {"type": "created", "id": "new-id"}});
            let body = serde_json::json!({"test_field": "test_value"});
            
            setup_mock_http!(&mock_server, "POST", $endpoint, 201, &response);
            
            let result: crate::Result<serde_json::Value> = client.post($endpoint, &body).await;
            assert!(result.is_ok());
        }
    };
}

/// Test PUT request
#[macro_export]
macro_rules! test_put_request {
    ($endpoint:expr) => {
        #[tokio::test]
        async fn test_put_request() {
            let (mock_server, client) = setup_test_client!();
            let response = serde_json::json!({"data": {"type": "updated", "id": "updated-id"}});
            let body = serde_json::json!({"update_field": "update_value"});
            
            setup_mock_http!(&mock_server, "PUT", $endpoint, 200, &response);
            
            let result: crate::Result<serde_json::Value> = client.put($endpoint, &body).await;
            assert!(result.is_ok());
        }
    };
}

/// Test DELETE request
#[macro_export]
macro_rules! test_delete_request {
    ($endpoint:expr) => {
        #[tokio::test]
        async fn test_delete_request() {
            let (mock_server, client) = setup_test_client!();
            
            setup_mock_http!(&mock_server, "DELETE", $endpoint, 204, &serde_json::json!({}));
            
            let result = client.delete($endpoint).await;
            assert!(result.is_ok());
        }
    };
}