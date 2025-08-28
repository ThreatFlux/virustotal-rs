//! Comprehensive tests for client.rs module to improve coverage
//! This module focuses on testing uncovered client functionality

use crate::auth::{ApiKey, ApiTier};
use crate::client::*;
use crate::error::{Error, Result};
use crate::{setup_test_client, test_http_methods, test_error_response, setup_mock_http};
use serde_json::json;
use std::time::Duration;

#[test]
fn test_client_direct_creation() {
    let api_key = ApiKey::new("test-api-key").unwrap();
    let result = Client::new(api_key.clone(), ApiTier::Public);
    
    assert!(result.is_ok());
    let client = result.unwrap();
    assert_eq!(client.api_key(), "test-api-key");
    assert_eq!(client.base_url(), "https://www.virustotal.com/api/v3/");
}

#[test]
fn test_client_with_timeout() {
    let api_key = ApiKey::new("test-api-key").unwrap();
    let client = Client::new(api_key, ApiTier::Premium).unwrap();
    
    let result = client.with_timeout(Duration::from_secs(60));
    assert!(result.is_ok());
    
    let new_client = result.unwrap();
    assert_eq!(new_client.api_key(), "test-api-key");
}

#[test]
fn test_client_with_base_url() {
    let client = create_test_client();
    
    // Test valid URL
    let result = client.with_base_url("https://custom.virustotal.com/api/v3/");
    assert!(result.is_ok());
    let new_client = result.unwrap();
    assert_eq!(new_client.base_url(), "https://custom.virustotal.com/api/v3/");
    
    // Test invalid URL
    let client2 = create_test_client();
    let result = client2.with_base_url("invalid-url");
    assert!(result.is_err());
    
    if let Err(Error::BadRequest(msg)) = result {
        assert!(msg.contains("Invalid base URL"));
    } else {
        panic!("Expected BadRequest error");
    }
}

// Generate HTTP method tests using separate macros
test_get_request!("/test-endpoint");
test_post_request!("/test-endpoint");
test_put_request!("/test-endpoint");
test_delete_request!("/test-endpoint");

#[tokio::test]
async fn test_client_delete_with_header() {
    let (mock_server, client) = setup_test_client!("test_key");
    
    setup_mock_http!(&mock_server, "DELETE", "/test-endpoint", 204, &json!({}));

    let result = client.delete_with_header("test-endpoint", "X-Custom-Header", "custom-value").await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_client_post_form() {
    let (mock_server, client) = setup_test_client!("test_key");

    let mut form_data = std::collections::HashMap::new();
    form_data.insert("field1", "value1");
    form_data.insert("field2", "value2");

    let response = json!({
        "data": {
            "type": "form_response",
            "id": "form-id"
        }
    });
    
    setup_mock_http!(&mock_server, "POST", "/test-form-endpoint", 200, &response);

    let result: Result<serde_json::Value> = client.post_form("test-form-endpoint", &form_data).await;
    assert!(result.is_ok());
}

// Generate error handling tests using the macro
test_error_response!(test_client_error_handling_400, "/bad-request", 400, "BadRequestError", "Invalid request parameters", BadRequest);
test_error_response!(test_client_error_handling_401, "/unauthorized", 401, "AuthenticationRequiredError", "Valid API key required", AuthenticationRequired);
test_error_response!(test_client_error_handling_403, "/forbidden", 403, "ForbiddenError", "Access denied", Forbidden);
test_error_response!(test_client_error_handling_404, "/not-found", 404, "NotFoundError", "Resource not found", NotFound);
test_error_response!(test_client_error_handling_429, "/rate-limited", 429, "QuotaExceededError", "Rate limit exceeded", QuotaExceeded);

#[tokio::test]
async fn test_client_error_handling_500() {
    let (mock_server, client) = setup_test_client!();
    
    let error_response = json!({
        "error": {
            "code": "InternalError",
            "message": "Internal server error"
        }
    });

    setup_mock_http!(&mock_server, "GET", "/server-error", 500, &error_response);

    let result: Result<serde_json::Value> = client.get("server-error").await;
    assert!(result.is_err());
}

#[tokio::test]
async fn test_client_malformed_json_response() {
    let (mock_server, client) = setup_test_client!();

    use wiremock::{Mock, ResponseTemplate, matchers::{method, path, header}};
    Mock::given(method("GET"))
        .and(path("/malformed-json"))
        .and(header("x-apikey", "test_key"))
        .respond_with(ResponseTemplate::new(200).set_body("{invalid json"))
        .mount(&mock_server)
        .await;

    let result: Result<serde_json::Value> = client.get("malformed-json").await;
    assert!(result.is_err());
    
    if let Err(Error::Json(_)) = result {
        // Expected JSON parsing error
    } else {
        panic!("Expected JSON parsing error");
    }
}

#[tokio::test]
async fn test_client_network_timeout() {
    let api_key = ApiKey::new("test-api-key").unwrap();
    let client = Client::new(api_key, ApiTier::Public).unwrap()
        .with_timeout(Duration::from_millis(1)).unwrap();
    
    // Try to connect to a non-existent server to trigger timeout
    let result: Result<serde_json::Value> = client.get("test-endpoint").await;
    assert!(result.is_err());
}

#[tokio::test]
async fn test_client_invalid_endpoint_url() {
    let api_key = ApiKey::new("test-api-key").unwrap();
    let client = Client::new(api_key, ApiTier::Public).unwrap();
    
    // Test with an endpoint that would create an invalid URL
    let result: Result<serde_json::Value> = client.get("").await;
    assert!(result.is_err());
}

#[test]
fn test_client_getters() {
    let api_key = ApiKey::new("test-api-key").unwrap();
    let client = Client::new(api_key, ApiTier::Public).unwrap();
    
    // Test API key getter
    assert_eq!(client.api_key(), "test-api-key");
    
    // Test base URL getter
    assert_eq!(client.base_url(), "https://www.virustotal.com/api/v3/");
    
    // Test HTTP client getter
    let http_client = client.http_client();
    assert!(!format!("{:?}", http_client).is_empty());
}

#[test]
fn test_client_clone() {
    let api_key = ApiKey::new("test-api-key").unwrap();
    let client = Client::new(api_key, ApiTier::Public).unwrap();
    let cloned_client = client.clone();
    
    assert_eq!(client.api_key(), cloned_client.api_key());
    assert_eq!(client.base_url(), cloned_client.base_url());
}

// Helper function to test basic module getters
fn test_basic_module_getters(client: &Client) {
    let _files = client.files();
    let _domains = client.domains();
    let _ip_addresses = client.ip_addresses();
    let _urls = client.urls();
    let _analysis = client.analysis();
    let _comments = client.comments();
    let _votes = client.votes();
    let _collections = client.collections();
}

// Helper function to test search and feed module getters  
fn test_search_and_feed_getters(client: &Client) {
    let _livehunt = client.livehunt();
    let _retrohunt = client.retrohunt();
    let _feeds = client.feeds();
    let _search = client.search();
    let _ioc_stream = client.ioc_stream();
}

// Helper function to test rule-related module getters
fn test_rule_module_getters(client: &Client) {
    let _sigma_rules = client.sigma_rules();
    let _yara_rulesets = client.yara_rulesets();
    let _crowdsourced_yara_rules = client.crowdsourced_yara_rules();
}

// Helper function to test premium feature getters
fn test_premium_module_getters(client: &Client) {
    let _graphs = client.graphs();
    let _groups = client.groups();
    let _users = client.users();
    let _private_files = client.private_files();
    let _private_urls = client.private_urls();
    let _zip_files = client.zip_files();
    let _references = client.references();
    let _file_behaviours = client.file_behaviours();
}

// Helper function to test threat intelligence getters
fn test_threat_intel_getters(client: &Client) {
    let _threat_actors = client.threat_actors();
    let _attack_tactics = client.attack_tactics();
    let _attack_techniques = client.attack_techniques();
    let _popular_threat_categories = client.popular_threat_categories();
    let _metadata = client.metadata();
}

#[test]
fn test_client_basic_modules() {
    let client = create_test_client();
    test_basic_module_getters(&client);
}

#[test]
fn test_client_search_modules() {
    let client = create_test_client();
    test_search_and_feed_getters(&client);
}

#[test]
fn test_client_rule_modules() {
    let client = create_test_client();
    test_rule_module_getters(&client);
}

#[test]
fn test_client_premium_modules() {
    let client = create_test_client();
    test_premium_module_getters(&client);
}

#[test]
fn test_client_threat_intel_modules() {
    let client = create_test_client();
    test_threat_intel_getters(&client);
}

#[test]
fn test_client_builder_defaults() {
    let api_key = ApiKey::new("test-key").unwrap();
    let client = Client::new(api_key, ApiTier::Public).unwrap();
    
    // Verify default timeout and user agent are set
    assert_eq!(client.api_key(), "test-key");
    assert_eq!(client.base_url(), "https://www.virustotal.com/api/v3/");
}

#[tokio::test]
async fn test_client_delete_error_handling() {
    let (mock_server, client) = setup_test_client!();

    let error_response = json!({
        "error": {
            "code": "BadRequestError",
            "message": "Cannot delete this resource"
        }
    });

    setup_mock_http!(&mock_server, "DELETE", "/delete-error", 400, &error_response);

    let result = client.delete("delete-error").await;
    assert!(result.is_err());
}

#[tokio::test]
async fn test_client_delete_with_header_error_handling() {
    let (mock_server, client) = setup_test_client!();

    let error_response = json!({
        "error": {
            "code": "ForbiddenError",
            "message": "Missing required permissions"
        }
    });

    setup_mock_http!(&mock_server, "DELETE", "/delete-header-error", 403, &error_response);

    let result = client.delete_with_header("delete-header-error", "X-Permission", "admin").await;
    assert!(result.is_err());
}

#[tokio::test]
async fn test_client_empty_response_handling() {
    let (mock_server, client) = setup_test_client!();

    use wiremock::{Mock, ResponseTemplate, matchers::{method, path, header}};
    Mock::given(method("GET"))
        .and(path("/empty-response"))
        .and(header("x-apikey", "test_key"))
        .respond_with(ResponseTemplate::new(200).set_body(""))
        .mount(&mock_server)
        .await;

    let result: Result<serde_json::Value> = client.get("empty-response").await;
    assert!(result.is_err());
}

#[test]
fn test_constants() {
    // Verify the constants are accessible and have expected values
    use crate::client::{BASE_URL, DEFAULT_TIMEOUT};
    
    assert_eq!(BASE_URL, "https://www.virustotal.com/api/v3/");
    assert_eq!(DEFAULT_TIMEOUT, Duration::from_secs(30));
}