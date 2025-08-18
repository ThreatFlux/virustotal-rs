use crate::{ApiTier, ClientBuilder, Error};
use std::time::Duration;

#[test]
fn test_client_builder_new() {
    let builder = ClientBuilder::new();
    assert!(builder.build().is_err()); // Should fail without API key
}

#[test]
fn test_client_builder_with_api_key() {
    let client = ClientBuilder::new().api_key("test_key").build();
    assert!(client.is_ok());
}

#[test]
fn test_client_builder_with_tier() {
    let client = ClientBuilder::new()
        .api_key("test_key")
        .tier(ApiTier::Premium)
        .build();
    assert!(client.is_ok());
}

#[test]
fn test_client_builder_with_timeout() {
    let client = ClientBuilder::new()
        .api_key("test_key")
        .timeout(Duration::from_secs(60))
        .build();
    assert!(client.is_ok());
}

#[test]
fn test_client_builder_with_base_url() {
    let client = ClientBuilder::new()
        .api_key("test_key")
        .base_url("https://example.com/api/")
        .build();
    assert!(client.is_ok());
}

#[test]
fn test_client_builder_default() {
    let builder = ClientBuilder::default();
    assert!(builder.build().is_err()); // Should fail without API key
}

#[test]
fn test_client_builder_missing_api_key() {
    let result = ClientBuilder::new().build();
    assert!(result.is_err());
    match result {
        Err(Error::BadRequest(msg)) => {
            assert!(msg.contains("API key"));
        }
        _ => panic!("Expected BadRequest error"),
    }
}

#[test]
fn test_client_api_key_getter() {
    let client = ClientBuilder::new()
        .api_key("test_key_123")
        .build()
        .unwrap();
    assert_eq!(client.api_key(), "test_key_123");
}

#[test]
fn test_client_base_url_getter() {
    let client = ClientBuilder::new().api_key("test_key").build().unwrap();
    assert_eq!(client.base_url(), "https://www.virustotal.com/api/v3/");
}

#[test]
fn test_client_with_custom_base_url() {
    let client = ClientBuilder::new()
        .api_key("test_key")
        .base_url("https://custom.api.com/")
        .build()
        .unwrap();
    assert_eq!(client.base_url(), "https://custom.api.com/");
}

#[test]
fn test_client_http_client_getter() {
    let client = ClientBuilder::new().api_key("test_key").build().unwrap();
    // Just verify that we can get the http_client reference
    let _http = client.http_client();
}

#[test]
fn test_client_files_method() {
    let client = ClientBuilder::new().api_key("test_key").build().unwrap();
    let _files_client = client.files();
}

#[test]
fn test_client_domains_method() {
    let client = ClientBuilder::new().api_key("test_key").build().unwrap();
    let _domains_client = client.domains();
}

#[test]
fn test_client_ip_addresses_method() {
    let client = ClientBuilder::new().api_key("test_key").build().unwrap();
    let _ip_client = client.ip_addresses();
}

#[test]
fn test_client_sigma_rules_method() {
    let client = ClientBuilder::new().api_key("test_key").build().unwrap();
    let _sigma_client = client.sigma_rules();
}

#[test]
fn test_client_yara_rulesets_method() {
    let client = ClientBuilder::new().api_key("test_key").build().unwrap();
    let _yara_client = client.yara_rulesets();
}
