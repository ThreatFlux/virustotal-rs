# VirusTotal Test Utilities Documentation

## Overview

This document describes the comprehensive test infrastructure utilities created for the VirusTotal Rust SDK. These utilities eliminate code duplication, improve test readability, and provide consistent patterns for testing across the entire library.

## Location

The main test utilities are located at `src/test_utils.rs` and are organized under the `test_utilities` module, only compiled when running tests.

## Key Components

### 1. Test Data Constants (`constants` module)

Provides consistent test data across all tests:

```rust
pub const SAMPLE_MD5: &str = "44d88612fea8a8f36de82e1278abb02f";
pub const SAMPLE_SHA1: &str = "3395856ce81f2b7382dee72602f798b642f14140"; 
pub const SAMPLE_SHA256: &str = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f";
pub const SAMPLE_DOMAIN: &str = "example.com";
pub const SAMPLE_IP: &str = "8.8.8.8";
pub const SAMPLE_URL: &str = "https://example.com/test";
pub const TEST_API_KEY: &str = "test_api_key_123";
pub const MALICIOUS_HASH: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
pub const CLEAN_HASH: &str = "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9";
pub const SAMPLE_TIMESTAMP: i64 = 1609459200; // 2021-01-01 00:00:00 UTC
```

### 2. Mock API Client (`MockApiClient`)

Simplifies test setup by providing pre-configured mock clients:

```rust
// Create a premium tier mock client
let mock_client = MockApiClient::new().await.unwrap();

// Create a public tier mock client  
let public_client = MockApiClient::with_public_tier().await.unwrap();

// Create with custom API key
let custom_client = MockApiClient::with_api_key("custom_key").await.unwrap();
```

### 3. Builder Patterns for Test Data

#### AnalysisStatsBuilder

Create test analysis statistics with sensible defaults and presets:

```rust
// Default clean stats
let clean_stats = AnalysisStatsBuilder::clean().build();

// Malicious preset
let malicious_stats = AnalysisStatsBuilder::malicious().build();

// Custom values with fluent API
let custom_stats = AnalysisStatsBuilder::new()
    .with_harmless(80)
    .with_malicious(5) 
    .with_suspicious(2)
    .build();
```

#### FileResponseBuilder

Build realistic file response data:

```rust
// Clean file preset
let clean_file = FileResponseBuilder::clean_file().build();

// Malicious file preset  
let malicious_file = FileResponseBuilder::malicious_file().build();

// Custom file with specific attributes
let custom_file = FileResponseBuilder::new("custom-hash")
    .with_size(2048)
    .with_names(vec!["document.pdf".to_string()])
    .with_reputation(25)
    .build();
```

#### DomainResponseBuilder

Build domain response data:

```rust
// Clean domain
let domain = DomainResponseBuilder::clean_domain().build();

// Malicious domain
let malicious_domain = DomainResponseBuilder::malicious_domain().build();

// Custom domain
let custom_domain = DomainResponseBuilder::new("example.org")
    .with_reputation(75)
    .with_tags(vec!["legitimate".to_string()])
    .build();
```

#### IpResponseBuilder

Build IP address response data:

```rust
// Clean IP
let ip = IpResponseBuilder::clean_ip().build();

// Malicious IP
let malicious_ip = IpResponseBuilder::malicious_ip().build();

// Custom IP
let custom_ip = IpResponseBuilder::new("1.1.1.1")
    .with_country("US".to_string())
    .with_as_owner("Cloudflare".to_string())
    .build();
```

### 4. Response Factory (`ResponseFactory`)

Easily create various API responses:

```rust
// Success response
let response = ResponseFactory::success_response(data);

// Collection with pagination
let collection = ResponseFactory::collection_response(
    vec![item1, item2], 
    Some("cursor123")
);

// Error responses
let (status, error) = ResponseFactory::rate_limit_error();
let (status, error) = ResponseFactory::not_found_error(); 
let (status, error) = ResponseFactory::unauthorized_error();
let (status, error) = ResponseFactory::forbidden_error();
```

### 5. Custom Assertion Macros

Provide expressive, domain-specific assertions:

```rust
// Analysis statistics assertions
assert_analysis_clean!(stats);
assert_analysis_malicious!(stats);

// Range assertions
assert_in_range!(value, 0, 100);

// String assertions  
assert_contains_substring!(text, "needle");

// HTTP status assertions
assert_http_success!(200);
assert_http_error!(404);
```

### 6. Test Environment Utilities

Manage test environment and temporary resources:

```rust
// Environment setup/cleanup
TestEnvironment::setup();
TestEnvironment::cleanup();

// Execute with environment wrapper
let result = TestEnvironment::with_test_env(|| async {
    // Test code here
}).await;

// Work with temporary files
TestEnvironment::with_temp_file(content, |path| async move {
    // Test with temporary file
}).await;
```

### 7. Mock Response Helpers

Create consistent mock HTTP responses:

```rust
// Basic mock response with headers
let response = create_mock_response(200);

// JSON response
let json_response = create_json_response(200, &data);
```

## Benefits

### Code Duplication Elimination

**Before:**
```rust
#[tokio::test]
async fn test_file_analysis() {
    // 20+ lines of boilerplate setup
    let mock_server = MockServer::start().await;
    let client = ClientBuilder::new()
        .api_key("test_key")
        .tier(ApiTier::Premium)
        .base_url(mock_server.uri())
        .build().unwrap();
    
    // Manual JSON construction - error prone
    let sample_data = json!({
        "type": "file",
        "id": "hash123", 
        "attributes": {
            // ... lots more JSON
        }
    });
    
    // Manual response setup
    let response = ResponseTemplate::new(200)
        .append_header("Content-Type", "application/json")
        .set_body_json(&json!({"data": sample_data}));
        
    // Manual assertions
    let stats = result["attributes"]["last_analysis_stats"];
    assert_eq!(stats["malicious"], 0);
    assert_eq!(stats["suspicious"], 0);
    // etc...
}
```

**After:**
```rust
#[tokio::test] 
async fn test_file_analysis() {
    let mock_client = MockApiClient::new().await.unwrap();
    let file_data = FileResponseBuilder::clean_file().build();
    let response = ResponseFactory::success_response(file_data);
    
    Mock::given(method("GET"))
        .and(path("/files/test"))
        .and(header("x-apikey", constants::TEST_API_KEY))
        .respond_with(create_json_response(200, &response))
        .mount(mock_client.mock_server())
        .await;
        
    let result = mock_client.client().get("files/test").await;
    let stats: AnalysisStats = serde_json::from_value(
        result.unwrap()["data"]["attributes"]["last_analysis_stats"].clone()
    ).unwrap();
    
    assert_analysis_clean!(stats);
}
```

### Improved Readability

The new utilities make test intentions clear:
- `FileResponseBuilder::malicious_file()` vs manual JSON construction
- `assert_analysis_clean!(stats)` vs multiple individual assertions  
- `ResponseFactory::rate_limit_error()` vs manual error JSON

### Type Safety

Builders provide compile-time safety while maintaining flexibility:
```rust
let stats = AnalysisStatsBuilder::new()
    .with_harmless(80)    // Type-safe u32
    .with_malicious(5)    // Type-safe u32  
    .build();             // Returns AnalysisStats struct
```

### Consistency

All tests use the same constants, reducing magic strings and ensuring consistent behavior.

## Usage Examples

### Complete File Analysis Test

```rust
#[tokio::test]
async fn test_complete_file_analysis() {
    let mock_client = MockApiClient::new().await.unwrap();
    
    // Test clean file
    let clean_file = FileResponseBuilder::clean_file()
        .with_names(vec!["document.pdf".to_string()])
        .build();
    
    Mock::given(method("GET"))
        .and(path("/files/clean-hash"))  
        .and(header("x-apikey", constants::TEST_API_KEY))
        .respond_with(create_json_response(200, 
            &ResponseFactory::success_response(clean_file)))
        .mount(mock_client.mock_server())
        .await;
        
    let result = mock_client.client().get("files/clean-hash").await;
    let file_data = result.unwrap()["data"].clone();
    let stats: AnalysisStats = serde_json::from_value(
        file_data["attributes"]["last_analysis_stats"].clone()
    ).unwrap();
    
    assert_analysis_clean!(stats);
    assert_contains_substring!(
        file_data["attributes"]["names"][0].as_str().unwrap(),
        "document"
    );
}
```

### Error Handling Test

```rust
#[tokio::test]
async fn test_error_handling() {
    let mock_client = MockApiClient::new().await.unwrap();
    
    let (status, error_response) = ResponseFactory::rate_limit_error();
    Mock::given(method("GET"))
        .and(path("/rate-limited"))
        .and(header("x-apikey", constants::TEST_API_KEY))
        .respond_with(create_json_response(status, &error_response))
        .mount(mock_client.mock_server())
        .await;
        
    let result = mock_client.client().get("rate-limited").await;
    match result {
        Err(Error::QuotaExceeded(_)) => {}, // Expected
        _ => panic!("Expected quota exceeded error"),
    }
}
```

### Collection Test

```rust  
#[tokio::test]
async fn test_file_collection() {
    let mock_client = MockApiClient::new().await.unwrap();
    
    let files = vec![
        FileResponseBuilder::new("hash1").build(),
        FileResponseBuilder::new("hash2").build(),
    ];
    
    let response = ResponseFactory::collection_response(
        files, 
        Some("next-cursor")
    );
    
    Mock::given(method("GET"))
        .and(path("/files"))
        .and(header("x-apikey", constants::TEST_API_KEY))
        .respond_with(create_json_response(200, &response))
        .mount(mock_client.mock_server())
        .await;
        
    let result = mock_client.client().get("files").await.unwrap();
    assert_eq!(result["data"].as_array().unwrap().len(), 2);
    assert_contains_substring!(
        result["links"]["next"].as_str().unwrap(),
        "next-cursor" 
    );
}
```

## Files Created/Modified

1. **`src/test_utils.rs`** - Main test utilities module (NEW)
2. **`src/lib.rs`** - Added test_utils module export (MODIFIED)  
3. **`src/tests/test_utils.rs`** - Updated for backward compatibility (MODIFIED)
4. **`src/tests/mod.rs`** - Added new test modules (MODIFIED)
5. **`src/tests/example_with_new_utilities.rs`** - Usage examples (NEW)
6. **`src/tests/test_utilities_tests.rs`** - Tests for utilities (NEW) 
7. **`src/tests/refactored_example.rs`** - Before/after examples (NEW)
8. **`Cargo.toml`** - Added tempfile dependency (MODIFIED)

## Test Coverage

The test utilities themselves have comprehensive test coverage with 23 tests covering:
- Constant validation
- Builder pattern functionality  
- Response factory methods
- Mock client creation
- Assertion macro behavior
- Error scenarios
- Environment utilities
- Fluent API chains

## Migration Guide

To migrate existing tests:

1. Replace manual mock server setup with `MockApiClient::new()`
2. Replace manual JSON construction with builder patterns
3. Replace manual assertions with custom assertion macros
4. Use constants instead of hardcoded test values
5. Use `ResponseFactory` for consistent error responses

The old `TestUtils` struct remains available for backward compatibility.

## Future Enhancements

Potential future improvements:
- Additional builders for other resource types (URLs, comments, etc.)
- Property-based testing utilities  
- Performance testing helpers
- Integration test utilities
- More specialized assertion macros

This test infrastructure significantly improves the development experience and code quality by eliminating duplication, improving readability, and ensuring consistency across all tests.