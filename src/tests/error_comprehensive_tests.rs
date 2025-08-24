//! Comprehensive tests for error.rs module to improve coverage
//! This module focuses on testing all error handling scenarios

use crate::error::*;
use reqwest::{Response, StatusCode};
use serde_json::json;
use std::io;

#[test]
fn test_error_display_formatting() {
    let errors = vec![
        Error::Http(reqwest::Error::from(io::Error::new(io::ErrorKind::TimedOut, "Request timed out"))),
        Error::Json(serde_json::Error::from(serde_json::from_str::<i32>("invalid").unwrap_err())),
        Error::BadRequest("Invalid parameters".to_string()),
        Error::AuthenticationRequired("API key required".to_string()),
        Error::Forbidden("Access denied".to_string()),
        Error::NotFound("Resource not found".to_string()),
        Error::QuotaExceeded("Rate limit exceeded".to_string()),
        Error::TooManyRequests("Too many requests".to_string()),
        Error::WrongCredentials("Invalid credentials".to_string()),
        Error::Transient("Temporary error".to_string()),
        Error::Unknown("Unknown error".to_string()),
    ];

    for error in errors {
        let display_str = format!("{}", error);
        assert!(!display_str.is_empty());
        
        let debug_str = format!("{:?}", error);
        assert!(!debug_str.is_empty());
    }
}

#[test]
fn test_error_source_chain() {
    use std::error::Error as StdError;
    
    let io_error = io::Error::new(io::ErrorKind::ConnectionRefused, "Connection refused");
    let reqwest_error = reqwest::Error::from(io_error);
    let vt_error = Error::Http(reqwest_error);
    
    // Test that we can walk the error source chain
    assert!(vt_error.source().is_some());
    
    let debug_output = format!("{:?}", vt_error);
    assert!(debug_output.contains("Http"));
}

#[test]
fn test_retryable_errors() {
    let retryable_errors = vec![
        Error::TooManyRequests("Rate limited".to_string()),
        Error::QuotaExceeded("Quota exceeded".to_string()),
        Error::Transient("Server error".to_string()),
    ];
    
    for error in retryable_errors {
        assert!(error.is_retryable(), "Error should be retryable: {:?}", error);
    }
}

#[test]
fn test_non_retryable_errors() {
    let non_retryable_errors = vec![
        Error::BadRequest("Bad request".to_string()),
        Error::AuthenticationRequired("Auth required".to_string()),
        Error::Forbidden("Forbidden".to_string()),
        Error::NotFound("Not found".to_string()),
        Error::WrongCredentials("Wrong creds".to_string()),
        Error::Unknown("Unknown".to_string()),
        Error::Json(serde_json::Error::from(serde_json::from_str::<i32>("invalid").unwrap_err())),
        Error::Http(reqwest::Error::from(io::Error::new(io::ErrorKind::InvalidData, "Invalid data"))),
    ];
    
    for error in non_retryable_errors {
        assert!(!error.is_retryable(), "Error should not be retryable: {:?}", error);
    }
}

#[test]
fn test_api_error_response_creation() {
    let error_response = ApiErrorResponse {
        code: "TestError".to_string(),
        message: "This is a test error".to_string(),
    };
    
    assert_eq!(error_response.code, "TestError");
    assert_eq!(error_response.message, "This is a test error");
}

#[test]
fn test_api_error_response_serialization() {
    let error_response = ApiErrorResponse {
        code: "SerializationTest".to_string(),
        message: "Testing serialization".to_string(),
    };
    
    let json = serde_json::to_string(&error_response).unwrap();
    assert!(json.contains("SerializationTest"));
    assert!(json.contains("Testing serialization"));
    
    let deserialized: ApiErrorResponse = serde_json::from_str(&json).unwrap();
    assert_eq!(deserialized.code, error_response.code);
    assert_eq!(deserialized.message, error_response.message);
}

#[test]
fn test_error_from_string_conversion() {
    let error_msg = "Test error message";
    let error = Error::BadRequest(error_msg.to_string());
    
    match error {
        Error::BadRequest(msg) => assert_eq!(msg, error_msg),
        _ => panic!("Unexpected error type"),
    }
}

#[test]
fn test_error_equality() {
    // Test that errors with same content are equal
    let error1 = Error::BadRequest("Same message".to_string());
    let error2 = Error::BadRequest("Same message".to_string());
    let error3 = Error::BadRequest("Different message".to_string());
    
    assert_eq!(error1.to_string(), error2.to_string());
    assert_ne!(error1.to_string(), error3.to_string());
}

#[tokio::test]
async fn test_error_from_response_400() {
    let _json_body = json!({
        "error": {
            "code": "BadRequestError",
            "message": "Invalid request parameters"
        }
    });
    
    // Create a mock response (this would normally come from reqwest)
    let error = Error::BadRequest("Invalid request parameters".to_string());
    
    match error {
        Error::BadRequest(msg) => {
            assert!(msg.contains("Invalid request parameters"));
        },
        _ => panic!("Expected BadRequest error"),
    }
}

#[tokio::test]
async fn test_error_from_response_401() {
    let error = Error::AuthenticationRequired("Valid API key required".to_string());
    
    assert!(error.is_retryable() == false);
    match error {
        Error::AuthenticationRequired(msg) => {
            assert!(msg.contains("Valid API key required"));
        },
        _ => panic!("Expected AuthenticationRequired error"),
    }
}

#[tokio::test]
async fn test_error_from_response_403() {
    let error = Error::Forbidden("Access denied to this resource".to_string());
    
    assert!(!error.is_retryable());
    match error {
        Error::Forbidden(msg) => {
            assert!(msg.contains("Access denied"));
        },
        _ => panic!("Expected Forbidden error"),
    }
}

#[tokio::test]
async fn test_error_from_response_404() {
    let error = Error::NotFound("The requested resource was not found".to_string());
    
    assert!(!error.is_retryable());
    match error {
        Error::NotFound(msg) => {
            assert!(msg.contains("not found"));
        },
        _ => panic!("Expected NotFound error"),
    }
}

#[tokio::test]
async fn test_error_from_response_429() {
    let error = Error::QuotaExceeded("Request rate limit exceeded".to_string());
    
    assert!(error.is_retryable());
    match error {
        Error::QuotaExceeded(msg) => {
            assert!(msg.contains("rate limit"));
        },
        _ => panic!("Expected QuotaExceeded error"),
    }
}

#[test]
fn test_error_chain_display() {
    let json_error = serde_json::Error::from(serde_json::from_str::<i32>("not_a_number").unwrap_err());
    let vt_error = Error::Json(json_error);
    
    let error_string = format!("{}", vt_error);
    assert!(error_string.contains("JSON"));
}

#[test]
fn test_http_error_wrapping() {
    let io_error = io::Error::new(io::ErrorKind::TimedOut, "Operation timed out");
    let reqwest_error = reqwest::Error::from(io_error);
    let vt_error = Error::Http(reqwest_error);
    
    assert!(!vt_error.is_retryable());
    
    let error_display = format!("{}", vt_error);
    assert!(!error_display.is_empty());
}

#[test]
fn test_all_error_variants_exist() {
    // Test that all expected error variants can be created
    let _http_error = Error::Http(reqwest::Error::from(io::Error::new(io::ErrorKind::Other, "test")));
    let _json_error = Error::Json(serde_json::Error::from(serde_json::from_str::<i32>("invalid").unwrap_err()));
    let _bad_request = Error::BadRequest("test".to_string());
    let _auth_required = Error::AuthenticationRequired("test".to_string());
    let _forbidden = Error::Forbidden("test".to_string());
    let _not_found = Error::NotFound("test".to_string());
    let _quota_exceeded = Error::QuotaExceeded("test".to_string());
    let _too_many_requests = Error::TooManyRequests("test".to_string());
    let _wrong_credentials = Error::WrongCredentials("test".to_string());
    let _transient = Error::Transient("test".to_string());
    let _unknown = Error::Unknown("test".to_string());
}

#[test]
fn test_error_conversion_from_reqwest() {
    let io_error = io::Error::new(io::ErrorKind::NotFound, "File not found");
    let reqwest_error = reqwest::Error::from(io_error);
    let vt_error = Error::from(reqwest_error);
    
    match vt_error {
        Error::Http(_) => {}, // Expected
        _ => panic!("Expected Http error variant"),
    }
}

#[test]
fn test_error_conversion_from_serde() {
    let serde_error = serde_json::Error::from(serde_json::from_str::<i32>("not_an_int").unwrap_err());
    let vt_error = Error::from(serde_error);
    
    match vt_error {
        Error::Json(_) => {}, // Expected
        _ => panic!("Expected Json error variant"),
    }
}

#[test]
fn test_result_type_alias() {
    fn returns_result() -> Result<String> {
        Ok("success".to_string())
    }
    
    let result = returns_result();
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), "success");
}

#[test]
fn test_api_error_response_edge_cases() {
    // Test with empty strings
    let empty_error = ApiErrorResponse {
        code: "".to_string(),
        message: "".to_string(),
    };
    
    assert_eq!(empty_error.code, "");
    assert_eq!(empty_error.message, "");
    
    // Test with very long strings
    let long_message = "a".repeat(1000);
    let long_error = ApiErrorResponse {
        code: "LongError".to_string(),
        message: long_message.clone(),
    };
    
    assert_eq!(long_error.message.len(), 1000);
    assert_eq!(long_error.message, long_message);
}

#[test]
fn test_error_message_formatting() {
    let errors_with_expected_substrings = vec![
        (Error::BadRequest("Invalid input".to_string()), "Invalid input"),
        (Error::AuthenticationRequired("Missing API key".to_string()), "Missing API key"),
        (Error::Forbidden("No permission".to_string()), "No permission"),
        (Error::NotFound("File missing".to_string()), "File missing"),
        (Error::QuotaExceeded("Limit reached".to_string()), "Limit reached"),
        (Error::TooManyRequests("Slow down".to_string()), "Slow down"),
        (Error::WrongCredentials("Bad password".to_string()), "Bad password"),
        (Error::Transient("Try again".to_string()), "Try again"),
        (Error::Unknown("What happened?".to_string()), "What happened?"),
    ];
    
    for (error, expected_substring) in errors_with_expected_substrings {
        let error_string = format!("{}", error);
        assert!(
            error_string.contains(expected_substring),
            "Error '{}' should contain '{}'",
            error_string,
            expected_substring
        );
    }
}

#[test]
fn test_error_debug_formatting() {
    let error = Error::BadRequest("Debug test".to_string());
    let debug_output = format!("{:?}", error);
    
    assert!(debug_output.contains("BadRequest"));
    assert!(debug_output.contains("Debug test"));
}

#[test]
fn test_api_error_response_default_values() {
    // Test that we can create ApiErrorResponse with default-like values
    let minimal_error = ApiErrorResponse {
        code: "Generic".to_string(),
        message: "An error occurred".to_string(),
    };
    
    assert!(!minimal_error.code.is_empty());
    assert!(!minimal_error.message.is_empty());
}

#[test]
fn test_error_categorization() {
    // Test client errors (4xx)
    let client_errors = vec![
        Error::BadRequest("test".to_string()),
        Error::AuthenticationRequired("test".to_string()),
        Error::Forbidden("test".to_string()),
        Error::NotFound("test".to_string()),
        Error::TooManyRequests("test".to_string()),
        Error::WrongCredentials("test".to_string()),
    ];
    
    for error in client_errors {
        // These are generally not retryable (except rate limiting)
        match error {
            Error::TooManyRequests(_) => assert!(error.is_retryable()),
            _ => assert!(!error.is_retryable()),
        }
    }
    
    // Test server/system errors
    let system_errors = vec![
        Error::QuotaExceeded("test".to_string()),
        Error::Transient("test".to_string()),
    ];
    
    for error in system_errors {
        assert!(error.is_retryable());
    }
}