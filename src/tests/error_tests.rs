use crate::error::{ApiError, Error};
use reqwest::StatusCode;

#[test]
fn test_error_bad_request() {
    let error = Error::BadRequest("Invalid parameter".to_string());

    let error_str = format!("{}", error);
    assert!(error_str.contains("Bad request"));
    assert!(error_str.contains("Invalid parameter"));
}

#[test]
fn test_error_json() {
    let json_error = serde_json::from_str::<String>("invalid json").unwrap_err();
    let error = Error::Json(json_error);

    let error_str = format!("{}", error);
    assert!(error_str.contains("JSON"));
}

#[test]
fn test_error_invalid_argument() {
    let error = Error::InvalidArgument("Invalid parameter".to_string());

    let error_str = format!("{}", error);
    assert!(error_str.contains("Invalid argument"));
    assert!(error_str.contains("Invalid parameter"));
}

#[test]
fn test_error_authentication_required() {
    let error = Error::AuthenticationRequired;

    let error_str = format!("{}", error);
    assert!(error_str.contains("Authentication required"));
}

#[test]
fn test_error_forbidden() {
    let error = Error::Forbidden;

    let error_str = format!("{}", error);
    assert!(error_str.contains("Forbidden"));
}

#[test]
fn test_error_not_found() {
    let error = Error::NotFound;

    let error_str = format!("{}", error);
    assert!(error_str.contains("Resource not found"));
}

#[test]
fn test_error_quota_exceeded() {
    let error = Error::QuotaExceeded("Daily limit reached".to_string());

    let error_str = format!("{}", error);
    assert!(error_str.contains("Daily limit reached"));
}

#[test]
fn test_error_too_many_requests() {
    let error = Error::TooManyRequests;

    let error_str = format!("{}", error);
    assert!(error_str.contains("Too many requests"));
}

#[test]
fn test_error_transient() {
    let error = Error::TransientError;

    let error_str = format!("{}", error);
    assert!(error_str.contains("Transient server error"));
}

#[test]
fn test_error_wrong_credentials() {
    let error = Error::WrongCredentials;

    let error_str = format!("{}", error);
    assert!(error_str.contains("Wrong credentials"));
}

#[test]
fn test_error_unknown() {
    let error = Error::Unknown("Unknown error occurred".to_string());

    let error_str = format!("{}", error);
    assert!(error_str.contains("Unknown error occurred"));
}

#[test]
fn test_error_from_response() {
    let api_error = ApiError {
        message: "Test error".to_string(),
        code: "BadRequestError".to_string(),
    };

    let error = Error::from_response(StatusCode::BAD_REQUEST, api_error);
    assert!(matches!(error, Error::BadRequest(_)));
}

#[test]
fn test_error_from_response_unauthorized() {
    let api_error = ApiError {
        message: "Unauthorized".to_string(),
        code: "WrongCredentialsError".to_string(),
    };

    let error = Error::from_response(StatusCode::UNAUTHORIZED, api_error);
    assert!(matches!(error, Error::WrongCredentials));
}

#[test]
fn test_error_from_response_forbidden() {
    let api_error = ApiError {
        message: "Forbidden".to_string(),
        code: "ForbiddenError".to_string(),
    };

    let error = Error::from_response(StatusCode::FORBIDDEN, api_error);
    assert!(matches!(error, Error::Forbidden));
}

#[test]
fn test_error_from_response_not_found() {
    let api_error = ApiError {
        message: "Not found".to_string(),
        code: "NotFoundError".to_string(),
    };

    let error = Error::from_response(StatusCode::NOT_FOUND, api_error);
    assert!(matches!(error, Error::NotFound));
}

#[test]
fn test_error_from_response_quota_exceeded() {
    let api_error = ApiError {
        message: "Quota exceeded".to_string(),
        code: "QuotaExceededError".to_string(),
    };

    let error = Error::from_response(StatusCode::TOO_MANY_REQUESTS, api_error);
    assert!(matches!(error, Error::QuotaExceeded(_)));
}

#[test]
fn test_error_from_response_too_many_requests() {
    let api_error = ApiError {
        message: "Too many requests".to_string(),
        code: "TooManyRequestsError".to_string(),
    };

    let error = Error::from_response(StatusCode::TOO_MANY_REQUESTS, api_error);
    assert!(matches!(error, Error::TooManyRequests));
}
