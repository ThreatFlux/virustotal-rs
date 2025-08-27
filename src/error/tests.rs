#[cfg(test)]
mod unit_tests {
    use crate::error::*;
    use std::time::Duration;

    #[test]
    fn test_error_from_response() {
        let error = ApiError {
            code: "BadRequestError".to_string(),
            message: "Invalid request".to_string(),
        };

        let err = Error::from_response(reqwest::StatusCode::BAD_REQUEST, error);
        match err {
            Error::BadRequest(msg) => assert_eq!(msg, "Invalid request"),
            _ => panic!("Expected BadRequest error"),
        }
    }

    #[test]
    fn test_retryable_errors() {
        assert!(Error::TooManyRequests.is_retryable());
        assert!(Error::TransientError.is_retryable());
        assert!(Error::DeadlineExceeded.is_retryable());
        assert!(!Error::NotFound.is_retryable());
        assert!(!Error::Forbidden.is_retryable());
    }

    #[test]
    fn test_error_categorization() {
        let auth_error = Error::AuthenticationRequired;
        assert_eq!(auth_error.category(), ErrorCategory::Authentication);
        assert!(auth_error.is_authentication_error());

        let client_error = Error::bad_request("test");
        assert_eq!(client_error.category(), ErrorCategory::Client);
        assert!(client_error.is_client_error());

        let server_error = Error::TransientError;
        assert_eq!(server_error.category(), ErrorCategory::Server);
        assert!(server_error.is_server_error());

        let rate_limit_error = Error::TooManyRequests;
        assert_eq!(rate_limit_error.category(), ErrorCategory::RateLimit);
        assert!(rate_limit_error.is_rate_limit_error());
    }

    #[test]
    fn test_error_severity() {
        let low_error = Error::NotAvailableYet;
        assert_eq!(low_error.severity(), ErrorSeverity::Low);

        let medium_error = Error::bad_request("test");
        assert_eq!(medium_error.severity(), ErrorSeverity::Medium);

        let high_error = Error::AuthenticationRequired;
        assert_eq!(high_error.severity(), ErrorSeverity::High);

        let critical_error = Error::UserNotActive;
        assert_eq!(critical_error.severity(), ErrorSeverity::Critical);
    }

    #[test]
    fn test_error_context() {
        let context = ErrorContext::with_operation("test_op")
            .with_resource("/api/test")
            .with_metadata("key", "value")
            .with_request_id("req-123");

        assert_eq!(context.operation.as_ref().unwrap(), "test_op");
        assert_eq!(context.resource.as_ref().unwrap(), "/api/test");
        assert_eq!(context.metadata.get("key").unwrap(), "value");
        assert_eq!(context.request_id.as_ref().unwrap(), "req-123");
    }

    #[test]
    fn test_error_chain() {
        let json_error = serde_json::from_str::<i32>("invalid").unwrap_err();
        let error = Error::Json(json_error);
        let chain = error.error_chain();
        assert!(chain.len() > 1);
        assert!(chain[0].contains("JSON parsing error"));
    }

    #[test]
    fn test_detailed_report() {
        let error = Error::bad_request("test error");
        let report = error.detailed_report();
        assert!(report.contains("Error: Bad request: test error"));
        assert!(report.contains("Category: Client"));
        assert!(report.contains("Severity: Medium"));
        assert!(report.contains("Retryable: false"));
    }

    #[test]
    fn test_api_error_detector() {
        use utils::ApiErrorDetector;

        assert!(ApiErrorDetector::is_rate_limited(
            reqwest::StatusCode::TOO_MANY_REQUESTS,
            ""
        ));
        assert!(ApiErrorDetector::is_rate_limited(
            reqwest::StatusCode::OK,
            "rate limit exceeded"
        ));

        assert!(ApiErrorDetector::is_quota_exceeded(
            reqwest::StatusCode::TOO_MANY_REQUESTS,
            ""
        ));
        assert!(ApiErrorDetector::is_quota_exceeded(
            reqwest::StatusCode::OK,
            "quota exceeded"
        ));

        assert!(ApiErrorDetector::is_auth_error(
            reqwest::StatusCode::UNAUTHORIZED,
            ""
        ));
        assert!(ApiErrorDetector::is_auth_error(
            reqwest::StatusCode::OK,
            "unauthorized"
        ));

        assert!(ApiErrorDetector::is_temporary(
            reqwest::StatusCode::SERVICE_UNAVAILABLE,
            ""
        ));
        assert!(ApiErrorDetector::is_temporary(
            reqwest::StatusCode::OK,
            "temporary error"
        ));
    }

    #[test]
    fn test_retry_policy() {
        use utils::RetryPolicy;

        let policy = RetryPolicy::default_api();
        let error = Error::TooManyRequests;

        assert!(policy.should_retry(&error, 0));
        assert!(policy.should_retry(&error, 1));
        assert!(policy.should_retry(&error, 2));
        assert!(!policy.should_retry(&error, 3));

        let non_retryable = Error::bad_request("test");
        assert!(!policy.should_retry(&non_retryable, 0));

        let delay = policy.delay_for_attempt(1, &error);
        assert!(delay >= Duration::from_millis(100));
        assert!(delay <= Duration::from_secs(60));
    }

    #[test]
    fn test_error_macros() {
        use crate::{bail_if, ensure};

        // Test bail_if macro
        fn test_bail_if(should_fail: bool) -> Result<()> {
            bail_if!(should_fail, Error::bad_request("test error"));
            Ok(())
        }

        assert!(test_bail_if(true).is_err());
        assert!(test_bail_if(false).is_ok());

        // Test ensure macro
        fn test_ensure(condition: bool) -> Result<()> {
            ensure!(condition, Error::bad_request("condition failed"));
            Ok(())
        }

        assert!(test_ensure(true).is_ok());
        assert!(test_ensure(false).is_err());
    }

    #[test]
    fn test_error_constructor_methods() {
        let error = Error::bad_request("test message");
        match error {
            Error::BadRequest(msg) => assert_eq!(msg, "test message"),
            _ => panic!("Expected BadRequest error"),
        }

        let error = Error::quota_exceeded("quota limit reached");
        match error {
            Error::QuotaExceeded(msg) => assert_eq!(msg, "quota limit reached"),
            _ => panic!("Expected QuotaExceeded error"),
        }

        let error = Error::configuration("config error");
        match error {
            Error::Configuration { message } => assert_eq!(message, "config error"),
            _ => panic!("Expected Configuration error"),
        }

        let error = Error::validation("validation error", Some("field".to_string()));
        match error {
            Error::Validation { message, field } => {
                assert_eq!(message, "validation error");
                assert_eq!(field.unwrap(), "field");
            }
            _ => panic!("Expected Validation error"),
        }

        let error = Error::io_error("IO error");
        match error {
            Error::Io { message } => assert_eq!(message, "IO error"),
            _ => panic!("Expected IO error"),
        }
    }

    #[test]
    fn test_error_conversion_trait() {
        use utils::ErrorConversion;

        let io_error = std::io::Error::new(std::io::ErrorKind::NotFound, "File not found");
        let vt_error = io_error.to_bad_request("Failed to read config");
        match vt_error {
            Error::BadRequest(msg) => assert!(msg.contains("Failed to read config")),
            _ => panic!("Expected BadRequest error"),
        }

        let io_error = std::io::Error::new(std::io::ErrorKind::PermissionDenied, "Access denied");
        let vt_error = io_error.to_config_error("Configuration access failed");
        match vt_error {
            Error::Configuration { message } => {
                assert!(message.contains("Configuration access failed"))
            }
            _ => panic!("Expected Configuration error"),
        }

        let io_error = std::io::Error::new(std::io::ErrorKind::InvalidInput, "Invalid input");
        let vt_error =
            io_error.to_validation_error("Validation failed", Some("input_field".to_string()));
        match vt_error {
            Error::Validation { message, field } => {
                assert!(message.contains("Validation failed"));
                assert_eq!(field.unwrap(), "input_field");
            }
            _ => panic!("Expected Validation error"),
        }

        let io_error = std::io::Error::new(std::io::ErrorKind::BrokenPipe, "Broken pipe");
        let vt_error = io_error.to_io_error("Network operation failed");
        match vt_error {
            Error::Io { message } => assert!(message.contains("Network operation failed")),
            _ => panic!("Expected IO error"),
        }
    }
}
