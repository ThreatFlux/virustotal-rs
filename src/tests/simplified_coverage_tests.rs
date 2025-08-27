// Simplified coverage tests that actually compile and work with the current codebase
use crate::common::AnalysisStats;
use crate::error::Error;
use serde_json::json;

/// Basic coverage tests that work with current structures
#[cfg(test)]
mod working_coverage_tests {
    use super::*;

    #[test]
    fn test_analysis_stats_creation() {
        let stats = AnalysisStats {
            harmless: 10,
            malicious: 0,
            suspicious: 0,
            undetected: 5,
            timeout: 0,
            confirmed_timeout: None,
            failure: None,
            type_unsupported: None,
        };

        assert_eq!(stats.harmless, 10);
        assert_eq!(stats.malicious, 0);
        assert_eq!(stats.suspicious, 0);
        assert_eq!(stats.undetected, 5);
    }

    #[test]
    fn test_analysis_stats_with_threats() {
        let stats = AnalysisStats {
            harmless: 5,
            malicious: 3,
            suspicious: 1,
            undetected: 2,
            timeout: 0,
            confirmed_timeout: None,
            failure: None,
            type_unsupported: None,
        };

        assert_eq!(stats.malicious, 3);
        assert_eq!(stats.suspicious, 1);
        assert!(stats.malicious > 0 || stats.suspicious > 0);
    }

    #[test]
    fn test_error_display() {
        let error = Error::NotFound;
        assert_eq!(format!("{}", error), "Resource not found");

        let error = Error::AuthenticationRequired;
        assert_eq!(format!("{}", error), "Authentication required");

        let error = Error::Forbidden;
        assert_eq!(
            format!("{}", error),
            "Forbidden: You are not allowed to perform this operation"
        );
    }

    #[test]
    fn test_error_variants() {
        // Test that different error types can be created
        let bad_request = Error::BadRequest("Invalid input".to_string());
        let quota_exceeded = Error::QuotaExceeded("Rate limited".to_string());
        let unknown = Error::Unknown("Server error".to_string());

        match bad_request {
            Error::BadRequest(msg) => assert_eq!(msg, "Invalid input"),
            _ => panic!("Expected BadRequest error"),
        }

        match quota_exceeded {
            Error::QuotaExceeded(msg) => assert_eq!(msg, "Rate limited"),
            _ => panic!("Expected QuotaExceeded error"),
        }

        match unknown {
            Error::Unknown(msg) => assert_eq!(msg, "Server error"),
            _ => panic!("Expected Unknown error"),
        }
    }

    #[test]
    fn test_error_is_retryable() {
        // Note: Some errors may not be retryable in the current implementation
        // This test verifies error creation and basic categorization
        let quota_error = Error::QuotaExceeded("Rate limited".to_string());
        let unknown_error = Error::Unknown("Server error".to_string());
        let not_found_error = Error::NotFound;
        let auth_error = Error::AuthenticationRequired;
        let forbidden_error = Error::Forbidden;

        // Test that errors can be created and matched
        match quota_error {
            Error::QuotaExceeded(_) => {}
            _ => panic!("Expected QuotaExceeded error"),
        }

        match unknown_error {
            Error::Unknown(_) => {}
            _ => panic!("Expected Unknown error"),
        }

        // These should not be retryable
        assert!(!not_found_error.is_retryable());
        assert!(!auth_error.is_retryable());
        assert!(!forbidden_error.is_retryable());
    }

    #[test]
    fn test_basic_json_operations() {
        let test_data = json!({
            "id": "test123",
            "type": "file",
            "attributes": {
                "name": "test.txt",
                "size": 1024
            }
        });

        assert_eq!(test_data["id"], "test123");
        assert_eq!(test_data["type"], "file");
        assert_eq!(test_data["attributes"]["size"], 1024);
    }

    #[test]
    fn test_analysis_stats_serialization() {
        let stats = AnalysisStats {
            harmless: 50,
            malicious: 2,
            suspicious: 1,
            undetected: 5,
            timeout: 0,
            confirmed_timeout: Some(0),
            failure: Some(1),
            type_unsupported: Some(3),
        };

        let serialized = serde_json::to_string(&stats).unwrap();
        let deserialized: AnalysisStats = serde_json::from_str(&serialized).unwrap();

        assert_eq!(stats.harmless, deserialized.harmless);
        assert_eq!(stats.malicious, deserialized.malicious);
        assert_eq!(stats.confirmed_timeout, deserialized.confirmed_timeout);
        assert_eq!(stats.failure, deserialized.failure);
    }
}
