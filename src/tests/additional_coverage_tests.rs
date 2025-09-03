// Additional tests to improve coverage without compilation errors

use crate::analysis::{Analysis, AnalysisAttributes, AnalysisStatus, Verdict};
use crate::common::AnalysisStats;
use crate::error::Error;
use crate::objects::Object;

#[cfg(test)]
mod coverage_improvement_tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn test_analysis_completed_status() {
        let analysis = create_test_analysis(AnalysisStatus::Completed);
        assert!(analysis.is_completed());
    }

    #[test]
    fn test_analysis_in_progress_status() {
        let analysis = create_test_analysis(AnalysisStatus::InProgress);
        assert!(!analysis.is_completed());
    }

    #[test]
    fn test_analysis_queued_status() {
        let analysis = create_test_analysis(AnalysisStatus::Queued);
        assert!(!analysis.is_completed());
    }

    #[test]
    fn test_verdict_malicious() {
        let analysis = create_analysis_with_stats(5, 0, 0, 0);
        assert_eq!(analysis.get_verdict(), Some(Verdict::Malicious));
    }

    #[test]
    fn test_verdict_suspicious() {
        let analysis = create_analysis_with_stats(0, 3, 0, 0);
        assert_eq!(analysis.get_verdict(), Some(Verdict::Suspicious));
    }

    #[test]
    fn test_verdict_harmless() {
        let analysis = create_analysis_with_stats(0, 0, 10, 0);
        assert_eq!(analysis.get_verdict(), Some(Verdict::Harmless));
    }

    #[test]
    fn test_verdict_undetected() {
        let analysis = create_analysis_with_stats(0, 0, 0, 0);
        assert_eq!(analysis.get_verdict(), Some(Verdict::Undetected));
    }

    #[test]
    fn test_verdict_no_stats() {
        let analysis = Analysis {
            object: Object {
                object_type: "analysis".to_string(),
                id: "test".to_string(),
                links: None,
                relationships: None,
                attributes: AnalysisAttributes {
                    date: None,
                    status: Some(AnalysisStatus::Completed),
                    stats: None,
                    results: None,
                    additional_attributes: HashMap::new(),
                },
            },
        };
        assert_eq!(analysis.get_verdict(), None);
    }

    // Error module coverage
    #[test]
    fn test_all_error_retryable_status() {
        assert!(Error::TooManyRequests.is_retryable());
        assert!(Error::TransientError.is_retryable());
        assert!(Error::DeadlineExceeded.is_retryable());

        assert!(!Error::NotFound.is_retryable());
        assert!(!Error::Forbidden.is_retryable());
        assert!(!Error::AuthenticationRequired.is_retryable());
        assert!(!Error::WrongCredentials.is_retryable());
        assert!(!Error::NotAvailableYet.is_retryable());
        assert!(!Error::UserNotActive.is_retryable());
        assert!(!Error::AlreadyExists.is_retryable());
        assert!(!Error::FailedDependency.is_retryable());
        assert!(!Error::UnselectiveContentQuery.is_retryable());
        assert!(!Error::UnsupportedContentQuery.is_retryable());
        assert!(!Error::BadRequest("test".to_string()).is_retryable());
        assert!(!Error::InvalidArgument("test".to_string()).is_retryable());
        assert!(!Error::QuotaExceeded("test".to_string()).is_retryable());
        assert!(!Error::Unknown("test".to_string()).is_retryable());
    }

    #[test]
    fn test_error_display_messages() {
        // Test all error variants display messages
        assert!(Error::NotAvailableYet.to_string().contains("not available"));
        assert!(Error::UnselectiveContentQuery
            .to_string()
            .contains("not selective"));
        assert!(Error::UnsupportedContentQuery
            .to_string()
            .contains("Unsupported"));
        assert!(Error::AuthenticationRequired
            .to_string()
            .contains("Authentication"));
        assert!(Error::UserNotActive.to_string().contains("not active"));
        assert!(Error::WrongCredentials
            .to_string()
            .contains("Wrong credentials"));
        assert!(Error::Forbidden.to_string().contains("Forbidden"));
        assert!(Error::NotFound.to_string().contains("not found"));
        assert!(Error::AlreadyExists.to_string().contains("already exists"));
        assert!(Error::FailedDependency.to_string().contains("Failed"));
        assert!(Error::TooManyRequests.to_string().contains("Too many"));
        assert!(Error::TransientError.to_string().contains("Transient"));
        assert!(Error::DeadlineExceeded.to_string().contains("deadline"));
    }

    // Helper functions
    fn create_test_analysis(status: AnalysisStatus) -> Analysis {
        Analysis {
            object: Object {
                object_type: "analysis".to_string(),
                id: "test".to_string(),
                links: None,
                relationships: None,
                attributes: AnalysisAttributes {
                    date: Some(1234567890),
                    status: Some(status),
                    stats: None,
                    results: None,
                    additional_attributes: HashMap::new(),
                },
            },
        }
    }

    fn create_analysis_with_stats(
        malicious: u32,
        suspicious: u32,
        harmless: u32,
        undetected: u32,
    ) -> Analysis {
        Analysis {
            object: Object {
                object_type: "analysis".to_string(),
                id: "test".to_string(),
                links: None,
                relationships: None,
                attributes: AnalysisAttributes {
                    date: None,
                    status: Some(AnalysisStatus::Completed),
                    stats: Some(AnalysisStats {
                        harmless,
                        malicious,
                        suspicious,
                        undetected,
                        timeout: 0,
                        confirmed_timeout: None,
                        failure: None,
                        type_unsupported: None,
                    }),
                    results: None,
                    additional_attributes: HashMap::new(),
                },
            },
        }
    }
}

// Additional tests for uncovered client methods
#[cfg(test)]
mod client_coverage_tests {
    use crate::auth::ApiTier;
    use crate::client::ClientBuilder;

    #[test]
    fn test_client_builder_with_public_tier() {
        let result = ClientBuilder::new()
            .api_key("test_key")
            .tier(ApiTier::Public)
            .build();

        assert!(result.is_ok());
        let client = result.unwrap();
        assert_eq!(client.api_key(), "test_key");
    }

    #[test]
    fn test_client_builder_default_timeout() {
        let result = ClientBuilder::new().api_key("test_key").build();

        assert!(result.is_ok());
    }

    #[test]
    fn test_client_methods_exist() {
        let client = ClientBuilder::new().api_key("test_key").build().unwrap();

        // Test that all client methods exist and return correct types
        let _ = client.files();
        let _ = client.domains();
        let _ = client.ip_addresses();
        let _ = client.sigma_rules();
        let _ = client.yara_rulesets();
    }
}

// Tests for common module structures
#[cfg(test)]
mod common_coverage_tests {
    use crate::common::{AnalysisResult, VoteStats};

    #[test]
    fn test_analysis_result_creation() {
        let result = AnalysisResult {
            category: "malicious".to_string(),
            result: Some("Trojan.Generic".to_string()),
            method: "signature".to_string(),
            engine_name: "TestEngine".to_string(),
            engine_version: Some("1.0".to_string()),
            engine_update: Some("20240101".to_string()),
        };

        assert_eq!(result.category, "malicious");
        assert_eq!(result.engine_name, "TestEngine");
        assert!(result.result.is_some());
    }

    #[test]
    fn test_vote_stats_creation() {
        let stats = VoteStats {
            harmless: 25,
            malicious: 5,
        };

        assert_eq!(stats.harmless, 25);
        assert_eq!(stats.malicious, 5);
    }

    #[test]
    fn test_analysis_stats_all_fields() {
        use crate::common::AnalysisStats;

        let stats = AnalysisStats {
            harmless: 10,
            malicious: 2,
            suspicious: 1,
            undetected: 5,
            timeout: 0,
            confirmed_timeout: Some(0),
            failure: Some(0),
            type_unsupported: Some(0),
        };

        assert_eq!(stats.harmless, 10);
        assert_eq!(stats.malicious, 2);
        assert_eq!(stats.suspicious, 1);
        assert_eq!(stats.undetected, 5);
        assert_eq!(stats.timeout, 0);
        assert_eq!(stats.confirmed_timeout, Some(0));
        assert_eq!(stats.failure, Some(0));
        assert_eq!(stats.type_unsupported, Some(0));
    }
}

// Tests for rate limiting
#[cfg(test)]
mod rate_limit_coverage_tests {
    use crate::auth::ApiTier;
    use crate::rate_limit::{RateLimitError, RateLimiter};

    #[tokio::test]
    async fn test_rate_limiter_public_tier() {
        let limiter = RateLimiter::new(ApiTier::Public);
        // Public tier has rate limits but check_rate_limit should work
        let result = limiter.check_rate_limit().await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_rate_limiter_premium_tier() {
        let limiter = RateLimiter::new(ApiTier::Premium);
        // Premium tier has no rate limits
        let result = limiter.check_rate_limit().await;
        assert!(result.is_ok());
    }

    #[test]
    fn test_rate_limit_error_display() {
        let error = RateLimitError::DailyQuotaExceeded;
        // Just verify it converts to string without checking exact content
        let _ = error.to_string();
    }
}

// Tests for object operations
#[cfg(test)]
mod objects_coverage_tests {
    use crate::objects::{Collection, CollectionMeta, Links};
    #[allow(unused_imports)]
    use std::collections::HashMap;

    // These object operations tests are now covered by the individual test files using macros
    // Removed duplicated functions: test_file_object_operations, test_domain_object_operations, test_ip_object_operations

    #[test]
    fn test_links_creation() {
        let links = Links {
            self_link: "https://example.com/self".to_string(),
            next: Some("https://example.com/next".to_string()),
            related: None,
        };

        assert_eq!(links.self_link, "https://example.com/self");
        assert!(links.next.is_some());
        assert!(links.related.is_none());
    }

    #[test]
    fn test_collection_meta_creation() {
        let meta = CollectionMeta {
            cursor: Some("cursor123".to_string()),
            count: Some(50),
        };

        assert_eq!(meta.cursor, Some("cursor123".to_string()));
        assert_eq!(meta.count, Some(50));
    }

    #[test]
    fn test_collection_creation() {
        let collection: Collection<String> = Collection {
            data: vec!["item1".to_string(), "item2".to_string()],
            meta: None,
            links: None,
        };

        assert_eq!(collection.data.len(), 2);
        assert_eq!(collection.data[0], "item1");
        assert!(collection.meta.is_none());
        assert!(collection.links.is_none());
    }
}
