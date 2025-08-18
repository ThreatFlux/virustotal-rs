// Comprehensive tests to improve code coverage to 80%+

use crate::analysis::{Analysis, AnalysisAttributes, AnalysisStatus, Verdict, EngineResult, AnalysisDescriptor, AnalysisResponse};
use crate::common::{AnalysisStats, AnalysisResult};
use crate::objects::{Object, CollectionIterator, Collection, CollectionMeta, Links};
use crate::files::{FileClient, FileAttributes, FileBehaviorSummary, MitreTrees, FileBehavior};
use crate::domains::{DomainClient, DomainAttributes};
use crate::ip_addresses::{IpAddressClient, IpAddressAttributes};
use crate::comments::{CommentIterator, Comment};
use crate::error::Error;
use crate::Client;
use std::collections::HashMap;

// Analysis module tests
#[cfg(test)]
mod analysis_tests {
    use super::*;

    #[test]
    fn test_analysis_is_completed() {
        let analysis = Analysis {
            object: Object {
                object_type: "analysis".to_string(),
                id: "test".to_string(),
                links: None,
                relationships: None,
                attributes: AnalysisAttributes {
                    date: Some(1234567890),
                    status: Some(AnalysisStatus::Completed),
                    stats: None,
                    results: None,
                    additional_attributes: HashMap::new(),
                },
            },
        };
        assert!(analysis.is_completed());
    }

    #[test]
    fn test_analysis_not_completed() {
        let analysis = Analysis {
            object: Object {
                object_type: "analysis".to_string(),
                id: "test".to_string(),
                links: None,
                relationships: None,
                attributes: AnalysisAttributes {
                    date: Some(1234567890),
                    status: Some(AnalysisStatus::InProgress),
                    stats: None,
                    results: None,
                    additional_attributes: HashMap::new(),
                },
            },
        };
        assert!(!analysis.is_completed());
    }

    #[test]
    fn test_analysis_not_completed_queued() {
        let analysis = Analysis {
            object: Object {
                object_type: "analysis".to_string(),
                id: "test".to_string(),
                links: None,
                relationships: None,
                attributes: AnalysisAttributes {
                    date: Some(1234567890),
                    status: Some(AnalysisStatus::Queued),
                    stats: None,
                    results: None,
                    additional_attributes: HashMap::new(),
                },
            },
        };
        assert!(!analysis.is_completed());
    }

    #[test]
    fn test_analysis_get_verdict_harmless() {
        let analysis = Analysis {
            object: Object {
                object_type: "analysis".to_string(),
                id: "test".to_string(),
                links: None,
                relationships: None,
                attributes: AnalysisAttributes {
                    date: None,
                    status: Some(AnalysisStatus::Completed),
                    stats: Some(AnalysisStats {
                        harmless: 10,
                        malicious: 0,
                        suspicious: 0,
                        undetected: 0,
                        timeout: 0,
                        confirmed_timeout: None,
                        failure: None,
                        type_unsupported: None,
                    }),
                    results: None,
                    additional_attributes: HashMap::new(),
                },
            },
        };
        assert_eq!(analysis.get_verdict(), Some(Verdict::Harmless));
    }

    #[test]
    fn test_analysis_get_verdict_undetected() {
        let analysis = Analysis {
            object: Object {
                object_type: "analysis".to_string(),
                id: "test".to_string(),
                links: None,
                relationships: None,
                attributes: AnalysisAttributes {
                    date: None,
                    status: Some(AnalysisStatus::Completed),
                    stats: Some(AnalysisStats {
                        harmless: 0,
                        malicious: 0,
                        suspicious: 0,
                        undetected: 0,
                        timeout: 0,
                        confirmed_timeout: None,
                        failure: None,
                        type_unsupported: None,
                    }),
                    results: None,
                    additional_attributes: HashMap::new(),
                },
            },
        };
        assert_eq!(analysis.get_verdict(), Some(Verdict::Undetected));
    }

    #[test]
    fn test_analysis_status_variants() {
        assert_eq!(serde_json::to_string(&AnalysisStatus::Queued).unwrap(), "\"queued\"");
        assert_eq!(serde_json::to_string(&AnalysisStatus::InProgress).unwrap(), "\"inprogress\"");
        assert_eq!(serde_json::to_string(&AnalysisStatus::Completed).unwrap(), "\"completed\"");
    }

    #[test]
    fn test_engine_result() {
        let result = EngineResult {
            category: "malicious".to_string(),
            result: "Trojan.Generic".to_string(),
            method: "signature".to_string(),
            engine_name: "TestEngine".to_string(),
            engine_version: Some("1.0".to_string()),
            engine_update: Some("20240101".to_string()),
        };
        
        let json = serde_json::to_string(&result).unwrap();
        assert!(json.contains("malicious"));
        assert!(json.contains("TestEngine"));
    }

    #[test]
    fn test_analysis_descriptor() {
        let descriptor = AnalysisDescriptor {
            object_type: "analysis".to_string(),
            id: "test-id".to_string(),
            links: Some(Links {
                self_link: "https://example.com/analysis/test-id".to_string(),
                next: None,
                related: None,
            }),
        };
        
        assert_eq!(descriptor.object_type, "analysis");
        assert_eq!(descriptor.id, "test-id");
        assert!(descriptor.links.is_some());
    }

    #[test]
    fn test_analysis_response() {
        let response = AnalysisResponse {
            data: AnalysisDescriptor {
                object_type: "analysis".to_string(),
                id: "test-id".to_string(),
                links: None,
            },
        };
        
        assert_eq!(response.data.id, "test-id");
    }
}

// Common module tests
#[cfg(test)]
mod common_tests {
    use super::*;
    use crate::common::VoteStats;

    #[test]
    fn test_analysis_result_variants() {
        let result = AnalysisResult {
            category: "harmless".to_string(),
            result: None,
            method: "signature".to_string(),
            engine_name: "TestEngine".to_string(),
            engine_version: None,
            engine_update: None,
        };
        
        let json = serde_json::to_string(&result).unwrap();
        assert!(json.contains("harmless"));
        assert!(json.contains("TestEngine"));
    }

    #[test]
    fn test_vote_stats() {
        let stats = VoteStats {
            harmless: 10,
            malicious: 2,
        };
        
        assert_eq!(stats.harmless, 10);
        assert_eq!(stats.malicious, 2);
    }
}

// Objects module tests for CollectionIterator
#[cfg(test)]
mod objects_tests {
    use super::*;

    #[test]
    fn test_collection_meta() {
        let meta = CollectionMeta {
            cursor: Some("next_cursor".to_string()),
            count: Some(100),
        };
        
        assert_eq!(meta.cursor.unwrap(), "next_cursor");
        assert_eq!(meta.count.unwrap(), 100);
    }

    #[test]
    fn test_links_structure() {
        let links = Links {
            self_link: "https://example.com/self".to_string(),
            next: Some("https://example.com/next".to_string()),
            related: Some("https://example.com/related".to_string()),
        };
        
        assert_eq!(links.self_link, "https://example.com/self");
        assert!(links.next.is_some());
        assert!(links.related.is_some());
    }
}

// Comments module tests
#[cfg(test)]
mod comments_tests {
    use super::*;
    use crate::comments::CommentAttributes;

    #[test]
    fn test_comment_structure() {
        let comment = Comment {
            object: Object {
                object_type: "comment".to_string(),
                id: "test-comment".to_string(),
                links: None,
                relationships: None,
                attributes: CommentAttributes {
                    date: 1234567890,
                    text: "Test comment".to_string(),
                    votes: HashMap::new(),
                    html: Some("<p>Test comment</p>".to_string()),
                },
            },
        };
        
        assert_eq!(comment.object.id, "test-comment");
        assert_eq!(comment.object.attributes.text, "Test comment");
        assert!(comment.object.attributes.html.is_some());
    }
}

// Error module tests
#[cfg(test)]
mod error_tests {
    use super::*;

    #[test]
    fn test_error_is_retryable() {
        assert!(Error::TooManyRequests.is_retryable());
        assert!(Error::TransientError.is_retryable());
        assert!(Error::DeadlineExceeded.is_retryable());
        assert!(!Error::NotFound.is_retryable());
        assert!(!Error::Forbidden.is_retryable());
        assert!(!Error::BadRequest("test".to_string()).is_retryable());
    }

    #[test]
    fn test_error_not_available_yet() {
        let error = Error::NotAvailableYet;
        assert!(error.to_string().contains("not available yet"));
    }

    #[test]
    fn test_error_user_not_active() {
        let error = Error::UserNotActive;
        assert!(error.to_string().contains("not active"));
    }

    #[test]
    fn test_error_already_exists() {
        let error = Error::AlreadyExists;
        assert!(error.to_string().contains("already exists"));
    }

    #[test]
    fn test_error_failed_dependency() {
        let error = Error::FailedDependency;
        assert!(error.to_string().contains("Failed dependency"));
    }

    #[test]
    fn test_error_deadline_exceeded() {
        let error = Error::DeadlineExceeded;
        assert!(error.to_string().contains("deadline exceeded"));
        assert!(error.is_retryable());
    }

    #[test]
    fn test_error_unselective_content_query() {
        let error = Error::UnselectiveContentQuery;
        assert!(error.to_string().contains("not selective enough"));
    }

    #[test]
    fn test_error_unsupported_content_query() {
        let error = Error::UnsupportedContentQuery;
        assert!(error.to_string().contains("Unsupported content"));
    }
}

// Files module comprehensive tests
#[cfg(test)]
mod files_comprehensive_tests {
    use super::*;
    use crate::files::{ProcessTreeNode, DnsLookup, IpTraffic, HttpConversation, Ja3Digest, 
                        MitreAttackTechnique, SigmaAnalysisResult, MitreTactic, MitreTechnique,
                        MitreSignature, MitreSeverity, SandboxMitreData, MitreLinks};

    #[test]
    fn test_process_tree_node() {
        let node = ProcessTreeNode {
            name: Some("cmd.exe".to_string()),
            process_id: Some("1234".to_string()),
            parent_process_id: Some("1000".to_string()),
            children: Some(vec![]),
        };
        
        assert_eq!(node.name.unwrap(), "cmd.exe");
        assert_eq!(node.process_id.unwrap(), "1234");
    }

    #[test]
    fn test_dns_lookup() {
        let lookup = DnsLookup {
            hostname: Some("example.com".to_string()),
            resolved_ips: Some(vec!["192.168.1.1".to_string()]),
        };
        
        assert_eq!(lookup.hostname.unwrap(), "example.com");
        assert_eq!(lookup.resolved_ips.unwrap()[0], "192.168.1.1");
    }

    #[test]
    fn test_ip_traffic() {
        let traffic = IpTraffic {
            destination_ip: Some("192.168.1.1".to_string()),
            destination_port: Some(443),
            protocol: Some("TCP".to_string()),
            bytes_sent: Some(1024),
        };
        
        assert_eq!(traffic.destination_ip.unwrap(), "192.168.1.1");
        assert_eq!(traffic.destination_port.unwrap(), 443);
        assert_eq!(traffic.protocol.unwrap(), "TCP");
    }

    #[test]
    fn test_http_conversation() {
        let conv = HttpConversation {
            request_method: Some("GET".to_string()),
            url: Some("https://example.com".to_string()),
            status_code: Some(200),
            headers: None,
        };
        
        assert_eq!(conv.request_method.unwrap(), "GET");
        assert_eq!(conv.status_code.unwrap(), 200);
    }

    #[test]
    fn test_ja3_digest() {
        let digest = Ja3Digest {
            digest: Some("abc123".to_string()),
            endpoint: Some("example.com".to_string()),
        };
        
        assert_eq!(digest.digest.unwrap(), "abc123");
        assert_eq!(digest.endpoint.unwrap(), "example.com");
    }

    #[test]
    fn test_mitre_attack_technique() {
        let technique = MitreAttackTechnique {
            id: Some("T1055".to_string()),
            name: Some("Process Injection".to_string()),
            description: None,
            severity: Some(MitreSeverity::HIGH),
        };
        
        assert_eq!(technique.id.unwrap(), "T1055");
        assert_eq!(technique.name.unwrap(), "Process Injection");
    }

    #[test]
    fn test_sigma_analysis_result() {
        let result = SigmaAnalysisResult {
            id: Some("rule-123".to_string()),
            name: Some("Test Rule".to_string()),
            description: None,
            source: None,
            context: None,
        };
        
        assert_eq!(result.id.unwrap(), "rule-123");
        assert_eq!(result.name.unwrap(), "Test Rule");
    }

    #[test]
    fn test_mitre_severity() {
        assert_eq!(serde_json::to_string(&MitreSeverity::HIGH).unwrap(), "\"HIGH\"");
        assert_eq!(serde_json::to_string(&MitreSeverity::MEDIUM).unwrap(), "\"MEDIUM\"");
        assert_eq!(serde_json::to_string(&MitreSeverity::LOW).unwrap(), "\"LOW\"");
        assert_eq!(serde_json::to_string(&MitreSeverity::INFO).unwrap(), "\"INFO\"");
        assert_eq!(serde_json::to_string(&MitreSeverity::UNKNOWN).unwrap(), "\"UNKNOWN\"");
    }

    #[test]
    fn test_mitre_tactic() {
        let tactic = MitreTactic {
            id: "TA0001".to_string(),
            name: "Initial Access".to_string(),
            description: "The adversary is trying to get into your network.".to_string(),
            link: "https://attack.mitre.org/tactics/TA0001/".to_string(),
            techniques: vec![],
        };
        
        assert_eq!(tactic.id, "TA0001");
        assert_eq!(tactic.name, "Initial Access");
    }

    #[test]
    fn test_mitre_technique() {
        let technique = MitreTechnique {
            id: "T1566".to_string(),
            name: "Phishing".to_string(),
            description: "Adversaries may send phishing messages.".to_string(),
            link: "https://attack.mitre.org/techniques/T1566/".to_string(),
            signatures: vec![],
        };
        
        assert_eq!(technique.id, "T1566");
        assert_eq!(technique.name, "Phishing");
    }

    #[test]
    fn test_mitre_signature() {
        let signature = MitreSignature {
            severity: MitreSeverity::HIGH,
            description: "Detected phishing attempt".to_string(),
            signature_id: Some("sig-001".to_string()),
        };
        
        assert_eq!(signature.severity, MitreSeverity::HIGH);
        assert_eq!(signature.description, "Detected phishing attempt");
    }

    #[test]
    fn test_sandbox_mitre_data() {
        let data = SandboxMitreData {
            tactics: vec![],
        };
        
        assert!(data.tactics.is_empty());
    }

    #[test]
    fn test_mitre_links() {
        let links = MitreLinks {
            self_link: Some("https://example.com/self".to_string()),
        };
        
        assert_eq!(links.self_link.unwrap(), "https://example.com/self");
    }

    #[test]
    fn test_mitre_trees() {
        let trees = MitreTrees {
            data: HashMap::new(),
            links: None,
        };
        
        assert!(trees.data.is_empty());
        assert!(trees.links.is_none());
    }
}

// Client module additional tests
#[cfg(test)]
mod client_additional_tests {
    use super::*;
    use crate::client::ClientBuilder;
    use crate::auth::ApiTier;

    #[test]
    fn test_client_builder_all_options() {
        let client = ClientBuilder::new()
            .api_key("test_key")
            .tier(ApiTier::Premium)
            .base_url("https://custom.api.com")
            .timeout(std::time::Duration::from_secs(60))
            .build();
        
        assert!(client.is_ok());
        let client = client.unwrap();
        assert_eq!(client.api_key(), "test_key");
        assert_eq!(client.base_url(), "https://custom.api.com/");
    }

    #[test]
    fn test_client_builder_missing_api_key() {
        let client = ClientBuilder::new().build();
        assert!(client.is_err());
    }
}

// Domains module comprehensive tests
#[cfg(test)]
mod domains_comprehensive_tests {
    use super::*;
    use crate::domains::{HttpsCertificate, CertSignature, PublicKey, RsaKey, EcKey, 
                         Validity, DnsRecord, PopularityRank};

    #[test]
    fn test_https_certificate() {
        let cert = HttpsCertificate {
            cert_signature: Some(CertSignature {
                signature: "sig123".to_string(),
                signature_algorithm: "RSA".to_string(),
            }),
            extensions: None,
            issuer: None,
            public_key: None,
            serial_number: Some("12345".to_string()),
            signature_algorithm: Some("RSA-SHA256".to_string()),
            size: Some(2048),
            subject: None,
            thumbprint: Some("thumb123".to_string()),
            thumbprint_sha256: Some("sha256thumb".to_string()),
            validity: None,
            version: Some("3".to_string()),
        };
        
        assert_eq!(cert.serial_number.unwrap(), "12345");
        assert_eq!(cert.signature_algorithm.unwrap(), "RSA-SHA256");
    }

    #[test]
    fn test_cert_signature() {
        let sig = CertSignature {
            signature: "sig123".to_string(),
            signature_algorithm: "RSA".to_string(),
        };
        
        assert_eq!(sig.signature, "sig123");
        assert_eq!(sig.signature_algorithm, "RSA");
    }

    #[test]
    fn test_public_key_rsa() {
        let key = PublicKey {
            algorithm: "RSA".to_string(),
            rsa: Some(RsaKey {
                key_size: 2048,
                modulus: "modulus123".to_string(),
                exponent: "65537".to_string(),
            }),
            ec: None,
        };
        
        assert_eq!(key.algorithm, "RSA");
        assert_eq!(key.rsa.unwrap().key_size, 2048);
    }

    #[test]
    fn test_public_key_ec() {
        let key = PublicKey {
            algorithm: "EC".to_string(),
            rsa: None,
            ec: Some(EcKey {
                key_size: 256,
                pub_x: "x123".to_string(),
                pub_y: "y456".to_string(),
            }),
        };
        
        assert_eq!(key.algorithm, "EC");
        assert_eq!(key.ec.unwrap().key_size, 256);
    }

    #[test]
    fn test_validity() {
        let validity = Validity {
            not_after: "2025-01-01".to_string(),
            not_before: "2024-01-01".to_string(),
        };
        
        assert_eq!(validity.not_after, "2025-01-01");
        assert_eq!(validity.not_before, "2024-01-01");
    }

    #[test]
    fn test_dns_record() {
        let record = DnsRecord {
            record_type: "A".to_string(),
            value: "192.168.1.1".to_string(),
            ttl: Some(3600),
        };
        
        assert_eq!(record.record_type, "A");
        assert_eq!(record.value, "192.168.1.1");
        assert_eq!(record.ttl.unwrap(), 3600);
    }

    #[test]
    fn test_popularity_rank() {
        let rank = PopularityRank {
            rank: 100,
            timestamp: 1234567890,
        };
        
        assert_eq!(rank.rank, 100);
        assert_eq!(rank.timestamp, 1234567890);
    }
}

// IP addresses module comprehensive tests
#[cfg(test)]
mod ip_addresses_comprehensive_tests {
    use super::*;

    #[test]
    fn test_ip_address_attributes_all_fields() {
        let attrs = IpAddressAttributes {
            asn: Some(12345),
            as_owner: Some("Example ISP".to_string()),
            country: Some("US".to_string()),
            continent: Some("NA".to_string()),
            network: Some("192.168.0.0/16".to_string()),
            whois: Some("WHOIS data".to_string()),
            whois_date: Some(1234567890),
            regional_internet_registry: Some("ARIN".to_string()),
            reputation: Some(0),
            harmless: Some(10),
            malicious: Some(0),
            suspicious: Some(0),
            undetected: Some(5),
            timeout: Some(0),
            last_analysis_date: Some(1234567890),
            last_modification_date: Some(1234567890),
            last_analysis_stats: None,
            last_analysis_results: None,
            total_votes: None,
            additional_attributes: HashMap::new(),
        };
        
        assert_eq!(attrs.asn.unwrap(), 12345);
        assert_eq!(attrs.as_owner.unwrap(), "Example ISP");
        assert_eq!(attrs.country.unwrap(), "US");
        assert_eq!(attrs.continent.unwrap(), "NA");
        assert_eq!(attrs.network.unwrap(), "192.168.0.0/16");
    }
}

// Rate limit module tests
#[cfg(test)]
mod rate_limit_tests {
    use super::*;
    use crate::rate_limit::{RateLimiter, RateLimitError};
    use crate::auth::ApiTier;

    #[tokio::test]
    async fn test_rate_limiter_premium_no_limits() {
        let limiter = RateLimiter::new(ApiTier::Premium);
        let result = limiter.check_rate_limit().await;
        assert!(result.is_ok());
    }

    #[test]
    fn test_rate_limit_error() {
        let error = RateLimitError::DailyQuotaExceeded;
        assert!(error.to_string().contains("daily quota"));
    }
}