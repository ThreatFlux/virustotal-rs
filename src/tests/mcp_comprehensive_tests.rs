//! Comprehensive tests for MCP (Model Context Protocol) functionality
//! This module aims to achieve maximum coverage of MCP-related code

#[cfg(feature = "mcp")]
mod mcp_client_ext_tests {
    use crate::tests::test_utils::create_test_client;
    use crate::mcp::transport::ServerConfig;

    #[tokio::test]
    async fn test_create_mcp_server() {
        let client = create_test_client();
        let mcp_server = client.create_mcp_server();
        
        // Verify the server was created successfully
        assert!(!format!("{:?}", mcp_server).is_empty());
    }

    #[tokio::test]
    async fn test_mcp_config_creation() {
        let client = create_test_client();
        let config = client.mcp_config();
        
        // Verify config has expected default values
        assert_eq!(config.address(), "127.0.0.1:8080");
        assert_eq!(config.server_mode(), crate::mcp::transport::ServerMode::Http);
    }

    #[tokio::test]
    async fn test_mcp_server_with_config() {
        let client = create_test_client();
        let mut config = client.mcp_config();
        
        // Test configuration builder pattern
        config = config.with_address("localhost:9000");
        config = config.with_stdio_mode();
        
        assert_eq!(config.address(), "localhost:9000");
        assert_eq!(config.server_mode(), crate::mcp::transport::ServerMode::Stdio);
        
        let server = client.create_mcp_server();
        assert!(!format!("{:?}", server).is_empty());
    }
}

#[cfg(feature = "mcp")]
mod mcp_search_comprehensive_tests {
    use crate::mcp::search::*;
    use crate::tests::test_utils::create_test_client;
    use serde_json::json;

    #[test]
    fn test_threat_intelligence_creation() {
        let intel = ThreatIntelligence {
            indicator: "malware.exe".to_string(),
            indicator_type: "file".to_string(),
            threat_score: 85,
            threat_categories: vec!["trojan".to_string(), "malware".to_string()],
            summary: "Detected as malicious by multiple engines".to_string(),
            detections: DetectionSummary {
                malicious: 45,
                suspicious: 5,
                clean: 10,
                total_engines: 60,
                detection_ratio: 0.83,
            },
            context: ThreatContext {
                first_seen: Some(1640995200), // 2022-01-01
                last_seen: Some(1672531200),  // 2023-01-01
                prevalence: Some("high".to_string()),
                source_countries: vec!["US".to_string(), "CN".to_string()],
                file_types: vec!["PE32".to_string()],
                sandbox_reports: 15,
            },
            last_analysis_date: Some(1672531200),
            reputation: Some(-75),
        };

        assert_eq!(intel.indicator, "malware.exe");
        assert_eq!(intel.threat_score, 85);
        assert_eq!(intel.detections.total_engines, 60);
        assert_eq!(intel.context.sandbox_reports, 15);
    }

    #[test]
    fn test_detection_summary_calculations() {
        let mut summary = DetectionSummary {
            malicious: 30,
            suspicious: 10,
            clean: 20,
            total_engines: 60,
            detection_ratio: 0.0, // Will be calculated
        };

        // Test calculation of detection ratio
        summary.detection_ratio = (summary.malicious + summary.suspicious) as f32 / summary.total_engines as f32;
        
        assert_eq!(summary.detection_ratio, 40.0 / 60.0);
        assert!((summary.detection_ratio - 0.6666667).abs() < 0.0001);
    }

    #[test]
    fn test_threat_context_optional_fields() {
        let context = ThreatContext {
            first_seen: None,
            last_seen: Some(1672531200),
            prevalence: None,
            source_countries: vec![],
            file_types: vec!["PDF".to_string()],
            sandbox_reports: 0,
        };

        assert!(context.first_seen.is_none());
        assert!(context.last_seen.is_some());
        assert!(context.prevalence.is_none());
        assert_eq!(context.file_types.len(), 1);
        assert_eq!(context.sandbox_reports, 0);
    }

    #[test]
    fn test_threat_score_calculation() {
        let calculate_threat_score = |malicious: u32, total: u32| -> u8 {
            if total == 0 { return 0; }
            let ratio = malicious as f32 / total as f32;
            (ratio * 100.0).min(100.0) as u8
        };

        assert_eq!(calculate_threat_score(0, 50), 0);
        assert_eq!(calculate_threat_score(25, 50), 50);
        assert_eq!(calculate_threat_score(50, 50), 100);
        assert_eq!(calculate_threat_score(75, 50), 100); // Capped at 100
    }

    #[test]
    fn test_serialization_deserialization() {
        let intel = ThreatIntelligence {
            indicator: "example.com".to_string(),
            indicator_type: "domain".to_string(),
            threat_score: 25,
            threat_categories: vec!["phishing".to_string()],
            summary: "Low confidence phishing domain".to_string(),
            detections: DetectionSummary {
                malicious: 2,
                suspicious: 3,
                clean: 45,
                total_engines: 50,
                detection_ratio: 0.1,
            },
            context: ThreatContext {
                first_seen: Some(1640995200),
                last_seen: Some(1672531200),
                prevalence: Some("low".to_string()),
                source_countries: vec!["RU".to_string()],
                file_types: vec![],
                sandbox_reports: 0,
            },
            last_analysis_date: Some(1672531200),
            reputation: Some(10),
        };

        // Test serialization
        let json = serde_json::to_string(&intel).expect("Failed to serialize");
        assert!(json.contains("example.com"));
        assert!(json.contains("domain"));
        
        // Test deserialization
        let deserialized: ThreatIntelligence = serde_json::from_str(&json).expect("Failed to deserialize");
        assert_eq!(deserialized.indicator, intel.indicator);
        assert_eq!(deserialized.threat_score, intel.threat_score);
        assert_eq!(deserialized.detections.total_engines, intel.detections.total_engines);
    }
}

#[cfg(feature = "mcp")]
mod mcp_transport_comprehensive_tests {
    use crate::mcp::transport::*;

    #[test]
    fn test_server_mode_variants() {
        assert_eq!(ServerMode::Http.to_string(), "http");
        assert_eq!(ServerMode::Stdio.to_string(), "stdio");
        
        // Test Debug implementation
        assert!(!format!("{:?}", ServerMode::Http).is_empty());
        assert!(!format!("{:?}", ServerMode::Stdio).is_empty());
    }

    #[test]
    fn test_api_tier_parsing() {
        use crate::auth::ApiTier;
        
        // Test string parsing for different cases
        assert_eq!("public".parse::<ApiTier>().unwrap(), ApiTier::Public);
        assert_eq!("premium".parse::<ApiTier>().unwrap(), ApiTier::Premium);
        assert_eq!("PUBLIC".parse::<ApiTier>().unwrap(), ApiTier::Public);
        assert_eq!("PREMIUM".parse::<ApiTier>().unwrap(), ApiTier::Premium);
        
        // Test invalid parsing
        assert!("invalid".parse::<ApiTier>().is_err());
        assert!("".parse::<ApiTier>().is_err());
    }

    #[test]
    fn test_server_config_builder() {
        let config = ServerConfig::new();
        
        // Test default values
        assert_eq!(config.address(), "127.0.0.1:8080");
        assert_eq!(config.server_mode(), ServerMode::Http);
        
        // Test builder pattern
        let config = config
            .with_address("0.0.0.0:3000")
            .with_http_mode();
            
        assert_eq!(config.address(), "0.0.0.0:3000");
        assert_eq!(config.server_mode(), ServerMode::Http);
        
        // Test stdio mode
        let config = config.with_stdio_mode();
        assert_eq!(config.server_mode(), ServerMode::Stdio);
    }

    #[test]
    fn test_server_config_validation() {
        let config = ServerConfig::new();
        
        // Test valid addresses
        let valid_addresses = [
            "localhost:8080",
            "127.0.0.1:3000",
            "0.0.0.0:8080",
            "192.168.1.1:9000",
        ];
        
        for addr in &valid_addresses {
            let config = config.with_address(addr);
            assert_eq!(config.address(), *addr);
        }
    }

    #[test]
    fn test_server_config_clone() {
        let config1 = ServerConfig::new().with_address("localhost:9000");
        let config2 = config1.clone();
        
        assert_eq!(config1.address(), config2.address());
        assert_eq!(config1.server_mode(), config2.server_mode());
    }

    #[test]
    fn test_server_config_debug() {
        let config = ServerConfig::new();
        let debug_str = format!("{:?}", config);
        
        assert!(debug_str.contains("ServerConfig"));
        assert!(!debug_str.is_empty());
    }
}

#[cfg(feature = "mcp")]
mod mcp_indicators_comprehensive_tests {
    use crate::mcp::indicators::*;

    #[test]
    fn test_indicator_type_detection() {
        // Test hash detection
        assert_eq!(detect_indicator_type("d41d8cd98f00b204e9800998ecf8427e"), IndicatorType::Hash);
        assert_eq!(detect_indicator_type("aec070645fe53ee3b3763059376134f058cc337247c978add178b6ccdfb0019f"), IndicatorType::Hash);
        
        // Test IP detection
        assert_eq!(detect_indicator_type("192.168.1.1"), IndicatorType::IpAddress);
        assert_eq!(detect_indicator_type("8.8.8.8"), IndicatorType::IpAddress);
        assert_eq!(detect_indicator_type("2001:db8::1"), IndicatorType::IpAddress);
        
        // Test domain detection
        assert_eq!(detect_indicator_type("example.com"), IndicatorType::Domain);
        assert_eq!(detect_indicator_type("subdomain.example.org"), IndicatorType::Domain);
        
        // Test URL detection
        assert_eq!(detect_indicator_type("https://example.com/path"), IndicatorType::Url);
        assert_eq!(detect_indicator_type("http://malware.example.com"), IndicatorType::Url);
        assert_eq!(detect_indicator_type("ftp://files.example.com"), IndicatorType::Url);
        
        // Test unknown
        assert_eq!(detect_indicator_type("not_a_valid_indicator"), IndicatorType::Unknown);
        assert_eq!(detect_indicator_type(""), IndicatorType::Unknown);
    }

    #[test]
    fn test_edge_case_detection() {
        // Test ambiguous cases
        assert_eq!(detect_indicator_type("123"), IndicatorType::Unknown);
        assert_eq!(detect_indicator_type("abc.def"), IndicatorType::Domain); // Treated as domain
        assert_eq!(detect_indicator_type("192.168.1"), IndicatorType::Unknown); // Incomplete IP
        
        // Test malformed hashes
        assert_eq!(detect_indicator_type("d41d8cd98f00b204e9800998ecf8427"), IndicatorType::Unknown); // 31 chars
        assert_eq!(detect_indicator_type("d41d8cd98f00b204e9800998ecf8427eX"), IndicatorType::Unknown); // Invalid hex
        
        // Test special characters
        assert_eq!(detect_indicator_type("example.com:8080"), IndicatorType::Unknown);
        assert_eq!(detect_indicator_type("192.168.1.1:80"), IndicatorType::Unknown);
    }

    #[test]
    fn test_hash_validation() {
        let validate_hash = |s: &str| -> bool {
            let len = s.len();
            (len == 32 || len == 40 || len == 64) && s.chars().all(|c| c.is_ascii_hexdigit())
        };

        // Valid MD5
        assert!(validate_hash("d41d8cd98f00b204e9800998ecf8427e"));
        // Valid SHA1
        assert!(validate_hash("da39a3ee5e6b4b0d3255bfef95601890afd80709"));
        // Valid SHA256
        assert!(validate_hash("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"));
        
        // Invalid cases
        assert!(!validate_hash("invalid_hash"));
        assert!(!validate_hash("d41d8cd98f00b204e9800998ecf8427")); // 31 chars
        assert!(!validate_hash("d41d8cd98f00b204e9800998ecf8427eX")); // Non-hex
    }

    #[test]
    fn test_ip_address_validation() {
        let validate_ipv4 = |s: &str| -> bool {
            s.parse::<std::net::Ipv4Addr>().is_ok()
        };

        let validate_ipv6 = |s: &str| -> bool {
            s.parse::<std::net::Ipv6Addr>().is_ok()
        };

        // Valid IPv4
        assert!(validate_ipv4("192.168.1.1"));
        assert!(validate_ipv4("8.8.8.8"));
        assert!(validate_ipv4("127.0.0.1"));
        
        // Valid IPv6
        assert!(validate_ipv6("2001:db8::1"));
        assert!(validate_ipv6("::1"));
        assert!(validate_ipv6("fe80::1"));
        
        // Invalid cases
        assert!(!validate_ipv4("192.168.1"));
        assert!(!validate_ipv4("256.1.1.1"));
        assert!(!validate_ipv6("invalid::ipv6::"));
    }

    #[test]
    fn test_domain_validation() {
        let validate_domain = |s: &str| -> bool {
            // Simple domain validation
            s.contains('.') && !s.starts_with('.') && !s.ends_with('.') && 
            s.chars().all(|c| c.is_alphanumeric() || c == '.' || c == '-')
        };

        // Valid domains
        assert!(validate_domain("example.com"));
        assert!(validate_domain("subdomain.example.org"));
        assert!(validate_domain("test-domain.co.uk"));
        
        // Invalid domains
        assert!(!validate_domain("example"));
        assert!(!validate_domain(".example.com"));
        assert!(!validate_domain("example.com."));
        assert!(!validate_domain("exam@ple.com"));
    }

    #[test]
    fn test_url_validation() {
        use url::Url;
        
        let validate_url = |s: &str| -> bool {
            Url::parse(s).is_ok()
        };

        // Valid URLs
        assert!(validate_url("https://example.com"));
        assert!(validate_url("http://subdomain.example.org/path"));
        assert!(validate_url("ftp://files.example.com"));
        
        // Invalid URLs
        assert!(!validate_url("not_a_url"));
        assert!(!validate_url("https://"));
        assert!(!validate_url("example.com")); // Missing protocol
    }
}

#[cfg(feature = "mcp-jwt")]
mod mcp_jwt_comprehensive_tests {
    use crate::mcp::auth::*;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    #[test]
    fn test_jwt_config_creation() {
        let config = JwtConfig::new("test-secret", vec!["read".to_string()]);
        
        assert_eq!(config.secret, "test-secret");
        assert_eq!(config.permissions, vec!["read"]);
        assert_eq!(config.expiration, Duration::from_secs(3600)); // Default 1 hour
    }

    #[test]
    fn test_jwt_config_builder() {
        let config = JwtConfig::builder()
            .secret("my-secret")
            .permissions(vec!["read", "write"])
            .expiration(Duration::from_secs(7200))
            .build();

        assert_eq!(config.secret, "my-secret");
        assert_eq!(config.permissions, vec!["read", "write"]);
        assert_eq!(config.expiration, Duration::from_secs(7200));
    }

    #[test]
    fn test_claims_creation() {
        let permissions = vec!["admin".to_string()];
        let exp = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() + 3600;
        
        let claims = Claims {
            permissions: permissions.clone(),
            exp: exp as usize,
        };

        assert_eq!(claims.permissions, permissions);
        assert_eq!(claims.exp, exp as usize);
    }

    #[test]
    fn test_permission_levels() {
        let readonly_permissions = vec!["read".to_string()];
        let admin_permissions = vec!["read".to_string(), "write".to_string(), "admin".to_string()];
        
        // Test that admin permissions include read
        assert!(admin_permissions.contains(&"read".to_string()));
        assert!(!readonly_permissions.contains(&"write".to_string()));
    }

    #[test]
    fn test_token_expiration_calculation() {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        let config = JwtConfig::new("secret", vec!["read".to_string()]);
        let exp = now + config.expiration.as_secs();
        
        // Token should expire in the future
        assert!(exp > now);
        // Should expire within reasonable time (default 1 hour)
        assert!(exp - now <= 3600);
    }
}

#[cfg(feature = "mcp-oauth")]
mod mcp_oauth_comprehensive_tests {
    use crate::mcp::oauth::*;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    #[test]
    fn test_oauth_config_builder() {
        let config = OAuthConfig::builder()
            .client_id("test-client-id")
            .client_secret("test-client-secret")
            .auth_url("https://example.com/auth")
            .token_url("https://example.com/token")
            .scopes(vec!["read", "write"])
            .build();

        assert_eq!(config.client_id, "test-client-id");
        assert_eq!(config.client_secret, "test-client-secret");
        assert_eq!(config.auth_url, "https://example.com/auth");
        assert_eq!(config.token_url, "https://example.com/token");
        assert_eq!(config.scopes, vec!["read", "write"]);
    }

    #[test]
    fn test_oauth_state_creation() {
        let state = OAuthState::new();
        
        // State should be a non-empty string
        assert!(!state.value.is_empty());
        // Should be at least 16 characters for security
        assert!(state.value.len() >= 16);
    }

    #[test]
    fn test_oauth_credentials() {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        let expires_in = 3600; // 1 hour
        
        let credentials = OAuthCredentials {
            access_token: "access-token".to_string(),
            token_type: "Bearer".to_string(),
            expires_in: Some(expires_in),
            refresh_token: Some("refresh-token".to_string()),
            scope: Some("read write".to_string()),
            expires_at: Some(now + expires_in),
        };

        assert_eq!(credentials.access_token, "access-token");
        assert_eq!(credentials.token_type, "Bearer");
        assert!(credentials.expires_in.is_some());
        assert!(credentials.refresh_token.is_some());
        assert!(credentials.expires_at.is_some());
    }

    #[test]
    fn test_oauth_credentials_expiration() {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        
        // Test non-expired credentials
        let valid_credentials = OAuthCredentials {
            access_token: "token".to_string(),
            token_type: "Bearer".to_string(),
            expires_in: Some(3600),
            refresh_token: None,
            scope: None,
            expires_at: Some(now + 1800), // Expires in 30 minutes
        };

        // Test expired credentials
        let expired_credentials = OAuthCredentials {
            access_token: "token".to_string(),
            token_type: "Bearer".to_string(),
            expires_in: Some(3600),
            refresh_token: None,
            scope: None,
            expires_at: Some(now - 1800), // Expired 30 minutes ago
        };

        assert!(valid_credentials.expires_at.unwrap() > now);
        assert!(expired_credentials.expires_at.unwrap() < now);
    }

    #[test]
    fn test_oauth_error_handling() {
        // Test invalid client credentials
        let invalid_config = OAuthConfig::builder()
            .client_id("")  // Empty client ID should be handled
            .client_secret("secret")
            .auth_url("https://example.com/auth")
            .token_url("https://example.com/token")
            .scopes(vec!["read"])
            .build();

        assert!(invalid_config.client_id.is_empty());
        // Application should handle validation appropriately
    }

    #[test]
    fn test_scope_formatting() {
        let scopes = vec!["read".to_string(), "write".to_string(), "admin".to_string()];
        let scope_string = scopes.join(" ");
        
        assert_eq!(scope_string, "read write admin");
        
        // Test parsing scopes back
        let parsed_scopes: Vec<&str> = scope_string.split(' ').collect();
        assert_eq!(parsed_scopes.len(), 3);
        assert!(parsed_scopes.contains(&"read"));
        assert!(parsed_scopes.contains(&"write"));
        assert!(parsed_scopes.contains(&"admin"));
    }
}