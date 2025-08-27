//! URL building utilities for VirusTotal API
//!
//! This module provides type-safe URL construction utilities to eliminate duplication
//! and reduce errors in URL building across the library.

pub mod builder;
pub mod constants;
pub mod encoding;
pub mod endpoints;
pub mod validation;

// Re-export commonly used items
pub use builder::{EndpointBuilder, QueryBuilder, VirusTotalUrlBuilder};
pub use constants::*;
pub use encoding::{build_query_string, encode_path_segment};
pub use endpoints::Endpoints;
pub use validation::{validate_domain, validate_hash, validate_ip};

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn test_virus_total_url_builder_default() {
        let builder = VirusTotalUrlBuilder::new();
        assert_eq!(builder.base_url(), VT_API_BASE);
    }

    #[test]
    fn test_virus_total_url_builder_custom() {
        let builder = VirusTotalUrlBuilder::with_base_url("https://example.com/api/").unwrap();
        assert_eq!(builder.base_url(), "https://example.com/api/");
    }

    #[test]
    fn test_virus_total_url_builder_normalizes_base_url() {
        let builder = VirusTotalUrlBuilder::with_base_url("https://example.com/api").unwrap();
        assert_eq!(builder.base_url(), "https://example.com/api/");
    }

    #[test]
    fn test_virus_total_url_builder_invalid_base_url() {
        let result = VirusTotalUrlBuilder::with_base_url("not-a-url");
        assert!(result.is_err());
    }

    #[test]
    fn test_virus_total_url_builder_build() {
        let builder = VirusTotalUrlBuilder::new();
        let url = builder.build("files").unwrap();
        assert_eq!(url, "https://www.virustotal.com/api/v3/files");
    }

    #[test]
    fn test_virus_total_url_builder_build_invalid_endpoint() {
        let builder = VirusTotalUrlBuilder::new();
        let result = builder.build("///invalid endpoint");
        assert!(result.is_err());
    }

    #[test]
    fn test_endpoint_builder_simple() {
        let endpoint = EndpointBuilder::new()
            .segment("files")
            .segment("test-hash")
            .build();
        assert_eq!(endpoint, "files/test-hash");
    }

    #[test]
    fn test_endpoint_builder_with_query() {
        let endpoint = EndpointBuilder::new()
            .segment("files")
            .query("limit", 10)
            .query("cursor", "abc123")
            .build();
        assert!(endpoint.contains("files?"));
        assert!(endpoint.contains("limit=10"));
        assert!(endpoint.contains("cursor=abc123"));
    }

    #[test]
    fn test_endpoint_builder_segments() {
        let endpoint = EndpointBuilder::new()
            .segments(vec!["files", "hash", "comments"])
            .build();
        assert_eq!(endpoint, "files/hash/comments");
    }

    #[test]
    fn test_endpoint_builder_raw_segment() {
        let endpoint = EndpointBuilder::new()
            .raw_segment("files")
            .raw_segment("special%20hash")
            .build();
        assert_eq!(endpoint, "files/special%20hash");
    }

    #[test]
    fn test_endpoint_builder_queries() {
        let params = vec![("limit", 10), ("offset", 20)];
        let endpoint = EndpointBuilder::new()
            .raw_segment("files")
            .queries(params)
            .build();
        assert!(endpoint.contains("files?"));
        assert!(endpoint.contains("limit=10"));
        assert!(endpoint.contains("offset=20"));
    }

    #[test]
    fn test_endpoint_builder_empty() {
        let endpoint = EndpointBuilder::new().build();
        assert_eq!(endpoint, "");
    }

    #[test]
    fn test_endpoint_builder_only_query() {
        let endpoint = EndpointBuilder::new().query("q", "test").build();
        assert_eq!(endpoint, "?q=test");
    }

    #[test]
    fn test_encode_path_segment() {
        assert_eq!(encode_path_segment("hello world"), "hello%20world");
        assert_eq!(
            encode_path_segment("test@example.com"),
            "test%40example.com"
        );
        assert_eq!(encode_path_segment(""), "");
        assert_eq!(encode_path_segment("normal"), "normal");
    }

    #[test]
    fn test_build_query_string() {
        let mut params = HashMap::new();
        params.insert("limit".to_string(), "10".to_string());
        params.insert("cursor".to_string(), "abc123".to_string());

        let query = build_query_string(&params);
        // Order is sorted by key
        assert_eq!(query, "cursor=abc123&limit=10");
    }

    #[test]
    fn test_build_query_string_empty() {
        let params = HashMap::new();
        let query = build_query_string(&params);
        assert_eq!(query, "");
    }

    #[test]
    fn test_build_query_string_special_chars() {
        let mut params = HashMap::new();
        params.insert("query".to_string(), "hello world & test".to_string());

        let query = build_query_string(&params);
        assert_eq!(query, "query=hello%20world%20%26%20test");
    }

    #[test]
    fn test_validate_hash_valid() {
        assert!(validate_hash("d41d8cd98f00b204e9800998ecf8427e").is_ok()); // MD5
        assert!(validate_hash("da39a3ee5e6b4b0d3255bfef95601890afd80709").is_ok()); // SHA1
        assert!(
            validate_hash("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
                .is_ok()
        ); // SHA256
        assert!(validate_hash("ABCDEF1234567890ABCDEF1234567890").is_ok()); // Mixed case MD5
    }

    #[test]
    fn test_validate_hash_invalid() {
        assert!(validate_hash("").is_err()); // Empty
        assert!(validate_hash("   ").is_err()); // Whitespace only
        assert!(validate_hash("invalid-hash").is_err()); // Non-hex characters
        assert!(validate_hash("123").is_err()); // Wrong length
        assert!(validate_hash("gggggggggggggggggggggggggggggggg").is_err()); // 32 chars but invalid hex
    }

    #[test]
    fn test_validate_domain_valid() {
        assert!(validate_domain("example.com").is_ok());
        assert!(validate_domain("sub.example.com").is_ok());
        assert!(validate_domain("test-domain.com").is_ok());
        assert!(validate_domain("a.b").is_ok()); // Minimal valid
        assert!(validate_domain("123.456").is_ok()); // Numeric
    }

    #[test]
    fn test_validate_domain_invalid() {
        assert!(validate_domain("").is_err()); // Empty
        assert!(validate_domain("   ").is_err()); // Whitespace only
        assert!(validate_domain(".example.com").is_err()); // Starts with dot
        assert!(validate_domain("example.com.").is_err()); // Ends with dot
        assert!(validate_domain("-example.com").is_err()); // Starts with dash
        assert!(validate_domain("example.com-").is_err()); // Ends with dash
        assert!(validate_domain("example$.com").is_err()); // Invalid characters
        let long_domain = "a".repeat(255); // Too long
        assert!(validate_domain(&long_domain).is_err());
    }

    #[test]
    fn test_validate_ip_valid() {
        assert!(validate_ip("192.168.1.1").is_ok()); // IPv4
        assert!(validate_ip("0.0.0.0").is_ok()); // IPv4 edge case
        assert!(validate_ip("255.255.255.255").is_ok()); // IPv4 max
        assert!(validate_ip("::1").is_ok()); // IPv6 localhost
        assert!(validate_ip("2001:db8::1").is_ok()); // IPv6
        assert!(validate_ip("::").is_ok()); // IPv6 unspecified
    }

    #[test]
    fn test_validate_ip_invalid() {
        assert!(validate_ip("").is_err()); // Empty
        assert!(validate_ip("   ").is_err()); // Whitespace only
        assert!(validate_ip("256.1.1.1").is_err()); // Invalid IPv4
        assert!(validate_ip("1.1.1").is_err()); // Incomplete IPv4
        assert!(validate_ip("not-an-ip").is_err()); // Invalid format
        assert!(validate_ip("192.168.1.1.1").is_err()); // Too many octets
    }

    #[test]
    fn test_endpoints_files() {
        let endpoint = Endpoints::files().build();
        assert_eq!(endpoint, "files");
    }

    #[test]
    fn test_endpoints_file() {
        let endpoint = Endpoints::file("d41d8cd98f00b204e9800998ecf8427e")
            .unwrap()
            .build();
        assert_eq!(endpoint, "files/d41d8cd98f00b204e9800998ecf8427e");
    }

    #[test]
    fn test_endpoints_file_invalid_hash() {
        let result = Endpoints::file("invalid-hash");
        assert!(result.is_err());
    }

    #[test]
    fn test_endpoints_domain() {
        let endpoint = Endpoints::domain("example.com").unwrap().build();
        assert_eq!(endpoint, "domains/example.com");
    }

    #[test]
    fn test_endpoints_domain_invalid() {
        let result = Endpoints::domain(".invalid.domain");
        assert!(result.is_err());
    }

    #[test]
    fn test_endpoints_ip_address() {
        let endpoint = Endpoints::ip_address("192.168.1.1").unwrap().build();
        assert_eq!(endpoint, "ip_addresses/192.168.1.1");
    }

    #[test]
    fn test_endpoints_ip_address_invalid() {
        let result = Endpoints::ip_address("invalid-ip");
        assert!(result.is_err());
    }

    #[test]
    fn test_endpoints_analysis() {
        let endpoint = Endpoints::analysis("test-id").build();
        assert_eq!(endpoint, "analyses/test-id");
    }

    #[test]
    fn test_endpoints_comments() {
        let endpoint = Endpoints::comments("files", "test-hash").build();
        assert_eq!(endpoint, "files/test-hash/comments");
    }

    #[test]
    fn test_endpoints_votes() {
        let endpoint = Endpoints::votes("files", "test-hash").build();
        assert_eq!(endpoint, "files/test-hash/votes");
    }

    #[test]
    fn test_endpoints_search() {
        let endpoint = Endpoints::search().build();
        assert_eq!(endpoint, "search");
    }

    #[test]
    fn test_endpoints_private_file() {
        let endpoint = Endpoints::private_file(
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        )
        .unwrap()
        .build();
        assert_eq!(
            endpoint,
            "private/files/e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn test_endpoints_private_file_invalid() {
        let result = Endpoints::private_file("invalid-hash");
        assert!(result.is_err());
    }

    #[test]
    fn test_endpoints_feeds() {
        let endpoint = Endpoints::feeds("files").build();
        assert_eq!(endpoint, "feeds/files");
    }

    #[test]
    fn test_endpoints_collection() {
        let endpoint = Endpoints::collection("test-id").build();
        assert_eq!(endpoint, "collections/test-id");
    }

    #[test]
    fn test_query_builder() {
        let query = QueryBuilder::new()
            .limit(10)
            .cursor("abc123")
            .filter("test")
            .build();

        assert!(query.contains("limit=10"));
        assert!(query.contains("cursor=abc123"));
        assert!(query.contains("filter=test"));
    }

    #[test]
    fn test_query_builder_optional() {
        let query = QueryBuilder::new()
            .param_opt("limit", Some(10))
            .param_opt("cursor", None::<&str>)
            .build();

        assert!(query.contains("limit=10"));
        assert!(!query.contains("cursor"));
    }

    #[test]
    fn test_query_builder_empty() {
        let query = QueryBuilder::new().build();
        assert_eq!(query, "");
    }

    #[test]
    fn test_query_builder_into_params() {
        let params = QueryBuilder::new()
            .param("limit", 10)
            .param("cursor", "test")
            .into_params();

        assert_eq!(params.get("limit"), Some(&"10".to_string()));
        assert_eq!(params.get("cursor"), Some(&"test".to_string()));
    }

    #[test]
    fn test_query_builder_order() {
        let query = QueryBuilder::new().order("name").build();

        assert!(query.contains("order=name"));
    }

    #[test]
    fn test_default_implementations() {
        let _builder = VirusTotalUrlBuilder::default();
        let _endpoint = EndpointBuilder::default();
        let _query = QueryBuilder::default();
    }
}
