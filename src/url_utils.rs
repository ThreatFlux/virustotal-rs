//! URL building utilities for VirusTotal API
//!
//! This module provides type-safe URL construction utilities to eliminate duplication
//! and reduce errors in URL building across the library.

use crate::error::{Error, Result};
use std::collections::HashMap;
use std::fmt;
use url::Url;

/// Base URL for VirusTotal API
pub const VT_API_BASE: &str = "https://www.virustotal.com/api/v3/";

/// Builder for constructing VirusTotal API URLs
#[derive(Debug, Clone)]
pub struct VirusTotalUrlBuilder {
    base_url: String,
}

impl Default for VirusTotalUrlBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl VirusTotalUrlBuilder {
    /// Create a new URL builder with the default base URL
    pub fn new() -> Self {
        Self {
            base_url: VT_API_BASE.to_string(),
        }
    }

    /// Create a URL builder with a custom base URL
    pub fn with_base_url(base_url: &str) -> Result<Self> {
        // Ensure base URL ends with '/'
        let normalized_base = if base_url.ends_with('/') {
            base_url.to_string()
        } else {
            format!("{}/", base_url)
        };

        // Validate the base URL
        Url::parse(&normalized_base)
            .map_err(|e| Error::bad_request(format!("Invalid base URL: {}", e)))?;

        Ok(Self {
            base_url: normalized_base,
        })
    }

    /// Get the base URL
    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    /// Build a complete URL from an endpoint
    pub fn build(&self, endpoint: &str) -> Result<String> {
        let base = Url::parse(&self.base_url)
            .map_err(|e| Error::bad_request(format!("Invalid base URL: {}", e)))?;

        let url = base
            .join(endpoint)
            .map_err(|e| Error::bad_request(format!("Invalid endpoint '{}': {}", endpoint, e)))?;

        Ok(url.to_string())
    }
}

/// Builder for constructing API endpoint paths
#[derive(Debug, Clone)]
pub struct EndpointBuilder {
    segments: Vec<String>,
    query_params: HashMap<String, String>,
}

impl Default for EndpointBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl EndpointBuilder {
    /// Create a new endpoint builder
    pub fn new() -> Self {
        Self {
            segments: Vec::new(),
            query_params: HashMap::new(),
        }
    }

    /// Add a path segment
    pub fn segment(mut self, segment: &str) -> Self {
        self.segments.push(encode_path_segment(segment));
        self
    }

    /// Add a raw segment without encoding (use with caution)
    pub fn raw_segment(mut self, segment: &str) -> Self {
        self.segments.push(segment.to_string());
        self
    }

    /// Add multiple segments
    pub fn segments<I, S>(mut self, segments: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        for segment in segments {
            self.segments.push(encode_path_segment(segment.as_ref()));
        }
        self
    }

    /// Add a query parameter
    pub fn query<K, V>(mut self, key: K, value: V) -> Self
    where
        K: Into<String>,
        V: fmt::Display,
    {
        self.query_params.insert(key.into(), value.to_string());
        self
    }

    /// Add an optional query parameter
    pub fn query_opt<K, V>(self, key: K, value: Option<V>) -> Self
    where
        K: Into<String>,
        V: fmt::Display,
    {
        match value {
            Some(v) => self.query(key, v),
            None => self,
        }
    }

    /// Add multiple query parameters
    pub fn queries<I, K, V>(mut self, params: I) -> Self
    where
        I: IntoIterator<Item = (K, V)>,
        K: Into<String>,
        V: fmt::Display,
    {
        for (key, value) in params {
            self.query_params.insert(key.into(), value.to_string());
        }
        self
    }

    /// Build the endpoint path
    pub fn build(self) -> String {
        let mut path = self.segments.join("/");

        if !self.query_params.is_empty() {
            path.push('?');
            path.push_str(&build_query_string(&self.query_params));
        }

        path
    }
}

/// Common endpoint patterns
pub struct Endpoints;

impl Endpoints {
    /// Files collection endpoint
    pub fn files() -> EndpointBuilder {
        EndpointBuilder::new().raw_segment("files")
    }

    /// Specific file endpoint
    pub fn file(file_id: &str) -> Result<EndpointBuilder> {
        validate_hash(file_id)?;
        Ok(EndpointBuilder::new().raw_segment("files").segment(file_id))
    }

    /// URLs collection endpoint
    pub fn urls() -> EndpointBuilder {
        EndpointBuilder::new().raw_segment("urls")
    }

    /// Specific URL endpoint
    pub fn url(url_id: &str) -> EndpointBuilder {
        EndpointBuilder::new().raw_segment("urls").segment(url_id)
    }

    /// Domains collection endpoint
    pub fn domains() -> EndpointBuilder {
        EndpointBuilder::new().raw_segment("domains")
    }

    /// Specific domain endpoint
    pub fn domain(domain: &str) -> Result<EndpointBuilder> {
        validate_domain(domain)?;
        Ok(EndpointBuilder::new()
            .raw_segment("domains")
            .segment(domain))
    }

    /// IP addresses collection endpoint
    pub fn ip_addresses() -> EndpointBuilder {
        EndpointBuilder::new().raw_segment("ip_addresses")
    }

    /// Specific IP address endpoint
    pub fn ip_address(ip: &str) -> Result<EndpointBuilder> {
        validate_ip(ip)?;
        Ok(EndpointBuilder::new()
            .raw_segment("ip_addresses")
            .segment(ip))
    }

    /// Analyses endpoint
    pub fn analyses() -> EndpointBuilder {
        EndpointBuilder::new().raw_segment("analyses")
    }

    /// Specific analysis endpoint
    pub fn analysis(analysis_id: &str) -> EndpointBuilder {
        EndpointBuilder::new()
            .raw_segment("analyses")
            .segment(analysis_id)
    }

    /// Comments endpoint for a resource
    pub fn comments(resource_type: &str, resource_id: &str) -> EndpointBuilder {
        EndpointBuilder::new()
            .raw_segment(resource_type)
            .segment(resource_id)
            .raw_segment("comments")
    }

    /// Votes endpoint for a resource
    pub fn votes(resource_type: &str, resource_id: &str) -> EndpointBuilder {
        EndpointBuilder::new()
            .raw_segment(resource_type)
            .segment(resource_id)
            .raw_segment("votes")
    }

    /// Search endpoint
    pub fn search() -> EndpointBuilder {
        EndpointBuilder::new().raw_segment("search")
    }

    /// Private files endpoint
    pub fn private_files() -> EndpointBuilder {
        EndpointBuilder::new()
            .raw_segment("private")
            .raw_segment("files")
    }

    /// Specific private file endpoint
    pub fn private_file(sha256: &str) -> Result<EndpointBuilder> {
        validate_hash(sha256)?;
        Ok(EndpointBuilder::new()
            .raw_segment("private")
            .raw_segment("files")
            .segment(sha256))
    }

    /// Private URLs endpoint
    pub fn private_urls() -> EndpointBuilder {
        EndpointBuilder::new()
            .raw_segment("private")
            .raw_segment("urls")
    }

    /// Feeds endpoint
    pub fn feeds(resource_type: &str) -> EndpointBuilder {
        EndpointBuilder::new()
            .raw_segment("feeds")
            .raw_segment(resource_type)
    }

    /// Collections endpoint
    pub fn collections() -> EndpointBuilder {
        EndpointBuilder::new().raw_segment("collections")
    }

    /// Specific collection endpoint
    pub fn collection(collection_id: &str) -> EndpointBuilder {
        EndpointBuilder::new()
            .raw_segment("collections")
            .segment(collection_id)
    }
}

/// Encode a path segment for URL safety
pub fn encode_path_segment(segment: &str) -> String {
    urlencoding::encode(segment).into_owned()
}

/// Build a query string from parameters
pub fn build_query_string(params: &HashMap<String, String>) -> String {
    if params.is_empty() {
        return String::new();
    }

    let mut pairs: Vec<_> = params.iter().collect();
    pairs.sort_by_key(|(k, _)| *k); // Sort for consistency

    pairs
        .into_iter()
        .map(|(k, v)| format!("{}={}", urlencoding::encode(k), urlencoding::encode(v)))
        .collect::<Vec<_>>()
        .join("&")
}

/// Validate a file hash (MD5, SHA1, SHA256)
pub fn validate_hash(hash: &str) -> Result<()> {
    let hash = hash.trim();

    if hash.is_empty() {
        return Err(Error::bad_request("Hash cannot be empty"));
    }

    // Check if it contains only hexadecimal characters
    if !hash.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(Error::bad_request(
            "Hash must contain only hexadecimal characters",
        ));
    }

    // Check length for common hash types
    match hash.len() {
        32 => Ok(()), // MD5
        40 => Ok(()), // SHA1
        64 => Ok(()), // SHA256
        _ => Err(Error::bad_request(
            "Hash must be 32 (MD5), 40 (SHA1), or 64 (SHA256) characters long",
        )),
    }
}

/// Validate a domain name
pub fn validate_domain(domain: &str) -> Result<()> {
    let domain = domain.trim();

    if domain.is_empty() {
        return Err(Error::bad_request("Domain cannot be empty"));
    }

    if domain.len() > 253 {
        return Err(Error::bad_request(
            "Domain name too long (max 253 characters)",
        ));
    }

    // Basic domain validation
    if domain.starts_with('.') || domain.ends_with('.') {
        return Err(Error::bad_request("Domain cannot start or end with '.'"));
    }

    if domain.starts_with('-') || domain.ends_with('-') {
        return Err(Error::bad_request("Domain cannot start or end with '-'"));
    }

    // Check for valid characters (simplified validation)
    if !domain
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
    {
        return Err(Error::bad_request("Domain contains invalid characters"));
    }

    Ok(())
}

/// Validate an IP address (IPv4 or IPv6)
pub fn validate_ip(ip: &str) -> Result<()> {
    let ip = ip.trim();

    if ip.is_empty() {
        return Err(Error::bad_request("IP address cannot be empty"));
    }

    // Try to parse as std::net::IpAddr for validation
    ip.parse::<std::net::IpAddr>()
        .map_err(|_| Error::bad_request("Invalid IP address format"))?;

    Ok(())
}

/// Query parameter builder for common patterns
#[derive(Debug, Clone)]
pub struct QueryBuilder {
    params: HashMap<String, String>,
}

impl Default for QueryBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl QueryBuilder {
    /// Create a new query builder
    pub fn new() -> Self {
        Self {
            params: HashMap::new(),
        }
    }

    /// Add a parameter
    pub fn param<K, V>(mut self, key: K, value: V) -> Self
    where
        K: Into<String>,
        V: fmt::Display,
    {
        self.params.insert(key.into(), value.to_string());
        self
    }

    /// Add an optional parameter
    pub fn param_opt<K, V>(self, key: K, value: Option<V>) -> Self
    where
        K: Into<String>,
        V: fmt::Display,
    {
        match value {
            Some(v) => self.param(key, v),
            None => self,
        }
    }

    /// Add limit parameter
    pub fn limit(self, limit: u32) -> Self {
        self.param("limit", limit)
    }

    /// Add cursor parameter
    pub fn cursor(self, cursor: &str) -> Self {
        self.param("cursor", cursor)
    }

    /// Add filter parameter
    pub fn filter(self, filter: &str) -> Self {
        self.param("filter", filter)
    }

    /// Add order parameter
    pub fn order(self, order: &str) -> Self {
        self.param("order", order)
    }

    /// Build the query string
    pub fn build(self) -> String {
        build_query_string(&self.params)
    }

    /// Get parameters as HashMap
    pub fn into_params(self) -> HashMap<String, String> {
        self.params
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
