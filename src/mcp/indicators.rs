//! Indicator detection and parsing for `VirusTotal` MCP integration
//!
//! This module provides functionality to detect and classify different types
//! of security indicators (hashes, IPs, domains, URLs) for automated analysis.

use regex::Regex;
use std::net::IpAddr;
use url::Url;

/// Types of indicators that can be analyzed
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IndicatorType {
    /// File hash (MD5, SHA1, SHA256, SHA512)
    Hash { hash_type: HashType, value: String },
    /// IP address (IPv4 or IPv6)
    IpAddress(String),
    /// Domain name
    Domain(String),
    /// URL
    Url(String),
    /// Unknown indicator type
    Unknown(String),
}

/// Hash types supported by `VirusTotal`
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HashType {
    Md5,
    Sha1,
    Sha256,
    Sha512,
}

impl HashType {
    /// Get the expected length of the hash
    pub fn len(&self) -> usize {
        match self {
            HashType::Md5 => 32,
            HashType::Sha1 => 40,
            HashType::Sha256 => 64,
            HashType::Sha512 => 128,
        }
    }

    /// Check if hash type is empty (always false for defined types)
    pub fn is_empty(&self) -> bool {
        false // Hash types always have a defined length
    }

    /// Get the name of the hash type
    pub fn name(&self) -> &'static str {
        match self {
            HashType::Md5 => "MD5",
            HashType::Sha1 => "SHA1",
            HashType::Sha256 => "SHA256",
            HashType::Sha512 => "SHA512",
        }
    }
}

/// Detect the type of indicator from a string input
pub fn detect_indicator_type(input: &str) -> IndicatorType {
    let trimmed = input.trim();

    // Check for hashes first (most specific)
    if let Some(hash_type) = detect_hash_type(trimmed) {
        return IndicatorType::Hash {
            hash_type,
            value: trimmed.to_lowercase(),
        };
    }

    // Check for IP addresses
    if trimmed.parse::<IpAddr>().is_ok() {
        return IndicatorType::IpAddress(trimmed.to_string());
    }

    // Check for URLs
    if is_url(trimmed) {
        return IndicatorType::Url(trimmed.to_string());
    }

    // Check for domains
    if is_domain(trimmed) {
        return IndicatorType::Domain(trimmed.to_lowercase());
    }

    // If nothing matches, return as unknown
    IndicatorType::Unknown(trimmed.to_string())
}

/// Detect hash type based on string length and format
fn detect_hash_type(input: &str) -> Option<HashType> {
    // Check if it's all hexadecimal characters
    if !input.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }

    match input.len() {
        32 => Some(HashType::Md5),
        40 => Some(HashType::Sha1),
        64 => Some(HashType::Sha256),
        128 => Some(HashType::Sha512),
        _ => None,
    }
}

/// Check if a string is a valid URL
fn is_url(input: &str) -> bool {
    if let Ok(url) = Url::parse(input) {
        // Must have a scheme and host
        url.scheme() == "http" || url.scheme() == "https"
    } else {
        false
    }
}

/// Check if a string is a valid domain name
fn is_domain(input: &str) -> bool {
    lazy_static::lazy_static! {
        static ref DOMAIN_REGEX: Regex = Regex::new(
            r"^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$"
        ).unwrap();
    }

    // Basic checks
    if input.is_empty() || input.len() > 253 || input.starts_with('.') || input.ends_with('.') {
        return false;
    }

    // Must contain at least one dot for domain
    if !input.contains('.') {
        return false;
    }

    // Check format with regex
    DOMAIN_REGEX.is_match(input)
}

impl IndicatorType {
    /// Get a human-readable description of the indicator type
    pub fn description(&self) -> String {
        match self {
            IndicatorType::Hash { hash_type, .. } => format!("{} Hash", hash_type.name()),
            IndicatorType::IpAddress(_) => "IP Address".to_string(),
            IndicatorType::Domain(_) => "Domain".to_string(),
            IndicatorType::Url(_) => "URL".to_string(),
            IndicatorType::Unknown(_) => "Unknown".to_string(),
        }
    }

    /// Get the raw value of the indicator
    pub fn value(&self) -> &str {
        match self {
            IndicatorType::Hash { value, .. } => value,
            IndicatorType::IpAddress(value) => value,
            IndicatorType::Domain(value) => value,
            IndicatorType::Url(value) => value,
            IndicatorType::Unknown(value) => value,
        }
    }

    /// Check if this indicator type is supported by the `VirusTotal` API
    pub fn is_supported(&self) -> bool {
        !matches!(self, IndicatorType::Unknown(_))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_detection() {
        // MD5
        let md5 = "d41d8cd98f00b204e9800998ecf8427e";
        if let IndicatorType::Hash { hash_type, value } = detect_indicator_type(md5) {
            assert_eq!(hash_type, HashType::Md5);
            assert_eq!(value, md5);
        } else {
            panic!("MD5 hash not detected");
        }

        // SHA1
        let sha1 = "da39a3ee5e6b4b0d3255bfef95601890afd80709";
        if let IndicatorType::Hash { hash_type, value } = detect_indicator_type(sha1) {
            assert_eq!(hash_type, HashType::Sha1);
            assert_eq!(value, sha1);
        } else {
            panic!("SHA1 hash not detected");
        }

        // SHA256
        let sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        if let IndicatorType::Hash { hash_type, value } = detect_indicator_type(sha256) {
            assert_eq!(hash_type, HashType::Sha256);
            assert_eq!(value, sha256);
        } else {
            panic!("SHA256 hash not detected");
        }

        // SHA512
        let sha512 = "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e";
        if let IndicatorType::Hash { hash_type, value } = detect_indicator_type(sha512) {
            assert_eq!(hash_type, HashType::Sha512);
            assert_eq!(value, sha512);
        } else {
            panic!("SHA512 hash not detected");
        }
    }

    #[test]
    fn test_ip_detection() {
        // IPv4
        let ipv4 = "192.168.1.1";
        if let IndicatorType::IpAddress(value) = detect_indicator_type(ipv4) {
            assert_eq!(value, ipv4);
        } else {
            panic!("IPv4 address not detected");
        }

        // IPv6
        let ipv6 = "2001:0db8:85a3:0000:0000:8a2e:0370:7334";
        if let IndicatorType::IpAddress(value) = detect_indicator_type(ipv6) {
            assert_eq!(value, ipv6);
        } else {
            panic!("IPv6 address not detected");
        }
    }

    #[test]
    fn test_domain_detection() {
        let domain = "example.com";
        if let IndicatorType::Domain(value) = detect_indicator_type(domain) {
            assert_eq!(value, domain);
        } else {
            panic!("Domain not detected");
        }

        let subdomain = "www.example.com";
        if let IndicatorType::Domain(value) = detect_indicator_type(subdomain) {
            assert_eq!(value, subdomain);
        } else {
            panic!("Subdomain not detected");
        }
    }

    #[test]
    fn test_url_detection() {
        let url = "https://example.com/path?query=value";
        if let IndicatorType::Url(value) = detect_indicator_type(url) {
            assert_eq!(value, url);
        } else {
            panic!("URL not detected");
        }

        let http_url = "http://example.com/";
        if let IndicatorType::Url(value) = detect_indicator_type(http_url) {
            assert_eq!(value, http_url);
        } else {
            panic!("HTTP URL not detected");
        }
    }

    #[test]
    fn test_unknown_detection() {
        let unknown = "this is not a valid indicator";
        if let IndicatorType::Unknown(value) = detect_indicator_type(unknown) {
            assert_eq!(value, unknown);
        } else {
            panic!("Unknown indicator not detected");
        }
    }

    #[test]
    fn test_edge_cases() {
        // Empty string
        assert!(matches!(
            detect_indicator_type(""),
            IndicatorType::Unknown(_)
        ));

        // Invalid hash (wrong length)
        assert!(matches!(
            detect_indicator_type("123456"),
            IndicatorType::Unknown(_)
        ));

        // Invalid hash (non-hex)
        assert!(matches!(
            detect_indicator_type("g41d8cd98f00b204e9800998ecf8427e"),
            IndicatorType::Unknown(_)
        ));

        // Invalid domain (no TLD)
        assert!(matches!(
            detect_indicator_type("localhost"),
            IndicatorType::Unknown(_)
        ));

        // Invalid URL (no scheme) - should be detected as Unknown because of the path
        assert!(matches!(
            detect_indicator_type("example.com/path"),
            IndicatorType::Unknown(_)
        ));
    }
}
