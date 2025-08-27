//! Validation functions for URL components

use crate::error::{Error, Result};

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

/// Check basic domain properties (empty, length)
fn validate_domain_basic(domain: &str) -> Result<()> {
    if domain.is_empty() {
        return Err(Error::bad_request("Domain cannot be empty"));
    }

    if domain.len() > 253 {
        return Err(Error::bad_request(
            "Domain name too long (max 253 characters)",
        ));
    }

    Ok(())
}

/// Check domain format rules (dots and dashes at edges)
fn validate_domain_format(domain: &str) -> Result<()> {
    if domain.starts_with('.') || domain.ends_with('.') {
        return Err(Error::bad_request("Domain cannot start or end with '.'"));
    }

    if domain.starts_with('-') || domain.ends_with('-') {
        return Err(Error::bad_request("Domain cannot start or end with '-'"));
    }

    Ok(())
}

/// Check domain character validity
fn validate_domain_characters(domain: &str) -> Result<()> {
    if !domain
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
    {
        return Err(Error::bad_request("Domain contains invalid characters"));
    }

    Ok(())
}

/// Validate a domain name
pub fn validate_domain(domain: &str) -> Result<()> {
    let domain = domain.trim();

    validate_domain_basic(domain)?;
    validate_domain_format(domain)?;
    validate_domain_characters(domain)?;

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
