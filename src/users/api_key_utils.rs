//! Utilities for API key generation and validation

use rand::Rng;

/// Generate a mock API key in VirusTotal's format
///
/// VirusTotal API keys are typically 64-character hexadecimal strings
/// This is useful for testing and mocking, but real API keys must come from VirusTotal
pub fn generate_mock_api_key() -> String {
    const HEX_CHARS: &[u8] = b"0123456789abcdef";
    let mut rng = rand::thread_rng();

    (0..64)
        .map(|_| {
            let idx = rng.gen_range(0..HEX_CHARS.len());
            HEX_CHARS[idx] as char
        })
        .collect()
}

/// Validate if a string looks like a valid VirusTotal API key format
///
/// Checks:
/// - Length is 64 characters
/// - All characters are hexadecimal (0-9, a-f, A-F)
pub fn is_valid_api_key_format(key: &str) -> bool {
    key.len() == 64 && key.chars().all(|c| c.is_ascii_hexdigit())
}

/// Mask an API key for display (shows first 8 and last 4 characters)
pub fn mask_api_key(key: &str) -> String {
    if key.len() <= 12 {
        return "*".repeat(key.len());
    }

    format!(
        "{}...{}",
        &key[..8.min(key.len())],
        &key[key.len().saturating_sub(4)..]
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_mock_api_key() {
        let key = generate_mock_api_key();
        assert_eq!(key.len(), 64);
        assert!(key.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_is_valid_api_key_format() {
        // Valid key
        let valid_key = "a".repeat(64);
        assert!(is_valid_api_key_format(&valid_key));

        // Invalid - too short
        let short_key = "a".repeat(63);
        assert!(!is_valid_api_key_format(&short_key));

        // Invalid - too long
        let long_key = "a".repeat(65);
        assert!(!is_valid_api_key_format(&long_key));

        // Invalid - contains non-hex characters
        let invalid_chars = "g".repeat(64);
        assert!(!is_valid_api_key_format(&invalid_chars));

        // Valid - uppercase hex
        let uppercase_key = "ABCDEF0123456789".repeat(4);
        assert!(is_valid_api_key_format(&uppercase_key));
    }

    #[test]
    fn test_mask_api_key() {
        let key = "1234567890abcdef".repeat(4); // 64 chars
        let masked = mask_api_key(&key);
        assert_eq!(masked, "12345678...cdef");

        let short_key = "12345";
        let masked_short = mask_api_key(short_key);
        assert_eq!(masked_short, "*****");
    }
}
