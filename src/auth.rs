use std::fmt;
use crate::crypto::{encrypt_api_key, decrypt_api_key, EncryptedApiKey};
use crate::Error;

#[derive(Debug, Clone)]
pub struct ApiKey(String);

impl ApiKey {
    pub fn new(key: impl Into<String>) -> Self {
        Self(key.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Encrypt this API key using FluxEncrypt
    pub fn encrypt(&self) -> Result<EncryptedApiKey, Error> {
        encrypt_api_key(&self.0)
            .map_err(|e| Error::CryptoError(format!("Failed to encrypt API key: {}", e)))
    }

    /// Create an ApiKey from an encrypted key using FluxEncrypt
    pub fn from_encrypted(encrypted: &EncryptedApiKey) -> Result<Self, Error> {
        let decrypted = decrypt_api_key(encrypted)
            .map_err(|e| Error::CryptoError(format!("Failed to decrypt API key: {}", e)))?;
        Ok(Self::new(decrypted))
    }
}

impl fmt::Display for ApiKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ApiKey(***)")
    }
}

impl From<String> for ApiKey {
    fn from(key: String) -> Self {
        Self::new(key)
    }
}

impl From<&str> for ApiKey {
    fn from(key: &str) -> Self {
        Self::new(key)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApiTier {
    Public,
    Premium,
}

impl ApiTier {
    pub fn daily_limit(&self) -> Option<u32> {
        match self {
            ApiTier::Public => Some(500),
            ApiTier::Premium => None,
        }
    }

    pub fn requests_per_minute(&self) -> u32 {
        match self {
            ApiTier::Public => 4,
            ApiTier::Premium => u32::MAX,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_api_key_creation() {
        let key = ApiKey::new("test_key");
        assert_eq!(key.as_str(), "test_key");
    }

    #[test]
    fn test_api_key_display_hides_value() {
        let key = ApiKey::new("secret_key");
        assert_eq!(format!("{}", key), "ApiKey(***)");
    }

    #[test]
    fn test_api_tier_limits() {
        assert_eq!(ApiTier::Public.daily_limit(), Some(500));
        assert_eq!(ApiTier::Public.requests_per_minute(), 4);

        assert_eq!(ApiTier::Premium.daily_limit(), None);
        assert_eq!(ApiTier::Premium.requests_per_minute(), u32::MAX);
    }
}
