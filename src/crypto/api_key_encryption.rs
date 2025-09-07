//! API key encryption using the FluxEncrypt crate for secure storage

use fluxencrypt::{cryptum, FluxError};
use fluxencrypt::keys::{KeyPair, PublicKey, PrivateKey};
use fluxencrypt::env::EnvSecretProvider;
use serde::{Deserialize, Serialize};
use base64::Engine;
use std::env;

/// Environment variable names for FluxEncrypt keys
pub const FLUX_PUBLIC_KEY_ENV: &str = "FLUX_PUBLIC_KEY";
pub const FLUX_PRIVATE_KEY_ENV: &str = "FLUX_PRIVATE_KEY";

/// Represents an encrypted API key with metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedApiKey {
    /// The encrypted API key data (base64 encoded)
    pub encrypted_data: String,
    /// Version identifier for encryption format
    pub version: u8,
}

impl EncryptedApiKey {
    /// Current encryption version
    pub const CURRENT_VERSION: u8 = 1;

    /// Create a new encrypted API key
    pub fn new(encrypted_data: String) -> Self {
        Self {
            encrypted_data,
            version: Self::CURRENT_VERSION,
        }
    }
}

/// Get or generate FluxEncrypt keys from environment
fn get_or_generate_keys() -> Result<(PublicKey, PrivateKey), FluxError> {
    // Try to load from environment first
    if env::var(FLUX_PUBLIC_KEY_ENV).is_ok() && env::var(FLUX_PRIVATE_KEY_ENV).is_ok() {
        let provider = EnvSecretProvider::new();
        let public_key = provider.get_public_key(FLUX_PUBLIC_KEY_ENV)?;
        let private_key = provider.get_private_key(FLUX_PRIVATE_KEY_ENV)?;
        Ok((public_key, private_key))
    } else {
        // Generate new keys if not found
        eprintln!("FluxEncrypt keys not found in environment. Generating new keys...");
        let keypair = KeyPair::generate(4096)?;
        
        // Display instructions for saving keys
        let public_pem_str = keypair.public_key().to_pem()?;
        let private_pem_str = keypair.private_key().to_pem()?;
        
        let public_base64 = base64::engine::general_purpose::STANDARD.encode(&public_pem_str);
        let private_base64 = base64::engine::general_purpose::STANDARD.encode(&private_pem_str);
        
        eprintln!("\n========================================");
        eprintln!("Generated new FluxEncrypt keys!");
        eprintln!("Save these environment variables:");
        eprintln!("========================================\n");
        eprintln!("export {}=\"{}\"", FLUX_PUBLIC_KEY_ENV, public_base64);
        eprintln!("\nexport {}=\"{}\"", FLUX_PRIVATE_KEY_ENV, private_base64);
        eprintln!("\n========================================");
        eprintln!("WARNING: Save these keys securely!");
        eprintln!("You will need them to decrypt your API keys.");
        eprintln!("========================================\n");
        
        Ok((keypair.public_key().clone(), keypair.private_key().clone()))
    }
}

/// Encrypt an API key using FluxEncrypt with RSA keys
///
/// # Arguments
/// * `api_key` - The plaintext API key to encrypt
///
/// # Returns
/// An `EncryptedApiKey` containing the encrypted data
///
/// # Errors
/// Returns an error if encryption fails or keys are not available
pub fn encrypt_api_key(api_key: &str) -> Result<EncryptedApiKey, FluxError> {
    let (public_key, _) = get_or_generate_keys()?;
    let cryptum = cryptum()?;
    
    // Encrypt the API key
    let encrypted = cryptum.encrypt(&public_key, api_key.as_bytes())?;
    
    // Convert encrypted bytes to base64 for storage
    let encrypted_base64 = base64::engine::general_purpose::STANDARD.encode(&encrypted);
    Ok(EncryptedApiKey::new(encrypted_base64))
}

/// Decrypt an API key using FluxEncrypt with RSA keys
///
/// # Arguments
/// * `encrypted_key` - The encrypted API key data
///
/// # Returns
/// The decrypted API key as a string
///
/// # Errors
/// Returns an error if decryption fails or keys are not available
pub fn decrypt_api_key(encrypted_key: &EncryptedApiKey) -> Result<String, FluxError> {
    let (_, private_key) = get_or_generate_keys()?;
    let cryptum = cryptum()?;
    
    // Decode from base64
    let encrypted_data = base64::engine::general_purpose::STANDARD
        .decode(&encrypted_key.encrypted_data)
        .map_err(|e| FluxError::invalid_input(format!("Base64 decode error: {}", e)))?;
    
    // Decrypt the data
    let decrypted = cryptum.decrypt(&private_key, &encrypted_data)?;
    
    String::from_utf8(decrypted)
        .map_err(|e| FluxError::invalid_input(format!("UTF-8 decode error: {}", e)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt_api_key() {
        // Set up test keys in environment
        let keypair = KeyPair::generate(2048).unwrap();
        
        env::set_var(FLUX_PUBLIC_KEY_ENV, base64::engine::general_purpose::STANDARD.encode(&keypair.public_key().to_pem().unwrap()));
        env::set_var(FLUX_PRIVATE_KEY_ENV, base64::engine::general_purpose::STANDARD.encode(&keypair.private_key().to_pem().unwrap()));
        
        let api_key = "test_api_key_12345";

        // Encrypt the API key
        let encrypted = encrypt_api_key(api_key).unwrap();
        assert_ne!(encrypted.encrypted_data, api_key);
        assert_eq!(encrypted.version, EncryptedApiKey::CURRENT_VERSION);

        // Decrypt the API key
        let decrypted = decrypt_api_key(&encrypted).unwrap();
        assert_eq!(decrypted, api_key);
        
        // Clean up
        env::remove_var(FLUX_PUBLIC_KEY_ENV);
        env::remove_var(FLUX_PRIVATE_KEY_ENV);
    }

    #[test]
    fn test_decrypt_with_wrong_keys() {
        // Set up first key pair
        let keypair1 = KeyPair::generate(2048).unwrap();
        env::set_var(FLUX_PUBLIC_KEY_ENV, base64::engine::general_purpose::STANDARD.encode(&keypair1.public_key().to_pem().unwrap()));
        env::set_var(FLUX_PRIVATE_KEY_ENV, base64::engine::general_purpose::STANDARD.encode(&keypair1.private_key().to_pem().unwrap()));
        
        let api_key = "test_api_key_12345";
        let encrypted = encrypt_api_key(api_key).unwrap();
        
        // Switch to different keys
        let keypair2 = KeyPair::generate(2048).unwrap();
        env::set_var(FLUX_PUBLIC_KEY_ENV, base64::engine::general_purpose::STANDARD.encode(&keypair2.public_key().to_pem().unwrap()));
        env::set_var(FLUX_PRIVATE_KEY_ENV, base64::engine::general_purpose::STANDARD.encode(&keypair2.private_key().to_pem().unwrap()));
        
        // Try to decrypt with wrong keys
        let result = decrypt_api_key(&encrypted);
        assert!(result.is_err());
        
        // Clean up
        env::remove_var(FLUX_PUBLIC_KEY_ENV);
        env::remove_var(FLUX_PRIVATE_KEY_ENV);
    }

    #[test]
    fn test_encrypted_api_key_serialization() {
        let encrypted_key = EncryptedApiKey::new("encrypted_data".to_string());
        
        // Serialize to JSON
        let json = serde_json::to_string(&encrypted_key).unwrap();
        
        // Deserialize from JSON
        let deserialized: EncryptedApiKey = serde_json::from_str(&json).unwrap();
        
        assert_eq!(deserialized.encrypted_data, encrypted_key.encrypted_data);
        assert_eq!(deserialized.version, encrypted_key.version);
    }
}