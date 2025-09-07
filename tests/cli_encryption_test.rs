//! Integration tests for CLI encryption functionality using FluxEncrypt

#[cfg(feature = "cli")]
mod cli_encryption_tests {
    use std::env;
    use fluxencrypt::keys::KeyPair;
    use base64::Engine;

    const TEST_API_KEY: &str = "test_vt_api_key_12345abcdef";

    /// Helper to set up FluxEncrypt keys in environment
    fn setup_flux_keys() -> (String, String) {
        // Generate test keys
        let keypair = KeyPair::generate(2048).unwrap();
        let public_pem_str = keypair.public_key().to_pem().unwrap();
        let private_pem_str = keypair.private_key().to_pem().unwrap();
        
        // Encode PEM strings to base64
        let public_base64 = base64::engine::general_purpose::STANDARD.encode(&public_pem_str);
        let private_base64 = base64::engine::general_purpose::STANDARD.encode(&private_pem_str);
        
        // Set environment variables
        env::set_var("FLUX_PUBLIC_KEY", &public_base64);
        env::set_var("FLUX_PRIVATE_KEY", &private_base64);
        
        (public_base64, private_base64)
    }

    /// Helper to clean up environment
    fn cleanup_env() {
        env::remove_var("FLUX_PUBLIC_KEY");
        env::remove_var("FLUX_PRIVATE_KEY");
        env::remove_var("VTI_API_KEY");
    }

    #[test]
    fn test_encrypt_decrypt_api_key_programmatically() {
        use virustotal_rs::{
            encrypt_api_key, decrypt_api_key,
            ApiKey,
        };
        
        // Set up keys
        let (_pub_key, _priv_key) = setup_flux_keys();
        
        // Test encryption
        let encrypted = encrypt_api_key(TEST_API_KEY).unwrap();
        assert!(!encrypted.encrypted_data.is_empty());
        assert_ne!(encrypted.encrypted_data, TEST_API_KEY);
        
        // Test decryption
        let decrypted = decrypt_api_key(&encrypted).unwrap();
        assert_eq!(decrypted, TEST_API_KEY);
        
        // Test ApiKey integration
        let api_key = ApiKey::new(TEST_API_KEY);
        let encrypted_key = api_key.encrypt().unwrap();
        let decrypted_key = ApiKey::from_encrypted(&encrypted_key).unwrap();
        assert_eq!(decrypted_key.as_str(), TEST_API_KEY);
        
        cleanup_env();
    }

    #[test]
    fn test_encrypt_without_keys_generates_new() {
        use virustotal_rs::encrypt_api_key;
        
        // Ensure no keys are set
        cleanup_env();
        
        // This should generate new keys
        let result = encrypt_api_key(TEST_API_KEY);
        
        // Should succeed (keys are generated)
        assert!(result.is_ok());
        
        // Keys should now be available
        assert!(env::var("FLUX_PUBLIC_KEY").is_ok() || env::var("FLUX_PRIVATE_KEY").is_ok());
        
        cleanup_env();
    }

    #[test]
    fn test_decrypt_with_wrong_keys_fails() {
        use virustotal_rs::{encrypt_api_key, decrypt_api_key};
        
        // Set up first key pair
        setup_flux_keys();
        let encrypted = encrypt_api_key(TEST_API_KEY).unwrap();
        
        // Switch to different keys
        cleanup_env();
        setup_flux_keys(); // Generates new, different keys
        
        // Decryption should fail
        let result = decrypt_api_key(&encrypted);
        assert!(result.is_err());
        
        cleanup_env();
    }

    #[test]
    fn test_encrypted_api_key_format() {
        use virustotal_rs::cli::utils::format_encrypted_api_key;
        
        setup_flux_keys();
        
        // Format for environment variable
        let formatted = format_encrypted_api_key(TEST_API_KEY).unwrap();
        
        // Should start with ENCRYPTED: prefix
        assert!(formatted.starts_with("ENCRYPTED:"));
        
        // Should contain valid JSON
        let json_part = formatted.strip_prefix("ENCRYPTED:").unwrap();
        let parsed: serde_json::Value = serde_json::from_str(json_part).unwrap();
        assert!(parsed.get("encrypted_data").is_some());
        assert!(parsed.get("version").is_some());
        
        cleanup_env();
    }

    #[test]
    fn test_load_encrypted_api_key_from_env() {
        use virustotal_rs::cli::utils::{format_encrypted_api_key, load_api_key_from_env};
        
        setup_flux_keys();
        
        // Create encrypted API key
        let encrypted_value = format_encrypted_api_key(TEST_API_KEY).unwrap();
        
        // Set in environment
        env::set_var("VTI_API_KEY", &encrypted_value);
        
        // Load from environment
        let api_key = load_api_key_from_env("VTI_API_KEY", false).unwrap();
        assert_eq!(api_key.as_str(), TEST_API_KEY);
        
        cleanup_env();
    }

    #[test]
    fn test_load_plaintext_api_key_with_warning() {
        use virustotal_rs::cli::utils::load_api_key_from_env;
        
        // Set plaintext API key
        env::set_var("VTI_API_KEY", TEST_API_KEY);
        
        // Load with insecure flag (no warning)
        let api_key = load_api_key_from_env("VTI_API_KEY", true).unwrap();
        assert_eq!(api_key.as_str(), TEST_API_KEY);
        
        // Load without insecure flag (should work but warn)
        let api_key = load_api_key_from_env("VTI_API_KEY", false).unwrap();
        assert_eq!(api_key.as_str(), TEST_API_KEY);
        
        cleanup_env();
    }

    #[test]
    fn test_cannot_decrypt_without_private_key() {
        use virustotal_rs::cli::utils::{format_encrypted_api_key, load_api_key_from_env};
        
        setup_flux_keys();
        
        // Create encrypted API key
        let encrypted_value = format_encrypted_api_key(TEST_API_KEY).unwrap();
        
        // Remove private key
        env::remove_var("FLUX_PRIVATE_KEY");
        
        // Set encrypted key in environment
        env::set_var("VTI_API_KEY", &encrypted_value);
        
        // Loading should fail
        let result = load_api_key_from_env("VTI_API_KEY", false);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("private key"));
        
        cleanup_env();
    }

    #[test]
    fn test_encryption_roundtrip_with_serialization() {
        use virustotal_rs::{encrypt_api_key, decrypt_api_key, EncryptedApiKey};
        
        setup_flux_keys();
        
        // Encrypt
        let encrypted = encrypt_api_key(TEST_API_KEY).unwrap();
        
        // Serialize to JSON
        let json = serde_json::to_string(&encrypted).unwrap();
        
        // Deserialize from JSON
        let deserialized: EncryptedApiKey = serde_json::from_str(&json).unwrap();
        
        // Decrypt
        let decrypted = decrypt_api_key(&deserialized).unwrap();
        assert_eq!(decrypted, TEST_API_KEY);
        
        cleanup_env();
    }

    #[test]
    fn test_multiple_api_keys_encryption() {
        use virustotal_rs::{encrypt_api_key, decrypt_api_key};
        
        setup_flux_keys();
        
        let api_keys = vec![
            "key_1_abcdef123456",
            "key_2_fedcba654321",
            "key_3_123abc456def",
        ];
        
        // Encrypt all keys
        let encrypted_keys: Vec<_> = api_keys
            .iter()
            .map(|key| encrypt_api_key(key).unwrap())
            .collect();
        
        // Verify all are different
        for i in 0..encrypted_keys.len() {
            for j in i + 1..encrypted_keys.len() {
                assert_ne!(
                    encrypted_keys[i].encrypted_data,
                    encrypted_keys[j].encrypted_data
                );
            }
        }
        
        // Decrypt all keys
        for (i, encrypted) in encrypted_keys.iter().enumerate() {
            let decrypted = decrypt_api_key(encrypted).unwrap();
            assert_eq!(decrypted, api_keys[i]);
        }
        
        cleanup_env();
    }

    #[test]
    fn test_base64_encoding_safety() {
        use virustotal_rs::encrypt_api_key;
        
        setup_flux_keys();
        
        // Test with API key containing special characters
        let special_key = "test+key/with=special&chars";
        let encrypted = encrypt_api_key(special_key).unwrap();
        
        // Encrypted data should be valid base64
        let decode_result = base64::engine::general_purpose::STANDARD
            .decode(&encrypted.encrypted_data);
        assert!(decode_result.is_ok());
        
        cleanup_env();
    }
}