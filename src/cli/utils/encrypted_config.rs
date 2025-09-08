//! Utilities for handling encrypted API keys in CLI configuration

use crate::crypto::{encrypt_api_key, EncryptedApiKey, FLUX_PRIVATE_KEY_ENV, FLUX_PUBLIC_KEY_ENV};
use crate::{ApiKey, Error};
use std::env;
use std::io::{self, Write};

/// Load API key from environment, handling both encrypted and plaintext formats
pub fn load_api_key_from_env(env_var: &str, insecure: bool) -> Result<ApiKey, Error> {
    let value = env::var(env_var).map_err(|_| Error::Configuration {
        message: format!("Environment variable {} not set", env_var),
    })?;

    // Check if the value is encrypted (starts with "ENCRYPTED:")
    if value.starts_with("ENCRYPTED:") {
        if insecure {
            return Err(Error::Configuration {
                message: "Cannot use --insecure flag with encrypted API key".to_string(),
            });
        }

        // Check if FluxEncrypt keys are available
        if env::var(FLUX_PRIVATE_KEY_ENV).is_err() {
            eprintln!("Warning: FluxEncrypt private key not found in environment.");
            eprintln!("The encrypted API key cannot be decrypted without the private key.");
            eprintln!(
                "Set {} environment variable with your FluxEncrypt private key.",
                FLUX_PRIVATE_KEY_ENV
            );
            return Err(Error::Configuration {
                message: format!(
                    "FluxEncrypt private key not found. Set {} environment variable.",
                    FLUX_PRIVATE_KEY_ENV
                ),
            });
        }

        // Parse the encrypted data
        let encrypted_data = value.strip_prefix("ENCRYPTED:").unwrap();
        let encrypted_key: EncryptedApiKey =
            serde_json::from_str(encrypted_data).map_err(Error::Json)?;

        // Decrypt using FluxEncrypt
        ApiKey::from_encrypted(&encrypted_key)
    } else {
        // Plain text API key
        if !insecure {
            eprintln!(
                "Warning: API key stored in plaintext. Consider encrypting it for better security."
            );
            eprintln!("Use 'vt-cli config encrypt-key' to encrypt your API key.");
        }
        Ok(ApiKey::new(value))
    }
}

/// Save encrypted API key to environment variable format
pub fn format_encrypted_api_key(api_key: &str) -> Result<String, Error> {
    // Check if FluxEncrypt keys are available
    if env::var(FLUX_PUBLIC_KEY_ENV).is_err() {
        eprintln!("Note: FluxEncrypt public key not found. New keys will be generated.");
    }

    let encrypted = encrypt_api_key(api_key)
        .map_err(|e| Error::CryptoError(format!("Failed to encrypt API key: {}", e)))?;

    let json = serde_json::to_string(&encrypted).map_err(Error::Json)?;

    Ok(format!("ENCRYPTED:{}", json))
}

/// Display instructions for setting up encrypted API key
pub fn display_encryption_instructions(encrypted_value: &str) {
    println!("\n========================================");
    println!("API Key Encrypted Successfully!");
    println!("========================================\n");
    println!("To use the encrypted API key, set your environment variable:");
    println!("\nexport VTI_API_KEY=\"{}\"", encrypted_value);
    println!("\nIMPORTANT: FluxEncrypt Keys Required!");
    println!("========================================");
    println!("Make sure you have saved the FluxEncrypt keys that were displayed above.");
    println!("You need both FLUX_PUBLIC_KEY and FLUX_PRIVATE_KEY environment variables.");
    println!("\nSecurity Notes:");
    println!("- Never commit the FluxEncrypt private key to version control");
    println!("- Store the private key securely (e.g., in a password manager)");
    println!("- The public key can be shared but keep it consistent");
    println!("- Without the private key, encrypted API keys cannot be decrypted");
}

/// Prompt user for input (generic helper)
pub fn prompt_for_input(prompt: &str) -> Result<String, Error> {
    print!("{}: ", prompt);
    io::stdout().flush().map_err(|e| Error::Io {
        message: format!("Failed to flush stdout: {}", e),
    })?;

    let mut input = String::new();
    io::stdin().read_line(&mut input).map_err(|e| Error::Io {
        message: format!("Failed to read input: {}", e),
    })?;

    Ok(input.trim().to_string())
}
