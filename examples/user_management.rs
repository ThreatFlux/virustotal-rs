//! Example demonstrating comprehensive user management with VirusTotal API
//!
//! This example shows:
//! - Getting user information (current user and specific users)
//! - Updating user profile information
//! - Resetting API keys
//! - Using the API key utilities

use std::env;
use virustotal_rs::users::api_key_utils::{
    generate_mock_api_key, is_valid_api_key_format, mask_api_key,
};
use virustotal_rs::users::{UserUpdate, UserUpdateAttributes, UserUpdateRequest};
use virustotal_rs::{ApiTier, Client};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Get API key from environment
    let api_key = env::var("VTI_API_KEY").expect("Please set VTI_API_KEY environment variable");

    // Create client
    let client = Client::new(api_key.clone().into(), ApiTier::Public)?;
    let users = client.users();

    println!("VirusTotal User Management Example");
    println!("===================================\n");

    // 1. Get current user information
    println!("1. Getting current user information:");
    println!("-------------------------------------");
    match users.get_user(&api_key).await {
        Ok(response) => {
            let user = &response.data;
            println!("User ID: {}", user.id);

            // These fields are only visible for the account owner
            if let Some(email) = &user.attributes.email {
                println!("Email: {}", email);
            }
            if let Some(apikey) = &user.attributes.apikey {
                println!("API Key: {}", mask_api_key(apikey));
            }
            if let Some(has_2fa) = &user.attributes.has_2fa {
                println!("2FA Enabled: {}", has_2fa);
            }

            // Public fields
            if let Some(reputation) = &user.attributes.reputation {
                println!("Reputation: {}", reputation);
            }
            if let Some(user_since) = &user.attributes.user_since {
                let date = chrono::DateTime::from_timestamp(*user_since, 0)
                    .map(|dt| dt.format("%Y-%m-%d").to_string())
                    .unwrap_or_else(|| "Unknown".to_string());
                println!("Member Since: {}", date);
            }

            // Check privileges
            if let Some(privileges) = &user.attributes.privileges {
                println!("\nPrivileges:");
                println!("  Download files: {:?}", privileges.download_file());
                println!("  Intelligence: {:?}", privileges.intelligence());
                println!("  Private scanning: {:?}", privileges.private_scanning());
            }

            // Check quotas
            if let Some(quotas) = &user.attributes.quotas {
                println!("\nQuotas:");
                if let Some(api_monthly) = &quotas.api_requests_monthly {
                    println!(
                        "  API requests (monthly): {}/{}",
                        api_monthly.used, api_monthly.allowed
                    );
                }
            }
        }
        Err(e) => eprintln!("Error getting user: {}", e),
    }

    // 2. Demonstrate API key utilities
    println!("\n2. API Key Utilities:");
    println!("----------------------");

    // Generate a mock API key for testing
    let mock_key = generate_mock_api_key();
    println!("Generated mock API key: {}", mask_api_key(&mock_key));
    println!("Is valid format: {}", is_valid_api_key_format(&mock_key));

    // Validate the current API key format
    println!(
        "Current API key is valid format: {}",
        is_valid_api_key_format(&api_key)
    );

    // 3. Update user profile (example - not executed)
    println!("\n3. User Profile Update Examples:");
    println!("---------------------------------");
    println!("Example update request (not executed):");

    let update_example = UserUpdateRequest {
        data: UserUpdate {
            object_type: "user".to_string(),
            attributes: UserUpdateAttributes {
                first_name: Some("John".to_string()),
                last_name: Some("Doe".to_string()),
                profile_phrase: Some("Security Researcher".to_string()),
                country: Some("US".to_string()),
                ..Default::default()
            },
        },
    };

    println!("{}", serde_json::to_string_pretty(&update_example)?);

    println!("\nTo actually update, you would call:");
    println!("users.update_user(&api_key, &update_request).await");

    // 4. API Key Reset (example - not executed)
    println!("\n4. API Key Reset Example:");
    println!("-------------------------");
    println!("WARNING: This would invalidate your current API key!");
    println!("\nTo reset API key, you would call:");
    println!("users.reset_api_key(&api_key).await");
    println!("\nThe response would contain the new API key in:");
    println!("response.data.attributes.apikey");

    // 5. Getting other users (public information only)
    println!("\n5. Getting Other Users:");
    println!("-----------------------");
    println!("When querying other users, you only see public fields:");
    println!("- reputation");
    println!("- status");
    println!("- user_since");
    println!("- first_name, last_name (if publicly visible)");
    println!("\nPrivate fields are NOT visible:");
    println!("- apikey");
    println!("- email");
    println!("- has_2fa");
    println!("- privileges");
    println!("- preferences");

    println!("\n✅ Example completed successfully!");

    Ok(())
}
