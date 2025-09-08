use crate::users::{UserUpdate, UserUpdateAttributes, UserUpdateRequest};
use crate::{Client, Error};
use clap::{Args, Subcommand};
use serde_json::json;
use std::collections::HashMap;

/// Command line arguments for user management operations
#[derive(Debug, Args, Clone)]
pub struct UserCommand {
    #[command(subcommand)]
    pub command: UserSubcommands,
}

/// Available user management subcommands
#[derive(Debug, Subcommand, Clone)]
pub enum UserSubcommands {
    /// Get information about a user (defaults to current user if no ID provided)
    Get {
        /// User ID or API key (defaults to current user)
        #[arg(value_name = "USER_ID")]
        user_id: Option<String>,
    },
    /// Update user information (defaults to current user if no ID provided)
    Update {
        /// User ID or API key (defaults to current user)
        #[arg(value_name = "USER_ID")]
        user_id: Option<String>,

        /// Update first name
        #[arg(long = "first-name")]
        first_name: Option<String>,

        /// Update last name
        #[arg(long = "last-name")]
        last_name: Option<String>,

        /// Update country
        #[arg(long = "country")]
        country: Option<String>,

        /// Update profile phrase
        #[arg(long = "profile-phrase")]
        profile_phrase: Option<String>,

        /// Update bio (legacy, use --profile-phrase instead)
        #[arg(long = "bio")]
        bio: Option<String>,

        /// Update preferences (format: key=value)
        #[arg(long = "preference", value_parser = parse_key_value)]
        preferences: Vec<(String, String)>,
    },
    /// Delete a user account
    Delete {
        /// User ID or API key (required)
        #[arg(value_name = "USER_ID")]
        user_id: String,

        /// User's password (required for deletion)
        #[arg(long = "password")]
        password: String,
    },
    /// Reset/regenerate API key (defaults to current user if no ID provided)
    ResetApiKey {
        /// User ID or API key (defaults to current user)
        #[arg(value_name = "USER_ID")]
        user_id: Option<String>,

        /// Confirm the API key reset (required unless --force is used)
        #[arg(long = "confirm", conflicts_with = "force")]
        confirm: bool,

        /// Force reset without confirmation prompt
        #[arg(long = "force", short = 'f')]
        force: bool,
    },
}

/// Parse a key=value string into a tuple
fn parse_key_value(s: &str) -> Result<(String, String), String> {
    let parts: Vec<_> = s.splitn(2, '=').collect();
    if parts.len() != 2 {
        return Err(format!("Invalid key=value format: {s}"));
    }
    Ok((parts[0].to_string(), parts[1].to_string()))
}

/// Execute user management commands
///
/// # Errors
///
/// Returns an error if:
/// - API request fails (network issues, authentication problems, etc.)
/// - Invalid user ID provided
/// - Insufficient permissions for the requested operation
/// - JSON serialization/deserialization fails
/// - User input validation fails
/// - Required fields are missing for update operations
pub async fn execute(client: &Client, cmd: UserCommand) -> Result<(), Error> {
    let users_client = client.users();

    match cmd.command {
        UserSubcommands::Get { user_id } => {
            // Use provided user_id or default to the API key (current user)
            let id = user_id.unwrap_or_else(|| client.api_key().to_string());
            let response = users_client.get_user(&id).await?;
            println!("{}", serde_json::to_string_pretty(&response)?);
        }

        UserSubcommands::Update {
            user_id,
            first_name,
            last_name,
            country,
            profile_phrase,
            bio,
            preferences,
        } => {
            // Build update attributes
            let mut attributes = UserUpdateAttributes::default();

            if let Some(fname) = first_name {
                attributes.first_name = Some(fname);
            }

            if let Some(lname) = last_name {
                attributes.last_name = Some(lname);
            }

            if let Some(c) = country {
                attributes.country = Some(c);
            }

            if let Some(pp) = profile_phrase {
                attributes.profile_phrase = Some(pp);
            }

            if let Some(b) = bio {
                attributes.bio = Some(b);
            }

            if !preferences.is_empty() {
                let mut prefs = HashMap::new();
                for (key, value) in preferences {
                    prefs.insert(key, json!(value));
                }
                attributes.preferences = Some(prefs);
            }

            // Create update request
            let update_request = UserUpdateRequest {
                data: UserUpdate {
                    object_type: "user".to_string(),
                    attributes,
                },
            };

            // Use provided user_id or default to the API key (current user)
            let id = user_id.unwrap_or_else(|| client.api_key().to_string());

            // Execute update
            let response = users_client.update_user(&id, &update_request).await?;

            println!("User updated successfully!");
            println!("{}", serde_json::to_string_pretty(&response)?);
        }

        UserSubcommands::Delete { user_id, password } => {
            users_client.delete_user(&user_id, &password).await?;
            println!("User deleted successfully!");
            // Note: Delete response may not contain useful data to display
        }

        UserSubcommands::ResetApiKey {
            user_id,
            confirm,
            force,
        } => {
            // Use provided user_id or default to the API key (current user)
            let id = user_id.unwrap_or_else(|| client.api_key().to_string());

            // Check for confirmation
            if !force && !confirm {
                eprintln!("Warning: Resetting the API key will invalidate the current key!");
                eprintln!("You will need to update your API key in all applications using it.");
                eprintln!();
                eprintln!("To proceed, use one of the following:");
                eprintln!("  --confirm    : Confirm you want to reset the API key");
                eprintln!("  --force (-f) : Force reset without confirmation");
                return Ok(());
            }

            println!("Resetting API key...");

            // Reset the API key
            let response = users_client.reset_api_key(&id).await?;

            println!("API key reset successfully!");

            // Display the new API key prominently
            if let Some(new_api_key) = &response.data.attributes.apikey {
                println!();
                println!("========================================");
                println!("NEW API KEY (save this securely!):");
                println!("{new_api_key}");
                println!("========================================");
                println!();
                println!("IMPORTANT:");
                println!("1. Your old API key is now invalid");
                println!("2. Update your environment variable:");
                println!("   export VTI_API_KEY={new_api_key}");
                println!("3. Update any applications using the old key");
            } else {
                println!("Note: New API key not visible in response (may need owner permissions)");
            }

            // Also show the full response for completeness
            println!();
            println!("Full response:");
            println!("{}", serde_json::to_string_pretty(&response)?);
        }
    }

    Ok(())
}
