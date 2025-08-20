#[allow(unused_imports)]
use std::collections::HashMap;
use virustotal_rs::{ApiTier, ClientBuilder, GroupUpdateAttributes, UserUpdateAttributes};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let api_key = std::env::var("VT_API_KEY").unwrap_or_else(|_| "test_key".to_string());

    let client = ClientBuilder::new()
        .api_key(api_key.clone())
        .tier(ApiTier::Premium)
        .build()?;

    println!("Testing VirusTotal Users and Groups Management");
    println!("===============================================");
    println!("🔑 Using API key: {}...", &api_key[..8.min(api_key.len())]);
    println!("===============================================\n");

    // ========== USER MANAGEMENT ==========
    println!("1. USER MANAGEMENT");
    println!("------------------");

    let users_client = client.users();

    // Get current user info (using API key)
    println!("\nGetting current user info...");
    match users_client.get_user(&api_key).await {
        Ok(user_response) => {
            let user = &user_response.data;
            println!("✓ User retrieved successfully");
            println!("  ID: {}", user.id);
            println!("  Type: {}", user.object_type);

            if let Some(email) = &user.attributes.email {
                println!("  Email: {}", email);
            }
            if let Some(first_name) = &user.attributes.first_name {
                println!("  First Name: {}", first_name);
            }
            if let Some(last_name) = &user.attributes.last_name {
                println!("  Last Name: {}", last_name);
            }
            if let Some(country) = &user.attributes.country {
                println!("  Country: {}", country);
            }
            if let Some(status) = &user.attributes.status {
                println!("  Status: {}", status);
            }

            // Check privileges
            if let Some(privileges) = &user.attributes.privileges {
                println!("\n  Privileges:");
                if let Some(download) = privileges.download_file {
                    println!("    Download files: {}", download);
                }
                if let Some(intel) = privileges.intelligence {
                    println!("    Intelligence: {}", intel);
                }
                if let Some(private_scan) = privileges.private_scanning {
                    println!("    Private scanning: {}", private_scan);
                }
                if let Some(retrohunt) = privileges.retrohunt {
                    println!("    Retrohunt: {}", retrohunt);
                }
                if let Some(livehunt) = privileges.livehunt {
                    println!("    Livehunt: {}", livehunt);
                }
            }

            // Check quotas
            if let Some(quotas) = &user.attributes.quotas {
                println!("\n  Quotas:");
                if let Some(daily) = &quotas.api_requests_daily {
                    println!("    API requests daily: {}/{}", daily.used, daily.allowed);
                }
                if let Some(monthly) = &quotas.api_requests_monthly {
                    println!(
                        "    API requests monthly: {}/{}",
                        monthly.used, monthly.allowed
                    );
                }
                if let Some(intel_searches) = &quotas.intelligence_searches_monthly {
                    println!(
                        "    Intelligence searches: {}/{}",
                        intel_searches.used, intel_searches.allowed
                    );
                }
                if let Some(intel_downloads) = &quotas.intelligence_downloads_monthly {
                    println!(
                        "    Intelligence downloads: {}/{}",
                        intel_downloads.used, intel_downloads.allowed
                    );
                }
            }
        }
        Err(e) => {
            println!("✗ Error getting user: {}", e);
            println!("  Note: Requires valid API key");
        }
    }

    // Update user attributes
    println!("\n2. UPDATE USER ATTRIBUTES");
    println!("-------------------------");

    let update_attrs = UserUpdateAttributes {
        bio: Some("VirusTotal SDK Test User".to_string()),
        ..Default::default()
    };

    let update_request = virustotal_rs::UserUpdateRequest {
        data: virustotal_rs::UserUpdate::new(update_attrs),
    };

    println!("Attempting to update user bio...");
    match users_client.update_user(&api_key, &update_request).await {
        Ok(updated_user) => {
            println!("✓ User updated successfully");
            if let Some(bio) = &updated_user.data.attributes.bio {
                println!("  New bio: {}", bio);
            }
        }
        Err(e) => {
            println!("✗ Error updating user: {}", e);
            println!("  Note: May require appropriate permissions");
        }
    }

    // Get user relationships
    println!("\n3. USER RELATIONSHIPS");
    println!("---------------------");

    // Get user's API keys
    println!("\nGetting user's API keys...");
    match users_client
        .get_relationship::<serde_json::Value>(&api_key, "api_keys", Some(10), None)
        .await
    {
        Ok(api_keys) => {
            println!("✓ Retrieved {} API keys", api_keys.data.len());
            for (i, _key) in api_keys.data.iter().enumerate() {
                println!("  {}. Key data available", i + 1);
            }
        }
        Err(e) => {
            println!("✗ Error getting API keys: {}", e);
        }
    }

    // Get user's groups
    println!("\nGetting user's groups...");
    match users_client
        .get_relationship::<serde_json::Value>(&api_key, "groups", Some(10), None)
        .await
    {
        Ok(groups) => {
            println!("✓ User belongs to {} groups", groups.data.len());
            for (i, _group) in groups.data.iter().enumerate() {
                println!("  {}. Group membership found", i + 1);
            }
        }
        Err(e) => {
            println!("✗ Error getting groups: {}", e);
        }
    }

    // ========== GROUP MANAGEMENT ==========
    println!("\n4. GROUP MANAGEMENT");
    println!("-------------------");

    let groups_client = client.groups();

    // Note: You'll need a valid group ID to test with
    let test_group_id = "your_group_id_here";

    println!("\nGetting group info for ID: {}", test_group_id);
    match groups_client.get_group(test_group_id).await {
        Ok(group_response) => {
            let group = &group_response.data;
            println!("✓ Group retrieved successfully");
            println!("  ID: {}", group.id);
            println!("  Name: {}", group.attributes.name);

            if let Some(description) = &group.attributes.description {
                println!("  Description: {}", description);
            }
            if let Some(owner_id) = &group.attributes.owner_id {
                println!("  Owner ID: {}", owner_id);
            }

            // Check group quotas
            if let Some(quotas) = &group.attributes.quotas {
                println!("\n  Group Quotas:");
                if let Some(monthly_api) = &quotas.api_requests_monthly {
                    println!(
                        "    API requests monthly: {}/{}",
                        monthly_api.used, monthly_api.allowed
                    );
                }
                if let Some(intel_searches) = &quotas.intelligence_searches_monthly {
                    println!(
                        "    Intelligence searches: {}/{}",
                        intel_searches.used, intel_searches.allowed
                    );
                }
            }
        }
        Err(e) => {
            println!("✗ Error getting group: {}", e);
            println!("  Note: Requires valid group ID and permissions");
        }
    }

    // Update group attributes
    println!("\n5. UPDATE GROUP ATTRIBUTES");
    println!("--------------------------");

    let group_update_attrs = GroupUpdateAttributes {
        description: Some("Updated via VirusTotal SDK".to_string()),
        ..Default::default()
    };

    let group_update_request = virustotal_rs::GroupUpdateRequest {
        data: virustotal_rs::GroupUpdate::new(group_update_attrs),
    };

    println!("Attempting to update group description...");
    match groups_client
        .update_group(test_group_id, &group_update_request)
        .await
    {
        Ok(updated_group) => {
            println!("✓ Group updated successfully");
            if let Some(desc) = &updated_group.data.attributes.description {
                println!("  New description: {}", desc);
            }
        }
        Err(e) => {
            println!("✗ Error updating group: {}", e);
            println!("  Note: Requires group admin permissions");
        }
    }

    // Get group members
    println!("\n6. GROUP MEMBERS");
    println!("----------------");

    println!("\nGetting group members...");
    match groups_client.get_users(test_group_id).await {
        Ok(users_response) => {
            println!("✓ Group has {} members", users_response.data.len());
            for (i, user) in users_response.data.iter().enumerate() {
                println!("  {}. User ID: {}", i + 1, user.id);
                if let Some(email) = &user.attributes.email {
                    println!("     Email: {}", email);
                }
            }
        }
        Err(e) => {
            println!("✗ Error getting group members: {}", e);
        }
    }

    // Get group administrators
    println!("\nGetting group administrators...");
    match groups_client.get_administrators(test_group_id).await {
        Ok(admins_response) => {
            println!("✓ Group has {} administrators", admins_response.data.len());
            for (i, admin) in admins_response.data.iter().enumerate() {
                println!("  {}. Admin ID: {}", i + 1, admin.id);
                if let Some(email) = &admin.attributes.email {
                    println!("     Email: {}", email);
                }
            }
        }
        Err(e) => {
            println!("✗ Error getting administrators: {}", e);
        }
    }

    // Check if a user is a member
    println!("\n7. MEMBERSHIP CHECKS");
    println!("--------------------");

    let check_user_id = "user_to_check";

    println!("\nChecking if user '{}' is a member...", check_user_id);
    match groups_client.is_member(test_group_id, check_user_id).await {
        Ok(is_member) => {
            println!("✓ User is member: {}", is_member);
        }
        Err(e) => {
            println!("✗ Error checking membership: {}", e);
        }
    }

    println!("\nChecking if user '{}' is an admin...", check_user_id);
    match groups_client
        .is_administrator(test_group_id, check_user_id)
        .await
    {
        Ok(is_admin) => {
            println!("✓ User is admin: {}", is_admin);
        }
        Err(e) => {
            println!("✗ Error checking admin status: {}", e);
        }
    }

    // Add users to group (requires email addresses)
    println!("\n8. ADD/REMOVE USERS");
    println!("-------------------");

    let new_user_emails = vec!["newuser@example.com"];

    println!("\nAdding users to group...");
    match groups_client
        .add_users(test_group_id, new_user_emails.clone())
        .await
    {
        Ok(()) => {
            println!("✓ Users added successfully");
        }
        Err(e) => {
            println!("✗ Error adding users: {}", e);
            println!("  Note: Requires admin permissions and valid email addresses");
        }
    }

    // Grant admin permissions
    println!("\nGranting admin permissions...");
    match groups_client
        .add_administrators(test_group_id, new_user_emails)
        .await
    {
        Ok(()) => {
            println!("✓ Admin permissions granted");
        }
        Err(e) => {
            println!("✗ Error granting admin permissions: {}", e);
        }
    }

    // Iterator example for relationships
    println!("\n9. ITERATING RELATIONSHIPS");
    println!("--------------------------");

    println!("\nIterating through user's submissions...");
    let mut submissions_iter = users_client
        .iter_relationship::<serde_json::Value>(&api_key, "submissions")
        .with_limit(5);

    match submissions_iter.next_batch().await {
        Ok(submissions) => {
            println!("✓ Retrieved {} submissions", submissions.len());
            for (i, _submission) in submissions.iter().enumerate() {
                println!("  {}. Submission found", i + 1);
            }
        }
        Err(e) => {
            println!("✗ Error getting submissions: {}", e);
        }
    }

    // ========== IMPORTANT NOTES ==========
    println!("\n10. IMPORTANT NOTES");
    println!("-------------------");

    println!("\n🔑 User Management:");
    println!("  - Get user by ID or API key");
    println!("  - Update user attributes (name, country, bio, preferences)");
    println!("  - Check privileges and quotas");
    println!("  - Access user relationships (groups, API keys, submissions)");

    println!("\n👥 Group Management:");
    println!("  - Get and update group information");
    println!("  - Manage group members and administrators");
    println!("  - Check membership and admin status");
    println!("  - Access group relationships (users, admins, graphs)");

    println!("\n⚠️ Permissions:");
    println!("  - User info: Accessible by user or group admin");
    println!("  - User deletion: Requires password confirmation");
    println!("  - Group management: Requires admin permissions");
    println!("  - Adding users: Requires email addresses (not usernames)");

    println!("\n🔐 Security:");
    println!("  - Delete user requires x-user-password header");
    println!("  - Some relationships only accessible to owners/admins");
    println!("  - API keys should be kept secure");

    println!("\n===============================================");
    println!("Users and Groups Management Testing Complete!");

    Ok(())
}
