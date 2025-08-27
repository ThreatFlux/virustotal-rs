//! VirusTotal Users and Groups Management API Example
//!
//! This example demonstrates how to work with VirusTotal's user and group management APIs.
//! It shows user information retrieval, updates, relationships, group management,
//! member operations, and administrative tasks.

mod common;

use common::{create_client_from_env, print_header, print_test_header, ExampleResult};
use virustotal_rs::{
    ApiTier, GroupUpdateAttributes, GroupsClient, UserUpdate, UserUpdateAttributes,
    UserUpdateRequest, UsersClient,
};

/// Test group ID - replace with actual group ID for testing
const TEST_GROUP_ID: &str = "your_group_id_here";

#[tokio::main]
async fn main() -> ExampleResult<()> {
    let client = create_client_from_env("VT_API_KEY", ApiTier::Premium)?;

    print_header("VirusTotal Users and Groups Management");

    // Get API key for user operations
    let api_key = std::env::var("VT_API_KEY").unwrap_or_else(|_| "test_key".to_string());
    println!(
        "🔑 Using API key: {}...\n",
        &api_key[..8.min(api_key.len())]
    );

    let users_client = client.users();
    let groups_client = client.groups();

    // Execute all test scenarios
    test_user_management(&users_client, &api_key).await;
    test_user_updates(&users_client, &api_key).await;
    test_user_relationships(&users_client, &api_key).await;
    test_group_management(&groups_client).await;
    test_group_updates(&groups_client).await;
    test_group_members(&groups_client).await;
    test_group_administrators(&groups_client).await;
    test_group_relationships(&groups_client).await;
    test_user_group_operations(&users_client, &groups_client, &api_key).await;
    print_important_notes();

    println!("\n==============================================");
    println!("Users and Groups Management Testing Complete!");

    Ok(())
}

/// Test basic user management operations
async fn test_user_management(users_client: &UsersClient, api_key: &str) {
    print_test_header("USER MANAGEMENT");

    println!("Getting current user info...");
    match users_client.get_user(api_key).await {
        Ok(user_response) => {
            println!("✓ User retrieved successfully");
            display_user_details(&user_response.data);
        }
        Err(e) => {
            println!("✗ Error getting user: {}", e);
            println!("  Note: Requires valid API key");
        }
    }
}

/// Display user details including attributes, privileges, and quotas
fn display_user_details(user: &virustotal_rs::users::User) {
    println!("  ID: {}", user.id);
    println!("  Type: {}", user.object_type);

    display_user_basic_info(&user.attributes);
    display_user_privileges(&user.attributes);
    display_user_quotas(&user.attributes);
}

/// Display basic user information
fn display_user_basic_info(attrs: &virustotal_rs::users::UserAttributes) {
    if let Some(email) = &attrs.email {
        println!("  Email: {}", email);
    }
    if let Some(first_name) = &attrs.first_name {
        println!("  First Name: {}", first_name);
    }
    if let Some(last_name) = &attrs.last_name {
        println!("  Last Name: {}", last_name);
    }
    if let Some(country) = &attrs.country {
        println!("  Country: {}", country);
    }
    if let Some(status) = &attrs.status {
        println!("  Status: {}", status);
    }
}

/// Display user privileges
fn display_user_privileges(attrs: &virustotal_rs::users::UserAttributes) {
    if let Some(privileges) = &attrs.privileges {
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
}

/// Display user quotas
fn display_user_quotas(attrs: &virustotal_rs::users::UserAttributes) {
    if let Some(quotas) = &attrs.quotas {
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

/// Test user update operations
async fn test_user_updates(users_client: &UsersClient, api_key: &str) {
    print_test_header("UPDATE USER ATTRIBUTES");

    let update_attrs = UserUpdateAttributes {
        bio: Some("VirusTotal SDK Test User".to_string()),
        ..Default::default()
    };

    let update_request = UserUpdateRequest {
        data: UserUpdate::new(update_attrs),
    };

    println!("Attempting to update user bio...");
    match users_client.update_user(api_key, &update_request).await {
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
}

/// Test user relationship operations
async fn test_user_relationships(users_client: &UsersClient, api_key: &str) {
    print_test_header("USER RELATIONSHIPS");

    test_user_api_keys(users_client, api_key).await;
    test_user_groups(users_client, api_key).await;
}

/// Test user API keys retrieval
async fn test_user_api_keys(users_client: &UsersClient, api_key: &str) {
    println!("\nGetting user's API keys...");
    match users_client
        .get_relationship::<serde_json::Value>(api_key, "api_keys", Some(10), None)
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
}

/// Test user groups retrieval
async fn test_user_groups(users_client: &UsersClient, api_key: &str) {
    println!("\nGetting user's groups...");
    match users_client
        .get_relationship::<serde_json::Value>(api_key, "groups", Some(10), None)
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
}

/// Test basic group management operations
async fn test_group_management(groups_client: &GroupsClient) {
    print_test_header("GROUP MANAGEMENT");

    println!("Getting group info for ID: {}", TEST_GROUP_ID);
    match groups_client.get_group(TEST_GROUP_ID).await {
        Ok(group_response) => {
            println!("✓ Group retrieved successfully");
            display_group_details(&group_response.data);
        }
        Err(e) => {
            println!("✗ Error getting group: {}", e);
            println!("  Note: Requires valid group ID and permissions");
        }
    }
}

/// Display group details including attributes and quotas
fn display_group_details(group: &virustotal_rs::groups::Group) {
    println!("  ID: {}", group.id);
    println!("  Name: {}", group.attributes.name);

    if let Some(description) = &group.attributes.description {
        println!("  Description: {}", description);
    }
    if let Some(owner_id) = &group.attributes.owner_id {
        println!("  Owner ID: {}", owner_id);
    }

    display_group_quotas(&group.attributes);
}

/// Display group quotas
fn display_group_quotas(attrs: &virustotal_rs::groups::GroupAttributes) {
    if let Some(quotas) = &attrs.quotas {
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

/// Test group update operations
async fn test_group_updates(groups_client: &GroupsClient) {
    print_test_header("UPDATE GROUP ATTRIBUTES");

    let group_update_attrs = GroupUpdateAttributes {
        description: Some("Updated via VirusTotal SDK".to_string()),
        ..Default::default()
    };

    let group_update_request = virustotal_rs::GroupUpdateRequest {
        data: virustotal_rs::GroupUpdate::new(group_update_attrs),
    };

    println!("Attempting to update group description...");
    match groups_client
        .update_group(TEST_GROUP_ID, &group_update_request)
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
}

/// Test group member operations
async fn test_group_members(groups_client: &GroupsClient) {
    print_test_header("GROUP MEMBERS");

    test_get_group_members(groups_client).await;
    test_add_remove_members(groups_client).await;
}

/// Test getting group members
async fn test_get_group_members(groups_client: &GroupsClient) {
    println!("Getting group members...");
    match groups_client.get_users(TEST_GROUP_ID).await {
        Ok(members_response) => {
            println!("✓ Retrieved {} group members", members_response.data.len());
            for (i, member) in members_response.data.iter().enumerate().take(5) {
                println!("  {}. User ID: {}", i + 1, member.id);
                if let Some(email) = &member.attributes.email {
                    println!("     Email: {}", email);
                }
            }
        }
        Err(e) => {
            println!("✗ Error getting group members: {}", e);
        }
    }
}

/// Test adding and removing members
async fn test_add_remove_members(groups_client: &GroupsClient) {
    println!("\nTesting member addition/removal...");

    let test_user_emails = vec!["test_user_1@example.com", "test_user_2@example.com"];

    // Test adding members
    match groups_client
        .add_users(TEST_GROUP_ID, test_user_emails.clone())
        .await
    {
        Ok(_) => {
            println!("✓ Members added successfully (or would be with valid IDs)");
        }
        Err(e) => {
            println!("✗ Error adding members: {}", e);
            println!("  Note: Requires valid user IDs and admin permissions");
        }
    }

    // Test removing members (one at a time)
    if let Some(user_email) = test_user_emails.first() {
        match groups_client.remove_user(TEST_GROUP_ID, user_email).await {
            Ok(_) => {
                println!(
                    "✓ Member {} removed successfully (or would be with valid ID)",
                    user_email
                );
            }
            Err(e) => {
                println!("✗ Error removing member {}: {}", user_email, e);
            }
        }
    }
}

/// Test group administrator operations
async fn test_group_administrators(groups_client: &GroupsClient) {
    print_test_header("GROUP ADMINISTRATORS");

    test_get_group_admins(groups_client).await;
    test_add_remove_admins(groups_client).await;
}

/// Test getting group administrators
async fn test_get_group_admins(groups_client: &GroupsClient) {
    println!("Getting group administrators...");
    match groups_client.get_administrators(TEST_GROUP_ID).await {
        Ok(admins_response) => {
            println!(
                "✓ Retrieved {} group administrators",
                admins_response.data.len()
            );
            for (i, admin) in admins_response.data.iter().enumerate().take(3) {
                println!("  {}. Admin ID: {}", i + 1, admin.id);
                if let Some(email) = &admin.attributes.email {
                    println!("     Email: {}", email);
                }
            }
        }
        Err(e) => {
            println!("✗ Error getting group administrators: {}", e);
        }
    }
}

/// Test adding and removing administrators
async fn test_add_remove_admins(groups_client: &GroupsClient) {
    println!("\nTesting administrator management...");

    let test_admin_emails = vec!["admin_user_1@example.com"];

    // Test adding administrators
    match groups_client
        .add_administrators(TEST_GROUP_ID, test_admin_emails.clone())
        .await
    {
        Ok(_) => {
            println!("✓ Administrator added successfully (or would be with valid ID)");
        }
        Err(e) => {
            println!("✗ Error adding administrator: {}", e);
            println!("  Note: Requires valid user ID and owner permissions");
        }
    }

    // Test removing administrators (one at a time)
    if let Some(admin_email) = test_admin_emails.first() {
        match groups_client
            .remove_administrator(TEST_GROUP_ID, admin_email)
            .await
        {
            Ok(_) => {
                println!(
                    "✓ Administrator {} removed successfully (or would be with valid ID)",
                    admin_email
                );
            }
            Err(e) => {
                println!("✗ Error removing administrator {}: {}", admin_email, e);
            }
        }
    }
}

/// Test group relationship operations
async fn test_group_relationships(groups_client: &GroupsClient) {
    print_test_header("GROUP RELATIONSHIPS");

    // Test getting group items (files, URLs, etc.)
    println!("Getting group items...");
    match groups_client
        .get_relationship::<serde_json::Value>(TEST_GROUP_ID, "items", Some(10), None)
        .await
    {
        Ok(items) => {
            println!("✓ Retrieved {} group items", items.data.len());
            for (i, _item) in items.data.iter().enumerate().take(3) {
                println!("  {}. Group item available", i + 1);
            }
        }
        Err(e) => {
            println!("✗ Error getting group items: {}", e);
        }
    }

    // Test getting group activity
    println!("\nGetting group activity...");
    match groups_client
        .get_relationship::<serde_json::Value>(TEST_GROUP_ID, "activity", Some(10), None)
        .await
    {
        Ok(activity) => {
            println!("✓ Retrieved {} activity entries", activity.data.len());
        }
        Err(e) => {
            println!("✗ Error getting group activity: {}", e);
        }
    }
}

/// Test combined user-group operations
async fn test_user_group_operations(
    users_client: &UsersClient,
    groups_client: &GroupsClient,
    api_key: &str,
) {
    print_test_header("USER-GROUP OPERATIONS");

    // Test relationship between specific user and group operations
    println!("Testing user-group relationship operations...");

    // Check if current user is in any specific groups
    match users_client
        .get_relationship::<serde_json::Value>(api_key, "groups", Some(5), None)
        .await
    {
        Ok(user_groups) => {
            println!("✓ User is member of {} groups", user_groups.data.len());

            // For each group, try to get more details
            for (i, group_data) in user_groups.data.iter().enumerate().take(2) {
                if let Some(group_id) = group_data.get("id") {
                    println!(
                        "  {}. Attempting to get details for group: {}",
                        i + 1,
                        group_id
                    );

                    if let Some(id_str) = group_id.as_str() {
                        match groups_client.get_group(id_str).await {
                            Ok(group_details) => {
                                println!(
                                    "     ✓ Group name: {}",
                                    group_details.data.attributes.name
                                );
                            }
                            Err(e) => {
                                println!("     ✗ Could not get group details: {}", e);
                            }
                        }
                    }
                }
            }
        }
        Err(e) => {
            println!("✗ Error getting user groups: {}", e);
        }
    }
}

/// Print important notes about users and groups management
fn print_important_notes() {
    print_test_header("IMPORTANT NOTES");

    println!("👤 User Management:");
    println!("  - User ID is typically the API key for the authenticated user");
    println!("  - User updates require appropriate permissions");
    println!("  - Quota information shows current usage and limits");

    println!("\n👥 Group Management:");
    println!("  - Group operations require valid group IDs");
    println!("  - Admin permissions needed for most group modifications");
    println!("  - Owner permissions required for administrator management");

    println!("\n🔑 Permissions:");
    println!("  - View operations: Basic API access");
    println!("  - Update operations: User/Admin permissions");
    println!("  - Member management: Admin permissions");
    println!("  - Admin management: Owner permissions");

    println!("\n⚡ Best Practices:");
    println!("  - Always check user/group permissions before operations");
    println!("  - Use pagination for large member lists");
    println!("  - Handle permission errors gracefully");
    println!("  - Monitor quota usage to avoid limits");
}
