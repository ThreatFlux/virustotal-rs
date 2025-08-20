use virustotal_rs::{
    ApiTier, ClientBuilder, CreateGraphRequest, GraphVisibility, PermissionDescriptor,
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let api_key = std::env::var("VT_API_KEY").unwrap_or_else(|_| "test_key".to_string());

    let client = ClientBuilder::new()
        .api_key(api_key)
        .tier(ApiTier::Premium)
        .build()?;

    println!("Testing VirusTotal Graph Permission Management");
    println!("==============================================\n");

    let graph_client = client.graphs();

    // Create a test graph first
    println!("SETUP: Creating test graph");
    println!("--------------------------");

    let create_request = CreateGraphRequest::new("Permission Test Graph".to_string())
        .with_description("Graph for testing permission management".to_string())
        .with_visibility(GraphVisibility::Private);

    let graph_id = match graph_client.create_graph(&create_request).await {
        Ok(graph) => {
            println!("✓ Graph created: {}", graph.object.id);
            graph.object.id
        }
        Err(e) => {
            eprintln!("✗ Error creating graph: {}", e);
            return Ok(());
        }
    };

    // 1. Test Editor Permissions
    println!("\n1. EDITOR PERMISSION MANAGEMENT");
    println!("--------------------------------");

    // Grant edit permissions to multiple users and groups
    println!("\nGranting edit permissions to users and groups:");
    let editors = vec![
        PermissionDescriptor::user("gilfoyle".to_string()),
        PermissionDescriptor::user("dinesh".to_string()),
        PermissionDescriptor::group("developers".to_string()),
    ];

    match graph_client.grant_edit_permission(&graph_id, editors).await {
        Ok(result) => {
            println!("✓ Successfully granted edit permissions");
            println!("  Added {} editors:", result.data.len());
            for editor in &result.data {
                println!(
                    "  - {} (ID: {})",
                    editor.object.object_type, editor.object.id
                );
                if let Some(first_name) = &editor.object.attributes.first_name {
                    if let Some(last_name) = &editor.object.attributes.last_name {
                        println!("    Name: {} {}", first_name, last_name);
                    }
                }
                if let Some(status) = &editor.object.attributes.status {
                    println!("    Status: {}", status);
                }
            }
        }
        Err(e) => {
            println!("✗ Error granting edit permissions: {}", e);
        }
    }

    // Check if specific user has edit permission
    println!("\n2. CHECKING EDIT PERMISSIONS");
    println!("----------------------------");

    let users_to_check = vec!["gilfoyle", "hendricks", "erlich"];
    for user_id in users_to_check {
        match graph_client.check_edit_permission(&graph_id, user_id).await {
            Ok(response) => {
                println!(
                    "User '{}': {} edit access",
                    user_id,
                    if response.data { "HAS" } else { "NO" }
                );
            }
            Err(e) => {
                println!("✗ Error checking permission for '{}': {}", user_id, e);
            }
        }
    }

    // Get list of all editors with minimal info
    println!("\n3. LISTING GRAPH EDITORS");
    println!("------------------------");

    match graph_client
        .get_graph_editors_descriptors(&graph_id, Some(20), None)
        .await
    {
        Ok(descriptors) => {
            println!("✓ Retrieved editor descriptors");
            println!("  Total editors: {}", descriptors.data.len());
            for descriptor in &descriptors.data {
                println!(
                    "  - {} '{}' (type: {})",
                    if descriptor.object_type == "user" {
                        "User"
                    } else {
                        "Group"
                    },
                    descriptor.id,
                    descriptor.object_type
                );
                if let Some(context) = &descriptor.context_attributes {
                    println!("    Context: {:?}", context);
                }
            }
        }
        Err(e) => {
            println!("✗ Error getting editor descriptors: {}", e);
        }
    }

    // Get full editor information
    println!("\n4. GETTING FULL EDITOR INFORMATION");
    println!("-----------------------------------");

    match graph_client
        .get_graph_editors(&graph_id, Some(10), None)
        .await
    {
        Ok(editors) => {
            println!("✓ Retrieved full editor information");
            for editor in editors.data.iter().take(3) {
                println!("\n  Editor: {}", editor.object.id);
                if let Some(first) = &editor.object.attributes.first_name {
                    if let Some(last) = &editor.object.attributes.last_name {
                        println!("  - Full Name: {} {}", first, last);
                    }
                }
                if let Some(phrase) = &editor.object.attributes.profile_phrase {
                    if !phrase.is_empty() {
                        println!("  - Profile: {}", phrase);
                    }
                }
                if let Some(reputation) = &editor.object.attributes.reputation {
                    println!("  - Reputation: {}", reputation);
                }
                if let Some(since) = &editor.object.attributes.user_since {
                    println!("  - User Since: {}", since);
                }
            }
        }
        Err(e) => {
            println!("✗ Error getting full editor information: {}", e);
        }
    }

    // 5. Test Viewer Permissions
    println!("\n5. VIEWER PERMISSION MANAGEMENT");
    println!("--------------------------------");

    // Grant view permissions
    println!("\nGranting view permissions:");
    let viewers = vec![
        PermissionDescriptor::user("jared".to_string()),
        PermissionDescriptor::user("monica".to_string()),
        PermissionDescriptor::group("analysts".to_string()),
        PermissionDescriptor::group("qa_team".to_string()),
    ];

    match graph_client.grant_view_permission(&graph_id, viewers).await {
        Ok(result) => {
            println!("✓ Successfully granted view permissions");
            println!("  Added {} viewers", result.data.len());
        }
        Err(e) => {
            println!("✗ Error granting view permissions: {}", e);
        }
    }

    // Check viewer permissions
    println!("\n6. CHECKING VIEWER PERMISSIONS");
    println!("------------------------------");

    let viewers_to_check = vec!["jared", "monica", "bighead"];
    for user_id in viewers_to_check {
        match graph_client.check_view_permission(&graph_id, user_id).await {
            Ok(response) => {
                println!(
                    "User '{}': {} view access",
                    user_id,
                    if response.data { "HAS" } else { "NO" }
                );
            }
            Err(e) => {
                println!("✗ Error checking permission for '{}': {}", user_id, e);
            }
        }
    }

    // 7. Revoke permissions
    println!("\n7. REVOKING PERMISSIONS");
    println!("-----------------------");

    // Revoke edit permission from a user
    println!("\nRevoking edit permission from 'dinesh':");
    match graph_client
        .revoke_edit_permission(&graph_id, "dinesh")
        .await
    {
        Ok(_) => {
            println!("✓ Successfully revoked edit permission from 'dinesh'");

            // Verify it was revoked
            if let Ok(response) = graph_client
                .check_edit_permission(&graph_id, "dinesh")
                .await
            {
                println!(
                    "  Verification: 'dinesh' {} has edit access",
                    if response.data { "still" } else { "no longer" }
                );
            }
        }
        Err(e) => {
            println!("✗ Error revoking edit permission: {}", e);
        }
    }

    // Revoke view permission from a user
    println!("\nRevoking view permission from 'jared':");
    match graph_client
        .revoke_view_permission(&graph_id, "jared")
        .await
    {
        Ok(_) => {
            println!("✓ Successfully revoked view permission from 'jared'");

            // Verify it was revoked
            if let Ok(response) = graph_client.check_view_permission(&graph_id, "jared").await {
                println!(
                    "  Verification: 'jared' {} has view access",
                    if response.data { "still" } else { "no longer" }
                );
            }
        }
        Err(e) => {
            println!("✗ Error revoking view permission: {}", e);
        }
    }

    // 8. Mixed permissions test
    println!("\n8. MIXED PERMISSIONS TEST");
    println!("-------------------------");

    println!("\nGranting both view and edit permissions to different users:");

    // Some users get edit access
    let new_editors = vec![PermissionDescriptor::user("richard".to_string())];

    // Others get only view access
    let new_viewers = vec![
        PermissionDescriptor::user("gavin".to_string()),
        PermissionDescriptor::user("laurie".to_string()),
    ];

    match graph_client
        .grant_edit_permission(&graph_id, new_editors)
        .await
    {
        Ok(_) => println!("✓ Granted edit permission to 'richard'"),
        Err(e) => println!("✗ Error: {}", e),
    }

    match graph_client
        .grant_view_permission(&graph_id, new_viewers)
        .await
    {
        Ok(_) => println!("✓ Granted view permissions to 'gavin' and 'laurie'"),
        Err(e) => println!("✗ Error: {}", e),
    }

    // Check their permissions
    println!("\nVerifying permission levels:");
    for user_id in &["richard", "gavin", "laurie"] {
        let can_edit = graph_client
            .check_edit_permission(&graph_id, user_id)
            .await
            .map(|r| r.data)
            .unwrap_or(false);

        let can_view = graph_client
            .check_view_permission(&graph_id, user_id)
            .await
            .map(|r| r.data)
            .unwrap_or(false);

        println!(
            "User '{}': Edit={}, View={}",
            user_id,
            if can_edit { "YES" } else { "NO" },
            if can_view { "YES" } else { "NO" }
        );
    }

    // 9. Get graph owner
    println!("\n9. GRAPH OWNER");
    println!("--------------");

    match graph_client.get_graph_owner(&graph_id).await {
        Ok(owner) => {
            println!("✓ Retrieved graph owner");
            println!("  Owner ID: {}", owner.object.id);
            if let Some(first) = &owner.object.attributes.first_name {
                if let Some(last) = &owner.object.attributes.last_name {
                    println!("  Name: {} {}", first, last);
                }
            }
            if let Some(status) = &owner.object.attributes.status {
                println!("  Status: {}", status);
            }
        }
        Err(e) => {
            println!("✗ Error getting owner: {}", e);
        }
    }

    // 10. Clean up
    println!("\n10. CLEANUP");
    println!("-----------");

    match graph_client.delete_graph(&graph_id).await {
        Ok(_) => {
            println!("✓ Test graph deleted successfully");
        }
        Err(e) => {
            println!("✗ Error deleting graph: {}", e);
        }
    }

    println!("\n==============================================");
    println!("Graph Permission Management Testing Complete!");

    Ok(())
}
