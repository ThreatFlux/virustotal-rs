use virustotal_rs::graphs::{GraphOwner, GraphOwnerAttributes, GraphRelationshipDescriptor};
use virustotal_rs::{
    ApiTier, ClientBuilder, CreateGraphRequest, GraphClient, GraphVisibility, PermissionDescriptor,
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
    if let Some(graph_id) = setup_test_graph(&graph_client).await {
        test_editor_permissions(&graph_client, &graph_id).await;
        test_viewer_permissions(&graph_client, &graph_id).await;
        test_permission_revocation(&graph_client, &graph_id).await;
        test_mixed_permissions(&graph_client, &graph_id).await;
        get_graph_owner_info(&graph_client, &graph_id).await;
        cleanup_test_graph(&graph_client, &graph_id).await;
    }

    println!("\n==============================================");
    println!("Graph Permission Management Testing Complete!");

    Ok(())
}

async fn setup_test_graph(graph_client: &GraphClient<'_>) -> Option<String> {
    println!("SETUP: Creating test graph");
    println!("--------------------------");

    let create_request = CreateGraphRequest::new("Permission Test Graph".to_string())
        .with_description("Graph for testing permission management".to_string())
        .with_visibility(GraphVisibility::Private);

    match graph_client.create_graph(&create_request).await {
        Ok(graph) => {
            println!("✓ Graph created: {}", graph.object.id);
            Some(graph.object.id)
        }
        Err(e) => {
            eprintln!("✗ Error creating graph: {}", e);
            None
        }
    }
}

async fn test_editor_permissions(graph_client: &GraphClient<'_>, graph_id: &str) {
    println!("\n1. EDITOR PERMISSION MANAGEMENT");
    println!("--------------------------------");

    grant_editor_permissions(graph_client, graph_id).await;
    check_editor_permissions(graph_client, graph_id).await;
    list_graph_editors(graph_client, graph_id).await;
    get_full_editor_information(graph_client, graph_id).await;
}

async fn grant_editor_permissions(graph_client: &GraphClient<'_>, graph_id: &str) {
    println!("\nGranting edit permissions to users and groups:");
    let editors = vec![
        PermissionDescriptor::user("gilfoyle".to_string()),
        PermissionDescriptor::user("dinesh".to_string()),
        PermissionDescriptor::group("developers".to_string()),
    ];

    match graph_client.grant_edit_permission(graph_id, editors).await {
        Ok(result) => {
            println!("✓ Successfully granted edit permissions");
            println!("  Added {} editors:", result.data.len());
            display_granted_editors(&result.data);
        }
        Err(e) => {
            println!("✗ Error granting edit permissions: {}", e);
        }
    }
}

fn display_granted_editors(editors: &[GraphOwner]) {
    for editor in editors {
        println!(
            "  - {} (ID: {})",
            editor.object.object_type, editor.object.id
        );
        display_user_details(&editor.object.attributes);
    }
}

fn display_user_details(attributes: &GraphOwnerAttributes) {
    if let Some(first_name) = &attributes.first_name {
        if let Some(last_name) = &attributes.last_name {
            println!("    Name: {} {}", first_name, last_name);
        }
    }
    if let Some(status) = &attributes.status {
        println!("    Status: {}", status);
    }
}

async fn check_editor_permissions(graph_client: &GraphClient<'_>, graph_id: &str) {
    println!("\n2. CHECKING EDIT PERMISSIONS");
    println!("----------------------------");

    let users_to_check = vec!["gilfoyle", "hendricks", "erlich"];
    for user_id in users_to_check {
        check_single_edit_permission(graph_client, graph_id, user_id).await;
    }
}

async fn check_single_edit_permission(
    graph_client: &GraphClient<'_>,
    graph_id: &str,
    user_id: &str,
) {
    match graph_client.check_edit_permission(graph_id, user_id).await {
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

async fn list_graph_editors(graph_client: &GraphClient<'_>, graph_id: &str) {
    println!("\n3. LISTING GRAPH EDITORS");
    println!("------------------------");

    match graph_client
        .get_graph_editors_descriptors(graph_id, Some(20), None)
        .await
    {
        Ok(descriptors) => {
            println!("✓ Retrieved editor descriptors");
            println!("  Total editors: {}", descriptors.data.len());
            display_editor_descriptors(&descriptors.data);
        }
        Err(e) => {
            println!("✗ Error getting editor descriptors: {}", e);
        }
    }
}

fn display_editor_descriptors(descriptors: &[GraphRelationshipDescriptor]) {
    for descriptor in descriptors {
        let user_type = if descriptor.object_type == "user" {
            "User"
        } else {
            "Group"
        };

        println!(
            "  - {} '{}' (type: {})",
            user_type, descriptor.id, descriptor.object_type
        );

        if let Some(context) = &descriptor.context_attributes {
            println!("    Context: {:?}", context);
        }
    }
}

async fn get_full_editor_information(graph_client: &GraphClient<'_>, graph_id: &str) {
    println!("\n4. GETTING FULL EDITOR INFORMATION");
    println!("-----------------------------------");

    match graph_client
        .get_graph_editors(graph_id, Some(10), None)
        .await
    {
        Ok(editors) => {
            println!("✓ Retrieved full editor information");
            display_full_editor_info(&editors.data);
        }
        Err(e) => {
            println!("✗ Error getting full editor information: {}", e);
        }
    }
}

fn display_full_editor_info(editors: &[GraphOwner]) {
    for editor in editors.iter().take(3) {
        println!("\n  Editor: {}", editor.object.id);
        display_detailed_user_info(&editor.object.attributes);
    }
}

fn display_detailed_user_info(attributes: &GraphOwnerAttributes) {
    if let Some(first) = &attributes.first_name {
        if let Some(last) = &attributes.last_name {
            println!("  - Full Name: {} {}", first, last);
        }
    }

    if let Some(phrase) = &attributes.profile_phrase {
        if !phrase.is_empty() {
            println!("  - Profile: {}", phrase);
        }
    }

    if let Some(reputation) = &attributes.reputation {
        println!("  - Reputation: {}", reputation);
    }

    if let Some(since) = &attributes.user_since {
        println!("  - User Since: {}", since);
    }
}

async fn test_viewer_permissions(graph_client: &GraphClient<'_>, graph_id: &str) {
    println!("\n5. VIEWER PERMISSION MANAGEMENT");
    println!("--------------------------------");

    grant_viewer_permissions(graph_client, graph_id).await;
    check_viewer_permissions(graph_client, graph_id).await;
}

async fn grant_viewer_permissions(graph_client: &GraphClient<'_>, graph_id: &str) {
    println!("\nGranting view permissions:");
    let viewers = vec![
        PermissionDescriptor::user("jared".to_string()),
        PermissionDescriptor::user("monica".to_string()),
        PermissionDescriptor::group("analysts".to_string()),
        PermissionDescriptor::group("qa_team".to_string()),
    ];

    match graph_client.grant_view_permission(graph_id, viewers).await {
        Ok(result) => {
            println!("✓ Successfully granted view permissions");
            println!("  Added {} viewers", result.data.len());
        }
        Err(e) => {
            println!("✗ Error granting view permissions: {}", e);
        }
    }
}

async fn check_viewer_permissions(graph_client: &GraphClient<'_>, graph_id: &str) {
    println!("\n6. CHECKING VIEWER PERMISSIONS");
    println!("------------------------------");

    let viewers_to_check = vec!["jared", "monica", "bighead"];
    for user_id in viewers_to_check {
        check_single_view_permission(graph_client, graph_id, user_id).await;
    }
}

async fn check_single_view_permission(
    graph_client: &GraphClient<'_>,
    graph_id: &str,
    user_id: &str,
) {
    match graph_client.check_view_permission(graph_id, user_id).await {
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

async fn test_permission_revocation(graph_client: &GraphClient<'_>, graph_id: &str) {
    println!("\n7. REVOKING PERMISSIONS");
    println!("-----------------------");

    revoke_edit_permission(graph_client, graph_id).await;
    revoke_view_permission(graph_client, graph_id).await;
}

async fn revoke_edit_permission(graph_client: &GraphClient<'_>, graph_id: &str) {
    println!("\nRevoking edit permission from 'dinesh':");
    match graph_client
        .revoke_edit_permission(graph_id, "dinesh")
        .await
    {
        Ok(_) => {
            println!("✓ Successfully revoked edit permission from 'dinesh'");
            verify_permission_revoked(graph_client, graph_id, "dinesh", "edit").await;
        }
        Err(e) => {
            println!("✗ Error revoking edit permission: {}", e);
        }
    }
}

async fn revoke_view_permission(graph_client: &GraphClient<'_>, graph_id: &str) {
    println!("\nRevoking view permission from 'jared':");
    match graph_client.revoke_view_permission(graph_id, "jared").await {
        Ok(_) => {
            println!("✓ Successfully revoked view permission from 'jared'");
            verify_permission_revoked(graph_client, graph_id, "jared", "view").await;
        }
        Err(e) => {
            println!("✗ Error revoking view permission: {}", e);
        }
    }
}

async fn verify_permission_revoked(
    graph_client: &GraphClient<'_>,
    graph_id: &str,
    user_id: &str,
    permission_type: &str,
) {
    let result = if permission_type == "edit" {
        graph_client.check_edit_permission(graph_id, user_id).await
    } else {
        graph_client.check_view_permission(graph_id, user_id).await
    };

    if let Ok(response) = result {
        println!(
            "  Verification: '{}' {} has {} access",
            user_id,
            if response.data { "still" } else { "no longer" },
            permission_type
        );
    }
}

async fn test_mixed_permissions(graph_client: &GraphClient<'_>, graph_id: &str) {
    println!("\n8. MIXED PERMISSIONS TEST");
    println!("-------------------------");

    grant_mixed_permissions(graph_client, graph_id).await;
    verify_mixed_permissions(graph_client, graph_id).await;
}

async fn grant_mixed_permissions(graph_client: &GraphClient<'_>, graph_id: &str) {
    println!("\nGranting both view and edit permissions to different users:");

    // Some users get edit access
    let new_editors = vec![PermissionDescriptor::user("richard".to_string())];

    // Others get only view access
    let new_viewers = vec![
        PermissionDescriptor::user("gavin".to_string()),
        PermissionDescriptor::user("laurie".to_string()),
    ];

    grant_specific_edit_permissions(graph_client, graph_id, new_editors).await;
    grant_specific_view_permissions(graph_client, graph_id, new_viewers).await;
}

async fn grant_specific_edit_permissions(
    graph_client: &GraphClient<'_>,
    graph_id: &str,
    editors: Vec<PermissionDescriptor>,
) {
    match graph_client.grant_edit_permission(graph_id, editors).await {
        Ok(_) => println!("✓ Granted edit permission to 'richard'"),
        Err(e) => println!("✗ Error: {}", e),
    }
}

async fn grant_specific_view_permissions(
    graph_client: &GraphClient<'_>,
    graph_id: &str,
    viewers: Vec<PermissionDescriptor>,
) {
    match graph_client.grant_view_permission(graph_id, viewers).await {
        Ok(_) => println!("✓ Granted view permissions to 'gavin' and 'laurie'"),
        Err(e) => println!("✗ Error: {}", e),
    }
}

async fn verify_mixed_permissions(graph_client: &GraphClient<'_>, graph_id: &str) {
    println!("\nVerifying permission levels:");
    let users = ["richard", "gavin", "laurie"];

    for user_id in &users {
        let permissions = check_user_permissions(graph_client, graph_id, user_id).await;
        println!(
            "User '{}': Edit={}, View={}",
            user_id,
            if permissions.0 { "YES" } else { "NO" },
            if permissions.1 { "YES" } else { "NO" }
        );
    }
}

async fn check_user_permissions(
    graph_client: &GraphClient<'_>,
    graph_id: &str,
    user_id: &str,
) -> (bool, bool) {
    let can_edit = graph_client
        .check_edit_permission(graph_id, user_id)
        .await
        .map(|r| r.data)
        .unwrap_or(false);

    let can_view = graph_client
        .check_view_permission(graph_id, user_id)
        .await
        .map(|r| r.data)
        .unwrap_or(false);

    (can_edit, can_view)
}

async fn get_graph_owner_info(graph_client: &GraphClient<'_>, graph_id: &str) {
    println!("\n9. GRAPH OWNER");
    println!("--------------");

    match graph_client.get_graph_owner(graph_id).await {
        Ok(owner) => {
            println!("✓ Retrieved graph owner");
            display_owner_information(&owner);
        }
        Err(e) => {
            println!("✗ Error getting owner: {}", e);
        }
    }
}

fn display_owner_information(owner: &GraphOwner) {
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

async fn cleanup_test_graph(graph_client: &GraphClient<'_>, graph_id: &str) {
    println!("\n10. CLEANUP");
    println!("-----------");

    match graph_client.delete_graph(graph_id).await {
        Ok(_) => {
            println!("✓ Test graph deleted successfully");
        }
        Err(e) => {
            println!("✗ Error deleting graph: {}", e);
        }
    }
}
