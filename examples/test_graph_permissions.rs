use virustotal_rs::graphs::{GraphOwner, GraphOwnerAttributes, GraphRelationshipDescriptor};
use virustotal_rs::{ApiTier, ClientBuilder, CreateGraphRequest, GraphClient, GraphVisibility};

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

    if let Some(graph_id) = setup_test_graph(&graph_client).await {
        run_permission_tests(&graph_client, &graph_id).await;
        cleanup_test_graph(&graph_client, &graph_id).await;
    }

    println!("\n==============================================");
    println!("Graph Permission Management Testing Complete!");
    Ok(())
}

async fn run_permission_tests(graph_client: &GraphClient<'_>, graph_id: &str) {
    test_editor_permissions(graph_client, graph_id).await;
    test_viewer_permissions(graph_client, graph_id).await;
    test_permission_revocation(graph_client, graph_id).await;
    test_mixed_permissions(graph_client, graph_id).await;
    get_graph_owner_info(graph_client, graph_id).await;
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
    println!("{}", "-".repeat("EDITOR PERMISSION MANAGEMENT".len() + 4));

    grant_editor_permissions(graph_client, graph_id).await;
    check_editor_permissions(graph_client, graph_id).await;
    list_graph_editors(graph_client, graph_id).await;
    get_full_editor_information(graph_client, graph_id).await;
}

async fn grant_editor_permissions(graph_client: &GraphClient<'_>, graph_id: &str) {
    println!("\nGranting edit permissions to users:");
    let editor_ids = vec!["gilfoyle".to_string(), "dinesh".to_string()];

    match graph_client.add_graph_editors(graph_id, &editor_ids).await {
        Ok(_) => {
            println!("✓ Successfully granted edit permissions");
            println!("  Added {} editors", editor_ids.len());
            for editor_id in &editor_ids {
                println!("  - User: {}", editor_id);
            }
        }
        Err(e) => {
            println!("✗ Error granting edit permissions: {}", e);
        }
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
    // Note: Permission checking is not directly available in the current API
    // We can check if the user is in the editors list instead
    match graph_client
        .get_graph_relationship_descriptors(graph_id, "editors", Some(50), None)
        .await
    {
        Ok(editors) => {
            let has_access = editors.data.iter().any(|editor| editor.id == user_id);
            println!(
                "User '{}': {} edit access",
                user_id,
                if has_access { "HAS" } else { "NO" }
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

    match fetch_editor_descriptors(graph_client, graph_id).await {
        Ok(descriptors) => {
            print_editor_success(&descriptors.data);
            display_editor_descriptors(&descriptors.data);
        }
        Err(e) => print_editor_error(&e),
    }
}

/// Fetch editor descriptors
async fn fetch_editor_descriptors(
    graph_client: &GraphClient<'_>,
    graph_id: &str,
) -> Result<virustotal_rs::Collection<GraphRelationshipDescriptor>, virustotal_rs::Error> {
    graph_client
        .get_graph_relationship_descriptors(graph_id, "editors", Some(20), None)
        .await
}

/// Print editor success message
fn print_editor_success(descriptors: &[GraphRelationshipDescriptor]) {
    println!("✓ Retrieved editor descriptors");
    println!("  Total editors: {}", descriptors.len());
}

/// Print editor error message
fn print_editor_error(error: &virustotal_rs::Error) {
    println!("✗ Error getting editor descriptors: {}", error);
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
    print_editor_info_header();

    match fetch_graph_editors(graph_client, graph_id).await {
        Ok(editors) => handle_editor_success(&editors.data),
        Err(e) => handle_editor_error(&e),
    }
}

/// Print header for editor information section
fn print_editor_info_header() {
    println!("\n4. GETTING FULL EDITOR INFORMATION");
    println!("-----------------------------------");
}

/// Fetch graph editors from the API
async fn fetch_graph_editors(
    graph_client: &GraphClient<'_>,
    graph_id: &str,
) -> Result<virustotal_rs::Collection<virustotal_rs::graphs::GraphOwner>, virustotal_rs::Error> {
    graph_client
        .get_graph_relationship(graph_id, "editors", Some(10), None)
        .await
}

/// Handle successful editor information retrieval
fn handle_editor_success(editors: &[GraphOwner]) {
    println!("✓ Retrieved full editor information");
    display_full_editor_info(editors);
}

/// Handle error in editor information retrieval
fn handle_editor_error(error: &virustotal_rs::Error) {
    println!("✗ Error getting full editor information: {}", error);
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
    let viewer_ids = vec!["jared".to_string(), "monica".to_string()];

    match graph_client.add_graph_viewers(graph_id, &viewer_ids).await {
        Ok(_) => {
            println!("✓ Successfully granted view permissions");
            println!("  Added {} viewers", viewer_ids.len());
            for viewer_id in &viewer_ids {
                println!("  - User: {}", viewer_id);
            }
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
    // Note: Permission checking is not directly available in the current API
    // We can check if the user is in the viewers list instead
    match graph_client
        .get_graph_relationship_descriptors(graph_id, "viewers", Some(50), None)
        .await
    {
        Ok(viewers) => {
            let has_access = viewers.data.iter().any(|viewer| viewer.id == user_id);
            println!(
                "User '{}': {} view access",
                user_id,
                if has_access { "HAS" } else { "NO" }
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
    let user_ids = vec!["dinesh".to_string()];
    match graph_client.remove_graph_editors(graph_id, &user_ids).await {
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
    let user_ids = vec!["jared".to_string()];
    match graph_client.remove_graph_viewers(graph_id, &user_ids).await {
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
        graph_client
            .get_graph_relationship_descriptors(graph_id, "editors", Some(50), None)
            .await
    } else {
        graph_client
            .get_graph_relationship_descriptors(graph_id, "viewers", Some(50), None)
            .await
    };

    if let Ok(response) = result {
        let has_access = response.data.iter().any(|item| item.id == user_id);
        println!(
            "  Verification: '{}' {} has {} access",
            user_id,
            if has_access { "still" } else { "no longer" },
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
    let new_editors = vec!["richard".to_string()];

    // Others get only view access
    let new_viewers = vec!["gavin".to_string(), "laurie".to_string()];

    grant_specific_edit_permissions(graph_client, graph_id, new_editors).await;
    grant_specific_view_permissions(graph_client, graph_id, new_viewers).await;
}

async fn grant_specific_edit_permissions(
    graph_client: &GraphClient<'_>,
    graph_id: &str,
    editor_ids: Vec<String>,
) {
    match graph_client.add_graph_editors(graph_id, &editor_ids).await {
        Ok(_) => println!("✓ Granted edit permission to 'richard'"),
        Err(e) => println!("✗ Error: {}", e),
    }
}

async fn grant_specific_view_permissions(
    graph_client: &GraphClient<'_>,
    graph_id: &str,
    viewer_ids: Vec<String>,
) {
    match graph_client.add_graph_viewers(graph_id, &viewer_ids).await {
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
        .get_graph_relationship_descriptors(graph_id, "editors", Some(50), None)
        .await
        .map(|editors| editors.data.iter().any(|editor| editor.id == user_id))
        .unwrap_or(false);

    let can_view = graph_client
        .get_graph_relationship_descriptors(graph_id, "viewers", Some(50), None)
        .await
        .map(|viewers| viewers.data.iter().any(|viewer| viewer.id == user_id))
        .unwrap_or(false);

    (can_edit, can_view)
}

async fn get_graph_owner_info(graph_client: &GraphClient<'_>, graph_id: &str) {
    println!("\n9. GRAPH OWNER");
    println!("--------------");

    match graph_client
        .get_graph_relationship::<GraphOwner>(graph_id, "owner", Some(1), None)
        .await
    {
        Ok(owners) => {
            if let Some(owner) = owners.data.first() {
                println!("✓ Retrieved graph owner");
                display_owner_information(owner);
            } else {
                println!("✗ No owner found");
            }
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
