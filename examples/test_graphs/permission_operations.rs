use super::display_utils::display_viewer_descriptors;
use crate::common::print_step_header;
use virustotal_rs::{GraphClient, PermissionDescriptor};

pub async fn test_permission_management(graph_client: &GraphClient<'_>, graph_id: &str) {
    print_step_header(10, "PERMISSION MANAGEMENT");
    execute_permission_tests(graph_client, graph_id).await;
}

pub async fn execute_permission_tests(graph_client: &GraphClient<'_>, graph_id: &str) {
    grant_view_permissions(graph_client, graph_id).await;
    check_view_permission(graph_client, graph_id).await;
    grant_edit_permissions(graph_client, graph_id).await;
    get_viewer_descriptors(graph_client, graph_id).await;
    revoke_permission(graph_client, graph_id).await;
}

pub async fn grant_view_permissions(graph_client: &GraphClient<'_>, graph_id: &str) {
    println!("\nGranting view permissions:");
    let viewers = vec![
        PermissionDescriptor::user("viewer1".to_string()),
        PermissionDescriptor::user("viewer2".to_string()),
        PermissionDescriptor::group("analysts".to_string()),
    ];

    match graph_client.grant_view_permission(graph_id, viewers).await {
        Ok(result) => {
            println!("   ✓ Granted view permissions");
            println!("   - Added {} viewers", result.data.len());
        }
        Err(e) => {
            println!("   ✗ Error granting view permissions: {}", e);
        }
    }
}

pub async fn check_view_permission(graph_client: &GraphClient<'_>, graph_id: &str) {
    println!("\nChecking view permission for 'viewer1':");
    match graph_client
        .check_view_permission(graph_id, "viewer1")
        .await
    {
        Ok(response) => {
            println!("   ✓ Permission check result: {}", response.data);
        }
        Err(e) => {
            println!("   ✗ Error checking permission: {}", e);
        }
    }
}

pub async fn grant_edit_permissions(graph_client: &GraphClient<'_>, graph_id: &str) {
    println!("\nGranting edit permissions:");
    let editors = vec![
        PermissionDescriptor::user("editor1".to_string()),
        PermissionDescriptor::group("developers".to_string()),
    ];

    match graph_client.grant_edit_permission(graph_id, editors).await {
        Ok(result) => {
            println!("   ✓ Granted edit permissions");
            println!("   - Added {} editors", result.data.len());
        }
        Err(e) => {
            println!("   ✗ Error granting edit permissions: {}", e);
        }
    }
}

pub async fn get_viewer_descriptors(graph_client: &GraphClient<'_>, graph_id: &str) {
    println!("\nGetting viewer descriptors:");
    match graph_client
        .get_graph_viewers_descriptors(graph_id, Some(10), None)
        .await
    {
        Ok(descriptors) => {
            println!("   ✓ Retrieved viewer descriptors");
            println!("   - Total viewers: {}", descriptors.data.len());
            display_viewer_descriptors(&descriptors.data);
        }
        Err(e) => {
            println!("   ✗ Error getting viewer descriptors: {}", e);
        }
    }
}

pub async fn revoke_permission(graph_client: &GraphClient<'_>, graph_id: &str) {
    println!("\nRevoking view permission from 'viewer2':");
    match graph_client
        .revoke_view_permission(graph_id, "viewer2")
        .await
    {
        Ok(_) => {
            println!("   ✓ Revoked view permission");
        }
        Err(e) => {
            println!("   ✗ Error revoking permission: {}", e);
        }
    }
}
