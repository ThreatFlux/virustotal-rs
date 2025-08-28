use super::display_utils::display_viewer_descriptors;
use crate::common::print_step_header;
use virustotal_rs::GraphClient;

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
    let viewers = vec!["viewer1".to_string(), "viewer2".to_string()];

    match graph_client.add_graph_viewers(graph_id, &viewers).await {
        Ok(_) => {
            println!("   ✓ Granted view permissions");
            println!("   - Added {} viewers", viewers.len());
        }
        Err(e) => {
            println!("   ✗ Error granting view permissions: {}", e);
        }
    }
}

pub async fn check_view_permission(graph_client: &GraphClient<'_>, graph_id: &str) {
    println!("\nChecking viewers list (viewer1 should be present):");
    match graph_client
        .get_graph_relationship::<virustotal_rs::graphs::GraphOwner>(
            graph_id,
            "viewers",
            Some(10),
            None,
        )
        .await
    {
        Ok(response) => {
            let viewer1_present = response.data.iter().any(|user| user.object.id == "viewer1");
            println!("   ✓ Retrieved viewers list");
            println!("   - viewer1 present: {}", viewer1_present);
        }
        Err(e) => {
            println!("   ✗ Error checking viewers: {}", e);
        }
    }
}

pub async fn grant_edit_permissions(graph_client: &GraphClient<'_>, graph_id: &str) {
    println!("\nGranting edit permissions:");
    let editors = vec!["editor1".to_string()];

    match graph_client.add_graph_editors(graph_id, &editors).await {
        Ok(_) => {
            println!("   ✓ Granted edit permissions");
            println!("   - Added {} editors", editors.len());
        }
        Err(e) => {
            println!("   ✗ Error granting edit permissions: {}", e);
        }
    }
}

pub async fn get_viewer_descriptors(graph_client: &GraphClient<'_>, graph_id: &str) {
    println!("\nGetting viewer descriptors:");
    match graph_client
        .get_graph_relationship_descriptors(graph_id, "viewers", Some(10), None)
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
    let users_to_remove = vec!["viewer2".to_string()];
    match graph_client
        .remove_graph_viewers(graph_id, &users_to_remove)
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
