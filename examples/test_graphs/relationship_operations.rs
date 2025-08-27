use super::comment_operations::test_comment_pagination;
use super::display_utils::{
    display_editor_list, display_owner_info, display_relationship_descriptors,
};
use crate::common::print_step_header;
use virustotal_rs::GraphClient;

pub async fn test_relationship_operations(graph_client: &GraphClient<'_>, graph_id: &str) {
    print_step_header(11, "GRAPH RELATIONSHIPS");
    execute_relationship_tests(graph_client, graph_id).await;
}

pub async fn execute_relationship_tests(graph_client: &GraphClient<'_>, graph_id: &str) {
    get_graph_owner(graph_client, graph_id).await;
    get_graph_editors(graph_client, graph_id).await;
    get_relationship_descriptors(graph_client, graph_id).await;
    test_comment_pagination(graph_client, graph_id).await;
}

pub async fn get_graph_owner(graph_client: &GraphClient<'_>, graph_id: &str) {
    println!("\nGetting graph owner:");
    match graph_client.get_graph_owner(graph_id).await {
        Ok(owner) => {
            println!("   ✓ Retrieved graph owner");
            display_owner_info(&owner);
        }
        Err(e) => {
            println!("   ✗ Error getting owner: {}", e);
        }
    }
}

pub async fn get_graph_editors(graph_client: &GraphClient<'_>, graph_id: &str) {
    println!("\nGetting graph editors:");
    match graph_client
        .get_graph_editors(graph_id, Some(10), None)
        .await
    {
        Ok(editors) => {
            println!("   ✓ Retrieved editors list");
            println!("   - Total editors: {}", editors.data.len());
            display_editor_list(&editors.data);
        }
        Err(e) => {
            println!("   ✗ Error getting editors: {}", e);
        }
    }
}

pub async fn get_relationship_descriptors(graph_client: &GraphClient<'_>, graph_id: &str) {
    println!("\nGetting relationship descriptors:");
    match graph_client
        .get_graph_relationship_descriptors(graph_id, "viewers", Some(5), None)
        .await
    {
        Ok(descriptors) => {
            println!("   ✓ Retrieved viewer descriptors");
            println!("   - Total viewers: {}", descriptors.data.len());
            display_relationship_descriptors(&descriptors.data);
        }
        Err(e) => {
            println!("   ✗ Error getting descriptors: {}", e);
            println!("   Note: Some relationships require specific permissions");
        }
    }
}
