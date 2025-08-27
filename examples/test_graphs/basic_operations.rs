use virustotal_rs::{
    CreateGraphRequest, GraphClient, GraphOrder, GraphVisibility,
};
use crate::common::print_step_header;
use super::graph_data::create_sample_graph_data;
use super::display_utils::*;
use virustotal_rs::graphs::Graph;

pub async fn list_graphs(graph_client: &GraphClient<'_>) {
    print_step_header(1, "LISTING GRAPHS");

    match graph_client
        .list_graphs(
            Some("visibility:public"),
            Some(GraphOrder::CreationDateDesc),
            Some(10),
            None,
        )
        .await
    {
        Ok(graphs) => {
            println!("   ✓ Retrieved graphs");
            display_pagination_info(&graphs.meta);
            display_graph_list(&graphs.data);
        }
        Err(e) => {
            println!("   ✗ Error listing graphs: {}", e);
            println!("   Note: Graph API may require specific privileges");
        }
    }
}

/// Handle graph creation result
pub fn handle_graph_creation_result(result: Result<Graph, virustotal_rs::Error>) -> Option<String> {
    match result {
        Ok(graph) => {
            println!("   ✓ Graph created successfully");
            display_created_graph_info(&graph);
            Some(graph.object.id)
        }
        Err(e) => {
            println!("   ✗ Error creating graph: {}", e);
            None
        }
    }
}

/// Create a test graph
pub async fn create_test_graph(graph_client: &GraphClient<'_>) -> Option<String> {
    print_step_header(2, "CREATING GRAPH");

    let graph_data = create_sample_graph_data();
    let create_request = build_create_request(graph_data);

    let result = graph_client.create_graph(&create_request).await;
    handle_graph_creation_result(result)
}

pub fn build_create_request(graph_data: serde_json::Value) -> CreateGraphRequest {
    CreateGraphRequest::new("SDK Test Graph".to_string())
        .with_description("Test graph created by Rust SDK".to_string())
        .with_graph_type("malware_analysis".to_string())
        .with_visibility(GraphVisibility::Private)
        .with_tags(vec!["test".to_string(), "rust_sdk".to_string()])
        .with_graph_data(graph_data)
}

pub async fn test_graph_operations(graph_client: &GraphClient<'_>, graph_id: &str) {
    retrieve_graph(graph_client, graph_id).await;
    update_graph(graph_client, graph_id).await;
}

pub async fn retrieve_graph(graph_client: &GraphClient<'_>, graph_id: &str) {
    print_step_header(3, "RETRIEVING GRAPH");

    match graph_client.get_graph(graph_id).await {
        Ok(graph) => {
            println!("   ✓ Graph retrieved successfully");
            display_graph_details(&graph.object.attributes);
        }
        Err(e) => {
            println!("   ✗ Error retrieving graph: {}", e);
        }
    }
}

pub async fn update_graph(graph_client: &GraphClient<'_>, graph_id: &str) {
    print_step_header(4, "UPDATING GRAPH");

    let update_request = build_update_request(graph_id);

    match graph_client.update_graph(graph_id, &update_request).await {
        Ok(updated) => {
            println!("   ✓ Graph updated successfully");
            display_updated_graph_info(&updated.object.attributes);
        }
        Err(e) => {
            println!("   ✗ Error updating graph: {}", e);
        }
    }
}

pub fn build_update_request(graph_id: &str) -> virustotal_rs::UpdateGraphRequest {
    virustotal_rs::UpdateGraphRequest::new(graph_id.to_string())
        .with_name("Updated SDK Test Graph".to_string())
        .with_description("Updated description for the test graph".to_string())
        .with_visibility(GraphVisibility::Public)
        .with_tags(vec!["updated".to_string(), "public".to_string()])
}

pub async fn search_graphs(graph_client: &GraphClient<'_>) {
    print_step_header(7, "SEARCHING GRAPHS");

    match graph_client.search_graphs("malware", Some(5), None).await {
        Ok(results) => {
            println!("   ✓ Search completed");
            println!("   - Found {} graphs", results.data.len());
            display_search_results(&results.data);
        }
        Err(e) => {
            println!("   ✗ Error searching graphs: {}", e);
        }
    }
}

pub async fn test_pagination(graph_client: &GraphClient<'_>) {
    print_step_header(8, "PAGINATION TEST");
    test_graph_pagination(graph_client).await;
}

pub async fn test_graph_pagination(graph_client: &GraphClient<'_>) {
    let mut graph_iterator =
        graph_client.list_graphs_iterator(Some("visibility:public"), Some(GraphOrder::NameAsc));

    println!("Fetching first batch of graphs:");
    match graph_iterator.next_batch().await {
        Ok(batch) => {
            println!("   ✓ Retrieved {} graphs in first batch", batch.len());
            display_paginated_graphs(&batch);
        }
        Err(e) => {
            println!("   ✗ Error fetching batch: {}", e);
        }
    }
}

pub async fn test_graph_filters(graph_client: &GraphClient<'_>) {
    print_step_header(13, "FILTERING BY OWNER");
    filter_graphs_by_owner(graph_client).await;

    print_step_header(14, "FILTERING BY TAG");
    filter_graphs_by_tag(graph_client).await;
}

pub async fn filter_graphs_by_owner(graph_client: &GraphClient<'_>) {
    match graph_client
        .list_graphs(Some("owner:admin"), None, Some(5), None)
        .await
    {
        Ok(graphs) => {
            println!("   ✓ Found {} graphs owned by 'admin'", graphs.data.len());
        }
        Err(e) => {
            println!("   ✗ Error filtering by owner: {}", e);
        }
    }
}

pub async fn filter_graphs_by_tag(graph_client: &GraphClient<'_>) {
    match graph_client
        .list_graphs(Some("tag:malware"), None, Some(5), None)
        .await
    {
        Ok(graphs) => {
            println!(
                "   ✓ Found {} graphs tagged with 'malware'",
                graphs.data.len()
            );
        }
        Err(e) => {
            println!("   ✗ Error filtering by tag: {}", e);
        }
    }
}

pub async fn cleanup_graph(graph_client: &GraphClient<'_>, graph_id: &str) {
    print_step_header(12, "CLEANUP");

    match graph_client.delete_graph(graph_id).await {
        Ok(_) => {
            println!("   ✓ Graph deleted successfully");
        }
        Err(e) => {
            println!("   ✗ Error deleting graph: {}", e);
        }
    }
}