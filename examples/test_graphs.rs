use virustotal_rs::GraphClient;

#[path = "common/mod.rs"]
mod common;

#[path = "test_graphs/mod.rs"]
mod test_graphs_module;

use common::setup_client;
use test_graphs_module::*;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = setup_client(virustotal_rs::ApiTier::Premium)?;

    println!("Testing VirusTotal Graph API");
    println!("=============================\n");

    let graph_client = client.graphs();
    execute_graph_tests(&graph_client).await;

    println!("\n=============================");
    println!("Graph API testing complete!");
    Ok(())
}

async fn execute_graph_tests(graph_client: &GraphClient<'_>) {
    list_graphs(graph_client).await;

    if let Some(graph_id) = create_test_graph(graph_client).await {
        run_graph_management_tests(graph_client, &graph_id).await;
        cleanup_graph(graph_client, &graph_id).await;
    }

    run_additional_graph_tests(graph_client).await;
}

async fn run_graph_management_tests(graph_client: &GraphClient<'_>, graph_id: &str) {
    test_graph_operations(graph_client, graph_id).await;
    test_comment_operations(graph_client, graph_id).await;
    test_permission_management(graph_client, graph_id).await;
    test_relationship_operations(graph_client, graph_id).await;
}

async fn run_additional_graph_tests(graph_client: &GraphClient<'_>) {
    search_graphs(graph_client).await;
    test_pagination(graph_client).await;
    test_graph_filters(graph_client).await;
}
