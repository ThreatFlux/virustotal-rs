use virustotal_rs::comments::Comment;
use virustotal_rs::graphs::{Graph, GraphAttributes, GraphOwner, GraphRelationshipDescriptor};
use virustotal_rs::objects::CollectionMeta;
use virustotal_rs::{
    CreateGraphRequest, GraphClient, GraphOrder, GraphVisibility, PermissionDescriptor,
    UpdateGraphRequest,
};

mod common;
use common::{print_step_header, setup_client};

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

async fn list_graphs(graph_client: &GraphClient<'_>) {
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

fn display_pagination_info(meta: &Option<CollectionMeta>) {
    if let Some(meta) = meta {
        if let Some(cursor) = &meta.cursor {
            println!(
                "   - Cursor for pagination: {}",
                &cursor[..20.min(cursor.len())]
            );
        }
    }
}

fn display_graph_list(graphs: &[Graph]) {
    for graph in graphs.iter().take(5) {
        println!("   - Graph ID: {}", graph.object.id);
        display_graph_basic_info(&graph.object.attributes);
        display_graph_metrics(&graph.object.attributes);
        display_graph_owner(&graph.object.attributes);
    }
}

fn display_graph_basic_info(attributes: &GraphAttributes) {
    if let Some(name) = &attributes.name {
        print!("     Name: {}", name);
    }
    if let Some(visibility) = &attributes.visibility {
        print!(" [{}]", visibility);
    }
    println!();
}

fn display_graph_metrics(attributes: &GraphAttributes) {
    if let Some(nodes) = &attributes.nodes_count {
        print!("     Nodes: {}", nodes);
    }
    if let Some(edges) = &attributes.edges_count {
        print!(", Edges: {}", edges);
    }
    println!();
}

fn display_graph_owner(attributes: &GraphAttributes) {
    if let Some(owner) = &attributes.owner {
        println!("     Owner: {}", owner);
    }
}

async fn create_test_graph(graph_client: &GraphClient<'_>) -> Option<String> {
    print_step_header(2, "CREATING GRAPH");

    let graph_data = create_sample_graph_data();
    let create_request = build_create_request(graph_data);

    match graph_client.create_graph(&create_request).await {
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

fn create_sample_graph_data() -> serde_json::Value {
    serde_json::json!({
        "nodes": [
            {
                "id": "file_1",
                "type": "file",
                "label": "malware.exe",
                "attributes": {
                    "sha256": "abc123def456",
                    "size": 1024000
                }
            },
            {
                "id": "domain_1",
                "type": "domain",
                "label": "malicious.com",
                "attributes": {
                    "reputation": -50
                }
            },
            {
                "id": "ip_1",
                "type": "ip_address",
                "label": "192.168.1.1",
                "attributes": {
                    "country": "US"
                }
            }
        ],
        "edges": [
            {
                "from": "file_1",
                "to": "domain_1",
                "label": "communicates_with",
                "type": "network"
            },
            {
                "from": "domain_1",
                "to": "ip_1",
                "label": "resolves_to",
                "type": "dns"
            }
        ]
    })
}

fn build_create_request(graph_data: serde_json::Value) -> CreateGraphRequest {
    CreateGraphRequest::new("SDK Test Graph".to_string())
        .with_description("Test graph created by Rust SDK".to_string())
        .with_graph_type("malware_analysis".to_string())
        .with_visibility(GraphVisibility::Private)
        .with_tags(vec!["test".to_string(), "rust_sdk".to_string()])
        .with_graph_data(graph_data)
}

fn display_created_graph_info(graph: &Graph) {
    println!("   - ID: {}", graph.object.id);
    if let Some(name) = &graph.object.attributes.name {
        println!("   - Name: {}", name);
    }
    if let Some(creation_date) = &graph.object.attributes.creation_date {
        println!("   - Created: {}", creation_date);
    }
}

async fn test_graph_operations(graph_client: &GraphClient<'_>, graph_id: &str) {
    retrieve_graph(graph_client, graph_id).await;
    update_graph(graph_client, graph_id).await;
}

async fn retrieve_graph(graph_client: &GraphClient<'_>, graph_id: &str) {
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

fn display_graph_details(attributes: &GraphAttributes) {
    if let Some(name) = &attributes.name {
        println!("   - Name: {}", name);
    }
    if let Some(description) = &attributes.description {
        println!("   - Description: {}", description);
    }
    if let Some(graph_type) = &attributes.graph_type {
        println!("   - Type: {}", graph_type);
    }
    if let Some(visibility) = &attributes.visibility {
        println!("   - Visibility: {}", visibility);
    }
    if let Some(tags) = &attributes.tags {
        if !tags.is_empty() {
            println!("   - Tags: {}", tags.join(", "));
        }
    }
}

async fn update_graph(graph_client: &GraphClient<'_>, graph_id: &str) {
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

fn build_update_request(graph_id: &str) -> UpdateGraphRequest {
    UpdateGraphRequest::new(graph_id.to_string())
        .with_name("Updated SDK Test Graph".to_string())
        .with_description("Updated description for the test graph".to_string())
        .with_visibility(GraphVisibility::Public)
        .with_tags(vec!["updated".to_string(), "public".to_string()])
}

fn display_updated_graph_info(attributes: &GraphAttributes) {
    if let Some(name) = &attributes.name {
        println!("   - New name: {}", name);
    }
    if let Some(visibility) = &attributes.visibility {
        println!("   - New visibility: {}", visibility);
    }
    if let Some(modification_date) = &attributes.modification_date {
        println!("   - Modified: {}", modification_date);
    }
}

async fn test_comment_operations(graph_client: &GraphClient<'_>, graph_id: &str) {
    add_graph_comments(graph_client, graph_id).await;
    retrieve_graph_comments(graph_client, graph_id).await;
}

async fn add_graph_comments(graph_client: &GraphClient<'_>, graph_id: &str) {
    print_step_header(5, "ADDING COMMENTS");

    let comments = [
        "This is a test comment on the graph",
        "This graph shows malware network connections",
    ];

    for (i, comment_text) in comments.iter().enumerate() {
        handle_comment_addition(graph_client, graph_id, comment_text, i).await;
    }
}

async fn handle_comment_addition(
    graph_client: &GraphClient<'_>,
    graph_id: &str,
    comment_text: &str,
    index: usize,
) {
    match graph_client.add_graph_comment(graph_id, comment_text).await {
        Ok(comment) => {
            if index == 0 {
                println!("   ✓ Comment added successfully");
                println!("   - Comment ID: {}", comment.object.id);
                println!("   - Text: {}", comment.object.attributes.text);
            } else {
                println!("   ✓ Second comment added successfully");
            }
        }
        Err(e) => {
            println!(
                "   ✗ Error adding {} comment: {}",
                if index == 0 { "first" } else { "second" },
                e
            );
        }
    }
}

async fn retrieve_graph_comments(graph_client: &GraphClient<'_>, graph_id: &str) {
    print_step_header(6, "RETRIEVING COMMENTS");

    match graph_client
        .get_graph_comments(graph_id, Some(10), None)
        .await
    {
        Ok(comments) => {
            println!("   ✓ Retrieved graph comments");
            println!("   - Total comments: {}", comments.data.len());
            display_comment_list(&comments.data);
        }
        Err(e) => {
            println!("   ✗ Error getting comments: {}", e);
        }
    }
}

fn display_comment_list(comments: &[Comment]) {
    for comment in comments.iter().take(5) {
        println!("\n   Comment ID: {}", comment.object.id);
        println!("   - Text: {}", comment.object.attributes.text);

        if let Some(date) = &comment.object.attributes.date {
            println!("   - Date: {}", date);
        }

        if let Some(votes) = &comment.object.attributes.votes {
            println!("   - Votes: +{} -{}", votes.positive, votes.negative);
        }
    }
}

async fn search_graphs(graph_client: &GraphClient<'_>) {
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

fn display_search_results(graphs: &[Graph]) {
    for graph in graphs.iter().take(3) {
        println!("   - Graph ID: {}", graph.object.id);
        if let Some(name) = &graph.object.attributes.name {
            println!("     Name: {}", name);
        }
    }
}

async fn test_pagination(graph_client: &GraphClient<'_>) {
    print_step_header(8, "PAGINATION TEST");
    test_graph_pagination(graph_client).await;
}

async fn test_graph_pagination(graph_client: &GraphClient<'_>) {
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

fn display_paginated_graphs(batch: &[Graph]) {
    for graph in batch.iter().take(3) {
        if let Some(name) = &graph.object.attributes.name {
            println!("   - {}", name);
        }
    }
}

async fn test_comment_pagination(graph_client: &GraphClient<'_>, graph_id: &str) {
    print_step_header(9, "COMMENT PAGINATION");

    let mut comment_iterator = graph_client.get_graph_comments_iterator(graph_id);

    println!("Fetching comments with iterator:");
    match comment_iterator.next_batch().await {
        Ok(batch) => {
            println!("   ✓ Retrieved {} comments", batch.len());
            display_paginated_comments(&batch);
        }
        Err(e) => {
            println!("   ✗ Error fetching comments: {}", e);
        }
    }
}

fn display_paginated_comments(batch: &[Comment]) {
    for comment in batch.iter().take(3) {
        let text = &comment.object.attributes.text;
        println!("   - {}", &text[..50.min(text.len())]);
    }
}

async fn test_permission_management(graph_client: &GraphClient<'_>, graph_id: &str) {
    print_step_header(10, "PERMISSION MANAGEMENT");
    execute_permission_tests(graph_client, graph_id).await;
}

async fn execute_permission_tests(graph_client: &GraphClient<'_>, graph_id: &str) {
    grant_view_permissions(graph_client, graph_id).await;
    check_view_permission(graph_client, graph_id).await;
    grant_edit_permissions(graph_client, graph_id).await;
    get_viewer_descriptors(graph_client, graph_id).await;
    revoke_permission(graph_client, graph_id).await;
}

async fn grant_view_permissions(graph_client: &GraphClient<'_>, graph_id: &str) {
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

async fn check_view_permission(graph_client: &GraphClient<'_>, graph_id: &str) {
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

async fn grant_edit_permissions(graph_client: &GraphClient<'_>, graph_id: &str) {
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

async fn get_viewer_descriptors(graph_client: &GraphClient<'_>, graph_id: &str) {
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

fn display_viewer_descriptors(descriptors: &[GraphRelationshipDescriptor]) {
    for descriptor in descriptors.iter().take(3) {
        println!("   - {} (ID: {})", descriptor.object_type, descriptor.id);
    }
}

async fn revoke_permission(graph_client: &GraphClient<'_>, graph_id: &str) {
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

async fn test_relationship_operations(graph_client: &GraphClient<'_>, graph_id: &str) {
    print_step_header(11, "GRAPH RELATIONSHIPS");
    execute_relationship_tests(graph_client, graph_id).await;
}

async fn execute_relationship_tests(graph_client: &GraphClient<'_>, graph_id: &str) {
    get_graph_owner(graph_client, graph_id).await;
    get_graph_editors(graph_client, graph_id).await;
    get_relationship_descriptors(graph_client, graph_id).await;
    test_comment_pagination(graph_client, graph_id).await;
}

async fn get_graph_owner(graph_client: &GraphClient<'_>, graph_id: &str) {
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

fn display_owner_info(owner: &GraphOwner) {
    println!("   - User ID: {}", owner.object.id);

    if let Some(first_name) = &owner.object.attributes.first_name {
        if let Some(last_name) = &owner.object.attributes.last_name {
            println!("   - Name: {} {}", first_name, last_name);
        }
    }

    if let Some(status) = &owner.object.attributes.status {
        println!("   - Status: {}", status);
    }

    if let Some(reputation) = &owner.object.attributes.reputation {
        println!("   - Reputation: {}", reputation);
    }
}

async fn get_graph_editors(graph_client: &GraphClient<'_>, graph_id: &str) {
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

fn display_editor_list(editors: &[GraphOwner]) {
    for editor in editors.iter().take(3) {
        println!("   - Editor: {}", editor.object.id);
    }
}

async fn get_relationship_descriptors(graph_client: &GraphClient<'_>, graph_id: &str) {
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

fn display_relationship_descriptors(descriptors: &[GraphRelationshipDescriptor]) {
    for descriptor in descriptors.iter().take(3) {
        println!("   - {} (ID: {})", descriptor.object_type, descriptor.id);
        if let Some(context) = &descriptor.context_attributes {
            println!("     Context: {:?}", context);
        }
    }
}

async fn cleanup_graph(graph_client: &GraphClient<'_>, graph_id: &str) {
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

async fn test_graph_filters(graph_client: &GraphClient<'_>) {
    print_step_header(13, "FILTERING BY OWNER");
    filter_graphs_by_owner(graph_client).await;

    print_step_header(14, "FILTERING BY TAG");
    filter_graphs_by_tag(graph_client).await;
}

async fn filter_graphs_by_owner(graph_client: &GraphClient<'_>) {
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

async fn filter_graphs_by_tag(graph_client: &GraphClient<'_>) {
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
