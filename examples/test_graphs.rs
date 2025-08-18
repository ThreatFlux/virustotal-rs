use virustotal_rs::{
    ApiTier, ClientBuilder, CreateGraphRequest, GraphOrder, GraphVisibility, PermissionDescriptor,
    UpdateGraphRequest,
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let api_key = std::env::var("VT_API_KEY").unwrap_or_else(|_| "test_key".to_string());

    let client = ClientBuilder::new()
        .api_key(api_key)
        .tier(ApiTier::Premium) // Some graph features may require premium privileges
        .build()?;

    println!("Testing VirusTotal Graph API");
    println!("=============================\n");

    let graph_client = client.graphs();

    // 1. List existing graphs
    println!("1. LISTING GRAPHS");
    println!("-----------------");

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
            if let Some(meta) = &graphs.meta {
                if let Some(cursor) = &meta.cursor {
                    println!(
                        "   - Cursor for pagination: {}",
                        &cursor[..20.min(cursor.len())]
                    );
                }
            }

            for graph in graphs.data.iter().take(5) {
                println!("   - Graph ID: {}", graph.object.id);
                if let Some(name) = &graph.object.attributes.name {
                    print!("     Name: {}", name);
                }
                if let Some(visibility) = &graph.object.attributes.visibility {
                    print!(" [{}]", visibility);
                }
                println!();

                if let Some(nodes) = &graph.object.attributes.nodes_count {
                    print!("     Nodes: {}", nodes);
                }
                if let Some(edges) = &graph.object.attributes.edges_count {
                    print!(", Edges: {}", edges);
                }
                println!();

                if let Some(owner) = &graph.object.attributes.owner {
                    println!("     Owner: {}", owner);
                }
            }
        }
        Err(e) => {
            println!("   ✗ Error listing graphs: {}", e);
            println!("   Note: Graph API may require specific privileges");
        }
    }

    // 2. Create a new graph
    println!("\n2. CREATING GRAPH");
    println!("-----------------");

    // Create graph data structure
    let graph_data = serde_json::json!({
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
    });

    let create_request = CreateGraphRequest::new("SDK Test Graph".to_string())
        .with_description("Test graph created by Rust SDK".to_string())
        .with_graph_type("malware_analysis".to_string())
        .with_visibility(GraphVisibility::Private)
        .with_tags(vec!["test".to_string(), "rust_sdk".to_string()])
        .with_graph_data(graph_data);

    let created_graph_id = match graph_client.create_graph(&create_request).await {
        Ok(graph) => {
            println!("   ✓ Graph created successfully");
            println!("   - ID: {}", graph.object.id);
            if let Some(name) = &graph.object.attributes.name {
                println!("   - Name: {}", name);
            }
            if let Some(creation_date) = &graph.object.attributes.creation_date {
                println!("   - Created: {}", creation_date);
            }
            Some(graph.object.id)
        }
        Err(e) => {
            println!("   ✗ Error creating graph: {}", e);
            None
        }
    };

    // 3. Get the created graph
    if let Some(graph_id) = &created_graph_id {
        println!("\n3. RETRIEVING GRAPH");
        println!("-------------------");

        match graph_client.get_graph(graph_id).await {
            Ok(graph) => {
                println!("   ✓ Graph retrieved successfully");
                if let Some(name) = &graph.object.attributes.name {
                    println!("   - Name: {}", name);
                }
                if let Some(description) = &graph.object.attributes.description {
                    println!("   - Description: {}", description);
                }
                if let Some(graph_type) = &graph.object.attributes.graph_type {
                    println!("   - Type: {}", graph_type);
                }
                if let Some(visibility) = &graph.object.attributes.visibility {
                    println!("   - Visibility: {}", visibility);
                }
                if let Some(tags) = &graph.object.attributes.tags {
                    if !tags.is_empty() {
                        println!("   - Tags: {}", tags.join(", "));
                    }
                }
            }
            Err(e) => {
                println!("   ✗ Error retrieving graph: {}", e);
            }
        }
    }

    // 4. Update the graph
    if let Some(graph_id) = &created_graph_id {
        println!("\n4. UPDATING GRAPH");
        println!("-----------------");

        let update_request = UpdateGraphRequest::new(graph_id.clone())
            .with_name("Updated SDK Test Graph".to_string())
            .with_description("Updated description for the test graph".to_string())
            .with_visibility(GraphVisibility::Public)
            .with_tags(vec!["updated".to_string(), "public".to_string()]);

        match graph_client.update_graph(graph_id, &update_request).await {
            Ok(updated) => {
                println!("   ✓ Graph updated successfully");
                if let Some(name) = &updated.object.attributes.name {
                    println!("   - New name: {}", name);
                }
                if let Some(visibility) = &updated.object.attributes.visibility {
                    println!("   - New visibility: {}", visibility);
                }
                if let Some(modification_date) = &updated.object.attributes.modification_date {
                    println!("   - Modified: {}", modification_date);
                }
            }
            Err(e) => {
                println!("   ✗ Error updating graph: {}", e);
            }
        }
    }

    // 5. Add comments to the graph
    if let Some(graph_id) = &created_graph_id {
        println!("\n5. ADDING COMMENTS");
        println!("------------------");

        // Add first comment
        match graph_client
            .add_graph_comment(graph_id, "This is a test comment on the graph")
            .await
        {
            Ok(comment) => {
                println!("   ✓ Comment added successfully");
                println!("   - Comment ID: {}", comment.object.id);
                println!("   - Text: {}", comment.object.attributes.text);
            }
            Err(e) => {
                println!("   ✗ Error adding comment: {}", e);
            }
        }

        // Add second comment
        match graph_client
            .add_graph_comment(graph_id, "This graph shows malware network connections")
            .await
        {
            Ok(_) => {
                println!("   ✓ Second comment added successfully");
            }
            Err(e) => {
                println!("   ✗ Error adding second comment: {}", e);
            }
        }
    }

    // 6. Get comments on the graph
    if let Some(graph_id) = &created_graph_id {
        println!("\n6. RETRIEVING COMMENTS");
        println!("----------------------");

        match graph_client
            .get_graph_comments(graph_id, Some(10), None)
            .await
        {
            Ok(comments) => {
                println!("   ✓ Retrieved graph comments");
                println!("   - Total comments: {}", comments.data.len());

                for comment in comments.data.iter().take(5) {
                    println!("\n   Comment ID: {}", comment.object.id);
                    println!("   - Text: {}", comment.object.attributes.text);
                    if let Some(date) = &comment.object.attributes.date {
                        println!("   - Date: {}", date);
                    }
                    if let Some(votes) = &comment.object.attributes.votes {
                        print!("   - Votes: +{}", votes.positive);
                        print!(" -{}", votes.negative);
                        println!();
                    }
                }
            }
            Err(e) => {
                println!("   ✗ Error getting comments: {}", e);
            }
        }
    }

    // 7. Search for graphs
    println!("\n7. SEARCHING GRAPHS");
    println!("-------------------");

    match graph_client.search_graphs("malware", Some(5), None).await {
        Ok(results) => {
            println!("   ✓ Search completed");
            println!("   - Found {} graphs", results.data.len());

            for graph in results.data.iter().take(3) {
                println!("   - Graph ID: {}", graph.object.id);
                if let Some(name) = &graph.object.attributes.name {
                    println!("     Name: {}", name);
                }
            }
        }
        Err(e) => {
            println!("   ✗ Error searching graphs: {}", e);
        }
    }

    // 8. Test pagination with iterators
    println!("\n8. PAGINATION TEST");
    println!("------------------");

    let mut graph_iterator =
        graph_client.list_graphs_iterator(Some("visibility:public"), Some(GraphOrder::NameAsc));

    println!("Fetching first batch of graphs:");
    match graph_iterator.next_batch().await {
        Ok(batch) => {
            println!("   ✓ Retrieved {} graphs in first batch", batch.len());
            for graph in batch.iter().take(3) {
                if let Some(name) = &graph.object.attributes.name {
                    println!("   - {}", name);
                }
            }
        }
        Err(e) => {
            println!("   ✗ Error fetching batch: {}", e);
        }
    }

    // 9. Test comment pagination
    if let Some(graph_id) = &created_graph_id {
        println!("\n9. COMMENT PAGINATION");
        println!("---------------------");

        let mut comment_iterator = graph_client.get_graph_comments_iterator(graph_id);

        println!("Fetching comments with iterator:");
        match comment_iterator.next_batch().await {
            Ok(batch) => {
                println!("   ✓ Retrieved {} comments", batch.len());
                for comment in batch.iter().take(3) {
                    let text = &comment.object.attributes.text;
                    println!("   - {}", &text[..50.min(text.len())]);
                }
            }
            Err(e) => {
                println!("   ✗ Error fetching comments: {}", e);
            }
        }
    }

    // 10. Test permission management
    if let Some(graph_id) = &created_graph_id {
        println!("\n10. PERMISSION MANAGEMENT");
        println!("-------------------------");

        // Grant view permissions
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

        // Check view permission
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

        // Grant edit permissions
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

        // Get viewers using descriptors (minimal info)
        println!("\nGetting viewer descriptors:");
        match graph_client
            .get_graph_viewers_descriptors(graph_id, Some(10), None)
            .await
        {
            Ok(descriptors) => {
                println!("   ✓ Retrieved viewer descriptors");
                println!("   - Total viewers: {}", descriptors.data.len());
                for descriptor in descriptors.data.iter().take(3) {
                    println!("   - {} (ID: {})", descriptor.object_type, descriptor.id);
                }
            }
            Err(e) => {
                println!("   ✗ Error getting viewer descriptors: {}", e);
            }
        }

        // Revoke a permission
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

    // 11. Test graph relationships
    if let Some(graph_id) = &created_graph_id {
        println!("\n11. GRAPH RELATIONSHIPS");
        println!("-----------------------");

        // Get graph owner
        println!("\nGetting graph owner:");
        match graph_client.get_graph_owner(graph_id).await {
            Ok(owner) => {
                println!("   ✓ Retrieved graph owner");
                println!("   - User ID: {}", owner.object.id);
                if let Some(first_name) = &owner.object.attributes.first_name {
                    print!("   - Name: {}", first_name);
                }
                if let Some(last_name) = &owner.object.attributes.last_name {
                    print!(" {}", last_name);
                }
                println!();
                if let Some(status) = &owner.object.attributes.status {
                    println!("   - Status: {}", status);
                }
                if let Some(reputation) = &owner.object.attributes.reputation {
                    println!("   - Reputation: {}", reputation);
                }
            }
            Err(e) => {
                println!("   ✗ Error getting owner: {}", e);
            }
        }

        // Get graph editors (may be empty)
        println!("\nGetting graph editors:");
        match graph_client
            .get_graph_editors(graph_id, Some(10), None)
            .await
        {
            Ok(editors) => {
                println!("   ✓ Retrieved editors list");
                println!("   - Total editors: {}", editors.data.len());
                for editor in editors.data.iter().take(3) {
                    println!("   - Editor: {}", editor.object.id);
                }
            }
            Err(e) => {
                println!("   ✗ Error getting editors: {}", e);
            }
        }

        // Get relationship descriptors (minimal info)
        println!("\nGetting relationship descriptors:");
        match graph_client
            .get_graph_relationship_descriptors(graph_id, "viewers", Some(5), None)
            .await
        {
            Ok(descriptors) => {
                println!("   ✓ Retrieved viewer descriptors");
                println!("   - Total viewers: {}", descriptors.data.len());
                for descriptor in descriptors.data.iter().take(3) {
                    println!("   - {} (ID: {})", descriptor.object_type, descriptor.id);
                    if let Some(context) = &descriptor.context_attributes {
                        println!("     Context: {:?}", context);
                    }
                }
            }
            Err(e) => {
                println!("   ✗ Error getting descriptors: {}", e);
                println!("   Note: Some relationships require specific permissions");
            }
        }
    }

    // 12. Delete the created graph
    if let Some(graph_id) = &created_graph_id {
        println!("\n12. CLEANUP");
        println!("-----------");

        match graph_client.delete_graph(graph_id).await {
            Ok(_) => {
                println!("   ✓ Graph deleted successfully");
            }
            Err(e) => {
                println!("   ✗ Error deleting graph: {}", e);
            }
        }
    }

    // 13. Filter graphs by owner
    println!("\n13. FILTERING BY OWNER");
    println!("----------------------");

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

    // 14. Filter graphs by tag
    println!("\n14. FILTERING BY TAG");
    println!("--------------------");

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

    println!("\n=============================");
    println!("Graph API testing complete!");

    Ok(())
}
