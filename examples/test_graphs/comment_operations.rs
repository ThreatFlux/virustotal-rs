use super::display_utils::{display_comment_list, display_paginated_comments};
use crate::common::print_step_header;
use virustotal_rs::GraphClient;

pub async fn test_comment_operations(graph_client: &GraphClient<'_>, graph_id: &str) {
    add_graph_comments(graph_client, graph_id).await;
    retrieve_graph_comments(graph_client, graph_id).await;
}

pub async fn add_graph_comments(graph_client: &GraphClient<'_>, graph_id: &str) {
    print_step_header(5, "ADDING COMMENTS");

    let comments = [
        "This is a test comment on the graph",
        "This graph shows malware network connections",
    ];

    for (i, comment_text) in comments.iter().enumerate() {
        handle_comment_addition(graph_client, graph_id, comment_text, i).await;
    }
}

pub async fn handle_comment_addition(
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

pub async fn retrieve_graph_comments(graph_client: &GraphClient<'_>, graph_id: &str) {
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

pub async fn test_comment_pagination(graph_client: &GraphClient<'_>, graph_id: &str) {
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
