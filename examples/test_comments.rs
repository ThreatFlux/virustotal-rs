use virustotal_rs::{ApiTier, ClientBuilder, CommentVoteType, CommentsClient};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let api_key = std::env::var("VT_API_KEY").unwrap_or_else(|_| "test_key".to_string());

    let client = ClientBuilder::new()
        .api_key(api_key)
        .tier(ApiTier::Public)
        .build()?;

    let comments_client = client.comments();

    println!("Testing Comments API:");
    println!("====================");

    // Test getting latest comments
    println!("\n1. Getting latest comments:");
    match comments_client.get_latest(None, Some(5)).await {
        Ok(comments) => {
            println!("   ✓ Successfully retrieved latest comments");
            if let Some(meta) = &comments.meta {
                if let Some(count) = meta.count {
                    println!("   - Total comments in batch: {}", count);
                }
                if let Some(_cursor) = &meta.cursor {
                    println!("   - Has more results: yes (cursor available)");
                }
            }
            for comment in comments.data.iter().take(3) {
                println!("\n   Comment: {}", comment.object.id);
                println!("   - Text: {}", comment.object.attributes.text);
                if let Some(tags) = &comment.object.attributes.tags {
                    println!("   - Tags: {:?}", tags);
                }
                if let Some(votes) = &comment.object.attributes.votes {
                    println!(
                        "   - Votes: {} positive, {} negative, {} abuse",
                        votes.positive, votes.negative, votes.abuse
                    );
                }

                // Parse comment ID to understand where it was posted
                if let Some((item_type, _, _)) =
                    CommentsClient::parse_comment_id(&comment.object.id)
                {
                    let item_desc = match item_type {
                        'd' => "domain",
                        'f' => "file",
                        'g' => "graph",
                        'i' => "IP address",
                        'u' => "URL",
                        _ => "unknown",
                    };
                    println!("   - Posted on: {}", item_desc);
                }
            }
        }
        Err(e) => println!("   ✗ Error: {}", e),
    }

    // Test getting filtered comments
    println!("\n2. Getting comments filtered by tag:");
    match comments_client
        .get_latest(Some("tag:malware"), Some(3))
        .await
    {
        Ok(comments) => {
            println!("   ✓ Successfully retrieved filtered comments");
            println!("   - Comments with 'malware' tag: {}", comments.data.len());
            for comment in &comments.data {
                if let Some(tags) = &comment.object.attributes.tags {
                    println!("   - Tags: {:?}", tags);
                }
            }
        }
        Err(e) => println!("   ✗ Error: {}", e),
    }

    // Example comment ID for testing (would be from actual data in production)
    let example_comment_id = "f-abc123456789-xyz987654321";

    // Test getting a specific comment
    println!("\n3. Getting a specific comment:");
    match comments_client.get(example_comment_id).await {
        Ok(comment) => {
            println!("   ✓ Successfully retrieved comment");
            println!("   - ID: {}", comment.object.id);
            println!("   - Text: {}", comment.object.attributes.text);
        }
        Err(e) => println!("   ✗ Error (expected if comment doesn't exist): {}", e),
    }

    // Test voting on a comment
    println!("\n4. Voting on a comment:");

    // Positive vote
    println!("   a) Adding positive vote:");
    match comments_client
        .vote(example_comment_id, CommentVoteType::Positive)
        .await
    {
        Ok(response) => {
            println!("      ✓ Successfully voted");
            println!(
                "      - Updated votes: {} positive, {} negative, {} abuse",
                response.data.positive, response.data.negative, response.data.abuse
            );
        }
        Err(e) => println!("      ✗ Error: {}", e),
    }

    // Negative vote
    println!("   b) Adding negative vote:");
    match comments_client
        .vote(example_comment_id, CommentVoteType::Negative)
        .await
    {
        Ok(response) => {
            println!("      ✓ Successfully voted");
            println!(
                "      - Updated votes: {} positive, {} negative, {} abuse",
                response.data.positive, response.data.negative, response.data.abuse
            );
        }
        Err(e) => println!("      ✗ Error: {}", e),
    }

    // Abuse vote
    println!("   c) Reporting as abuse:");
    match comments_client
        .vote(example_comment_id, CommentVoteType::Abuse)
        .await
    {
        Ok(response) => {
            println!("      ✓ Successfully reported");
            println!(
                "      - Updated votes: {} positive, {} negative, {} abuse",
                response.data.positive, response.data.negative, response.data.abuse
            );
        }
        Err(e) => println!("      ✗ Error: {}", e),
    }

    // Test comment ID parsing
    println!("\n5. Comment ID parsing utilities:");
    let test_ids = vec![
        "f-1234567890abcdef-random123",
        "d-example.com-xyz456",
        "i-192.168.1.1-abc789",
        "u-base64urlid-def012",
        "g-graphid123-ghi345",
    ];

    for id in test_ids {
        println!("   ID: {}", id);
        if let Some((item_type, item_id, random_str)) = CommentsClient::parse_comment_id(id) {
            let item_desc = match item_type {
                'd' => "domain",
                'f' => "file",
                'g' => "graph",
                'i' => "IP address",
                'u' => "URL",
                _ => "unknown",
            };
            println!("      - Type: {} ({})", item_type, item_desc);
            println!("      - Item ID: {}", item_id);
            println!("      - Random suffix: {}", random_str);
        }
    }

    // Test getting comment relationships
    println!("\n6. Getting comment relationships:");
    match comments_client
        .get_relationship::<serde_json::Value>(example_comment_id, "item")
        .await
    {
        Ok(items) => {
            println!("   ✓ Successfully retrieved related items");
            println!("   - Number of related items: {}", items.data.len());
        }
        Err(e) => println!("   ✗ Error: {}", e),
    }

    // Test pagination with iterator
    println!("\n7. Testing comment iteration:");
    let mut iterator = comments_client.get_latest_iterator(Some("tag:phishing".to_string()));
    match iterator.next_batch().await {
        Ok(batch) => {
            if batch.is_empty() {
                println!("   - No comments with 'phishing' tag found");
            } else {
                println!("   ✓ Retrieved batch of {} comments", batch.len());
                for comment in batch.iter().take(2) {
                    println!(
                        "   - Comment: {}",
                        &comment.object.attributes.text
                            [..50.min(comment.object.attributes.text.len())]
                    );
                }
            }
        }
        Err(e) => println!("   ✗ Error: {}", e),
    }

    // Test deleting a comment (only works if you own the comment)
    println!("\n8. Deleting a comment:");
    match comments_client.delete(example_comment_id).await {
        Ok(()) => {
            println!("   ✓ Successfully deleted comment");
        }
        Err(e) => println!("   ✗ Error (expected if you don't own the comment): {}", e),
    }

    println!("\n====================");
    println!("Comments API testing complete!");

    Ok(())
}
