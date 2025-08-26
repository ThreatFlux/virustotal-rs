use virustotal_rs::{ApiTier, ClientBuilder, CommentVoteType, CommentsClient};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let api_key = std::env::var("VT_API_KEY").unwrap_or_else(|_| "test_key".to_string());
    let client = ClientBuilder::new()
        .api_key(api_key)
        .tier(ApiTier::Public)
        .build()?;

    let comments_client = client.comments();
    let example_comment_id = "f-abc123456789-xyz987654321";
    run_comment_tests(&comments_client, example_comment_id).await?;
    Ok(())
}

async fn run_comment_tests(
    comments_client: &CommentsClient<'_>,
    example_comment_id: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    println!("Testing Comments API:");
    println!("====================");

    test_latest_comments(comments_client).await?;
    test_filtered_comments(comments_client).await?;
    test_get_comment(comments_client, example_comment_id).await?;
    test_voting(comments_client, example_comment_id).await?;
    test_id_parsing();
    test_relationships(comments_client, example_comment_id).await?;
    test_iterator(comments_client).await?;
    test_delete(comments_client, example_comment_id).await?;

    println!("\n====================");
    println!("Comments API testing complete!");
    Ok(())
}

async fn test_latest_comments(
    comments_client: &CommentsClient<'_>,
) -> Result<(), Box<dyn std::error::Error>> {
    println!("\n1. Getting latest comments:");
    match comments_client.get_latest(None, Some(5)).await {
        Ok(comments) => {
            println!("   ✓ Successfully retrieved latest comments");
            if let Some(meta) = &comments.meta {
                if let Some(count) = meta.count {
                    println!("   - Total comments in batch: {}", count);
                }
                if meta.cursor.is_some() {
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
            }
        }
        Err(e) => println!("   ✗ Error: {}", e),
    }
    Ok(())
}

async fn test_filtered_comments(
    comments_client: &CommentsClient<'_>,
) -> Result<(), Box<dyn std::error::Error>> {
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
    Ok(())
}

async fn test_get_comment(
    comments_client: &CommentsClient<'_>,
    comment_id: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    println!("\n3. Getting a specific comment:");
    match comments_client.get(comment_id).await {
        Ok(comment) => {
            println!("   ✓ Successfully retrieved comment");
            println!("   - ID: {}", comment.object.id);
            println!("   - Text: {}", comment.object.attributes.text);
        }
        Err(e) => println!("   ✗ Error (expected if comment doesn't exist): {}", e),
    }
    Ok(())
}

async fn vote_and_print(
    comments_client: &CommentsClient<'_>,
    comment_id: &str,
    vote: CommentVoteType,
    label: &str,
) {
    println!("   {}", label);
    match comments_client.vote(comment_id, vote).await {
        Ok(response) => {
            println!("      ✓ Successfully voted");
            println!(
                "      - Updated votes: {} positive, {} negative, {} abuse",
                response.data.positive, response.data.negative, response.data.abuse
            );
        }
        Err(e) => println!("      ✗ Error: {}", e),
    }
}

async fn test_voting(
    comments_client: &CommentsClient<'_>,
    comment_id: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    println!("\n4. Voting on a comment:");
    vote_and_print(
        comments_client,
        comment_id,
        CommentVoteType::Positive,
        "   a) Adding positive vote:",
    )
    .await;
    vote_and_print(
        comments_client,
        comment_id,
        CommentVoteType::Negative,
        "   b) Adding negative vote:",
    )
    .await;
    vote_and_print(
        comments_client,
        comment_id,
        CommentVoteType::Abuse,
        "   c) Reporting as abuse:",
    )
    .await;
    Ok(())
}

fn test_id_parsing() {
    println!("\n5. Comment ID parsing utilities:");
    let test_ids = [
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
}

async fn test_relationships(
    comments_client: &CommentsClient<'_>,
    comment_id: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    println!("\n6. Getting comment relationships:");
    match comments_client
        .get_relationship::<serde_json::Value>(comment_id, "item")
        .await
    {
        Ok(items) => {
            println!("   ✓ Successfully retrieved related items");
            println!("   - Number of related items: {}", items.data.len());
        }
        Err(e) => println!("   ✗ Error: {}", e),
    }
    Ok(())
}

async fn test_iterator(
    comments_client: &CommentsClient<'_>,
) -> Result<(), Box<dyn std::error::Error>> {
    println!("\n7. Testing comment iteration:");
    let mut iterator = comments_client.get_latest_iterator(Some("tag:phishing".to_string()));
    match iterator.next_batch().await {
        Ok(batch) => {
            if batch.is_empty() {
                println!("   - No comments with 'phishing' tag found");
            } else {
                println!("   ✓ Retrieved batch of {} comments", batch.len());
                for comment in batch.iter().take(2) {
                    let text = &comment.object.attributes.text;
                    println!("   - Comment: {}", &text[..50.min(text.len())]);
                }
            }
        }
        Err(e) => println!("   ✗ Error: {}", e),
    }
    Ok(())
}

async fn test_delete(
    comments_client: &CommentsClient<'_>,
    comment_id: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    println!("\n8. Deleting a comment:");
    match comments_client.delete(comment_id).await {
        Ok(()) => println!("   ✓ Successfully deleted comment"),
        Err(e) => println!("   ✗ Error (expected if you don't own the comment): {}", e),
    }
    Ok(())
}
