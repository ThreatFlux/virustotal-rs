use virustotal_rs::{ApiTier, ClientBuilder, UrlClient, VoteVerdict};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let api_key = std::env::var("VT_API_KEY").unwrap_or_else(|_| "test_key".to_string());

    let client = ClientBuilder::new()
        .api_key(api_key)
        .tier(ApiTier::Public)
        .build()?;

    let url_client = client.urls();

    // Example URL to test
    let test_url = "http://www.example.com/test";

    println!("Testing URL API methods:");
    println!("========================");

    // Test URL identifier generation
    println!("\n1. URL Identifier Generation:");
    let base64_id = UrlClient::generate_url_id(test_url);
    let sha256_id = UrlClient::generate_url_sha256(test_url);
    println!("   URL: {}", test_url);
    println!("   Base64 ID (no padding): {}", base64_id);
    println!("   SHA256 ID: {}", sha256_id);

    // Test scanning a URL
    println!("\n2. Scanning URL:");
    match url_client.scan(test_url).await {
        Ok(analysis) => {
            println!("   ✓ URL submitted for scanning");
            println!("   - Analysis ID: {}", analysis.data.id);
            println!("   - Type: {}", analysis.data.object_type);
        }
        Err(e) => println!("   ✗ Error: {}", e),
    }

    // Test getting URL report by ID
    println!("\n3. Getting URL report:");
    match url_client.get(&base64_id).await {
        Ok(url_report) => {
            println!("   ✓ Successfully retrieved URL report");
            println!("   - URL: {:?}", url_report.object.attributes.url);
            println!(
                "   - Final URL: {:?}",
                url_report.object.attributes.final_url
            );
            println!("   - Title: {:?}", url_report.object.attributes.title);
            println!(
                "   - Reputation: {:?}",
                url_report.object.attributes.reputation
            );
            println!(
                "   - Times submitted: {:?}",
                url_report.object.attributes.times_submitted
            );

            if let Some(stats) = &url_report.object.attributes.last_analysis_stats {
                println!("   - Last analysis stats:");
                println!("     • Harmless: {}", stats.harmless);
                println!("     • Malicious: {}", stats.malicious);
                println!("     • Suspicious: {}", stats.suspicious);
                println!("     • Undetected: {}", stats.undetected);
            }

            if let Some(votes) = &url_report.object.attributes.total_votes {
                println!("   - Total votes:");
                println!("     • Harmless: {}", votes.harmless);
                println!("     • Malicious: {}", votes.malicious);
            }
        }
        Err(e) => println!("   ✗ Error: {}", e),
    }

    // Test getting URL report by actual URL (convenience method)
    println!("\n4. Getting URL report by actual URL:");
    match url_client.get_by_url(test_url).await {
        Ok(url_report) => {
            println!("   ✓ Successfully retrieved URL report using actual URL");
            println!("   - ID: {}", url_report.object.id);
        }
        Err(e) => println!("   ✗ Error: {}", e),
    }

    // Test rescanning a URL
    println!("\n5. Requesting URL rescan:");
    match url_client.rescan(&base64_id).await {
        Ok(analysis) => {
            println!("   ✓ URL rescan requested");
            println!("   - New analysis ID: {}", analysis.data.id);
        }
        Err(e) => println!("   ✗ Error: {}", e),
    }

    // Test getting comments
    println!("\n6. Getting comments on URL:");
    match url_client.get_comments(&base64_id).await {
        Ok(comments) => {
            println!("   ✓ Successfully retrieved comments");
            if let Some(meta) = &comments.meta {
                if let Some(count) = meta.count {
                    println!("   - Total comments: {}", count);
                }
            }
            for comment in comments.data.iter().take(3) {
                println!("   - Comment: {}", comment.object.attributes.text);
            }
        }
        Err(e) => println!("   ✗ Error: {}", e),
    }

    // Test adding a comment
    println!("\n7. Adding a comment:");
    match url_client
        .add_comment(&base64_id, "This is a test comment #testing")
        .await
    {
        Ok(comment) => {
            println!("   ✓ Successfully added comment");
            println!("   - Comment ID: {}", comment.object.id);
            println!("   - Text: {}", comment.object.attributes.text);
            if let Some(tags) = &comment.object.attributes.tags {
                println!("   - Tags: {:?}", tags);
            }
        }
        Err(e) => println!("   ✗ Error: {}", e),
    }

    // Test getting votes
    println!("\n8. Getting votes on URL:");
    match url_client.get_votes(&base64_id).await {
        Ok(votes) => {
            println!("   ✓ Successfully retrieved votes");
            if let Some(meta) = &votes.meta {
                if let Some(count) = meta.count {
                    println!("   - Total votes: {}", count);
                }
            }
        }
        Err(e) => println!("   ✗ Error: {}", e),
    }

    // Test adding a vote
    println!("\n9. Adding a vote (harmless):");
    match url_client.add_vote(&base64_id, VoteVerdict::Harmless).await {
        Ok(vote) => {
            println!("   ✓ Successfully added vote");
            println!("   - Vote verdict: {:?}", vote.object.attributes.verdict);
        }
        Err(e) => println!("   ✗ Error: {}", e),
    }

    // Test getting relationships
    println!("\n10. Getting URL relationships:");

    // Get analyses
    match url_client.get_analyses(&base64_id).await {
        Ok(analyses) => {
            println!("   ✓ Retrieved analyses");
            if let Some(meta) = &analyses.meta {
                if let Some(count) = meta.count {
                    println!("   - Number of analyses: {}", count);
                }
            }
        }
        Err(e) => println!("   ✗ Error getting analyses: {}", e),
    }

    // Get downloaded files
    match url_client.get_downloaded_files(&base64_id).await {
        Ok(files) => {
            println!("   ✓ Retrieved downloaded files");
            if let Some(meta) = &files.meta {
                if let Some(count) = meta.count {
                    println!("   - Number of downloaded files: {}", count);
                }
            }
        }
        Err(e) => println!("   ✗ Error getting downloaded files: {}", e),
    }

    // Get redirecting URLs
    match url_client.get_redirecting_urls(&base64_id).await {
        Ok(urls) => {
            println!("   ✓ Retrieved redirecting URLs");
            if let Some(meta) = &urls.meta {
                if let Some(count) = meta.count {
                    println!("   - Number of redirecting URLs: {}", count);
                }
            }
        }
        Err(e) => println!("   ✗ Error getting redirecting URLs: {}", e),
    }

    // Test using iterators for paginated results
    println!("\n11. Testing pagination with comments iterator:");
    let mut comments_iter = url_client.get_comments_iterator(&base64_id);
    match comments_iter.next_batch().await {
        Ok(batch) => {
            if batch.is_empty() {
                println!("   - No comments found");
            } else {
                println!("   ✓ Retrieved first batch of comments");
                println!("   - Batch size: {}", batch.len());
            }
        }
        Err(e) => println!("   ✗ Error: {}", e),
    }

    println!("\n========================");
    println!("URL API testing complete!");

    Ok(())
}
