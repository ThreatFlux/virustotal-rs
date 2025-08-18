use std::env;
use virustotal_rs::{ApiTier, ClientBuilder};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Get API key from environment variable
    let api_key = env::var("VTI_API_KEY").expect("VTI_API_KEY environment variable not set");

    println!("Using API key from VTI_API_KEY environment variable");

    // Create client
    let client = ClientBuilder::new()
        .api_key(api_key)
        .tier(ApiTier::Public)
        .build()?;

    // Test file hash from the provided URL
    let file_hash = "02032ea322036e66f2825a0342979ad942ad5e201a674dc1c0085617467d661c";

    println!("\n=== Testing File API ===");
    println!("Fetching file: {}", file_hash);

    // Get file information
    match client.files().get(file_hash).await {
        Ok(file) => {
            println!("\n✓ File retrieved successfully!");
            println!("  Type: {:?}", file.object.attributes.type_description);
            println!("  Size: {:?} bytes", file.object.attributes.size);
            println!("  SHA256: {:?}", file.object.attributes.sha256);
            println!("  MD5: {:?}", file.object.attributes.md5);
            println!("  Names: {:?}", file.object.attributes.names);
            println!(
                "  Meaningful name: {:?}",
                file.object.attributes.meaningful_name
            );

            if let Some(stats) = &file.object.attributes.last_analysis_stats {
                println!("\n  Last Analysis Stats:");
                println!("    Harmless: {}", stats.harmless);
                println!("    Malicious: {}", stats.malicious);
                println!("    Suspicious: {}", stats.suspicious);
                println!("    Undetected: {}", stats.undetected);
                println!("    Timeout: {}", stats.timeout);
            }

            if let Some(reputation) = file.object.attributes.reputation {
                println!("\n  Reputation: {}", reputation);
            }

            if let Some(votes) = &file.object.attributes.total_votes {
                println!(
                    "  Total Votes - Harmless: {}, Malicious: {}",
                    votes.harmless, votes.malicious
                );
            }

            // Test getting comments
            println!("\n=== Testing Comments ===");
            match client.files().get_comments_with_limit(file_hash, 5).await {
                Ok(comments) => {
                    println!("✓ Retrieved {} comments", comments.data.len());
                    for (i, comment) in comments.data.iter().take(3).enumerate() {
                        println!(
                            "  Comment {}: {}",
                            i + 1,
                            comment
                                .object
                                .attributes
                                .text
                                .chars()
                                .take(100)
                                .collect::<String>()
                        );
                    }
                }
                Err(e) => println!("  No comments or error: {}", e),
            }

            // Test getting votes
            println!("\n=== Testing Votes ===");
            match client.files().get_votes(file_hash).await {
                Ok(votes) => {
                    println!("✓ Retrieved {} votes", votes.data.len());
                    for (i, vote) in votes.data.iter().take(3).enumerate() {
                        println!("  Vote {}: {:?}", i + 1, vote.object.attributes.verdict);
                    }
                }
                Err(e) => println!("  No votes or error: {}", e),
            }

            // Test relationships
            println!("\n=== Testing Relationships ===");

            // Contacted domains
            match client.files().get_contacted_domains(file_hash).await {
                Ok(domains) => {
                    println!("✓ Contacted domains: {} found", domains.data.len());
                    for (i, domain) in domains.data.iter().take(3).enumerate() {
                        if let Some(id) = domain.get("id").and_then(|v| v.as_str()) {
                            println!("  Domain {}: {}", i + 1, id);
                        }
                    }
                }
                Err(e) => println!("  No contacted domains or error: {}", e),
            }

            // Similar files
            match client.files().get_similar_files(file_hash).await {
                Ok(similar) => {
                    println!("✓ Similar files: {} found", similar.data.len());
                }
                Err(e) => println!("  No similar files or error: {}", e),
            }

            println!("\n=== All tests completed successfully! ===");
        }
        Err(e) => {
            eprintln!("Error fetching file: {}", e);
            eprintln!("Make sure your API key is valid and has access to this file");
        }
    }

    Ok(())
}
