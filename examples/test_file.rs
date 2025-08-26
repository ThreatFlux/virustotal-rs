use virustotal_rs::{ApiTier, Client, File};
#[path = "common/mod.rs"]
mod common;
use common::{build_client_from_env, print_analysis_stats, SAMPLE_FILE_HASH};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = build_client_from_env("VTI_API_KEY", ApiTier::Public)?;
    run_workflow(&client, SAMPLE_FILE_HASH).await?;
    Ok(())
}

async fn run_workflow(client: &Client, file_hash: &str) -> Result<(), Box<dyn std::error::Error>> {
    println!("\n=== Testing File API ===");
    println!("Fetching file: {}", file_hash);

    match client.files().get(file_hash).await {
        Ok(file) => {
            print_file_info(&file);
            show_comments(client, file_hash).await?;
            show_votes(client, file_hash).await?;
            show_relationships(client, file_hash).await?;
            println!("\n=== All tests completed successfully! ===");
        }
        Err(e) => {
            eprintln!("Error fetching file: {}", e);
            eprintln!("Make sure your API key is valid and has access to this file");
        }
    }

    Ok(())
}

fn print_file_info(file: &File) {
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
        print_analysis_stats("Last Analysis Stats", stats);
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
}

async fn show_comments(client: &Client, file_hash: &str) -> Result<(), Box<dyn std::error::Error>> {
    println!("\n=== Testing Comments ===");
    match client.files().get_comments_with_limit(file_hash, 5).await {
        Ok(comments) => {
            println!("✓ Retrieved {} comments", comments.data.len());
            for (i, comment) in comments.data.iter().take(3).enumerate() {
                let snippet: String = comment.object.attributes.text.chars().take(100).collect();
                println!("  Comment {}: {}", i + 1, snippet);
            }
        }
        Err(e) => println!("  No comments or error: {}", e),
    }
    Ok(())
}

async fn show_votes(client: &Client, file_hash: &str) -> Result<(), Box<dyn std::error::Error>> {
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
    Ok(())
}

async fn show_relationships(
    client: &Client,
    file_hash: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    println!("\n=== Testing Relationships ===");

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

    match client.files().get_similar_files(file_hash).await {
        Ok(similar) => println!("✓ Similar files: {} found", similar.data.len()),
        Err(e) => println!("  No similar files or error: {}", e),
    }

    Ok(())
}
