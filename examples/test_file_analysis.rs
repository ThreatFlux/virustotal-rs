use std::time::Duration;
use tokio::time::sleep;
use virustotal_rs::{ApiTier, Client};
#[path = "common/mod.rs"]
mod common;
use common::{build_client_from_env, print_analysis_stats, SAMPLE_FILE_HASH};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = build_client_from_env("VTI_API_KEY", ApiTier::Public)?;
    request_and_check_analysis(&client, SAMPLE_FILE_HASH).await?;
    println!("\n=== Test completed ===");
    Ok(())
}

async fn request_and_check_analysis(
    client: &Client,
    file_hash: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    println!("\n=== Testing File Analysis (Rescan) ===");
    println!("Requesting analysis for file: {}", file_hash);

    match client.files().analyse(file_hash).await {
        Ok(analysis_response) => {
            println!("✓ Analysis request submitted successfully!");
            println!("  Analysis ID: {}", analysis_response.data.id);
            println!("  Type: {}", analysis_response.data.object_type);

            if let Some(links) = &analysis_response.data.links {
                println!("  Self link: {}", links.self_link);
            }

            println!("\nWaiting 5 seconds before checking analysis status...");
            sleep(Duration::from_secs(5)).await;
            fetch_analysis_details(client, &analysis_response.data.id).await?;
        }
        Err(e) => {
            println!("Error requesting analysis: {}", e);
            println!("Note: Rate limits may apply (4 requests/minute for public API)");
            if e.to_string().contains("204") || e.to_string().contains("quota") {
                println!("\n⚠ Rate limit reached. Public API allows:");
                println!("  - 4 requests per minute");
                println!("  - 500 requests per day");
                println!("  - 15,500 requests per month");
            }
        }
    }
    Ok(())
}

async fn fetch_analysis_details(
    client: &Client,
    analysis_id: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    println!("Fetching analysis details...");
    match client.files().get_analysis(analysis_id).await {
        Ok(analysis) => {
            println!("✓ Analysis details retrieved!");
            println!("  Status: {:?}", analysis.object.attributes.status);

            if let Some(stats) = &analysis.object.attributes.stats {
                print_analysis_stats("Analysis Stats", stats);
            }

            if let Some(results) = &analysis.object.attributes.results {
                let detected = results
                    .values()
                    .filter(|r| r.category == "malicious")
                    .count();
                println!("\n  Engines that detected threats: {}", detected);
            }
        }
        Err(e) => {
            println!("Could not retrieve analysis details: {}", e);
            println!("Note: Analysis might still be in progress");
        }
    }
    Ok(())
}
