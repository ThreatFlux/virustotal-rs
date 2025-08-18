use std::env;
use std::time::Duration;
use tokio::time::sleep;
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

    // Test file hash
    let file_hash = "02032ea322036e66f2825a0342979ad942ad5e201a674dc1c0085617467d661c";

    println!("\n=== Testing File Analysis (Rescan) ===");
    println!("Requesting analysis for file: {}", file_hash);

    // Request analysis (rescan)
    match client.files().analyse(file_hash).await {
        Ok(analysis_response) => {
            println!("✓ Analysis request submitted successfully!");
            println!("  Analysis ID: {}", analysis_response.data.id);
            println!("  Type: {}", analysis_response.data.object_type);

            if let Some(links) = &analysis_response.data.links {
                println!("  Self link: {}", links.self_link);
            }

            // Wait a bit and check analysis status
            println!("\nWaiting 5 seconds before checking analysis status...");
            sleep(Duration::from_secs(5)).await;

            println!("Fetching analysis details...");
            match client
                .files()
                .get_analysis(&analysis_response.data.id)
                .await
            {
                Ok(analysis) => {
                    println!("✓ Analysis details retrieved!");
                    println!("  Status: {:?}", analysis.object.attributes.status);

                    if let Some(stats) = &analysis.object.attributes.stats {
                        println!("\n  Analysis Stats:");
                        println!("    Harmless: {}", stats.harmless);
                        println!("    Malicious: {}", stats.malicious);
                        println!("    Suspicious: {}", stats.suspicious);
                        println!("    Undetected: {}", stats.undetected);
                        println!("    Timeout: {}", stats.timeout);
                    }

                    if let Some(results) = &analysis.object.attributes.results {
                        println!(
                            "\n  Engines that detected threats: {}",
                            results
                                .values()
                                .filter(|r| r.category == "malicious")
                                .count()
                        );
                    }
                }
                Err(e) => {
                    println!("Could not retrieve analysis details: {}", e);
                    println!("Note: Analysis might still be in progress");
                }
            }
        }
        Err(e) => {
            println!("Error requesting analysis: {}", e);
            println!("Note: Rate limits may apply (4 requests/minute for public API)");

            // Check if it's a rate limit error
            if e.to_string().contains("204") || e.to_string().contains("quota") {
                println!("\n⚠ Rate limit reached. Public API allows:");
                println!("  - 4 requests per minute");
                println!("  - 500 requests per day");
                println!("  - 15,500 requests per month");
            }
        }
    }

    println!("\n=== Test completed ===");

    Ok(())
}
