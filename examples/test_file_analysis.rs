use std::env;
use std::time::Duration;
use tokio::time::sleep;
use virustotal_rs::{ApiTier, Client, ClientBuilder};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let api_key = env::var("VTI_API_KEY").expect("VTI_API_KEY environment variable not set");
    println!("Using API key from VTI_API_KEY environment variable");

    let client = ClientBuilder::new()
        .api_key(api_key)
        .tier(ApiTier::Public)
        .build()?;

    let file_hash = "02032ea322036e66f2825a0342979ad942ad5e201a674dc1c0085617467d661c";
    request_and_check_analysis(&client, file_hash).await?;
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
                println!("\n  Analysis Stats:");
                println!("    Harmless: {}", stats.harmless);
                println!("    Malicious: {}", stats.malicious);
                println!("    Suspicious: {}", stats.suspicious);
                println!("    Undetected: {}", stats.undetected);
                println!("    Timeout: {}", stats.timeout);
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
