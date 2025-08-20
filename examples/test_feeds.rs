#[allow(unused_imports)]
use std::io::Write;
use virustotal_rs::{ApiTier, ClientBuilder, FeedConfig, FeedsClient};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // NOTE: File feeds require a File feeds license
    // Sandbox feeds require a Sandbox feeds license
    let api_key = std::env::var("VT_FEEDS_API_KEY")
        .or_else(|_| std::env::var("VT_API_KEY"))
        .unwrap_or_else(|_| "test_key".to_string());

    let client = ClientBuilder::new()
        .api_key(api_key)
        .tier(ApiTier::Premium)
        .build()?;

    println!("Testing VirusTotal File Intelligence Feeds");
    println!("==========================================");
    println!("🚧 NOTE: Requires File feeds or Sandbox feeds license");
    println!("==========================================\n");

    let feeds = client.feeds();

    // 1. Get the latest available feed time
    println!("1. LATEST AVAILABLE FEEDS");
    println!("-------------------------");

    let latest_minute = FeedsClient::get_latest_available_time(false);
    let latest_hour = FeedsClient::get_latest_available_time(true);

    println!("Latest available per-minute feed: {}", latest_minute);
    println!("Latest available hourly feed: {}", latest_hour);
    println!("  (60-minute lag for per-minute, 2-hour lag for hourly)");

    // 2. Download a per-minute file feed batch
    println!("\n2. PER-MINUTE FILE FEED BATCH");
    println!("------------------------------");

    // Use a specific time or the latest available
    let feed_time = "202312010802"; // December 1, 2023 08:02 UTC

    println!("Downloading file feed for: {}", feed_time);
    println!("  Year: {}", &feed_time[0..4]);
    println!("  Month: {}", &feed_time[4..6]);
    println!("  Day: {}", &feed_time[6..8]);
    println!("  Hour: {}", &feed_time[8..10]);
    println!("  Minute: {}", &feed_time[10..12]);

    match feeds.get_file_feed_batch(feed_time).await {
        Ok(batch_data) => {
            println!("✓ Downloaded batch: {} bytes", batch_data.len());

            // In production, you would:
            // 1. Decompress the bzip2 data
            // 2. Parse each line as JSON
            // 3. Process the feed items

            // Save to file for inspection
            let filename = format!("feed_{}.bz2", feed_time);
            std::fs::write(&filename, &batch_data)?;
            println!("  Saved to: {}", filename);

            // Example of how to process (requires bzip2 decompression)
            /*
            use bzip2::read::BzDecoder;
            use std::io::BufRead;

            let decoder = BzDecoder::new(&batch_data[..]);
            let reader = std::io::BufReader::new(decoder);

            for line in reader.lines() {
                if let Ok(line) = line {
                    if let Ok(item) = feeds.parse_feed_line(&line) {
                        println!("  File ID: {}", item.id);
                        if let Some(url) = &item.download_url {
                            println!("    Download: {}", url);
                        }
                    }
                }
            }
            */
        }
        Err(e) => {
            println!("✗ Error downloading batch: {}", e);
            println!("  Note: Requires File feeds license");
            println!("  404 errors for missing batches are normal (rare)");
        }
    }

    // 3. Download an hourly file feed batch
    println!("\n3. HOURLY FILE FEED BATCH");
    println!("-------------------------");

    let hourly_time = "2023120108"; // December 1, 2023 08:00-08:59 UTC

    println!("Downloading hourly feed for: {}", hourly_time);

    match feeds.get_hourly_file_feed_batch(hourly_time).await {
        Ok(batch_data) => {
            println!("✓ Downloaded hourly batch: {} bytes", batch_data.len());
            println!("  Contains 60 per-minute feeds in .tar.bz2 format");

            // Save for inspection
            let filename = format!("feed_hourly_{}.tar.bz2", hourly_time);
            std::fs::write(&filename, &batch_data)?;
            println!("  Saved to: {}", filename);
        }
        Err(e) => {
            println!("✗ Error downloading hourly batch: {}", e);
        }
    }

    // 4. Download a file from the feed
    println!("\n4. DOWNLOAD FILE FROM FEED");
    println!("--------------------------");

    // This token would come from the download_url in a feed item
    let example_token = "abc123token_from_feed";

    println!("Attempting to download file with token: {}", example_token);

    match feeds.download_feed_file(example_token).await {
        Ok(file_data) => {
            println!("✓ Downloaded file: {} bytes", file_data.len());

            // Save the file
            let filename = format!("downloaded_file_{}.bin", example_token);
            std::fs::write(&filename, &file_data)?;
            println!("  Saved to: {}", filename);
        }
        Err(e) => {
            println!("✗ Error downloading file: {}", e);
            println!("  Note: Requires valid token from feed");
            println!("  Links expire after 7 days");
        }
    }

    // 5. Sandbox analyses feed
    println!("\n5. SANDBOX ANALYSES FEED");
    println!("------------------------");

    println!("Downloading sandbox feed for: {}", feed_time);

    #[allow(deprecated)]
    match feeds.get_sandbox_feed_batch(feed_time).await {
        Ok(batch_data) => {
            println!("✓ Downloaded sandbox batch: {} bytes", batch_data.len());
            println!("  Contains behavior reports in bzip2 format");

            let filename = format!("sandbox_feed_{}.bz2", feed_time);
            std::fs::write(&filename, &batch_data)?;
            println!("  Saved to: {}", filename);
        }
        Err(e) => {
            println!("✗ Error downloading sandbox feed: {}", e);
            println!("  Note: Requires Sandbox feeds license");
        }
    }

    // 6. Generate time ranges for batch processing
    println!("\n6. TIME RANGE GENERATION");
    println!("------------------------");

    let start_time = "202312010800";
    let end_time = "202312010805";

    let time_range = FeedsClient::get_time_range(start_time, end_time, false);

    println!("Time range from {} to {}:", start_time, end_time);
    for time in &time_range {
        println!("  - {}", time);
    }

    // 7. Batch download with retry logic
    println!("\n7. BATCH DOWNLOAD WITH RETRY");
    println!("-----------------------------");

    let config = FeedConfig::default();

    println!("Feed processing configuration:");
    println!("  Max retries: {}", config.max_retries);
    println!("  Retry delay: {} seconds", config.retry_delay_secs);
    println!("  Skip missing: {}", config.skip_missing);
    println!(
        "  Max consecutive missing: {}",
        config.max_consecutive_missing
    );

    let mut consecutive_missing = 0;
    let times_to_fetch = vec!["202312010800", "202312010801", "202312010802"];

    for time in &times_to_fetch {
        println!("\nFetching batch: {}", time);

        let mut retries = 0;
        loop {
            match feeds.get_file_feed_batch(time).await {
                Ok(data) => {
                    println!("  ✓ Success: {} bytes", data.len());
                    consecutive_missing = 0;
                    break;
                }
                Err(e) => {
                    if e.to_string().contains("404") {
                        consecutive_missing += 1;
                        println!("  ⚠️ Missing batch (404) - #{}", consecutive_missing);

                        if consecutive_missing >= config.max_consecutive_missing {
                            println!("  ✗ Too many consecutive missing batches");
                            break;
                        }

                        if config.skip_missing {
                            break; // Skip to next batch
                        }
                    }

                    retries += 1;
                    if retries >= config.max_retries {
                        println!("  ✗ Max retries reached");
                        break;
                    }

                    println!("  Retry {} of {}...", retries, config.max_retries);
                    tokio::time::sleep(tokio::time::Duration::from_secs(config.retry_delay_secs))
                        .await;
                }
            }
        }
    }

    // 8. Parse feed line example
    println!("\n8. PARSE FEED LINE");
    println!("------------------");

    let example_line = r#"{"id":"abc123","type":"file","attributes":{"sha256":"def456","size":1024},"download_url":"https://example.com/download/token123","submitter":{"country":"US","method":"api"}}"#;

    println!("Parsing example feed line...");

    match feeds.parse_feed_line(example_line) {
        Ok(item) => {
            println!("✓ Parsed successfully:");
            println!("  ID: {}", item.id);
            println!("  Type: {}", item.object_type);

            if let Some(url) = &item.download_url {
                println!("  Download URL: {}", url);
            }

            if let Some(submitter) = &item.submitter {
                if let Some(country) = &submitter.country {
                    println!("  Submitter country: {}", country);
                }
                if let Some(method) = &submitter.method {
                    println!("  Submission method: {}", method);
                }
            }
        }
        Err(e) => {
            println!("✗ Error parsing line: {}", e);
        }
    }

    // 9. Important notes
    println!("\n9. IMPORTANT NOTES");
    println!("------------------");

    println!("📊 File Intelligence Feed:");
    println!("  - Continuous real-time stream of file analyses");
    println!("  - One JSON per line in bzip2 compressed batches");
    println!("  - New batch every minute");
    println!("  - 60-minute lag for latest data");
    println!("  - 7-day retention");

    println!("\n🔬 Sandbox Analyses Feed:");
    println!("  - Behavior reports for uploaded files");
    println!("  - Similar structure to file feeds");
    println!("  - Requires separate Sandbox feeds license");

    println!("\n⏱️ Time Formats:");
    println!("  - Per-minute: YYYYMMDDhhmm (e.g., 202312010802)");
    println!("  - Hourly: YYYYMMDDhh (e.g., 2023120108)");

    println!("\n⚠️ Missing Batches:");
    println!("  - 404 errors are rare but normal");
    println!("  - Multiple consecutive 404s indicate a problem");
    println!("  - Client code should handle gracefully");

    println!("\n📥 Download Links:");
    println!("  - Valid for 7 days (feed lifetime)");
    println!("  - Found in download_url attribute");
    println!("  - Requires download file privilege");

    println!("\n==========================================");
    println!("File Intelligence Feeds Testing Complete!");
    println!("\nNOTE: All operations require appropriate licenses:");
    println!("  - File feeds license for file feed endpoints");
    println!("  - Sandbox feeds license for behavior feed endpoints");
    println!("  - Download privilege for file downloads");

    Ok(())
}
