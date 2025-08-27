#[allow(unused_imports)]
use std::io::Write;
use virustotal_rs::{ApiTier, ClientBuilder, FeedConfig, FeedsClient};

/// Print feed time breakdown
fn print_feed_time_info(feed_time: &str) {
    println!("Downloading file feed for: {}", feed_time);
    println!("  Year: {}", &feed_time[0..4]);
    println!("  Month: {}", &feed_time[4..6]);
    println!("  Day: {}", &feed_time[6..8]);
    println!("  Hour: {}", &feed_time[8..10]);
    println!("  Minute: {}", &feed_time[10..12]);
}

/// Save data to file and print confirmation
fn save_file(filename: &str, data: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    std::fs::write(filename, data)?;
    println!("  Saved to: {}", filename);
    Ok(())
}

/// Download per-minute file feed batch
async fn demo_per_minute_feed(
    feeds: &FeedsClient,
    feed_time: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    println!("\n2. PER-MINUTE FILE FEED BATCH");
    println!("------------------------------");

    print_feed_time_info(feed_time);

    match feeds.get_file_feed_batch(feed_time).await {
        Ok(batch_data) => {
            println!("✓ Downloaded batch: {} bytes", batch_data.len());
            let filename = format!("feed_{}.bz2", feed_time);
            save_file(&filename, &batch_data)?;
        }
        Err(e) => {
            println!("✗ Error downloading batch: {}", e);
            println!("  Note: Requires File feeds license");
            println!("  404 errors for missing batches are normal (rare)");
        }
    }
    Ok(())
}

/// Download hourly file feed batch
async fn demo_hourly_feed(
    feeds: &FeedsClient,
    hourly_time: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    println!("\n3. HOURLY FILE FEED BATCH");
    println!("-------------------------");

    println!("Downloading hourly feed for: {}", hourly_time);

    match feeds.get_hourly_file_feed_batch(hourly_time).await {
        Ok(batch_data) => {
            println!("✓ Downloaded hourly batch: {} bytes", batch_data.len());
            println!("  Contains 60 per-minute feeds in .tar.bz2 format");
            let filename = format!("feed_hourly_{}.tar.bz2", hourly_time);
            save_file(&filename, &batch_data)?;
        }
        Err(e) => {
            println!("✗ Error downloading hourly batch: {}", e);
        }
    }
    Ok(())
}

/// Download file from feed using token
async fn demo_file_download(
    feeds: &FeedsClient,
    token: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    println!("\n4. DOWNLOAD FILE FROM FEED");
    println!("--------------------------");

    println!("Attempting to download file with token: {}", token);

    match feeds.download_feed_file(token).await {
        Ok(file_data) => {
            println!("✓ Downloaded file: {} bytes", file_data.len());
            let filename = format!("downloaded_file_{}.bin", token);
            save_file(&filename, &file_data)?;
        }
        Err(e) => {
            println!("✗ Error downloading file: {}", e);
            println!("  Note: Requires valid token from feed");
            println!("  Links expire after 7 days");
        }
    }
    Ok(())
}

/// Download sandbox feed batch
async fn demo_sandbox_feed(
    feeds: &FeedsClient,
    feed_time: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    println!("\n5. SANDBOX ANALYSES FEED");
    println!("------------------------");

    println!("Downloading sandbox feed for: {}", feed_time);

    #[allow(deprecated)]
    match feeds.get_sandbox_feed_batch(feed_time).await {
        Ok(batch_data) => {
            println!("✓ Downloaded sandbox batch: {} bytes", batch_data.len());
            println!("  Contains behavior reports in bzip2 format");
            let filename = format!("sandbox_feed_{}.bz2", feed_time);
            save_file(&filename, &batch_data)?;
        }
        Err(e) => {
            println!("✗ Error downloading sandbox feed: {}", e);
            println!("  Note: Requires Sandbox feeds license");
        }
    }
    Ok(())
}

/// Demo time range generation
fn demo_time_ranges() {
    println!("\n6. TIME RANGE GENERATION");
    println!("------------------------");

    let start_time = "202312010800";
    let end_time = "202312010805";
    let time_range = FeedsClient::get_time_range(start_time, end_time, false);

    println!("Time range from {} to {}:", start_time, end_time);
    for time in &time_range {
        println!("  - {}", time);
    }
}

/// Attempt to download a batch with retry logic
async fn fetch_batch_with_retry(
    feeds: &FeedsClient,
    time: &str,
    config: &FeedConfig,
    consecutive_missing: &mut u32,
) -> bool {
    println!("\nFetching batch: {}", time);

    let mut retries = 0;
    loop {
        match feeds.get_file_feed_batch(time).await {
            Ok(data) => {
                println!("  ✓ Success: {} bytes", data.len());
                *consecutive_missing = 0;
                return true;
            }
            Err(e) => {
                if e.to_string().contains("404") {
                    *consecutive_missing += 1;
                    println!("  ⚠️ Missing batch (404) - #{}", consecutive_missing);

                    if *consecutive_missing >= config.max_consecutive_missing {
                        println!("  ✗ Too many consecutive missing batches");
                        return false;
                    }

                    if config.skip_missing {
                        return true; // Skip to next batch
                    }
                }

                retries += 1;
                if retries >= config.max_retries {
                    println!("  ✗ Max retries reached");
                    return false;
                }

                println!("  Retry {} of {}...", retries, config.max_retries);
                tokio::time::sleep(tokio::time::Duration::from_secs(config.retry_delay_secs)).await;
            }
        }
    }
}

/// Demo batch download with retry logic
async fn demo_batch_retry(feeds: &FeedsClient) {
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
        if !fetch_batch_with_retry(feeds, time, &config, &mut consecutive_missing).await {
            break;
        }
    }
}

/// Demo feed line parsing
fn demo_feed_parsing(feeds: &FeedsClient) {
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
}

/// Print important notes and information
fn print_important_notes() {
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
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize client
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

    // 1. Show latest available feeds
    println!("1. LATEST AVAILABLE FEEDS");
    println!("-------------------------");
    let latest_minute = FeedsClient::get_latest_available_time(false);
    let latest_hour = FeedsClient::get_latest_available_time(true);
    println!("Latest available per-minute feed: {}", latest_minute);
    println!("Latest available hourly feed: {}", latest_hour);
    println!("  (60-minute lag for per-minute, 2-hour lag for hourly)");

    // Run all demos
    let feed_time = "202312010802";
    let hourly_time = "2023120108";
    let example_token = "abc123token_from_feed";

    demo_per_minute_feed(&feeds, feed_time).await?;
    demo_hourly_feed(&feeds, hourly_time).await?;
    demo_file_download(&feeds, example_token).await?;
    demo_sandbox_feed(&feeds, feed_time).await?;
    demo_time_ranges();
    demo_batch_retry(&feeds).await;
    demo_feed_parsing(&feeds);
    print_important_notes();

    Ok(())
}
