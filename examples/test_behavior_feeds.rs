use virustotal_rs::{ApiTier, BehaviorFeedItem, ClientBuilder, FeedsClient};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // NOTE: Sandbox feeds require a Sandbox feeds license
    let api_key = std::env::var("VT_SANDBOX_API_KEY")
        .or_else(|_| std::env::var("VT_API_KEY"))
        .unwrap_or_else(|_| "test_key".to_string());

    let client = ClientBuilder::new()
        .api_key(api_key)
        .tier(ApiTier::Premium)
        .build()?;

    println!("Testing VirusTotal Sandbox Analyses (Behavior) Feeds");
    println!("=====================================================");
    println!("🔬 NOTE: Requires Sandbox feeds license");
    println!("=====================================================\n");

    let feeds = client.feeds();

    // 1. Get latest available behavior feed time
    println!("1. LATEST AVAILABLE BEHAVIOR FEEDS");
    println!("-----------------------------------");

    let latest_minute = FeedsClient::get_latest_available_time(false);
    let latest_hour = FeedsClient::get_latest_available_time(true);

    println!(
        "Latest available per-minute behavior feed: {}",
        latest_minute
    );
    println!("Latest available hourly behavior feed: {}", latest_hour);
    println!("  (60-minute lag for per-minute, 2-hour lag for hourly)");

    // 2. Download a per-minute behavior feed batch
    println!("\n2. PER-MINUTE BEHAVIOR FEED BATCH");
    println!("----------------------------------");

    let feed_time = "202312010802"; // December 1, 2023 08:02 UTC

    println!("Downloading behavior feed for: {}", feed_time);

    match feeds.get_file_behaviour_feed_batch(feed_time).await {
        Ok(batch_data) => {
            println!("✓ Downloaded behavior batch: {} bytes", batch_data.len());
            println!("  Contains sandbox analysis reports in bzip2 format");

            // Save for inspection
            let filename = format!("behavior_feed_{}.bz2", feed_time);
            std::fs::write(&filename, &batch_data)?;
            println!("  Saved to: {}", filename);

            // Example of processing behavior feed items
            // In production, decompress and parse each line
            /*
            use bzip2::read::BzDecoder;
            use std::io::BufRead;

            let decoder = BzDecoder::new(&batch_data[..]);
            let reader = std::io::BufReader::new(decoder);

            for line in reader.lines() {
                if let Ok(line) = line {
                    if let Ok(item) = feeds.parse_behaviour_feed_line(&line) {
                        println!("\n  Behavior ID: {}", item.id);
                        println!("  Type: {}", item.object_type);

                        // Check for artifact download URLs
                        if let Some(evtx_url) = &item.context_attributes.evtx {
                            println!("  EVTX available: {}", evtx_url);

                            // Extract token and download
                            if let Some(token) = BehaviorFeedItem::extract_token(evtx_url) {
                                let evtx_data = feeds.download_behaviour_evtx(&token).await?;
                                println!("    Downloaded EVTX: {} bytes", evtx_data.len());
                            }
                        }

                        if let Some(pcap_url) = &item.context_attributes.pcap {
                            println!("  PCAP available: {}", pcap_url);
                        }

                        if let Some(html_url) = &item.context_attributes.html_report {
                            println!("  HTML report available: {}", html_url);
                        }

                        if let Some(memdump_url) = &item.context_attributes.memdump {
                            println!("  Memory dump available: {}", memdump_url);
                        }
                    }
                }
            }
            */
        }
        Err(e) => {
            println!("✗ Error downloading behavior feed: {}", e);
            println!("  Note: Requires Sandbox feeds license");
        }
    }

    // 3. Download hourly behavior feed batch
    println!("\n3. HOURLY BEHAVIOR FEED BATCH");
    println!("------------------------------");

    let hourly_time = "2023120108"; // December 1, 2023 08:00-08:59 UTC

    match feeds
        .get_hourly_file_behaviour_feed_batch(hourly_time)
        .await
    {
        Ok(batch_data) => {
            println!(
                "✓ Downloaded hourly behavior batch: {} bytes",
                batch_data.len()
            );
            println!("  Contains 60 per-minute behavior feeds in .tar.bz2 format");

            let filename = format!("behavior_feed_hourly_{}.tar.bz2", hourly_time);
            std::fs::write(&filename, &batch_data)?;
            println!("  Saved to: {}", filename);
        }
        Err(e) => {
            println!("✗ Error downloading hourly behavior feed: {}", e);
        }
    }

    // 4. Parse example behavior feed line
    println!("\n4. PARSE BEHAVIOR FEED LINE");
    println!("----------------------------");

    let example_line = r#"{
        "id": "abc123_cape",
        "type": "file_behaviour",
        "attributes": {
            "sandbox_name": "cape",
            "analysis_date": 1234567890,
            "verdict": "malicious"
        },
        "context_attributes": {
            "file_md5": "d41d8cd98f00b204e9800998ecf8427e",
            "file_sha1": "da39a3ee5e6b4b0d3255bfef95601890afd80709",
            "file_type_tag": "exe",
            "html_report": "https://www.virustotal.com/api/v3/feeds/file_behaviours/TOKEN123/html",
            "pcap": "https://www.virustotal.com/api/v3/feeds/file_behaviours/TOKEN123/pcap",
            "evtx": "https://www.virustotal.com/api/v3/feeds/file_behaviours/TOKEN123/evtx",
            "memdump": "https://www.virustotal.com/api/v3/feeds/file_behaviours/TOKEN123/memdump"
        }
    }"#;

    println!("Parsing example behavior feed line...");

    match feeds.parse_behaviour_feed_line(example_line) {
        Ok(item) => {
            println!("✓ Parsed successfully:");
            println!("  ID: {}", item.id);
            println!("  Type: {}", item.object_type);

            if let Some(md5) = &item.context_attributes.file_md5 {
                println!("  File MD5: {}", md5);
            }

            if let Some(sha1) = &item.context_attributes.file_sha1 {
                println!("  File SHA1: {}", sha1);
            }

            if let Some(file_type) = &item.context_attributes.file_type_tag {
                println!("  File type: {}", file_type);
            }

            // Extract tokens from artifact URLs
            if let Some(evtx_url) = &item.context_attributes.evtx {
                if let Some(token) = BehaviorFeedItem::extract_token(evtx_url) {
                    println!("  EVTX token: {}", token);
                }
            }

            if let Some(pcap_url) = &item.context_attributes.pcap {
                if let Some(token) = BehaviorFeedItem::extract_token(pcap_url) {
                    println!("  PCAP token: {}", token);
                }
            }

            if let Some(html_url) = &item.context_attributes.html_report {
                if let Some(token) = BehaviorFeedItem::extract_token(html_url) {
                    println!("  HTML report token: {}", token);
                }
            }

            if let Some(memdump_url) = &item.context_attributes.memdump {
                if let Some(token) = BehaviorFeedItem::extract_token(memdump_url) {
                    println!("  Memory dump token: {}", token);
                }
            }
        }
        Err(e) => {
            println!("✗ Error parsing line: {}", e);
        }
    }

    // 5. Download behavior artifacts (using example tokens)
    println!("\n5. DOWNLOAD BEHAVIOR ARTIFACTS");
    println!("-------------------------------");

    let example_token = "TOKEN123_from_feed";

    println!(
        "Attempting to download artifacts with token: {}",
        example_token
    );

    // Download EVTX
    println!("\nDownloading EVTX (Windows Event Log)...");
    match feeds.download_behaviour_evtx(example_token).await {
        Ok(evtx_data) => {
            println!("✓ Downloaded EVTX: {} bytes", evtx_data.len());

            let filename = format!("behavior_{}_events.evtx", example_token);
            std::fs::write(&filename, &evtx_data)?;
            println!("  Saved to: {}", filename);
        }
        Err(e) => {
            println!("✗ Error downloading EVTX: {}", e);
            println!("  Note: Requires valid token from behavior feed");
        }
    }

    // Download PCAP
    println!("\nDownloading PCAP (network capture)...");
    match feeds.download_behaviour_pcap(example_token).await {
        Ok(pcap_data) => {
            println!("✓ Downloaded PCAP: {} bytes", pcap_data.len());

            let filename = format!("behavior_{}_network.pcap", example_token);
            std::fs::write(&filename, &pcap_data)?;
            println!("  Saved to: {}", filename);
        }
        Err(e) => {
            println!("✗ Error downloading PCAP: {}", e);
        }
    }

    // Download HTML report
    println!("\nDownloading HTML report...");
    match feeds.download_behaviour_html(example_token).await {
        Ok(html_data) => {
            println!("✓ Downloaded HTML report: {} bytes", html_data.len());

            let filename = format!("behavior_{}_report.html", example_token);
            std::fs::write(&filename, &html_data)?;
            println!("  Saved to: {}", filename);
        }
        Err(e) => {
            println!("✗ Error downloading HTML report: {}", e);
        }
    }

    // Download memory dump
    println!("\nDownloading memory dump...");
    match feeds.download_behaviour_memdump(example_token).await {
        Ok(memdump_data) => {
            println!("✓ Downloaded memory dump: {} bytes", memdump_data.len());

            let filename = format!("behavior_{}_memory.dmp", example_token);
            std::fs::write(&filename, &memdump_data)?;
            println!("  Saved to: {}", filename);
        }
        Err(e) => {
            println!("✗ Error downloading memory dump: {}", e);
        }
    }

    // 6. Test deprecated methods (backward compatibility)
    println!("\n6. BACKWARD COMPATIBILITY");
    println!("-------------------------");

    println!("Testing deprecated method names...");

    #[allow(deprecated)]
    match feeds.get_sandbox_feed_batch(feed_time).await {
        Ok(data) => {
            println!("✓ Deprecated get_sandbox_feed_batch still works");
            println!("  Returns: {} bytes", data.len());
        }
        Err(e) => {
            println!("  Error: {}", e);
        }
    }

    #[allow(deprecated)]
    match feeds.get_hourly_sandbox_feed_batch(hourly_time).await {
        Ok(data) => {
            println!("✓ Deprecated get_hourly_sandbox_feed_batch still works");
            println!("  Returns: {} bytes", data.len());
        }
        Err(e) => {
            println!("  Error: {}", e);
        }
    }

    // 7. Generate time ranges for behavior feeds
    println!("\n7. TIME RANGE FOR BATCH PROCESSING");
    println!("-----------------------------------");

    let start = "202312010800";
    let end = "202312010805";

    let time_range = FeedsClient::get_time_range(start, end, false);

    println!("Behavior feed times from {} to {}:", start, end);
    for time in &time_range {
        println!("  - {}", time);
    }

    println!("\nTo process multiple batches:");
    println!("  1. Generate time range");
    println!("  2. Download each batch");
    println!("  3. Decompress and parse");
    println!("  4. Extract artifact tokens");
    println!("  5. Download desired artifacts");

    // 8. Important notes
    println!("\n8. IMPORTANT NOTES");
    println!("------------------");

    println!("🔬 Sandbox Analyses Feed:");
    println!("  - Contains detailed behavior reports from sandboxes");
    println!("  - Each line is a FileBehaviour object");
    println!("  - Includes context_attributes with artifact URLs");
    println!("  - Requires Sandbox feeds license");

    println!("\n📦 Artifacts Available:");
    println!("  - EVTX: Windows Event Log files");
    println!("  - PCAP: Network packet captures");
    println!("  - HTML: Detailed analysis reports");
    println!("  - Memory dump: Process memory snapshots");

    println!("\n⏱️ Feed Availability:");
    println!("  - Per-minute: 60-minute lag");
    println!("  - Hourly: 2-hour lag");
    println!("  - 7-day retention period");

    println!("\n🔗 Download URLs:");
    println!("  - Found in context_attributes");
    println!("  - Extract token from URL path");
    println!("  - Use specific download methods for each artifact type");
    println!("  - Links expire after 7 days");

    println!("\n📝 Processing Tips:");
    println!("  - Decompress bzip2 data before parsing");
    println!("  - Each line is a separate JSON object");
    println!("  - Handle missing batches gracefully (404s are normal)");
    println!("  - Implement retry logic for reliability");

    println!("\n=====================================================");
    println!("Sandbox Analyses Feed Testing Complete!");
    println!("\nNOTE: All operations require a Sandbox feeds license.");
    println!("Without proper privileges, operations will fail.");

    Ok(())
}
