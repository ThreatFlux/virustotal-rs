use virustotal_rs::{ApiTier, ClientBuilder, FeedsClient};

/// Initialize client with API key from environment
fn initialize_client() -> Result<virustotal_rs::Client, Box<dyn std::error::Error>> {
    let api_key = std::env::var("VT_FEEDS_API_KEY")
        .or_else(|_| std::env::var("VT_API_KEY"))
        .unwrap_or_else(|_| "test_key".to_string());

    let client = ClientBuilder::new()
        .api_key(api_key)
        .tier(ApiTier::Premium)
        .build()?;

    Ok(client)
}

/// Print introduction and feed information
fn print_introduction() {
    println!("Testing VirusTotal Domain, IP, and URL Intelligence Feeds");
    println!("========================================================");
    println!("🔒 NOTE: Each feed type requires its specific license:");
    println!("   - Domain feeds: Domain feeds license");
    println!("   - IP feeds: IP feeds license");
    println!("   - URL feeds: URL feeds license");
    println!("========================================================\n");
}

/// Print latest available feed times
fn print_feed_times() {
    let latest_minute = FeedsClient::get_latest_available_time(false);
    let latest_hour = FeedsClient::get_latest_available_time(true);

    println!("Latest available per-minute feed: {}", latest_minute);
    println!("Latest available hourly feed: {}", latest_hour);
    println!("  (60-minute lag for per-minute, 2-hour lag for hourly)\n");
}

/// Test domain intelligence feeds
async fn test_domain_feeds(
    feeds: &virustotal_rs::FeedsClient,
    feed_time: &str,
    hourly_time: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    println!("1. DOMAIN INTELLIGENCE FEED");
    println!("---------------------------");

    println!("Downloading domain feed for: {}", feed_time);

    match feeds.get_domain_feed_batch(feed_time).await {
        Ok(batch_data) => {
            println!("✓ Downloaded domain batch: {} bytes", batch_data.len());
            println!("  Contains domain analysis reports in bzip2 format");

            // Save for inspection
            let filename = format!("domain_feed_{}.bz2", feed_time);
            std::fs::write(&filename, &batch_data)?;
            println!("  Saved to: {}", filename);
        }
        Err(e) => {
            println!("✗ Error downloading domain feed: {}", e);
            println!("  Note: Requires Domain feeds license");
        }
    }

    // Hourly domain feed
    println!("\nDownloading hourly domain feed for: {}", hourly_time);

    match feeds.get_hourly_domain_feed_batch(hourly_time).await {
        Ok(batch_data) => {
            println!(
                "✓ Downloaded hourly domain batch: {} bytes",
                batch_data.len()
            );
            println!("  Contains 60 per-minute domain feeds in .tar.bz2 format");

            let filename = format!("domain_feed_hourly_{}.tar.bz2", hourly_time);
            std::fs::write(&filename, &batch_data)?;
            println!("  Saved to: {}", filename);
        }
        Err(e) => {
            println!("✗ Error downloading hourly domain feed: {}", e);
        }
    }

    Ok(())
}

/// Test IP address intelligence feeds
async fn test_ip_feeds(
    feeds: &virustotal_rs::FeedsClient,
    feed_time: &str,
    hourly_time: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    println!("\n2. IP ADDRESS INTELLIGENCE FEED");
    println!("-------------------------------");

    println!("Downloading IP feed for: {}", feed_time);

    match feeds.get_ip_feed_batch(feed_time).await {
        Ok(batch_data) => {
            println!("✓ Downloaded IP batch: {} bytes", batch_data.len());
            println!("  Contains IP address analysis reports in bzip2 format");

            // Save for inspection
            let filename = format!("ip_feed_{}.bz2", feed_time);
            std::fs::write(&filename, &batch_data)?;
            println!("  Saved to: {}", filename);
        }
        Err(e) => {
            println!("✗ Error downloading IP feed: {}", e);
            println!("  Note: Requires IP feeds license");
        }
    }

    // Hourly IP feed
    println!("\nDownloading hourly IP feed for: {}", hourly_time);

    match feeds.get_hourly_ip_feed_batch(hourly_time).await {
        Ok(batch_data) => {
            println!("✓ Downloaded hourly IP batch: {} bytes", batch_data.len());
            println!("  Contains 60 per-minute IP feeds in .tar.bz2 format");

            let filename = format!("ip_feed_hourly_{}.tar.bz2", hourly_time);
            std::fs::write(&filename, &batch_data)?;
            println!("  Saved to: {}", filename);
        }
        Err(e) => {
            println!("✗ Error downloading hourly IP feed: {}", e);
        }
    }

    Ok(())
}

/// Test URL intelligence feeds
async fn test_url_feeds(
    feeds: &virustotal_rs::FeedsClient,
    feed_time: &str,
    hourly_time: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    println!("\n3. URL INTELLIGENCE FEED");
    println!("------------------------");

    println!("Downloading URL feed for: {}", feed_time);

    match feeds.get_url_feed_batch(feed_time).await {
        Ok(batch_data) => {
            println!("✓ Downloaded URL batch: {} bytes", batch_data.len());
            println!("  Contains URL analysis reports in bzip2 format");
            println!("  Includes submitter information (lossy-ciphered)");

            // Save for inspection
            let filename = format!("url_feed_{}.bz2", feed_time);
            std::fs::write(&filename, &batch_data)?;
            println!("  Saved to: {}", filename);
        }
        Err(e) => {
            println!("✗ Error downloading URL feed: {}", e);
            println!("  Note: Requires URL feeds license");
        }
    }

    // Hourly URL feed
    println!("\nDownloading hourly URL feed for: {}", hourly_time);

    match feeds.get_hourly_url_feed_batch(hourly_time).await {
        Ok(batch_data) => {
            println!("✓ Downloaded hourly URL batch: {} bytes", batch_data.len());
            println!("  Contains 60 per-minute URL feeds in .tar.bz2 format");

            let filename = format!("url_feed_hourly_{}.tar.bz2", hourly_time);
            std::fs::write(&filename, &batch_data)?;
            println!("  Saved to: {}", filename);
        }
        Err(e) => {
            println!("✗ Error downloading hourly URL feed: {}", e);
        }
    }

    Ok(())
}

/// Test parsing example feed lines
fn test_feed_line_parsing(
    feeds: &virustotal_rs::FeedsClient,
) -> Result<(), Box<dyn std::error::Error>> {
    println!("\n4. PARSE EXAMPLE FEED LINES");
    println!("----------------------------");

    // Example domain feed line
    let domain_line = r#"{
        "id": "malicious.example.com",
        "type": "domain",
        "attributes": {
            "reputation": -50,
            "last_analysis_stats": {
                "malicious": 45,
                "suspicious": 10,
                "undetected": 25,
                "harmless": 3
            },
            "categories": {
                "Symantec": "malware"
            }
        }
    }"#;

    println!("Parsing example domain feed line...");
    match feeds.parse_domain_feed_line(domain_line) {
        Ok(item) => {
            println!("✓ Domain: {}", item.id);
            if let Some(reputation) = item.attributes.get("reputation") {
                println!("  Reputation: {}", reputation);
            }
        }
        Err(e) => println!("✗ Error parsing domain: {}", e),
    }

    // Example IP feed line
    let ip_line = r#"{
        "id": "203.0.113.42",
        "type": "ip_address",
        "attributes": {
            "country": "US",
            "as_owner": "Example Networks Inc.",
            "reputation": -10,
            "continent": "NA",
            "network": "203.0.113.0/24"
        }
    }"#;

    println!("\nParsing example IP feed line...");
    match feeds.parse_ip_feed_line(ip_line) {
        Ok(item) => {
            println!("✓ IP: {}", item.id);
            if let Some(country) = item.attributes.get("country") {
                println!("  Country: {}", country);
            }
            if let Some(as_owner) = item.attributes.get("as_owner") {
                println!("  AS Owner: {}", as_owner);
            }
        }
        Err(e) => println!("✗ Error parsing IP: {}", e),
    }

    // Example URL feed line with submitter
    let url_line = r#"{
        "id": "https://phishing.example.com/login",
        "type": "url",
        "attributes": {
            "last_final_url": "https://phishing.example.com/login",
            "title": "Fake Login Page",
            "last_analysis_stats": {
                "malicious": 55,
                "suspicious": 5,
                "undetected": 20,
                "harmless": 3
            }
        },
        "submitter": {
            "country": "GB",
            "method": "manual"
        }
    }"#;

    println!("\nParsing example URL feed line...");
    match feeds.parse_url_feed_line(url_line) {
        Ok(item) => {
            println!("✓ URL: {}", item.id);
            if let Some(title) = item.attributes.get("title") {
                println!("  Title: {}", title);
            }
            if let Some(submitter) = &item.submitter {
                println!("  Submitter:");
                if let Some(country) = &submitter.country {
                    println!("    Country: {}", country);
                }
                if let Some(method) = &submitter.method {
                    println!("    Method: {}", method);
                }
            }
        }
        Err(e) => println!("✗ Error parsing URL: {}", e),
    }

    Ok(())
}

/// Demonstrate time range generation
fn demonstrate_time_ranges() {
    println!("\n5. TIME RANGE GENERATION");
    println!("------------------------");

    let start = "202312010800";
    let end = "202312010805";

    let time_range = FeedsClient::get_time_range(start, end, false);

    println!("Feed times from {} to {}:", start, end);
    for time in &time_range {
        println!("  - {}", time);
    }

    println!("\nTo process multiple batches:");
    println!("  1. Generate time range for desired period");
    println!("  2. Download each batch (domain/IP/URL)");
    println!("  3. Decompress bzip2 data");
    println!("  4. Parse each line as JSON");
    println!("  5. Process according to your needs");
}

/// Print important notes about the feeds
fn print_important_notes() {
    println!("\n6. IMPORTANT NOTES");
    println!("------------------");

    println!("📊 Domain Intelligence Feed:");
    println!("  - Continuous stream of domain analyses");
    println!("  - Contains reputation, categories, DNS records");
    println!("  - Same structure as GET /domains/{{domain}}");
    println!("  - Requires Domain feeds license");

    println!("\n🌐 IP Intelligence Feed:");
    println!("  - Continuous stream of IP address analyses");
    println!("  - Contains geolocation, AS info, reputation");
    println!("  - Same structure as GET /ip_addresses/{{ip}}");
    println!("  - Requires IP feeds license");

    println!("\n🔗 URL Intelligence Feed:");
    println!("  - Continuous stream of URL analyses");
    println!("  - Includes submitter information (anonymized)");
    println!("  - Same structure as GET /urls/{{id}}");
    println!("  - Requires URL feeds license");

    println!("\n⏱️ Feed Characteristics:");
    println!("  - Format: bzip2 compressed, one JSON per line");
    println!("  - Per-minute: 60-minute lag, YYYYMMDDhhmm format");
    println!("  - Hourly: 2-hour lag, YYYYMMDDhh format");
    println!("  - Retention: 7 days for all feeds");
    println!("  - Missing batches: Rare but normal (404 errors)");

    println!("\n🔑 License Requirements:");
    println!("  - Each feed type requires its specific license");
    println!("  - Licenses are independent (can have domain but not IP)");
    println!("  - Contact VirusTotal for licensing information");

    println!("\n💡 Processing Tips:");
    println!("  - Use streaming decompression for large batches");
    println!("  - Implement retry logic for failed downloads");
    println!("  - Handle 404s gracefully (skip missing batches)");
    println!("  - Store processed data for historical analysis");
    println!("  - Monitor feed lag to ensure timely processing");
}

/// Print final completion message
fn print_completion_message() {
    println!("\n========================================================");
    println!("Domain, IP, and URL Intelligence Feeds Testing Complete!");
    println!("\nNOTE: All operations require appropriate feed licenses.");
    println!("Without proper privileges, operations will fail with 403/404 errors.");
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = initialize_client()?;
    let feeds = client.feeds();

    print_introduction();
    print_feed_times();

    // Example feed time
    let feed_time = "202312010802"; // December 1, 2023 08:02 UTC
    let hourly_time = "2023120108"; // December 1, 2023 08:00-08:59 UTC

    test_domain_feeds(&feeds, feed_time, hourly_time).await?;
    test_ip_feeds(&feeds, feed_time, hourly_time).await?;
    test_url_feeds(&feeds, feed_time, hourly_time).await?;
    test_feed_line_parsing(&feeds)?;
    demonstrate_time_ranges();
    print_important_notes();
    print_completion_message();

    Ok(())
}