use virustotal_rs::{ApiTier, BehaviorFeedItem, ClientBuilder, FeedsClient};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = setup_client()?;
    print_header();

    let feeds = client.feeds();

    // Run all test scenarios
    test_latest_feed_times();
    test_per_minute_batch(&feeds).await?;
    test_hourly_batch(&feeds).await?;
    test_feed_parsing(&feeds);
    test_artifact_downloads(&feeds).await;
    test_deprecated_methods(&feeds).await;
    test_time_ranges();
    print_important_notes();

    Ok(())
}

/// Setup client with API key
fn setup_client() -> Result<virustotal_rs::Client, Box<dyn std::error::Error>> {
    let api_key = std::env::var("VT_SANDBOX_API_KEY")
        .or_else(|_| std::env::var("VT_API_KEY"))
        .unwrap_or_else(|_| "test_key".to_string());

    Ok(ClientBuilder::new()
        .api_key(api_key)
        .tier(ApiTier::Premium)
        .build()?)
}

/// Print application header
fn print_header() {
    println!("Testing VirusTotal Sandbox Analyses (Behavior) Feeds");
    println!("=====================================================");
    println!("🔬 NOTE: Requires Sandbox feeds license");
    println!("=====================================================\n");
}

/// Test latest available feed times
fn test_latest_feed_times() {
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
}

/// Test per-minute behavior feed batch download
async fn test_per_minute_batch(feeds: &FeedsClient) -> Result<(), Box<dyn std::error::Error>> {
    println!("\n2. PER-MINUTE BEHAVIOR FEED BATCH");
    println!("----------------------------------");

    let feed_time = "202312010802"; // December 1, 2023 08:02 UTC
    println!("Downloading behavior feed for: {}", feed_time);

    match download_behavior_batch(feeds, feed_time).await {
        Ok(batch_data) => {
            print_batch_success(&batch_data);
            save_batch_data(&batch_data, feed_time)?;
        }
        Err(e) => print_batch_error(&e),
    }
    Ok(())
}

/// Download behavior batch data
async fn download_behavior_batch(
    feeds: &FeedsClient,
    feed_time: &str,
) -> Result<Vec<u8>, virustotal_rs::Error> {
    feeds.get_file_behaviour_feed_batch(feed_time).await
}

/// Print batch download success
fn print_batch_success(batch_data: &[u8]) {
    println!("✓ Downloaded behavior batch: {} bytes", batch_data.len());
    println!("  Contains sandbox analysis reports in bzip2 format");
}

/// Save batch data to file
fn save_batch_data(batch_data: &[u8], feed_time: &str) -> Result<(), Box<dyn std::error::Error>> {
    let filename = format!("behavior_feed_{}.bz2", feed_time);
    std::fs::write(&filename, batch_data)?;
    println!("  Saved to: {}", filename);
    Ok(())
}

/// Print batch download error
fn print_batch_error(error: &virustotal_rs::Error) {
    println!("✗ Error downloading behavior feed: {}", error);
    println!("  Note: Requires Sandbox feeds license");
}

/// Test hourly behavior feed batch download
async fn test_hourly_batch(feeds: &FeedsClient) -> Result<(), Box<dyn std::error::Error>> {
    println!("\n3. HOURLY BEHAVIOR FEED BATCH");
    println!("------------------------------");

    let hourly_time = "2023120108"; // December 1, 2023 08:00-08:59 UTC

    match download_hourly_batch(feeds, hourly_time).await {
        Ok(batch_data) => {
            print_hourly_success(&batch_data);
            save_hourly_data(&batch_data, hourly_time)?;
        }
        Err(e) => print_hourly_error(&e),
    }
    Ok(())
}

/// Download hourly batch data
async fn download_hourly_batch(
    feeds: &FeedsClient,
    hourly_time: &str,
) -> Result<Vec<u8>, virustotal_rs::Error> {
    feeds
        .get_hourly_file_behaviour_feed_batch(hourly_time)
        .await
}

/// Print hourly download success
fn print_hourly_success(batch_data: &[u8]) {
    println!(
        "✓ Downloaded hourly behavior batch: {} bytes",
        batch_data.len()
    );
    println!("  Contains 60 per-minute behavior feeds in .tar.bz2 format");
}

/// Save hourly data to file
fn save_hourly_data(
    batch_data: &[u8],
    hourly_time: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let filename = format!("behavior_feed_hourly_{}.tar.bz2", hourly_time);
    std::fs::write(&filename, batch_data)?;
    println!("  Saved to: {}", filename);
    Ok(())
}

/// Print hourly download error
fn print_hourly_error(error: &virustotal_rs::Error) {
    println!("✗ Error downloading hourly behavior feed: {}", error);
}

/// Test parsing behavior feed line
fn test_feed_parsing(feeds: &FeedsClient) {
    println!("\n4. PARSE BEHAVIOR FEED LINE");
    println!("----------------------------");

    let example_line = create_example_feed_line();
    println!("Parsing example behavior feed line...");

    match parse_feed_line(feeds, &example_line) {
        Ok(item) => display_parsed_item(&item),
        Err(e) => println!("✗ Error parsing line: {}", e),
    }
}

/// Create example feed line for testing
fn create_example_feed_line() -> String {
    r#"{
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
    }"#
    .to_string()
}

/// Parse behavior feed line
fn parse_feed_line(
    feeds: &FeedsClient,
    line: &str,
) -> Result<BehaviorFeedItem, virustotal_rs::Error> {
    feeds.parse_behaviour_feed_line(line)
}

/// Display parsed feed item
fn display_parsed_item(item: &BehaviorFeedItem) {
    println!("✓ Parsed successfully:");
    println!("  ID: {}", item.id);
    println!("  Type: {}", item.object_type);

    display_file_hashes(item);
    display_artifact_tokens(item);
}

/// Display file hashes from feed item
fn display_file_hashes(item: &BehaviorFeedItem) {
    if let Some(md5) = &item.context_attributes.file_md5 {
        println!("  File MD5: {}", md5);
    }
    if let Some(sha1) = &item.context_attributes.file_sha1 {
        println!("  File SHA1: {}", sha1);
    }
    if let Some(file_type) = &item.context_attributes.file_type_tag {
        println!("  File type: {}", file_type);
    }
}

/// Display artifact tokens from URLs
fn display_artifact_tokens(item: &BehaviorFeedItem) {
    extract_and_display_token(&item.context_attributes.evtx, "EVTX");
    extract_and_display_token(&item.context_attributes.pcap, "PCAP");
    extract_and_display_token(&item.context_attributes.html_report, "HTML report");
    extract_and_display_token(&item.context_attributes.memdump, "Memory dump");
}

/// Extract and display token from URL
fn extract_and_display_token(url: &Option<String>, artifact_type: &str) {
    if let Some(url) = url {
        if let Some(token) = BehaviorFeedItem::extract_token(url) {
            println!("  {} token: {}", artifact_type, token);
        }
    }
}

/// Test downloading behavior artifacts
async fn test_artifact_downloads(feeds: &FeedsClient) {
    println!("\n5. DOWNLOAD BEHAVIOR ARTIFACTS");
    println!("-------------------------------");

    let example_token = "TOKEN123_from_feed";
    println!(
        "Attempting to download artifacts with token: {}",
        example_token
    );

    download_evtx(feeds, example_token).await;
    download_pcap(feeds, example_token).await;
    download_html_report(feeds, example_token).await;
    download_memory_dump(feeds, example_token).await;
}

/// Download EVTX artifact
async fn download_evtx(feeds: &FeedsClient, token: &str) {
    println!("\nDownloading EVTX (Windows Event Log)...");
    match feeds.download_behaviour_evtx(token).await {
        Ok(evtx_data) => {
            println!("✓ Downloaded EVTX: {} bytes", evtx_data.len());
            save_artifact(&evtx_data, token, "events.evtx");
        }
        Err(e) => print_artifact_error("EVTX", &e),
    }
}

/// Download PCAP artifact
async fn download_pcap(feeds: &FeedsClient, token: &str) {
    println!("\nDownloading PCAP (network capture)...");
    match feeds.download_behaviour_pcap(token).await {
        Ok(pcap_data) => {
            println!("✓ Downloaded PCAP: {} bytes", pcap_data.len());
            save_artifact(&pcap_data, token, "network.pcap");
        }
        Err(e) => print_artifact_error("PCAP", &e),
    }
}

/// Download HTML report
async fn download_html_report(feeds: &FeedsClient, token: &str) {
    println!("\nDownloading HTML report...");
    match feeds.download_behaviour_html(token).await {
        Ok(html_data) => {
            println!("✓ Downloaded HTML report: {} bytes", html_data.len());
            save_artifact(&html_data, token, "report.html");
        }
        Err(e) => print_artifact_error("HTML report", &e),
    }
}

/// Download memory dump
async fn download_memory_dump(feeds: &FeedsClient, token: &str) {
    println!("\nDownloading memory dump...");
    match feeds.download_behaviour_memdump(token).await {
        Ok(memdump_data) => {
            println!("✓ Downloaded memory dump: {} bytes", memdump_data.len());
            save_artifact(&memdump_data, token, "memory.dmp");
        }
        Err(e) => print_artifact_error("memory dump", &e),
    }
}

/// Save artifact data to file
fn save_artifact(data: &[u8], token: &str, extension: &str) {
    let filename = format!("behavior_{}_{}", token, extension);
    if let Err(e) = std::fs::write(&filename, data) {
        println!("  Warning: Could not save {}: {}", filename, e);
    } else {
        println!("  Saved to: {}", filename);
    }
}

/// Print artifact download error
fn print_artifact_error(artifact_type: &str, error: &virustotal_rs::Error) {
    println!("✗ Error downloading {}: {}", artifact_type, error);
    if artifact_type == "EVTX" {
        println!("  Note: Requires valid token from behavior feed");
    }
}

/// Test deprecated methods for backward compatibility
async fn test_deprecated_methods(feeds: &FeedsClient) {
    println!("\n6. BACKWARD COMPATIBILITY");
    println!("-------------------------");
    println!("Testing deprecated method names...");

    test_deprecated_sandbox_feed(feeds).await;
    test_deprecated_hourly_feed(feeds).await;
}

/// Test deprecated sandbox feed method
async fn test_deprecated_sandbox_feed(feeds: &FeedsClient) {
    let feed_time = "202312010802";
    #[allow(deprecated)]
    match feeds.get_sandbox_feed_batch(feed_time).await {
        Ok(data) => {
            println!("✓ Deprecated get_sandbox_feed_batch still works");
            println!("  Returns: {} bytes", data.len());
        }
        Err(e) => println!("  Error: {}", e),
    }
}

/// Test deprecated hourly feed method
async fn test_deprecated_hourly_feed(feeds: &FeedsClient) {
    let hourly_time = "2023120108";
    #[allow(deprecated)]
    match feeds.get_hourly_sandbox_feed_batch(hourly_time).await {
        Ok(data) => {
            println!("✓ Deprecated get_hourly_sandbox_feed_batch still works");
            println!("  Returns: {} bytes", data.len());
        }
        Err(e) => println!("  Error: {}", e),
    }
}

/// Test time range generation
fn test_time_ranges() {
    println!("\n7. TIME RANGE FOR BATCH PROCESSING");
    println!("-----------------------------------");

    let start = "202312010800";
    let end = "202312010805";

    let time_range = FeedsClient::get_time_range(start, end, false);

    println!("Behavior feed times from {} to {}:", start, end);
    for time in &time_range {
        println!("  - {}", time);
    }

    print_batch_processing_tips();
}

/// Print batch processing tips
fn print_batch_processing_tips() {
    println!("\nTo process multiple batches:");
    println!("  1. Generate time range");
    println!("  2. Download each batch");
    println!("  3. Decompress and parse");
    println!("  4. Extract artifact tokens");
    println!("  5. Download desired artifacts");
}

/// Print important notes about the API
fn print_important_notes() {
    println!("\n8. IMPORTANT NOTES");
    println!("------------------");

    print_feed_info();
    print_artifacts_info();
    print_availability_info();
    print_download_urls_info();
    print_processing_tips();
    print_completion_message();
}

/// Print feed information
fn print_feed_info() {
    println!("🔬 Sandbox Analyses Feed:");
    println!("  - Contains detailed behavior reports from sandboxes");
    println!("  - Each line is a FileBehaviour object");
    println!("  - Includes context_attributes with artifact URLs");
    println!("  - Requires Sandbox feeds license");
}

/// Print artifacts information
fn print_artifacts_info() {
    println!("\n📦 Artifacts Available:");
    println!("  - EVTX: Windows Event Log files");
    println!("  - PCAP: Network packet captures");
    println!("  - HTML: Detailed analysis reports");
    println!("  - Memory dump: Process memory snapshots");
}

/// Print availability information
fn print_availability_info() {
    println!("\n⏱️ Feed Availability:");
    println!("  - Per-minute: 60-minute lag");
    println!("  - Hourly: 2-hour lag");
    println!("  - 7-day retention period");
}

/// Print download URLs information
fn print_download_urls_info() {
    println!("\n🔗 Download URLs:");
    println!("  - Found in context_attributes");
    println!("  - Extract token from URL path");
    println!("  - Use specific download methods for each artifact type");
    println!("  - Links expire after 7 days");
}

/// Print processing tips
fn print_processing_tips() {
    println!("\n📝 Processing Tips:");
    println!("  - Decompress bzip2 data before parsing");
    println!("  - Each line is a separate JSON object");
    println!("  - Handle missing batches gracefully (404s are normal)");
    println!("  - Implement retry logic for reliability");
}

/// Print completion message
fn print_completion_message() {
    println!("\n=====================================================");
    println!("Sandbox Analyses Feed Testing Complete!");
    println!("\nNOTE: All operations require a Sandbox feeds license.");
    println!("Without proper privileges, operations will fail.");
}
