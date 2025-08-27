//! VirusTotal Private URL Scanning API Example
//!
//! This example demonstrates the VirusTotal Private URL Scanning API capabilities.
//! It shows how to scan URLs with custom parameters, retrieve analysis reports,
//! explore relationships, and work with pagination.

mod common;

use base64::{engine::general_purpose, Engine as _};
use common::{create_client_from_env, print_header, print_test_header, ExampleResult};
use virustotal_rs::{ApiTier, PrivateUrlAttributes, PrivateUrlScanParams, PrivateUrlsClient};

/// Test URLs for various scenarios
const TEST_URLS: &[&str] = &[
    "https://www.example.com",
    "https://www.google.com",
    "https://www.wikipedia.org",
    "https://www.example.org",
    "https://www.suspicious-example.com",
];

/// Known test URLs for malicious scanning
const MALICIOUS_TEST_URL: &str = "http://malware.testing.google.test/testing/malware/";

#[tokio::main]
async fn main() -> ExampleResult<()> {
    let client = create_client_from_env("VT_PRIVATE_API_KEY", ApiTier::Premium)?;

    print_header("VirusTotal Private URL Scanning API");
    println!("⚠️  NOTE: Requires Private Scanning License\n");

    let private_urls = client.private_urls();

    // Execute all test scenarios
    test_url_scanning_with_parameters(&private_urls).await;
    test_url_identifier_generation().await;
    test_url_report_retrieval(&private_urls).await;
    test_malicious_url_analysis(&private_urls).await;
    test_url_relationships(&private_urls).await;
    test_minimal_scan(&private_urls).await;
    test_comprehensive_scan(&private_urls).await;
    test_relationship_pagination(&private_urls).await;
    test_relationship_descriptors(&private_urls).await;
    print_important_notes();

    println!("\n===========================================");
    println!("Private URL Scanning API Testing Complete!");
    println!("NOTE: Most features require a Private Scanning License.");

    Ok(())
}

/// Test URL scanning with comprehensive parameters
async fn test_url_scanning_with_parameters(private_urls: &PrivateUrlsClient) {
    print_test_header("SCAN URL WITH PARAMETERS");

    let test_url = TEST_URLS[0];
    let scan_params = create_comprehensive_scan_params();

    display_scan_parameters(test_url, &scan_params);

    match private_urls.scan_url(test_url, Some(scan_params)).await {
        Ok(response) => {
            println!("✓ URL scan submitted successfully");
            println!("  Analysis ID: {}", response.data.id);
            println!("  Type: {}", response.data.object_type);
            if let Some(links) = &response.data.links {
                println!("  Self link: {}", links.self_link);
            }

            // Wait for analysis to start
            tokio::time::sleep(tokio::time::Duration::from_secs(3)).await;
            println!("\n  Use the analysis ID with the analysis endpoint to check status");
        }
        Err(e) => {
            println!("✗ Error scanning URL: {}", e);
            println!("  Note: Private URL scanning requires special API privileges");
        }
    }
}

/// Create comprehensive scan parameters
fn create_comprehensive_scan_params() -> PrivateUrlScanParams {
    PrivateUrlScanParams::new()
        .user_agent("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36".to_string())
        .with_chrome_headless()
        .add_sandbox("cape_win")
        .retention_period_days(7)
        .storage_region("US".to_string())
        .interaction_timeout(120)
}

/// Display scan parameters for user reference
fn display_scan_parameters(url: &str, _params: &PrivateUrlScanParams) {
    println!("Scanning URL: {}", url);
    println!("  - User Agent: Mozilla/5.0...");
    println!("  - Sandboxes: chrome_headless_linux, cape_win");
    println!("  - Retention: 7 days");
    println!("  - Storage: US");
    println!("  - Interaction timeout: 120 seconds");
}

/// Test URL identifier generation using base64 encoding
async fn test_url_identifier_generation() {
    print_test_header("URL IDENTIFIER GENERATION");

    let test_urls = vec![
        "http://www.example.com",
        "https://www.virustotal.com/gui/home/upload",
        "http://suspicious-site.com/malware.exe",
    ];

    for url in &test_urls {
        let url_id = encode_url_to_base64(url);
        println!("URL: {}", url);
        println!("  Base64 ID: {}", url_id);
    }
}

/// Encode URL to base64 identifier
fn encode_url_to_base64(url: &str) -> String {
    general_purpose::URL_SAFE_NO_PAD.encode(url.as_bytes())
}

/// Test URL report retrieval using base64 identifier
async fn test_url_report_retrieval(private_urls: &PrivateUrlsClient) {
    print_test_header("GET URL REPORT (BASE64 ID)");

    let test_url = TEST_URLS[1]; // google.com
    let url_id = encode_url_to_base64(test_url);

    println!("Getting report for: {}", test_url);
    println!("Using Base64 ID: {}", url_id);

    match private_urls.get_url(&url_id).await {
        Ok(url_report) => {
            println!("✓ URL report retrieved");
            display_url_report_details(&url_report.data.object.attributes);
        }
        Err(e) => {
            println!("✗ Error getting URL report: {}", e);
            println!("  Note: URL may not have been scanned privately");
        }
    }
}

/// Display URL report details
fn display_url_report_details(attrs: &PrivateUrlAttributes) {
    display_basic_url_info(attrs);
    display_analysis_stats(attrs);
    display_url_categories(attrs);
    display_response_info(attrs);
}

/// Display basic URL information
fn display_basic_url_info(attrs: &PrivateUrlAttributes) {
    if let Some(url) = &attrs.url {
        println!("  URL: {}", url);
    }
    if let Some(final_url) = &attrs.final_url {
        println!("  Final URL: {}", final_url);
    }
    if let Some(title) = &attrs.title {
        println!("  Title: {}", title);
    }
    if let Some(reputation) = &attrs.reputation {
        println!("  Reputation: {}", reputation);
    }
}

/// Display analysis statistics
fn display_analysis_stats(attrs: &PrivateUrlAttributes) {
    if let Some(stats) = &attrs.last_analysis_stats {
        println!("  Last analysis stats:");
        if let Some(malicious) = stats.malicious {
            println!("    - Malicious: {}", malicious);
        }
        if let Some(suspicious) = stats.suspicious {
            println!("    - Suspicious: {}", suspicious);
        }
        if let Some(harmless) = stats.harmless {
            println!("    - Harmless: {}", harmless);
        }
        if let Some(undetected) = stats.undetected {
            println!("    - Undetected: {}", undetected);
        }
    }
}

/// Display URL categories
fn display_url_categories(attrs: &PrivateUrlAttributes) {
    if let Some(categories) = &attrs.categories {
        if !categories.is_empty() {
            println!("  Categories:");
            for (source, category) in categories.iter().take(3) {
                println!("    - {}: {}", source, category);
            }
        }
    }
}

/// Display response information
fn display_response_info(attrs: &PrivateUrlAttributes) {
    if let Some(response_code) = &attrs.last_http_response_code {
        println!("  Last HTTP response: {}", response_code);
    }
    if let Some(chain) = &attrs.redirection_chain {
        if !chain.is_empty() {
            println!("  Redirection chain: {} redirects", chain.len());
        }
    }
}

/// Test analysis of known malicious URL
async fn test_malicious_url_analysis(private_urls: &PrivateUrlsClient) {
    print_test_header("KNOWN MALICIOUS URL TEST");

    let malicious_id = encode_url_to_base64(MALICIOUS_TEST_URL);

    println!("Testing with known malicious URL");
    println!("URL: {}", MALICIOUS_TEST_URL);

    match private_urls.get_url(&malicious_id).await {
        Ok(url_report) => {
            println!("✓ Malicious URL report retrieved");
            display_malicious_analysis(&url_report.data.object.attributes);
        }
        Err(e) => {
            println!("✗ Error getting malicious URL report: {}", e);
        }
    }
}

/// Display malicious analysis results
fn display_malicious_analysis(attrs: &PrivateUrlAttributes) {
    if let Some(stats) = &attrs.last_analysis_stats {
        if let Some(malicious) = stats.malicious {
            println!("  Malicious detections: {}", malicious);
        }
    }

    if let Some(threat_names) = &attrs.threat_names {
        if !threat_names.is_empty() {
            println!("  Threat names:");
            for name in threat_names.iter().take(5) {
                println!("    - {}", name);
            }
        }
    }

    display_detection_engines(attrs);
}

/// Display detection engine results
fn display_detection_engines(attrs: &PrivateUrlAttributes) {
    if let Some(results) = &attrs.last_analysis_results {
        println!("  Detection engines: {} total", results.len());

        let detections: Vec<_> = results
            .iter()
            .filter(|(_, r)| r.category.as_deref() == Some("malicious"))
            .take(5)
            .collect();

        if !detections.is_empty() {
            println!("  Engines detecting as malicious:");
            for (engine, result) in detections {
                if let Some(res) = &result.result {
                    println!("    - {}: {}", engine, res);
                }
            }
        }
    }
}

/// Test URL relationship analysis
async fn test_url_relationships(private_urls: &PrivateUrlsClient) {
    print_test_header("URL RELATIONSHIPS");

    let popular_url = TEST_URLS[2]; // wikipedia.org
    let popular_id = encode_url_to_base64(popular_url);

    println!("Getting relationships for: {}", popular_url);

    test_analyses_relationship(private_urls, &popular_id).await;
    test_downloaded_files_relationship(private_urls, &popular_id).await;
    test_redirecting_urls_relationship(private_urls, &popular_id).await;
    test_serving_ip_relationship(private_urls, &popular_id).await;
}

/// Test analyses relationship
async fn test_analyses_relationship(private_urls: &PrivateUrlsClient, url_id: &str) {
    println!("\nGetting URL analyses...");
    match private_urls
        .get_relationship::<serde_json::Value>(url_id, "analyses", Some(5), None)
        .await
    {
        Ok(analyses) => {
            println!("✓ Found {} analyses", analyses.data.len());
            for analysis in analyses.data.iter().take(2) {
                if let Some(id) = analysis.get("id") {
                    println!("  - Analysis: {}", id);
                }
            }
        }
        Err(e) => {
            println!("✗ Error getting analyses: {}", e);
        }
    }
}

/// Test downloaded files relationship
async fn test_downloaded_files_relationship(private_urls: &PrivateUrlsClient, url_id: &str) {
    println!("\nGetting downloaded files...");
    match private_urls
        .get_relationship::<serde_json::Value>(url_id, "downloaded_files", Some(5), None)
        .await
    {
        Ok(files) => {
            if files.data.is_empty() {
                println!("  No downloaded files found");
            } else {
                println!("✓ Found {} downloaded files", files.data.len());
                for file in files.data.iter().take(2) {
                    if let Some(id) = file.get("id") {
                        println!("  - File: {}", id);
                    }
                }
            }
        }
        Err(e) => {
            println!("✗ Error getting downloaded files: {}", e);
        }
    }
}

/// Test redirecting URLs relationship
async fn test_redirecting_urls_relationship(private_urls: &PrivateUrlsClient, url_id: &str) {
    println!("\nGetting redirecting URLs...");
    match private_urls
        .get_relationship::<serde_json::Value>(url_id, "redirecting_urls", Some(5), None)
        .await
    {
        Ok(urls) => {
            if urls.data.is_empty() {
                println!("  No redirecting URLs found");
            } else {
                println!("✓ Found {} redirecting URLs", urls.data.len());
            }
        }
        Err(e) => {
            println!("✗ Error getting redirecting URLs: {}", e);
        }
    }
}

/// Test serving IP relationship
async fn test_serving_ip_relationship(private_urls: &PrivateUrlsClient, url_id: &str) {
    println!("\nGetting last serving IP address...");
    match private_urls
        .get_relationship::<serde_json::Value>(url_id, "last_serving_ip_address", Some(1), None)
        .await
    {
        Ok(ips) => {
            if !ips.data.is_empty() {
                println!("✓ Last serving IP found");
                if let Some(ip) = ips.data.first() {
                    if let Some(id) = ip.get("id") {
                        println!("  IP: {}", id);
                    }
                }
            }
        }
        Err(e) => {
            println!("✗ Error getting last serving IP: {}", e);
        }
    }
}

/// Test minimal URL scan without parameters
async fn test_minimal_scan(private_urls: &PrivateUrlsClient) {
    print_test_header("MINIMAL URL SCAN");

    let simple_url = TEST_URLS[3]; // example.org

    println!("Scanning URL with default settings: {}", simple_url);

    match private_urls.scan_url(simple_url, None).await {
        Ok(response) => {
            println!("✓ URL scan submitted");
            println!("  Analysis ID: {}", response.data.id);
            println!("  Using default retention and sandbox settings");
        }
        Err(e) => {
            println!("✗ Error scanning URL: {}", e);
        }
    }
}

/// Test comprehensive scan with all sandboxes
async fn test_comprehensive_scan(private_urls: &PrivateUrlsClient) {
    print_test_header("COMPREHENSIVE SCAN");

    let comprehensive_url = TEST_URLS[4]; // suspicious-example.com
    let comprehensive_params = create_comprehensive_scan_with_all_sandboxes();

    display_comprehensive_scan_info(comprehensive_url);

    match private_urls
        .scan_url(comprehensive_url, Some(comprehensive_params))
        .await
    {
        Ok(response) => {
            println!("✓ Comprehensive scan submitted");
            println!("  Analysis ID: {}", response.data.id);
        }
        Err(e) => {
            println!("✗ Error with comprehensive scan: {}", e);
        }
    }
}

/// Create comprehensive scan parameters with all sandboxes
fn create_comprehensive_scan_with_all_sandboxes() -> PrivateUrlScanParams {
    PrivateUrlScanParams::new()
        .sandboxes(vec![
            "chrome_headless_linux".to_string(),
            "cape_win".to_string(),
            "zenbox_windows".to_string(),
        ])
        .retention_period_days(28) // Maximum retention
        .storage_region("EU".to_string())
        .interaction_sandbox("cape_win".to_string())
        .interaction_timeout(600) // 10 minutes
}

/// Display comprehensive scan information
fn display_comprehensive_scan_info(url: &str) {
    println!("Comprehensive scan of: {}", url);
    println!("  - All sandboxes enabled");
    println!("  - Maximum retention (28 days)");
    println!("  - EU storage region");
    println!("  - Extended interaction timeout (10 min)");
}

/// Test relationship pagination
async fn test_relationship_pagination(private_urls: &PrivateUrlsClient) {
    print_test_header("RELATIONSHIP PAGINATION");

    let paginated_url = TEST_URLS[1]; // google.com
    let paginated_id = encode_url_to_base64(paginated_url);

    println!("Testing pagination for URL submissions...");

    let mut submissions_iter = private_urls
        .get_relationship_iterator::<serde_json::Value>(paginated_id, "submissions".to_string());

    match submissions_iter.next_batch().await {
        Ok(batch) => {
            println!("✓ Retrieved {} submissions in first batch", batch.len());

            if batch.len() >= 10 {
                println!("  More pages may be available");
            }
        }
        Err(e) => {
            println!("✗ Error with pagination: {}", e);
        }
    }
}

/// Test relationship descriptors
async fn test_relationship_descriptors(private_urls: &PrivateUrlsClient) {
    print_test_header("RELATIONSHIP DESCRIPTORS");

    let test_url = TEST_URLS[1]; // google.com
    let url_id = encode_url_to_base64(test_url);

    println!("Getting graph descriptors for URL...");

    match private_urls
        .get_relationship_descriptors(&url_id, "graphs", Some(5), None)
        .await
    {
        Ok(descriptors) => {
            if descriptors.data.is_empty() {
                println!("  No graphs found");
            } else {
                println!("✓ Found {} graph descriptors", descriptors.data.len());
                display_graph_descriptors(&descriptors.data);
            }
        }
        Err(e) => {
            println!("✗ Error getting descriptors: {}", e);
        }
    }
}

/// Display graph descriptors
fn display_graph_descriptors(descriptors: &[std::collections::HashMap<String, serde_json::Value>]) {
    for descriptor in descriptors.iter().take(2) {
        if let Some(id) = descriptor.get("id") {
            println!("  - Graph ID: {}", id);
        }
        if let Some(context) = descriptor.get("context") {
            println!("    Context: {}", context);
        }
    }
}

/// Print important notes and best practices
fn print_important_notes() {
    print_test_header("IMPORTANT NOTES");

    println!("📘 URL Identifiers:");
    println!("  1. SHA-256 of canonized URL (returned by API)");
    println!("  2. Base64-encoded URL without padding (easier to generate)");
    println!("\n  Example base64 encoding:");
    println!("  let url_id = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(url);");

    println!("\n🔒 Private Scanning:");
    println!("  - Requires Private Scanning License");
    println!("  - Data retention: 1-28 days");
    println!("  - Storage regions: US, CA, EU, GB");

    println!("\n🖥️ Sandboxes:");
    println!("  - chrome_headless_linux: Comprehensive web analysis");
    println!("  - cape_win: Windows behavioral analysis");
    println!("  - zenbox_windows: Alternative Windows sandbox");

    println!("\n⚡ Best Practices:");
    println!("  - Use chrome_headless_linux for comprehensive analysis");
    println!("  - Set appropriate retention based on needs");
    println!("  - Choose storage region based on compliance requirements");
}
