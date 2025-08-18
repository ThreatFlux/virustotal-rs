use virustotal_rs::{ApiTier, ClientBuilder, PrivateUrlScanParams};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // NOTE: Private URL scanning requires special privileges
    let api_key = std::env::var("VT_PRIVATE_API_KEY")
        .or_else(|_| std::env::var("VT_API_KEY"))
        .unwrap_or_else(|_| "test_key".to_string());

    let client = ClientBuilder::new()
        .api_key(api_key)
        .tier(ApiTier::Premium)
        .build()?;

    println!("Testing VirusTotal Private URL Scanning API");
    println!("===========================================");
    println!("⚠️  NOTE: Requires Private Scanning License");
    println!("===========================================\n");

    let private_urls = client.private_urls();

    // 1. Test URL scanning with parameters
    println!("1. SCAN URL WITH PARAMETERS");
    println!("---------------------------");

    let test_url = "https://www.example.com";

    // Create scan parameters for comprehensive analysis
    let scan_params = PrivateUrlScanParams::new()
        .user_agent("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36".to_string())
        .with_chrome_headless() // Add Chrome Headless for comprehensive analysis
        .add_sandbox("cape_win")
        .retention_period_days(7)
        .storage_region("US".to_string())
        .interaction_timeout(120);

    println!("Scanning URL: {}", test_url);
    println!("  - User Agent: Mozilla/5.0...");
    println!("  - Sandboxes: chrome_headless_linux, cape_win");
    println!("  - Retention: 7 days");
    println!("  - Storage: US");
    println!("  - Interaction timeout: 120 seconds");

    match private_urls.scan_url(test_url, Some(scan_params)).await {
        Ok(response) => {
            println!("✓ URL scan submitted successfully");
            println!("  Analysis ID: {}", response.data.id);
            println!("  Type: {}", response.data.object_type);
            if let Some(links) = &response.data.links {
                println!("  Self link: {}", links.self_link);
            }

            // Wait a bit for analysis to start
            tokio::time::sleep(tokio::time::Duration::from_secs(3)).await;

            // You could check the analysis status using the analysis ID
            println!(
                "\n  To check analysis status, use the analysis ID with the analysis endpoint"
            );
        }
        Err(e) => {
            println!("✗ Error scanning URL: {}", e);
            println!("  Note: Private URL scanning requires special API privileges");
        }
    }

    // 2. Test URL identifier generation
    println!("\n2. URL IDENTIFIER GENERATION");
    println!("----------------------------");

    use base64::{engine::general_purpose, Engine as _};

    let urls = vec![
        "http://www.example.com",
        "https://www.virustotal.com/gui/home/upload",
        "http://suspicious-site.com/malware.exe",
    ];

    for url in &urls {
        let url_id = general_purpose::URL_SAFE_NO_PAD.encode(url.as_bytes());
        println!("URL: {}", url);
        println!("  Base64 ID: {}", url_id);
    }

    // 3. Get URL analysis report using base64 identifier
    println!("\n3. GET URL REPORT (BASE64 ID)");
    println!("------------------------------");

    let test_url = "https://www.google.com";
    let url_id = general_purpose::URL_SAFE_NO_PAD.encode(test_url.as_bytes());

    println!("Getting report for: {}", test_url);
    println!("Using Base64 ID: {}", url_id);

    match private_urls.get_url(&url_id).await {
        Ok(url_report) => {
            println!("✓ URL report retrieved");

            let attrs = &url_report.data.object.attributes;

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
            if let Some(categories) = &attrs.categories {
                if !categories.is_empty() {
                    println!("  Categories:");
                    for (source, category) in categories.iter().take(3) {
                        println!("    - {}: {}", source, category);
                    }
                }
            }
            if let Some(response_code) = &attrs.last_http_response_code {
                println!("  Last HTTP response: {}", response_code);
            }
            if let Some(chain) = &attrs.redirection_chain {
                if !chain.is_empty() {
                    println!("  Redirection chain: {} redirects", chain.len());
                }
            }
        }
        Err(e) => {
            println!("✗ Error getting URL report: {}", e);
            println!("  Note: URL may not have been scanned privately");
        }
    }

    // 4. Test with a known malicious URL (using EICAR test URL)
    println!("\n4. KNOWN MALICIOUS URL TEST");
    println!("---------------------------");

    // This is a safe test URL that's known to be flagged
    let malicious_url = "http://malware.testing.google.test/testing/malware/";
    let malicious_id = general_purpose::URL_SAFE_NO_PAD.encode(malicious_url.as_bytes());

    println!("Testing with known malicious URL");
    println!("URL: {}", malicious_url);

    match private_urls.get_url(&malicious_id).await {
        Ok(url_report) => {
            println!("✓ Malicious URL report retrieved");

            let attrs = &url_report.data.object.attributes;

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

            if let Some(results) = &attrs.last_analysis_results {
                println!("  Detection engines: {} total", results.len());

                let detections: Vec<_> = results
                    .iter()
                    .filter(|(_, r)| r.category == Some("malicious".to_string()))
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
        Err(e) => {
            println!("✗ Error getting malicious URL report: {}", e);
        }
    }

    // 5. Test URL relationships
    println!("\n5. URL RELATIONSHIPS");
    println!("--------------------");

    let popular_url = "https://www.wikipedia.org";
    let popular_id = general_purpose::URL_SAFE_NO_PAD.encode(popular_url.as_bytes());

    println!("Getting relationships for: {}", popular_url);

    // Get analyses
    println!("\nGetting URL analyses...");
    match private_urls
        .get_relationship::<serde_json::Value>(&popular_id, "analyses", Some(5), None)
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

    // Get downloaded files
    println!("\nGetting downloaded files...");
    match private_urls
        .get_relationship::<serde_json::Value>(&popular_id, "downloaded_files", Some(5), None)
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

    // Get redirecting URLs
    println!("\nGetting redirecting URLs...");
    match private_urls
        .get_relationship::<serde_json::Value>(&popular_id, "redirecting_urls", Some(5), None)
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

    // Get last serving IP address
    println!("\nGetting last serving IP address...");
    match private_urls
        .get_relationship::<serde_json::Value>(
            &popular_id,
            "last_serving_ip_address",
            Some(1),
            None,
        )
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

    // 6. Test minimal scan (without parameters)
    println!("\n6. MINIMAL URL SCAN");
    println!("-------------------");

    let simple_url = "https://www.example.org";

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

    // 7. Test comprehensive scan with all sandboxes
    println!("\n7. COMPREHENSIVE SCAN");
    println!("---------------------");

    let comprehensive_url = "https://www.suspicious-example.com";

    let comprehensive_params = PrivateUrlScanParams::new()
        .sandboxes(vec![
            "chrome_headless_linux".to_string(),
            "cape_win".to_string(),
            "zenbox_windows".to_string(),
        ])
        .retention_period_days(28) // Maximum retention
        .storage_region("EU".to_string())
        .interaction_sandbox("cape_win".to_string())
        .interaction_timeout(600); // 10 minutes

    println!("Comprehensive scan of: {}", comprehensive_url);
    println!("  - All sandboxes enabled");
    println!("  - Maximum retention (28 days)");
    println!("  - EU storage region");
    println!("  - Extended interaction timeout (10 min)");

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

    // 8. Test pagination with relationship iterator
    println!("\n8. RELATIONSHIP PAGINATION");
    println!("--------------------------");

    let paginated_url = "https://www.google.com";
    let paginated_id = general_purpose::URL_SAFE_NO_PAD.encode(paginated_url.as_bytes());

    println!("Testing pagination for URL submissions...");

    let mut submissions_iter = private_urls.get_relationship_iterator::<serde_json::Value>(
        paginated_id.clone(),
        "submissions".to_string(),
    );

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

    // 9. Get relationship descriptors (IDs only)
    println!("\n9. RELATIONSHIP DESCRIPTORS");
    println!("---------------------------");

    println!("Getting graph descriptors for URL...");

    match private_urls
        .get_relationship_descriptors(&paginated_id, "graphs", Some(5), None)
        .await
    {
        Ok(descriptors) => {
            if descriptors.data.is_empty() {
                println!("  No graphs found");
            } else {
                println!("✓ Found {} graph descriptors", descriptors.data.len());
                for descriptor in descriptors.data.iter().take(2) {
                    if let Some(id) = descriptor.get("id") {
                        println!("  - Graph ID: {}", id);
                    }
                    if let Some(context) = descriptor.get("context") {
                        println!("    Context: {}", context);
                    }
                }
            }
        }
        Err(e) => {
            println!("✗ Error getting descriptors: {}", e);
        }
    }

    // 10. Important notes
    println!("\n10. IMPORTANT NOTES");
    println!("-------------------");

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

    println!("\n===========================================");
    println!("Private URL Scanning API Testing Complete!");
    println!("\nNOTE: Most features require a Private Scanning License.");
    println!("Without proper privileges, operations will fail.");

    Ok(())
}
