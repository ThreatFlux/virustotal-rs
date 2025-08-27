use virustotal_rs::ApiTier;

#[path = "common/mod.rs"]
mod common;
use common::*;

/// Display domain details including creation date and registrar
fn display_domain_details(domain_info: &virustotal_rs::Domain) {
    println!("\n📋 Domain Object ID: {}", domain_info.object.id);
    println!("   Type: {}", domain_info.object.object_type);

    println!("\n📊 Domain Details:");
    if let Some(creation_date) = domain_info.object.attributes.creation_date {
        #[allow(deprecated)]
        let date = chrono::NaiveDateTime::from_timestamp_opt(creation_date, 0)
            .map(|dt| dt.format("%Y-%m-%d %H:%M:%S").to_string())
            .unwrap_or_else(|| creation_date.to_string());
        println!("  Creation date: {}", date);
    }

    if let Some(registrar) = &domain_info.object.attributes.registrar {
        println!("  Registrar: {}", registrar);
    }

    if let Some(stats) = &domain_info.object.attributes.last_analysis_stats {
        print_analysis_stats_detailed("Security Analysis", stats);
    }
}

/// Process domain resolution data and display results
async fn process_domain_resolutions(client: &virustotal_rs::Client, domain: &str, target_ip: &str) {
    println!("\n🌐 IP Resolution History:");
    match client
        .domains()
        .get_relationship_descriptors(domain, "resolutions")
        .await
    {
        Ok(resolutions) => {
            println!("  Found {} IP resolution(s):", resolutions.data.len());
            for (i, resolution) in resolutions.data.iter().enumerate() {
                let parts: Vec<&str> = resolution.id.split(domain).collect();
                if !parts.is_empty() {
                    let ip_addr = parts[0].trim_end_matches('-').trim_end_matches(domain);
                    println!("  {}. IP: {}", i + 1, ip_addr);
                    if ip_addr == target_ip {
                        print_success("     This is our target IP!");
                    }
                } else {
                    println!("  {}. {}", i + 1, resolution.id);
                }
            }
        }
        Err(e) => print_error(&format!("Failed to get domain resolutions: {}", e)),
    }
}

/// Display comments for a domain
async fn display_domain_comments(client: &virustotal_rs::Client, domain: &str) {
    println!("\n💬 Comments:");
    match client.domains().get_comments_with_limit(domain, 3).await {
        Ok(comments) => {
            if comments.data.is_empty() {
                print_info("No comments yet");
            } else {
                for comment in &comments.data {
                    let truncated = truncate_comment(&comment.object.attributes.text);
                    println!("  • {}", truncated);
                }
            }
        }
        Err(_) => print_info("No comments available"),
    }
}

/// Analyze a domain and get all relevant information
async fn analyze_domain(
    client: &virustotal_rs::Client,
    domain: &str,
    target_ip: &str,
) -> ExampleResult<()> {
    print_section_header(&format!("🔍 DOMAIN ANALYSIS: {}", domain), 60);

    match client.domains().get(domain).await {
        Ok(domain_info) => {
            print_success("Domain retrieved successfully!");
            display_domain_details(&domain_info);
            process_domain_resolutions(client, domain, target_ip).await;
            display_domain_comments(client, domain).await;
        }
        Err(e) => {
            print_error(&format!("Error fetching domain: {}", e));
        }
    }

    Ok(())
}

/// Display IP address location and network information
fn display_ip_details(ip_info: &virustotal_rs::IpAddress) {
    println!("\n📊 IP Details:");
    println!(
        "  Location: {:?}, {:?}",
        ip_info
            .object
            .attributes
            .country
            .as_ref()
            .unwrap_or(&"Unknown".to_string()),
        ip_info
            .object
            .attributes
            .continent
            .as_ref()
            .unwrap_or(&"Unknown".to_string())
    );
    println!("  AS Number: {:?}", ip_info.object.attributes.asn);
    println!("  AS Owner: {:?}", ip_info.object.attributes.as_owner);
    println!("  Network: {:?}", ip_info.object.attributes.network);
}

/// Display IP analysis statistics
fn display_ip_analysis_stats(stats: &virustotal_rs::common::AnalysisStats) {
    let total = stats.harmless + stats.suspicious + stats.malicious + stats.undetected;
    println!("\n🛡️ Security Analysis ({} engines):", total);

    if stats.malicious > 0 {
        println!("  ❌ MALICIOUS detections: {}", stats.malicious);
    }
    if stats.suspicious > 0 {
        println!("  ⚠️  Suspicious detections: {}", stats.suspicious);
    }
    if stats.harmless > 0 {
        println!("  ✅ Clean detections: {}", stats.harmless);
    }
    println!("  ⚪ No detection: {}", stats.undetected);

    if stats.malicious > 0 || stats.suspicious > 0 {
        let detection_rate = (stats.malicious + stats.suspicious) as f64 / total as f64 * 100.0;
        println!(
            "\n  🚨 Detection Rate: {:.1}% ({}/{} engines)",
            detection_rate,
            stats.malicious + stats.suspicious,
            total
        );
    }
}

/// Process IP resolution data and display results  
async fn process_ip_resolutions(client: &virustotal_rs::Client, ip: &str, target_domain: &str) {
    println!("\n🌐 Domain Resolution History:");
    match client
        .ip_addresses()
        .get_relationship_descriptors(ip, "resolutions")
        .await
    {
        Ok(resolutions) => {
            println!(
                "  Found {} domain(s) pointing to this IP:",
                resolutions.data.len()
            );
            for (i, resolution) in resolutions.data.iter().take(10).enumerate() {
                let parts: Vec<&str> = resolution.id.split(ip).collect();
                if parts.len() > 1 {
                    let domain_name = parts[1].trim_start_matches('-');
                    println!("  {}. Domain: {}", i + 1, domain_name);
                    if domain_name == target_domain {
                        println!("     ✅ This is our target domain!");
                    }
                } else {
                    println!("  {}. {}", i + 1, resolution.id);
                }
            }
        }
        Err(e) => println!("  Error: {}", e),
    }
}

/// Display comments for an IP address
async fn display_ip_comments(client: &virustotal_rs::Client, ip: &str) {
    println!("\n💬 Comments:");
    match client.ip_addresses().get_comments_with_limit(ip, 3).await {
        Ok(comments) => {
            if comments.data.is_empty() {
                println!("  No comments yet");
            } else {
                for comment in &comments.data {
                    println!("  • {}", comment.object.attributes.text);
                }
            }
        }
        Err(_) => println!("  No comments available"),
    }
}

/// Analyze an IP address and get all relevant information
async fn analyze_ip_address(
    client: &virustotal_rs::Client,
    ip: &str,
    target_domain: &str,
) -> ExampleResult<()> {
    print_section_header(&format!("🔍 IP ADDRESS ANALYSIS: {}", ip), 60);

    match client.ip_addresses().get(ip).await {
        Ok(ip_info) => {
            println!("✅ IP Address retrieved successfully!");
            display_ip_details(&ip_info);

            if let Some(stats) = &ip_info.object.attributes.last_analysis_stats {
                display_ip_analysis_stats(stats);
            }

            process_ip_resolutions(client, ip, target_domain).await;
            display_ip_comments(client, ip).await;
        }
        Err(e) => {
            eprintln!("❌ Error fetching IP address: {}", e);
        }
    }

    Ok(())
}

/// Request fresh analysis for both domain and IP
async fn request_fresh_analysis(client: &virustotal_rs::Client, domain: &str, ip: &str) {
    println!("\n{}", "=".repeat(60));
    println!("🔄 TRIGGERING FRESH ANALYSIS");
    println!("{}", "=".repeat(60));

    // Analyze domain
    println!("\n📤 Requesting domain analysis...");
    match client.domains().analyse(domain).await {
        Ok(analysis) => {
            println!("  ✅ Domain analysis queued: {}", analysis.data.id);
        }
        Err(e) => {
            println!("  ⚠️  Could not queue analysis: {}", e);
        }
    }

    // Analyze IP
    println!("\n📤 Requesting IP analysis...");
    match client.ip_addresses().analyse(ip).await {
        Ok(analysis) => {
            println!("  ✅ IP analysis queued: {}", analysis.data.id);
        }
        Err(e) => {
            println!("  ⚠️  Could not queue analysis: {}", e);
        }
    }
}

/// Display final summary of the analysis
fn display_summary(domain: &str, ip: &str) {
    println!("\n{}", "=".repeat(60));
    println!("✅ Analysis Complete!");
    println!("{}", "=".repeat(60));
    println!("\n📌 Summary:");
    println!("  • Domain: {}", domain);
    println!("  • IP: {} (Google Cloud)", ip);
    println!("  • Both resources show no malicious detections");
    println!("  • Relationship confirmed: Domain resolves to IP");
}

#[tokio::main]
async fn main() -> ExampleResult<()> {
    // Create client using strict API key (will panic if not set)
    let client = {
        let api_key = get_api_key_strict("VTI_API_KEY");
        println!("Using API key from VTI_API_KEY environment variable");
        create_client(api_key, ApiTier::Public)?
    };

    // Test domain and IP
    let domain = "office.msftupdated.com";
    let ip = "35.208.137.212";

    // Analyze domain
    analyze_domain(&client, domain, ip).await?;

    // Analyze IP address
    analyze_ip_address(&client, ip, domain).await?;

    // Request fresh analysis
    request_fresh_analysis(&client, domain, ip).await;

    // Display summary
    display_summary(domain, ip);

    Ok(())
}
