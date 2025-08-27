use std::env;
use virustotal_rs::common::{AnalysisStats, VoteStats};
use virustotal_rs::objects::Collection;
use virustotal_rs::{ApiTier, Client, ClientBuilder, Domain, IpAddress};

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

    // Test domain and IP
    let domain = "office.msftupdated.com";
    let ip = "35.208.137.212";

    // Test domain
    test_domain(&client, domain, ip).await;

    // Test IP address
    test_ip_address(&client, ip, domain).await;

    print_section_header("✅ All tests completed!");

    Ok(())
}

/// Print a section header with decorative borders
fn print_section_header(title: &str) {
    println!("\n{}", "=".repeat(60));
    println!("=== {} ===", title);
    println!("{}", "=".repeat(60));
}

/// Display analysis statistics for any resource
fn display_analysis_stats(stats: &AnalysisStats, resource_type: &str) {
    println!("\n🔍 Last Analysis Stats:");
    println!("  ✅ Harmless: {}", stats.harmless);
    println!("  ⚠️  Suspicious: {}", stats.suspicious);
    println!("  🚫 Malicious: {}", stats.malicious);
    println!("  ❓ Undetected: {}", stats.undetected);

    let total = stats.harmless + stats.suspicious + stats.malicious + stats.undetected;
    if stats.malicious > 0 || stats.suspicious > 0 {
        println!(
            "  ⚠️  Detection rate: {}/{} engines flagged this {}",
            stats.malicious + stats.suspicious,
            total,
            resource_type
        );
    }
}

/// Display community votes for any resource
fn display_community_votes(votes: &VoteStats) {
    println!("\n👍 Community Votes:");
    println!("  Harmless: {}", votes.harmless);
    println!("  Malicious: {}", votes.malicious);
}

/// Display reputation score for any resource
fn display_reputation(reputation: i32) {
    println!("\n🎯 Reputation Score: {}", reputation);
}

/// Test domain functionality
async fn test_domain(client: &Client, domain: &str, target_ip: &str) {
    print_section_header(&format!("Testing Domain: {}", domain));

    match client.domains().get(domain).await {
        Ok(domain_info) => {
            println!("✓ Domain retrieved successfully!");
            display_domain_info(&domain_info);
            check_domain_relations(client, domain, target_ip).await;
        }
        Err(e) => {
            eprintln!("❌ Error fetching domain: {}", e);
        }
    }
}

/// Display domain-specific information
fn display_domain_info(domain_info: &Domain) {
    let attrs = &domain_info.object.attributes;

    // Basic info
    println!("\n📊 Basic Information:");
    println!("  Creation date: {:?}", attrs.creation_date);
    println!("  Last update: {:?}", attrs.last_update_date);
    println!("  Last analysis: {:?}", attrs.last_analysis_date);
    println!("  Registrar: {:?}", attrs.registrar);

    // Reputation
    if let Some(reputation) = attrs.reputation {
        display_reputation(reputation);
    }

    // Categories
    if let Some(categories) = &attrs.categories {
        println!("\n📁 Categories:");
        for (source, category) in categories.iter().take(5) {
            println!("  - {}: {}", source, category);
        }
    }

    // Analysis stats
    if let Some(stats) = &attrs.last_analysis_stats {
        display_analysis_stats(stats, "domain");
    }

    // Votes
    if let Some(votes) = &attrs.total_votes {
        display_community_votes(votes);
    }

    // DNS Records
    if let Some(dns_records) = &attrs.dns_records {
        println!("\n🌐 DNS Records:");
        for record in dns_records.iter().take(5) {
            println!("  {} → {}", record.record_type, record.value);
        }
    }
}

/// Check domain relations (resolutions, subdomains, communicating files)
async fn check_domain_relations(client: &Client, domain: &str, target_ip: &str) {
    // Get resolutions (IPs)
    println!("\n🔗 Checking domain resolutions (IP addresses)...");
    match client.domains().get_resolutions(domain).await {
        Ok(resolutions) => {
            println!("  Found {} resolution(s)", resolutions.data.len());
            for (i, resolution) in resolutions.data.iter().take(5).enumerate() {
                if let Some(ip_addr) = resolution.get("id").and_then(|v| v.as_str()) {
                    println!("  {}. {}", i + 1, ip_addr);
                    if ip_addr == target_ip {
                        println!("     ✓ Matches our target IP!");
                    }
                }
            }
        }
        Err(e) => println!("  Error getting resolutions: {}", e),
    }

    // Get subdomains
    println!("\n🌳 Checking subdomains...");
    match client.domains().get_subdomains(domain).await {
        Ok(subdomains) => {
            println!("  Found {} subdomain(s)", subdomains.data.len());
            for (i, subdomain) in subdomains.data.iter().take(5).enumerate() {
                if let Some(name) = subdomain.get("id").and_then(|v| v.as_str()) {
                    println!("  {}. {}", i + 1, name);
                }
            }
        }
        Err(e) => println!("  No subdomains found or error: {}", e),
    }

    // Get communicating files
    display_communicating_files(
        "domain",
        client.domains().get_communicating_files(domain).await,
    )
    .await;
}

/// Test IP address functionality
async fn test_ip_address(client: &Client, ip: &str, target_domain: &str) {
    print_section_header(&format!("Testing IP Address: {}", ip));

    match client.ip_addresses().get(ip).await {
        Ok(ip_info) => {
            println!("✓ IP Address retrieved successfully!");
            display_ip_info(&ip_info);
            check_ip_relations(client, ip, target_domain).await;
        }
        Err(e) => {
            eprintln!("❌ Error fetching IP address: {}", e);
        }
    }
}

/// Display IP-specific information
fn display_ip_info(ip_info: &IpAddress) {
    let attrs = &ip_info.object.attributes;

    // Basic info
    println!("\n📊 Basic Information:");
    println!("  ASN: {:?}", attrs.asn);
    println!("  AS Owner: {:?}", attrs.as_owner);
    println!("  Country: {:?}", attrs.country);
    println!("  Continent: {:?}", attrs.continent);
    println!("  Network: {:?}", attrs.network);

    // Reputation
    if let Some(reputation) = attrs.reputation {
        display_reputation(reputation);
    }

    // Analysis stats
    if let Some(stats) = &attrs.last_analysis_stats {
        display_analysis_stats(stats, "IP");
    }

    // Votes
    if let Some(votes) = &attrs.total_votes {
        display_community_votes(votes);
    }
}

/// Check IP relations (resolutions, communicating files, URLs)
async fn check_ip_relations(client: &Client, ip: &str, target_domain: &str) {
    // Get resolutions (domains pointing to this IP)
    println!("\n🔗 Checking IP resolutions (domains)...");
    match client.ip_addresses().get_resolutions(ip).await {
        Ok(resolutions) => {
            println!("  Found {} resolution(s)", resolutions.data.len());
            for (i, resolution) in resolutions.data.iter().take(10).enumerate() {
                if let Some(domain_name) = resolution.get("id").and_then(|v| v.as_str()) {
                    println!("  {}. {}", i + 1, domain_name);
                    if domain_name == target_domain {
                        println!("     ✓ Matches our target domain!");
                    }
                }
            }
        }
        Err(e) => println!("  Error getting resolutions: {}", e),
    }

    // Get communicating files
    display_communicating_files(
        "IP",
        client.ip_addresses().get_communicating_files(ip).await,
    )
    .await;

    // Get URLs
    println!("\n🌐 Checking URLs hosted on this IP...");
    match client.ip_addresses().get_urls(ip).await {
        Ok(urls) => {
            println!("  Found {} URL(s)", urls.data.len());
            for (i, url) in urls.data.iter().take(5).enumerate() {
                if let Some(url_str) = url.get("id").and_then(|v| v.as_str()) {
                    println!("  {}. {}", i + 1, url_str);
                }
            }
        }
        Err(e) => println!("  No URLs or error: {}", e),
    }
}

/// Display communicating files for any resource
async fn display_communicating_files(
    _resource_type: &str,
    files_result: Result<Collection<serde_json::Value>, virustotal_rs::Error>,
) {
    println!("\n📦 Checking communicating files...");
    match files_result {
        Ok(files) => {
            println!("  Found {} communicating file(s)", files.data.len());
            for (i, file) in files.data.iter().take(3).enumerate() {
                if let Some(hash) = file.get("id").and_then(|v| v.as_str()) {
                    println!("  {}. {}", i + 1, &hash[..32]);
                }
            }
        }
        Err(e) => println!("  No communicating files or error: {}", e),
    }
}
