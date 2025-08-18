use std::env;
use virustotal_rs::{ApiTier, ClientBuilder};

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

    println!("\n{}", "=".repeat(60));
    println!("=== Testing Domain: {} ===", domain);
    println!("{}", "=".repeat(60));

    // Get domain information
    match client.domains().get(domain).await {
        Ok(domain_info) => {
            println!("✓ Domain retrieved successfully!");

            // Basic info
            println!("\n📊 Basic Information:");
            println!(
                "  Creation date: {:?}",
                domain_info.object.attributes.creation_date
            );
            println!(
                "  Last update: {:?}",
                domain_info.object.attributes.last_update_date
            );
            println!(
                "  Last analysis: {:?}",
                domain_info.object.attributes.last_analysis_date
            );
            println!("  Registrar: {:?}", domain_info.object.attributes.registrar);

            // Reputation
            if let Some(reputation) = domain_info.object.attributes.reputation {
                println!("\n🎯 Reputation Score: {}", reputation);
            }

            // Categories
            if let Some(categories) = &domain_info.object.attributes.categories {
                println!("\n📁 Categories:");
                for (source, category) in categories.iter().take(5) {
                    println!("  - {}: {}", source, category);
                }
            }

            // Analysis stats
            if let Some(stats) = &domain_info.object.attributes.last_analysis_stats {
                println!("\n🔍 Last Analysis Stats:");
                println!("  ✅ Harmless: {}", stats.harmless);
                println!("  ⚠️  Suspicious: {}", stats.suspicious);
                println!("  🚫 Malicious: {}", stats.malicious);
                println!("  ❓ Undetected: {}", stats.undetected);

                let total = stats.harmless + stats.suspicious + stats.malicious + stats.undetected;
                if stats.malicious > 0 || stats.suspicious > 0 {
                    println!(
                        "  ⚠️  Detection rate: {}/{} engines flagged this domain",
                        stats.malicious + stats.suspicious,
                        total
                    );
                }
            }

            // Votes
            if let Some(votes) = &domain_info.object.attributes.total_votes {
                println!("\n👍 Community Votes:");
                println!("  Harmless: {}", votes.harmless);
                println!("  Malicious: {}", votes.malicious);
            }

            // DNS Records
            if let Some(dns_records) = &domain_info.object.attributes.dns_records {
                println!("\n🌐 DNS Records:");
                for record in dns_records.iter().take(5) {
                    println!("  {} → {}", record.record_type, record.value);
                }
            }

            // Get resolutions (IPs)
            println!("\n🔗 Checking domain resolutions (IP addresses)...");
            match client.domains().get_resolutions(domain).await {
                Ok(resolutions) => {
                    println!("  Found {} resolution(s)", resolutions.data.len());
                    for (i, resolution) in resolutions.data.iter().take(5).enumerate() {
                        if let Some(ip_addr) = resolution.get("id").and_then(|v| v.as_str()) {
                            println!("  {}. {}", i + 1, ip_addr);
                            if ip_addr == ip {
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
            println!("\n📦 Checking communicating files...");
            match client.domains().get_communicating_files(domain).await {
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
        Err(e) => {
            eprintln!("❌ Error fetching domain: {}", e);
        }
    }

    println!("\n{}", "=".repeat(60));
    println!("=== Testing IP Address: {} ===", ip);
    println!("{}", "=".repeat(60));

    // Get IP information
    match client.ip_addresses().get(ip).await {
        Ok(ip_info) => {
            println!("✓ IP Address retrieved successfully!");

            // Basic info
            println!("\n📊 Basic Information:");
            println!("  ASN: {:?}", ip_info.object.attributes.asn);
            println!("  AS Owner: {:?}", ip_info.object.attributes.as_owner);
            println!("  Country: {:?}", ip_info.object.attributes.country);
            println!("  Continent: {:?}", ip_info.object.attributes.continent);
            println!("  Network: {:?}", ip_info.object.attributes.network);

            // Reputation
            if let Some(reputation) = ip_info.object.attributes.reputation {
                println!("\n🎯 Reputation Score: {}", reputation);
            }

            // Analysis stats
            if let Some(stats) = &ip_info.object.attributes.last_analysis_stats {
                println!("\n🔍 Last Analysis Stats:");
                println!("  ✅ Harmless: {}", stats.harmless);
                println!("  ⚠️  Suspicious: {}", stats.suspicious);
                println!("  🚫 Malicious: {}", stats.malicious);
                println!("  ❓ Undetected: {}", stats.undetected);

                let total = stats.harmless + stats.suspicious + stats.malicious + stats.undetected;
                if stats.malicious > 0 || stats.suspicious > 0 {
                    println!(
                        "  ⚠️  Detection rate: {}/{} engines flagged this IP",
                        stats.malicious + stats.suspicious,
                        total
                    );
                }
            }

            // Votes
            if let Some(votes) = &ip_info.object.attributes.total_votes {
                println!("\n👍 Community Votes:");
                println!("  Harmless: {}", votes.harmless);
                println!("  Malicious: {}", votes.malicious);
            }

            // Get resolutions (domains pointing to this IP)
            println!("\n🔗 Checking IP resolutions (domains)...");
            match client.ip_addresses().get_resolutions(ip).await {
                Ok(resolutions) => {
                    println!("  Found {} resolution(s)", resolutions.data.len());
                    for (i, resolution) in resolutions.data.iter().take(10).enumerate() {
                        if let Some(domain_name) = resolution.get("id").and_then(|v| v.as_str()) {
                            println!("  {}. {}", i + 1, domain_name);
                            if domain_name == domain {
                                println!("     ✓ Matches our target domain!");
                            }
                        }
                    }
                }
                Err(e) => println!("  Error getting resolutions: {}", e),
            }

            // Get communicating files
            println!("\n📦 Checking communicating files...");
            match client.ip_addresses().get_communicating_files(ip).await {
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
        Err(e) => {
            eprintln!("❌ Error fetching IP address: {}", e);
        }
    }

    println!("\n{}", "=".repeat(60));
    println!("✅ All tests completed!");
    println!("{}", "=".repeat(60));

    Ok(())
}
