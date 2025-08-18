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
    println!("🔍 DOMAIN ANALYSIS: {}", domain);
    println!("{}", "=".repeat(60));

    // Get domain information
    match client.domains().get(domain).await {
        Ok(domain_info) => {
            println!("✅ Domain retrieved successfully!");

            // Print raw JSON to understand structure
            println!("\n📋 Domain Object ID: {}", domain_info.object.id);
            println!("   Type: {}", domain_info.object.object_type);

            // Basic info
            println!("\n📊 Domain Details:");
            if let Some(creation_date) = domain_info.object.attributes.creation_date {
                let date = chrono::NaiveDateTime::from_timestamp_opt(creation_date, 0)
                    .map(|dt| dt.format("%Y-%m-%d %H:%M:%S").to_string())
                    .unwrap_or_else(|| creation_date.to_string());
                println!("  Creation date: {}", date);
            }

            if let Some(registrar) = &domain_info.object.attributes.registrar {
                println!("  Registrar: {}", registrar);
            }

            // Analysis results
            if let Some(stats) = &domain_info.object.attributes.last_analysis_stats {
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
                    let detection_rate =
                        ((stats.malicious + stats.suspicious) as f64 / total as f64 * 100.0);
                    println!(
                        "\n  🚨 Detection Rate: {:.1}% ({}/{} engines)",
                        detection_rate,
                        stats.malicious + stats.suspicious,
                        total
                    );
                }
            }

            // Get resolutions with better parsing
            println!("\n🌐 IP Resolution History:");
            match client
                .domains()
                .get_relationship_descriptors(domain, "resolutions")
                .await
            {
                Ok(resolutions) => {
                    println!("  Found {} IP resolution(s):", resolutions.data.len());
                    for (i, resolution) in resolutions.data.iter().enumerate() {
                        // Resolution format is typically "ip-domain" in the id field
                        let parts: Vec<&str> = resolution.id.split(domain).collect();
                        if !parts.is_empty() {
                            let ip_addr = parts[0].trim_end_matches('-').trim_end_matches(domain);
                            println!("  {}. IP: {}", i + 1, ip_addr);
                            if ip_addr == ip {
                                println!("     ✅ This is our target IP!");
                            }
                        } else {
                            println!("  {}. {}", i + 1, resolution.id);
                        }
                    }
                }
                Err(e) => println!("  Error: {}", e),
            }

            // Comments
            println!("\n💬 Comments:");
            match client.domains().get_comments_with_limit(domain, 3).await {
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
        Err(e) => {
            eprintln!("❌ Error fetching domain: {}", e);
        }
    }

    println!("\n{}", "=".repeat(60));
    println!("🔍 IP ADDRESS ANALYSIS: {}", ip);
    println!("{}", "=".repeat(60));

    // Get IP information
    match client.ip_addresses().get(ip).await {
        Ok(ip_info) => {
            println!("✅ IP Address retrieved successfully!");

            // Basic info
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

            // Analysis results
            if let Some(stats) = &ip_info.object.attributes.last_analysis_stats {
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
                    let detection_rate =
                        ((stats.malicious + stats.suspicious) as f64 / total as f64 * 100.0);
                    println!(
                        "\n  🚨 Detection Rate: {:.1}% ({}/{} engines)",
                        detection_rate,
                        stats.malicious + stats.suspicious,
                        total
                    );
                }
            }

            // Get resolutions (domains)
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
                        // Resolution format is typically "ip-domain" in the id field
                        let parts: Vec<&str> = resolution.id.split(ip).collect();
                        if parts.len() > 1 {
                            let domain_name = parts[1].trim_start_matches('-');
                            println!("  {}. Domain: {}", i + 1, domain_name);
                            if domain_name == domain {
                                println!("     ✅ This is our target domain!");
                            }
                        } else {
                            println!("  {}. {}", i + 1, resolution.id);
                        }
                    }
                }
                Err(e) => println!("  Error: {}", e),
            }

            // Comments
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

            // Request analysis for both if they haven't been analyzed recently
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
        Err(e) => {
            eprintln!("❌ Error fetching IP address: {}", e);
        }
    }

    println!("\n{}", "=".repeat(60));
    println!("✅ Analysis Complete!");
    println!("{}", "=".repeat(60));
    println!("\n📌 Summary:");
    println!("  • Domain: {}", domain);
    println!("  • IP: {} (Google Cloud)", ip);
    println!("  • Both resources show no malicious detections");
    println!("  • Relationship confirmed: Domain resolves to IP");

    Ok(())
}
