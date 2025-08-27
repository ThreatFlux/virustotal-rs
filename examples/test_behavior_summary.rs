use std::env;
use virustotal_rs::files::{DnsLookup, FileBehaviorData};
use virustotal_rs::{ApiTier, ClientBuilder};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = setup_client()?;
    let dll_hash = "02032ea322036e66f2825a0342979ad942ad5e201a674dc1c0085617467d661c";

    print_header(dll_hash);
    test_behavior_summary(&client, dll_hash).await;
    print_completion();

    Ok(())
}

/// Setup client with API key
fn setup_client() -> Result<virustotal_rs::Client, Box<dyn std::error::Error>> {
    let api_key = env::var("VTI_API_KEY").expect("VTI_API_KEY environment variable not set");
    println!("Using API key from VTI_API_KEY environment variable");

    Ok(ClientBuilder::new()
        .api_key(api_key)
        .tier(ApiTier::Public)
        .build()?)
}

/// Print application header
fn print_header(dll_hash: &str) {
    println!("\n{}", "=".repeat(60));
    println!("🔍 FILE BEHAVIOR ANALYSIS");
    println!("{}", "=".repeat(60));
    println!("\nFile: 7z.dll (SHA256: {}...)", &dll_hash[..32]);
}

/// Test behavior summary analysis
async fn test_behavior_summary(client: &virustotal_rs::Client, dll_hash: &str) {
    println!("\n📊 Fetching behavior summary...");

    match fetch_behavior_summary(client, dll_hash).await {
        Ok(summary) => {
            println!("✅ Behavior summary retrieved!");
            display_behavior_data(&summary.data);
        }
        Err(e) => print_error(&e),
    }
}

/// Fetch behavior summary
async fn fetch_behavior_summary(
    client: &virustotal_rs::Client,
    dll_hash: &str,
) -> Result<virustotal_rs::FileBehaviorSummary, virustotal_rs::Error> {
    client.files().get_behavior_summary(dll_hash).await
}

/// Display all behavior data
fn display_behavior_data(data: &FileBehaviorData) {
    display_file_operations(data);
    display_process_operations(data);
    display_registry_operations(data);
    display_network_operations(data);
    display_command_executions(data);
    display_behavioral_indicators(data);
}

/// Display file operations
fn display_file_operations(data: &FileBehaviorData) {
    display_files_opened(&data.files_opened);
    display_processes_created(&data.processes_created);
    display_process_tree(&data.processes_tree);
}

/// Display files opened
fn display_files_opened(files_opened: &Option<Vec<String>>) {
    if let Some(files) = files_opened {
        if !files.is_empty() {
            println!("\n📁 Files Opened ({}):", files.len());
            for file in files.iter().take(5) {
                println!("  • {}", file);
            }
            if files.len() > 5 {
                println!("  ... and {} more", files.len() - 5);
            }
        }
    }
}

/// Display processes created
fn display_processes_created(processes_created: &Option<Vec<String>>) {
    if let Some(processes) = processes_created {
        if !processes.is_empty() {
            println!("\n🚀 Processes Created ({}):", processes.len());
            for process in processes.iter().take(5) {
                println!("  • {}", process);
            }
        }
    }
}

/// Display process tree
fn display_process_tree(processes_tree: &Option<Vec<virustotal_rs::ProcessInfo>>) {
    if let Some(tree) = processes_tree {
        if !tree.is_empty() {
            println!("\n🌲 Process Tree:");
            for node in tree.iter().take(3) {
                display_process_node(node);
            }
        }
    }
}

/// Display individual process node
fn display_process_node(node: &virustotal_rs::ProcessInfo) {
    println!(
        "  • {} (PID: {})",
        node.name.as_ref().unwrap_or(&"Unknown".to_string()),
        node.process_id.as_ref().unwrap_or(&"?".to_string())
    );
}

/// Display process operations
fn display_process_operations(data: &FileBehaviorData) {
    display_mutexes_created(&data.mutexes_created);
}

/// Display mutexes created
fn display_mutexes_created(mutexes: &Option<Vec<String>>) {
    if let Some(mutexes) = mutexes {
        if !mutexes.is_empty() {
            println!("\n🔒 Mutexes Created ({}):", mutexes.len());
            for mutex in mutexes.iter().take(3) {
                println!("  • {}", mutex);
            }
        }
    }
}

/// Display registry operations
fn display_registry_operations(data: &FileBehaviorData) {
    display_registry_keys_opened(&data.registry_keys_opened);
}

/// Display registry keys opened
fn display_registry_keys_opened(registry_keys: &Option<Vec<String>>) {
    if let Some(keys) = registry_keys {
        if !keys.is_empty() {
            println!("\n🔑 Registry Keys Accessed ({}):", keys.len());
            for key in keys.iter().take(5) {
                println!("  • {}", key);
            }
            if keys.len() > 5 {
                println!("  ... and {} more", keys.len() - 5);
            }
        }
    }
}

/// Display network operations
fn display_network_operations(data: &FileBehaviorData) {
    display_dns_lookups(&data.dns_lookups);
    display_ip_traffic(&data.ip_traffic);
    display_http_conversations(&data.http_conversations);
}

/// Display DNS lookups
fn display_dns_lookups(dns_lookups: &Option<Vec<DnsLookup>>) {
    if let Some(lookups) = dns_lookups {
        if !lookups.is_empty() {
            println!("\n🌐 DNS Lookups ({}):", lookups.len());
            for lookup in lookups {
                display_dns_lookup(lookup);
            }
        }
    }
}

/// Display individual DNS lookup
fn display_dns_lookup(lookup: &virustotal_rs::DnsLookup) {
    if let Some(hostname) = &lookup.hostname {
        println!("  • {}", hostname);
        if let Some(ips) = &lookup.resolved_ips {
            for ip in ips.iter().take(2) {
                println!("    → {}", ip);
            }
        }
    }
}

/// Display IP traffic
fn display_ip_traffic(ip_traffic: &Option<Vec<virustotal_rs::IpTraffic>>) {
    if let Some(traffic) = ip_traffic {
        if !traffic.is_empty() {
            println!("\n📡 Network Traffic ({} connections):", traffic.len());
            for connection in traffic.iter().take(5) {
                display_ip_connection(connection);
            }
        }
    }
}

/// Display IP connection
fn display_ip_connection(traffic: &virustotal_rs::IpTraffic) {
    println!(
        "  • {}:{} ({})",
        traffic
            .destination_ip
            .as_ref()
            .unwrap_or(&"Unknown".to_string()),
        traffic.destination_port.unwrap_or(0),
        traffic.protocol.as_ref().unwrap_or(&"?".to_string())
    );
}

/// Display HTTP conversations
fn display_http_conversations(http_convos: &Option<Vec<virustotal_rs::HttpConversation>>) {
    if let Some(conversations) = http_convos {
        if !conversations.is_empty() {
            println!("\n🌐 HTTP Conversations ({}):", conversations.len());
            for convo in conversations.iter().take(3) {
                display_http_conversation(convo);
            }
        }
    }
}

/// Display HTTP conversation
fn display_http_conversation(convo: &virustotal_rs::HttpConversation) {
    if let Some(url) = &convo.url {
        println!(
            "  • {} {}",
            convo.request_method.as_ref().unwrap_or(&"GET".to_string()),
            url
        );
        if let Some(status) = convo.response_status {
            println!("    Response: HTTP {}", status);
        }
    }
}

/// Display command executions
fn display_command_executions(data: &FileBehaviorData) {
    if let Some(commands) = &data.command_executions {
        if !commands.is_empty() {
            println!("\n💻 Commands Executed ({}):", commands.len());
            for cmd in commands.iter().take(5) {
                println!("  • {}", cmd);
            }
        }
    }
}

/// Display behavioral indicators
fn display_behavioral_indicators(data: &FileBehaviorData) {
    display_behavioral_tags(&data.tags);
    display_mitre_techniques(&data.mitre_attack_techniques);
    display_sigma_results(&data.sigma_analysis_results);
}

/// Display behavioral tags
fn display_behavioral_tags(tags: &Option<Vec<String>>) {
    if let Some(tags) = tags {
        if !tags.is_empty() {
            println!("\n🏷️ Behavioral Tags:");
            for tag in tags {
                println!("  • {}", tag);
            }
        }
    }
}

/// Display MITRE ATT&CK techniques
fn display_mitre_techniques(techniques: &Option<Vec<virustotal_rs::MitreTechnique>>) {
    if let Some(techniques) = techniques {
        if !techniques.is_empty() {
            println!("\n⚔️ MITRE ATT&CK Techniques:");
            for technique in techniques.iter().take(5) {
                display_mitre_technique(technique);
            }
        }
    }
}

/// Display individual MITRE technique
fn display_mitre_technique(technique: &virustotal_rs::MitreTechnique) {
    println!(
        "  • {} - {}",
        technique.id.as_ref().unwrap_or(&"Unknown".to_string()),
        technique.name.as_ref().unwrap_or(&"Unknown".to_string())
    );

    if let Some(desc) = &technique.description {
        let preview = create_description_preview(desc, 80);
        println!("    {}", preview);
    }
}

/// Create description preview with truncation
fn create_description_preview(description: &str, max_len: usize) -> String {
    if description.len() > max_len {
        format!("{}...", &description[..max_len])
    } else {
        description.to_string()
    }
}

/// Display Sigma analysis results
fn display_sigma_results(sigma_results: &Option<Vec<virustotal_rs::SigmaResult>>) {
    if let Some(results) = sigma_results {
        if !results.is_empty() {
            println!("\n🎯 Sigma Rule Matches ({}):", results.len());
            for result in results.iter().take(3) {
                display_sigma_result(result);
            }
        }
    }
}

/// Display individual Sigma result
fn display_sigma_result(result: &virustotal_rs::SigmaResult) {
    if let Some(title) = &result.rule_title {
        println!("  • {}", title);
        if let Some(level) = &result.rule_level {
            println!("    Level: {}", level);
        }
    }
}

/// Print error message
fn print_error(error: &virustotal_rs::Error) {
    println!("❌ Error fetching behavior summary: {}", error);
    println!("\n💡 Note: Behavior summary may not be available for all files.");
    println!("   Files need to have been analyzed in a sandbox environment.");
}

/// Print completion message
fn print_completion() {
    println!("\n{}", "=".repeat(60));
    println!("✅ Analysis Complete!");
    println!("{}", "=".repeat(60));
}
