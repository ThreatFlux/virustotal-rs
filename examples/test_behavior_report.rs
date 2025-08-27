use std::env;
use virustotal_rs::{ApiTier, ClientBuilder};
use virustotal_rs::files::{FileBehaviorAttributes, DnsLookup, IpTraffic, ProcessTreeNode, SigmaResult};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = setup_client()?;
    let (file_hash, sandbox_name, sandbox_id) = setup_sandbox_info();

    print_header(&sandbox_id);
    test_behavior_report(&client, &sandbox_id).await;
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

/// Setup sandbox information
fn setup_sandbox_info() -> (String, String, String) {
    let file_hash = "02032ea322036e66f2825a0342979ad942ad5e201a674dc1c0085617467d661c".to_string();
    let sandbox_name = "VirusTotal Jujubox".to_string();
    let sandbox_id = format!("{}_{}", file_hash, sandbox_name);
    (file_hash, sandbox_name, sandbox_id)
}

/// Print application header
fn print_header(sandbox_id: &str) {
    println!("\n{}", "=".repeat(60));
    println!("📊 FILE BEHAVIOR REPORT FROM SANDBOX");
    println!("{}", "=".repeat(60));
    println!("\nSandbox ID: {}", sandbox_id);
}

/// Test behavior report retrieval
async fn test_behavior_report(client: &virustotal_rs::Client, sandbox_id: &str) {
    println!("\n🔍 Fetching behavior report from sandbox...");

    match fetch_behavior_report(client, sandbox_id).await {
        Ok(behavior) => {
            println!("✅ Behavior report retrieved!");
            display_report_overview(&behavior);
            display_behavior_details(&behavior.data.attributes);
        }
        Err(e) => print_error(&e),
    }
}

/// Fetch behavior report
async fn fetch_behavior_report(
    client: &virustotal_rs::Client,
    sandbox_id: &str,
) -> Result<virustotal_rs::FileBehavior, virustotal_rs::Error> {
    client.files().get_behavior_report(sandbox_id).await
}

/// Display report overview
fn display_report_overview(behavior: &virustotal_rs::FileBehavior) {
    println!("\n📋 Report Details:");
    println!("  ID: {}", behavior.data.id);
    println!("  Type: {}", behavior.data.object_type);
}

/// Display behavior details
fn display_behavior_details(attrs: &FileBehaviorAttributes) {
    display_basic_info(attrs);
    display_file_activities(attrs);
    display_process_activities(attrs);
    display_network_activities(attrs);
    display_registry_activities(attrs);
    display_system_activities(attrs);
    display_analysis_results(attrs);
    display_report_availability(attrs);
}

/// Display basic sandbox information
fn display_basic_info(attrs: &FileBehaviorAttributes) {
    if let Some(sandbox) = &attrs.sandbox_name {
        println!("  Sandbox: {}", sandbox);
    }

    if let Some(date) = attrs.analysis_date {
        let dt = format_timestamp(date);
        println!("  Analysis Date: {}", dt);
    }

    if let Some(behash) = &attrs.behash {
        println!("  Behavioral Hash: {}", behash);
    }
}

/// Format timestamp
fn format_timestamp(timestamp: i64) -> String {
    #[allow(deprecated)]
    chrono::NaiveDateTime::from_timestamp_opt(timestamp, 0)
        .map(|dt| dt.format("%Y-%m-%d %H:%M:%S").to_string())
        .unwrap_or_else(|| timestamp.to_string())
}

/// Display file activities
fn display_file_activities(attrs: &FileBehaviorAttributes) {
    display_files_opened(&attrs.files_opened);
    display_files_written(&attrs.files_written);
    display_files_dropped(&attrs.files_dropped);
}

/// Display files opened
fn display_files_opened(files: &Option<Vec<String>>) {
    if let Some(files) = files {
        if !files.is_empty() {
            println!("\n📂 Files Opened ({}):", files.len());
            for file in files.iter().take(5) {
                println!("  • {}", file);
            }
        }
    }
}

/// Display files written
fn display_files_written(files: &Option<Vec<String>>) {
    if let Some(files) = files {
        if !files.is_empty() {
            println!("\n✏️ Files Written ({}):", files.len());
            for file in files.iter().take(5) {
                println!("  • {}", file);
            }
        }
    }
}

/// Display files dropped
fn display_files_dropped(files: &Option<Vec<virustotal_rs::DroppedFileInfo>>) {
    if let Some(files) = files {
        if !files.is_empty() {
            println!("\n📦 Files Dropped ({}):", files.len());
            for file_drop in files.iter().take(3) {
                display_dropped_file(file_drop);
            }
        }
    }
}

/// Display individual dropped file
fn display_dropped_file(file_drop: &virustotal_rs::DroppedFileInfo) {
    if let Some(path) = &file_drop.path {
        print!("  • {}", path);
        if let Some(sha) = &file_drop.sha256 {
            print!(" (SHA256: {}...)", &sha[..16]);
        }
        if let Some(ftype) = &file_drop.file_type {
            print!(" [{}]", ftype);
        }
        println!();
    }
}

/// Display process activities
fn display_process_activities(attrs: &FileBehaviorAttributes) {
    display_processes_created(&attrs.processes_created);
    display_command_executions(&attrs.command_executions);
}

/// Display processes created
fn display_processes_created(procs: &Option<Vec<String>>) {
    if let Some(procs) = procs {
        if !procs.is_empty() {
            println!("\n🚀 Processes Created ({}):", procs.len());
            for proc in procs.iter().take(5) {
                println!("  • {}", proc);
            }
        }
    }
}

/// Display command executions
fn display_command_executions(commands: &Option<Vec<String>>) {
    if let Some(commands) = commands {
        if !commands.is_empty() {
            println!("\n💻 Commands Executed ({}):", commands.len());
            for cmd in commands.iter().take(5) {
                println!("  • {}", cmd);
            }
        }
    }
}

/// Display network activities
fn display_network_activities(attrs: &FileBehaviorAttributes) {
    display_dns_lookups(&attrs.dns_lookups);
    display_ip_traffic(&attrs.ip_traffic);
}

/// Display DNS lookups
fn display_dns_lookups(dns: &Option<Vec<DnsLookup>>) {
    if let Some(dns) = dns {
        if !dns.is_empty() {
            println!("\n🌐 DNS Lookups ({}):", dns.len());
            for lookup in dns.iter().take(5) {
                if let Some(hostname) = &lookup.hostname {
                    println!("  • {}", hostname);
                    if let Some(ips) = &lookup.resolved_ips {
                        for ip in ips.iter().take(2) {
                            println!("    → {}", ip);
                        }
                    }
                }
            }
        }
    }
}

/// Display IP traffic
fn display_ip_traffic(traffic: &Option<Vec<IpTraffic>>) {
    if let Some(traffic) = traffic {
        if !traffic.is_empty() {
            println!("\n📡 IP Traffic ({} connections):", traffic.len());
            for conn in traffic.iter().take(5) {
                if let (Some(ip), Some(port)) = (&conn.destination_ip, conn.destination_port) {
                    print!("  • {}:{}", ip, port);
                    if let Some(proto) = &conn.protocol {
                        print!(" ({})", proto);
                    }
                    println!();
                }
            }
        }
    }
}

/// Display registry activities
fn display_registry_activities(attrs: &FileBehaviorAttributes) {
    display_registry_keys_opened(&attrs.registry_keys_opened);
    display_registry_keys_set(&attrs.registry_keys_set);
}

/// Display registry keys opened
fn display_registry_keys_opened(keys: &Option<Vec<String>>) {
    if let Some(keys) = keys {
        if !keys.is_empty() {
            println!("\n🔑 Registry Keys Opened ({}):", keys.len());
            for key in keys.iter().take(3) {
                println!("  • {}", key);
            }
        }
    }
}

/// Display registry keys set
fn display_registry_keys_set(keys: &Option<Vec<virustotal_rs::RegistryKeySet>>) {
    if let Some(keys) = keys {
        if !keys.is_empty() {
            println!("\n📝 Registry Keys Set ({}):", keys.len());
            for key_set in keys.iter().take(3) {
                if let Some(key) = &key_set.key {
                    print!("  • {}", key);
                    if let Some(value) = &key_set.value {
                        print!(" = {}", value);
                    }
                    println!();
                }
            }
        }
    }
}

/// Display system activities
fn display_system_activities(attrs: &FileBehaviorAttributes) {
    display_mutexes_created(&attrs.mutexes_created);
    display_services_activity(attrs);
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

/// Display services activity
fn display_services_activity(attrs: &FileBehaviorAttributes) {
    let service_count = calculate_service_count(attrs);

    if service_count > 0 {
        println!("\n⚙️ Service Activity:");
        display_services_created(&attrs.services_created);
        display_services_started(&attrs.services_started);
    }
}

/// Calculate total service count
fn calculate_service_count(attrs: &FileBehaviorAttributes) -> usize {
    attrs
        .services_created
        .as_ref()
        .map(|s| s.len())
        .unwrap_or(0)
        + attrs
            .services_started
            .as_ref()
            .map(|s| s.len())
            .unwrap_or(0)
        + attrs
            .services_stopped
            .as_ref()
            .map(|s| s.len())
            .unwrap_or(0)
}

/// Display services created
fn display_services_created(services: &Option<Vec<String>>) {
    if let Some(services) = services {
        for svc in services.iter().take(2) {
            println!("  • Created: {}", svc);
        }
    }
}

/// Display services started
fn display_services_started(services: &Option<Vec<String>>) {
    if let Some(services) = services {
        for svc in services.iter().take(2) {
            println!("  • Started: {}", svc);
        }
    }
}

/// Display analysis results
fn display_analysis_results(attrs: &FileBehaviorAttributes) {
    display_verdicts(&attrs.verdicts);
    display_tags(&attrs.tags);
}

/// Display verdicts
fn display_verdicts(verdicts: &Option<Vec<String>>) {
    if let Some(verdicts) = verdicts {
        if !verdicts.is_empty() {
            println!("\n⚖️ Verdicts: {}", verdicts.join(", "));
        }
    }
}

/// Display behavioral tags
fn display_tags(tags: &Option<Vec<String>>) {
    if let Some(tags) = tags {
        if !tags.is_empty() {
            println!("\n🏷️ Behavioral Tags: {}", tags.join(", "));
        }
    }
}

/// Display report availability
fn display_report_availability(attrs: &FileBehaviorAttributes) {
    println!("\n📄 Report Availability:");
    if let Some(has_html) = attrs.has_html_report {
        println!("  • HTML Report: {}", if has_html { "✅" } else { "❌" });
    }
    if let Some(has_pcap) = attrs.has_pcap {
        println!("  • PCAP Available: {}", if has_pcap { "✅" } else { "❌" });
    }
}

/// Print error message
fn print_error(error: &virustotal_rs::Error) {
    println!("❌ Error fetching behavior report: {}", error);
    println!("\n💡 Note: The sandbox_id must be in the format: SHA256_SandboxName");
    print_sandbox_examples();
}

/// Print sandbox name examples
fn print_sandbox_examples() {
    println!("\n   Common sandbox names:");
    println!("   • VirusTotal Jujubox");
    println!("   • VirusTotal Observer");
    println!("   • Zenbox");
    println!("   • C2AE");
    println!("   • Dr.Web vxCube");
}

/// Print completion message
fn print_completion() {
    println!("\n{}", "=".repeat(60));
    println!("✅ Analysis Complete!");
    println!("{}", "=".repeat(60));
}
