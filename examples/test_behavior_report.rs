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

    // To get a specific sandbox report, you need the sandbox_id
    // Format: SHA256_SandboxName
    // Example: 02032ea322036e66f2825a0342979ad942ad5e201a674dc1c0085617467d661c_VirusTotal Jujubox

    let file_hash = "02032ea322036e66f2825a0342979ad942ad5e201a674dc1c0085617467d661c";
    let sandbox_name = "VirusTotal Jujubox"; // Example sandbox name
    let sandbox_id = format!("{}_{}", file_hash, sandbox_name);

    println!("\n{}", "=".repeat(60));
    println!("📊 FILE BEHAVIOR REPORT FROM SANDBOX");
    println!("{}", "=".repeat(60));
    println!("\nSandbox ID: {}", sandbox_id);

    // Get specific behavior report
    println!("\n🔍 Fetching behavior report from sandbox...");
    match client.files().get_behavior_report(&sandbox_id).await {
        Ok(behavior) => {
            println!("✅ Behavior report retrieved!");

            println!("\n📋 Report Details:");
            println!("  ID: {}", behavior.data.id);
            println!("  Type: {}", behavior.data.object_type);

            let attrs = &behavior.data.attributes;

            // Basic info
            if let Some(sandbox) = &attrs.sandbox_name {
                println!("  Sandbox: {}", sandbox);
            }

            if let Some(date) = attrs.analysis_date {
                let dt = chrono::NaiveDateTime::from_timestamp_opt(date, 0)
                    .map(|dt| dt.format("%Y-%m-%d %H:%M:%S").to_string())
                    .unwrap_or_else(|| date.to_string());
                println!("  Analysis Date: {}", dt);
            }

            if let Some(behash) = &attrs.behash {
                println!("  Behavioral Hash: {}", behash);
            }

            // Command executions
            if let Some(commands) = &attrs.command_executions {
                if !commands.is_empty() {
                    println!("\n💻 Commands Executed ({}):", commands.len());
                    for cmd in commands.iter().take(5) {
                        println!("  • {}", cmd);
                    }
                }
            }

            // Files activity
            if let Some(files) = &attrs.files_opened {
                if !files.is_empty() {
                    println!("\n📂 Files Opened ({}):", files.len());
                    for file in files.iter().take(5) {
                        println!("  • {}", file);
                    }
                }
            }

            if let Some(files) = &attrs.files_written {
                if !files.is_empty() {
                    println!("\n✏️ Files Written ({}):", files.len());
                    for file in files.iter().take(5) {
                        println!("  • {}", file);
                    }
                }
            }

            if let Some(files) = &attrs.files_dropped {
                if !files.is_empty() {
                    println!("\n📦 Files Dropped ({}):", files.len());
                    for file_drop in files.iter().take(3) {
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
                }
            }

            // Process activity
            if let Some(procs) = &attrs.processes_created {
                if !procs.is_empty() {
                    println!("\n🚀 Processes Created ({}):", procs.len());
                    for proc in procs.iter().take(5) {
                        println!("  • {}", proc);
                    }
                }
            }

            // Network activity
            if let Some(dns) = &attrs.dns_lookups {
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

            if let Some(traffic) = &attrs.ip_traffic {
                if !traffic.is_empty() {
                    println!("\n📡 IP Traffic ({} connections):", traffic.len());
                    for conn in traffic.iter().take(5) {
                        if let (Some(ip), Some(port)) =
                            (&conn.destination_ip, conn.destination_port)
                        {
                            print!("  • {}:{}", ip, port);
                            if let Some(proto) = &conn.protocol {
                                print!(" ({})", proto);
                            }
                            println!();
                        }
                    }
                }
            }

            // Registry activity
            if let Some(keys) = &attrs.registry_keys_opened {
                if !keys.is_empty() {
                    println!("\n🔑 Registry Keys Opened ({}):", keys.len());
                    for key in keys.iter().take(3) {
                        println!("  • {}", key);
                    }
                }
            }

            if let Some(keys) = &attrs.registry_keys_set {
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

            // Mutexes
            if let Some(mutexes) = &attrs.mutexes_created {
                if !mutexes.is_empty() {
                    println!("\n🔒 Mutexes Created ({}):", mutexes.len());
                    for mutex in mutexes.iter().take(3) {
                        println!("  • {}", mutex);
                    }
                }
            }

            // Services
            let service_count = attrs
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
                    .unwrap_or(0);

            if service_count > 0 {
                println!("\n⚙️ Service Activity:");
                if let Some(services) = &attrs.services_created {
                    for svc in services.iter().take(2) {
                        println!("  • Created: {}", svc);
                    }
                }
                if let Some(services) = &attrs.services_started {
                    for svc in services.iter().take(2) {
                        println!("  • Started: {}", svc);
                    }
                }
            }

            // Verdicts and tags
            if let Some(verdicts) = &attrs.verdicts {
                if !verdicts.is_empty() {
                    println!("\n⚖️ Verdicts: {}", verdicts.join(", "));
                }
            }

            if let Some(tags) = &attrs.tags {
                if !tags.is_empty() {
                    println!("\n🏷️ Behavioral Tags: {}", tags.join(", "));
                }
            }

            // Report availability
            println!("\n📄 Report Availability:");
            if let Some(has_html) = attrs.has_html_report {
                println!("  • HTML Report: {}", if has_html { "✅" } else { "❌" });
            }
            if let Some(has_pcap) = attrs.has_pcap {
                println!("  • PCAP Available: {}", if has_pcap { "✅" } else { "❌" });
            }
        }
        Err(e) => {
            println!("❌ Error fetching behavior report: {}", e);
            println!("\n💡 Note: The sandbox_id must be in the format: SHA256_SandboxName");
            println!("   Example: {}_VirusTotal Jujubox", file_hash);
            println!("\n   Common sandbox names:");
            println!("   • VirusTotal Jujubox");
            println!("   • VirusTotal Observer");
            println!("   • Zenbox");
            println!("   • C2AE");
            println!("   • Dr.Web vxCube");
        }
    }

    println!("\n{}", "=".repeat(60));
    println!("✅ Analysis Complete!");
    println!("{}", "=".repeat(60));

    Ok(())
}
