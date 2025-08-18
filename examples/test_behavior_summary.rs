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

    // Test file hash (7z.dll from CTF)
    let dll_hash = "02032ea322036e66f2825a0342979ad942ad5e201a674dc1c0085617467d661c";

    println!("\n{}", "=".repeat(60));
    println!("🔍 FILE BEHAVIOR ANALYSIS");
    println!("{}", "=".repeat(60));
    println!("\nFile: 7z.dll (SHA256: {}...)", &dll_hash[..32]);

    // Get behavior summary
    println!("\n📊 Fetching behavior summary...");
    match client.files().get_behavior_summary(dll_hash).await {
        Ok(summary) => {
            println!("✅ Behavior summary retrieved!");

            if let Some(files_opened) = &summary.data.files_opened {
                if !files_opened.is_empty() {
                    println!("\n📁 Files Opened ({}):", files_opened.len());
                    for file in files_opened.iter().take(5) {
                        println!("  • {}", file);
                    }
                    if files_opened.len() > 5 {
                        println!("  ... and {} more", files_opened.len() - 5);
                    }
                }
            }

            if let Some(processes_created) = &summary.data.processes_created {
                if !processes_created.is_empty() {
                    println!("\n🚀 Processes Created ({}):", processes_created.len());
                    for process in processes_created.iter().take(5) {
                        println!("  • {}", process);
                    }
                }
            }

            if let Some(processes_tree) = &summary.data.processes_tree {
                if !processes_tree.is_empty() {
                    println!("\n🌲 Process Tree:");
                    for node in processes_tree.iter().take(3) {
                        println!(
                            "  • {} (PID: {})",
                            node.name.as_ref().unwrap_or(&"Unknown".to_string()),
                            node.process_id.as_ref().unwrap_or(&"?".to_string())
                        );
                    }
                }
            }

            if let Some(registry_keys) = &summary.data.registry_keys_opened {
                if !registry_keys.is_empty() {
                    println!("\n🔑 Registry Keys Accessed ({}):", registry_keys.len());
                    for key in registry_keys.iter().take(5) {
                        println!("  • {}", key);
                    }
                    if registry_keys.len() > 5 {
                        println!("  ... and {} more", registry_keys.len() - 5);
                    }
                }
            }

            if let Some(mutexes) = &summary.data.mutexes_created {
                if !mutexes.is_empty() {
                    println!("\n🔒 Mutexes Created ({}):", mutexes.len());
                    for mutex in mutexes.iter().take(3) {
                        println!("  • {}", mutex);
                    }
                }
            }

            if let Some(dns_lookups) = &summary.data.dns_lookups {
                if !dns_lookups.is_empty() {
                    println!("\n🌐 DNS Lookups ({}):", dns_lookups.len());
                    for lookup in dns_lookups {
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

            if let Some(ip_traffic) = &summary.data.ip_traffic {
                if !ip_traffic.is_empty() {
                    println!("\n📡 Network Traffic ({} connections):", ip_traffic.len());
                    for traffic in ip_traffic.iter().take(5) {
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
                }
            }

            if let Some(http_convos) = &summary.data.http_conversations {
                if !http_convos.is_empty() {
                    println!("\n🌐 HTTP Conversations ({}):", http_convos.len());
                    for convo in http_convos.iter().take(3) {
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
                }
            }

            if let Some(commands) = &summary.data.command_executions {
                if !commands.is_empty() {
                    println!("\n💻 Commands Executed ({}):", commands.len());
                    for cmd in commands.iter().take(5) {
                        println!("  • {}", cmd);
                    }
                }
            }

            if let Some(tags) = &summary.data.tags {
                if !tags.is_empty() {
                    println!("\n🏷️ Behavioral Tags:");
                    for tag in tags {
                        println!("  • {}", tag);
                    }
                }
            }

            if let Some(mitre_techniques) = &summary.data.mitre_attack_techniques {
                if !mitre_techniques.is_empty() {
                    println!("\n⚔️ MITRE ATT&CK Techniques:");
                    for technique in mitre_techniques.iter().take(5) {
                        println!(
                            "  • {} - {}",
                            technique.id.as_ref().unwrap_or(&"Unknown".to_string()),
                            technique.name.as_ref().unwrap_or(&"Unknown".to_string())
                        );
                        if let Some(desc) = &technique.description {
                            let preview = if desc.len() > 80 {
                                format!("{}...", &desc[..80])
                            } else {
                                desc.clone()
                            };
                            println!("    {}", preview);
                        }
                    }
                }
            }

            if let Some(sigma_results) = &summary.data.sigma_analysis_results {
                if !sigma_results.is_empty() {
                    println!("\n🎯 Sigma Rule Matches ({}):", sigma_results.len());
                    for result in sigma_results.iter().take(3) {
                        if let Some(title) = &result.rule_title {
                            println!("  • {}", title);
                            if let Some(level) = &result.rule_level {
                                println!("    Level: {}", level);
                            }
                        }
                    }
                }
            }
        }
        Err(e) => {
            println!("❌ Error fetching behavior summary: {}", e);
            println!("\n💡 Note: Behavior summary may not be available for all files.");
            println!("   Files need to have been analyzed in a sandbox environment.");
        }
    }

    println!("\n{}", "=".repeat(60));
    println!("✅ Analysis Complete!");
    println!("{}", "=".repeat(60));

    Ok(())
}
