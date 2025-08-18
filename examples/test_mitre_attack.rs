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
    println!("⚔️ MITRE ATT&CK TECHNIQUES ANALYSIS");
    println!("{}", "=".repeat(60));
    println!("\nFile: 7z.dll (SHA256: {}...)", &dll_hash[..32]);

    // Get MITRE ATT&CK techniques
    println!("\n📊 Fetching MITRE ATT&CK techniques tree...");
    match client.files().get_mitre_attack_techniques(dll_hash).await {
        Ok(mitre_trees) => {
            println!("✅ MITRE ATT&CK data retrieved!");

            // Iterate through each sandbox's results
            for (sandbox_name, sandbox_data) in &mitre_trees.data {
                println!("\n{}", "=".repeat(60));
                println!("🖥️ SANDBOX: {}", sandbox_name);
                println!("{}", "=".repeat(60));

                if sandbox_data.tactics.is_empty() {
                    println!("  ℹ️ No tactics observed in this sandbox");
                    continue;
                }

                println!("  Found {} tactics", sandbox_data.tactics.len());

                // Display each tactic
                for tactic in &sandbox_data.tactics {
                    println!("\n  🎯 TACTIC: {} ({})", tactic.name, tactic.id);
                    println!("     Link: {}", tactic.link);

                    // Show tactic description (truncated)
                    let desc_preview = if tactic.description.len() > 200 {
                        format!("{}...", &tactic.description[..200].replace('\n', " "))
                    } else {
                        tactic.description.replace('\n', " ")
                    };
                    println!("     Description: {}", desc_preview);

                    println!("\n     📌 Techniques ({}):", tactic.techniques.len());

                    // Display each technique
                    for technique in &tactic.techniques {
                        println!("\n       🔸 {} - {}", technique.id, technique.name);
                        println!("          Link: {}", technique.link);

                        // Show technique description (truncated)
                        let tech_desc = if technique.description.len() > 150 {
                            format!("{}...", &technique.description[..150].replace('\n', " "))
                        } else {
                            technique.description.replace('\n', " ")
                        };
                        println!("          Description: {}", tech_desc);

                        // Show signatures
                        if !technique.signatures.is_empty() {
                            println!("\n          🔍 Signatures:");
                            for sig in &technique.signatures {
                                let severity_emoji = match sig.severity {
                                    virustotal_rs::files::MitreSeverity::High => "🔴",
                                    virustotal_rs::files::MitreSeverity::Medium => "🟠",
                                    virustotal_rs::files::MitreSeverity::Low => "🟡",
                                    virustotal_rs::files::MitreSeverity::Info => "🔵",
                                    virustotal_rs::files::MitreSeverity::Unknown => "⚪",
                                };
                                println!(
                                    "             {} {:?}: {}",
                                    severity_emoji, sig.severity, sig.description
                                );
                            }
                        }
                    }
                }
            }

            // Summary statistics
            println!("\n{}", "=".repeat(60));
            println!("📊 SUMMARY");
            println!("{}", "=".repeat(60));

            let total_sandboxes = mitre_trees.data.len();
            let sandboxes_with_tactics = mitre_trees
                .data
                .values()
                .filter(|sd| !sd.tactics.is_empty())
                .count();

            println!("  • Total sandboxes analyzed: {}", total_sandboxes);
            println!("  • Sandboxes with detections: {}", sandboxes_with_tactics);

            // Collect all unique tactics and techniques
            let mut unique_tactics = std::collections::HashSet::new();
            let mut unique_techniques = std::collections::HashSet::new();
            let mut high_severity_count = 0;
            let mut medium_severity_count = 0;
            let mut low_severity_count = 0;
            let mut info_severity_count = 0;

            for sandbox_data in mitre_trees.data.values() {
                for tactic in &sandbox_data.tactics {
                    unique_tactics.insert(&tactic.id);
                    for technique in &tactic.techniques {
                        unique_techniques.insert(&technique.id);
                        for sig in &technique.signatures {
                            match sig.severity {
                                virustotal_rs::files::MitreSeverity::High => {
                                    high_severity_count += 1
                                }
                                virustotal_rs::files::MitreSeverity::Medium => {
                                    medium_severity_count += 1
                                }
                                virustotal_rs::files::MitreSeverity::Low => low_severity_count += 1,
                                virustotal_rs::files::MitreSeverity::Info => {
                                    info_severity_count += 1
                                }
                                virustotal_rs::files::MitreSeverity::Unknown => {}
                            }
                        }
                    }
                }
            }

            println!("  • Unique tactics observed: {}", unique_tactics.len());
            println!(
                "  • Unique techniques observed: {}",
                unique_techniques.len()
            );

            if high_severity_count
                + medium_severity_count
                + low_severity_count
                + info_severity_count
                > 0
            {
                println!("\n  🔍 Signature Severities:");
                if high_severity_count > 0 {
                    println!("     🔴 HIGH: {}", high_severity_count);
                }
                if medium_severity_count > 0 {
                    println!("     🟠 MEDIUM: {}", medium_severity_count);
                }
                if low_severity_count > 0 {
                    println!("     🟡 LOW: {}", low_severity_count);
                }
                if info_severity_count > 0 {
                    println!("     🔵 INFO: {}", info_severity_count);
                }
            }

            // Display links if available
            if let Some(links) = &mitre_trees.links {
                if let Some(self_link) = &links.self_link {
                    println!("\n  📎 API Link: {}", self_link);
                }
            }
        }
        Err(e) => {
            println!("❌ Error fetching MITRE ATT&CK techniques: {}", e);
            println!("\n💡 Note: MITRE ATT&CK data may not be available for all files.");
            println!("   Files need to have been analyzed in a sandbox environment.");
        }
    }

    println!("\n{}", "=".repeat(60));
    println!("✅ Analysis Complete!");
    println!("{}", "=".repeat(60));

    Ok(())
}
