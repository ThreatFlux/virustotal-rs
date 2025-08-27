use std::env;
use virustotal_rs::files::{MitreSignature, SandboxMitreData};
use virustotal_rs::{ApiTier, ClientBuilder};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = setup_client()?;
    let dll_hash = "02032ea322036e66f2825a0342979ad942ad5e201a674dc1c0085617467d661c";

    print_header(dll_hash);
    test_mitre_attack_techniques(&client, dll_hash).await;

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
    println!("⚔️ MITRE ATT&CK TECHNIQUES ANALYSIS");
    println!("{}", "=".repeat(60));
    println!("\nFile: 7z.dll (SHA256: {}...)", &dll_hash[..32]);
}

/// Test MITRE ATT&CK techniques analysis
async fn test_mitre_attack_techniques(client: &virustotal_rs::Client, dll_hash: &str) {
    println!("\n📊 Fetching MITRE ATT&CK techniques tree...");

    match fetch_mitre_techniques(client, dll_hash).await {
        Ok(mitre_trees) => {
            println!("✅ MITRE ATT&CK data retrieved!");
            process_mitre_data(&mitre_trees);
            print_summary(&mitre_trees);
        }
        Err(e) => print_error(&e),
    }

    print_completion();
}

/// Fetch MITRE ATT&CK techniques
async fn fetch_mitre_techniques(
    client: &virustotal_rs::Client,
    dll_hash: &str,
) -> Result<virustotal_rs::MitreTrees, virustotal_rs::Error> {
    client.files().get_mitre_attack_techniques(dll_hash).await
}

/// Process and display MITRE data
fn process_mitre_data(mitre_trees: &virustotal_rs::MitreTrees) {
    for (sandbox_name, sandbox_data) in &mitre_trees.data {
        display_sandbox_header(sandbox_name);

        if sandbox_data.tactics.is_empty() {
            println!("  ℹ️ No tactics observed in this sandbox");
            continue;
        }

        display_sandbox_tactics(sandbox_data);
    }
}

/// Display sandbox header
fn display_sandbox_header(sandbox_name: &str) {
    println!("\n{}", "=".repeat(60));
    println!("🖥️ SANDBOX: {}", sandbox_name);
    println!("{}", "=".repeat(60));
}

/// Display sandbox tactics
fn display_sandbox_tactics(sandbox_data: &SandboxMitreData) {
    println!("  Found {} tactics", sandbox_data.tactics.len());

    for tactic in &sandbox_data.tactics {
        display_tactic_info(tactic);
        display_tactic_techniques(tactic);
    }
}

/// Display tactic information
fn display_tactic_info(tactic: &virustotal_rs::MitreTactic) {
    println!("\n  🎯 TACTIC: {} ({})", tactic.name, tactic.id);
    println!("     Link: {}", tactic.link);

    let desc_preview = create_description_preview(&tactic.description, 200);
    println!("     Description: {}", desc_preview);

    println!("\n     📌 Techniques ({}):", tactic.techniques.len());
}

/// Create description preview with truncation
fn create_description_preview(description: &str, max_len: usize) -> String {
    if description.len() > max_len {
        format!("{}...", &description[..max_len].replace('\n', " "))
    } else {
        description.replace('\n', " ")
    }
}

/// Display tactic techniques
fn display_tactic_techniques(tactic: &virustotal_rs::MitreTactic) {
    for technique in &tactic.techniques {
        display_technique_info(technique);
        display_technique_signatures(technique);
    }
}

/// Display technique information
fn display_technique_info(technique: &virustotal_rs::MitreTechnique) {
    println!("\n       🔸 {} - {}", technique.id, technique.name);
    println!("          Link: {}", technique.link);

    let tech_desc = create_description_preview(&technique.description, 150);
    println!("          Description: {}", tech_desc);
}

/// Display technique signatures
fn display_technique_signatures(technique: &virustotal_rs::MitreTechnique) {
    if !technique.signatures.is_empty() {
        println!("\n          🔍 Signatures:");
        for sig in &technique.signatures {
            display_signature(sig);
        }
    }
}

/// Display individual signature
fn display_signature(sig: &MitreSignature) {
    let severity_emoji = get_severity_emoji(&sig.severity);
    println!(
        "             {} {:?}: {}",
        severity_emoji, sig.severity, sig.description
    );
}

/// Get emoji for severity level
fn get_severity_emoji(severity: &virustotal_rs::files::MitreSeverity) -> &'static str {
    match severity {
        virustotal_rs::files::MitreSeverity::High => "🔴",
        virustotal_rs::files::MitreSeverity::Medium => "🟠",
        virustotal_rs::files::MitreSeverity::Low => "🟡",
        virustotal_rs::files::MitreSeverity::Info => "🔵",
        virustotal_rs::files::MitreSeverity::Unknown => "⚪",
    }
}

/// Print summary statistics
fn print_summary(mitre_trees: &virustotal_rs::MitreTrees) {
    println!("\n{}", "=".repeat(60));
    println!("📊 SUMMARY");
    println!("{}", "=".repeat(60));

    let stats = calculate_summary_stats(mitre_trees);
    display_summary_stats(&stats);
    display_severity_counts(&stats);
    display_api_links(mitre_trees);
}

/// Calculate summary statistics
fn calculate_summary_stats(mitre_trees: &virustotal_rs::MitreTrees) -> SummaryStats {
    let total_sandboxes = mitre_trees.data.len();
    let sandboxes_with_tactics = mitre_trees
        .data
        .values()
        .filter(|sd| !sd.tactics.is_empty())
        .count();

    let mut stats = SummaryStats {
        total_sandboxes,
        sandboxes_with_tactics,
        unique_tactics: std::collections::HashSet::new(),
        unique_techniques: std::collections::HashSet::new(),
        high_severity_count: 0,
        medium_severity_count: 0,
        low_severity_count: 0,
        info_severity_count: 0,
    };

    collect_tactics_and_techniques(mitre_trees, &mut stats);
    stats
}

/// Collect tactics and techniques statistics
fn collect_tactics_and_techniques(
    mitre_trees: &virustotal_rs::MitreTrees,
    stats: &mut SummaryStats,
) {
    for sandbox_data in mitre_trees.data.values() {
        for tactic in &sandbox_data.tactics {
            stats.unique_tactics.insert(&tactic.id);
            for technique in &tactic.techniques {
                stats.unique_techniques.insert(&technique.id);
                count_signature_severities(technique, stats);
            }
        }
    }
}

/// Count signature severities
fn count_signature_severities(technique: &virustotal_rs::MitreTechnique, stats: &mut SummaryStats) {
    for sig in &technique.signatures {
        match sig.severity {
            virustotal_rs::files::MitreSeverity::High => stats.high_severity_count += 1,
            virustotal_rs::files::MitreSeverity::Medium => stats.medium_severity_count += 1,
            virustotal_rs::files::MitreSeverity::Low => stats.low_severity_count += 1,
            virustotal_rs::files::MitreSeverity::Info => stats.info_severity_count += 1,
            virustotal_rs::files::MitreSeverity::Unknown => {}
        }
    }
}

/// Display summary statistics
fn display_summary_stats(stats: &SummaryStats) {
    println!("  • Total sandboxes analyzed: {}", stats.total_sandboxes);
    println!(
        "  • Sandboxes with detections: {}",
        stats.sandboxes_with_tactics
    );
    println!(
        "  • Unique tactics observed: {}",
        stats.unique_tactics.len()
    );
    println!(
        "  • Unique techniques observed: {}",
        stats.unique_techniques.len()
    );
}

/// Display severity counts
fn display_severity_counts(stats: &SummaryStats) {
    let total_severities = stats.high_severity_count
        + stats.medium_severity_count
        + stats.low_severity_count
        + stats.info_severity_count;

    if total_severities > 0 {
        println!("\n  🔍 Signature Severities:");
        if stats.high_severity_count > 0 {
            println!("     🔴 HIGH: {}", stats.high_severity_count);
        }
        if stats.medium_severity_count > 0 {
            println!("     🟠 MEDIUM: {}", stats.medium_severity_count);
        }
        if stats.low_severity_count > 0 {
            println!("     🟡 LOW: {}", stats.low_severity_count);
        }
        if stats.info_severity_count > 0 {
            println!("     🔵 INFO: {}", stats.info_severity_count);
        }
    }
}

/// Display API links if available
fn display_api_links(mitre_trees: &virustotal_rs::MitreTrees) {
    if let Some(links) = &mitre_trees.links {
        if let Some(self_link) = &links.self_link {
            println!("\n  📎 API Link: {}", self_link);
        }
    }
}

/// Print error message
fn print_error(error: &virustotal_rs::Error) {
    println!("❌ Error fetching MITRE ATT&CK techniques: {}", error);
    println!("\n💡 Note: MITRE ATT&CK data may not be available for all files.");
    println!("   Files need to have been analyzed in a sandbox environment.");
}

/// Print completion message
fn print_completion() {
    println!("\n{}", "=".repeat(60));
    println!("✅ Analysis Complete!");
    println!("{}", "=".repeat(60));
}

/// Summary statistics structure
struct SummaryStats {
    total_sandboxes: usize,
    sandboxes_with_tactics: usize,
    unique_tactics: std::collections::HashSet<String>,
    unique_techniques: std::collections::HashSet<String>,
    high_severity_count: usize,
    medium_severity_count: usize,
    low_severity_count: usize,
    info_severity_count: usize,
}
