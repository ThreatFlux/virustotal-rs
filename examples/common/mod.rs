use virustotal_rs::common::AnalysisStats;
use virustotal_rs::{ApiTier, Client, ClientBuilder};

#[allow(dead_code)]
pub const SAMPLE_FILE_HASH: &str =
    "02032ea322036e66f2825a0342979ad942ad5e201a674dc1c0085617467d661c";

pub fn build_client_from_env(
    var: &str,
    tier: ApiTier,
) -> Result<Client, Box<dyn std::error::Error>> {
    let api_key =
        std::env::var(var).unwrap_or_else(|_| panic!("{} environment variable not set", var));
    println!("Using API key from {} environment variable", var);
    let client = ClientBuilder::new().api_key(api_key).tier(tier).build()?;
    Ok(client)
}

#[allow(dead_code)]
pub fn print_analysis_stats(label: &str, stats: &AnalysisStats) {
    println!("\n  {}:", label);
    println!("    Harmless: {}", stats.harmless);
    println!("    Malicious: {}", stats.malicious);
    println!("    Suspicious: {}", stats.suspicious);
    println!("    Undetected: {}", stats.undetected);
    println!("    Timeout: {}", stats.timeout);
}
