
/// Print analysis statistics in standardized format
pub fn print_analysis_stats(stats: &serde_json::Value, prefix: &str) {
    use virustotal_rs::{common::AnalysisStats, DisplayStats};

    if let Ok(analysis_stats) = serde_json::from_value::<AnalysisStats>(stats.clone()) {
        let formatted = analysis_stats.display_formatted(prefix, false);
        println!("{}", formatted);
    } else {
        print_fallback_stats(stats, prefix);
    }
}

/// Print fallback stats when conversion fails
pub fn print_fallback_stats(stats: &serde_json::Value, prefix: &str) {
    if let Some(malicious) = stats.get("malicious").and_then(|v| v.as_u64()) {
        println!("{}  - Malicious: {}", prefix, malicious);
    }
    if let Some(suspicious) = stats.get("suspicious").and_then(|v| v.as_u64()) {
        println!("{}  - Suspicious: {}", prefix, suspicious);
    }
    if let Some(undetected) = stats.get("undetected").and_then(|v| v.as_u64()) {
        println!("{}  - Undetected: {}", prefix, undetected);
    }
}

/// Print file information using display utilities
pub fn print_file_info(file: &serde_json::Value, prefix: &str) {
    use virustotal_rs::{format_file_size, format_reputation};

    if let Some(size) = file.get("size").and_then(|v| v.as_u64()) {
        println!("{}Size: {}", prefix, format_file_size(size));
    }
    if let Some(type_desc) = file.get("type_description").and_then(|v| v.as_str()) {
        println!("{}Type: {}", prefix, type_desc);
    }
    if let Some(reputation) = file.get("reputation").and_then(|v| v.as_i64()) {
        println!(
            "{}Reputation: {}",
            prefix,
            format_reputation(reputation as i32)
        );
    }
}