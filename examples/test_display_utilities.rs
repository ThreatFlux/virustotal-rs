use virustotal_rs::{
    common::{AnalysisStats, VoteStats},
    format_file_size, format_reputation, format_timestamp, pretty_print_json, truncate_hash,
    truncate_text, DisplayStats, DisplayVotes,
};

fn main() {
    println!("=== VirusTotal Display Utilities Demo ===\n");

    // Test analysis stats display
    let stats = AnalysisStats {
        harmless: 45,
        malicious: 2,
        suspicious: 1,
        undetected: 12,
        timeout: 0,
        confirmed_timeout: None,
        failure: None,
        type_unsupported: None,
    };

    println!("📊 Analysis Statistics:");
    println!("Summary: {}", stats.display_summary());
    println!("Threat Level: {}", stats.threat_level());
    println!("Detection Rate: {:.1}%", stats.detection_rate());
    println!("\nDetailed Analysis:");
    println!("{}\n", stats.display_detailed());

    // Test vote stats display
    let votes = VoteStats {
        harmless: 25,
        malicious: 5,
    };

    println!("🗳️  Vote Statistics:");
    println!("Summary: {}", votes.display_summary());
    println!("Consensus: {}", votes.consensus());
    println!("Detailed Votes:");
    println!("{}\n", votes.display_detailed());

    // Test file size formatting
    println!("📦 File Size Formatting:");
    let sizes = [512, 1024, 1048576, 2147483648, 1099511627776];
    for size in &sizes {
        println!("  {} bytes = {}", size, format_file_size(*size));
    }

    // Test reputation formatting
    println!("\n🏆 Reputation Formatting:");
    let reputations = [85, 65, 35, 0, -25, -60];
    for rep in &reputations {
        println!("  {}", format_reputation(*rep));
    }

    // Test timestamp formatting
    println!("\n⏰ Timestamp Formatting:");
    let timestamp = 1609459200; // 2021-01-01 00:00:00 UTC
    println!("  Unix {} = {}", timestamp, format_timestamp(timestamp));

    // Test hash truncation
    println!("\n🔢 Hash Truncation:");
    let hash = "02032ea322036e66f2825a0342979ad942ad5e201a674dc1c0085617467d661c";
    println!("  Original: {}", hash);
    println!("  Truncated (16): {}", truncate_hash(hash, Some(16)));
    println!("  Truncated (32): {}", truncate_hash(hash, Some(32)));

    // Test text truncation
    println!("\n✂️  Text Truncation:");
    let long_text = "This is a very long comment that demonstrates text truncation functionality in the display utilities module.";
    println!("  Original ({}): {}", long_text.len(), long_text);
    println!("  Truncated (50): {}", truncate_text(long_text, 50));

    // Test JSON pretty printing
    println!("\n🎨 JSON Pretty Printing:");
    let json_data = serde_json::json!({
        "file_id": "abc123",
        "analysis": {
            "malicious": 2,
            "harmless": 48,
            "reputation": 75
        },
        "metadata": {
            "size": 1048576,
            "type": "PE32 executable"
        }
    });

    println!("Pretty JSON:");
    println!("{}", pretty_print_json(&json_data));

    println!("\n✅ Display utilities demo completed!");
}
