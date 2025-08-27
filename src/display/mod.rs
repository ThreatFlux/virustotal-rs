//! Display utilities for VirusTotal data types
//!
//! This module provides comprehensive display and formatting utilities to eliminate code duplication
//! across the VirusTotal library. It includes traits for consistent display of common data types,
//! formatting utilities for various data formats, and pretty-printing helpers.
//!
//! # Features
//!
//! - **Display Traits**: Standardized display interfaces for common VirusTotal data types
//! - **Pretty Printing**: JSON, table, and list formatting utilities
//! - **Data Formatting**: Human-readable formatting for file sizes, timestamps, and hashes
//! - **Statistical Display**: Specialized formatters for analysis stats and voting data
//!
//! # Examples
//!
//! ```rust
//! use virustotal_rs::display::{DisplayStats, format_file_size, format_timestamp};
//! use virustotal_rs::common::AnalysisStats;
//!
//! let stats = AnalysisStats {
//!     harmless: 45,
//!     malicious: 2,
//!     suspicious: 1,
//!     undetected: 12,
//!     timeout: 0,
//!     confirmed_timeout: None,
//!     failure: None,
//!     type_unsupported: None,
//! };
//!
//! // Display with trait
//! println!("{}", stats.display_summary());
//!
//! // Format file size
//! println!("Size: {}", format_file_size(1048576)); // "Size: 1.0 MB"
//! ```

pub mod traits;
pub mod types;
pub mod formatting;
pub mod structured;
pub mod implementations;
pub mod helpers;

// Re-export main public API
pub use traits::{DisplayStats, DisplayVotes, DisplayDetails};
pub use types::{ThreatLevel, VoteConsensus, DisplayOptions};
pub use formatting::{
    format_file_size, format_timestamp, format_timestamp_relative, 
    truncate_hash, truncate_text, format_reputation
};
pub use structured::{pretty_print_json, format_table, format_list};
pub use helpers::display_options;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::{AnalysisStats, VoteStats};
    use std::collections::HashMap;

    #[test]
    fn test_format_file_size() {
        assert_eq!(format_file_size(0), "0 B");
        assert_eq!(format_file_size(1023), "1023 B");
        assert_eq!(format_file_size(1024), "1.0 KB");
        assert_eq!(format_file_size(1048576), "1.0 MB");
        assert_eq!(format_file_size(1073741824), "1.0 GB");
        assert_eq!(format_file_size(1500), "1.5 KB");
    }

    #[test]
    fn test_truncate_hash() {
        let hash = "02032ea322036e66f2825a0342979ad942ad5e201a674dc1c0085617467d661c";
        assert_eq!(truncate_hash(hash, Some(16)), "02032ea322036e66...");
        assert_eq!(truncate_hash("short", Some(16)), "short");
        assert_eq!(truncate_hash(hash, None), "02032ea322036e66...");
    }

    #[test]
    fn test_truncate_text() {
        assert_eq!(
            truncate_text("This is a long comment that should be truncated", 10),
            "This is..."
        );
        assert_eq!(truncate_text("Short", 10), "Short");
        assert_eq!(truncate_text("", 10), "");
    }

    #[test]
    fn test_format_reputation() {
        assert_eq!(format_reputation(80), "80 (Excellent)");
        assert_eq!(format_reputation(60), "60 (Good)");
        assert_eq!(format_reputation(-50), "-50 (Bad)");
        assert_eq!(format_reputation(0), "0 (Neutral)");
        assert_eq!(format_reputation(90), "90 (Excellent)");
        assert_eq!(format_reputation(-80), "-80 (Terrible)");
    }

    #[test]
    fn test_analysis_stats_display() {
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

        assert_eq!(stats.display_summary(), "3/60 engines detected threats");
        assert!(stats.display_detailed().contains("Malicious: 2"));
        assert_eq!(stats.detection_rate(), 5.0);
        assert!(stats.is_malicious());
        assert!(stats.is_suspicious());
        assert_eq!(stats.total_engines(), 60);
        assert_eq!(stats.threat_level(), ThreatLevel::Low);
    }

    #[test]
    fn test_vote_stats_display() {
        let votes = VoteStats {
            harmless: 10,
            malicious: 2,
        };

        assert_eq!(votes.display_summary(), "12 votes (10👍 2👎)");
        assert!(votes.display_detailed().contains("Community Votes"));
        assert_eq!(votes.vote_ratio(), 5.0);
        assert_eq!(votes.consensus(), VoteConsensus::StronglyHarmless); // 10/12 = 83.3% >= 80%
    }

    #[test]
    fn test_vote_stats_no_votes() {
        let votes = VoteStats {
            harmless: 0,
            malicious: 0,
        };

        assert_eq!(votes.display_summary(), "No votes");
        assert_eq!(votes.consensus(), VoteConsensus::NoConsensus);
    }

    #[test]
    fn test_threat_levels() {
        let clean_stats = AnalysisStats {
            harmless: 50,
            malicious: 0,
            suspicious: 0,
            undetected: 10,
            timeout: 0,
            confirmed_timeout: None,
            failure: None,
            type_unsupported: None,
        };
        assert_eq!(clean_stats.threat_level(), ThreatLevel::Clean);

        let critical_stats = AnalysisStats {
            harmless: 20,
            malicious: 30,
            suspicious: 5,
            undetected: 5,
            timeout: 0,
            confirmed_timeout: None,
            failure: None,
            type_unsupported: None,
        };
        assert_eq!(critical_stats.threat_level(), ThreatLevel::Critical);
    }

    #[test]
    fn test_format_list() {
        let items = vec!["First item".to_string(), "Second item".to_string()];
        let list = format_list(&items, Some("•"), Some("  "));
        assert!(list.contains("• First item"));
        assert!(list.contains("• Second item"));

        let default_list = format_list(&items, None, None);
        assert!(default_list.contains("• First item"));
    }

    #[test]
    fn test_display_options() {
        let brief = display_options("brief");
        assert!(!brief.show_detailed_stats);
        assert_eq!(brief.max_width, Some(80));

        let detailed = display_options("detailed");
        assert!(detailed.show_detailed_stats);
        assert!(detailed.show_percentages);

        let default = display_options("unknown");
        assert!(!default.show_detailed_stats);
    }

    #[test]
    fn test_format_table() {
        let mut data = HashMap::new();
        data.insert("Name".to_string(), "Example File".to_string());
        data.insert("Size".to_string(), "1024 bytes".to_string());

        let table = format_table(&data, Some("File Information"));
        assert!(table.contains("File Information"));
        assert!(table.contains("Name"));
        assert!(table.contains("Example File"));

        let no_title_table = format_table(&data, None);
        assert!(!no_title_table.contains("File Information"));
    }
}