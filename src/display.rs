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

use crate::common::{AnalysisStats, VoteStats};
use chrono::{DateTime, Utc};
use serde_json::Value;
use std::collections::HashMap;
use std::fmt;

// ============================================================================
// Display Traits
// ============================================================================

/// Trait for displaying analysis statistics in various formats
///
/// This trait provides standardized methods for displaying VirusTotal analysis statistics
/// across different contexts and with varying levels of detail.
pub trait DisplayStats {
    /// Display a concise summary of the analysis statistics
    fn display_summary(&self) -> String;

    /// Display detailed analysis statistics with percentages
    fn display_detailed(&self) -> String;

    /// Display analysis statistics with custom formatting
    fn display_formatted(&self, prefix: &str, show_percentages: bool) -> String;

    /// Get the detection rate as a percentage
    fn detection_rate(&self) -> f64;

    /// Check if the analysis shows malicious results
    fn is_malicious(&self) -> bool;

    /// Check if the analysis shows suspicious results
    fn is_suspicious(&self) -> bool;

    /// Get the total number of engines that analyzed
    fn total_engines(&self) -> u32;

    /// Get a threat level assessment
    fn threat_level(&self) -> ThreatLevel;
}

/// Trait for displaying voting statistics
pub trait DisplayVotes {
    /// Display vote statistics in a summary format
    fn display_summary(&self) -> String;

    /// Display detailed vote statistics with percentages
    fn display_detailed(&self) -> String;

    /// Get the vote ratio (harmless vs malicious)
    fn vote_ratio(&self) -> f64;

    /// Get the community consensus
    fn consensus(&self) -> VoteConsensus;
}

/// Trait for displaying detailed object information
pub trait DisplayDetails {
    /// Display a brief summary suitable for lists
    fn display_brief(&self) -> String;

    /// Display comprehensive details
    fn display_full(&self) -> String;

    /// Display with custom formatting options
    fn display_with_options(&self, options: &DisplayOptions) -> String;
}

// ============================================================================
// Enums and Structs
// ============================================================================

/// Threat level assessment based on analysis results
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ThreatLevel {
    /// No threats detected
    Clean,
    /// Low threat level (few suspicious detections)
    Low,
    /// Medium threat level (some malicious detections)
    Medium,
    /// High threat level (many malicious detections)
    High,
    /// Critical threat level (overwhelming malicious consensus)
    Critical,
}

/// Community vote consensus
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VoteConsensus {
    /// Strong harmless consensus
    StronglyHarmless,
    /// Leaning harmless
    LeaningHarmless,
    /// Mixed opinions
    Mixed,
    /// Leaning malicious  
    LeaningMalicious,
    /// Strong malicious consensus
    StronglyMalicious,
    /// No votes available
    NoConsensus,
}

/// Display formatting options
#[derive(Debug, Clone, Default)]
pub struct DisplayOptions {
    /// Include timestamps in output
    pub show_timestamps: bool,
    /// Include detailed statistics
    pub show_detailed_stats: bool,
    /// Maximum width for text truncation
    pub max_width: Option<usize>,
    /// Prefix for each line
    pub prefix: String,
    /// Use colored output (for terminal display)
    pub use_colors: bool,
    /// Show percentage values
    pub show_percentages: bool,
}

// ============================================================================
// Trait Implementations
// ============================================================================

// Helper functions for AnalysisStats
impl AnalysisStats {
    /// Append core detection categories to the result string
    fn append_core_detections(&self, result: &mut String, total: u32) {
        if self.malicious > 0 {
            let pct = (self.malicious as f64 / total as f64) * 100.0;
            result.push_str(&format!(
                "  ❌ Malicious: {} ({:.1}%)\n",
                self.malicious, pct
            ));
        }

        if self.suspicious > 0 {
            let pct = (self.suspicious as f64 / total as f64) * 100.0;
            result.push_str(&format!(
                "  ⚠️  Suspicious: {} ({:.1}%)\n",
                self.suspicious, pct
            ));
        }

        if self.harmless > 0 {
            let pct = (self.harmless as f64 / total as f64) * 100.0;
            result.push_str(&format!("  ✅ Harmless: {} ({:.1}%)\n", self.harmless, pct));
        }

        if self.undetected > 0 {
            let pct = (self.undetected as f64 / total as f64) * 100.0;
            result.push_str(&format!(
                "  ⚪ Undetected: {} ({:.1}%)\n",
                self.undetected, pct
            ));
        }

        if self.timeout > 0 {
            let pct = (self.timeout as f64 / total as f64) * 100.0;
            result.push_str(&format!("  ⏱️  Timeout: {} ({:.1}%)\n", self.timeout, pct));
        }
    }

    /// Append optional detection categories to the result string
    fn append_optional_detections(&self, result: &mut String, total: u32) {
        if let Some(failure) = self.failure {
            if failure > 0 {
                let pct = (failure as f64 / total as f64) * 100.0;
                result.push_str(&format!("  💥 Failure: {} ({:.1}%)\n", failure, pct));
            }
        }

        if let Some(confirmed_timeout) = self.confirmed_timeout {
            if confirmed_timeout > 0 {
                let pct = (confirmed_timeout as f64 / total as f64) * 100.0;
                result.push_str(&format!(
                    "  ⏲️  Confirmed Timeout: {} ({:.1}%)\n",
                    confirmed_timeout, pct
                ));
            }
        }

        if let Some(type_unsupported) = self.type_unsupported {
            if type_unsupported > 0 {
                let pct = (type_unsupported as f64 / total as f64) * 100.0;
                result.push_str(&format!(
                    "  🚫 Unsupported: {} ({:.1}%)\n",
                    type_unsupported, pct
                ));
            }
        }
    }

    /// Append the overall detection rate to the result string
    fn append_detection_rate(&self, result: &mut String) {
        let detection_rate = self.detection_rate();
        if detection_rate > 0.0 {
            result.push_str(&format!(
                "\n🚨 Overall Detection Rate: {:.1}%",
                detection_rate
            ));
        }
    }

    /// Add a formatted category to the result string
    fn add_formatted_category(
        &self,
        result: &mut String,
        category: &str,
        count: u32,
        total: u32,
        prefix: &str,
        show_percentages: bool,
    ) {
        if count > 0 {
            if show_percentages {
                let pct = (count as f64 / total as f64) * 100.0;
                result.push_str(&format!(
                    "{}{}: {} ({:.1}%)\n",
                    prefix, category, count, pct
                ));
            } else {
                result.push_str(&format!("{}{}: {}\n", prefix, category, count));
            }
        }
    }
}

impl DisplayStats for AnalysisStats {
    fn display_summary(&self) -> String {
        let total = self.total_engines();
        let threats = self.malicious + self.suspicious;

        if threats == 0 {
            format!("Clean ({} engines)", total)
        } else {
            format!("{}/{} engines detected threats", threats, total)
        }
    }

    fn display_detailed(&self) -> String {
        let total = self.total_engines();
        let mut result = String::new();

        result.push_str(&format!("Analysis Results ({} engines):\n", total));

        // Add core detection categories
        self.append_core_detections(&mut result, total);

        // Add optional categories
        self.append_optional_detections(&mut result, total);

        // Add overall detection rate
        self.append_detection_rate(&mut result);

        result.trim_end().to_string()
    }

    fn display_formatted(&self, prefix: &str, show_percentages: bool) -> String {
        let total = self.total_engines();
        let mut result = String::new();

        // Add each category using helper function
        self.add_formatted_category(
            &mut result,
            "Malicious",
            self.malicious,
            total,
            prefix,
            show_percentages,
        );
        self.add_formatted_category(
            &mut result,
            "Suspicious",
            self.suspicious,
            total,
            prefix,
            show_percentages,
        );
        self.add_formatted_category(
            &mut result,
            "Harmless",
            self.harmless,
            total,
            prefix,
            show_percentages,
        );
        self.add_formatted_category(
            &mut result,
            "Undetected",
            self.undetected,
            total,
            prefix,
            show_percentages,
        );
        self.add_formatted_category(
            &mut result,
            "Timeout",
            self.timeout,
            total,
            prefix,
            show_percentages,
        );

        result.trim_end().to_string()
    }

    fn detection_rate(&self) -> f64 {
        let total = self.total_engines();
        if total == 0 {
            0.0
        } else {
            ((self.malicious + self.suspicious) as f64 / total as f64) * 100.0
        }
    }

    fn is_malicious(&self) -> bool {
        self.malicious > 0
    }

    fn is_suspicious(&self) -> bool {
        self.suspicious > 0
    }

    fn total_engines(&self) -> u32 {
        self.harmless
            + self.malicious
            + self.suspicious
            + self.undetected
            + self.timeout
            + self.failure.unwrap_or(0)
            + self.confirmed_timeout.unwrap_or(0)
            + self.type_unsupported.unwrap_or(0)
    }

    fn threat_level(&self) -> ThreatLevel {
        let total = self.total_engines();
        if total == 0 {
            return ThreatLevel::Clean;
        }

        let malicious_rate = (self.malicious as f64 / total as f64) * 100.0;
        let threat_rate = ((self.malicious + self.suspicious) as f64 / total as f64) * 100.0;

        if malicious_rate >= 50.0 {
            ThreatLevel::Critical
        } else if malicious_rate >= 20.0 {
            ThreatLevel::High
        } else if threat_rate >= 10.0 {
            ThreatLevel::Medium
        } else if threat_rate > 0.0 {
            ThreatLevel::Low
        } else {
            ThreatLevel::Clean
        }
    }
}

impl DisplayVotes for VoteStats {
    fn display_summary(&self) -> String {
        let total = self.harmless + self.malicious;
        if total == 0 {
            "No votes".to_string()
        } else {
            format!("{} votes ({}👍 {}👎)", total, self.harmless, self.malicious)
        }
    }

    fn display_detailed(&self) -> String {
        let total = self.harmless + self.malicious;
        if total == 0 {
            "No community votes available".to_string()
        } else {
            let harmless_pct = (self.harmless as f64 / total as f64) * 100.0;
            let malicious_pct = (self.malicious as f64 / total as f64) * 100.0;

            format!(
                "Community Votes ({} total):\n  ✅ Harmless: {} ({:.1}%)\n  ❌ Malicious: {} ({:.1}%)",
                total, self.harmless, harmless_pct, self.malicious, malicious_pct
            )
        }
    }

    fn vote_ratio(&self) -> f64 {
        if self.malicious == 0 {
            f64::INFINITY
        } else {
            self.harmless as f64 / self.malicious as f64
        }
    }

    fn consensus(&self) -> VoteConsensus {
        let total = self.harmless + self.malicious;
        if total == 0 {
            return VoteConsensus::NoConsensus;
        }

        let harmless_pct = (self.harmless as f64 / total as f64) * 100.0;

        if harmless_pct >= 80.0 {
            VoteConsensus::StronglyHarmless
        } else if harmless_pct >= 60.0 {
            VoteConsensus::LeaningHarmless
        } else if harmless_pct >= 40.0 {
            VoteConsensus::Mixed
        } else if harmless_pct >= 20.0 {
            VoteConsensus::LeaningMalicious
        } else {
            VoteConsensus::StronglyMalicious
        }
    }
}

// ============================================================================
// Formatting Utilities
// ============================================================================

/// Format file size in human-readable format
///
/// Converts byte sizes to human-readable format using appropriate units (B, KB, MB, GB, TB).
///
/// # Arguments
///
/// * `bytes` - Size in bytes
///
/// # Returns
///
/// Formatted string with appropriate unit
///
/// # Examples
///
/// ```rust
/// use virustotal_rs::display::format_file_size;
///
/// assert_eq!(format_file_size(1024), "1.0 KB");
/// assert_eq!(format_file_size(1048576), "1.0 MB");
/// assert_eq!(format_file_size(500), "500 B");
/// ```
pub fn format_file_size(bytes: u64) -> String {
    const UNITS: &[&str] = &["B", "KB", "MB", "GB", "TB", "PB"];
    let mut size = bytes as f64;
    let mut unit_index = 0;

    while size >= 1024.0 && unit_index < UNITS.len() - 1 {
        size /= 1024.0;
        unit_index += 1;
    }

    if unit_index == 0 {
        format!("{} {}", bytes, UNITS[unit_index])
    } else {
        format!("{:.1} {}", size, UNITS[unit_index])
    }
}

/// Format timestamp as human-readable date/time
///
/// Converts Unix timestamps to human-readable format.
///
/// # Arguments
///
/// * `timestamp` - Unix timestamp in seconds
///
/// # Returns
///
/// Formatted date string
///
/// # Examples
///
/// ```rust
/// use virustotal_rs::display::format_timestamp;
///
/// let formatted = format_timestamp(1609459200); // 2021-01-01 00:00:00 UTC
/// assert!(formatted.contains("2021"));
/// ```
pub fn format_timestamp(timestamp: i64) -> String {
    if let Some(dt) = DateTime::from_timestamp(timestamp, 0) {
        dt.format("%Y-%m-%d %H:%M:%S UTC").to_string()
    } else {
        format!("Invalid timestamp: {}", timestamp)
    }
}

/// Format timestamp as relative time (e.g., "2 hours ago")
///
/// Converts Unix timestamps to relative time format.
///
/// # Arguments
///
/// * `timestamp` - Unix timestamp in seconds
///
/// # Returns
///
/// Formatted relative time string
///
/// # Examples
///
/// ```rust
/// use virustotal_rs::display::format_timestamp_relative;
/// use chrono::Utc;
///
/// let one_hour_ago = Utc::now().timestamp() - 3600;
/// let formatted = format_timestamp_relative(one_hour_ago);
/// assert!(formatted.contains("hour"));
/// ```
pub fn format_timestamp_relative(timestamp: i64) -> String {
    if let Some(dt) = DateTime::from_timestamp(timestamp, 0) {
        let now = Utc::now();
        let duration = now.signed_duration_since(dt);

        if duration.num_days() > 0 {
            format!("{} days ago", duration.num_days())
        } else if duration.num_hours() > 0 {
            format!("{} hours ago", duration.num_hours())
        } else if duration.num_minutes() > 0 {
            format!("{} minutes ago", duration.num_minutes())
        } else if duration.num_seconds() > 0 {
            format!("{} seconds ago", duration.num_seconds())
        } else {
            "just now".to_string()
        }
    } else {
        format!("Invalid timestamp: {}", timestamp)
    }
}

/// Truncate hash or ID for display
///
/// Truncates long hashes or IDs for more readable display.
///
/// # Arguments
///
/// * `hash` - Hash or ID string to truncate
/// * `length` - Maximum length (default: 16)
///
/// # Returns
///
/// Truncated hash with ellipsis if truncated
///
/// # Examples
///
/// ```rust
/// use virustotal_rs::display::truncate_hash;
///
/// let hash = "02032ea322036e66f2825a0342979ad942ad5e201a674dc1c0085617467d661c";
/// assert_eq!(truncate_hash(hash, Some(16)), "02032ea322036e66...");
/// assert_eq!(truncate_hash("short", Some(16)), "short");
/// ```
pub fn truncate_hash(hash: &str, length: Option<usize>) -> String {
    let max_len = length.unwrap_or(16);
    if hash.len() <= max_len {
        hash.to_string()
    } else {
        format!("{}...", &hash[..max_len])
    }
}

/// Truncate text for display
///
/// Generic text truncation with customizable length and ellipsis.
///
/// # Arguments
///
/// * `text` - Text to truncate
/// * `max_length` - Maximum length before truncation
///
/// # Returns
///
/// Truncated text with ellipsis if truncated
///
/// # Examples
///
/// ```rust
/// use virustotal_rs::display::truncate_text;
///
/// assert_eq!(truncate_text("This is a long comment", 10), "This is...");
/// assert_eq!(truncate_text("Short", 10), "Short");
/// ```
pub fn truncate_text(text: &str, max_length: usize) -> String {
    if text.len() <= max_length {
        text.to_string()
    } else {
        let truncated: String = text.chars().take(max_length.saturating_sub(3)).collect();
        format!("{}...", truncated)
    }
}

/// Format reputation score with descriptive text
///
/// Converts numerical reputation scores to descriptive format.
///
/// # Arguments
///
/// * `reputation` - Reputation score (typically -100 to 100)
///
/// # Returns
///
/// Formatted reputation string with description
///
/// # Examples
///
/// ```rust
/// use virustotal_rs::display::format_reputation;
///
/// assert_eq!(format_reputation(80), "80 (Excellent)");
/// assert_eq!(format_reputation(-50), "-50 (Bad)");
/// assert_eq!(format_reputation(0), "0 (Neutral)");
/// ```
pub fn format_reputation(reputation: i32) -> String {
    let description = match reputation {
        r if r >= 75 => "Excellent",
        r if r >= 50 => "Good",
        r if r >= 25 => "Fair",
        r if r >= 0 => "Neutral",
        r if r >= -25 => "Poor",
        r if r >= -50 => "Bad",
        _ => "Terrible",
    };

    format!("{} ({})", reputation, description)
}

// ============================================================================
// JSON and Structured Data Utilities
// ============================================================================

/// Pretty print JSON value with indentation
///
/// Formats JSON values for readable display.
///
/// # Arguments
///
/// * `value` - JSON value to format
///
/// # Returns
///
/// Formatted JSON string
///
/// # Examples
///
/// ```rust
/// use virustotal_rs::display::pretty_print_json;
/// use serde_json::json;
///
/// let data = json!({"name": "test", "value": 42});
/// let formatted = pretty_print_json(&data);
/// assert!(formatted.contains("\"name\""));
/// ```
pub fn pretty_print_json(value: &Value) -> String {
    serde_json::to_string_pretty(value).unwrap_or_else(|_| "Invalid JSON".to_string())
}

/// Format key-value pairs as a table
///
/// Creates a formatted table from key-value pairs.
///
/// # Arguments
///
/// * `data` - HashMap of key-value pairs
/// * `title` - Optional table title
///
/// # Returns
///
/// Formatted table string
///
/// # Examples
///
/// ```rust
/// use virustotal_rs::display::format_table;
/// use std::collections::HashMap;
///
/// let mut data = HashMap::new();
/// data.insert("Name".to_string(), "Example File".to_string());
/// data.insert("Size".to_string(), "1024 bytes".to_string());
///
/// let table = format_table(&data, Some("File Information"));
/// assert!(table.contains("Name"));
/// assert!(table.contains("Example File"));
/// ```
pub fn format_table(data: &HashMap<String, String>, title: Option<&str>) -> String {
    let mut result = String::new();

    if let Some(t) = title {
        result.push_str(&format!("{}\n", t));
        result.push_str(&format!("{}\n", "-".repeat(t.len())));
    }

    let max_key_len = data.keys().map(|k| k.len()).max().unwrap_or(0);

    for (key, value) in data {
        result.push_str(&format!(
            "{:width$} : {}\n",
            key,
            value,
            width = max_key_len
        ));
    }

    result.trim_end().to_string()
}

/// Format a list with bullets and indentation
///
/// Creates a formatted bulleted list.
///
/// # Arguments
///
/// * `items` - Vector of items to display
/// * `bullet` - Bullet character/string (default: "•")
/// * `indent` - Indentation string (default: "  ")
///
/// # Returns
///
/// Formatted list string
///
/// # Examples
///
/// ```rust
/// use virustotal_rs::display::format_list;
///
/// let items = vec!["First item".to_string(), "Second item".to_string()];
/// let list = format_list(&items, Some("•"), Some("  "));
/// assert!(list.contains("• First item"));
/// ```
pub fn format_list(items: &[String], bullet: Option<&str>, indent: Option<&str>) -> String {
    let bullet_char = bullet.unwrap_or("•");
    let indent_str = indent.unwrap_or("  ");

    items
        .iter()
        .map(|item| format!("{}{} {}", indent_str, bullet_char, item))
        .collect::<Vec<_>>()
        .join("\n")
}

// ============================================================================
// Display Helper Functions
// ============================================================================

/// Create display options with common presets
///
/// Factory function for creating DisplayOptions with common configurations.
///
/// # Arguments
///
/// * `preset` - Preset name ("brief", "detailed", "table", "json")
///
/// # Returns
///
/// Configured DisplayOptions
///
/// # Examples
///
/// ```rust
/// use virustotal_rs::display::display_options;
///
/// let options = display_options("detailed");
/// assert!(options.show_detailed_stats);
/// ```
pub fn display_options(preset: &str) -> DisplayOptions {
    match preset {
        "brief" => DisplayOptions {
            show_timestamps: false,
            show_detailed_stats: false,
            max_width: Some(80),
            prefix: String::new(),
            use_colors: false,
            show_percentages: false,
        },
        "detailed" => DisplayOptions {
            show_timestamps: true,
            show_detailed_stats: true,
            max_width: None,
            prefix: "  ".to_string(),
            use_colors: false,
            show_percentages: true,
        },
        "table" => DisplayOptions {
            show_timestamps: true,
            show_detailed_stats: false,
            max_width: Some(120),
            prefix: String::new(),
            use_colors: false,
            show_percentages: false,
        },
        "json" => DisplayOptions {
            show_timestamps: true,
            show_detailed_stats: true,
            max_width: None,
            prefix: String::new(),
            use_colors: false,
            show_percentages: true,
        },
        _ => DisplayOptions::default(),
    }
}

// ============================================================================
// Display Implementation Helpers
// ============================================================================

impl fmt::Display for ThreatLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let text = match self {
            ThreatLevel::Clean => "Clean",
            ThreatLevel::Low => "Low Risk",
            ThreatLevel::Medium => "Medium Risk",
            ThreatLevel::High => "High Risk",
            ThreatLevel::Critical => "Critical Risk",
        };
        write!(f, "{}", text)
    }
}

impl fmt::Display for VoteConsensus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let text = match self {
            VoteConsensus::StronglyHarmless => "Strongly Harmless",
            VoteConsensus::LeaningHarmless => "Leaning Harmless",
            VoteConsensus::Mixed => "Mixed Opinions",
            VoteConsensus::LeaningMalicious => "Leaning Malicious",
            VoteConsensus::StronglyMalicious => "Strongly Malicious",
            VoteConsensus::NoConsensus => "No Consensus",
        };
        write!(f, "{}", text)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
