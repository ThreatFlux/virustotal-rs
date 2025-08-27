//! Data formatting utilities
//!
//! This module provides functions for formatting various types of data
//! into human-readable formats.

use chrono::{DateTime, Utc};

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
