//! Display helper functions and utilities
//!
//! This module provides helper functions for creating display options
//! and other display-related utilities.

use super::types::DisplayOptions;

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
