//! Display traits for VirusTotal data types
//!
//! This module defines the core traits for displaying VirusTotal analysis data
//! in various formats with consistent interfaces.

use super::types::{DisplayOptions, ThreatLevel, VoteConsensus};

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
