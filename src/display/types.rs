//! Types and enums for display functionality
//!
//! This module defines the data types used for display configuration
//! and classification of threats and votes.

use std::fmt;

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
