//! Trait implementations for AnalysisStats and VoteStats
//!
//! This module provides the concrete implementations of display traits
//! for the main VirusTotal data types.

use crate::common::{AnalysisStats, VoteStats};
use super::traits::{DisplayStats, DisplayVotes};
use super::types::{ThreatLevel, VoteConsensus};

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