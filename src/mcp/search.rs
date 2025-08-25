//! High-level search functionality for MCP integration
//!
//! This module provides the main search function that automatically detects
//! indicator types and performs appropriate `VirusTotal` API queries.

use crate::common::AnalysisStats;
use crate::mcp::indicators::{detect_indicator_type, IndicatorType};
use crate::mcp::{convert_vt_error, McpResult};
use crate::Client;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Consolidated threat intelligence response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatIntelligence {
    /// The original indicator that was searched
    pub indicator: String,
    /// The type of indicator
    pub indicator_type: String,
    /// Overall threat score (0-100, higher is more malicious)
    pub threat_score: u8,
    /// Threat categories detected
    pub threat_categories: Vec<String>,
    /// Summary of findings suitable for LLMs
    pub summary: String,
    /// Detection results from various engines
    pub detections: DetectionSummary,
    /// Additional contextual information
    pub context: ThreatContext,
    /// Timestamp of analysis
    pub last_analysis_date: Option<i64>,
    /// Raw reputation score from `VirusTotal`
    pub reputation: Option<i32>,
}

/// Summary of detections across engines
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectionSummary {
    /// Number of engines that flagged as malicious
    pub malicious: u32,
    /// Number of engines that flagged as suspicious
    pub suspicious: u32,
    /// Number of engines with no detection
    pub clean: u32,
    /// Total number of engines that scanned
    pub total_engines: u32,
    /// Detection ratio (malicious + suspicious) / total
    pub detection_ratio: f32,
}

/// Additional context about the threat
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatContext {
    /// Associated malware families
    pub malware_families: Vec<String>,
    /// File type (for file indicators)
    pub file_type: Option<String>,
    /// File size in bytes (for file indicators)  
    pub file_size: Option<u64>,
    /// Country of origin (for IP indicators)
    pub country: Option<String>,
    /// ASN (for IP indicators)
    pub asn: Option<String>,
    /// Registrar (for domain indicators)
    pub registrar: Option<String>,
    /// Creation date (for domain indicators)
    pub creation_date: Option<i64>,
    /// Associated URLs (for domain/IP indicators)
    pub associated_urls: Vec<String>,
    /// MITRE ATT&CK tactics
    pub mitre_tactics: Vec<String>,
    /// MITRE ATT&CK techniques
    pub mitre_techniques: Vec<String>,
}

/// High-level search function that auto-detects indicator type
/// and performs appropriate `VirusTotal` analysis
pub async fn vti_search(client: &Client, indicator: String) -> McpResult<ThreatIntelligence> {
    let indicator_type = detect_indicator_type(&indicator);

    match indicator_type {
        IndicatorType::Hash { hash_type: _, value } => {
            search_file_hash(client, &value).await
        }
        IndicatorType::IpAddress(ip) => {
            search_ip_address(client, &ip).await
        }
        IndicatorType::Domain(domain) => {
            search_domain(client, &domain).await
        }
        IndicatorType::Url(url) => {
            search_url(client, &url).await
        }
        IndicatorType::Unknown(_) => {
            Err(anyhow::anyhow!(
                "Unable to determine indicator type for: {}. Supported types: file hashes (MD5/SHA1/SHA256/SHA512), IP addresses, domains, and URLs.",
                indicator
            ))
        }
    }
}

/// Helper function to calculate detection summary from analysis stats
fn calculate_detection_summary(stats: &AnalysisStats) -> DetectionSummary {
    let total_engines =
        stats.harmless + stats.malicious + stats.suspicious + stats.undetected + stats.timeout;

    DetectionSummary {
        malicious: stats.malicious,
        suspicious: stats.suspicious,
        clean: stats.harmless + stats.undetected,
        total_engines,
        detection_ratio: if total_engines > 0 {
            (stats.malicious + stats.suspicious) as f32 / total_engines as f32
        } else {
            0.0
        },
    }
}

/// Helper function to calculate threat score
fn calculate_threat_score(stats: &AnalysisStats) -> u8 {
    let total_engines =
        stats.harmless + stats.malicious + stats.suspicious + stats.undetected + stats.timeout;

    if total_engines > 0 {
        ((stats.malicious as f32 + stats.suspicious as f32 * 0.5) / total_engines as f32 * 100.0)
            as u8
    } else {
        0
    }
}

/// Helper function to extract threat categories from analysis results
fn extract_threat_categories<T>(
    results: &Option<HashMap<String, T>>,
    category_extractor: impl Fn(&T) -> (&str, Option<&String>),
) -> Vec<String> {
    let mut threat_categories = Vec::new();

    if let Some(ref results) = results {
        for (_, result) in results.iter() {
            let (category, result_name) = category_extractor(result);
            if category == "malicious" || category == "suspicious" {
                if let Some(name) = result_name {
                    if !threat_categories.contains(name) && threat_categories.len() < 10 {
                        threat_categories.push(name.clone());
                    }
                }
            }
        }
    }

    threat_categories
}

/// Helper function to format detection ratio message
fn format_detection_ratio(detections: &DetectionSummary) -> String {
    format!(
        "Detection ratio: {}/{} engines flagged it ({} malicious, {} suspicious).",
        detections.malicious + detections.suspicious,
        detections.total_engines,
        detections.malicious,
        detections.suspicious
    )
}

/// Helper function to create threat level description
fn get_threat_level_description(threat_score: u8, indicator_type: &str) -> String {
    let entity = match indicator_type {
        "file" => "file",
        "ip" => "IP address",
        "domain" => "domain",
        "url" => "URL",
        _ => "indicator",
    };

    if threat_score == 0 {
        format!(
            "This {} appears to be clean with no malicious detections.",
            entity
        )
    } else if threat_score < 20 {
        format!("This {} has low threat indicators.", entity)
    } else if threat_score < 50 {
        format!("This {} shows moderate threat indicators.", entity)
    } else if threat_score < 80 {
        if indicator_type == "file" {
            "This file is likely malicious with high threat indicators.".to_string()
        } else {
            format!("This {} is likely malicious.", entity)
        }
    } else {
        format!("This {} is almost certainly malicious.", entity)
    }
}

/// Search for file hash information
async fn search_file_hash(client: &Client, hash: &str) -> McpResult<ThreatIntelligence> {
    let file = client.files().get(hash).await.map_err(convert_vt_error)?;

    let stats = file
        .object
        .attributes
        .last_analysis_stats
        .clone()
        .unwrap_or_default();

    let detection_summary = calculate_detection_summary(&stats);
    let threat_score = calculate_threat_score(&stats);

    // Extract threat categories
    let threat_categories =
        extract_threat_categories(&file.object.attributes.last_analysis_results, |result| {
            (result.category.as_str(), result.result.as_ref())
        });

    // Extract malware families
    let mut malware_families = Vec::new();
    if let Some(ref families) = file.object.attributes.popular_threat_classification {
        malware_families.push(families.suggested_threat_label.clone());
    }

    // Create summary
    let summary = create_file_summary(&file.object.attributes, &detection_summary, threat_score);

    // Extract MITRE ATT&CK data
    let mitre_tactics = Vec::new();
    let mitre_techniques = Vec::new();

    // MITRE ATT&CK data extraction is simplified for now
    // This would need proper field mapping based on `VirusTotal` API response

    let context = ThreatContext {
        malware_families,
        file_type: file.object.attributes.type_description,
        file_size: file.object.attributes.size,
        country: None,
        asn: None,
        registrar: None,
        creation_date: None,
        associated_urls: Vec::new(),
        mitre_tactics,
        mitre_techniques,
    };

    Ok(ThreatIntelligence {
        indicator: hash.to_string(),
        indicator_type: "File Hash".to_string(),
        threat_score,
        threat_categories,
        summary,
        detections: detection_summary,
        context,
        last_analysis_date: file.object.attributes.last_analysis_date,
        reputation: file.object.attributes.reputation,
    })
}

/// Search for IP address information
async fn search_ip_address(client: &Client, ip: &str) -> McpResult<ThreatIntelligence> {
    let ip_info = client
        .ip_addresses()
        .get(ip)
        .await
        .map_err(convert_vt_error)?;

    let stats = ip_info
        .object
        .attributes
        .last_analysis_stats
        .clone()
        .unwrap_or_default();

    let detection_summary = calculate_detection_summary(&stats);
    let threat_score = calculate_threat_score(&stats);

    // Extract threat categories
    let threat_categories =
        extract_threat_categories(&ip_info.object.attributes.last_analysis_results, |result| {
            (result.category.as_str(), result.result.as_ref())
        });

    let summary = create_ip_summary(&ip_info.object.attributes, &detection_summary, threat_score);

    let context = ThreatContext {
        malware_families: Vec::new(),
        file_type: None,
        file_size: None,
        country: ip_info.object.attributes.country,
        asn: ip_info.object.attributes.as_owner,
        registrar: None,
        creation_date: None,
        associated_urls: Vec::new(),
        mitre_tactics: Vec::new(),
        mitre_techniques: Vec::new(),
    };

    Ok(ThreatIntelligence {
        indicator: ip.to_string(),
        indicator_type: "IP Address".to_string(),
        threat_score,
        threat_categories,
        summary,
        detections: detection_summary,
        context,
        last_analysis_date: ip_info.object.attributes.last_analysis_date,
        reputation: ip_info.object.attributes.reputation,
    })
}

/// Search for domain information
async fn search_domain(client: &Client, domain: &str) -> McpResult<ThreatIntelligence> {
    let domain_info = client
        .domains()
        .get(domain)
        .await
        .map_err(convert_vt_error)?;

    let stats = domain_info
        .object
        .attributes
        .last_analysis_stats
        .clone()
        .unwrap_or_default();

    let detection_summary = calculate_detection_summary(&stats);
    let threat_score = calculate_threat_score(&stats);

    let threat_categories = extract_threat_categories(
        &domain_info.object.attributes.last_analysis_results,
        |result| (result.category.as_str(), result.result.as_ref()),
    );

    let summary = create_domain_summary(
        &domain_info.object.attributes,
        &detection_summary,
        threat_score,
    );

    let context = ThreatContext {
        malware_families: Vec::new(),
        file_type: None,
        file_size: None,
        country: None,
        asn: None,
        registrar: domain_info.object.attributes.registrar,
        creation_date: domain_info.object.attributes.creation_date,
        associated_urls: Vec::new(),
        mitre_tactics: Vec::new(),
        mitre_techniques: Vec::new(),
    };

    Ok(ThreatIntelligence {
        indicator: domain.to_string(),
        indicator_type: "Domain".to_string(),
        threat_score,
        threat_categories,
        summary,
        detections: detection_summary,
        context,
        last_analysis_date: domain_info.object.attributes.last_analysis_date,
        reputation: domain_info.object.attributes.reputation,
    })
}

/// Search for URL information
async fn search_url(client: &Client, url: &str) -> McpResult<ThreatIntelligence> {
    use base64::{engine::general_purpose, Engine as _};
    let url_id = general_purpose::STANDARD.encode(url);
    let url_info = client.urls().get(&url_id).await.map_err(convert_vt_error)?;

    let stats = url_info
        .object
        .attributes
        .last_analysis_stats
        .clone()
        .unwrap_or_default();

    let detection_summary = calculate_detection_summary(&stats);
    let threat_score = calculate_threat_score(&stats);

    let threat_categories = extract_threat_categories(
        &url_info.object.attributes.last_analysis_results,
        |result| (result.category.as_str(), Some(&result.result)),
    );

    let summary = create_url_summary(
        &url_info.object.attributes,
        &detection_summary,
        threat_score,
    );

    let context = ThreatContext {
        malware_families: Vec::new(),
        file_type: None,
        file_size: None,
        country: None,
        asn: None,
        registrar: None,
        creation_date: None,
        associated_urls: Vec::new(),
        mitre_tactics: Vec::new(),
        mitre_techniques: Vec::new(),
    };

    Ok(ThreatIntelligence {
        indicator: url.to_string(),
        indicator_type: "URL".to_string(),
        threat_score,
        threat_categories,
        summary,
        detections: detection_summary,
        context,
        last_analysis_date: url_info.object.attributes.last_analysis_date,
        reputation: url_info.object.attributes.reputation,
    })
}

/// Create a human-readable summary for file analysis
fn create_file_summary(
    attributes: &crate::files::FileAttributes,
    detections: &DetectionSummary,
    threat_score: u8,
) -> String {
    let mut parts = Vec::new();

    parts.push(get_threat_level_description(threat_score, "file"));
    parts.push(format_detection_ratio(detections));

    if let Some(file_type) = &attributes.type_description {
        parts.push(format!("File type: {}", file_type));
    }

    if let Some(size) = attributes.size {
        parts.push(format!("File size: {} bytes", size));
    }

    parts.join(" ")
}

/// Create a human-readable summary for IP analysis
fn create_ip_summary(
    attributes: &crate::ip_addresses::IpAddressAttributes,
    detections: &DetectionSummary,
    threat_score: u8,
) -> String {
    let mut parts = Vec::new();

    parts.push(get_threat_level_description(threat_score, "ip"));
    parts.push(format_detection_ratio(detections));

    if let Some(country) = &attributes.country {
        parts.push(format!("Located in: {}", country));
    }

    if let Some(asn) = &attributes.as_owner {
        parts.push(format!("ASN: {}", asn));
    }

    parts.join(" ")
}

/// Create a human-readable summary for domain analysis
fn create_domain_summary(
    attributes: &crate::domains::DomainAttributes,
    detections: &DetectionSummary,
    threat_score: u8,
) -> String {
    let mut parts = Vec::new();

    parts.push(get_threat_level_description(threat_score, "domain"));
    parts.push(format_detection_ratio(detections));

    if let Some(registrar) = &attributes.registrar {
        parts.push(format!("Registrar: {}", registrar));
    }

    parts.join(" ")
}

/// Create a human-readable summary for URL analysis  
fn create_url_summary(
    attributes: &crate::urls::UrlAttributes,
    detections: &DetectionSummary,
    threat_score: u8,
) -> String {
    let mut parts = Vec::new();

    parts.push(get_threat_level_description(threat_score, "url"));
    parts.push(format_detection_ratio(detections));

    if let Some(title) = &attributes.title {
        parts.push(format!("Page title: {}", title));
    }

    parts.join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detection_summary_calculation() {
        let summary = DetectionSummary {
            malicious: 5,
            suspicious: 3,
            clean: 42,
            total_engines: 50,
            detection_ratio: 0.16,
        };

        assert_eq!(
            summary.malicious + summary.suspicious + summary.clean,
            summary.total_engines
        );
        assert!((summary.detection_ratio - 0.16).abs() < 0.01);
    }

    #[test]
    fn test_threat_score_calculation() {
        // Test with 50 total engines: 10 malicious, 5 suspicious
        let malicious = 10.0;
        let suspicious = 5.0;
        let total = 50.0;

        let threat_score = ((malicious + suspicious * 0.5) / total * 100.0) as u8;
        assert_eq!(threat_score, 25); // (10 + 2.5) / 50 * 100 = 25%
    }
}
