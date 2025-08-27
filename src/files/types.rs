//! Core file types and attributes

use crate::common::{AnalysisResult, AnalysisStats, VoteStats};
use crate::objects::Object;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct File {
    #[serde(flatten)]
    pub object: Object<FileAttributes>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct FileAttributes {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub type_description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub type_tag: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub type_extension: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vhash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tlsh: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trid: Option<Vec<TridInfo>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub creation_date: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub names: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_modification_date: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub size: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub meaningful_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub downloadable: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sha1: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub md5: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ssdeep: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub magic: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_analysis_date: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_analysis_stats: Option<AnalysisStats>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_analysis_results: Option<HashMap<String, AnalysisResult>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_submission_date: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub first_submission_date: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub times_submitted: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unique_sources: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reputation: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub total_votes: Option<VoteStats>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tags: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub crowdsourced_ids_stats: Option<HashMap<String, u32>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub crowdsourced_ids_results: Option<Vec<CrowdsourcedId>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sandbox_verdicts: Option<HashMap<String, SandboxVerdict>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sigma_analysis_summary: Option<SigmaAnalysis>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub popular_threat_classification: Option<ThreatClassification>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub crowdsourced_yara_results: Option<Vec<YaraResult>>,
    #[serde(flatten)]
    pub additional_attributes: HashMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TridInfo {
    pub file_type: String,
    pub probability: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrowdsourcedId {
    pub alert_severity: Option<String>,
    pub rule_name: String,
    pub rule_category: Option<String>,
    pub alert_context: Option<Vec<AlertContext>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertContext {
    pub url: Option<String>,
    pub hostname: Option<String>,
    pub ip: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxVerdict {
    pub category: String,
    pub sandbox_name: String,
    pub malware_classification: Option<Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SigmaAnalysis {
    pub critical: Option<u32>,
    pub high: Option<u32>,
    pub medium: Option<u32>,
    pub low: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatClassification {
    pub suggested_threat_label: String,
    pub popular_threat_category: Option<Vec<ThreatCategory>>,
    pub popular_threat_name: Option<Vec<ThreatName>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatCategory {
    pub count: u32,
    pub value: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatName {
    pub count: u32,
    pub value: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct YaraResult {
    pub rule_name: String,
    pub ruleset_name: String,
    pub ruleset_id: String,
    pub source: String,
    pub author: Option<String>,
    pub description: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UploadUrlResponse {
    pub data: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DownloadUrlResponse {
    pub data: String,
}
