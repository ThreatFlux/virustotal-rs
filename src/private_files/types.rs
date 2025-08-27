//! Type definitions for private file operations

use crate::objects::Object;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Private file analysis data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrivateFile {
    #[serde(flatten)]
    pub object: Object<PrivateFileAttributes>,
}

/// Attributes for private file analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrivateFileAttributes {
    /// SHA256 hash of the file
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,

    /// SHA1 hash of the file
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sha1: Option<String>,

    /// MD5 hash of the file
    #[serde(skip_serializing_if = "Option::is_none")]
    pub md5: Option<String>,

    /// Size of the file in bytes
    #[serde(skip_serializing_if = "Option::is_none")]
    pub size: Option<u64>,

    /// Type description of the file
    #[serde(skip_serializing_if = "Option::is_none")]
    pub type_description: Option<String>,

    /// Magic string of the file
    #[serde(skip_serializing_if = "Option::is_none")]
    pub magic: Option<String>,

    /// Tags associated with the file
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tags: Option<Vec<String>>,

    /// Analysis status
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,

    /// First submission date
    #[serde(skip_serializing_if = "Option::is_none")]
    pub first_submission_date: Option<i64>,

    /// Last analysis date
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_analysis_date: Option<i64>,

    /// Last analysis results
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_analysis_results: Option<HashMap<String, EngineResult>>,

    /// Last analysis statistics
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_analysis_stats: Option<AnalysisStats>,

    /// Reputation score
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reputation: Option<i32>,

    /// Additional attributes
    #[serde(flatten)]
    pub additional_attributes: HashMap<String, serde_json::Value>,
}

/// Engine detection result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EngineResult {
    /// Category of the detection
    #[serde(skip_serializing_if = "Option::is_none")]
    pub category: Option<String>,

    /// Engine name
    #[serde(skip_serializing_if = "Option::is_none")]
    pub engine_name: Option<String>,

    /// Engine version
    #[serde(skip_serializing_if = "Option::is_none")]
    pub engine_version: Option<String>,

    /// Result of the scan (malware name or "clean")
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<String>,

    /// Detection method used
    #[serde(skip_serializing_if = "Option::is_none")]
    pub method: Option<String>,

    /// Engine update date
    #[serde(skip_serializing_if = "Option::is_none")]
    pub engine_update: Option<String>,
}

/// Analysis statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisStats {
    /// Number of engines that detected the file as malicious
    #[serde(skip_serializing_if = "Option::is_none")]
    pub malicious: Option<u32>,

    /// Number of engines that detected the file as suspicious
    #[serde(skip_serializing_if = "Option::is_none")]
    pub suspicious: Option<u32>,

    /// Number of engines that detected the file as clean
    #[serde(skip_serializing_if = "Option::is_none")]
    pub undetected: Option<u32>,

    /// Number of engines that couldn't scan the file
    #[serde(skip_serializing_if = "Option::is_none")]
    pub failure: Option<u32>,

    /// Number of engines that timed out
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timeout: Option<u32>,

    /// Number of engines that returned a type unsupported error
    #[serde(skip_serializing_if = "Option::is_none")]
    pub type_unsupported: Option<u32>,
}

/// File information in analysis metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileInfo {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub size: Option<u64>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub sha1: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub md5: Option<String>,
}

/// Process information in behavior report
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessInfo {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub process_id: Option<String>,
}
