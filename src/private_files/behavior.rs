//! Behavior analysis types for private files

use super::types::ProcessInfo;
use crate::objects::Object;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Private file behavior report
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrivateFileBehavior {
    #[serde(flatten)]
    pub object: Object<PrivateFileBehaviorAttributes>,
}

/// Attributes for private file behavior
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrivateFileBehaviorAttributes {
    /// Behavior hash
    #[serde(skip_serializing_if = "Option::is_none")]
    pub behash: Option<String>,

    /// Highlighted API calls
    #[serde(skip_serializing_if = "Option::is_none")]
    pub calls_highlighted: Option<Vec<String>>,

    /// Files opened during execution
    #[serde(skip_serializing_if = "Option::is_none")]
    pub files_opened: Option<Vec<String>>,

    /// Whether HTML report is available
    #[serde(skip_serializing_if = "Option::is_none")]
    pub has_html_report: Option<bool>,

    /// Whether PCAP is available
    #[serde(skip_serializing_if = "Option::is_none")]
    pub has_pcap: Option<bool>,

    /// Modules loaded during execution
    #[serde(skip_serializing_if = "Option::is_none")]
    pub modules_loaded: Option<Vec<String>>,

    /// Process tree
    #[serde(skip_serializing_if = "Option::is_none")]
    pub processes_tree: Option<Vec<ProcessInfo>>,

    /// Registry keys opened
    #[serde(skip_serializing_if = "Option::is_none")]
    pub registry_keys_opened: Option<Vec<String>>,

    /// Sandbox name
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sandbox_name: Option<String>,

    /// Behavior tags
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tags: Option<Vec<String>>,

    /// Highlighted text strings
    #[serde(skip_serializing_if = "Option::is_none")]
    pub text_highlighted: Option<Vec<String>>,

    /// Mutexes created
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mutexes_created: Option<Vec<String>>,

    /// Mutexes opened
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mutexes_opened: Option<Vec<String>>,

    /// Processes terminated
    #[serde(skip_serializing_if = "Option::is_none")]
    pub processes_terminated: Option<Vec<String>>,

    /// Additional attributes
    #[serde(flatten)]
    pub additional_attributes: HashMap<String, serde_json::Value>,
}

/// Dropped file information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DroppedFile {
    #[serde(flatten)]
    pub object: Object<DroppedFileAttributes>,
}

/// Attributes for dropped files
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DroppedFileAttributes {
    /// SHA256 hash of the dropped file
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,

    /// Path where the file was dropped
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,

    /// Size of the dropped file
    #[serde(skip_serializing_if = "Option::is_none")]
    pub size: Option<u64>,

    /// Type of the dropped file
    #[serde(skip_serializing_if = "Option::is_none")]
    pub type_description: Option<String>,

    /// Additional attributes
    #[serde(flatten)]
    pub additional_attributes: HashMap<String, serde_json::Value>,
}
