//! Analysis-related types and functionality for private files

use super::types::{AnalysisStats, EngineResult, FileInfo};
use crate::objects::Object;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Private analysis status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrivateAnalysis {
    #[serde(flatten)]
    pub object: Object<PrivateAnalysisAttributes>,
}

/// Attributes for private analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrivateAnalysisAttributes {
    /// Analysis status (queued, in-progress, completed)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,

    /// Analysis statistics
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stats: Option<AnalysisStats>,

    /// Analysis results by engine
    #[serde(skip_serializing_if = "Option::is_none")]
    pub results: Option<HashMap<String, EngineResult>>,

    /// Analysis date
    #[serde(skip_serializing_if = "Option::is_none")]
    pub date: Option<i64>,

    /// Additional attributes
    #[serde(flatten)]
    pub additional_attributes: HashMap<String, serde_json::Value>,
}

/// Response for getting a single private analysis with file info
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrivateAnalysisResponse {
    pub data: PrivateAnalysis,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub meta: Option<PrivateAnalysisMeta>,
}

/// Metadata for private analysis response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrivateAnalysisMeta {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file_info: Option<FileInfo>,
}

/// Reanalysis parameters
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ReanalyzeParams {
    /// If true, file won't be detonated in sandbox environments
    #[serde(skip_serializing_if = "Option::is_none")]
    pub disable_sandbox: Option<bool>,

    /// If file should have internet access in sandboxes
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enable_internet: Option<bool>,

    /// Intercept HTTPS/TLS/SSL communication
    #[serde(skip_serializing_if = "Option::is_none")]
    pub intercept_tls: Option<bool>,

    /// Command line arguments for sandbox execution
    #[serde(skip_serializing_if = "Option::is_none")]
    pub command_line: Option<String>,

    /// Sandbox for interactive use (defaults to "cape")
    #[serde(skip_serializing_if = "Option::is_none")]
    pub interaction_sandbox: Option<String>,

    /// Interaction timeout in seconds (60-1800, defaults to 60)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub interaction_timeout: Option<u32>,
}

impl ReanalyzeParams {
    /// Create new reanalysis parameters
    pub fn new() -> Self {
        Self::default()
    }

    /// Set disable sandbox parameter
    pub fn disable_sandbox(mut self, disable: bool) -> Self {
        self.disable_sandbox = Some(disable);
        self
    }

    /// Set enable internet parameter
    pub fn enable_internet(mut self, enable: bool) -> Self {
        self.enable_internet = Some(enable);
        self
    }

    /// Set intercept TLS parameter
    pub fn intercept_tls(mut self, intercept: bool) -> Self {
        self.intercept_tls = Some(intercept);
        self
    }

    /// Set command line arguments
    pub fn command_line<S: Into<String>>(mut self, command_line: S) -> Self {
        self.command_line = Some(command_line.into());
        self
    }

    /// Set interaction sandbox (defaults to "cape")
    pub fn interaction_sandbox<S: Into<String>>(mut self, sandbox: S) -> Self {
        self.interaction_sandbox = Some(sandbox.into());
        self
    }

    /// Set interaction timeout in seconds (60-1800, defaults to 60)
    pub fn interaction_timeout(mut self, timeout: u32) -> Self {
        self.interaction_timeout = Some(timeout.clamp(60, 1800));
        self
    }
}
