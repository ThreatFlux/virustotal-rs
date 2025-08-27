//! Upload-related types and functionality for private files

use serde::{Deserialize, Serialize};

/// Private file upload response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrivateFileUploadResponse {
    pub data: PrivateFileUploadData,
}

/// Data for private file upload response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrivateFileUploadData {
    #[serde(rename = "type")]
    pub object_type: String,
    pub id: String,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub links: Option<PrivateFileUploadLinks>,
}

/// Links for private file upload
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrivateFileUploadLinks {
    #[serde(rename = "self")]
    pub self_link: String,
}

/// Response containing upload URL for large files
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UploadUrlResponse {
    pub data: String,
}

/// Upload parameters for private file scanning
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PrivateFileUploadParams {
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

    /// Password for protected ZIP files
    #[serde(skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,

    /// Number of days to retain the report (1-28)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retention_period_days: Option<u32>,

    /// Storage region (US or EU)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub storage_region: Option<String>,

    /// Sandbox for interactive use
    #[serde(skip_serializing_if = "Option::is_none")]
    pub interaction_sandbox: Option<String>,

    /// Interaction timeout in seconds (60-1800)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub interaction_timeout: Option<u32>,

    /// Preferred sandbox locale (e.g., EN_US)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub locale: Option<String>,
}

impl PrivateFileUploadParams {
    /// Create new upload parameters
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

    /// Set password for protected files
    pub fn password<S: Into<String>>(mut self, password: S) -> Self {
        self.password = Some(password.into());
        self
    }

    /// Set retention period in days (1-28)
    pub fn retention_period_days(mut self, days: u32) -> Self {
        self.retention_period_days = Some(days.clamp(1, 28));
        self
    }

    /// Set storage region
    pub fn storage_region<S: Into<String>>(mut self, region: S) -> Self {
        self.storage_region = Some(region.into());
        self
    }

    /// Set interaction sandbox
    pub fn interaction_sandbox<S: Into<String>>(mut self, sandbox: S) -> Self {
        self.interaction_sandbox = Some(sandbox.into());
        self
    }

    /// Set interaction timeout in seconds (60-1800)
    pub fn interaction_timeout(mut self, timeout: u32) -> Self {
        self.interaction_timeout = Some(timeout.clamp(60, 1800));
        self
    }

    /// Set locale
    pub fn locale<S: Into<String>>(mut self, locale: S) -> Self {
        self.locale = Some(locale.into());
        self
    }
}
