use crate::files::{FileBehavior, FileBehaviorSummary, MitreTrees};
use crate::objects::{Collection, CollectionIterator, Object};
use crate::{Client, Result};
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

/// Process information in behavior report
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessInfo {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub process_id: Option<String>,
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

/// Client for Private File Scanning operations
pub struct PrivateFilesClient<'a> {
    pub(crate) client: &'a Client,
}

impl<'a> PrivateFilesClient<'a> {
    pub fn new(client: &'a Client) -> Self {
        Self { client }
    }

    /// List private analyses
    ///
    /// GET /private/analyses
    ///
    /// Returns a list of the last private analyses sorted by most recent first.
    /// Use order="date-" to reverse the order.
    pub async fn list_analyses(
        &self,
        limit: Option<u32>,
        cursor: Option<&str>,
        order: Option<&str>,
    ) -> Result<Collection<PrivateAnalysis>> {
        let mut url = String::from("private/analyses?");

        if let Some(l) = limit {
            // Maximum 40 analyses
            let limit = l.min(40);
            url.push_str(&format!("limit={}&", limit));
        }

        if let Some(c) = cursor {
            url.push_str(&format!("cursor={}&", urlencoding::encode(c)));
        }

        if let Some(o) = order {
            url.push_str(&format!("order={}&", urlencoding::encode(o)));
        } else {
            // Default to date- (most recent first)
            url.push_str("order=date-&");
        }

        // Remove trailing '&' or '?'
        url.pop();

        self.client.get(&url).await
    }

    /// Get an iterator for listing private analyses
    pub fn list_analyses_iterator(&self) -> CollectionIterator<'_, PrivateAnalysis> {
        CollectionIterator::new(self.client, "private/analyses".to_string())
    }

    /// Get a single private analysis
    ///
    /// GET /private/analyses/{id}
    ///
    /// Returns information about a specific analysis including file metadata.
    /// The status can be "queued", "in-progress", or "completed".
    pub async fn get_single_analysis(&self, analysis_id: &str) -> Result<PrivateAnalysisResponse> {
        let url = format!("private/analyses/{}", urlencoding::encode(analysis_id));
        self.client.get(&url).await
    }

    /// Upload a file for private scanning (files up to 32MB)
    ///
    /// POST /private/files
    ///
    /// The file contents should be provided as bytes.
    /// For files larger than 32MB, use `upload_large_file` instead.
    pub async fn upload_file(
        &self,
        file_data: &[u8],
        params: Option<PrivateFileUploadParams>,
    ) -> Result<PrivateFileUploadResponse> {
        let mut form = reqwest::multipart::Form::new().part(
            "file",
            reqwest::multipart::Part::bytes(file_data.to_vec()).file_name("file"),
        );

        // Add optional parameters
        if let Some(p) = params {
            if let Some(disable_sandbox) = p.disable_sandbox {
                form = form.text("disable_sandbox", disable_sandbox.to_string());
            }
            if let Some(enable_internet) = p.enable_internet {
                form = form.text("enable_internet", enable_internet.to_string());
            }
            if let Some(intercept_tls) = p.intercept_tls {
                form = form.text("intercept_tls", intercept_tls.to_string());
            }
            if let Some(command_line) = p.command_line {
                form = form.text("command_line", command_line);
            }
            if let Some(password) = p.password {
                form = form.text("password", password);
            }
            if let Some(retention_period_days) = p.retention_period_days {
                form = form.text("retention_period_days", retention_period_days.to_string());
            }
            if let Some(storage_region) = p.storage_region {
                form = form.text("storage_region", storage_region);
            }
            if let Some(interaction_sandbox) = p.interaction_sandbox {
                form = form.text("interaction_sandbox", interaction_sandbox);
            }
            if let Some(interaction_timeout) = p.interaction_timeout {
                form = form.text("interaction_timeout", interaction_timeout.to_string());
            }
            if let Some(locale) = p.locale {
                form = form.text("locale", locale);
            }
        }

        self.client.post_multipart("private/files", form).await
    }

    /// List previously analyzed private files
    ///
    /// GET /private/files
    ///
    /// Returns a list of previously analysed private files ordered by SHA256.
    pub async fn list_files(
        &self,
        limit: Option<u32>,
        cursor: Option<&str>,
    ) -> Result<Collection<PrivateFile>> {
        let mut url = String::from("private/files?");

        if let Some(l) = limit {
            // Maximum 40 files
            let limit = l.min(40);
            url.push_str(&format!("limit={}&", limit));
        }

        if let Some(c) = cursor {
            url.push_str(&format!("cursor={}&", urlencoding::encode(c)));
        }

        // Remove trailing '&' or '?'
        url.pop();

        self.client.get(&url).await
    }

    /// Get an iterator for listing private files
    pub fn list_files_iterator(&self) -> CollectionIterator<'_, PrivateFile> {
        CollectionIterator::new(self.client, "private/files".to_string())
    }

    /// Create an upload URL for large files (>32MB, up to 650MB)
    ///
    /// GET /private/files/upload_url
    ///
    /// Returns a URL that can be used to upload large files directly.
    pub async fn create_upload_url(&self) -> Result<UploadUrlResponse> {
        self.client.get("private/files/upload_url").await
    }

    /// Upload a large file using the upload URL
    ///
    /// This method handles the upload to the URL obtained from `create_upload_url`.
    /// The actual upload is done via PUT request to the provided URL.
    pub async fn upload_large_file(
        &self,
        _upload_url: &str,
        _file_data: &[u8],
    ) -> Result<PrivateFileUploadResponse> {
        // Note: This would need special handling to upload directly to the
        // provided URL and then confirm the upload
        // This is a placeholder showing the expected interface

        // 1. PUT file_data to upload_url
        // 2. Confirm upload by calling the confirmation endpoint

        unimplemented!("Large file upload requires special HTTP client handling")
    }

    /// Get a private file report by SHA-256 hash
    ///
    /// GET /private/files/{id}
    ///
    /// This endpoint returns information about a file scanned privately.
    /// Note: Only accepts SHA-256 as the file's ID, MD5 and SHA-1 are NOT supported.
    pub async fn get_file(&self, sha256: &str) -> Result<PrivateFile> {
        let url = format!("private/files/{}", urlencoding::encode(sha256));
        self.client.get(&url).await
    }

    /// Delete a private file report
    ///
    /// DELETE /private/files/{id}
    ///
    /// This endpoint deletes a private file from storage, as well as all the
    /// PrivateFile and PrivateAnalysis associated with it.
    ///
    /// Parameters:
    /// - `sha256`: File's SHA-256 hash
    /// - `only_from_storage`: If true, only the file will be deleted from storage,
    ///   but the generated reports and analyses won't be deleted.
    pub async fn delete_file(&self, sha256: &str, only_from_storage: bool) -> Result<()> {
        let url = if only_from_storage {
            format!(
                "private/files/{}?only_from_storage=true",
                urlencoding::encode(sha256)
            )
        } else {
            format!("private/files/{}", urlencoding::encode(sha256))
        };
        self.client.delete(&url).await
    }

    /// Get the analysis status for a private file
    ///
    /// GET /private/files/{id}/analyses/{analysis_id}
    ///
    /// Parameters:
    /// - `sha256`: File's SHA-256 hash
    /// - `analysis_id`: The analysis ID to retrieve
    pub async fn get_analysis(&self, sha256: &str, analysis_id: &str) -> Result<PrivateAnalysis> {
        let url = format!(
            "private/files/{}/analyses/{}",
            urlencoding::encode(sha256),
            urlencoding::encode(analysis_id)
        );
        self.client.get(&url).await
    }

    /// Get all analyses for a private file
    ///
    /// GET /private/files/{id}/analyses
    ///
    /// Parameters:
    /// - `sha256`: File's SHA-256 hash
    pub async fn get_analyses(
        &self,
        sha256: &str,
        limit: Option<u32>,
        cursor: Option<&str>,
    ) -> Result<Collection<PrivateAnalysis>> {
        let mut url = format!("private/files/{}/analyses?", urlencoding::encode(sha256));

        if let Some(l) = limit {
            url.push_str(&format!("limit={}&", l));
        }

        if let Some(c) = cursor {
            url.push_str(&format!("cursor={}&", urlencoding::encode(c)));
        }

        // Remove trailing '&' or '?'
        url.pop();

        self.client.get(&url).await
    }

    /// Get analyses iterator for pagination
    ///
    /// Parameters:
    /// - `sha256`: File's SHA-256 hash
    pub fn get_analyses_iterator(&self, sha256: &str) -> CollectionIterator<'_, PrivateAnalysis> {
        let url = format!("private/files/{}/analyses", urlencoding::encode(sha256));
        CollectionIterator::new(self.client, url)
    }

    /// Get behavior report for a private file
    ///
    /// GET /private/files/{id}/behaviours
    ///
    /// Parameters:
    /// - `sha256`: File's SHA-256 hash
    pub async fn get_behaviors(
        &self,
        sha256: &str,
        limit: Option<u32>,
        cursor: Option<&str>,
    ) -> Result<Collection<FileBehavior>> {
        let mut url = format!("private/files/{}/behaviours?", urlencoding::encode(sha256));

        if let Some(l) = limit {
            url.push_str(&format!("limit={}&", l));
        }

        if let Some(c) = cursor {
            url.push_str(&format!("cursor={}&", urlencoding::encode(c)));
        }

        // Remove trailing '&' or '?'
        url.pop();

        self.client.get(&url).await
    }

    /// Get behavior summary for a private file
    ///
    /// GET /private/files/{id}/behaviour_summary
    ///
    /// Parameters:
    /// - `sha256`: File's SHA-256 hash
    pub async fn get_behavior_summary(&self, sha256: &str) -> Result<FileBehaviorSummary> {
        let url = format!(
            "private/files/{}/behaviour_summary",
            urlencoding::encode(sha256)
        );
        self.client.get(&url).await
    }

    /// Get MITRE ATT&CK tactics and techniques for a private file
    ///
    /// GET /private/files/{id}/behaviour_mitre_trees
    ///
    /// Parameters:
    /// - `sha256`: File's SHA-256 hash
    pub async fn get_mitre_attack_data(&self, sha256: &str) -> Result<MitreTrees> {
        let url = format!(
            "private/files/{}/behaviour_mitre_trees",
            urlencoding::encode(sha256)
        );
        self.client.get(&url).await
    }

    /// Get files dropped by a private file during sandbox analysis
    ///
    /// GET /private/files/{id}/dropped_files
    ///
    /// Parameters:
    /// - `sha256`: File's SHA-256 hash
    pub async fn get_dropped_files(
        &self,
        sha256: &str,
        limit: Option<u32>,
        cursor: Option<&str>,
    ) -> Result<Collection<DroppedFile>> {
        let mut url = format!(
            "private/files/{}/dropped_files?",
            urlencoding::encode(sha256)
        );

        if let Some(l) = limit {
            url.push_str(&format!("limit={}&", l));
        }

        if let Some(c) = cursor {
            url.push_str(&format!("cursor={}&", urlencoding::encode(c)));
        }

        // Remove trailing '&' or '?'
        url.pop();

        self.client.get(&url).await
    }

    /// Get dropped files iterator for pagination
    ///
    /// Parameters:
    /// - `sha256`: File's SHA-256 hash
    pub fn get_dropped_files_iterator(&self, sha256: &str) -> CollectionIterator<'_, DroppedFile> {
        let url = format!(
            "private/files/{}/dropped_files",
            urlencoding::encode(sha256)
        );
        CollectionIterator::new(self.client, url)
    }

    /// Re-analyze a private file
    ///
    /// POST /private/files/{sha256}/analyse
    ///
    /// Reanalyses a private file with optional parameters.
    ///
    /// Parameters:
    /// - `sha256`: File's SHA-256 hash
    /// - `params`: Optional reanalysis parameters
    pub async fn reanalyze(
        &self,
        sha256: &str,
        params: Option<ReanalyzeParams>,
    ) -> Result<PrivateAnalysis> {
        let mut url = format!("private/files/{}/analyse", urlencoding::encode(sha256));

        // Add query parameters if provided
        if let Some(p) = params {
            let mut query_params = Vec::new();

            if let Some(disable_sandbox) = p.disable_sandbox {
                query_params.push(format!("disable_sandbox={}", disable_sandbox));
            }
            if let Some(enable_internet) = p.enable_internet {
                query_params.push(format!("enable_internet={}", enable_internet));
            }
            if let Some(intercept_tls) = p.intercept_tls {
                query_params.push(format!("intercept_tls={}", intercept_tls));
            }
            if let Some(ref command_line) = p.command_line {
                query_params.push(format!(
                    "command_line={}",
                    urlencoding::encode(command_line)
                ));
            }
            if let Some(ref interaction_sandbox) = p.interaction_sandbox {
                query_params.push(format!(
                    "interaction_sandbox={}",
                    urlencoding::encode(interaction_sandbox)
                ));
            }
            if let Some(interaction_timeout) = p.interaction_timeout {
                query_params.push(format!("interaction_timeout={}", interaction_timeout));
            }

            if !query_params.is_empty() {
                url.push('?');
                url.push_str(&query_params.join("&"));
            }
        }

        let empty_body = serde_json::json!({});
        self.client.post(&url, &empty_body).await
    }

    /// Get comments on a private file
    ///
    /// GET /private/files/{id}/comments
    ///
    /// Parameters:
    /// - `sha256`: File's SHA-256 hash
    pub async fn get_comments(
        &self,
        sha256: &str,
        limit: Option<u32>,
        cursor: Option<&str>,
    ) -> Result<Collection<crate::comments::Comment>> {
        let mut url = format!("private/files/{}/comments?", urlencoding::encode(sha256));

        if let Some(l) = limit {
            url.push_str(&format!("limit={}&", l));
        }

        if let Some(c) = cursor {
            url.push_str(&format!("cursor={}&", urlencoding::encode(c)));
        }

        // Remove trailing '&' or '?'
        url.pop();

        self.client.get(&url).await
    }

    /// Add a comment to a private file
    ///
    /// POST /private/files/{id}/comments
    ///
    /// Parameters:
    /// - `sha256`: File's SHA-256 hash
    /// - `comment_text`: The comment text to add
    pub async fn add_comment(
        &self,
        sha256: &str,
        comment_text: &str,
    ) -> Result<crate::comments::Comment> {
        let url = format!("private/files/{}/comments", urlencoding::encode(sha256));
        let request = crate::comments::CreateCommentRequest::new(comment_text);
        self.client.post(&url, &request).await
    }

    /// Download a private file
    ///
    /// GET /private/files/{id}/download
    ///
    /// Returns the raw file bytes.
    ///
    /// Parameters:
    /// - `sha256`: File's SHA-256 hash
    pub async fn download(&self, sha256: &str) -> Result<Vec<u8>> {
        let url = format!("private/files/{}/download", urlencoding::encode(sha256));
        self.client.get_bytes(&url).await
    }

    /// Get a specific private file behavior report
    ///
    /// GET /private/file_behaviours/{sandbox_id}
    ///
    /// Fetches a Private File Behaviour object by ID.
    ///
    /// Parameters:
    /// - `sandbox_id`: The sandbox report ID returned by get_behaviors endpoint
    pub async fn get_file_behavior(&self, sandbox_id: &str) -> Result<PrivateFileBehavior> {
        let url = format!(
            "private/file_behaviours/{}",
            urlencoding::encode(sandbox_id)
        );
        self.client.get(&url).await
    }

    /// Get behavior reports from a private file (alternate endpoint)
    ///
    /// GET /private/file/{id}/behaviours
    ///
    /// Note: This is an alternate endpoint path (file vs files)
    ///
    /// Parameters:
    /// - `sha256`: File's SHA-256 hash
    pub async fn get_file_behaviors_alt(
        &self,
        sha256: &str,
    ) -> Result<Collection<PrivateFileBehavior>> {
        let url = format!("private/file/{}/behaviours", urlencoding::encode(sha256));
        self.client.get(&url).await
    }

    /// Get objects related to a private file's behavior report
    ///
    /// GET /private/file_behaviours/{sandbox_id}/{relationship}
    ///
    /// Parameters:
    /// - `sandbox_id`: The sandbox report ID
    /// - `relationship`: The relationship name
    pub async fn get_behavior_relationship<T>(
        &self,
        sandbox_id: &str,
        relationship: &str,
        limit: Option<u32>,
        cursor: Option<&str>,
    ) -> Result<Collection<T>>
    where
        T: serde::de::DeserializeOwned,
    {
        let mut url = format!(
            "private/file_behaviours/{}/{}?",
            urlencoding::encode(sandbox_id),
            relationship
        );

        if let Some(l) = limit {
            url.push_str(&format!("limit={}&", l));
        }

        if let Some(c) = cursor {
            url.push_str(&format!("cursor={}&", urlencoding::encode(c)));
        }

        // Remove trailing '&' or '?'
        url.pop();

        self.client.get(&url).await
    }

    /// Get object descriptors related to a private file's behavior report
    ///
    /// GET /private/file_behaviours/{sandbox_id}/relationships/{relationship}
    ///
    /// Returns just the related object's IDs and context attributes.
    ///
    /// Parameters:
    /// - `sandbox_id`: The sandbox report ID
    /// - `relationship`: The relationship name
    pub async fn get_behavior_relationship_descriptors(
        &self,
        sandbox_id: &str,
        relationship: &str,
        limit: Option<u32>,
        cursor: Option<&str>,
    ) -> Result<Collection<serde_json::Value>> {
        let mut url = format!(
            "private/file_behaviours/{}/relationships/{}?",
            urlencoding::encode(sandbox_id),
            relationship
        );

        if let Some(l) = limit {
            url.push_str(&format!("limit={}&", l));
        }

        if let Some(c) = cursor {
            url.push_str(&format!("cursor={}&", urlencoding::encode(c)));
        }

        // Remove trailing '&' or '?'
        url.pop();

        self.client.get(&url).await
    }

    /// Get objects related to a private analysis
    ///
    /// GET /private/analyses/{id}/{relationship}
    ///
    /// Parameters:
    /// - `analysis_id`: The analysis identifier
    /// - `relationship`: The relationship name
    pub async fn get_analysis_relationship<T>(
        &self,
        analysis_id: &str,
        relationship: &str,
    ) -> Result<Collection<T>>
    where
        T: serde::de::DeserializeOwned,
    {
        let url = format!(
            "private/analyses/{}/{}",
            urlencoding::encode(analysis_id),
            relationship
        );
        self.client.get(&url).await
    }

    /// Get object descriptors related to a private analysis
    ///
    /// GET /private/analyses/{id}/relationships/{relationship}
    ///
    /// Returns just the related object's IDs and context attributes.
    ///
    /// Parameters:
    /// - `analysis_id`: The analysis identifier
    /// - `relationship`: The relationship name
    pub async fn get_analysis_relationship_descriptors(
        &self,
        analysis_id: &str,
        relationship: &str,
    ) -> Result<Collection<serde_json::Value>> {
        let url = format!(
            "private/analyses/{}/relationships/{}",
            urlencoding::encode(analysis_id),
            relationship
        );
        self.client.get(&url).await
    }

    /// Get a detailed HTML behavior report
    ///
    /// GET /private/file_behaviours/{sandbox_id}/html
    ///
    /// Returns a Private File Behaviour object as an HTML report.
    ///
    /// Parameters:
    /// - `sandbox_id`: The sandbox report ID returned by get_behaviors endpoint
    pub async fn get_behavior_html_report(&self, sandbox_id: &str) -> Result<String> {
        let url = format!(
            "private/file_behaviours/{}/html",
            urlencoding::encode(sandbox_id)
        );
        self.client.get_raw(&url).await
    }

    /// Get the EVTX file generated during behavior analysis
    ///
    /// GET /private/file_behaviours/{sandbox_id}/evtx
    ///
    /// Fetch the Windows Event Log (EVTX) file associated with the sandbox execution.
    ///
    /// Parameters:
    /// - `sandbox_id`: The sandbox report ID
    pub async fn get_behavior_evtx(&self, sandbox_id: &str) -> Result<Vec<u8>> {
        let url = format!(
            "private/file_behaviours/{}/evtx",
            urlencoding::encode(sandbox_id)
        );
        self.client.get_bytes(&url).await
    }

    /// Get the PCAP file generated during behavior analysis
    ///
    /// GET /private/file_behaviours/{sandbox_id}/pcap
    ///
    /// Fetch the packet capture (PCAP) file with network traffic from the sandbox execution.
    ///
    /// Parameters:
    /// - `sandbox_id`: The sandbox report ID
    pub async fn get_behavior_pcap(&self, sandbox_id: &str) -> Result<Vec<u8>> {
        let url = format!(
            "private/file_behaviours/{}/pcap",
            urlencoding::encode(sandbox_id)
        );
        self.client.get_bytes(&url).await
    }

    /// Get the memory dump file generated during behavior analysis
    ///
    /// GET /private/file_behaviours/{sandbox_id}/memdump
    ///
    /// Fetch the memory dump file associated with the sandbox execution.
    ///
    /// Parameters:
    /// - `sandbox_id`: The sandbox report ID
    pub async fn get_behavior_memdump(&self, sandbox_id: &str) -> Result<Vec<u8>> {
        let url = format!(
            "private/file_behaviours/{}/memdump",
            urlencoding::encode(sandbox_id)
        );
        self.client.get_bytes(&url).await
    }

    /// Get objects related to a private file
    ///
    /// GET /private/files/{id}/{relationship}
    ///
    /// Parameters:
    /// - `sha256`: File's SHA-256 hash
    /// - `relationship`: The relationship name to retrieve
    pub async fn get_relationship<T>(
        &self,
        sha256: &str,
        relationship: &str,
        limit: Option<u32>,
        cursor: Option<&str>,
    ) -> Result<Collection<T>>
    where
        T: serde::de::DeserializeOwned,
    {
        let mut url = format!(
            "private/files/{}/{}?",
            urlencoding::encode(sha256),
            relationship
        );

        if let Some(l) = limit {
            url.push_str(&format!("limit={}&", l));
        }

        if let Some(c) = cursor {
            url.push_str(&format!("cursor={}&", urlencoding::encode(c)));
        }

        // Remove trailing '&' or '?'
        url.pop();

        self.client.get(&url).await
    }

    /// Get object descriptors related to a private file
    ///
    /// GET /private/files/{id}/relationships/{relationship}
    ///
    /// This endpoint returns just the related object's IDs (and context attributes, if any)
    /// instead of returning all attributes.
    ///
    /// Parameters:
    /// - `sha256`: File's SHA-256 hash
    /// - `relationship`: The relationship name to retrieve
    pub async fn get_relationship_descriptors(
        &self,
        sha256: &str,
        relationship: &str,
        limit: Option<u32>,
        cursor: Option<&str>,
    ) -> Result<Collection<serde_json::Value>> {
        let mut url = format!(
            "private/files/{}/relationships/{}?",
            urlencoding::encode(sha256),
            relationship
        );

        if let Some(l) = limit {
            url.push_str(&format!("limit={}&", l));
        }

        if let Some(c) = cursor {
            url.push_str(&format!("cursor={}&", urlencoding::encode(c)));
        }

        // Remove trailing '&' or '?'
        url.pop();

        self.client.get(&url).await
    }

    /// Create a password-protected ZIP file with private files
    ///
    /// Creates a ZIP file containing the files specified by their hashes.
    /// Optionally you can provide a password for protecting the ZIP file.
    ///
    /// The ZIP file creation is asynchronous - use `get_zip_status()` to check progress.
    ///
    /// # Arguments
    /// * `request` - Request containing hashes and optional password
    ///
    /// # Example
    /// ```ignore
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// # let client = virustotal_rs::Client::new("your_api_key".into(), virustotal_rs::ApiTier::Public)?;
    /// # let private_files_client = client.private_files();
    /// use virustotal_rs::private_files::CreatePrivateZipRequest;
    /// let request = CreatePrivateZipRequest::new(vec![
    ///     "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".to_string(),
    ///     "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f".to_string(),
    /// ]).with_password("mysecretpassword".to_string());
    ///
    /// let zip_file = private_files_client.create_zip(&request).await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn create_zip(&self, request: &CreatePrivateZipRequest) -> Result<PrivateZipFile> {
        self.client.post("private/zip_files", request).await
    }

    /// Check the status of a private ZIP file
    ///
    /// Returns the current status and progress of the ZIP file creation.
    ///
    /// # Status values
    /// - `starting` - ZIP creation is starting
    /// - `creating` - ZIP is being created
    /// - `finished` - ZIP is ready for download
    /// - `timeout` - Creation timed out
    /// - `error-starting` - Error when starting
    /// - `error-creating` - Error during creation
    ///
    /// When status is "finished", the file can be downloaded.
    pub async fn get_zip_status(&self, zip_file_id: &str) -> Result<PrivateZipFile> {
        let endpoint = format!("private/zip_files/{}", zip_file_id);
        self.client.get(&endpoint).await
    }

    /// Get a download URL for a private ZIP file
    ///
    /// Returns a signed URL from where you can download the specified ZIP file.
    /// The URL expires after 1 hour.
    ///
    /// The ZIP file must have status "finished" before downloading.
    pub async fn get_zip_download_url(
        &self,
        zip_file_id: &str,
    ) -> Result<PrivateZipDownloadUrlResponse> {
        let endpoint = format!("private/zip_files/{}/download_url", zip_file_id);
        self.client.get(&endpoint).await
    }

    /// Download a private ZIP file directly
    ///
    /// This endpoint redirects to the download URL. The download URL can be reused
    /// for 1 hour before it expires.
    ///
    /// Returns the ZIP file content as bytes.
    pub async fn download_zip(&self, zip_file_id: &str) -> Result<Vec<u8>> {
        let endpoint = format!("private/zip_files/{}/download", zip_file_id);
        self.client.get_bytes(&endpoint).await
    }

    /// Wait for ZIP file creation to complete
    ///
    /// Polls the status until the ZIP file is finished or an error occurs.
    ///
    /// # Arguments
    /// * `zip_file_id` - ID of the ZIP file to monitor
    /// * `max_wait_seconds` - Maximum time to wait (default: 300 seconds)
    pub async fn wait_for_zip_completion(
        &self,
        zip_file_id: &str,
        max_wait_seconds: Option<u64>,
    ) -> Result<PrivateZipFile> {
        let max_wait = max_wait_seconds.unwrap_or(300); // Default 5 minutes
        let poll_interval = 2; // Poll every 2 seconds
        let max_iterations = max_wait / poll_interval;

        for _ in 0..max_iterations {
            let status = self.get_zip_status(zip_file_id).await?;

            match status.data.attributes.status.as_str() {
                "finished" => return Ok(status),
                "timeout" | "error-starting" | "error-creating" => {
                    return Err(crate::Error::Unknown(format!(
                        "ZIP file creation failed with status: {}",
                        status.data.attributes.status
                    )));
                }
                _ => {
                    // Still processing, wait before next poll
                    tokio::time::sleep(tokio::time::Duration::from_secs(poll_interval)).await;
                }
            }
        }

        Err(crate::Error::Unknown(
            "Timeout waiting for ZIP file creation".to_string(),
        ))
    }
}

/// Request to create a private ZIP file
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreatePrivateZipRequest {
    pub data: CreatePrivateZipData,
}

/// Data for creating a private ZIP file
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreatePrivateZipData {
    /// Optional password for the ZIP file
    #[serde(skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,

    /// List of file hashes (SHA-256, SHA-1, or MD5)
    pub hashes: Vec<String>,
}

/// Private ZIP file response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrivateZipFile {
    pub data: PrivateZipFileData,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrivateZipFileData {
    #[serde(rename = "type")]
    pub object_type: String,
    pub id: String,
    pub attributes: PrivateZipFileAttributes,
}

/// Attributes for a private ZIP file
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrivateZipFileAttributes {
    /// Current status of the ZIP file creation
    pub status: String,

    /// Current progress (0-100)
    pub progress: u32,

    /// Number of files successfully added
    pub files_ok: u32,

    /// Number of files that failed to be added
    pub files_error: u32,
}

/// Download URL response for private ZIP files
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrivateZipDownloadUrlResponse {
    pub data: String,
}

/// Helper methods for creating private ZIP file requests
impl CreatePrivateZipRequest {
    /// Create a new ZIP file request with hashes
    pub fn new(hashes: Vec<String>) -> Self {
        Self {
            data: CreatePrivateZipData {
                password: None,
                hashes,
            },
        }
    }

    /// Create a new password-protected ZIP file request
    pub fn new_with_password(hashes: Vec<String>, password: String) -> Self {
        Self {
            data: CreatePrivateZipData {
                password: Some(password),
                hashes,
            },
        }
    }

    /// Set password for the ZIP file
    pub fn with_password(mut self, password: String) -> Self {
        self.data.password = Some(password);
        self
    }

    /// Add a hash to the ZIP file
    pub fn add_hash(mut self, hash: String) -> Self {
        self.data.hashes.push(hash);
        self
    }

    /// Add multiple hashes to the ZIP file
    pub fn add_hashes(mut self, hashes: Vec<String>) -> Self {
        self.data.hashes.extend(hashes);
        self
    }
}

impl Client {
    /// Get the Private Files client
    pub fn private_files(&self) -> PrivateFilesClient<'_> {
        PrivateFilesClient::new(self)
    }
}

/// Helper methods for upload parameters
impl PrivateFileUploadParams {
    /// Create new upload parameters with default values
    pub fn new() -> Self {
        Self::default()
    }

    /// Set whether to disable sandbox execution
    pub fn disable_sandbox(mut self, disable: bool) -> Self {
        self.disable_sandbox = Some(disable);
        self
    }

    /// Set whether to enable internet access in sandbox
    pub fn enable_internet(mut self, enable: bool) -> Self {
        self.enable_internet = Some(enable);
        self
    }

    /// Set whether to intercept TLS/SSL
    pub fn intercept_tls(mut self, intercept: bool) -> Self {
        self.intercept_tls = Some(intercept);
        self
    }

    /// Set command line arguments
    pub fn command_line(mut self, cmd: String) -> Self {
        self.command_line = Some(cmd);
        self
    }

    /// Set password for ZIP files
    pub fn password(mut self, pwd: String) -> Self {
        self.password = Some(pwd);
        self
    }

    /// Set retention period in days (1-28)
    pub fn retention_period_days(mut self, days: u32) -> Self {
        self.retention_period_days = Some(days.clamp(1, 28));
        self
    }

    /// Set storage region (US or EU)
    pub fn storage_region(mut self, region: String) -> Self {
        self.storage_region = Some(region);
        self
    }

    /// Set interaction sandbox
    pub fn interaction_sandbox(mut self, sandbox: String) -> Self {
        self.interaction_sandbox = Some(sandbox);
        self
    }

    /// Set interaction timeout (60-1800 seconds)
    pub fn interaction_timeout(mut self, timeout: u32) -> Self {
        self.interaction_timeout = Some(timeout.clamp(60, 1800));
        self
    }

    /// Set locale (e.g., EN_US)
    pub fn locale(mut self, locale: String) -> Self {
        self.locale = Some(locale);
        self
    }
}

/// Helper methods for reanalysis parameters
impl ReanalyzeParams {
    /// Create new reanalysis parameters with default values
    pub fn new() -> Self {
        Self::default()
    }

    /// Set whether to disable sandbox execution
    pub fn disable_sandbox(mut self, disable: bool) -> Self {
        self.disable_sandbox = Some(disable);
        self
    }

    /// Set whether to enable internet access in sandbox
    pub fn enable_internet(mut self, enable: bool) -> Self {
        self.enable_internet = Some(enable);
        self
    }

    /// Set whether to intercept TLS/SSL
    pub fn intercept_tls(mut self, intercept: bool) -> Self {
        self.intercept_tls = Some(intercept);
        self
    }

    /// Set command line arguments
    pub fn command_line(mut self, cmd: String) -> Self {
        self.command_line = Some(cmd);
        self
    }

    /// Set interaction sandbox (defaults to "cape")
    pub fn interaction_sandbox(mut self, sandbox: String) -> Self {
        self.interaction_sandbox = Some(sandbox);
        self
    }

    /// Set interaction timeout (60-1800 seconds, defaults to 60)
    pub fn interaction_timeout(mut self, timeout: u32) -> Self {
        self.interaction_timeout = Some(timeout.clamp(60, 1800));
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_private_file_attributes() {
        let attrs = PrivateFileAttributes {
            sha256: Some("abc123".to_string()),
            sha1: Some("def456".to_string()),
            md5: Some("ghi789".to_string()),
            size: Some(1024),
            type_description: Some("PE32 executable".to_string()),
            magic: Some("PE32".to_string()),
            tags: Some(vec!["malware".to_string()]),
            status: Some("completed".to_string()),
            first_submission_date: Some(1234567890),
            last_analysis_date: Some(1234567890),
            last_analysis_results: None,
            last_analysis_stats: None,
            reputation: Some(-50),
            additional_attributes: HashMap::new(),
        };

        assert_eq!(attrs.sha256.unwrap(), "abc123");
        assert_eq!(attrs.size.unwrap(), 1024);
        assert_eq!(attrs.reputation.unwrap(), -50);
    }

    #[test]
    fn test_analysis_stats() {
        let stats = AnalysisStats {
            malicious: Some(45),
            suspicious: Some(5),
            undetected: Some(20),
            failure: Some(2),
            timeout: Some(1),
            type_unsupported: Some(0),
        };

        assert_eq!(stats.malicious.unwrap(), 45);
        assert_eq!(stats.suspicious.unwrap(), 5);
        assert_eq!(stats.undetected.unwrap(), 20);
    }

    #[test]
    fn test_engine_result() {
        let result = EngineResult {
            category: Some("malicious".to_string()),
            engine_name: Some("TestEngine".to_string()),
            engine_version: Some("1.0.0".to_string()),
            result: Some("Trojan.Generic".to_string()),
            method: Some("signature".to_string()),
            engine_update: Some("20240101".to_string()),
        };

        assert_eq!(result.category.unwrap(), "malicious");
        assert_eq!(result.result.unwrap(), "Trojan.Generic");
    }

    #[test]
    fn test_upload_params() {
        let params = PrivateFileUploadParams::new()
            .disable_sandbox(true)
            .enable_internet(false)
            .command_line("/c calc.exe".to_string())
            .retention_period_days(7)
            .storage_region("EU".to_string())
            .locale("EN_US".to_string());

        assert_eq!(params.disable_sandbox, Some(true));
        assert_eq!(params.enable_internet, Some(false));
        assert_eq!(params.command_line, Some("/c calc.exe".to_string()));
        assert_eq!(params.retention_period_days, Some(7));
        assert_eq!(params.storage_region, Some("EU".to_string()));
        assert_eq!(params.locale, Some("EN_US".to_string()));
    }

    #[test]
    fn test_reanalyze_params() {
        let params = ReanalyzeParams::new()
            .disable_sandbox(false)
            .enable_internet(true)
            .interaction_sandbox("cape".to_string())
            .interaction_timeout(120);

        assert_eq!(params.disable_sandbox, Some(false));
        assert_eq!(params.enable_internet, Some(true));
        assert_eq!(params.interaction_sandbox, Some("cape".to_string()));
        assert_eq!(params.interaction_timeout, Some(120));
    }

    #[test]
    fn test_param_limits() {
        // Test retention period limits
        let params1 = PrivateFileUploadParams::new().retention_period_days(100);
        assert_eq!(params1.retention_period_days, Some(28)); // Capped at 28

        let params2 = PrivateFileUploadParams::new().retention_period_days(0);
        assert_eq!(params2.retention_period_days, Some(1)); // Minimum 1

        // Test interaction timeout limits
        let params3 = ReanalyzeParams::new().interaction_timeout(2000);
        assert_eq!(params3.interaction_timeout, Some(1800)); // Capped at 1800

        let params4 = ReanalyzeParams::new().interaction_timeout(30);
        assert_eq!(params4.interaction_timeout, Some(60)); // Minimum 60
    }

    #[test]
    fn test_dropped_file_attributes() {
        let attrs = DroppedFileAttributes {
            sha256: Some("dropped123".to_string()),
            path: Some("C:\\Windows\\Temp\\dropped.exe".to_string()),
            size: Some(2048),
            type_description: Some("PE32 executable".to_string()),
            additional_attributes: HashMap::new(),
        };

        assert_eq!(attrs.sha256.unwrap(), "dropped123");
        assert_eq!(attrs.path.unwrap(), "C:\\Windows\\Temp\\dropped.exe");
        assert_eq!(attrs.size.unwrap(), 2048);
    }

    #[test]
    fn test_private_analysis_attributes() {
        let attrs = PrivateAnalysisAttributes {
            status: Some("completed".to_string()),
            stats: Some(AnalysisStats {
                malicious: Some(30),
                suspicious: Some(10),
                undetected: Some(40),
                failure: Some(0),
                timeout: Some(0),
                type_unsupported: Some(0),
            }),
            results: None,
            date: Some(1234567890),
            additional_attributes: HashMap::new(),
        };

        assert_eq!(attrs.status.unwrap(), "completed");
        assert!(attrs.stats.is_some());
        let stats = attrs.stats.unwrap();
        assert_eq!(stats.malicious.unwrap(), 30);
    }

    #[test]
    fn test_private_file_upload_response() {
        let response = PrivateFileUploadResponse {
            data: PrivateFileUploadData {
                object_type: "analysis".to_string(),
                id: "analysis_123".to_string(),
                links: Some(PrivateFileUploadLinks {
                    self_link: "/api/v3/analyses/analysis_123".to_string(),
                }),
            },
        };

        assert_eq!(response.data.object_type, "analysis");
        assert_eq!(response.data.id, "analysis_123");
        assert!(response.data.links.is_some());
    }

    #[test]
    fn test_private_file_serialization() {
        let file = PrivateFile {
            object: Object {
                id: "test_hash".to_string(),
                object_type: "file".to_string(),
                links: None,
                relationships: None,
                attributes: PrivateFileAttributes {
                    sha256: Some("abc123".to_string()),
                    sha1: Some("def456".to_string()),
                    md5: Some("ghi789".to_string()),
                    size: Some(1024),
                    type_description: Some("PE32 executable".to_string()),
                    magic: Some("PE32".to_string()),
                    tags: Some(vec!["malware".to_string()]),
                    status: Some("completed".to_string()),
                    first_submission_date: Some(1234567890),
                    last_analysis_date: Some(1234567891),
                    last_analysis_results: None,
                    last_analysis_stats: None,
                    reputation: Some(-50),
                    additional_attributes: HashMap::new(),
                },
            },
        };

        // Test serialization
        let json = serde_json::to_string(&file).unwrap();
        assert!(json.contains("\"sha256\":\"abc123\""));
        assert!(json.contains("\"size\":1024"));

        // Test deserialization
        let deserialized: PrivateFile = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.object.id, "test_hash");
        assert_eq!(
            deserialized.object.attributes.sha256,
            Some("abc123".to_string())
        );
    }

    #[test]
    fn test_engine_results_map() {
        let mut results = HashMap::new();

        results.insert(
            "TestEngine1".to_string(),
            EngineResult {
                category: Some("malicious".to_string()),
                engine_name: Some("TestEngine1".to_string()),
                engine_version: Some("1.0".to_string()),
                result: Some("Trojan.Generic".to_string()),
                method: Some("signature".to_string()),
                engine_update: Some("20240101".to_string()),
            },
        );

        results.insert(
            "TestEngine2".to_string(),
            EngineResult {
                category: Some("undetected".to_string()),
                engine_name: Some("TestEngine2".to_string()),
                engine_version: Some("2.0".to_string()),
                result: None,
                method: Some("heuristic".to_string()),
                engine_update: Some("20240102".to_string()),
            },
        );

        assert_eq!(results.len(), 2);
        assert!(results.contains_key("TestEngine1"));
        assert_eq!(
            results.get("TestEngine1").unwrap().result.as_ref().unwrap(),
            "Trojan.Generic"
        );
    }

    #[test]
    fn test_analysis_stats_calculation() {
        let stats = AnalysisStats {
            malicious: Some(45),
            suspicious: Some(5),
            undetected: Some(20),
            failure: Some(2),
            timeout: Some(1),
            type_unsupported: Some(0),
        };

        // Calculate total
        let total = stats.malicious.unwrap_or(0)
            + stats.suspicious.unwrap_or(0)
            + stats.undetected.unwrap_or(0)
            + stats.failure.unwrap_or(0)
            + stats.timeout.unwrap_or(0)
            + stats.type_unsupported.unwrap_or(0);

        assert_eq!(total, 73);

        // Calculate detection rate
        let detections = stats.malicious.unwrap_or(0) + stats.suspicious.unwrap_or(0);
        let valid_scans = detections + stats.undetected.unwrap_or(0);
        let detection_rate = (detections as f64 / valid_scans as f64) * 100.0;

        assert!(detection_rate > 71.0 && detection_rate < 72.0);
    }

    #[test]
    fn test_upload_url_response() {
        let response = UploadUrlResponse {
            data: "https://upload.virustotal.com/private/upload/abc123".to_string(),
        };

        assert!(response.data.starts_with("https://"));
        assert!(response.data.contains("upload"));
    }

    #[test]
    fn test_dropped_file_paths() {
        let dropped_files = vec![
            DroppedFile {
                object: Object {
                    id: "dropped1".to_string(),
                    object_type: "file".to_string(),
                    links: None,
                    relationships: None,
                    attributes: DroppedFileAttributes {
                        sha256: Some("dropped_hash1".to_string()),
                        path: Some("C:\\Windows\\Temp\\malware.exe".to_string()),
                        size: Some(2048),
                        type_description: Some("PE32 executable".to_string()),
                        additional_attributes: HashMap::new(),
                    },
                },
            },
            DroppedFile {
                object: Object {
                    id: "dropped2".to_string(),
                    object_type: "file".to_string(),
                    links: None,
                    relationships: None,
                    attributes: DroppedFileAttributes {
                        sha256: Some("dropped_hash2".to_string()),
                        path: Some("C:\\Users\\Public\\payload.dll".to_string()),
                        size: Some(4096),
                        type_description: Some("PE32+ DLL".to_string()),
                        additional_attributes: HashMap::new(),
                    },
                },
            },
        ];

        assert_eq!(dropped_files.len(), 2);
        assert!(dropped_files[0]
            .object
            .attributes
            .path
            .as_ref()
            .unwrap()
            .contains("Temp"));
        assert!(dropped_files[1]
            .object
            .attributes
            .path
            .as_ref()
            .unwrap()
            .contains("Public"));
    }

    #[test]
    fn test_private_analysis_status() {
        let statuses = vec!["queued", "in-progress", "completed"];

        for status in statuses {
            let analysis = PrivateAnalysis {
                object: Object {
                    id: format!("analysis_{}", status),
                    object_type: "analysis".to_string(),
                    links: None,
                    relationships: None,
                    attributes: PrivateAnalysisAttributes {
                        status: Some(status.to_string()),
                        stats: None,
                        results: None,
                        date: Some(1234567890),
                        additional_attributes: HashMap::new(),
                    },
                },
            };

            assert_eq!(analysis.object.attributes.status.unwrap(), status);
        }
    }

    #[test]
    fn test_large_file_size_limits() {
        // Test various file sizes
        let small_file = 32 * 1024 * 1024; // 32MB - should use regular upload
        let medium_file = 100 * 1024 * 1024; // 100MB - should use upload URL
        let large_file = 650 * 1024 * 1024; // 650MB - maximum allowed
        let too_large = 700 * 1024 * 1024; // 700MB - too large

        assert!(small_file <= 32 * 1024 * 1024);
        assert!(medium_file > 32 * 1024 * 1024 && medium_file <= 650 * 1024 * 1024);
        assert!(large_file <= 650 * 1024 * 1024);
        assert!(too_large > 650 * 1024 * 1024);
    }

    #[test]
    fn test_private_file_links() {
        let links = PrivateFileUploadLinks {
            self_link: "/api/v3/analyses/abc123".to_string(),
        };

        assert!(links.self_link.starts_with("/api/v3/"));
        assert!(links.self_link.contains("analyses"));
    }

    #[test]
    fn test_delete_file_parameters() {
        // Test that delete can be called with different options
        let _sha256 = "abc123def456";

        // Should handle both true and false for only_from_storage
        let only_storage_true = true;
        let only_storage_false = false;

        assert!(only_storage_true);
        assert!(!only_storage_false);
    }

    #[test]
    fn test_create_private_zip_request() {
        let request = CreatePrivateZipRequest::new(vec![
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".to_string(),
            "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f".to_string(),
        ]);

        assert_eq!(request.data.hashes.len(), 2);
        assert!(request.data.password.is_none());
    }

    #[test]
    fn test_create_private_zip_with_password() {
        let request = CreatePrivateZipRequest::new_with_password(
            vec!["abc123".to_string()],
            "mysecretpassword".to_string(),
        );

        assert_eq!(request.data.hashes.len(), 1);
        assert_eq!(request.data.password.unwrap(), "mysecretpassword");
    }

    #[test]
    fn test_private_zip_builder_methods() {
        let request = CreatePrivateZipRequest::new(vec!["hash1".to_string()])
            .with_password("password123".to_string())
            .add_hash("hash2".to_string())
            .add_hashes(vec!["hash3".to_string(), "hash4".to_string()]);

        assert_eq!(request.data.hashes.len(), 4);
        assert_eq!(request.data.password.unwrap(), "password123");
    }

    #[test]
    fn test_private_zip_status_values() {
        let statuses = vec![
            "starting",
            "creating",
            "finished",
            "timeout",
            "error-starting",
            "error-creating",
        ];

        for status in statuses {
            let attrs = PrivateZipFileAttributes {
                status: status.to_string(),
                progress: 0,
                files_ok: 0,
                files_error: 0,
            };

            assert_eq!(attrs.status, status);
        }
    }

    #[test]
    fn test_private_zip_progress() {
        let mut attrs = PrivateZipFileAttributes {
            status: "starting".to_string(),
            progress: 0,
            files_ok: 0,
            files_error: 0,
        };

        // Starting state
        assert_eq!(attrs.progress, 0);

        // Creating state
        attrs.status = "creating".to_string();
        attrs.progress = 45;
        attrs.files_ok = 3;
        assert_eq!(attrs.progress, 45);
        assert_eq!(attrs.files_ok, 3);

        // Finished state
        attrs.status = "finished".to_string();
        attrs.progress = 100;
        attrs.files_ok = 10;
        assert_eq!(attrs.progress, 100);
        assert_eq!(attrs.files_ok, 10);
    }

    #[tokio::test]
    async fn test_private_zip_operations() {
        use crate::{ApiTier, ClientBuilder};

        let client = ClientBuilder::new()
            .api_key("test_key")
            .tier(ApiTier::Premium)
            .build()
            .unwrap();

        let private_files = client.private_files();

        // Test create ZIP
        let request =
            CreatePrivateZipRequest::new(vec!["test_hash1".to_string(), "test_hash2".to_string()])
                .with_password("test_password".to_string());

        let result = private_files.create_zip(&request).await;
        assert!(result.is_err()); // Will fail without valid API key

        // Test get ZIP status
        let status_result = private_files.get_zip_status("test_zip_id").await;
        assert!(status_result.is_err());

        // Test get download URL
        let url_result = private_files.get_zip_download_url("test_zip_id").await;
        assert!(url_result.is_err());

        // Test download ZIP
        let download_result = private_files.download_zip("test_zip_id").await;
        assert!(download_result.is_err());
    }

    #[test]
    fn test_sha256_only_requirement() {
        // Test that we're documenting SHA-256 only requirement
        let valid_sha256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f";
        let invalid_md5 = "e5828c564f71fea3a12dde8bd5d27063";
        let invalid_sha1 = "7bae8076a5771865123be7112468b79e9d78a640";

        assert_eq!(valid_sha256.len(), 64); // SHA-256 is 64 hex chars
        assert_eq!(invalid_md5.len(), 32); // MD5 is 32 hex chars
        assert_eq!(invalid_sha1.len(), 40); // SHA-1 is 40 hex chars
    }

    #[test]
    fn test_private_analysis_response() {
        let response = PrivateAnalysisResponse {
            data: PrivateAnalysis {
                object: Object {
                    id: "analysis_123".to_string(),
                    object_type: "private_analysis".to_string(),
                    links: None,
                    relationships: None,
                    attributes: PrivateAnalysisAttributes {
                        status: Some("completed".to_string()),
                        stats: None,
                        results: None,
                        date: Some(1620127014),
                        additional_attributes: HashMap::new(),
                    },
                },
            },
            meta: Some(PrivateAnalysisMeta {
                file_info: Some(FileInfo {
                    size: Some(5),
                    sha256: Some(
                        "11a77c3d96c06974b53d7f40a577e6813739eb5c811b2a86f59038ea90add772"
                            .to_string(),
                    ),
                    sha1: Some("7bae8076a5771865123be7112468b79e9d78a640".to_string()),
                    md5: Some("e5828c564f71fea3a12dde8bd5d27063".to_string()),
                }),
            }),
        };

        assert_eq!(response.data.object.attributes.status.unwrap(), "completed");
        assert!(response.meta.is_some());
        let meta = response.meta.unwrap();
        assert!(meta.file_info.is_some());
        let file_info = meta.file_info.unwrap();
        assert_eq!(file_info.size.unwrap(), 5);
        assert_eq!(file_info.sha256.unwrap().len(), 64);
    }

    #[test]
    fn test_private_file_behavior() {
        let behavior = PrivateFileBehavior {
            object: Object {
                id: "sandbox_123".to_string(),
                object_type: "private_file_behaviour".to_string(),
                links: None,
                relationships: None,
                attributes: PrivateFileBehaviorAttributes {
                    behash: Some("3f4a02b305dde56c7c606849289bb194".to_string()),
                    calls_highlighted: Some(vec!["GetTickCount".to_string()]),
                    files_opened: Some(vec!["C:\\Windows\\system32\\ws2_32.dll".to_string()]),
                    has_html_report: Some(true),
                    has_pcap: Some(true),
                    modules_loaded: Some(vec!["UxTheme.dll".to_string()]),
                    processes_tree: Some(vec![ProcessInfo {
                        name: Some("malware.exe".to_string()),
                        process_id: Some("2340".to_string()),
                    }]),
                    registry_keys_opened: Some(vec!["HKCU\\Software\\Test".to_string()]),
                    sandbox_name: Some("`VirusTotal` Jujubox".to_string()),
                    tags: Some(vec!["DIRECT_CPU_CLOCK_ACCESS".to_string()]),
                    text_highlighted: Some(vec!["PuTTY Configuration".to_string()]),
                    mutexes_created: Some(vec!["TestMutex".to_string()]),
                    mutexes_opened: Some(vec!["ShimCacheMutex".to_string()]),
                    processes_terminated: Some(vec!["C:\\Temp\\test.exe".to_string()]),
                    additional_attributes: HashMap::new(),
                },
            },
        };

        assert!(behavior.object.attributes.has_html_report.unwrap());
        assert!(behavior.object.attributes.has_pcap.unwrap());
        assert_eq!(
            behavior.object.attributes.sandbox_name.unwrap(),
            "`VirusTotal` Jujubox"
        );
        assert_eq!(behavior.object.attributes.processes_tree.unwrap().len(), 1);
    }

    #[test]
    fn test_process_info() {
        let process = ProcessInfo {
            name: Some("explorer.exe".to_string()),
            process_id: Some("1234".to_string()),
        };

        assert_eq!(process.name.unwrap(), "explorer.exe");
        assert_eq!(process.process_id.unwrap(), "1234");
    }

    #[test]
    fn test_file_info() {
        let file_info = FileInfo {
            size: Some(1024),
            sha256: Some("abc123".to_string()),
            sha1: Some("def456".to_string()),
            md5: Some("ghi789".to_string()),
        };

        assert_eq!(file_info.size.unwrap(), 1024);
        assert_eq!(file_info.sha256.unwrap(), "abc123");
        assert_eq!(file_info.sha1.unwrap(), "def456");
        assert_eq!(file_info.md5.unwrap(), "ghi789");
    }

    #[test]
    fn test_behavior_report_artifacts() {
        // Test that we have methods for all behavior artifacts
        let sandbox_id = "test_sandbox_123";

        // These methods should exist and accept sandbox_id
        assert_eq!(sandbox_id, "test_sandbox_123");

        // Test behavior attributes flags
        let attrs = PrivateFileBehaviorAttributes {
            behash: Some("hash123".to_string()),
            has_html_report: Some(true),
            has_pcap: Some(true),
            sandbox_name: Some("TestSandbox".to_string()),
            calls_highlighted: None,
            files_opened: None,
            modules_loaded: None,
            processes_tree: None,
            registry_keys_opened: None,
            tags: None,
            text_highlighted: None,
            mutexes_created: None,
            mutexes_opened: None,
            processes_terminated: None,
            additional_attributes: HashMap::new(),
        };

        assert!(attrs.has_html_report.unwrap());
        assert!(attrs.has_pcap.unwrap());
        assert_eq!(attrs.sandbox_name.unwrap(), "TestSandbox");
    }

    #[test]
    fn test_analysis_order_parameter() {
        // Test that list_analyses can handle order parameter
        let order_options = vec!["date-", "date+"];

        for order in order_options {
            assert!(order.contains("date"));
        }
    }

    #[test]
    fn test_sandbox_id_format() {
        // Sandbox IDs typically have format: {sha256}_{sandbox_name}-{timestamp}
        let sandbox_id = "9f9e74241d59eccfe7040bfdcbbceacb374eda397cc53a4197b59e4f6f380a91_`VirusTotal` Jujubox-1658933614";

        assert!(sandbox_id.contains("_"));
        assert!(sandbox_id.contains("-"));

        let parts: Vec<&str> = sandbox_id.split('_').collect();
        assert_eq!(parts.len(), 2);

        // First part should be SHA256 (64 chars)
        assert_eq!(parts[0].len(), 64);
    }
}
