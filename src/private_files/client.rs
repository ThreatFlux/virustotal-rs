//! Client for Private File Scanning operations

use super::{analysis::*, behavior::*, types::*, upload::*, zip::*};
use crate::files::{FileBehavior, FileBehaviorSummary, MitreTrees};
use crate::objects::{Collection, CollectionIterator};
use crate::url_utils::{EndpointBuilder, Endpoints};
use crate::{Client, Result};

/// Client for Private File Scanning operations
pub struct PrivateFilesClient<'a> {
    pub(crate) client: &'a Client,
}

impl<'a> PrivateFilesClient<'a> {
    pub fn new(client: &'a Client) -> Self {
        Self { client }
    }

    // Analysis operations

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
        let endpoint = EndpointBuilder::new()
            .raw_segment("private")
            .raw_segment("analyses")
            .query_opt("limit", limit.map(|l| l.min(40))) // Maximum 40 analyses
            .query_opt("cursor", cursor)
            .query("order", order.unwrap_or("date-")) // Default to date- (most recent first)
            .build();

        self.client.get(&endpoint).await
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

    // Upload operations

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
            form = self.add_upload_params_to_form(form, p)?;
        }

        self.client.post_multipart("private/files", form).await
    }

    /// Helper method to add upload parameters to multipart form
    fn add_upload_params_to_form(
        &self,
        mut form: reqwest::multipart::Form,
        params: PrivateFileUploadParams,
    ) -> Result<reqwest::multipart::Form> {
        if let Some(disable_sandbox) = params.disable_sandbox {
            form = form.text("disable_sandbox", disable_sandbox.to_string());
        }
        if let Some(enable_internet) = params.enable_internet {
            form = form.text("enable_internet", enable_internet.to_string());
        }
        if let Some(intercept_tls) = params.intercept_tls {
            form = form.text("intercept_tls", intercept_tls.to_string());
        }
        if let Some(command_line) = params.command_line {
            form = form.text("command_line", command_line);
        }
        if let Some(password) = params.password {
            form = form.text("password", password);
        }
        if let Some(retention_period_days) = params.retention_period_days {
            form = form.text("retention_period_days", retention_period_days.to_string());
        }
        if let Some(storage_region) = params.storage_region {
            form = form.text("storage_region", storage_region);
        }
        if let Some(interaction_sandbox) = params.interaction_sandbox {
            form = form.text("interaction_sandbox", interaction_sandbox);
        }
        if let Some(interaction_timeout) = params.interaction_timeout {
            form = form.text("interaction_timeout", interaction_timeout.to_string());
        }
        if let Some(locale) = params.locale {
            form = form.text("locale", locale);
        }
        Ok(form)
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

    // File management operations

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
        let url = Endpoints::private_file(sha256)?
            .query_opt(
                "only_from_storage",
                if only_from_storage {
                    Some("true")
                } else {
                    None
                },
            )
            .build();
        self.client.delete(&url).await
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

    // Analysis operations for specific files

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
        let base_path = format!("private/files/{}/analyses", urlencoding::encode(sha256));
        let url = Self::build_paginated_url(&base_path, limit, cursor);
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
            let query_params = self.build_reanalysis_query_params(p);
            if !query_params.is_empty() {
                url.push('?');
                url.push_str(&query_params.join("&"));
            }
        }

        let empty_body = serde_json::json!({});
        self.client.post(&url, &empty_body).await
    }

    /// Helper method to build query parameters for reanalysis
    fn build_reanalysis_query_params(&self, params: ReanalyzeParams) -> Vec<String> {
        let mut query_params = Vec::new();

        if let Some(disable_sandbox) = params.disable_sandbox {
            query_params.push(format!("disable_sandbox={}", disable_sandbox));
        }
        if let Some(enable_internet) = params.enable_internet {
            query_params.push(format!("enable_internet={}", enable_internet));
        }
        if let Some(intercept_tls) = params.intercept_tls {
            query_params.push(format!("intercept_tls={}", intercept_tls));
        }
        if let Some(ref command_line) = params.command_line {
            query_params.push(format!(
                "command_line={}",
                urlencoding::encode(command_line)
            ));
        }
        if let Some(ref interaction_sandbox) = params.interaction_sandbox {
            query_params.push(format!(
                "interaction_sandbox={}",
                urlencoding::encode(interaction_sandbox)
            ));
        }
        if let Some(interaction_timeout) = params.interaction_timeout {
            query_params.push(format!("interaction_timeout={}", interaction_timeout));
        }

        query_params
    }

    // Behavior analysis operations

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
        let base_path = format!("private/files/{}/behaviours", urlencoding::encode(sha256));
        let url = Self::build_paginated_url(&base_path, limit, cursor);
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
        let base_path = format!(
            "private/files/{}/dropped_files",
            urlencoding::encode(sha256)
        );
        let url = Self::build_paginated_url(&base_path, limit, cursor);
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

    // Detailed behavior reports

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

    // Relationship operations

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

    /// Build URL for paginated queries
    fn build_paginated_url(base_path: &str, limit: Option<u32>, cursor: Option<&str>) -> String {
        let mut params = Vec::new();

        if let Some(l) = limit {
            params.push(format!("limit={}", l));
        }
        if let Some(c) = cursor {
            params.push(format!("cursor={}", urlencoding::encode(c)));
        }

        if params.is_empty() {
            base_path.to_string()
        } else {
            format!("{}?{}", base_path, params.join("&"))
        }
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
        let base_path = format!(
            "private/files/{}/{}",
            urlencoding::encode(sha256),
            relationship
        );
        let url = Self::build_paginated_url(&base_path, limit, cursor);
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
        let base_path = format!(
            "private/files/{}/relationships/{}",
            urlencoding::encode(sha256),
            relationship
        );
        let url = Self::build_paginated_url(&base_path, limit, cursor);
        self.client.get(&url).await
    }

    // Comments operations

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
        let base_path = format!("private/files/{}/comments", urlencoding::encode(sha256));
        let url = Self::build_paginated_url(&base_path, limit, cursor);
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

    // ZIP file operations

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
                    return Err(crate::Error::unknown(format!(
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

        Err(crate::Error::unknown(
            "Timeout waiting for ZIP file creation",
        ))
    }
}
