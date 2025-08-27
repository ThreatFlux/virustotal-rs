//! Miscellaneous operations for private files
//!
//! This module contains various operations including relationships,
//! comments, and ZIP file operations.

use super::{PrivateFilesClient, Result};
use crate::objects::Collection;
use crate::private_files::{
    CreatePrivateZipRequest, PrivateZipDownloadUrlResponse, PrivateZipFile,
};

impl<'a> PrivateFilesClient<'a> {
    // Relationship operations

    /// Get objects related to a private file
    ///
    /// GET /private/files/{id}/{relationship}
    ///
    /// Parameters:
    /// - `sha256`: File's SHA-256 hash
    /// - `relationship`: The relationship type
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
    ///
    /// Parameters:
    /// - `sha256`: File's SHA-256 hash
    /// - `relationship`: The relationship type
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
    ///
    /// Returns the ZIP file content as bytes.
    pub async fn download_zip(&self, zip_file_id: &str) -> Result<Vec<u8>> {
        let endpoint = format!("private/zip_files/{}/download", zip_file_id);
        self.client.get_bytes(&endpoint).await
    }

    /// Wait for ZIP file creation to complete
    ///
    /// Polls the status until the ZIP file is finished or an error occurs.
    pub async fn wait_for_zip_completion(
        &self,
        zip_file_id: &str,
        poll_interval_seconds: u64,
        max_wait_minutes: u64,
    ) -> Result<PrivateZipFile> {
        use tokio::time::{sleep, Duration, Instant};

        let start_time = Instant::now();
        let max_duration = Duration::from_secs(max_wait_minutes * 60);
        let poll_interval = Duration::from_secs(poll_interval_seconds);

        loop {
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
                    // Still in progress, check timeout
                    if start_time.elapsed() >= max_duration {
                        return Err(crate::Error::Unknown(
                            "Timeout waiting for ZIP file creation".to_string(),
                        ));
                    }

                    sleep(poll_interval).await;
                }
            }
        }
    }
}
