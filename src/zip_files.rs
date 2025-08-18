use crate::objects::Object;
use crate::{Client, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Represents a ZIP file in VirusTotal
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZipFile {
    #[serde(flatten)]
    pub object: Object<ZipFileAttributes>,
}

/// Attributes for a ZIP file
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ZipFileAttributes {
    /// Current status of the ZIP file creation
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<ZipFileStatus>,

    /// Current progress (0-100)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub progress: Option<u8>,

    /// Number of files successfully added
    #[serde(skip_serializing_if = "Option::is_none")]
    pub files_ok: Option<u32>,

    /// Number of files that failed to be added
    #[serde(skip_serializing_if = "Option::is_none")]
    pub files_error: Option<u32>,

    /// Total number of files to be added
    #[serde(skip_serializing_if = "Option::is_none")]
    pub files_total: Option<u32>,

    /// Additional attributes
    #[serde(flatten)]
    pub additional_attributes: HashMap<String, serde_json::Value>,
}

/// Status of ZIP file creation
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub enum ZipFileStatus {
    Starting,
    Creating,
    Finished,
    Timeout,
    ErrorStarting,
    ErrorCreating,
}

/// Request to create a ZIP file
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateZipFileRequest {
    pub data: CreateZipFileData,
}

/// Data for creating a ZIP file
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateZipFileData {
    /// Password for the ZIP file
    #[serde(skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,

    /// List of file hashes (SHA-256, SHA-1, or MD5)
    pub hashes: Vec<String>,
}

/// Response containing a download URL
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DownloadUrlResponse {
    pub data: String,
}

/// Client for ZIP files operations
pub struct ZipFilesClient<'a> {
    pub(crate) client: &'a Client,
}

impl<'a> ZipFilesClient<'a> {
    pub fn new(client: &'a Client) -> Self {
        Self { client }
    }

    /// Create a password-protected ZIP file containing specified files
    ///
    /// The files are specified by their hashes (SHA-256, SHA-1, or MD5).
    /// The ZIP file creation is asynchronous - use `get_status()` to check progress.
    pub async fn create(&self, request: &CreateZipFileRequest) -> Result<ZipFile> {
        self.client.post("intelligence/zip_files", request).await
    }

    /// Check the status of a ZIP file
    ///
    /// Returns the current status and progress of the ZIP file creation.
    /// When status is "finished", the file can be downloaded.
    pub async fn get_status(&self, zip_file_id: &str) -> Result<ZipFile> {
        let url = format!("intelligence/zip_files/{}", zip_file_id);
        self.client.get(&url).await
    }

    /// Get a download URL for a ZIP file
    ///
    /// Returns a signed URL that expires after 1 hour.
    /// The ZIP file must have status "finished" before downloading.
    pub async fn get_download_url(&self, zip_file_id: &str) -> Result<DownloadUrlResponse> {
        let url = format!("intelligence/zip_files/{}/download_url", zip_file_id);
        self.client.get(&url).await
    }

    /// Download a ZIP file directly
    ///
    /// Downloads the ZIP file content as bytes.
    /// The ZIP file must have status "finished" before downloading.
    pub async fn download(&self, zip_file_id: &str) -> Result<Vec<u8>> {
        let url = format!("intelligence/zip_files/{}/download", zip_file_id);
        self.client.get_bytes(&url).await
    }

    /// Wait for ZIP file creation to complete
    ///
    /// Polls the status until the ZIP file is finished or an error occurs.
    /// Returns the final status.
    pub async fn wait_for_completion(
        &self,
        zip_file_id: &str,
        max_wait_seconds: Option<u64>,
    ) -> Result<ZipFile> {
        let max_wait = max_wait_seconds.unwrap_or(300); // Default 5 minutes
        let poll_interval = 2; // Poll every 2 seconds
        let max_iterations = max_wait / poll_interval;

        for _ in 0..max_iterations {
            let status = self.get_status(zip_file_id).await?;

            if let Some(ref file_status) = status.object.attributes.status {
                match file_status {
                    ZipFileStatus::Finished => return Ok(status),
                    ZipFileStatus::Timeout
                    | ZipFileStatus::ErrorStarting
                    | ZipFileStatus::ErrorCreating => {
                        return Err(crate::Error::Unknown(format!(
                            "ZIP file creation failed with status: {:?}",
                            file_status
                        )));
                    }
                    _ => {
                        // Still processing, wait before next poll
                        tokio::time::sleep(tokio::time::Duration::from_secs(poll_interval)).await;
                    }
                }
            }
        }

        Err(crate::Error::Unknown(
            "Timeout waiting for ZIP file creation".to_string(),
        ))
    }
}

/// Helper methods for creating ZIP files
impl CreateZipFileRequest {
    /// Create a new ZIP file request with hashes
    pub fn new(hashes: Vec<String>) -> Self {
        Self {
            data: CreateZipFileData {
                password: None,
                hashes,
            },
        }
    }

    /// Create a new password-protected ZIP file request
    pub fn new_with_password(hashes: Vec<String>, password: String) -> Self {
        Self {
            data: CreateZipFileData {
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
    /// Get the ZIP files client for bulk file download operations
    pub fn zip_files(&self) -> ZipFilesClient<'_> {
        ZipFilesClient::new(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_zip_file_attributes() {
        let attrs = ZipFileAttributes {
            status: Some(ZipFileStatus::Creating),
            progress: Some(45),
            files_ok: Some(3),
            files_error: Some(0),
            files_total: Some(10),
            ..Default::default()
        };

        assert_eq!(attrs.status.unwrap(), ZipFileStatus::Creating);
        assert_eq!(attrs.progress.unwrap(), 45);
        assert_eq!(attrs.files_ok.unwrap(), 3);
        assert_eq!(attrs.files_error.unwrap(), 0);
        assert_eq!(attrs.files_total.unwrap(), 10);
    }

    #[test]
    fn test_zip_file_status() {
        let statuses = vec![
            ZipFileStatus::Starting,
            ZipFileStatus::Creating,
            ZipFileStatus::Finished,
            ZipFileStatus::Timeout,
            ZipFileStatus::ErrorStarting,
            ZipFileStatus::ErrorCreating,
        ];

        for status in statuses {
            let json = serde_json::to_string(&status).unwrap();
            let deserialized: ZipFileStatus = serde_json::from_str(&json).unwrap();
            assert_eq!(status, deserialized);
        }
    }

    #[test]
    fn test_create_zip_file_request() {
        let request = CreateZipFileRequest::new(vec![
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".to_string(),
            "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f".to_string(),
        ])
        .with_password("mysecretpassword".to_string());

        assert_eq!(request.data.hashes.len(), 2);
        assert_eq!(request.data.password.unwrap(), "mysecretpassword");
    }

    #[test]
    fn test_create_zip_file_with_password() {
        let request = CreateZipFileRequest::new_with_password(
            vec!["abc123".to_string()],
            "password123".to_string(),
        );

        assert_eq!(request.data.hashes.len(), 1);
        assert_eq!(request.data.hashes[0], "abc123");
        assert_eq!(request.data.password.unwrap(), "password123");
    }

    #[test]
    fn test_add_hashes_to_request() {
        let request = CreateZipFileRequest::new(vec!["hash1".to_string()])
            .add_hash("hash2".to_string())
            .add_hashes(vec!["hash3".to_string(), "hash4".to_string()]);

        assert_eq!(request.data.hashes.len(), 4);
        assert_eq!(request.data.hashes[0], "hash1");
        assert_eq!(request.data.hashes[1], "hash2");
        assert_eq!(request.data.hashes[2], "hash3");
        assert_eq!(request.data.hashes[3], "hash4");
    }

    #[test]
    fn test_zip_file_progress() {
        // Starting state
        let mut attrs = ZipFileAttributes {
            status: Some(ZipFileStatus::Starting),
            progress: Some(0),
            ..Default::default()
        };
        assert_eq!(attrs.progress.unwrap(), 0);

        // Creating state
        attrs.status = Some(ZipFileStatus::Creating);
        attrs.progress = Some(50);
        assert_eq!(attrs.progress.unwrap(), 50);

        // Finished state
        attrs.status = Some(ZipFileStatus::Finished);
        attrs.progress = Some(100);
        assert_eq!(attrs.progress.unwrap(), 100);
    }
}
