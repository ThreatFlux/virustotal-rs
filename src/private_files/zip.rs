//! ZIP file handling for private files

use serde::{Deserialize, Serialize};

/// Request for creating a private ZIP file
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
