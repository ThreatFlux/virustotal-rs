//! File management operations for private files
//!
//! This module contains methods for managing private files including
//! listing, retrieving, deleting, and downloading files.

use super::{PrivateFilesClient, Result};
use crate::objects::{Collection, CollectionIterator};
use crate::private_files::PrivateFile;
use crate::url_utils::Endpoints;

impl<'a> PrivateFilesClient<'a> {
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
}
