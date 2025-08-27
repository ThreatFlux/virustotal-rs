//! Behavior analysis operations for private files
//!
//! This module contains methods for analyzing file behavior including
//! behavior reports, MITRE data, dropped files, and detailed artifacts.

use super::{PrivateFilesClient, Result};
use crate::files::{FileBehavior, FileBehaviorSummary, MitreTrees};
use crate::objects::{Collection, CollectionIterator};
use crate::private_files::{DroppedFile, PrivateFileBehavior};

impl<'a> PrivateFilesClient<'a> {
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
}
