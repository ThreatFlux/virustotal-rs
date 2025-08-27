//! File analysis operations for private files
//!
//! This module contains methods for analyzing private files including
//! getting analysis status, listing analyses, and triggering reanalysis.

use super::{PrivateFilesClient, Result};
use crate::objects::{Collection, CollectionIterator};
use crate::private_files::{PrivateAnalysis, ReanalyzeParams};

impl<'a> PrivateFilesClient<'a> {
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
}
