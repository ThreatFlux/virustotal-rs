//! Analysis operations for private files
//!
//! This module contains methods for handling private analysis operations
//! including listing, retrieving, and managing analyses.

use super::{PrivateFilesClient, Result};
use crate::objects::{Collection, CollectionIterator};
use crate::private_files::{PrivateAnalysis, PrivateAnalysisResponse};
use crate::url_utils::EndpointBuilder;

impl<'a> PrivateFilesClient<'a> {
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
}
