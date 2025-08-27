//! Helper utilities for private files client
//!
//! This module contains utility functions and helpers used across
//! multiple private files operations.

use super::PrivateFilesClient;

impl<'a> PrivateFilesClient<'a> {
    /// Build URL for paginated queries
    pub(super) fn build_paginated_url(
        base_path: &str,
        limit: Option<u32>,
        cursor: Option<&str>,
    ) -> String {
        let mut url = base_path.to_string();
        let mut query_params = Vec::new();

        if let Some(l) = limit {
            query_params.push(format!("limit={}", l));
        }

        if let Some(c) = cursor {
            query_params.push(format!("cursor={}", urlencoding::encode(c)));
        }

        if !query_params.is_empty() {
            url.push('?');
            url.push_str(&query_params.join("&"));
        }

        url
    }
}
