//! URL and endpoint builders for constructing VirusTotal API URLs

use crate::error::{Error, Result};
use super::constants::VT_API_BASE;
use super::encoding::{encode_path_segment, build_query_string};
use std::collections::HashMap;
use std::fmt;
use url::Url;

/// Builder for constructing VirusTotal API URLs
#[derive(Debug, Clone)]
pub struct VirusTotalUrlBuilder {
    base_url: String,
}

impl Default for VirusTotalUrlBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl VirusTotalUrlBuilder {
    /// Create a new URL builder with the default base URL
    pub fn new() -> Self {
        Self {
            base_url: VT_API_BASE.to_string(),
        }
    }

    /// Create a URL builder with a custom base URL
    pub fn with_base_url(base_url: &str) -> Result<Self> {
        // Ensure base URL ends with '/'
        let normalized_base = if base_url.ends_with('/') {
            base_url.to_string()
        } else {
            format!("{}/", base_url)
        };

        // Validate the base URL
        Url::parse(&normalized_base)
            .map_err(|e| Error::bad_request(format!("Invalid base URL: {}", e)))?;

        Ok(Self {
            base_url: normalized_base,
        })
    }

    /// Get the base URL
    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    /// Build a complete URL from an endpoint
    pub fn build(&self, endpoint: &str) -> Result<String> {
        let base = Url::parse(&self.base_url)
            .map_err(|e| Error::bad_request(format!("Invalid base URL: {}", e)))?;

        let url = base
            .join(endpoint)
            .map_err(|e| Error::bad_request(format!("Invalid endpoint '{}': {}", endpoint, e)))?;

        Ok(url.to_string())
    }
}

/// Builder for constructing API endpoint paths
#[derive(Debug, Clone)]
pub struct EndpointBuilder {
    segments: Vec<String>,
    query_params: HashMap<String, String>,
}

impl Default for EndpointBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl EndpointBuilder {
    /// Create a new endpoint builder
    pub fn new() -> Self {
        Self {
            segments: Vec::new(),
            query_params: HashMap::new(),
        }
    }

    /// Add a path segment
    pub fn segment(mut self, segment: &str) -> Self {
        self.segments.push(encode_path_segment(segment));
        self
    }

    /// Add a raw segment without encoding (use with caution)
    pub fn raw_segment(mut self, segment: &str) -> Self {
        self.segments.push(segment.to_string());
        self
    }

    /// Add multiple segments
    pub fn segments<I, S>(mut self, segments: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        for segment in segments {
            self.segments.push(encode_path_segment(segment.as_ref()));
        }
        self
    }

    /// Add a query parameter
    pub fn query<K, V>(mut self, key: K, value: V) -> Self
    where
        K: Into<String>,
        V: fmt::Display,
    {
        self.query_params.insert(key.into(), value.to_string());
        self
    }

    /// Add an optional query parameter
    pub fn query_opt<K, V>(self, key: K, value: Option<V>) -> Self
    where
        K: Into<String>,
        V: fmt::Display,
    {
        match value {
            Some(v) => self.query(key, v),
            None => self,
        }
    }

    /// Add multiple query parameters
    pub fn queries<I, K, V>(mut self, params: I) -> Self
    where
        I: IntoIterator<Item = (K, V)>,
        K: Into<String>,
        V: fmt::Display,
    {
        for (key, value) in params {
            self.query_params.insert(key.into(), value.to_string());
        }
        self
    }

    /// Build the endpoint path
    pub fn build(self) -> String {
        let mut path = self.segments.join("/");

        if !self.query_params.is_empty() {
            path.push('?');
            path.push_str(&build_query_string(&self.query_params));
        }

        path
    }
}

/// Query parameter builder for common patterns
#[derive(Debug, Clone)]
pub struct QueryBuilder {
    params: HashMap<String, String>,
}

impl Default for QueryBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl QueryBuilder {
    /// Create a new query builder
    pub fn new() -> Self {
        Self {
            params: HashMap::new(),
        }
    }

    /// Add a parameter
    pub fn param<K, V>(mut self, key: K, value: V) -> Self
    where
        K: Into<String>,
        V: fmt::Display,
    {
        self.params.insert(key.into(), value.to_string());
        self
    }

    /// Add an optional parameter
    pub fn param_opt<K, V>(self, key: K, value: Option<V>) -> Self
    where
        K: Into<String>,
        V: fmt::Display,
    {
        match value {
            Some(v) => self.param(key, v),
            None => self,
        }
    }

    /// Add limit parameter
    pub fn limit(self, limit: u32) -> Self {
        self.param("limit", limit)
    }

    /// Add cursor parameter
    pub fn cursor(self, cursor: &str) -> Self {
        self.param("cursor", cursor)
    }

    /// Add filter parameter
    pub fn filter(self, filter: &str) -> Self {
        self.param("filter", filter)
    }

    /// Add order parameter
    pub fn order(self, order: &str) -> Self {
        self.param("order", order)
    }

    /// Build the query string
    pub fn build(self) -> String {
        build_query_string(&self.params)
    }

    /// Get parameters as HashMap
    pub fn into_params(self) -> HashMap<String, String> {
        self.params
    }
}