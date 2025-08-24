use crate::analysis::AnalysisResponse;
use crate::comments::{
    Comment, CommentIterator, CreateCommentAttributes, CreateCommentData, CreateCommentRequest,
};
use crate::common::AnalysisStats;
use crate::objects::{Collection, CollectionIterator, Object, ObjectOperations, ObjectResponse};
use crate::votes::{Vote, VoteRequest, VoteVerdict};
use crate::{Client, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;

/// Represents a URL object in `VirusTotal`
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Url {
    #[serde(flatten)]
    pub object: Object<UrlAttributes>,
}

/// Attributes for a URL object
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct UrlAttributes {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub final_url: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_analysis_date: Option<i64>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_analysis_stats: Option<AnalysisStats>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_analysis_results: Option<HashMap<String, UrlAnalysisResult>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_submission_date: Option<i64>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_http_response_code: Option<i32>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_http_response_content_length: Option<i64>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_http_response_content_sha256: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_http_response_headers: Option<HashMap<String, String>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_http_response_cookies: Option<HashMap<String, String>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub categories: Option<HashMap<String, String>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub reputation: Option<i32>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub times_submitted: Option<i32>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub threat_names: Option<Vec<String>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub tags: Option<Vec<String>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub total_votes: Option<VoteSummary>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub trackers: Option<HashMap<String, TrackerInfo>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub html_meta: Option<HashMap<String, Vec<String>>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub outgoing_links: Option<Vec<String>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub redirection_chain: Option<Vec<String>>,

    #[serde(flatten)]
    pub additional_attributes: HashMap<String, serde_json::Value>,
}

/// Analysis result from a specific scanner
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UrlAnalysisResult {
    pub method: String,
    pub engine_name: String,
    pub category: String,
    pub result: String,
}

/// Vote summary for a URL
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VoteSummary {
    pub harmless: i32,
    pub malicious: i32,
}

/// Tracker information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrackerInfo {
    pub url: Option<String>,
    pub timestamp: Option<i64>,
    pub id: Option<String>,
}

/// Request structure for scanning a URL
#[derive(Debug, Clone, Serialize)]
pub struct UrlScanRequest {
    pub url: String,
}

impl ObjectOperations for Url {
    type Attributes = UrlAttributes;

    fn collection_name() -> &'static str {
        "urls"
    }
}

/// Client for interacting with URL-related endpoints
pub struct UrlClient<'a> {
    pub(crate) client: &'a Client,
}

impl<'a> UrlClient<'a> {
    pub fn new(client: &'a Client) -> Self {
        Self { client }
    }

    /// Generate a URL identifier using base64 encoding (without padding)
    pub fn generate_url_id(url: &str) -> String {
        URL_SAFE_NO_PAD.encode(url.as_bytes())
    }

    /// Generate a URL identifier using SHA256 of the canonized URL
    /// Note: This is a simplified version. Full canonicalization is done server-side
    pub fn generate_url_sha256(url: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(url.as_bytes());
        format!("{:x}", hasher.finalize())
    }

    /// Scan a URL for analysis
    pub async fn scan(&self, url: &str) -> Result<AnalysisResponse> {
        let endpoint = "urls";
        let mut form = HashMap::new();
        form.insert("url", url);

        // Use a custom method to send form data
        let response = self.client.post_form(endpoint, &form).await?;
        Ok(response)
    }

    /// Get a URL report by ID
    /// The ID can be either:
    /// - SHA256 of the canonized URL
    /// - Base64 representation of the URL (without padding)
    pub async fn get(&self, url_id: &str) -> Result<Url> {
        let url = Url::object_url(url_id);
        let response: ObjectResponse<UrlAttributes> = self.client.get(&url).await?;
        Ok(Url {
            object: response.data,
        })
    }

    /// Get a URL report by actual URL (convenience method)
    pub async fn get_by_url(&self, url: &str) -> Result<Url> {
        let url_id = Self::generate_url_id(url);
        self.get(&url_id).await
    }

    /// Request a URL rescan (re-analyze)
    pub async fn rescan(&self, url_id: &str) -> Result<AnalysisResponse> {
        let endpoint = format!("{}/{}/analyse", Url::collection_name(), url_id);
        self.client.post(&endpoint, &()).await
    }

    /// Request a URL rescan by actual URL (convenience method)
    pub async fn rescan_by_url(&self, url: &str) -> Result<AnalysisResponse> {
        let url_id = Self::generate_url_id(url);
        self.rescan(&url_id).await
    }

    /// Get comments on a URL
    pub async fn get_comments(&self, url_id: &str) -> Result<Collection<Comment>> {
        let endpoint = format!("{}/{}/comments", Url::collection_name(), url_id);
        self.client.get(&endpoint).await
    }

    /// Get comments iterator for paginated results
    pub fn get_comments_iterator(&self, url_id: &str) -> CommentIterator<'_> {
        let url = format!("{}/{}/comments", Url::collection_name(), url_id);
        CommentIterator::new(self.client, url)
    }

    /// Add a comment on a URL
    pub async fn add_comment(&self, url_id: &str, text: &str) -> Result<Comment> {
        let endpoint = format!("{}/{}/comments", Url::collection_name(), url_id);
        let request = CreateCommentRequest {
            data: CreateCommentData {
                object_type: "comment".to_string(),
                attributes: CreateCommentAttributes {
                    text: text.to_string(),
                },
            },
        };
        self.client.post(&endpoint, &request).await
    }

    /// Get votes on a URL
    pub async fn get_votes(&self, url_id: &str) -> Result<Collection<Vote>> {
        let endpoint = format!("{}/{}/votes", Url::collection_name(), url_id);
        self.client.get(&endpoint).await
    }

    /// Get votes iterator for paginated results
    pub fn get_votes_iterator(&self, url_id: &str) -> CollectionIterator<'_, Vote> {
        let url = format!("{}/{}/votes", Url::collection_name(), url_id);
        CollectionIterator::new(self.client, url)
    }

    /// Add a vote on a URL
    pub async fn add_vote(&self, url_id: &str, verdict: VoteVerdict) -> Result<Vote> {
        let endpoint = format!("{}/{}/votes", Url::collection_name(), url_id);
        let request = VoteRequest::new(verdict);
        self.client.post(&endpoint, &request).await
    }

    /// Get objects related to a URL
    pub async fn get_relationship<T>(
        &self,
        url_id: &str,
        relationship: &str,
    ) -> Result<Collection<T>>
    where
        T: for<'de> Deserialize<'de>,
    {
        let url = Url::relationship_objects_url(url_id, relationship);
        self.client.get(&url).await
    }

    /// Get object descriptors related to a URL
    pub async fn get_relationship_descriptors(
        &self,
        url_id: &str,
        relationship: &str,
    ) -> Result<Collection<serde_json::Value>> {
        let url = Url::relationships_url(url_id, relationship);
        self.client.get(&url).await
    }

    /// Get relationship iterator for paginated results
    pub fn get_relationship_iterator<T>(
        &self,
        url_id: &str,
        relationship: &str,
    ) -> CollectionIterator<'_, T>
    where
        T: for<'de> Deserialize<'de> + Clone,
    {
        let url = Url::relationship_objects_url(url_id, relationship);
        CollectionIterator::new(self.client, url)
    }

    // Convenience methods for common relationships

    /// Get analyses for a URL
    pub async fn get_analyses(&self, url_id: &str) -> Result<Collection<serde_json::Value>> {
        self.get_relationship(url_id, "analyses").await
    }

    /// Get downloaded files from a URL
    pub async fn get_downloaded_files(
        &self,
        url_id: &str,
    ) -> Result<Collection<serde_json::Value>> {
        self.get_relationship(url_id, "downloaded_files").await
    }

    /// Get graphs for a URL
    pub async fn get_graphs(&self, url_id: &str) -> Result<Collection<serde_json::Value>> {
        self.get_relationship(url_id, "graphs").await
    }

    /// Get last serving IP address for a URL
    pub async fn get_last_serving_ip_address(
        &self,
        url_id: &str,
    ) -> Result<Collection<serde_json::Value>> {
        self.get_relationship(url_id, "last_serving_ip_address")
            .await
    }

    /// Get redirecting URLs
    pub async fn get_redirecting_urls(
        &self,
        url_id: &str,
    ) -> Result<Collection<serde_json::Value>> {
        self.get_relationship(url_id, "redirecting_urls").await
    }

    /// Get submissions for a URL
    pub async fn get_submissions(&self, url_id: &str) -> Result<Collection<serde_json::Value>> {
        self.get_relationship(url_id, "submissions").await
    }
}

impl Client {
    /// Get the URL client for URL-related operations
    pub fn urls(&self) -> UrlClient<'_> {
        UrlClient::new(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_url_collection_name() {
        assert_eq!(Url::collection_name(), "urls");
    }

    #[test]
    fn test_url_id_generation_base64() {
        let url = "http://www.example.com/path";
        let id = UrlClient::generate_url_id(url);
        // Verify it's base64 without padding
        assert!(!id.contains('='));
        assert!(!id.is_empty());
    }

    #[test]
    fn test_url_id_generation_sha256() {
        let url = "http://www.example.com/path";
        let hash = UrlClient::generate_url_sha256(url);
        // SHA256 should be 64 hex characters
        assert_eq!(hash.len(), 64);
        assert!(hash.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_url_object_url() {
        let url_id = "test_url_id";
        assert_eq!(Url::object_url(url_id), "urls/test_url_id");
    }

    #[test]
    fn test_url_relationships_url() {
        let url_id = "test_url_id";
        assert_eq!(
            Url::relationships_url(url_id, "analyses"),
            "urls/test_url_id/relationships/analyses"
        );
    }

    #[test]
    fn test_url_relationship_objects_url() {
        let url_id = "test_url_id";
        assert_eq!(
            Url::relationship_objects_url(url_id, "downloaded_files"),
            "urls/test_url_id/downloaded_files"
        );
    }

    #[test]
    fn test_url_attributes_creation() {
        let attrs = UrlAttributes {
            url: Some("http://example.com".to_string()),
            final_url: Some("https://example.com".to_string()),
            title: Some("Example Domain".to_string()),
            reputation: Some(0),
            times_submitted: Some(100),
            ..Default::default()
        };

        assert_eq!(attrs.url.unwrap(), "http://example.com");
        assert_eq!(attrs.final_url.unwrap(), "https://example.com");
        assert_eq!(attrs.title.unwrap(), "Example Domain");
        assert_eq!(attrs.reputation.unwrap(), 0);
        assert_eq!(attrs.times_submitted.unwrap(), 100);
    }

    #[test]
    fn test_vote_summary() {
        let summary = VoteSummary {
            harmless: 10,
            malicious: 2,
        };

        assert_eq!(summary.harmless, 10);
        assert_eq!(summary.malicious, 2);
    }

    #[test]
    fn test_url_analysis_result() {
        let result = UrlAnalysisResult {
            method: "blacklist".to_string(),
            engine_name: "TestEngine".to_string(),
            category: "malicious".to_string(),
            result: "Phishing".to_string(),
        };

        assert_eq!(result.method, "blacklist");
        assert_eq!(result.engine_name, "TestEngine");
        assert_eq!(result.category, "malicious");
        assert_eq!(result.result, "Phishing");
    }

    #[test]
    fn test_tracker_info() {
        let tracker = TrackerInfo {
            url: Some("http://tracker.example.com".to_string()),
            timestamp: Some(1234567890),
            id: Some("tracker_123".to_string()),
        };

        assert_eq!(tracker.url.unwrap(), "http://tracker.example.com");
        assert_eq!(tracker.timestamp.unwrap(), 1234567890);
        assert_eq!(tracker.id.unwrap(), "tracker_123");
    }

    #[test]
    fn test_url_scan_request() {
        let request = UrlScanRequest {
            url: "http://example.com".to_string(),
        };

        assert_eq!(request.url, "http://example.com");
    }
}
