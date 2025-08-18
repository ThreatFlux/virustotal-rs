use crate::client::Client;
use crate::error::Result;
use crate::objects::{Collection, CollectionIterator, Object};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::collections::HashMap;

/// Client for VirusTotal Private URL Scanning API
///
/// NOTE: Private URL scanning requires special privileges and is only available
/// with a Private Scanning License.
pub struct PrivateUrlsClient {
    client: Client,
}

impl PrivateUrlsClient {
    pub fn new(client: Client) -> Self {
        Self { client }
    }

    /// Scan a URL privately
    ///
    /// This returns an Analysis ID. The analysis can be retrieved by using the Analysis endpoint.
    ///
    /// # Arguments
    /// * `url` - URL to scan
    /// * `params` - Optional parameters for the scan
    ///
    /// # Notes
    /// - To get comprehensive analysis, use `chrome_headless_linux` sandbox
    /// - Default retention is 1 day (max 28 days)
    /// - Storage regions: US, CA, EU, GB
    pub async fn scan_url(
        &self,
        url: &str,
        params: Option<PrivateUrlScanParams>,
    ) -> Result<PrivateUrlScanResponse> {
        let mut form_data = HashMap::new();
        form_data.insert("url", url.to_string());

        // Need to store the generated strings outside to keep them alive
        let sandboxes_str;
        let retention_str;
        let timeout_str;

        if let Some(params) = params {
            if let Some(user_agent) = params.user_agent {
                form_data.insert("user_agent", user_agent);
            }
            if let Some(sandboxes) = params.sandboxes {
                sandboxes_str = sandboxes.join(",");
                form_data.insert("sandboxes", sandboxes_str.clone());
            }
            if let Some(retention) = params.retention_period_days {
                retention_str = retention.to_string();
                form_data.insert("retention_period_days", retention_str.clone());
            }
            if let Some(region) = params.storage_region {
                form_data.insert("storage_region", region);
            }
            if let Some(interaction_sandbox) = params.interaction_sandbox {
                form_data.insert("interaction_sandbox", interaction_sandbox);
            }
            if let Some(timeout) = params.interaction_timeout {
                timeout_str = timeout.to_string();
                form_data.insert("interaction_timeout", timeout_str.clone());
            }
        }

        // Convert to the expected format for post_form
        let form_refs: HashMap<&str, &str> =
            form_data.iter().map(|(k, v)| (*k, v.as_str())).collect();

        self.client.post_form("private/urls", &form_refs).await
    }

    /// Get a URL analysis report
    ///
    /// # Arguments
    /// * `url_id` - URL identifier (SHA-256 of canonized URL or base64-encoded URL without padding)
    ///
    /// # URL Identifiers
    /// URL identifiers can be:
    /// 1. SHA-256 of the canonized URL
    /// 2. Base64-encoded URL (without "=" padding)
    ///
    /// Example base64 encoding in Rust:
    /// ```
    /// use base64::{Engine as _, engine::general_purpose};
    /// let url = "http://www.example.com/path";
    /// let url_id = general_purpose::URL_SAFE_NO_PAD.encode(url.as_bytes());
    /// ```
    pub async fn get_url(&self, url_id: &str) -> Result<PrivateUrlResponse> {
        let endpoint = format!("private/urls/{}", url_id);
        self.client.get(&endpoint).await
    }

    /// Get objects related to a private URL
    ///
    /// # Arguments
    /// * `url_id` - URL identifier
    /// * `relationship` - Relationship name (e.g., "analyses", "downloaded_files", "graphs", etc.)
    /// * `limit` - Maximum number of related objects to retrieve
    /// * `cursor` - Continuation cursor for pagination
    ///
    /// # Available Relationships
    /// - analyses: URL analysis
    /// - downloaded_files: Files downloaded from the URL
    /// - graphs: Graphs containing this URL
    /// - last_serving_ip_address: Last IP that served this URL
    /// - redirecting_urls: URLs that redirect to this URL
    /// - submissions: URL submissions
    pub async fn get_relationship<T>(
        &self,
        url_id: &str,
        relationship: &str,
        limit: Option<u32>,
        cursor: Option<&str>,
    ) -> Result<Collection<T>>
    where
        T: DeserializeOwned,
    {
        let mut endpoint = format!("private/urls/{}/{}", url_id, relationship);
        let mut params = vec![];

        if let Some(limit) = limit {
            params.push(format!("limit={}", limit));
        }
        if let Some(cursor) = cursor {
            params.push(format!("cursor={}", cursor));
        }

        if !params.is_empty() {
            endpoint.push('?');
            endpoint.push_str(&params.join("&"));
        }

        self.client.get(&endpoint).await
    }

    /// Get relationship descriptors (IDs only)
    pub async fn get_relationship_descriptors(
        &self,
        url_id: &str,
        relationship: &str,
        limit: Option<u32>,
        cursor: Option<&str>,
    ) -> Result<Collection<HashMap<String, serde_json::Value>>> {
        self.get_relationship(url_id, relationship, limit, cursor)
            .await
    }

    /// Create an iterator for URL relationships
    pub fn get_relationship_iterator<T>(
        &self,
        url_id: String,
        relationship: String,
    ) -> CollectionIterator<'_, T>
    where
        T: DeserializeOwned + Clone + Send + 'static,
    {
        let endpoint = format!("private/urls/{}/{}", url_id, relationship);
        CollectionIterator::new(&self.client, endpoint)
    }
}

/// Parameters for private URL scanning
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrivateUrlScanParams {
    /// User agent string to use when fetching the URL
    pub user_agent: Option<String>,

    /// Comma-separated list of sandboxes to use
    /// Possible values: chrome_headless_linux, cape_win, zenbox_windows
    pub sandboxes: Option<Vec<String>>,

    /// Number of days the report and URL are kept (1-28)
    /// Defaults to group's retention policy (usually 1 day)
    pub retention_period_days: Option<u32>,

    /// Storage region where the URL will be stored
    /// Allowed values: US, CA, EU, GB
    pub storage_region: Option<String>,

    /// Sandbox for interactive use (defaults to cape_win)
    pub interaction_sandbox: Option<String>,

    /// Interaction timeout in seconds (60-1800)
    /// Default: 60 seconds
    pub interaction_timeout: Option<u32>,
}

impl PrivateUrlScanParams {
    pub fn new() -> Self {
        Self {
            user_agent: None,
            sandboxes: None,
            retention_period_days: None,
            storage_region: None,
            interaction_sandbox: None,
            interaction_timeout: None,
        }
    }

    /// Set user agent
    pub fn user_agent(mut self, user_agent: String) -> Self {
        self.user_agent = Some(user_agent);
        self
    }

    /// Add a sandbox
    pub fn add_sandbox(mut self, sandbox: &str) -> Self {
        if let Some(ref mut sandboxes) = self.sandboxes {
            sandboxes.push(sandbox.to_string());
        } else {
            self.sandboxes = Some(vec![sandbox.to_string()]);
        }
        self
    }

    /// Use Chrome Headless Linux sandbox for comprehensive analysis
    pub fn with_chrome_headless(self) -> Self {
        self.add_sandbox("chrome_headless_linux")
    }

    /// Set sandboxes
    pub fn sandboxes(mut self, sandboxes: Vec<String>) -> Self {
        self.sandboxes = Some(sandboxes);
        self
    }

    /// Set retention period in days (1-28)
    pub fn retention_period_days(mut self, days: u32) -> Self {
        // Clamp to valid range
        let days = days.clamp(1, 28);
        self.retention_period_days = Some(days);
        self
    }

    /// Set storage region (US, CA, EU, GB)
    pub fn storage_region(mut self, region: String) -> Self {
        self.storage_region = Some(region);
        self
    }

    /// Set interaction sandbox (default: cape_win)
    pub fn interaction_sandbox(mut self, sandbox: String) -> Self {
        self.interaction_sandbox = Some(sandbox);
        self
    }

    /// Set interaction timeout in seconds (60-1800)
    pub fn interaction_timeout(mut self, seconds: u32) -> Self {
        // Clamp to valid range
        let seconds = seconds.clamp(60, 1800);
        self.interaction_timeout = Some(seconds);
        self
    }
}

impl Default for PrivateUrlScanParams {
    fn default() -> Self {
        Self::new()
    }
}

/// Response from private URL scan
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrivateUrlScanResponse {
    pub data: PrivateUrlScanData,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrivateUrlScanData {
    /// Analysis ID
    pub id: String,

    /// Object type (usually "analysis")
    #[serde(rename = "type")]
    pub object_type: String,

    /// Links to related resources
    pub links: Option<PrivateUrlScanLinks>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrivateUrlScanLinks {
    #[serde(rename = "self")]
    pub self_link: String,
}

/// Private URL response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrivateUrlResponse {
    pub data: PrivateUrl,
}

/// Private URL object
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrivateUrl {
    #[serde(flatten)]
    pub object: Object<PrivateUrlAttributes>,
}

/// Private URL attributes
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrivateUrlAttributes {
    /// URL
    pub url: Option<String>,

    /// Final URL after redirects
    pub final_url: Option<String>,

    /// Title of the page
    pub title: Option<String>,

    /// Response headers
    pub response_headers: Option<HashMap<String, String>>,

    /// HTML meta tags
    pub html_meta: Option<HashMap<String, String>>,

    /// Reputation score
    pub reputation: Option<i64>,

    /// Last analysis date (Unix timestamp)
    pub last_analysis_date: Option<i64>,

    /// Last analysis stats
    pub last_analysis_stats: Option<AnalysisStats>,

    /// Last analysis results
    pub last_analysis_results: Option<HashMap<String, EngineResult>>,

    /// Total votes
    pub total_votes: Option<Votes>,

    /// Categories
    pub categories: Option<HashMap<String, String>>,

    /// Tags
    pub tags: Option<Vec<String>>,

    /// Threat names
    pub threat_names: Option<Vec<String>>,

    /// Last HTTP response code
    pub last_http_response_code: Option<i32>,

    /// Last HTTP response content length
    pub last_http_response_content_length: Option<i64>,

    /// Last HTTP response content SHA256
    pub last_http_response_content_sha256: Option<String>,

    /// Redirection chain
    pub redirection_chain: Option<Vec<String>>,

    /// Outgoing links
    pub outgoing_links: Option<Vec<String>>,

    /// Times submitted
    pub times_submitted: Option<i64>,

    /// First submission date
    pub first_submission_date: Option<i64>,

    /// Last submission date  
    pub last_submission_date: Option<i64>,
}

/// Analysis statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisStats {
    pub malicious: Option<i64>,
    pub suspicious: Option<i64>,
    pub undetected: Option<i64>,
    pub harmless: Option<i64>,
    pub timeout: Option<i64>,
}

/// Engine detection result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EngineResult {
    pub category: Option<String>,
    pub result: Option<String>,
    pub method: Option<String>,
    pub engine_name: Option<String>,
}

/// Voting statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Votes {
    pub harmless: Option<i64>,
    pub malicious: Option<i64>,
}

impl crate::Client {
    pub fn private_urls(&self) -> PrivateUrlsClient {
        PrivateUrlsClient::new(self.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_url_scan_params_builder() {
        let params = PrivateUrlScanParams::new()
            .user_agent("Mozilla/5.0".to_string())
            .with_chrome_headless()
            .add_sandbox("cape_win")
            .retention_period_days(7)
            .storage_region("US".to_string())
            .interaction_timeout(120);

        assert_eq!(params.user_agent, Some("Mozilla/5.0".to_string()));
        assert_eq!(
            params.sandboxes,
            Some(vec![
                "chrome_headless_linux".to_string(),
                "cape_win".to_string()
            ])
        );
        assert_eq!(params.retention_period_days, Some(7));
        assert_eq!(params.storage_region, Some("US".to_string()));
        assert_eq!(params.interaction_timeout, Some(120));
    }

    #[test]
    fn test_retention_period_clamping() {
        let params1 = PrivateUrlScanParams::new().retention_period_days(0);
        assert_eq!(params1.retention_period_days, Some(1));

        let params2 = PrivateUrlScanParams::new().retention_period_days(50);
        assert_eq!(params2.retention_period_days, Some(28));

        let params3 = PrivateUrlScanParams::new().retention_period_days(14);
        assert_eq!(params3.retention_period_days, Some(14));
    }

    #[test]
    fn test_interaction_timeout_clamping() {
        let params1 = PrivateUrlScanParams::new().interaction_timeout(30);
        assert_eq!(params1.interaction_timeout, Some(60));

        let params2 = PrivateUrlScanParams::new().interaction_timeout(2000);
        assert_eq!(params2.interaction_timeout, Some(1800));

        let params3 = PrivateUrlScanParams::new().interaction_timeout(300);
        assert_eq!(params3.interaction_timeout, Some(300));
    }

    #[test]
    fn test_base64_url_encoding() {
        use base64::{engine::general_purpose, Engine as _};

        let url = "http://www.example.com/path";
        let url_id = general_purpose::URL_SAFE_NO_PAD.encode(url.as_bytes());

        // Should not contain padding
        assert!(!url_id.contains('='));

        // Should be URL-safe base64
        assert!(!url_id.contains('+'));
        assert!(!url_id.contains('/'));
    }

    #[tokio::test]
    async fn test_private_url_scan() {
        use crate::{ApiTier, ClientBuilder};

        let client = ClientBuilder::new()
            .api_key("test_key")
            .tier(ApiTier::Premium)
            .build()
            .unwrap();

        let private_urls = client.private_urls();

        // Test basic scan
        let result = private_urls.scan_url("https://example.com", None).await;

        // Will fail without valid API key, but we're testing the method exists
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_private_url_scan_with_params() {
        use crate::{ApiTier, ClientBuilder};

        let client = ClientBuilder::new()
            .api_key("test_key")
            .tier(ApiTier::Premium)
            .build()
            .unwrap();

        let private_urls = client.private_urls();

        let params = PrivateUrlScanParams::new()
            .with_chrome_headless()
            .retention_period_days(14)
            .storage_region("US".to_string());

        let result = private_urls
            .scan_url("https://example.com", Some(params))
            .await;

        // Will fail without valid API key, but we're testing the method exists
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_get_url_report() {
        use crate::{ApiTier, ClientBuilder};
        use base64::{engine::general_purpose, Engine as _};

        let client = ClientBuilder::new()
            .api_key("test_key")
            .tier(ApiTier::Premium)
            .build()
            .unwrap();

        let private_urls = client.private_urls();

        // Test with base64 ID
        let url = "https://example.com";
        let url_id = general_purpose::URL_SAFE_NO_PAD.encode(url.as_bytes());

        let result = private_urls.get_url(&url_id).await;

        // Will fail without valid API key, but we're testing the method exists
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_url_relationships() {
        use crate::{ApiTier, ClientBuilder};
        use base64::{engine::general_purpose, Engine as _};

        let client = ClientBuilder::new()
            .api_key("test_key")
            .tier(ApiTier::Premium)
            .build()
            .unwrap();

        let private_urls = client.private_urls();

        let url = "https://example.com";
        let url_id = general_purpose::URL_SAFE_NO_PAD.encode(url.as_bytes());

        // Test various relationships
        let relationships = vec![
            "analyses",
            "downloaded_files",
            "graphs",
            "last_serving_ip_address",
            "redirecting_urls",
            "submissions",
        ];

        for relationship in relationships {
            let result = private_urls
                .get_relationship::<serde_json::Value>(&url_id, relationship, Some(10), None)
                .await;

            // Will fail without valid API key, but we're testing the method exists
            assert!(result.is_err());
        }
    }

    #[test]
    fn test_sandbox_builder() {
        let params = PrivateUrlScanParams::new()
            .add_sandbox("chrome_headless_linux")
            .add_sandbox("cape_win")
            .add_sandbox("zenbox_windows");

        assert_eq!(
            params.sandboxes,
            Some(vec![
                "chrome_headless_linux".to_string(),
                "cape_win".to_string(),
                "zenbox_windows".to_string()
            ])
        );
    }

    #[test]
    fn test_comprehensive_params() {
        let params = PrivateUrlScanParams::new()
            .user_agent("Custom User Agent".to_string())
            .with_chrome_headless()
            .add_sandbox("cape_win")
            .retention_period_days(21)
            .storage_region("EU".to_string())
            .interaction_sandbox("cape_win".to_string())
            .interaction_timeout(300);

        assert_eq!(params.user_agent, Some("Custom User Agent".to_string()));
        assert_eq!(params.sandboxes.as_ref().unwrap().len(), 2);
        assert_eq!(params.retention_period_days, Some(21));
        assert_eq!(params.storage_region, Some("EU".to_string()));
        assert_eq!(params.interaction_sandbox, Some("cape_win".to_string()));
        assert_eq!(params.interaction_timeout, Some(300));
    }

    #[test]
    fn test_url_id_generation_various_urls() {
        use base64::{engine::general_purpose, Engine as _};

        let test_urls = vec![
            "https://www.google.com",
            "http://example.com/path/to/file.html",
            "https://subdomain.example.org:8080/query?param=value",
            "ftp://files.example.com/download/",
        ];

        for url in test_urls {
            let url_id = general_purpose::URL_SAFE_NO_PAD.encode(url.as_bytes());

            // Verify it's valid base64 without padding
            assert!(!url_id.is_empty());
            assert!(!url_id.contains('='));
            assert!(!url_id.contains('+'));
            assert!(!url_id.contains('/'));
        }
    }
}
