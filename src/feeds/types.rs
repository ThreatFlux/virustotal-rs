use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Represents an item from a file or sandbox feed
///
/// This is a simplified representation. The actual feed items contain
/// all file object attributes plus additional context attributes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeedItem {
    /// File or sandbox report ID
    pub id: String,

    /// Object type
    #[serde(rename = "type")]
    pub object_type: String,

    /// File attributes (same as GET /files/{id} response)
    pub attributes: HashMap<String, serde_json::Value>,

    /// Download URL for the file (file feed only)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub download_url: Option<String>,

    /// Submitter information (lossy-ciphered, non-identifiable)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub submitter: Option<FeedSubmitter>,

    /// Additional context attributes
    #[serde(flatten)]
    pub context: HashMap<String, serde_json::Value>,
}

/// Submitter information in feed items
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeedSubmitter {
    /// Country of submission
    #[serde(skip_serializing_if = "Option::is_none")]
    pub country: Option<String>,

    /// Submission method
    #[serde(skip_serializing_if = "Option::is_none")]
    pub method: Option<String>,

    /// Additional submitter attributes
    #[serde(flatten)]
    pub additional: HashMap<String, serde_json::Value>,
}

/// Represents a behavior feed item
///
/// This structure represents a line from the file behaviour feed,
/// containing sandbox analysis results with artifact download links.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BehaviorFeedItem {
    /// Behavior ID (`SHA256_SandboxName` format)
    pub id: String,

    /// Object type (always "file_behaviour")
    #[serde(rename = "type")]
    pub object_type: String,

    /// FileBehaviour object attributes
    pub attributes: HashMap<String, serde_json::Value>,

    /// Context attributes with download links
    pub context_attributes: BehaviorContextAttributes,

    /// Relationships
    #[serde(skip_serializing_if = "Option::is_none")]
    pub relationships: Option<HashMap<String, serde_json::Value>>,

    /// Links
    #[serde(skip_serializing_if = "Option::is_none")]
    pub links: Option<HashMap<String, serde_json::Value>>,
}

/// Context attributes for behavior feed items
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BehaviorContextAttributes {
    /// File MD5 hash
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file_md5: Option<String>,

    /// File SHA1 hash
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file_sha1: Option<String>,

    /// File type tag
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file_type_tag: Option<String>,

    /// HTML report download URL
    #[serde(skip_serializing_if = "Option::is_none")]
    pub html_report: Option<String>,

    /// PCAP file download URL
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pcap: Option<String>,

    /// EVTX file download URL
    #[serde(skip_serializing_if = "Option::is_none")]
    pub evtx: Option<String>,

    /// Memory dump download URL
    #[serde(skip_serializing_if = "Option::is_none")]
    pub memdump: Option<String>,
}

impl BehaviorFeedItem {
    /// Extract the download token from a URL
    ///
    /// # Example
    /// ```
    /// use virustotal_rs::feeds::BehaviorFeedItem;
    /// let url = "https://www.virustotal.com/api/v3/feeds/file_behaviours/TOKEN123/evtx";
    /// let token = BehaviorFeedItem::extract_token(url);
    /// assert_eq!(token, Some("TOKEN123".to_string()));
    /// ```
    pub fn extract_token(url: &str) -> Option<String> {
        // Look for the pattern /file_behaviours/<TOKEN>/<artifact>
        if let Some(idx) = url.find("/file_behaviours/") {
            let after_prefix = &url[idx + 17..]; // Skip "/file_behaviours/"
            let parts: Vec<&str> = after_prefix.split('/').collect();
            if parts.len() >= 2 && !parts[0].is_empty() {
                return Some(parts[0].to_string());
            }
        }
        None
    }
}

/// Represents a domain feed item
///
/// This structure represents a line from the domain feed,
/// containing domain analysis results.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DomainFeedItem {
    /// Domain name or ID
    pub id: String,

    /// Object type (always "domain")
    #[serde(rename = "type")]
    pub object_type: String,

    /// Domain attributes (same as GET /domains/{domain} response)
    pub attributes: HashMap<String, serde_json::Value>,

    /// Relationships
    #[serde(skip_serializing_if = "Option::is_none")]
    pub relationships: Option<HashMap<String, serde_json::Value>>,

    /// Links
    #[serde(skip_serializing_if = "Option::is_none")]
    pub links: Option<HashMap<String, serde_json::Value>>,

    /// Additional context attributes
    #[serde(flatten)]
    pub context: HashMap<String, serde_json::Value>,
}

/// Represents an IP address feed item
///
/// This structure represents a line from the IP address feed,
/// containing IP address analysis results.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpFeedItem {
    /// IP address
    pub id: String,

    /// Object type (always "ip_address")
    #[serde(rename = "type")]
    pub object_type: String,

    /// IP address attributes (same as GET /ip_addresses/{ip} response)
    pub attributes: HashMap<String, serde_json::Value>,

    /// Relationships
    #[serde(skip_serializing_if = "Option::is_none")]
    pub relationships: Option<HashMap<String, serde_json::Value>>,

    /// Links
    #[serde(skip_serializing_if = "Option::is_none")]
    pub links: Option<HashMap<String, serde_json::Value>>,

    /// Additional context attributes
    #[serde(flatten)]
    pub context: HashMap<String, serde_json::Value>,
}

/// Represents a URL feed item
///
/// This structure represents a line from the URL feed,
/// containing URL analysis results with submitter information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UrlFeedItem {
    /// URL identifier
    pub id: String,

    /// Object type (always "url")
    #[serde(rename = "type")]
    pub object_type: String,

    /// URL attributes (same as GET /urls/{id} response)
    pub attributes: HashMap<String, serde_json::Value>,

    /// Submitter information (lossy-ciphered, non-identifiable)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub submitter: Option<FeedSubmitter>,

    /// Relationships
    #[serde(skip_serializing_if = "Option::is_none")]
    pub relationships: Option<HashMap<String, serde_json::Value>>,

    /// Links
    #[serde(skip_serializing_if = "Option::is_none")]
    pub links: Option<HashMap<String, serde_json::Value>>,

    /// Additional context attributes
    #[serde(flatten)]
    pub context: HashMap<String, serde_json::Value>,
}

/// Configuration for feed processing
#[derive(Debug, Clone)]
pub struct FeedConfig {
    /// Maximum number of retries for failed batches
    pub max_retries: u32,

    /// Delay between retries in seconds
    pub retry_delay_secs: u64,

    /// Continue on missing batches (404 errors)
    pub skip_missing: bool,

    /// Maximum consecutive missing batches before stopping
    pub max_consecutive_missing: u32,
}

impl Default for FeedConfig {
    fn default() -> Self {
        Self {
            max_retries: 3,
            retry_delay_secs: 5,
            skip_missing: true,
            max_consecutive_missing: 10,
        }
    }
}
