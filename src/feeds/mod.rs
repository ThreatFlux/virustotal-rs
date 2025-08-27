//! VirusTotal Intelligence Feeds module
//!
//! This module provides access to VirusTotal Intelligence Feeds for files, domains,
//! IP addresses, URLs, and sandbox behavior analyses.

pub mod client;
pub mod types;
pub mod utilities;

// Re-export public types and client
pub use client::FeedsClient;
pub use types::{
    BehaviorContextAttributes, BehaviorFeedItem, DomainFeedItem, FeedConfig, FeedItem,
    FeedSubmitter, IpFeedItem, UrlFeedItem,
};
pub use utilities::{format_time, get_latest_available_time, get_time_range};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_feed_config_default() {
        let config = FeedConfig::default();
        assert_eq!(config.max_retries, 3);
        assert_eq!(config.retry_delay_secs, 5);
        assert!(config.skip_missing);
        assert_eq!(config.max_consecutive_missing, 10);
    }

    #[test]
    fn test_feed_item_deserialization() {
        let json = r#"{
            "id": "test_file_id",
            "type": "file",
            "attributes": {
                "sha256": "abc123",
                "size": 1024
            },
            "download_url": "https://example.com/download/token123",
            "submitter": {
                "country": "US",
                "method": "api"
            }
        }"#;

        let item: FeedItem = serde_json::from_str(json).unwrap();
        assert_eq!(item.id, "test_file_id");
        assert_eq!(item.object_type, "file");
        assert!(item.download_url.is_some());
        assert!(item.submitter.is_some());

        let submitter = item.submitter.unwrap();
        assert_eq!(submitter.country, Some("US".to_string()));
        assert_eq!(submitter.method, Some("api".to_string()));
    }

    #[tokio::test]
    async fn test_feeds_client_creation() {
        use crate::{ApiTier, ClientBuilder};

        let client = ClientBuilder::new()
            .api_key("test_key")
            .tier(ApiTier::Premium)
            .build()
            .unwrap();

        let feeds = client.feeds();

        // Test that methods exist and return errors without valid API key
        let result = feeds.get_file_feed_batch("202312010802").await;
        assert!(result.is_err());

        let hourly_result = feeds.get_hourly_file_feed_batch("2023120108").await;
        assert!(hourly_result.is_err());

        let download_result = feeds.download_feed_file("test_token").await;
        assert!(download_result.is_err());

        // Test behavior feed methods
        let behaviour_result = feeds.get_file_behaviour_feed_batch("202312010802").await;
        assert!(behaviour_result.is_err());

        let hourly_behaviour = feeds
            .get_hourly_file_behaviour_feed_batch("2023120108")
            .await;
        assert!(hourly_behaviour.is_err());

        // Test artifact downloads
        let evtx_result = feeds.download_behaviour_evtx("test_token").await;
        assert!(evtx_result.is_err());

        let pcap_result = feeds.download_behaviour_pcap("test_token").await;
        assert!(pcap_result.is_err());

        let html_result = feeds.download_behaviour_html("test_token").await;
        assert!(html_result.is_err());

        let memdump_result = feeds.download_behaviour_memdump("test_token").await;
        assert!(memdump_result.is_err());

        // Test domain feed methods
        let domain_result = feeds.get_domain_feed_batch("202312010802").await;
        assert!(domain_result.is_err());

        let hourly_domain = feeds.get_hourly_domain_feed_batch("2023120108").await;
        assert!(hourly_domain.is_err());

        // Test IP feed methods
        let ip_result = feeds.get_ip_feed_batch("202312010802").await;
        assert!(ip_result.is_err());

        let hourly_ip = feeds.get_hourly_ip_feed_batch("2023120108").await;
        assert!(hourly_ip.is_err());

        // Test URL feed methods
        let url_result = feeds.get_url_feed_batch("202312010802").await;
        assert!(url_result.is_err());

        let hourly_url = feeds.get_hourly_url_feed_batch("2023120108").await;
        assert!(hourly_url.is_err());
    }

    #[test]
    fn test_parse_feed_line() {
        use crate::{ApiTier, ClientBuilder};

        let client = ClientBuilder::new()
            .api_key("test_key")
            .tier(ApiTier::Premium)
            .build()
            .unwrap();

        let feeds = client.feeds();

        let line = r#"{"id":"test","type":"file","attributes":{"sha256":"abc"}}"#;
        let result = feeds.parse_feed_line(line);
        assert!(result.is_ok());

        let item = result.unwrap();
        assert_eq!(item.id, "test");
        assert_eq!(item.object_type, "file");
    }

    #[test]
    fn test_behavior_feed_item_deserialization() {
        let json = r#"{
            "id": "abc123_cape",
            "type": "file_behaviour",
            "attributes": {
                "sandbox_name": "cape",
                "analysis_date": 1234567890
            },
            "context_attributes": {
                "file_md5": "abc123",
                "file_sha1": "def456",
                "file_type_tag": "exe",
                "html_report": "https://www.virustotal.com/api/v3/feeds/file_behaviours/TOKEN123/html",
                "pcap": "https://www.virustotal.com/api/v3/feeds/file_behaviours/TOKEN123/pcap",
                "evtx": "https://www.virustotal.com/api/v3/feeds/file_behaviours/TOKEN123/evtx",
                "memdump": "https://www.virustotal.com/api/v3/feeds/file_behaviours/TOKEN123/memdump"
            }
        }"#;

        let item: BehaviorFeedItem = serde_json::from_str(json).unwrap();
        assert_eq!(item.id, "abc123_cape");
        assert_eq!(item.object_type, "file_behaviour");
        assert_eq!(item.context_attributes.file_md5, Some("abc123".to_string()));
        assert_eq!(
            item.context_attributes.file_sha1,
            Some("def456".to_string())
        );
        assert_eq!(
            item.context_attributes.file_type_tag,
            Some("exe".to_string())
        );
        assert!(item.context_attributes.html_report.is_some());
        assert!(item.context_attributes.pcap.is_some());
        assert!(item.context_attributes.evtx.is_some());
        assert!(item.context_attributes.memdump.is_some());
    }

    #[test]
    fn test_extract_token() {
        let url = "https://www.virustotal.com/api/v3/feeds/file_behaviours/TOKEN123/evtx";
        let token = BehaviorFeedItem::extract_token(url);
        assert_eq!(token, Some("TOKEN123".to_string()));

        let url2 = "https://www.virustotal.com/api/v3/feeds/file_behaviours/ANOTHER_TOKEN/pcap";
        let token2 = BehaviorFeedItem::extract_token(url2);
        assert_eq!(token2, Some("ANOTHER_TOKEN".to_string()));

        let invalid_url = "https://www.virustotal.com/invalid/url";
        let no_token = BehaviorFeedItem::extract_token(invalid_url);
        assert!(no_token.is_none());
    }

    #[test]
    fn test_parse_behaviour_feed_line() {
        use crate::{ApiTier, ClientBuilder};

        let client = ClientBuilder::new()
            .api_key("test_key")
            .tier(ApiTier::Premium)
            .build()
            .unwrap();

        let feeds = client.feeds();

        let line = r#"{
            "id": "test_behavior",
            "type": "file_behaviour",
            "attributes": {},
            "context_attributes": {
                "file_md5": "md5hash",
                "evtx": "https://www.virustotal.com/api/v3/feeds/file_behaviours/TOKEN/evtx"
            }
        }"#;

        let result = feeds.parse_behaviour_feed_line(line);
        assert!(result.is_ok());

        let item = result.unwrap();
        assert_eq!(item.id, "test_behavior");
        assert_eq!(item.object_type, "file_behaviour");
        assert_eq!(
            item.context_attributes.file_md5,
            Some("md5hash".to_string())
        );

        // Test token extraction from URL
        if let Some(evtx_url) = &item.context_attributes.evtx {
            let token = BehaviorFeedItem::extract_token(evtx_url);
            assert_eq!(token, Some("TOKEN".to_string()));
        }
    }

    #[test]
    fn test_domain_feed_item_deserialization() {
        let json = r#"{
            "id": "example.com",
            "type": "domain",
            "attributes": {
                "last_analysis_stats": {
                    "malicious": 2,
                    "suspicious": 1,
                    "undetected": 70,
                    "harmless": 10
                },
                "reputation": 15
            },
            "relationships": {
                "subdomains": {
                    "data": []
                }
            }
        }"#;

        let item: DomainFeedItem = serde_json::from_str(json).unwrap();
        assert_eq!(item.id, "example.com");
        assert_eq!(item.object_type, "domain");
        assert!(item.attributes.contains_key("reputation"));
        assert!(item.relationships.is_some());
    }

    #[test]
    fn test_ip_feed_item_deserialization() {
        let json = r#"{
            "id": "192.168.1.1",
            "type": "ip_address",
            "attributes": {
                "country": "US",
                "as_owner": "Example ISP",
                "reputation": 0,
                "last_analysis_stats": {
                    "malicious": 0,
                    "suspicious": 0,
                    "undetected": 83,
                    "harmless": 0
                }
            }
        }"#;

        let item: IpFeedItem = serde_json::from_str(json).unwrap();
        assert_eq!(item.id, "192.168.1.1");
        assert_eq!(item.object_type, "ip_address");
        assert!(item.attributes.contains_key("country"));
        assert!(item.attributes.contains_key("as_owner"));
    }

    #[test]
    fn test_url_feed_item_deserialization() {
        let json = r#"{
            "id": "https://example.com/path",
            "type": "url",
            "attributes": {
                "last_final_url": "https://example.com/path",
                "last_analysis_stats": {
                    "malicious": 0,
                    "suspicious": 0,
                    "undetected": 83,
                    "harmless": 10
                }
            },
            "submitter": {
                "country": "US",
                "method": "api"
            }
        }"#;

        let item: UrlFeedItem = serde_json::from_str(json).unwrap();
        assert_eq!(item.id, "https://example.com/path");
        assert_eq!(item.object_type, "url");
        assert!(item.attributes.contains_key("last_final_url"));
        assert!(item.submitter.is_some());

        let submitter = item.submitter.unwrap();
        assert_eq!(submitter.country, Some("US".to_string()));
        assert_eq!(submitter.method, Some("api".to_string()));
    }

    #[test]
    fn test_parse_domain_feed_line() {
        use crate::{ApiTier, ClientBuilder};

        let client = ClientBuilder::new()
            .api_key("test_key")
            .tier(ApiTier::Premium)
            .build()
            .unwrap();

        let feeds = client.feeds();

        let line = r#"{"id":"test.com","type":"domain","attributes":{"reputation":10}}"#;

        let result = feeds.parse_domain_feed_line(line);
        assert!(result.is_ok());

        let item = result.unwrap();
        assert_eq!(item.id, "test.com");
        assert_eq!(item.object_type, "domain");
    }

    #[test]
    fn test_parse_ip_feed_line() {
        use crate::{ApiTier, ClientBuilder};

        let client = ClientBuilder::new()
            .api_key("test_key")
            .tier(ApiTier::Premium)
            .build()
            .unwrap();

        let feeds = client.feeds();

        let line = r#"{"id":"10.0.0.1","type":"ip_address","attributes":{"country":"US"}}"#;

        let result = feeds.parse_ip_feed_line(line);
        assert!(result.is_ok());

        let item = result.unwrap();
        assert_eq!(item.id, "10.0.0.1");
        assert_eq!(item.object_type, "ip_address");
    }

    #[test]
    fn test_parse_url_feed_line() {
        use crate::{ApiTier, ClientBuilder};

        let client = ClientBuilder::new()
            .api_key("test_key")
            .tier(ApiTier::Premium)
            .build()
            .unwrap();

        let feeds = client.feeds();

        let line = r#"{"id":"https://test.com","type":"url","attributes":{},"submitter":{"country":"UK"}}"#;

        let result = feeds.parse_url_feed_line(line);
        assert!(result.is_ok());

        let item = result.unwrap();
        assert_eq!(item.id, "https://test.com");
        assert_eq!(item.object_type, "url");
        assert!(item.submitter.is_some());
    }
}
