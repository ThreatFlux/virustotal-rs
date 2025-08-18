use crate::objects::{Collection, CollectionIterator, Object};
use crate::{Client, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Represents an IoC Stream notification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IocStreamNotification {
    #[serde(flatten)]
    pub object: Object<IocStreamNotificationAttributes>,
}

/// Attributes for an IoC Stream notification
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct IocStreamNotificationAttributes {
    /// Notification date (UTC timestamp)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub notification_date: Option<i64>,

    /// Origin of the notification (e.g., "hunting", "subscriptions")
    #[serde(skip_serializing_if = "Option::is_none")]
    pub origin: Option<String>,

    /// Sources associated with the notification
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sources: Option<Vec<NotificationSource>>,

    /// Tags associated with the notification
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tags: Option<Vec<String>>,

    /// Hunting-specific information
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hunting_info: Option<HuntingInfo>,

    /// Additional attributes
    #[serde(flatten)]
    pub additional_attributes: HashMap<String, serde_json::Value>,
}

/// IoC Stream object with context
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IocStreamObject {
    /// The actual object (file, domain, URL, or IP address)
    #[serde(flatten)]
    pub object: serde_json::Value,

    /// Context attributes
    #[serde(skip_serializing_if = "Option::is_none")]
    pub context_attributes: Option<IocStreamContext>,
}

/// Context attributes for IoC Stream objects
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct IocStreamContext {
    /// Notification ID
    pub notification_id: String,

    /// Notification date (UTC timestamp)
    pub notification_date: i64,

    /// Origin of the notification
    pub origin: String,

    /// Sources associated with the notification
    pub sources: Vec<NotificationSource>,

    /// Tags associated with the notification
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tags: Option<Vec<String>>,

    /// Hunting-specific information
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hunting_info: Option<HuntingInfo>,
}

/// Source of a notification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NotificationSource {
    /// Source type (e.g., "hunting_ruleset", "retrohunt_job", "collection", "threat_actor")
    #[serde(rename = "type")]
    pub source_type: String,

    /// Source ID
    pub id: String,

    /// Source name
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

/// Hunting-specific information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HuntingInfo {
    /// Matched rule name
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rule_name: Option<String>,

    /// Matched rule tags
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rule_tags: Option<Vec<String>>,

    /// Matched contents as hexdump
    #[serde(skip_serializing_if = "Option::is_none")]
    pub snippet: Option<String>,

    /// Country where the file was uploaded from
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_country: Option<String>,

    /// Unique identifier for the source
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_key: Option<String>,
}

/// Options for IoC Stream ordering
#[derive(Debug, Clone, Copy)]
pub enum IocStreamOrder {
    DateAsc,
    DateDesc,
}

impl IocStreamOrder {
    /// Convert to API parameter string
    pub fn to_string(&self) -> &'static str {
        match self {
            IocStreamOrder::DateAsc => "date+",
            IocStreamOrder::DateDesc => "date-",
        }
    }
}

/// Options for entity types in IoC Stream
#[derive(Debug, Clone, Copy)]
pub enum EntityType {
    File,
    Domain,
    Url,
    IpAddress,
}

impl EntityType {
    /// Convert to API parameter string
    pub fn to_string(&self) -> &'static str {
        match self {
            EntityType::File => "file",
            EntityType::Domain => "domain",
            EntityType::Url => "url",
            EntityType::IpAddress => "ip_address",
        }
    }
}

/// Options for source types in IoC Stream
#[derive(Debug, Clone, Copy)]
pub enum SourceType {
    HuntingRuleset,
    RetrohuntJob,
    Collection,
    ThreatActor,
}

impl SourceType {
    /// Convert to API parameter string
    pub fn to_string(&self) -> &'static str {
        match self {
            SourceType::HuntingRuleset => "hunting_ruleset",
            SourceType::RetrohuntJob => "retrohunt_job",
            SourceType::Collection => "collection",
            SourceType::ThreatActor => "threat_actor",
        }
    }
}

/// Client for IoC Stream operations
pub struct IocStreamClient<'a> {
    pub(crate) client: &'a Client,
}

impl<'a> IocStreamClient<'a> {
    pub fn new(client: &'a Client) -> Self {
        Self { client }
    }

    /// Get objects from the IoC Stream
    ///
    /// Filters can be combined in the same filter string:
    /// - date:2023-02-07T10:00:00+: Objects from notifications after this date
    /// - date:2023-02-07-: Objects from notifications before this date  
    /// - origin:hunting: Objects from specific origin (hunting, subscriptions)
    /// - entity_id:objectId: Objects with specific ID
    /// - entity_type:file: Only specific entity types (file, domain, url, ip_address)
    /// - source_type:hunting_ruleset: Specific source types
    /// - source_id:objectId: Specific source ID
    /// - notification_tag:ruleName: Notifications with specific tag
    pub async fn get_stream(
        &self,
        filter: Option<&str>,
        order: Option<IocStreamOrder>,
        limit: Option<u32>,
        descriptors_only: Option<bool>,
        cursor: Option<&str>,
    ) -> Result<Collection<IocStreamObject>> {
        let mut url = String::from("ioc_stream?");

        if let Some(f) = filter {
            url.push_str(&format!("filter={}&", urlencoding::encode(f)));
        }

        if let Some(o) = order {
            url.push_str(&format!("order={}&", o.to_string()));
        }

        if let Some(l) = limit {
            url.push_str(&format!("limit={}&", l.min(40))); // Max 40
        }

        if let Some(d) = descriptors_only {
            url.push_str(&format!("descriptors_only={}&", d));
        }

        if let Some(c) = cursor {
            url.push_str(&format!("cursor={}&", urlencoding::encode(c)));
        }

        // Remove trailing '&' or '?'
        url.pop();

        self.client.get(&url).await
    }

    /// Get IoC Stream with pagination support
    pub fn get_stream_iterator(
        &self,
        filter: Option<&str>,
        order: Option<IocStreamOrder>,
        descriptors_only: Option<bool>,
    ) -> CollectionIterator<'_, IocStreamObject> {
        let mut url = String::from("ioc_stream?");

        if let Some(f) = filter {
            url.push_str(&format!("filter={}&", urlencoding::encode(f)));
        }

        if let Some(o) = order {
            url.push_str(&format!("order={}&", o.to_string()));
        }

        if let Some(d) = descriptors_only {
            url.push_str(&format!("descriptors_only={}&", d));
        }

        // Remove trailing '&' or '?'
        url.pop();

        CollectionIterator::new(self.client, url)
    }

    /// Delete notifications from the IoC Stream
    ///
    /// Uses the same filters as get_stream() to delete all matching notifications
    pub async fn delete_notifications(&self, filter: &str) -> Result<()> {
        let url = format!("ioc_stream?filter={}", urlencoding::encode(filter));
        self.client.delete(&url).await
    }

    /// Get a specific IoC Stream notification
    pub async fn get_notification(&self, notification_id: &str) -> Result<IocStreamNotification> {
        let url = format!(
            "ioc_stream_notifications/{}",
            urlencoding::encode(notification_id)
        );
        self.client.get(&url).await
    }

    /// Delete a specific IoC Stream notification
    pub async fn delete_notification(&self, notification_id: &str) -> Result<()> {
        let url = format!(
            "ioc_stream_notifications/{}",
            urlencoding::encode(notification_id)
        );
        self.client.delete(&url).await
    }

    /// Helper to build a filter for date range
    pub fn build_date_filter(start: Option<&str>, end: Option<&str>) -> String {
        let mut filter = String::new();

        if let Some(start_date) = start {
            filter.push_str(&format!("date:{}+", start_date));
        }

        if let Some(end_date) = end {
            if !filter.is_empty() {
                filter.push(' ');
            }
            filter.push_str(&format!("date:{}-", end_date));
        }

        filter
    }

    /// Helper to build a complex filter
    pub fn build_filter(
        date_start: Option<&str>,
        date_end: Option<&str>,
        origin: Option<&str>,
        entity_type: Option<EntityType>,
        source_type: Option<SourceType>,
        source_id: Option<&str>,
        notification_tag: Option<&str>,
    ) -> String {
        let mut parts = Vec::new();

        if let Some(start) = date_start {
            parts.push(format!("date:{}+", start));
        }

        if let Some(end) = date_end {
            parts.push(format!("date:{}-", end));
        }

        if let Some(o) = origin {
            parts.push(format!("origin:{}", o));
        }

        if let Some(et) = entity_type {
            parts.push(format!("entity_type:{}", et.to_string()));
        }

        if let Some(st) = source_type {
            parts.push(format!("source_type:{}", st.to_string()));
        }

        if let Some(sid) = source_id {
            parts.push(format!("source_id:{}", sid));
        }

        if let Some(tag) = notification_tag {
            parts.push(format!("notification_tag:{}", tag));
        }

        parts.join(" ")
    }
}

impl Client {
    /// Get the IoC Stream client
    pub fn ioc_stream(&self) -> IocStreamClient<'_> {
        IocStreamClient::new(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_notification_source() {
        let source = NotificationSource {
            source_type: "hunting_ruleset".to_string(),
            id: "ruleset_123".to_string(),
            name: Some("My Hunting Ruleset".to_string()),
        };

        assert_eq!(source.source_type, "hunting_ruleset");
        assert_eq!(source.id, "ruleset_123");
        assert_eq!(source.name.unwrap(), "My Hunting Ruleset");
    }

    #[test]
    fn test_hunting_info() {
        let info = HuntingInfo {
            rule_name: Some("MalwareDetection".to_string()),
            rule_tags: Some(vec!["malware".to_string(), "trojan".to_string()]),
            snippet: Some("4D 5A 90 00 03 00 00 00".to_string()),
            source_country: Some("US".to_string()),
            source_key: Some("key_123".to_string()),
        };

        assert_eq!(info.rule_name.unwrap(), "MalwareDetection");
        assert_eq!(info.rule_tags.unwrap().len(), 2);
        assert_eq!(info.source_country.unwrap(), "US");
    }

    #[test]
    fn test_ioc_stream_order_strings() {
        assert_eq!(IocStreamOrder::DateAsc.to_string(), "date+");
        assert_eq!(IocStreamOrder::DateDesc.to_string(), "date-");
    }

    #[test]
    fn test_entity_type_strings() {
        assert_eq!(EntityType::File.to_string(), "file");
        assert_eq!(EntityType::Domain.to_string(), "domain");
        assert_eq!(EntityType::Url.to_string(), "url");
        assert_eq!(EntityType::IpAddress.to_string(), "ip_address");
    }

    #[test]
    fn test_source_type_strings() {
        assert_eq!(SourceType::HuntingRuleset.to_string(), "hunting_ruleset");
        assert_eq!(SourceType::RetrohuntJob.to_string(), "retrohunt_job");
        assert_eq!(SourceType::Collection.to_string(), "collection");
        assert_eq!(SourceType::ThreatActor.to_string(), "threat_actor");
    }

    #[test]
    fn test_build_date_filter() {
        let filter = IocStreamClient::build_date_filter(
            Some("2023-02-07T10:00:00"),
            Some("2023-03-07T00:00:00"),
        );
        assert_eq!(
            filter,
            "date:2023-02-07T10:00:00+ date:2023-03-07T00:00:00-"
        );

        let filter_start_only =
            IocStreamClient::build_date_filter(Some("2023-02-07T10:00:00"), None);
        assert_eq!(filter_start_only, "date:2023-02-07T10:00:00+");

        let filter_end_only = IocStreamClient::build_date_filter(None, Some("2023-03-07T00:00:00"));
        assert_eq!(filter_end_only, "date:2023-03-07T00:00:00-");
    }

    #[test]
    fn test_build_complex_filter() {
        let filter = IocStreamClient::build_filter(
            Some("2023-02-07T10:00:00"),
            None,
            Some("hunting"),
            Some(EntityType::File),
            Some(SourceType::HuntingRuleset),
            Some("ruleset_123"),
            Some("malware"),
        );

        assert!(filter.contains("date:2023-02-07T10:00:00+"));
        assert!(filter.contains("origin:hunting"));
        assert!(filter.contains("entity_type:file"));
        assert!(filter.contains("source_type:hunting_ruleset"));
        assert!(filter.contains("source_id:ruleset_123"));
        assert!(filter.contains("notification_tag:malware"));
    }

    #[test]
    fn test_ioc_stream_context() {
        let context = IocStreamContext {
            notification_id: "notif_123".to_string(),
            notification_date: 1682985600,
            origin: "hunting".to_string(),
            sources: vec![NotificationSource {
                source_type: "hunting_ruleset".to_string(),
                id: "ruleset_123".to_string(),
                name: None,
            }],
            tags: Some(vec!["tag1".to_string(), "tag2".to_string()]),
            hunting_info: None,
        };

        assert_eq!(context.notification_id, "notif_123");
        assert_eq!(context.origin, "hunting");
        assert_eq!(context.sources.len(), 1);
        assert_eq!(context.tags.unwrap().len(), 2);
    }
}
