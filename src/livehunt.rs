use crate::objects::{Collection, CollectionIterator, Object};
use crate::{Client, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Represents a Livehunt ruleset in VirusTotal
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LivehuntRuleset {
    #[serde(flatten)]
    pub object: Object<LivehuntRulesetAttributes>,
}

/// Attributes for a Livehunt ruleset
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct LivehuntRulesetAttributes {
    /// Ruleset name
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,

    /// Whether the ruleset is enabled
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,

    /// Maximum number of matches per time period
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limit: Option<u32>,

    /// YARA rules content
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rules: Option<String>,

    /// Email addresses for notifications
    #[serde(skip_serializing_if = "Option::is_none")]
    pub notification_emails: Option<Vec<String>>,

    /// Type of objects to match (file, url, domain, ip)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub match_object_type: Option<String>,

    /// Creation date (UTC timestamp)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub creation_date: Option<i64>,

    /// Last modification date (UTC timestamp)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub modification_date: Option<i64>,

    /// Number of rules in the ruleset
    #[serde(skip_serializing_if = "Option::is_none")]
    pub number_of_rules: Option<u32>,

    /// Tags associated with the ruleset
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tags: Option<Vec<String>>,

    /// Additional attributes
    #[serde(flatten)]
    pub additional_attributes: HashMap<String, serde_json::Value>,
}

/// Request to create a new Livehunt ruleset
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateLivehuntRulesetRequest {
    pub data: CreateLivehuntRulesetData,
}

/// Data for creating a Livehunt ruleset
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateLivehuntRulesetData {
    #[serde(rename = "type")]
    pub object_type: String,
    pub attributes: CreateLivehuntRulesetAttributes,
}

/// Attributes for creating a Livehunt ruleset
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateLivehuntRulesetAttributes {
    pub name: String,
    pub rules: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limit: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub notification_emails: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub match_object_type: Option<String>,
}

/// Request to update a Livehunt ruleset
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateLivehuntRulesetRequest {
    pub data: UpdateLivehuntRulesetData,
}

/// Data for updating a Livehunt ruleset
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateLivehuntRulesetData {
    #[serde(rename = "type")]
    pub object_type: String,
    pub id: String,
    pub attributes: UpdateLivehuntRulesetAttributes,
}

/// Attributes for updating a Livehunt ruleset
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct UpdateLivehuntRulesetAttributes {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limit: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rules: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub notification_emails: Option<Vec<String>>,
}

/// Represents a Livehunt notification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LivehuntNotification {
    #[serde(flatten)]
    pub object: Object<LivehuntNotificationAttributes>,
}

/// Attributes for a Livehunt notification
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct LivehuntNotificationAttributes {
    /// Notification date (UTC timestamp)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub date: Option<i64>,

    /// Tags associated with the notification
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tags: Option<Vec<String>>,

    /// Ruleset ID that triggered the notification
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ruleset_id: Option<String>,

    /// Ruleset name
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ruleset_name: Option<String>,

    /// Rule name that matched
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rule_name: Option<String>,

    /// File hash (SHA256)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,

    /// Source key
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_key: Option<String>,

    /// Match snippet
    #[serde(skip_serializing_if = "Option::is_none")]
    pub snippet: Option<String>,

    /// Whether match was in a subfile
    #[serde(skip_serializing_if = "Option::is_none")]
    pub match_in_subfile: Option<bool>,

    /// Additional attributes
    #[serde(flatten)]
    pub additional_attributes: HashMap<String, serde_json::Value>,
}

/// Context attributes for notification files
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NotificationFileContext {
    pub match_in_subfile: bool,
    pub notification_date: i64,
    pub notification_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub notification_snippet: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub notification_source_key: Option<String>,
    pub notification_tags: Vec<String>,
    pub ruleset_id: String,
    pub ruleset_name: String,
    pub rule_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rule_tags: Option<Vec<String>>,
}

/// File object with notification context
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NotificationFile {
    #[serde(flatten)]
    pub file: serde_json::Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub context_attributes: Option<NotificationFileContext>,
}

/// Options for Livehunt ruleset ordering
#[derive(Debug, Clone, Copy)]
pub enum LivehuntRulesetOrder {
    NameAsc,
    NameDesc,
    CreationDateAsc,
    CreationDateDesc,
    ModificationDateAsc,
    ModificationDateDesc,
}

impl LivehuntRulesetOrder {
    /// Convert to API parameter string
    pub fn to_string(&self) -> &'static str {
        match self {
            LivehuntRulesetOrder::NameAsc => "name+",
            LivehuntRulesetOrder::NameDesc => "name-",
            LivehuntRulesetOrder::CreationDateAsc => "creation_date+",
            LivehuntRulesetOrder::CreationDateDesc => "creation_date-",
            LivehuntRulesetOrder::ModificationDateAsc => "modification_date+",
            LivehuntRulesetOrder::ModificationDateDesc => "modification_date-",
        }
    }
}

/// Options for notification ordering
#[derive(Debug, Clone, Copy)]
pub enum NotificationOrder {
    DateAsc,
    DateDesc,
}

impl NotificationOrder {
    /// Convert to API parameter string
    pub fn to_string(&self) -> &'static str {
        match self {
            NotificationOrder::DateAsc => "date+",
            NotificationOrder::DateDesc => "date-",
        }
    }
}

/// Object types that can be matched by Livehunt rules
#[derive(Debug, Clone, Copy)]
pub enum MatchObjectType {
    File,
    Url,
    Domain,
    Ip,
}

impl MatchObjectType {
    /// Convert to API parameter string
    pub fn to_string(&self) -> &'static str {
        match self {
            MatchObjectType::File => "file",
            MatchObjectType::Url => "url",
            MatchObjectType::Domain => "domain",
            MatchObjectType::Ip => "ip",
        }
    }
}

/// Editor descriptor for permission management
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EditorDescriptor {
    #[serde(rename = "type")]
    pub object_type: String,
    pub id: String,
}

/// Request to add editors
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AddEditorsRequest {
    pub data: Vec<EditorDescriptor>,
}

/// Request to transfer ownership
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransferOwnershipRequest {
    pub data: EditorDescriptor,
}

/// Response for permission check
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PermissionCheckResponse {
    pub data: bool,
}

/// Operation response for async operations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OperationResponse {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<OperationError>,
}

/// Operation error details
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OperationError {
    pub code: String,
    pub message: String,
}

/// Client for Livehunt operations
pub struct LivehuntClient<'a> {
    pub(crate) client: &'a Client,
}

impl<'a> LivehuntClient<'a> {
    pub fn new(client: &'a Client) -> Self {
        Self { client }
    }

    // ===== Ruleset Management =====

    /// List Livehunt rulesets
    pub async fn list_rulesets(
        &self,
        filter: Option<&str>,
        order: Option<LivehuntRulesetOrder>,
        limit: Option<u32>,
        cursor: Option<&str>,
    ) -> Result<Collection<LivehuntRuleset>> {
        let mut url = String::from("intelligence/hunting_rulesets?");

        if let Some(f) = filter {
            url.push_str(&format!("filter={}&", urlencoding::encode(f)));
        }

        if let Some(o) = order {
            url.push_str(&format!("order={}&", o.to_string()));
        }

        if let Some(l) = limit {
            url.push_str(&format!("limit={}&", l));
        }

        if let Some(c) = cursor {
            url.push_str(&format!("cursor={}&", urlencoding::encode(c)));
        }

        // Remove trailing '&' or '?'
        url.pop();

        self.client.get(&url).await
    }

    /// List rulesets with pagination support
    pub fn list_rulesets_iterator(
        &self,
        filter: Option<&str>,
        order: Option<LivehuntRulesetOrder>,
    ) -> CollectionIterator<'_, LivehuntRuleset> {
        let mut url = String::from("intelligence/hunting_rulesets?");

        if let Some(f) = filter {
            url.push_str(&format!("filter={}&", urlencoding::encode(f)));
        }

        if let Some(o) = order {
            url.push_str(&format!("order={}&", o.to_string()));
        }

        // Remove trailing '&' or '?'
        url.pop();

        CollectionIterator::new(self.client, url)
    }

    /// Create a new Livehunt ruleset
    pub async fn create_ruleset(
        &self,
        request: &CreateLivehuntRulesetRequest,
    ) -> Result<LivehuntRuleset> {
        self.client
            .post("intelligence/hunting_rulesets", request)
            .await
    }

    /// Get a Livehunt ruleset by ID
    pub async fn get_ruleset(&self, ruleset_id: &str) -> Result<LivehuntRuleset> {
        let url = format!(
            "intelligence/hunting_rulesets/{}",
            urlencoding::encode(ruleset_id)
        );
        self.client.get(&url).await
    }

    /// Update a Livehunt ruleset
    pub async fn update_ruleset(
        &self,
        ruleset_id: &str,
        request: &UpdateLivehuntRulesetRequest,
    ) -> Result<LivehuntRuleset> {
        let url = format!(
            "intelligence/hunting_rulesets/{}",
            urlencoding::encode(ruleset_id)
        );
        self.client.patch(&url, request).await
    }

    /// Delete a Livehunt ruleset
    pub async fn delete_ruleset(&self, ruleset_id: &str) -> Result<()> {
        let url = format!(
            "intelligence/hunting_rulesets/{}",
            urlencoding::encode(ruleset_id)
        );
        self.client.delete(&url).await
    }

    /// Delete all Livehunt rulesets (requires x-confirm-delete header)
    pub async fn delete_all_rulesets(&self, _username: &str) -> Result<OperationResponse> {
        // This would need special handling for the x-confirm-delete header
        // For now, return an error indicating this needs to be implemented with header support
        Err(crate::Error::Unknown(
            "delete_all_rulesets requires x-confirm-delete header support".to_string(),
        ))
    }

    // ===== Permission Management =====

    /// Check if a user or group is a ruleset editor
    pub async fn check_editor_permission(
        &self,
        ruleset_id: &str,
        user_or_group_id: &str,
    ) -> Result<PermissionCheckResponse> {
        let url = format!(
            "intelligence/hunting_rulesets/{}/relationships/editors/{}",
            urlencoding::encode(ruleset_id),
            urlencoding::encode(user_or_group_id)
        );
        self.client.get(&url).await
    }

    /// Grant edit permissions to users or groups
    pub async fn grant_edit_permissions(
        &self,
        ruleset_id: &str,
        request: &AddEditorsRequest,
    ) -> Result<()> {
        let url = format!(
            "intelligence/hunting_rulesets/{}/relationships/editors",
            urlencoding::encode(ruleset_id)
        );
        self.client.post(&url, request).await
    }

    /// Revoke edit permission from a user or group
    pub async fn revoke_edit_permission(
        &self,
        ruleset_id: &str,
        user_or_group_id: &str,
    ) -> Result<()> {
        let url = format!(
            "intelligence/hunting_rulesets/{}/relationships/editors/{}",
            urlencoding::encode(ruleset_id),
            urlencoding::encode(user_or_group_id)
        );
        self.client.delete(&url).await
    }

    /// Transfer ruleset ownership to another user
    pub async fn transfer_ownership(
        &self,
        ruleset_id: &str,
        request: &TransferOwnershipRequest,
    ) -> Result<()> {
        let url = format!(
            "intelligence/hunting_rulesets/{}/relationships/owner",
            urlencoding::encode(ruleset_id)
        );
        self.client.post(&url, request).await
    }

    // ===== Relationships =====

    /// Get objects related to a ruleset
    pub async fn get_relationship<T>(
        &self,
        ruleset_id: &str,
        relationship: &str,
        limit: Option<u32>,
        cursor: Option<&str>,
    ) -> Result<Collection<T>>
    where
        T: serde::de::DeserializeOwned,
    {
        let mut url = format!(
            "intelligence/hunting_rulesets/{}/{}?",
            urlencoding::encode(ruleset_id),
            relationship
        );

        if let Some(l) = limit {
            url.push_str(&format!("limit={}&", l));
        }

        if let Some(c) = cursor {
            url.push_str(&format!("cursor={}&", urlencoding::encode(c)));
        }

        // Remove trailing '&' or '?'
        url.pop();

        self.client.get(&url).await
    }

    /// Get object descriptors related to a ruleset
    pub async fn get_relationship_descriptors<T>(
        &self,
        ruleset_id: &str,
        relationship: &str,
        limit: Option<u32>,
        cursor: Option<&str>,
    ) -> Result<Collection<T>>
    where
        T: serde::de::DeserializeOwned,
    {
        let mut url = format!(
            "intelligence/hunting_rulesets/{}/relationships/{}?",
            urlencoding::encode(ruleset_id),
            relationship
        );

        if let Some(l) = limit {
            url.push_str(&format!("limit={}&", l));
        }

        if let Some(c) = cursor {
            url.push_str(&format!("cursor={}&", urlencoding::encode(c)));
        }

        // Remove trailing '&' or '?'
        url.pop();

        self.client.get(&url).await
    }

    // ===== Notifications =====

    /// Get Livehunt notifications
    pub async fn list_notifications(
        &self,
        filter: Option<&str>,
        order: Option<NotificationOrder>,
        limit: Option<u32>,
        count_limit: Option<u32>,
        cursor: Option<&str>,
    ) -> Result<Collection<LivehuntNotification>> {
        let mut url = String::from("intelligence/hunting_notifications?");

        if let Some(f) = filter {
            url.push_str(&format!("filter={}&", urlencoding::encode(f)));
        }

        if let Some(o) = order {
            url.push_str(&format!("order={}&", o.to_string()));
        }

        if let Some(l) = limit {
            url.push_str(&format!("limit={}&", l));
        }

        if let Some(cl) = count_limit {
            url.push_str(&format!("count_limit={}&", cl.min(10000))); // Max 10,000
        }

        if let Some(c) = cursor {
            url.push_str(&format!("cursor={}&", urlencoding::encode(c)));
        }

        // Remove trailing '&' or '?'
        url.pop();

        self.client.get(&url).await
    }

    /// List notifications with pagination support
    pub fn list_notifications_iterator(
        &self,
        filter: Option<&str>,
        order: Option<NotificationOrder>,
        count_limit: Option<u32>,
    ) -> CollectionIterator<'_, LivehuntNotification> {
        let mut url = String::from("intelligence/hunting_notifications?");

        if let Some(f) = filter {
            url.push_str(&format!("filter={}&", urlencoding::encode(f)));
        }

        if let Some(o) = order {
            url.push_str(&format!("order={}&", o.to_string()));
        }

        if let Some(cl) = count_limit {
            url.push_str(&format!("count_limit={}&", cl.min(10000)));
        }

        // Remove trailing '&' or '?'
        url.pop();

        CollectionIterator::new(self.client, url)
    }

    /// Get a specific notification
    pub async fn get_notification(&self, notification_id: &str) -> Result<LivehuntNotification> {
        let url = format!(
            "intelligence/hunting_notifications/{}",
            urlencoding::encode(notification_id)
        );
        self.client.get(&url).await
    }

    /// Delete a specific notification
    pub async fn delete_notification(&self, notification_id: &str) -> Result<()> {
        let url = format!(
            "intelligence/hunting_notifications/{}",
            urlencoding::encode(notification_id)
        );
        self.client.delete(&url).await
    }

    /// Delete notifications in bulk
    pub async fn delete_notifications(&self, tag: Option<&str>) -> Result<()> {
        let mut url = String::from("intelligence/hunting_notifications");

        if let Some(t) = tag {
            url.push_str(&format!("?tag={}", urlencoding::encode(t)));
        }

        self.client.delete(&url).await
    }

    /// Retrieve file objects for notifications
    pub async fn list_notification_files(
        &self,
        filter: Option<&str>,
        limit: Option<u32>,
        count_limit: Option<u32>,
        cursor: Option<&str>,
    ) -> Result<Collection<NotificationFile>> {
        let mut url = String::from("intelligence/hunting_notification_files?");

        if let Some(f) = filter {
            url.push_str(&format!("filter={}&", urlencoding::encode(f)));
        }

        if let Some(l) = limit {
            url.push_str(&format!("limit={}&", l));
        }

        if let Some(cl) = count_limit {
            url.push_str(&format!("count_limit={}&", cl.min(10000)));
        }

        if let Some(c) = cursor {
            url.push_str(&format!("cursor={}&", urlencoding::encode(c)));
        }

        // Remove trailing '&' or '?'
        url.pop();

        self.client.get(&url).await
    }
}

/// Helper methods for creating Livehunt rulesets
impl CreateLivehuntRulesetRequest {
    /// Create a new ruleset request
    pub fn new(name: String, rules: String) -> Self {
        Self {
            data: CreateLivehuntRulesetData {
                object_type: "hunting_ruleset".to_string(),
                attributes: CreateLivehuntRulesetAttributes {
                    name,
                    rules,
                    enabled: None,
                    limit: None,
                    notification_emails: None,
                    match_object_type: None,
                },
            },
        }
    }

    /// Set enabled status
    pub fn with_enabled(mut self, enabled: bool) -> Self {
        self.data.attributes.enabled = Some(enabled);
        self
    }

    /// Set match limit
    pub fn with_limit(mut self, limit: u32) -> Self {
        self.data.attributes.limit = Some(limit);
        self
    }

    /// Set notification emails
    pub fn with_notification_emails(mut self, emails: Vec<String>) -> Self {
        self.data.attributes.notification_emails = Some(emails);
        self
    }

    /// Set match object type
    pub fn with_match_object_type(mut self, object_type: MatchObjectType) -> Self {
        self.data.attributes.match_object_type = Some(object_type.to_string().to_owned());
        self
    }
}

impl Client {
    /// Get the Livehunt client
    pub fn livehunt(&self) -> LivehuntClient<'_> {
        LivehuntClient::new(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_livehunt_ruleset_attributes() {
        let attrs = LivehuntRulesetAttributes {
            name: Some("Test Ruleset".to_string()),
            enabled: Some(true),
            limit: Some(100),
            rules: Some("rule test { condition: true }".to_string()),
            notification_emails: Some(vec!["test@example.com".to_string()]),
            match_object_type: Some("file".to_string()),
            ..Default::default()
        };

        assert_eq!(attrs.name.unwrap(), "Test Ruleset");
        assert_eq!(attrs.enabled.unwrap(), true);
        assert_eq!(attrs.limit.unwrap(), 100);
        assert!(attrs.rules.unwrap().contains("rule test"));
    }

    #[test]
    fn test_create_ruleset_request() {
        let request = CreateLivehuntRulesetRequest::new(
            "My Ruleset".to_string(),
            "rule example { strings: $ = \"test\" condition: all of them }".to_string(),
        )
        .with_enabled(true)
        .with_limit(50)
        .with_notification_emails(vec!["notify@example.com".to_string()])
        .with_match_object_type(MatchObjectType::File);

        assert_eq!(request.data.attributes.name, "My Ruleset");
        assert_eq!(request.data.attributes.enabled.unwrap(), true);
        assert_eq!(request.data.attributes.limit.unwrap(), 50);
        assert_eq!(
            request.data.attributes.notification_emails.unwrap().len(),
            1
        );
        assert_eq!(request.data.attributes.match_object_type.unwrap(), "file");
    }

    #[test]
    fn test_livehunt_ruleset_order_strings() {
        assert_eq!(LivehuntRulesetOrder::NameAsc.to_string(), "name+");
        assert_eq!(LivehuntRulesetOrder::NameDesc.to_string(), "name-");
        assert_eq!(
            LivehuntRulesetOrder::CreationDateAsc.to_string(),
            "creation_date+"
        );
        assert_eq!(
            LivehuntRulesetOrder::CreationDateDesc.to_string(),
            "creation_date-"
        );
    }

    #[test]
    fn test_notification_order_strings() {
        assert_eq!(NotificationOrder::DateAsc.to_string(), "date+");
        assert_eq!(NotificationOrder::DateDesc.to_string(), "date-");
    }

    #[test]
    fn test_match_object_type_strings() {
        assert_eq!(MatchObjectType::File.to_string(), "file");
        assert_eq!(MatchObjectType::Url.to_string(), "url");
        assert_eq!(MatchObjectType::Domain.to_string(), "domain");
        assert_eq!(MatchObjectType::Ip.to_string(), "ip");
    }

    #[test]
    fn test_notification_attributes() {
        let attrs = LivehuntNotificationAttributes {
            date: Some(1234567890),
            tags: Some(vec!["malware".to_string(), "trojan".to_string()]),
            ruleset_id: Some("ruleset_123".to_string()),
            ruleset_name: Some("Malware Detection".to_string()),
            rule_name: Some("TrojanDetector".to_string()),
            sha256: Some("abc123def456".to_string()),
            ..Default::default()
        };

        assert_eq!(attrs.date.unwrap(), 1234567890);
        assert_eq!(attrs.tags.unwrap().len(), 2);
        assert_eq!(attrs.ruleset_name.unwrap(), "Malware Detection");
        assert_eq!(attrs.rule_name.unwrap(), "TrojanDetector");
    }

    #[test]
    fn test_notification_file_context() {
        let context = NotificationFileContext {
            match_in_subfile: false,
            notification_date: 1234567890,
            notification_id: "notif_123".to_string(),
            notification_snippet: Some("00 01 02 03".to_string()),
            notification_source_key: Some("key_123".to_string()),
            notification_tags: vec!["tag1".to_string(), "tag2".to_string()],
            ruleset_id: "ruleset_123".to_string(),
            ruleset_name: "Test Ruleset".to_string(),
            rule_name: "TestRule".to_string(),
            rule_tags: Some(vec!["test".to_string()]),
        };

        assert_eq!(context.match_in_subfile, false);
        assert_eq!(context.notification_id, "notif_123");
        assert_eq!(context.ruleset_name, "Test Ruleset");
        assert_eq!(context.rule_name, "TestRule");
    }

    #[test]
    fn test_editor_descriptor() {
        let editor = EditorDescriptor {
            object_type: "user".to_string(),
            id: "user123".to_string(),
        };

        assert_eq!(editor.object_type, "user");
        assert_eq!(editor.id, "user123");

        let request = AddEditorsRequest { data: vec![editor] };

        assert_eq!(request.data.len(), 1);
    }

    #[test]
    fn test_operation_response() {
        let response = OperationResponse {
            id: Some("op_123".to_string()),
            status: Some("completed".to_string()),
            error: None,
        };

        assert_eq!(response.id.unwrap(), "op_123");
        assert_eq!(response.status.unwrap(), "completed");
        assert!(response.error.is_none());

        let error_response = OperationResponse {
            id: None,
            status: Some("failed".to_string()),
            error: Some(OperationError {
                code: "ERR001".to_string(),
                message: "Operation failed".to_string(),
            }),
        };

        assert!(error_response.error.is_some());
    }
}
