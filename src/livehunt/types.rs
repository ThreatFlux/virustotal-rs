use crate::objects::Object;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Represents a Livehunt ruleset in `VirusTotal`
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
