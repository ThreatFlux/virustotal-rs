use crate::objects::Object;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Represents a Graph in `VirusTotal`
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Graph {
    #[serde(flatten)]
    pub object: Object<GraphAttributes>,
}

/// Attributes for a Graph
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct GraphAttributes {
    /// Graph name
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,

    /// Graph description
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

    /// Graph type
    #[serde(skip_serializing_if = "Option::is_none")]
    pub graph_type: Option<String>,

    /// Owner of the graph
    #[serde(skip_serializing_if = "Option::is_none")]
    pub owner: Option<String>,

    /// Creation date (UTC timestamp)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub creation_date: Option<i64>,

    /// Last modification date (UTC timestamp)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub modification_date: Option<i64>,

    /// Number of nodes
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nodes_count: Option<u32>,

    /// Number of edges
    #[serde(skip_serializing_if = "Option::is_none")]
    pub edges_count: Option<u32>,

    /// Graph visibility (public/private)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub visibility: Option<String>,

    /// Tags associated with the graph
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tags: Option<Vec<String>>,

    /// Graph data/content
    #[serde(skip_serializing_if = "Option::is_none")]
    pub graph_data: Option<serde_json::Value>,

    /// Additional attributes
    #[serde(flatten)]
    pub additional_attributes: HashMap<String, serde_json::Value>,
}

/// Request to create a new Graph
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateGraphRequest {
    pub data: CreateGraphData,
}

/// Data for creating a Graph
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateGraphData {
    #[serde(rename = "type")]
    pub object_type: String,
    pub attributes: CreateGraphAttributes,
}

/// Attributes for creating a Graph
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateGraphAttributes {
    /// Graph name (required)
    pub name: String,

    /// Graph description (optional)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

    /// Graph type (optional)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub graph_type: Option<String>,

    /// Graph visibility (optional)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub visibility: Option<String>,

    /// Tags (optional)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tags: Option<Vec<String>>,

    /// Graph data/content (optional)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub graph_data: Option<serde_json::Value>,
}

/// Request to update a Graph
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateGraphRequest {
    pub data: UpdateGraphData,
}

/// Data for updating a Graph
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateGraphData {
    #[serde(rename = "type")]
    pub object_type: String,
    pub id: String,
    pub attributes: UpdateGraphAttributes,
}

/// Attributes for updating a Graph
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct UpdateGraphAttributes {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub graph_type: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub visibility: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub tags: Option<Vec<String>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub graph_data: Option<serde_json::Value>,
}

/// Request to add a comment to a graph
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AddGraphCommentRequest {
    pub data: AddGraphCommentData,
}

/// Data for adding a comment to a graph
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AddGraphCommentData {
    #[serde(rename = "type")]
    pub object_type: String,
    pub attributes: AddGraphCommentAttributes,
}

/// Attributes for adding a comment to a graph
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AddGraphCommentAttributes {
    pub text: String,
}

/// Graph visibility options
#[derive(Debug, Clone, Copy)]
pub enum GraphVisibility {
    Public,
    Private,
}

impl GraphVisibility {
    /// Convert to API parameter string
    pub fn to_string(&self) -> &'static str {
        match self {
            GraphVisibility::Public => "public",
            GraphVisibility::Private => "private",
        }
    }
}

/// User information for graph owner
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphOwner {
    #[serde(flatten)]
    pub object: Object<GraphOwnerAttributes>,
}

/// Attributes for graph owner
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphOwnerAttributes {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub first_name: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_name: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub profile_phrase: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub reputation: Option<i32>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_since: Option<i64>,

    #[serde(flatten)]
    pub additional_attributes: HashMap<String, serde_json::Value>,
}

/// Descriptor for graph relationships (minimal info)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphRelationshipDescriptor {
    #[serde(rename = "type")]
    pub object_type: String,
    pub id: String,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub context_attributes: Option<serde_json::Value>,
}

/// Request to grant viewer/editor permissions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GrantPermissionRequest {
    pub data: Vec<PermissionDescriptor>,
}

/// Descriptor for user/group permissions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PermissionDescriptor {
    #[serde(rename = "type")]
    pub object_type: String,
    pub id: String,
}

/// Response for permission check
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphPermissionCheckResponse {
    pub data: bool,
}

/// Graph ordering options
#[derive(Debug, Clone, Copy)]
pub enum GraphOrder {
    NameAsc,
    NameDesc,
    CreationDateAsc,
    CreationDateDesc,
    ModificationDateAsc,
    ModificationDateDesc,
    NodesCountAsc,
    NodesCountDesc,
}

impl GraphOrder {
    /// Convert to API parameter string
    pub fn to_string(&self) -> &'static str {
        match self {
            GraphOrder::NameAsc => "name+",
            GraphOrder::NameDesc => "name-",
            GraphOrder::CreationDateAsc => "creation_date+",
            GraphOrder::CreationDateDesc => "creation_date-",
            GraphOrder::ModificationDateAsc => "modification_date+",
            GraphOrder::ModificationDateDesc => "modification_date-",
            GraphOrder::NodesCountAsc => "nodes_count+",
            GraphOrder::NodesCountDesc => "nodes_count-",
        }
    }
}
