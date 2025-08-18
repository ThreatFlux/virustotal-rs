use crate::comments::Comment;
use crate::objects::{Collection, CollectionIterator, Object};
use crate::{Client, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Represents a Graph in VirusTotal
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

/// Client for Graph operations
pub struct GraphClient<'a> {
    pub(crate) client: &'a Client,
}

impl<'a> GraphClient<'a> {
    pub fn new(client: &'a Client) -> Self {
        Self { client }
    }

    /// List graphs
    ///
    /// Accepted filters:
    /// - owner:<username>
    /// - tag:<tag>
    /// - visibility:public|private
    pub async fn list_graphs(
        &self,
        filter: Option<&str>,
        order: Option<GraphOrder>,
        limit: Option<u32>,
        cursor: Option<&str>,
    ) -> Result<Collection<Graph>> {
        let mut url = String::from("graphs?");

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

    /// List graphs with pagination support
    pub fn list_graphs_iterator(
        &self,
        filter: Option<&str>,
        order: Option<GraphOrder>,
    ) -> CollectionIterator<'_, Graph> {
        let mut url = String::from("graphs?");

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

    /// Create a new graph
    pub async fn create_graph(&self, request: &CreateGraphRequest) -> Result<Graph> {
        self.client.post("graphs", request).await
    }

    /// Get a graph by ID
    pub async fn get_graph(&self, graph_id: &str) -> Result<Graph> {
        let url = format!("graphs/{}", urlencoding::encode(graph_id));
        self.client.get(&url).await
    }

    /// Update a graph
    pub async fn update_graph(
        &self,
        graph_id: &str,
        request: &UpdateGraphRequest,
    ) -> Result<Graph> {
        let url = format!("graphs/{}", urlencoding::encode(graph_id));
        self.client.patch(&url, request).await
    }

    /// Delete a graph
    pub async fn delete_graph(&self, graph_id: &str) -> Result<()> {
        let url = format!("graphs/{}", urlencoding::encode(graph_id));
        self.client.delete(&url).await
    }

    /// Get comments on a graph
    pub async fn get_graph_comments(
        &self,
        graph_id: &str,
        limit: Option<u32>,
        cursor: Option<&str>,
    ) -> Result<Collection<Comment>> {
        let mut url = format!("graphs/{}/comments?", urlencoding::encode(graph_id));

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

    /// Get comments with pagination support
    pub fn get_graph_comments_iterator(&self, graph_id: &str) -> CollectionIterator<'_, Comment> {
        let url = format!("graphs/{}/comments", urlencoding::encode(graph_id));
        CollectionIterator::new(self.client, url)
    }

    /// Add a comment to a graph
    pub async fn add_graph_comment(&self, graph_id: &str, comment_text: &str) -> Result<Comment> {
        let url = format!("graphs/{}/comments", urlencoding::encode(graph_id));
        let request = AddGraphCommentRequest {
            data: AddGraphCommentData {
                object_type: "comment".to_string(),
                attributes: AddGraphCommentAttributes {
                    text: comment_text.to_string(),
                },
            },
        };
        self.client.post(&url, &request).await
    }

    /// Get related objects for a graph
    ///
    /// Supported relationships:
    /// - owner: Returns the user who owns the graph
    /// - editors: Returns users who can edit the graph
    /// - viewers: Returns users who can view the graph
    /// - group: Returns the group the graph belongs to
    pub async fn get_graph_relationship<T>(
        &self,
        graph_id: &str,
        relationship: &str,
        limit: Option<u32>,
        cursor: Option<&str>,
    ) -> Result<Collection<T>>
    where
        T: serde::de::DeserializeOwned,
    {
        let mut url = format!("graphs/{}/{}?", urlencoding::encode(graph_id), relationship);

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

    /// Get object descriptors related to a graph (minimal info)
    ///
    /// This returns just the related object's IDs and context attributes
    /// instead of returning all attributes
    pub async fn get_graph_relationship_descriptors(
        &self,
        graph_id: &str,
        relationship: &str,
        limit: Option<u32>,
        cursor: Option<&str>,
    ) -> Result<Collection<GraphRelationshipDescriptor>> {
        let mut url = format!(
            "graphs/{}/relationships/{}?",
            urlencoding::encode(graph_id),
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

    /// Get the owner of a graph
    pub async fn get_graph_owner(&self, graph_id: &str) -> Result<GraphOwner> {
        let url = format!("graphs/{}/owner", urlencoding::encode(graph_id));
        self.client.get(&url).await
    }

    /// Get editors of a graph
    pub async fn get_graph_editors(
        &self,
        graph_id: &str,
        limit: Option<u32>,
        cursor: Option<&str>,
    ) -> Result<Collection<GraphOwner>> {
        self.get_graph_relationship(graph_id, "editors", limit, cursor)
            .await
    }

    /// Get viewers of a graph  
    pub async fn get_graph_viewers(
        &self,
        graph_id: &str,
        limit: Option<u32>,
        cursor: Option<&str>,
    ) -> Result<Collection<GraphOwner>> {
        self.get_graph_relationship(graph_id, "viewers", limit, cursor)
            .await
    }

    /// Get group associated with a graph
    pub async fn get_graph_group(&self, graph_id: &str) -> Result<serde_json::Value> {
        let url = format!("graphs/{}/group", urlencoding::encode(graph_id));
        self.client.get(&url).await
    }

    // ===== Viewer Permission Management =====

    /// Get users and groups that can view a graph (using relationships endpoint)
    pub async fn get_graph_viewers_descriptors(
        &self,
        graph_id: &str,
        limit: Option<u32>,
        cursor: Option<&str>,
    ) -> Result<Collection<GraphRelationshipDescriptor>> {
        self.get_graph_relationship_descriptors(graph_id, "viewers", limit, cursor)
            .await
    }

    /// Grant view permission to users or groups
    pub async fn grant_view_permission(
        &self,
        graph_id: &str,
        users_or_groups: Vec<PermissionDescriptor>,
    ) -> Result<Collection<GraphOwner>> {
        let url = format!(
            "graphs/{}/relationships/viewers",
            urlencoding::encode(graph_id)
        );
        let request = GrantPermissionRequest {
            data: users_or_groups,
        };
        self.client.post(&url, &request).await
    }

    /// Check if a user or group can view a graph
    pub async fn check_view_permission(
        &self,
        graph_id: &str,
        user_or_group_id: &str,
    ) -> Result<GraphPermissionCheckResponse> {
        let url = format!(
            "graphs/{}/relationships/viewers/{}",
            urlencoding::encode(graph_id),
            urlencoding::encode(user_or_group_id)
        );
        self.client.get(&url).await
    }

    /// Revoke view permission from a user or group
    pub async fn revoke_view_permission(
        &self,
        graph_id: &str,
        user_or_group_id: &str,
    ) -> Result<()> {
        let url = format!(
            "graphs/{}/relationships/viewers/{}",
            urlencoding::encode(graph_id),
            urlencoding::encode(user_or_group_id)
        );
        self.client.delete(&url).await
    }

    // ===== Editor Permission Management =====
    //
    // Complete editor permission management including:
    // - Grant edit permissions to users/groups (POST /graphs/{id}/relationships/editors)
    // - Check if user/group has edit permission (GET /graphs/{id}/relationships/editors/{user_or_group_id})
    // - Revoke edit permission (DELETE /graphs/{id}/relationships/editors/{user_or_group_id})
    // - List all editors with full or minimal information

    /// Get users and groups that can edit a graph (using relationships endpoint)
    pub async fn get_graph_editors_descriptors(
        &self,
        graph_id: &str,
        limit: Option<u32>,
        cursor: Option<&str>,
    ) -> Result<Collection<GraphRelationshipDescriptor>> {
        self.get_graph_relationship_descriptors(graph_id, "editors", limit, cursor)
            .await
    }

    /// Grant edit permission to users or groups
    pub async fn grant_edit_permission(
        &self,
        graph_id: &str,
        users_or_groups: Vec<PermissionDescriptor>,
    ) -> Result<Collection<GraphOwner>> {
        let url = format!(
            "graphs/{}/relationships/editors",
            urlencoding::encode(graph_id)
        );
        let request = GrantPermissionRequest {
            data: users_or_groups,
        };
        self.client.post(&url, &request).await
    }

    /// Check if a user or group can edit a graph
    pub async fn check_edit_permission(
        &self,
        graph_id: &str,
        user_or_group_id: &str,
    ) -> Result<GraphPermissionCheckResponse> {
        let url = format!(
            "graphs/{}/relationships/editors/{}",
            urlencoding::encode(graph_id),
            urlencoding::encode(user_or_group_id)
        );
        self.client.get(&url).await
    }

    /// Revoke edit permission from a user or group
    ///
    /// DELETE /graphs/{id}/relationships/editors/{user_or_group_id}
    ///
    /// This endpoint removes a user or group as a graph editor.
    pub async fn revoke_edit_permission(
        &self,
        graph_id: &str,
        user_or_group_id: &str,
    ) -> Result<()> {
        let url = format!(
            "graphs/{}/relationships/editors/{}",
            urlencoding::encode(graph_id),
            urlencoding::encode(user_or_group_id)
        );
        self.client.delete(&url).await
    }

    /// Search graphs
    pub async fn search_graphs(
        &self,
        query: &str,
        limit: Option<u32>,
        cursor: Option<&str>,
    ) -> Result<Collection<Graph>> {
        let mut url = format!("graphs/search?query={}&", urlencoding::encode(query));

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
}

/// Helper methods for creating graphs
impl CreateGraphRequest {
    /// Create a new graph request
    pub fn new(name: String) -> Self {
        Self {
            data: CreateGraphData {
                object_type: "graph".to_string(),
                attributes: CreateGraphAttributes {
                    name,
                    description: None,
                    graph_type: None,
                    visibility: None,
                    tags: None,
                    graph_data: None,
                },
            },
        }
    }

    /// Set description
    pub fn with_description(mut self, description: String) -> Self {
        self.data.attributes.description = Some(description);
        self
    }

    /// Set graph type
    pub fn with_graph_type(mut self, graph_type: String) -> Self {
        self.data.attributes.graph_type = Some(graph_type);
        self
    }

    /// Set visibility
    pub fn with_visibility(mut self, visibility: GraphVisibility) -> Self {
        self.data.attributes.visibility = Some(visibility.to_string().to_owned());
        self
    }

    /// Set tags
    pub fn with_tags(mut self, tags: Vec<String>) -> Self {
        self.data.attributes.tags = Some(tags);
        self
    }

    /// Set graph data
    pub fn with_graph_data(mut self, data: serde_json::Value) -> Self {
        self.data.attributes.graph_data = Some(data);
        self
    }
}

/// Helper methods for updating graphs
impl UpdateGraphRequest {
    /// Create a new update request
    pub fn new(graph_id: String) -> Self {
        Self {
            data: UpdateGraphData {
                object_type: "graph".to_string(),
                id: graph_id,
                attributes: UpdateGraphAttributes::default(),
            },
        }
    }

    /// Update name
    pub fn with_name(mut self, name: String) -> Self {
        self.data.attributes.name = Some(name);
        self
    }

    /// Update description
    pub fn with_description(mut self, description: String) -> Self {
        self.data.attributes.description = Some(description);
        self
    }

    /// Update graph type
    pub fn with_graph_type(mut self, graph_type: String) -> Self {
        self.data.attributes.graph_type = Some(graph_type);
        self
    }

    /// Update visibility
    pub fn with_visibility(mut self, visibility: GraphVisibility) -> Self {
        self.data.attributes.visibility = Some(visibility.to_string().to_owned());
        self
    }

    /// Update tags
    pub fn with_tags(mut self, tags: Vec<String>) -> Self {
        self.data.attributes.tags = Some(tags);
        self
    }

    /// Update graph data
    pub fn with_graph_data(mut self, data: serde_json::Value) -> Self {
        self.data.attributes.graph_data = Some(data);
        self
    }
}

/// Helper methods for permission management
impl PermissionDescriptor {
    /// Create a new user permission descriptor
    pub fn user(user_id: String) -> Self {
        Self {
            object_type: "user".to_string(),
            id: user_id,
        }
    }

    /// Create a new group permission descriptor
    pub fn group(group_id: String) -> Self {
        Self {
            object_type: "group".to_string(),
            id: group_id,
        }
    }
}

impl Client {
    /// Get the Graph client
    pub fn graphs(&self) -> GraphClient<'_> {
        GraphClient::new(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_graph_attributes() {
        let attrs = GraphAttributes {
            name: Some("Test Graph".to_string()),
            description: Some("A test graph".to_string()),
            graph_type: Some("malware_analysis".to_string()),
            visibility: Some("public".to_string()),
            nodes_count: Some(10),
            edges_count: Some(15),
            ..Default::default()
        };

        assert_eq!(attrs.name.unwrap(), "Test Graph");
        assert_eq!(attrs.description.unwrap(), "A test graph");
        assert_eq!(attrs.graph_type.unwrap(), "malware_analysis");
        assert_eq!(attrs.visibility.unwrap(), "public");
        assert_eq!(attrs.nodes_count.unwrap(), 10);
        assert_eq!(attrs.edges_count.unwrap(), 15);
    }

    #[test]
    fn test_create_graph_request() {
        let request = CreateGraphRequest::new("My Graph".to_string())
            .with_description("Graph description".to_string())
            .with_visibility(GraphVisibility::Private)
            .with_tags(vec!["tag1".to_string(), "tag2".to_string()]);

        assert_eq!(request.data.attributes.name, "My Graph");
        assert_eq!(
            request.data.attributes.description.unwrap(),
            "Graph description"
        );
        assert_eq!(request.data.attributes.visibility.unwrap(), "private");
        assert_eq!(request.data.attributes.tags.unwrap().len(), 2);
    }

    #[test]
    fn test_update_graph_request() {
        let request = UpdateGraphRequest::new("graph_123".to_string())
            .with_name("Updated Graph".to_string())
            .with_visibility(GraphVisibility::Public)
            .with_tags(vec!["updated".to_string()]);

        assert_eq!(request.data.id, "graph_123");
        assert_eq!(request.data.attributes.name.unwrap(), "Updated Graph");
        assert_eq!(request.data.attributes.visibility.unwrap(), "public");
        assert_eq!(request.data.attributes.tags.unwrap().len(), 1);
    }

    #[test]
    fn test_graph_visibility_strings() {
        assert_eq!(GraphVisibility::Public.to_string(), "public");
        assert_eq!(GraphVisibility::Private.to_string(), "private");
    }

    #[test]
    fn test_graph_order_strings() {
        assert_eq!(GraphOrder::NameAsc.to_string(), "name+");
        assert_eq!(GraphOrder::NameDesc.to_string(), "name-");
        assert_eq!(GraphOrder::CreationDateAsc.to_string(), "creation_date+");
        assert_eq!(GraphOrder::CreationDateDesc.to_string(), "creation_date-");
        assert_eq!(GraphOrder::NodesCountAsc.to_string(), "nodes_count+");
        assert_eq!(GraphOrder::NodesCountDesc.to_string(), "nodes_count-");
    }

    #[test]
    fn test_add_graph_comment_request() {
        let request = AddGraphCommentRequest {
            data: AddGraphCommentData {
                object_type: "comment".to_string(),
                attributes: AddGraphCommentAttributes {
                    text: "This is a comment".to_string(),
                },
            },
        };

        assert_eq!(request.data.object_type, "comment");
        assert_eq!(request.data.attributes.text, "This is a comment");
    }

    #[test]
    fn test_graph_with_data() {
        let graph_data = serde_json::json!({
            "nodes": [
                {"id": "1", "label": "Node 1"},
                {"id": "2", "label": "Node 2"}
            ],
            "edges": [
                {"from": "1", "to": "2", "label": "connects"}
            ]
        });

        let request =
            CreateGraphRequest::new("Data Graph".to_string()).with_graph_data(graph_data.clone());

        assert!(request.data.attributes.graph_data.is_some());
        let data = request.data.attributes.graph_data.unwrap();
        assert!(data["nodes"].is_array());
        assert_eq!(data["nodes"].as_array().unwrap().len(), 2);
    }

    #[test]
    fn test_graph_owner_attributes() {
        let owner_attrs = GraphOwnerAttributes {
            first_name: Some("Richard".to_string()),
            last_name: Some("Hendricks".to_string()),
            profile_phrase: Some("CEO of Pied Piper".to_string()),
            reputation: Some(1),
            status: Some("active".to_string()),
            user_since: Some(1528111032),
            additional_attributes: HashMap::new(),
        };

        assert_eq!(owner_attrs.first_name.unwrap(), "Richard");
        assert_eq!(owner_attrs.last_name.unwrap(), "Hendricks");
        assert_eq!(owner_attrs.profile_phrase.unwrap(), "CEO of Pied Piper");
        assert_eq!(owner_attrs.reputation.unwrap(), 1);
        assert_eq!(owner_attrs.status.unwrap(), "active");
        assert_eq!(owner_attrs.user_since.unwrap(), 1528111032);
    }

    #[test]
    fn test_graph_relationship_descriptor() {
        let descriptor = GraphRelationshipDescriptor {
            object_type: "user".to_string(),
            id: "user123".to_string(),
            context_attributes: Some(serde_json::json!({
                "role": "editor",
                "added_at": 1234567890
            })),
        };

        assert_eq!(descriptor.object_type, "user");
        assert_eq!(descriptor.id, "user123");
        assert!(descriptor.context_attributes.is_some());

        let context = descriptor.context_attributes.unwrap();
        assert_eq!(context["role"], "editor");
        assert_eq!(context["added_at"], 1234567890);
    }

    #[test]
    fn test_permission_descriptor() {
        let user_perm = PermissionDescriptor::user("hendricks".to_string());
        assert_eq!(user_perm.object_type, "user");
        assert_eq!(user_perm.id, "hendricks");

        let group_perm = PermissionDescriptor::group("piedpiper".to_string());
        assert_eq!(group_perm.object_type, "group");
        assert_eq!(group_perm.id, "piedpiper");
    }

    #[test]
    fn test_grant_permission_request() {
        let permissions = vec![
            PermissionDescriptor::user("gilfoyle".to_string()),
            PermissionDescriptor::user("dinesh".to_string()),
            PermissionDescriptor::group("engineers".to_string()),
        ];

        let request = GrantPermissionRequest { data: permissions };
        assert_eq!(request.data.len(), 3);
        assert_eq!(request.data[0].id, "gilfoyle");
        assert_eq!(request.data[1].id, "dinesh");
        assert_eq!(request.data[2].object_type, "group");
    }

    #[test]
    fn test_permission_check_response() {
        let response = GraphPermissionCheckResponse { data: true };
        assert_eq!(response.data, true);

        let response_false = GraphPermissionCheckResponse { data: false };
        assert_eq!(response_false.data, false);
    }
}
