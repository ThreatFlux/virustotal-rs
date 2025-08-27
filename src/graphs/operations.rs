use super::types::*;
use crate::comments::Comment;
use crate::objects::{Collection, CollectionIterator};
use crate::{Client, Result};

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
    /// - owner:`<username>`
    /// - tag:`<tag>`
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
