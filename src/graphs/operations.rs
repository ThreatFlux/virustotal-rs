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

    /// Build a URL with query parameters
    fn build_url(
        base: &str,
        filter: Option<&str>,
        order: Option<&str>,
        limit: Option<u32>,
        cursor: Option<&str>,
    ) -> String {
        let mut url = String::from(base);
        url.push('?');

        if let Some(f) = filter {
            url.push_str(&format!("filter={}&", urlencoding::encode(f)));
        }

        if let Some(o) = order {
            url.push_str(&format!("order={}&", urlencoding::encode(o)));
        }

        if let Some(l) = limit {
            url.push_str(&format!("limit={}&", l));
        }

        if let Some(c) = cursor {
            url.push_str(&format!("cursor={}&", urlencoding::encode(c)));
        }

        // Remove trailing '&' or '?'
        url.pop();
        url
    }

    /// Build a URL for a specific graph with pagination
    fn build_graph_url(
        graph_id: &str,
        suffix: &str,
        limit: Option<u32>,
        cursor: Option<&str>,
    ) -> String {
        let base = format!("graphs/{}/{}", urlencoding::encode(graph_id), suffix);
        Self::build_url(&base, None, None, limit, cursor)
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
        let order_str = order.map(|o| o.to_string());
        let url = Self::build_url("graphs", filter, order_str, limit, cursor);
        self.client.get(&url).await
    }

    /// List graphs with pagination support
    pub fn list_graphs_iterator(
        &self,
        filter: Option<&str>,
        order: Option<GraphOrder>,
    ) -> CollectionIterator<'_, Graph> {
        let order_str = order.map(|o| o.to_string());
        let url = Self::build_url("graphs", filter, order_str, None, None);
        CollectionIterator::new(self.client, url)
    }

    /// Get a graph by ID
    pub async fn get_graph(&self, graph_id: &str) -> Result<Graph> {
        let url = format!("graphs/{}", urlencoding::encode(graph_id));
        self.client.get(&url).await
    }

    /// Create a new graph
    pub async fn create_graph(&self, request: &CreateGraphRequest) -> Result<Graph> {
        self.client.post("graphs", request).await
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
        let url = Self::build_graph_url(graph_id, "comments", limit, cursor);
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
        let url = Self::build_graph_url(graph_id, relationship, limit, cursor);
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
        let suffix = format!("relationships/{}", relationship);
        let url = Self::build_graph_url(graph_id, &suffix, limit, cursor);
        self.client.get(&url).await
    }

    /// Get a relationship iterator for pagination
    pub fn get_graph_relationship_iterator<T>(
        &self,
        graph_id: &str,
        relationship: &str,
    ) -> CollectionIterator<'_, T>
    where
        T: serde::de::DeserializeOwned + Clone,
    {
        let url = format!("graphs/{}/{}", urlencoding::encode(graph_id), relationship);
        CollectionIterator::new(self.client, url)
    }

    /// Helper to create permission request  
    fn create_permission_request(user_ids: &[String]) -> GrantPermissionRequest {
        GrantPermissionRequest {
            data: user_ids
                .iter()
                .map(|id| PermissionDescriptor {
                    object_type: "user".to_string(),
                    id: id.clone(),
                })
                .collect(),
        }
    }

    /// Add editors to a graph
    pub async fn add_graph_editors(&self, graph_id: &str, user_ids: &[String]) -> Result<()> {
        let url = format!("graphs/{}/editors", urlencoding::encode(graph_id));
        let request = Self::create_permission_request(user_ids);
        self.client.post(&url, &request).await
    }

    /// Remove editors from a graph
    pub async fn remove_graph_editors(&self, graph_id: &str, user_ids: &[String]) -> Result<()> {
        let url = format!("graphs/{}/editors", urlencoding::encode(graph_id));
        let request = Self::create_permission_request(user_ids);
        self.client.delete_with_body(&url, &request).await
    }

    /// Add viewers to a graph
    pub async fn add_graph_viewers(&self, graph_id: &str, user_ids: &[String]) -> Result<()> {
        let url = format!("graphs/{}/viewers", urlencoding::encode(graph_id));
        let request = Self::create_permission_request(user_ids);
        self.client.post(&url, &request).await
    }

    /// Remove viewers from a graph
    pub async fn remove_graph_viewers(&self, graph_id: &str, user_ids: &[String]) -> Result<()> {
        let url = format!("graphs/{}/viewers", urlencoding::encode(graph_id));
        let request = Self::create_permission_request(user_ids);
        self.client.delete_with_body(&url, &request).await
    }
}
