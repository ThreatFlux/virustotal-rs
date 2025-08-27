//! Collections client implementation

use super::enums::{CollectionOrder, ExportFormat};
use super::requests::{CollectionItemsRequest, CreateCollectionRequest, UpdateCollectionRequest};
use super::types::Collection;
use crate::comments::{Comment, CommentIterator};
use crate::objects::{Collection as ObjectCollection, CollectionIterator};
use crate::{Client, Result};
use serde::Serialize;

/// Client for Collections operations
pub struct CollectionsClient<'a> {
    pub(crate) client: &'a Client,
}

impl<'a> CollectionsClient<'a> {
    pub fn new(client: &'a Client) -> Self {
        Self { client }
    }

    /// Create a new collection
    pub async fn create(&self, request: &CreateCollectionRequest) -> Result<Collection> {
        self.client.post("collections", request).await
    }

    /// Get a collection by ID
    pub async fn get(&self, collection_id: &str) -> Result<Collection> {
        let url = format!("collections/{}", collection_id);
        self.client.get(&url).await
    }

    /// Update a collection
    pub async fn update(
        &self,
        collection_id: &str,
        request: &UpdateCollectionRequest,
    ) -> Result<Collection> {
        let url = format!("collections/{}", collection_id);
        self.client.patch(&url, request).await
    }

    /// Delete a collection
    pub async fn delete(&self, collection_id: &str) -> Result<()> {
        let url = format!("collections/{}", collection_id);
        self.client.delete(&url).await
    }

    /// List collections (requires special privileges)
    pub async fn list(
        &self,
        filter: Option<&str>,
        order: Option<CollectionOrder>,
        limit: Option<u32>,
        cursor: Option<&str>,
    ) -> Result<ObjectCollection<Collection>> {
        let url = self.build_collections_url(filter, order, limit, cursor);
        self.client.get(&url).await
    }

    /// List collections with pagination support
    pub fn list_iterator(
        &self,
        filter: Option<&str>,
        order: Option<CollectionOrder>,
    ) -> CollectionIterator<'_, Collection> {
        let url = self.build_collections_base_url(filter, order);
        CollectionIterator::new(self.client, url)
    }

    /// Get comments on a collection
    pub async fn get_comments(&self, collection_id: &str) -> Result<ObjectCollection<Comment>> {
        let url = format!("collections/{}/comments", collection_id);
        self.client.get(&url).await
    }

    /// Get comments on a collection with pagination
    pub fn get_comments_iterator(&self, collection_id: &str) -> CommentIterator<'_> {
        let url = format!("collections/{}/comments", collection_id);
        CommentIterator::new(self.client, url)
    }

    /// Add a comment to a collection
    pub async fn add_comment(&self, collection_id: &str, text: &str) -> Result<Comment> {
        let url = format!("collections/{}/comments", collection_id);
        let request = serde_json::json!({
            "data": {
                "type": "comment",
                "attributes": {
                    "text": text
                }
            }
        });
        self.client.post(&url, &request).await
    }

    /// Get objects related to a collection
    pub async fn get_relationship<T>(
        &self,
        collection_id: &str,
        relationship: &str,
    ) -> Result<ObjectCollection<T>>
    where
        T: serde::de::DeserializeOwned,
    {
        let url = format!("collections/{}/{}", collection_id, relationship);
        self.client.get(&url).await
    }

    /// Get object descriptors related to a collection
    pub async fn get_relationship_descriptors<T>(
        &self,
        collection_id: &str,
        relationship: &str,
    ) -> Result<ObjectCollection<T>>
    where
        T: serde::de::DeserializeOwned,
    {
        let url = format!(
            "collections/{}/relationships/{}",
            collection_id, relationship
        );
        self.client.get(&url).await
    }

    /// Add items to a collection relationship (domains, urls, `ip_addresses`, or files)
    pub async fn add_items<T>(
        &self,
        collection_id: &str,
        relationship: &str,
        items: &CollectionItemsRequest<T>,
    ) -> Result<()>
    where
        T: Serialize,
    {
        let url = format!("collections/{}/{}", collection_id, relationship);
        self.client.post(&url, items).await
    }

    /// Remove items from a collection relationship
    pub async fn remove_items<T>(
        &self,
        collection_id: &str,
        relationship: &str,
        items: &CollectionItemsRequest<T>,
    ) -> Result<()>
    where
        T: Serialize,
    {
        let url = format!("collections/{}/{}", collection_id, relationship);
        self.client.delete_with_body(&url, items).await
    }

    /// Export IOCs from a collection (requires special privileges)
    pub async fn export(&self, collection_id: &str, format: ExportFormat) -> Result<Vec<u8>> {
        let url = format!(
            "collections/{}/download/{}",
            collection_id,
            format.to_string()
        );
        self.client.get_bytes(&url).await
    }

    /// Export IOCs from a collection relationship
    pub async fn export_relationship(
        &self,
        collection_id: &str,
        relationship: &str,
        format: ExportFormat,
    ) -> Result<Vec<u8>> {
        let url = format!(
            "collections/{}/{}/download/{}",
            collection_id,
            relationship,
            format.to_string()
        );
        self.client.get_bytes(&url).await
    }

    /// Export aggregations from a collection
    pub async fn export_aggregations(
        &self,
        collection_id: &str,
        format: ExportFormat,
    ) -> Result<Vec<u8>> {
        let url = format!(
            "collections/{}/aggregations/download/{}",
            collection_id,
            format.to_string()
        );
        self.client.get_bytes(&url).await
    }

    /// Search IOCs inside a collection (requires special privileges)
    pub async fn search<T>(
        &self,
        collection_id: &str,
        query: &str,
        order: Option<&str>,
        limit: Option<u32>,
        cursor: Option<&str>,
    ) -> Result<ObjectCollection<T>>
    where
        T: serde::de::DeserializeOwned,
    {
        let url = self.build_search_url(collection_id, query, order, limit, cursor);
        self.client.get(&url).await
    }

    // Private helper methods for URL building
    fn build_collections_url(
        &self,
        filter: Option<&str>,
        order: Option<CollectionOrder>,
        limit: Option<u32>,
        cursor: Option<&str>,
    ) -> String {
        let mut url = self.build_collections_base_url(filter, order);

        if let Some(l) = limit {
            url.push_str(&format!("&limit={}", l.min(40))); // Max 40
        }

        if let Some(c) = cursor {
            url.push_str(&format!("&cursor={}", c));
        }

        url
    }

    fn build_collections_base_url(
        &self,
        filter: Option<&str>,
        order: Option<CollectionOrder>,
    ) -> String {
        let mut url = String::from("collections?");

        if let Some(f) = filter {
            url.push_str(&format!("filter={}&", urlencoding::encode(f)));
        }

        if let Some(o) = order {
            url.push_str(&format!("order={}&", o.to_string()));
        }

        // Remove trailing '&' or '?'
        url.pop();
        url
    }

    fn build_search_url(
        &self,
        collection_id: &str,
        query: &str,
        order: Option<&str>,
        limit: Option<u32>,
        cursor: Option<&str>,
    ) -> String {
        let mut url = format!(
            "collections/{}/search?query={}",
            collection_id,
            urlencoding::encode(query)
        );

        if let Some(o) = order {
            url.push_str(&format!("&order={}", o));
        }

        if let Some(l) = limit {
            url.push_str(&format!("&limit={}", l.min(40))); // Max 40
        }

        if let Some(c) = cursor {
            url.push_str(&format!("&cursor={}", c));
        }

        url
    }
}

impl Client {
    /// Get the Collections client for collection operations
    pub fn collections(&self) -> CollectionsClient<'_> {
        CollectionsClient::new(self)
    }
}
