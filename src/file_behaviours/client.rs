use super::types::{FileBehaviour, FileBehaviourAttributes};
use crate::comments::CommentIterator;
use crate::objects::{Collection, CollectionIterator, ObjectOperations, ObjectResponse};
use crate::{Client, Result};
use serde::Deserialize;

pub struct FileBehaviourClient<'a> {
    pub(crate) client: &'a Client,
}

impl<'a> FileBehaviourClient<'a> {
    pub fn new(client: &'a Client) -> Self {
        Self { client }
    }

    /// Get a file behaviour report by sandbox ID
    pub async fn get(&self, sandbox_id: &str) -> Result<FileBehaviour> {
        let url = FileBehaviour::object_url(sandbox_id);
        let response: ObjectResponse<FileBehaviourAttributes> = self.client.get(&url).await?;
        Ok(FileBehaviour {
            object: response.data,
        })
    }

    /// Get objects related to a behaviour report
    pub async fn get_relationship<T>(
        &self,
        sandbox_id: &str,
        relationship: &str,
    ) -> Result<Collection<T>>
    where
        T: for<'de> Deserialize<'de>,
    {
        let url = FileBehaviour::relationship_objects_url(sandbox_id, relationship);
        self.client.get(&url).await
    }

    /// Get object descriptors related to a behaviour report
    pub async fn get_relationship_descriptors(
        &self,
        sandbox_id: &str,
        relationship: &str,
    ) -> Result<Collection<serde_json::Value>> {
        let url = FileBehaviour::relationships_url(sandbox_id, relationship);
        self.client.get(&url).await
    }

    /// Get relationship iterator for paginated results
    pub fn get_relationship_iterator<T>(
        &self,
        sandbox_id: &str,
        relationship: &str,
    ) -> CollectionIterator<'_, T>
    where
        T: for<'de> Deserialize<'de> + Clone,
    {
        let url = FileBehaviour::relationship_objects_url(sandbox_id, relationship);
        CollectionIterator::new(self.client, url)
    }

    /// Get a detailed HTML behaviour report
    pub async fn get_html_report(&self, sandbox_id: &str) -> Result<String> {
        let url = format!("{}/{}/html", FileBehaviour::collection_name(), sandbox_id);
        self.client.get_raw(&url).await
    }

    /// Get the EVTX file generated during a file's behavior analysis
    /// Note: This endpoint requires special privileges
    pub async fn get_evtx(&self, sandbox_id: &str) -> Result<Vec<u8>> {
        let url = format!("{}/{}/evtx", FileBehaviour::collection_name(), sandbox_id);
        self.client.get_bytes(&url).await
    }

    /// Get the PCAP file generated during a file's behavior analysis
    /// Note: This endpoint requires special privileges
    pub async fn get_pcap(&self, sandbox_id: &str) -> Result<Vec<u8>> {
        let url = format!("{}/{}/pcap", FileBehaviour::collection_name(), sandbox_id);
        self.client.get_bytes(&url).await
    }

    /// Get the memdump file generated during a file's behavior analysis
    /// Note: This endpoint requires special privileges
    pub async fn get_memdump(&self, sandbox_id: &str) -> Result<Vec<u8>> {
        let url = format!(
            "{}/{}/memdump",
            FileBehaviour::collection_name(),
            sandbox_id
        );
        self.client.get_bytes(&url).await
    }

    /// Get comments for a file behaviour report
    pub async fn get_comments_iterator(&self, sandbox_id: &str) -> CommentIterator<'_> {
        let url = FileBehaviour::relationship_objects_url(sandbox_id, "comments");
        CommentIterator::new(self.client, url)
    }

    // Convenience methods for common relationships
    pub async fn get_contacted_domains(
        &self,
        sandbox_id: &str,
    ) -> Result<Collection<serde_json::Value>> {
        self.get_relationship(sandbox_id, "contacted_domains").await
    }

    pub async fn get_contacted_ips(
        &self,
        sandbox_id: &str,
    ) -> Result<Collection<serde_json::Value>> {
        self.get_relationship(sandbox_id, "contacted_ips").await
    }

    pub async fn get_dropped_files(
        &self,
        sandbox_id: &str,
    ) -> Result<Collection<serde_json::Value>> {
        self.get_relationship(sandbox_id, "dropped_files").await
    }

    pub async fn get_contacted_urls(
        &self,
        sandbox_id: &str,
    ) -> Result<Collection<serde_json::Value>> {
        self.get_relationship(sandbox_id, "contacted_urls").await
    }

    pub async fn get_attack_techniques(
        &self,
        sandbox_id: &str,
    ) -> Result<Collection<serde_json::Value>> {
        self.get_relationship(sandbox_id, "attack_techniques").await
    }

    pub async fn get_sigma_analysis(
        &self,
        sandbox_id: &str,
    ) -> Result<Collection<serde_json::Value>> {
        self.get_relationship(sandbox_id, "sigma_analysis").await
    }
}

impl Client {
    pub fn file_behaviours(&self) -> FileBehaviourClient<'_> {
        FileBehaviourClient::new(self)
    }
}
