//! File client implementation with upload and download functionality

use super::behavior::{FileBehavior, FileBehaviorSummaryResponse};
use super::mitre::MitreTrees;
use super::types::{DownloadUrlResponse, File, FileAttributes, UploadUrlResponse};
use crate::comments::CommentIterator;
use crate::objects::{Collection, CollectionIterator, ObjectOperations, ObjectResponse};
use crate::{Client, Result};
use reqwest::multipart;
use serde::Deserialize;
use std::path::Path;
use tokio::fs;

impl ObjectOperations for File {
    type Attributes = FileAttributes;

    fn collection_name() -> &'static str {
        "files"
    }
}

pub struct FileClient<'a> {
    pub(crate) client: &'a Client,
}

impl<'a> FileClient<'a> {
    pub async fn get(&self, file_id: &str) -> Result<File> {
        let url = File::object_url(file_id);
        let response: ObjectResponse<FileAttributes> = self.client.get(&url).await?;
        Ok(File {
            object: response.data,
        })
    }

    pub async fn get_with_relationships(
        &self,
        file_id: &str,
        relationships: &[&str],
    ) -> Result<File> {
        let url = format!(
            "{}?relationships={}",
            File::object_url(file_id),
            relationships.join(",")
        );
        let response: ObjectResponse<FileAttributes> = self.client.get(&url).await?;
        Ok(File {
            object: response.data,
        })
    }

    // File-specific upload methods
    pub async fn upload(&self, file_path: impl AsRef<Path>) -> Result<crate::AnalysisResponse> {
        self.upload_with_password(file_path, None).await
    }

    pub async fn upload_with_password(
        &self,
        file_path: impl AsRef<Path>,
        password: Option<&str>,
    ) -> Result<crate::AnalysisResponse> {
        let file_path = file_path.as_ref();
        let file_bytes = fs::read(file_path)
            .await
            .map_err(|e| crate::Error::io_error(format!("Failed to read file: {}", e)))?;

        const MAX_DIRECT_UPLOAD_SIZE: usize = 32 * 1024 * 1024; // 32MB

        if file_bytes.len() > MAX_DIRECT_UPLOAD_SIZE {
            let upload_url = self.get_upload_url().await?;
            self.upload_to_url(&upload_url, file_bytes, file_path, password)
                .await
        } else {
            self.upload_direct(file_bytes, file_path, password).await
        }
    }

    pub async fn upload_bytes(
        &self,
        bytes: Vec<u8>,
        filename: &str,
    ) -> Result<crate::AnalysisResponse> {
        self.upload_bytes_with_password(bytes, filename, None).await
    }

    pub async fn upload_bytes_with_password(
        &self,
        bytes: Vec<u8>,
        filename: &str,
        password: Option<&str>,
    ) -> Result<crate::AnalysisResponse> {
        const MAX_DIRECT_UPLOAD_SIZE: usize = 32 * 1024 * 1024; // 32MB

        if bytes.len() > MAX_DIRECT_UPLOAD_SIZE {
            let upload_url = self.get_upload_url().await?;
            self.upload_bytes_to_url(&upload_url, bytes, filename, password)
                .await
        } else {
            self.upload_direct_bytes(bytes, filename, password).await
        }
    }

    async fn upload_direct(
        &self,
        file_bytes: Vec<u8>,
        file_path: &Path,
        password: Option<&str>,
    ) -> Result<crate::AnalysisResponse> {
        let filename = file_path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("unknown");
        self.upload_direct_bytes(file_bytes, filename, password)
            .await
    }

    async fn upload_direct_bytes(
        &self,
        bytes: Vec<u8>,
        filename: &str,
        password: Option<&str>,
    ) -> Result<crate::AnalysisResponse> {
        let form = self.create_multipart_form(bytes, filename, password);
        self.post_multipart_form("files", form).await
    }

    async fn upload_to_url(
        &self,
        upload_url: &str,
        file_bytes: Vec<u8>,
        file_path: &Path,
        password: Option<&str>,
    ) -> Result<crate::AnalysisResponse> {
        let filename = file_path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("unknown");
        self.upload_bytes_to_url(upload_url, file_bytes, filename, password)
            .await
    }

    async fn upload_bytes_to_url(
        &self,
        upload_url: &str,
        bytes: Vec<u8>,
        filename: &str,
        password: Option<&str>,
    ) -> Result<crate::AnalysisResponse> {
        let form = self.create_multipart_form(bytes, filename, password);
        let request = self
            .client
            .http_client()
            .post(upload_url)
            .header("x-apikey", self.client.api_key())
            .multipart(form);

        let response = request.send().await.map_err(crate::Error::Http)?;
        self.handle_upload_response(response).await
    }

    async fn post_multipart_form(
        &self,
        endpoint: &str,
        form: multipart::Form,
    ) -> Result<crate::AnalysisResponse> {
        let url = format!("{}/{}", self.client.base_url(), endpoint);
        let request = self
            .client
            .http_client()
            .post(&url)
            .header("x-apikey", self.client.api_key())
            .multipart(form);

        let response = request.send().await.map_err(crate::Error::Http)?;
        self.handle_upload_response(response).await
    }

    pub async fn get_upload_url(&self) -> Result<String> {
        let response: UploadUrlResponse = self.client.get("files/upload_url").await?;
        Ok(response.data)
    }

    pub async fn get_download_url(&self, file_id: &str) -> Result<String> {
        let url = format!("{}/download_url", File::object_url(file_id));
        let response: DownloadUrlResponse = self.client.get(&url).await?;
        Ok(response.data)
    }

    pub async fn download(&self, file_id: &str) -> Result<Vec<u8>> {
        let download_url = self.get_download_url(file_id).await?;

        let response = self
            .client
            .http_client()
            .get(&download_url)
            .send()
            .await
            .map_err(crate::Error::Http)?;

        if response.status().is_success() {
            response
                .bytes()
                .await
                .map(|b| b.to_vec())
                .map_err(crate::Error::Http)
        } else {
            let status = response.status();
            let text = response.text().await.map_err(crate::Error::Http)?;
            Err(crate::Error::unknown(format!(
                "Failed to download file: HTTP {} - {}",
                status,
                text.chars().take(200).collect::<String>()
            )))
        }
    }

    pub async fn get_behavior_summary(&self, file_id: &str) -> Result<FileBehaviorSummaryResponse> {
        let url = format!("{}/behaviour_summary", File::object_url(file_id));
        self.client.get(&url).await
    }

    pub async fn get_mitre_attack_techniques(&self, file_id: &str) -> Result<MitreTrees> {
        let url = format!("{}/behaviour_mitre_trees", File::object_url(file_id));
        self.client.get(&url).await
    }

    pub async fn get_behavior_report(&self, sandbox_id: &str) -> Result<FileBehavior> {
        let url = format!("file_behaviours/{}", sandbox_id);
        self.client.get(&url).await
    }

    /// Helper method to create multipart form with file and optional password
    fn create_multipart_form(
        &self,
        bytes: Vec<u8>,
        filename: &str,
        password: Option<&str>,
    ) -> multipart::Form {
        let part = multipart::Part::bytes(bytes).file_name(filename.to_string());
        let mut form = multipart::Form::new().part("file", part);

        if let Some(pwd) = password {
            form = form.text("password", pwd.to_string());
        }

        form
    }

    /// Helper method to handle upload response with common error handling logic
    async fn handle_upload_response(
        &self,
        response: reqwest::Response,
    ) -> Result<crate::AnalysisResponse> {
        if response.status().is_success() {
            let text = response.text().await.map_err(crate::Error::Http)?;
            serde_json::from_str(&text).map_err(crate::Error::Json)
        } else {
            let status = response.status();
            let text = response.text().await.map_err(crate::Error::Http)?;

            if let Ok(error_response) =
                serde_json::from_str::<crate::error::ApiErrorResponse>(&text)
            {
                Err(crate::Error::from_response(status, error_response.error))
            } else {
                Err(crate::Error::unknown(format!(
                    "HTTP {}: {}",
                    status,
                    text.chars().take(200).collect::<String>()
                )))
            }
        }
    }

    pub async fn get_comments_iterator(&self, file_id: &str) -> CommentIterator<'_> {
        let url = File::relationship_objects_url(file_id, "comments");
        CommentIterator::new(self.client, url)
    }

    pub fn get_relationship_iterator<T>(
        &self,
        file_id: &str,
        relationship: &str,
    ) -> CollectionIterator<'_, T>
    where
        T: for<'de> Deserialize<'de> + Clone,
    {
        use crate::iterator_utils::RelationshipIteratorBuilder;
        RelationshipIteratorBuilder::create::<File, T>(self.client, file_id, relationship)
    }
}

/// File-specific convenience methods for relationships
impl<'a> FileClient<'a> {
    pub async fn get_behaviours(&self, file_id: &str) -> Result<Collection<serde_json::Value>> {
        self.get_relationship(file_id, "behaviours").await
    }

    pub async fn get_bundled_files(&self, file_id: &str) -> Result<Collection<serde_json::Value>> {
        self.get_relationship(file_id, "bundled_files").await
    }

    pub async fn get_carbonblack_children(
        &self,
        file_id: &str,
    ) -> Result<Collection<serde_json::Value>> {
        self.get_relationship(file_id, "carbonblack_children").await
    }

    pub async fn get_carbonblack_parents(
        &self,
        file_id: &str,
    ) -> Result<Collection<serde_json::Value>> {
        self.get_relationship(file_id, "carbonblack_parents").await
    }

    pub async fn get_compressed_parents(
        &self,
        file_id: &str,
    ) -> Result<Collection<serde_json::Value>> {
        self.get_relationship(file_id, "compressed_parents").await
    }

    pub async fn get_contacted_domains(
        &self,
        file_id: &str,
    ) -> Result<Collection<serde_json::Value>> {
        self.get_relationship(file_id, "contacted_domains").await
    }

    pub async fn get_contacted_ips(&self, file_id: &str) -> Result<Collection<serde_json::Value>> {
        self.get_relationship(file_id, "contacted_ips").await
    }

    pub async fn get_contacted_urls(&self, file_id: &str) -> Result<Collection<serde_json::Value>> {
        self.get_relationship(file_id, "contacted_urls").await
    }

    pub async fn get_dropped_files(&self, file_id: &str) -> Result<Collection<serde_json::Value>> {
        self.get_relationship(file_id, "dropped_files").await
    }

    pub async fn get_execution_parents(
        &self,
        file_id: &str,
    ) -> Result<Collection<serde_json::Value>> {
        self.get_relationship(file_id, "execution_parents").await
    }

    pub async fn get_itw_urls(&self, file_id: &str) -> Result<Collection<serde_json::Value>> {
        self.get_relationship(file_id, "itw_urls").await
    }

    pub async fn get_overlay_parents(
        &self,
        file_id: &str,
    ) -> Result<Collection<serde_json::Value>> {
        self.get_relationship(file_id, "overlay_parents").await
    }

    pub async fn get_pcap_parents(&self, file_id: &str) -> Result<Collection<serde_json::Value>> {
        self.get_relationship(file_id, "pcap_parents").await
    }

    pub async fn get_pe_resource_parents(
        &self,
        file_id: &str,
    ) -> Result<Collection<serde_json::Value>> {
        self.get_relationship(file_id, "pe_resource_parents").await
    }

    pub async fn get_similar_files(&self, file_id: &str) -> Result<Collection<serde_json::Value>> {
        self.get_relationship(file_id, "similar_files").await
    }
}

// Apply the macro to generate common methods
crate::impl_common_client_methods!(FileClient<'a>, "files");

impl Client {
    pub fn files(&self) -> FileClient<'_> {
        FileClient::new(self)
    }
}
