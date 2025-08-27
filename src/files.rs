use crate::comments::CommentIterator;
use crate::common::{AnalysisResult, AnalysisStats, VoteStats};
use crate::objects::{Collection, CollectionIterator, Object, ObjectOperations, ObjectResponse};
use crate::{Client, Result};
use reqwest::multipart;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;
use tokio::fs;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct File {
    #[serde(flatten)]
    pub object: Object<FileAttributes>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct FileAttributes {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub type_description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub type_tag: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub type_extension: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vhash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tlsh: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trid: Option<Vec<TridInfo>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub creation_date: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub names: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_modification_date: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub size: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub meaningful_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub downloadable: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sha1: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub md5: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ssdeep: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub magic: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_analysis_date: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_analysis_stats: Option<AnalysisStats>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_analysis_results: Option<HashMap<String, AnalysisResult>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_submission_date: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub first_submission_date: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub times_submitted: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unique_sources: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reputation: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub total_votes: Option<VoteStats>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tags: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub crowdsourced_ids_stats: Option<HashMap<String, u32>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub crowdsourced_ids_results: Option<Vec<CrowdsourcedId>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sandbox_verdicts: Option<HashMap<String, SandboxVerdict>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sigma_analysis_summary: Option<SigmaAnalysis>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub popular_threat_classification: Option<ThreatClassification>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub crowdsourced_yara_results: Option<Vec<YaraResult>>,
    #[serde(flatten)]
    pub additional_attributes: HashMap<String, serde_json::Value>,
}

// File-specific structs that aren't shared
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TridInfo {
    pub file_type: String,
    pub probability: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrowdsourcedId {
    pub alert_severity: Option<String>,
    pub rule_name: String,
    pub rule_category: Option<String>,
    pub alert_context: Option<Vec<AlertContext>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertContext {
    pub url: Option<String>,
    pub hostname: Option<String>,
    pub ip: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxVerdict {
    pub category: String,
    pub sandbox_name: String,
    pub malware_classification: Option<Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SigmaAnalysis {
    pub critical: Option<u32>,
    pub high: Option<u32>,
    pub medium: Option<u32>,
    pub low: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatClassification {
    pub suggested_threat_label: String,
    pub popular_threat_category: Option<Vec<ThreatCategory>>,
    pub popular_threat_name: Option<Vec<ThreatName>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatCategory {
    pub count: u32,
    pub value: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatName {
    pub count: u32,
    pub value: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct YaraResult {
    pub rule_name: String,
    pub ruleset_name: String,
    pub ruleset_id: String,
    pub source: String,
    pub author: Option<String>,
    pub description: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UploadUrlResponse {
    pub data: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DownloadUrlResponse {
    pub data: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileBehaviorSummary {
    pub calls_highlighted: Option<Vec<String>>,
    pub files_opened: Option<Vec<String>>,
    pub files_written: Option<Vec<String>>,
    pub files_deleted: Option<Vec<String>>,
    pub files_dropped: Option<Vec<String>>,
    pub files_copied: Option<Vec<String>>,
    pub files_moved: Option<Vec<String>>,
    pub files_attribute_changed: Option<Vec<String>>,
    pub modules_loaded: Option<Vec<String>>,
    pub mutexes_created: Option<Vec<String>>,
    pub mutexes_opened: Option<Vec<String>>,
    pub processes_created: Option<Vec<String>>,
    pub processes_terminated: Option<Vec<String>>,
    pub processes_injected: Option<Vec<String>>,
    pub processes_tree: Option<Vec<ProcessTreeNode>>,
    pub registry_keys_created: Option<Vec<String>>,
    pub registry_keys_deleted: Option<Vec<String>>,
    pub registry_keys_opened: Option<Vec<String>>,
    pub registry_keys_set: Option<Vec<String>>,
    pub services_created: Option<Vec<String>>,
    pub services_started: Option<Vec<String>>,
    pub services_stopped: Option<Vec<String>>,
    pub services_deleted: Option<Vec<String>>,
    pub dns_lookups: Option<Vec<DnsLookup>>,
    pub ip_traffic: Option<Vec<IpTraffic>>,
    pub http_conversations: Option<Vec<HttpConversation>>,
    pub ja3_digests: Option<Vec<Ja3Digest>>,
    pub tags: Option<Vec<String>>,
    pub text_highlighted: Option<Vec<String>>,
    pub mitre_attack_techniques: Option<Vec<MitreAttackTechnique>>,
    pub command_executions: Option<Vec<String>>,
    pub sigma_analysis_results: Option<Vec<SigmaAnalysisResult>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessTreeNode {
    pub name: Option<String>,
    pub process_id: Option<String>,
    pub parent_process_id: Option<String>,
    pub children: Option<Vec<ProcessTreeNode>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsLookup {
    pub hostname: Option<String>,
    pub resolved_ips: Option<Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpTraffic {
    pub destination_ip: Option<String>,
    pub destination_port: Option<u16>,
    pub protocol: Option<String>,
    pub bytes_sent: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpConversation {
    pub url: Option<String>,
    pub request_method: Option<String>,
    pub response_status: Option<u16>,
    pub response_body_size: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Ja3Digest {
    pub digest: Option<String>,
    pub description: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MitreAttackTechnique {
    pub id: Option<String>,
    pub name: Option<String>,
    pub description: Option<String>,
    pub severity: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SigmaAnalysisResult {
    pub rule_title: Option<String>,
    pub rule_source: Option<String>,
    pub rule_level: Option<String>,
    pub rule_description: Option<String>,
    pub match_context: Option<HashMap<String, serde_json::Value>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileBehaviorSummaryResponse {
    pub data: FileBehaviorSummary,
}

// MITRE ATT&CK structures
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MitreTrees {
    pub data: HashMap<String, SandboxMitreData>,
    pub links: Option<MitreLinks>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MitreLinks {
    #[serde(rename = "self")]
    pub self_link: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxMitreData {
    pub tactics: Vec<MitreTactic>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MitreTactic {
    pub id: String,
    pub name: String,
    pub description: String,
    pub link: String,
    pub techniques: Vec<MitreTechnique>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MitreTechnique {
    pub id: String,
    pub name: String,
    pub description: String,
    pub link: String,
    pub signatures: Vec<MitreSignature>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MitreSignature {
    pub severity: MitreSeverity,
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum MitreSeverity {
    High,
    Medium,
    Low,
    Info,
    Unknown,
}

// File behavior report structures
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileBehavior {
    pub data: FileBehaviorData,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileBehaviorData {
    pub id: String,
    #[serde(rename = "type")]
    pub object_type: String,
    pub attributes: FileBehaviorAttributes,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileBehaviorAttributes {
    pub analysis_date: Option<i64>,
    pub behash: Option<String>,
    pub command_executions: Option<Vec<String>>,
    pub dns_lookups: Option<Vec<DnsLookup>>,
    pub files_copied: Option<Vec<String>>,
    pub files_deleted: Option<Vec<String>>,
    pub files_dropped: Option<Vec<FileDrop>>,
    pub files_opened: Option<Vec<String>>,
    pub files_written: Option<Vec<String>>,
    pub has_html_report: Option<bool>,
    pub has_pcap: Option<bool>,
    pub http_conversations: Option<Vec<HttpConversation>>,
    pub ip_traffic: Option<Vec<IpTraffic>>,
    pub ja3_digests: Option<Vec<Ja3Digest>>,
    pub last_modification_date: Option<i64>,
    pub mitre_attack_techniques: Option<Vec<MitreAttackTechnique>>,
    pub modules_loaded: Option<Vec<String>>,
    pub mutexes_created: Option<Vec<String>>,
    pub mutexes_opened: Option<Vec<String>>,
    pub processes_created: Option<Vec<String>>,
    pub processes_injected: Option<Vec<String>>,
    pub processes_killed: Option<Vec<String>>,
    pub processes_terminated: Option<Vec<String>>,
    pub processes_tree: Option<Vec<ProcessTreeNode>>,
    pub registry_keys_deleted: Option<Vec<String>>,
    pub registry_keys_opened: Option<Vec<String>>,
    pub registry_keys_set: Option<Vec<RegistryKeySet>>,
    pub sandbox_name: Option<String>,
    pub services_created: Option<Vec<String>>,
    pub services_deleted: Option<Vec<String>>,
    pub services_opened: Option<Vec<String>>,
    pub services_started: Option<Vec<String>>,
    pub services_stopped: Option<Vec<String>>,
    pub sigma_analysis_results: Option<Vec<SigmaAnalysisResult>>,
    pub tags: Option<Vec<String>>,
    pub text_decoded: Option<Vec<String>>,
    pub text_highlighted: Option<Vec<String>>,
    pub verdicts: Option<Vec<String>>,
    pub verdicts_labels: Option<Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileDrop {
    pub path: Option<String>,
    pub sha256: Option<String>,
    #[serde(rename = "type")]
    pub file_type: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistryKeySet {
    pub key: Option<String>,
    pub value: Option<String>,
}

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
        let part = multipart::Part::bytes(bytes).file_name(filename.to_string());
        let mut form = multipart::Form::new().part("file", part);

        if let Some(pwd) = password {
            form = form.text("password", pwd.to_string());
        }

        let url = format!("{}/files", self.client.base_url());
        let request = self
            .client
            .http_client()
            .post(&url)
            .header("x-apikey", self.client.api_key())
            .multipart(form);

        let response = request.send().await.map_err(crate::Error::Http)?;

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
        let part = multipart::Part::bytes(bytes).file_name(filename.to_string());
        let mut form = multipart::Form::new().part("file", part);

        if let Some(pwd) = password {
            form = form.text("password", pwd.to_string());
        }

        let request = self
            .client
            .http_client()
            .post(upload_url)
            .header("x-apikey", self.client.api_key())
            .multipart(form);

        let response = request.send().await.map_err(crate::Error::Http)?;

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
        let url = File::relationship_objects_url(file_id, relationship);
        CollectionIterator::new(self.client, url)
    }

    // File-specific convenience methods
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_file_collection_name() {
        assert_eq!(File::collection_name(), "files");
    }

    #[test]
    fn test_file_url() {
        assert_eq!(
            File::object_url("275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"),
            "files/275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
        );
    }

    #[test]
    fn test_file_relationships_url() {
        assert_eq!(
            File::relationships_url("hash123", "bundled_files"),
            "files/hash123/relationships/bundled_files"
        );
    }
}
