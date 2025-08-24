use crate::comments::CommentIterator;
use crate::objects::{Collection, CollectionIterator, Object, ObjectOperations, ObjectResponse};
use crate::{Client, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileBehaviour {
    #[serde(flatten)]
    pub object: Object<FileBehaviourAttributes>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct FileBehaviourAttributes {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub analysis_date: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sandbox: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub command_executions: Option<Vec<CommandExecution>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub processes_tree: Option<Vec<ProcessTreeNode>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub processes_terminated: Option<Vec<TerminatedProcess>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub processes_created: Option<Vec<CreatedProcess>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub files_opened: Option<Vec<FileOperation>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub files_written: Option<Vec<FileOperation>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub files_deleted: Option<Vec<FileOperation>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub files_dropped: Option<Vec<DroppedFile>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub files_copied: Option<Vec<FileCopyOperation>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub files_moved: Option<Vec<FileMoveOperation>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub registry_keys_opened: Option<Vec<RegistryOperation>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub registry_keys_set: Option<Vec<RegistryOperation>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub registry_keys_deleted: Option<Vec<RegistryOperation>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ip_traffic: Option<Vec<IpTraffic>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dns_lookups: Option<Vec<DnsLookup>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub http_conversations: Option<Vec<HttpConversation>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ja3_digests: Option<Vec<Ja3Digest>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tls_conversations: Option<Vec<TlsConversation>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub modules_loaded: Option<Vec<ModuleOperation>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub services_opened: Option<Vec<ServiceOperation>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub services_created: Option<Vec<ServiceOperation>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub services_started: Option<Vec<ServiceOperation>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub services_stopped: Option<Vec<ServiceOperation>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub services_deleted: Option<Vec<ServiceOperation>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mutexes_opened: Option<Vec<MutexOperation>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mutexes_created: Option<Vec<MutexOperation>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sigma_analysis_summary: Option<SigmaAnalysisSummary>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mitre_attack_techniques: Option<Vec<MitreAttackTechnique>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub calls_highlighted: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verdicts: Option<HashMap<String, String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub has_html_report: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub has_evtx: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub has_pcap: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub has_memdump: Option<bool>,
    #[serde(flatten)]
    pub additional_attributes: HashMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommandExecution {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub command: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pid: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub time: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessTreeNode {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub process_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_process_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub children: Option<Vec<ProcessTreeNode>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub time: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TerminatedProcess {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub process_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pid: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub time: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreatedProcess {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub process_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pid: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub command_line: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub time: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileOperation {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pid: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub process_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub time: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DroppedFile {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub size: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pid: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub process_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub time: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileCopyOperation {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub destination: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pid: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub process_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub time: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileMoveOperation {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub destination: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pid: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub process_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub time: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistryOperation {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pid: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub process_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub time: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpTraffic {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub destination_ip: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub destination_port: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub protocol: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bytes_sent: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bytes_received: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pid: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub process_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub time: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsLookup {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hostname: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resolved_ips: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pid: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub process_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub time: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpConversation {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_method: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status_code: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub headers: Option<HashMap<String, String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_agent: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pid: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub process_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub time: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Ja3Digest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub digest: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pid: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub process_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub time: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsConversation {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub server_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ja3: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ja3s: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pid: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub process_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub time: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModuleOperation {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub module_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub module_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pid: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub process_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub time: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceOperation {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub service_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub service_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pid: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub process_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub time: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MutexOperation {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mutex_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pid: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub process_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub time: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SigmaAnalysisSummary {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub critical: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub high: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub medium: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub low: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub informational: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MitreAttackTechnique {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub severity: Option<String>,
}

impl ObjectOperations for FileBehaviour {
    type Attributes = FileBehaviourAttributes;

    fn collection_name() -> &'static str {
        "file_behaviours"
    }
}

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_file_behaviour_collection_name() {
        assert_eq!(FileBehaviour::collection_name(), "file_behaviours");
    }

    #[test]
    fn test_file_behaviour_url() {
        let sandbox_id =
            "5353e23f3653402339c93a8565307c6308ff378e03fcf23a4378f31c434030b0_`VirusTotal` Jujubox";
        assert_eq!(
            FileBehaviour::object_url(sandbox_id),
            format!("file_behaviours/{}", sandbox_id)
        );
    }

    #[test]
    fn test_file_behaviour_relationships_url() {
        let sandbox_id = "test_id";
        assert_eq!(
            FileBehaviour::relationships_url(sandbox_id, "contacted_domains"),
            "file_behaviours/test_id/relationships/contacted_domains"
        );
    }

    #[test]
    fn test_file_behaviour_relationship_objects_url() {
        let sandbox_id = "test_id";
        assert_eq!(
            FileBehaviour::relationship_objects_url(sandbox_id, "contacted_domains"),
            "file_behaviours/test_id/contacted_domains"
        );
    }

    #[test]
    fn test_command_execution_creation() {
        let command = CommandExecution {
            command: Some("cmd.exe /c echo test".to_string()),
            pid: Some(1234),
            time: Some("2024-01-01T00:00:00Z".to_string()),
        };

        assert_eq!(command.command.unwrap(), "cmd.exe /c echo test");
        assert_eq!(command.pid.unwrap(), 1234);
    }

    #[test]
    fn test_process_tree_node_creation() {
        let node = ProcessTreeNode {
            name: Some("explorer.exe".to_string()),
            process_id: Some("1000".to_string()),
            parent_process_id: Some("500".to_string()),
            children: Some(vec![]),
            time: Some("2024-01-01T00:00:00Z".to_string()),
        };

        assert_eq!(node.name.unwrap(), "explorer.exe");
        assert_eq!(node.process_id.unwrap(), "1000");
        assert_eq!(node.parent_process_id.unwrap(), "500");
    }

    #[test]
    fn test_dropped_file_creation() {
        let dropped = DroppedFile {
            file_path: Some("C:\\temp\\malware.exe".to_string()),
            sha256: Some("abc123".to_string()),
            size: Some(1024),
            pid: Some(1234),
            process_name: Some("malware.exe".to_string()),
            time: Some("2024-01-01T00:00:00Z".to_string()),
        };

        assert_eq!(dropped.file_path.unwrap(), "C:\\temp\\malware.exe");
        assert_eq!(dropped.sha256.unwrap(), "abc123");
        assert_eq!(dropped.size.unwrap(), 1024);
    }

    #[test]
    fn test_sigma_analysis_summary_creation() {
        let summary = SigmaAnalysisSummary {
            critical: Some(2),
            high: Some(5),
            medium: Some(10),
            low: Some(3),
            informational: Some(1),
        };

        assert_eq!(summary.critical.unwrap(), 2);
        assert_eq!(summary.high.unwrap(), 5);
        assert_eq!(summary.medium.unwrap(), 10);
        assert_eq!(summary.low.unwrap(), 3);
        assert_eq!(summary.informational.unwrap(), 1);
    }

    #[test]
    fn test_mitre_attack_technique_creation() {
        let technique = MitreAttackTechnique {
            id: Some("T1055".to_string()),
            name: Some("Process Injection".to_string()),
            description: Some("Adversaries may inject code into processes".to_string()),
            severity: Some("HIGH".to_string()),
        };

        assert_eq!(technique.id.unwrap(), "T1055");
        assert_eq!(technique.name.unwrap(), "Process Injection");
        assert_eq!(technique.severity.unwrap(), "HIGH");
    }

    #[test]
    fn test_ip_traffic_creation() {
        let traffic = IpTraffic {
            destination_ip: Some("192.168.1.100".to_string()),
            destination_port: Some(443),
            protocol: Some("TCP".to_string()),
            bytes_sent: Some(2048),
            bytes_received: Some(4096),
            pid: Some(1234),
            process_name: Some("malware.exe".to_string()),
            time: Some("2024-01-01T12:00:00Z".to_string()),
        };

        assert_eq!(traffic.destination_ip.unwrap(), "192.168.1.100");
        assert_eq!(traffic.destination_port.unwrap(), 443);
        assert_eq!(traffic.protocol.unwrap(), "TCP");
        assert_eq!(traffic.bytes_sent.unwrap(), 2048);
        assert_eq!(traffic.bytes_received.unwrap(), 4096);
    }

    #[test]
    fn test_registry_operation_creation() {
        let registry_op = RegistryOperation {
            key: Some("HKEY_CURRENT_USER\\Software\\Test".to_string()),
            value: Some("TestValue".to_string()),
            data: Some("TestData".to_string()),
            pid: Some(1234),
            process_name: Some("malware.exe".to_string()),
            time: Some("2024-01-01T12:00:00Z".to_string()),
        };

        assert_eq!(
            registry_op.key.unwrap(),
            "HKEY_CURRENT_USER\\Software\\Test"
        );
        assert_eq!(registry_op.value.unwrap(), "TestValue");
        assert_eq!(registry_op.data.unwrap(), "TestData");
    }

    #[test]
    fn test_tls_conversation_creation() {
        let tls_conv = TlsConversation {
            server_name: Some("example.com".to_string()),
            ja3: Some("769,47-53-5-10-49161-49162-49171-49172-50-56-19-4".to_string()),
            ja3s: Some("769,47,65281".to_string()),
            pid: Some(1234),
            process_name: Some("browser.exe".to_string()),
            time: Some("2024-01-01T12:00:00Z".to_string()),
        };

        assert_eq!(tls_conv.server_name.unwrap(), "example.com");
        assert!(tls_conv.ja3.unwrap().contains("769,47"));
        assert!(tls_conv.ja3s.unwrap().contains("769,47"));
    }

    #[test]
    fn test_service_operation_creation() {
        let service_op = ServiceOperation {
            service_name: Some("TestService".to_string()),
            service_path: Some("C:\\Windows\\System32\\testservice.exe".to_string()),
            pid: Some(1234),
            process_name: Some("services.exe".to_string()),
            time: Some("2024-01-01T12:00:00Z".to_string()),
        };

        assert_eq!(service_op.service_name.unwrap(), "TestService");
        assert_eq!(
            service_op.service_path.unwrap(),
            "C:\\Windows\\System32\\testservice.exe"
        );
    }

    #[test]
    fn test_mutex_operation_creation() {
        let mutex_op = MutexOperation {
            mutex_name: Some("Global\\TestMutex".to_string()),
            pid: Some(1234),
            process_name: Some("malware.exe".to_string()),
            time: Some("2024-01-01T12:00:00Z".to_string()),
        };

        assert_eq!(mutex_op.mutex_name.unwrap(), "Global\\TestMutex");
        assert_eq!(mutex_op.pid.unwrap(), 1234);
    }
}
