use crate::objects::{Object, ObjectOperations};
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
