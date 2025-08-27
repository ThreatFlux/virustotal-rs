//! File behavior analysis types and structures

use super::network::{DnsLookup, HttpConversation, IpTraffic, Ja3Digest};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

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
