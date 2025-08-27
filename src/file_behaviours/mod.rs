//! VirusTotal File Behaviours module
//!
//! This module provides access to VirusTotal file behavior analysis results
//! including sandbox execution data, process trees, network activity, and more.

pub mod client;
pub mod types;

// Re-export public types and client
pub use client::FileBehaviourClient;
pub use types::{
    CommandExecution, CreatedProcess, DnsLookup, DroppedFile, FileBehaviour,
    FileBehaviourAttributes, FileCopyOperation, FileMoveOperation, FileOperation, HttpConversation,
    IpTraffic, Ja3Digest, MitreAttackTechnique, ModuleOperation, MutexOperation, ProcessTreeNode,
    RegistryOperation, ServiceOperation, SigmaAnalysisSummary, TerminatedProcess, TlsConversation,
};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::objects::ObjectOperations;

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
