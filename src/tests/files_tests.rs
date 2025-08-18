use crate::files::{File, FileAttributes, MitreSeverity};
use crate::objects::{Object, ObjectOperations};

#[test]
fn test_file_object_operations() {
    assert_eq!(File::collection_name(), "files");
    assert_eq!(File::object_url("abc123"), "files/abc123");
    assert_eq!(
        File::relationships_url("abc123", "comments"),
        "files/abc123/relationships/comments"
    );
}

#[test]
fn test_mitre_severity_enum() {
    let high = MitreSeverity::High;
    let medium = MitreSeverity::Medium;
    let low = MitreSeverity::Low;
    let info = MitreSeverity::Info;
    let unknown = MitreSeverity::Unknown;

    assert!(matches!(high, MitreSeverity::High));
    assert!(matches!(medium, MitreSeverity::Medium));
    assert!(matches!(low, MitreSeverity::Low));
    assert!(matches!(info, MitreSeverity::Info));
    assert!(matches!(unknown, MitreSeverity::Unknown));
}

#[test]
fn test_file_creation() {
    let file = File {
        object: Object {
            id: "test_hash".to_string(),
            object_type: "file".to_string(),
            links: None,
            relationships: None,
            attributes: FileAttributes {
                type_description: Some("PE32 executable".to_string()),
                size: Some(1024),
                sha256: Some("abc123".to_string()),
                md5: Some("def456".to_string()),
                reputation: Some(100),
                tags: Some(vec!["malware".to_string()]),
                ..Default::default()
            },
        },
    };

    assert_eq!(file.object.id, "test_hash");
    assert_eq!(file.object.attributes.size, Some(1024));
    assert_eq!(file.object.attributes.reputation, Some(100));
}

#[test]
fn test_file_attributes_default() {
    let attrs = FileAttributes::default();
    assert!(attrs.type_description.is_none());
    assert!(attrs.size.is_none());
    assert!(attrs.sha256.is_none());
    assert!(attrs.reputation.is_none());
    assert!(attrs.tags.is_none());
}

#[test]
fn test_file_behavior_summary_fields() {
    use crate::files::FileBehaviorSummary;

    let summary = FileBehaviorSummary {
        files_opened: Some(vec!["file1.txt".to_string()]),
        processes_created: Some(vec!["cmd.exe".to_string()]),
        dns_lookups: Some(vec![]),
        tags: Some(vec!["suspicious".to_string()]),
        calls_highlighted: None,
        files_written: None,
        files_deleted: None,
        files_dropped: None,
        files_copied: None,
        files_moved: None,
        files_attribute_changed: None,
        modules_loaded: None,
        mutexes_created: None,
        mutexes_opened: None,
        processes_injected: None,
        processes_terminated: None,
        processes_tree: None,
        registry_keys_created: None,
        registry_keys_deleted: None,
        registry_keys_opened: None,
        registry_keys_set: None,
        services_created: None,
        services_deleted: None,
        services_started: None,
        services_stopped: None,
        text_highlighted: None,
        mitre_attack_techniques: None,
        ip_traffic: None,
        http_conversations: None,
        ja3_digests: None,
        command_executions: None,
        sigma_analysis_results: None,
    };

    assert_eq!(summary.files_opened.unwrap().len(), 1);
    assert_eq!(summary.processes_created.unwrap().len(), 1);
    assert!(summary.dns_lookups.unwrap().is_empty());
    assert_eq!(summary.tags.unwrap()[0], "suspicious");
}

#[test]
fn test_process_tree_node() {
    use crate::files::ProcessTreeNode;

    let node = ProcessTreeNode {
        name: Some("explorer.exe".to_string()),
        process_id: Some("1234".to_string()),
        parent_process_id: Some("1000".to_string()),
        children: Some(vec![]),
    };

    assert_eq!(node.name, Some("explorer.exe".to_string()));
    assert_eq!(node.process_id, Some("1234".to_string()));
    assert_eq!(node.parent_process_id, Some("1000".to_string()));
    assert!(node.children.unwrap().is_empty());
}

#[test]
fn test_dns_lookup() {
    use crate::files::DnsLookup;

    let lookup = DnsLookup {
        hostname: Some("example.com".to_string()),
        resolved_ips: Some(vec!["192.168.1.1".to_string(), "192.168.1.2".to_string()]),
    };

    assert_eq!(lookup.hostname, Some("example.com".to_string()));
    assert_eq!(lookup.resolved_ips.unwrap().len(), 2);
}

#[test]
fn test_ip_traffic() {
    use crate::files::IpTraffic;

    let traffic = IpTraffic {
        destination_ip: Some("10.0.0.1".to_string()),
        destination_port: Some(443),
        protocol: Some("TCP".to_string()),
        bytes_sent: Some(1024),
    };

    assert_eq!(traffic.destination_ip, Some("10.0.0.1".to_string()));
    assert_eq!(traffic.destination_port, Some(443));
    assert_eq!(traffic.protocol, Some("TCP".to_string()));
    assert_eq!(traffic.bytes_sent, Some(1024));
}

#[test]
fn test_http_conversation() {
    use crate::files::HttpConversation;

    let conv = HttpConversation {
        url: Some("https://example.com/api".to_string()),
        request_method: Some("POST".to_string()),
        response_status: Some(200),
        response_body_size: Some(2048),
    };

    assert_eq!(conv.url, Some("https://example.com/api".to_string()));
    assert_eq!(conv.request_method, Some("POST".to_string()));
    assert_eq!(conv.response_status, Some(200));
    assert_eq!(conv.response_body_size, Some(2048));
}
