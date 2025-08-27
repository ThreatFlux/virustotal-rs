use super::*;

#[test]
fn test_livehunt_ruleset_attributes() {
    let attrs = LivehuntRulesetAttributes {
        name: Some("Test Ruleset".to_string()),
        enabled: Some(true),
        limit: Some(100),
        rules: Some("rule test { condition: true }".to_string()),
        notification_emails: Some(vec!["test@example.com".to_string()]),
        match_object_type: Some("file".to_string()),
        ..Default::default()
    };

    assert_eq!(attrs.name.unwrap(), "Test Ruleset");
    assert!(attrs.enabled.unwrap());
    assert_eq!(attrs.limit.unwrap(), 100);
    assert!(attrs.rules.unwrap().contains("rule test"));
}

#[test]
fn test_create_ruleset_request() {
    let request = CreateLivehuntRulesetRequest::new(
        "My Ruleset".to_string(),
        "rule example { strings: $ = \"test\" condition: all of them }".to_string(),
    )
    .with_enabled(true)
    .with_limit(50)
    .with_notification_emails(vec!["notify@example.com".to_string()])
    .with_match_object_type(MatchObjectType::File);

    assert_eq!(request.data.attributes.name, "My Ruleset");
    assert!(request.data.attributes.enabled.unwrap());
    assert_eq!(request.data.attributes.limit.unwrap(), 50);
    assert_eq!(
        request.data.attributes.notification_emails.unwrap().len(),
        1
    );
    assert_eq!(request.data.attributes.match_object_type.unwrap(), "file");
}

#[test]
fn test_livehunt_ruleset_order_strings() {
    assert_eq!(LivehuntRulesetOrder::NameAsc.to_string(), "name+");
    assert_eq!(LivehuntRulesetOrder::NameDesc.to_string(), "name-");
    assert_eq!(
        LivehuntRulesetOrder::CreationDateAsc.to_string(),
        "creation_date+"
    );
    assert_eq!(
        LivehuntRulesetOrder::CreationDateDesc.to_string(),
        "creation_date-"
    );
}

#[test]
fn test_notification_order_strings() {
    assert_eq!(NotificationOrder::DateAsc.to_string(), "date+");
    assert_eq!(NotificationOrder::DateDesc.to_string(), "date-");
}

#[test]
fn test_match_object_type_strings() {
    assert_eq!(MatchObjectType::File.to_string(), "file");
    assert_eq!(MatchObjectType::Url.to_string(), "url");
    assert_eq!(MatchObjectType::Domain.to_string(), "domain");
    assert_eq!(MatchObjectType::Ip.to_string(), "ip");
}

#[test]
fn test_notification_attributes() {
    let attrs = LivehuntNotificationAttributes {
        date: Some(1234567890),
        tags: Some(vec!["malware".to_string(), "trojan".to_string()]),
        ruleset_id: Some("ruleset_123".to_string()),
        ruleset_name: Some("Malware Detection".to_string()),
        rule_name: Some("TrojanDetector".to_string()),
        sha256: Some("abc123def456".to_string()),
        ..Default::default()
    };

    assert_eq!(attrs.date.unwrap(), 1234567890);
    assert_eq!(attrs.tags.unwrap().len(), 2);
    assert_eq!(attrs.ruleset_name.unwrap(), "Malware Detection");
    assert_eq!(attrs.rule_name.unwrap(), "TrojanDetector");
}

#[test]
fn test_notification_file_context() {
    let context = NotificationFileContext {
        match_in_subfile: false,
        notification_date: 1234567890,
        notification_id: "notif_123".to_string(),
        notification_snippet: Some("00 01 02 03".to_string()),
        notification_source_key: Some("key_123".to_string()),
        notification_tags: vec!["tag1".to_string(), "tag2".to_string()],
        ruleset_id: "ruleset_123".to_string(),
        ruleset_name: "Test Ruleset".to_string(),
        rule_name: "TestRule".to_string(),
        rule_tags: Some(vec!["test".to_string()]),
    };

    assert!(!context.match_in_subfile);
    assert_eq!(context.notification_id, "notif_123");
    assert_eq!(context.ruleset_name, "Test Ruleset");
    assert_eq!(context.rule_name, "TestRule");
}

#[test]
fn test_editor_descriptor() {
    let editor = EditorDescriptor {
        object_type: "user".to_string(),
        id: "user123".to_string(),
    };

    assert_eq!(editor.object_type, "user");
    assert_eq!(editor.id, "user123");

    let request = AddEditorsRequest { data: vec![editor] };

    assert_eq!(request.data.len(), 1);
}

#[test]
fn test_operation_response() {
    let response = OperationResponse {
        id: Some("op_123".to_string()),
        status: Some("completed".to_string()),
        error: None,
    };

    assert_eq!(response.id.unwrap(), "op_123");
    assert_eq!(response.status.unwrap(), "completed");
    assert!(response.error.is_none());

    let error_response = OperationResponse {
        id: None,
        status: Some("failed".to_string()),
        error: Some(OperationError {
            code: "ERR001".to_string(),
            message: "Operation failed".to_string(),
        }),
    };

    assert!(error_response.error.is_some());
}
