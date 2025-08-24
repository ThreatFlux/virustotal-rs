//! Comprehensive tests for API modules to improve coverage
//! This module focuses on testing various API endpoint modules

use crate::attack_tactics::*;
use crate::attack_techniques::*;
use crate::urls::*;
use crate::collections::*;
use crate::comments::*;
use crate::livehunt::*;
use crate::retrohunt::*;
use crate::search::*;
use crate::tests::test_utils::{create_test_client, create_mock_server};
use crate::tests::mock_data::*;
use serde_json::json;
use wiremock::{
    matchers::{method, path, path_regex, query_param},
    Mock, ResponseTemplate,
};

// Attack Tactics Tests
#[tokio::test]
async fn test_attack_tactics_client_get() {
    let mock_server = create_mock_server().await;
    let client = create_test_client().with_base_url(&mock_server.uri()).unwrap();

    let tactic_id = "TA0001";
    
    Mock::given(method("GET"))
        .and(path(format!("/attack_tactics/{}", tactic_id)))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": {
                "type": "attack_tactic",
                "id": tactic_id,
                "attributes": {
                    "name": "Initial Access",
                    "description": "The adversary is trying to get into your network",
                    "external_id": "TA0001",
                    "platforms": ["Windows", "macOS", "Linux"],
                    "tactics": ["initial-access"]
                }
            }
        })))
        .mount(&mock_server)
        .await;

    let result = client.attack_tactics().get(tactic_id).await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_attack_tactics_get_techniques() {
    let mock_server = create_mock_server().await;
    let client = create_test_client().with_base_url(&mock_server.uri()).unwrap();

    let tactic_id = "TA0001";
    
    Mock::given(method("GET"))
        .and(path_regex(format!(r"^/attack_tactics/{}/attack_techniques", tactic_id)))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": [
                {
                    "type": "attack_technique",
                    "id": "T1566",
                    "attributes": {
                        "name": "Phishing",
                        "description": "Adversaries may send phishing messages",
                        "platforms": ["Windows", "macOS", "Linux"]
                    }
                }
            ]
        })))
        .mount(&mock_server)
        .await;

    let result = client.attack_tactics().get_techniques(tactic_id).await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_attack_tactics_get_objects() {
    let mock_server = create_mock_server().await;
    let client = create_test_client().with_base_url(&mock_server.uri()).unwrap();

    let tactic_id = "TA0001";
    
    Mock::given(method("GET"))
        .and(path_regex(format!(r"^/attack_tactics/{}/objects", tactic_id)))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": [
                {
                    "type": "file",
                    "id": "example-hash",
                    "attributes": {
                        "meaningful_name": "malware.exe",
                        "size": 1024
                    }
                }
            ]
        })))
        .mount(&mock_server)
        .await;

    let result = client.attack_tactics().get_objects(tactic_id).await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_attack_tactics_relationships() {
    let mock_server = create_mock_server().await;
    let client = create_test_client().with_base_url(&mock_server.uri()).unwrap();

    let tactic_id = "TA0001";
    
    Mock::given(method("GET"))
        .and(path_regex(format!(r"^/attack_tactics/{}/relationships", tactic_id)))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": [
                {
                    "type": "relationship",
                    "id": "rel-001",
                    "attributes": {
                        "relationship_type": "uses",
                        "source_object": tactic_id,
                        "target_object": "T1566"
                    }
                }
            ]
        })))
        .mount(&mock_server)
        .await;

    let result = client.attack_tactics().get_relationships(tactic_id).await;
    assert!(result.is_ok());
}

// Attack Techniques Tests
#[tokio::test]
async fn test_attack_techniques_client_get() {
    let mock_server = create_mock_server().await;
    let client = create_test_client().with_base_url(&mock_server.uri()).unwrap();

    let technique_id = "T1566";
    
    Mock::given(method("GET"))
        .and(path(format!("/attack_techniques/{}", technique_id)))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": {
                "type": "attack_technique",
                "id": technique_id,
                "attributes": {
                    "name": "Phishing",
                    "description": "Adversaries may send phishing messages to gain access",
                    "external_id": "T1566",
                    "platforms": ["Windows", "macOS", "Linux"],
                    "tactics": ["initial-access"],
                    "subtechniques": ["T1566.001", "T1566.002"]
                }
            }
        })))
        .mount(&mock_server)
        .await;

    let result = client.attack_techniques().get(technique_id).await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_attack_techniques_get_subtechniques() {
    let mock_server = create_mock_server().await;
    let client = create_test_client().with_base_url(&mock_server.uri()).unwrap();

    let technique_id = "T1566";
    
    Mock::given(method("GET"))
        .and(path_regex(format!(r"^/attack_techniques/{}/subtechniques", technique_id)))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": [
                {
                    "type": "attack_technique",
                    "id": "T1566.001",
                    "attributes": {
                        "name": "Spearphishing Attachment",
                        "description": "Adversaries may send spearphishing emails with attachments",
                        "is_subtechnique": true
                    }
                }
            ]
        })))
        .mount(&mock_server)
        .await;

    let result = client.attack_techniques().get_subtechniques(technique_id).await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_attack_techniques_get_parent() {
    let mock_server = create_mock_server().await;
    let client = create_test_client().with_base_url(&mock_server.uri()).unwrap();

    let subtechnique_id = "T1566.001";
    
    Mock::given(method("GET"))
        .and(path_regex(format!(r"^/attack_techniques/{}/parent_technique", subtechnique_id)))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": {
                "type": "attack_technique",
                "id": "T1566",
                "attributes": {
                    "name": "Phishing",
                    "description": "Parent technique for phishing attacks"
                }
            }
        })))
        .mount(&mock_server)
        .await;

    let result = client.attack_techniques().get_parent(subtechnique_id).await;
    assert!(result.is_ok());
}

// URLs Tests
#[tokio::test]
async fn test_urls_client_scan() {
    let mock_server = create_mock_server().await;
    let client = create_test_client().with_base_url(&mock_server.uri()).unwrap();

    let test_url = "https://example.com/suspicious";
    
    Mock::given(method("POST"))
        .and(path("/urls"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": {
                "type": "analysis",
                "id": "url-analysis-id",
                "attributes": {
                    "status": "queued"
                }
            }
        })))
        .mount(&mock_server)
        .await;

    let result = client.urls().scan(test_url).await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_urls_client_get() {
    let mock_server = create_mock_server().await;
    let client = create_test_client().with_base_url(&mock_server.uri()).unwrap();

    let url_id = "example-url-id";
    
    Mock::given(method("GET"))
        .and(path(format!("/urls/{}", url_id)))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": {
                "type": "url",
                "id": url_id,
                "attributes": {
                    "url": "https://example.com",
                    "last_analysis_stats": {
                        "harmless": 50,
                        "malicious": 2,
                        "suspicious": 1,
                        "undetected": 17
                    }
                }
            }
        })))
        .mount(&mock_server)
        .await;

    let result = client.urls().get(url_id).await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_urls_rescan() {
    let mock_server = create_mock_server().await;
    let client = create_test_client().with_base_url(&mock_server.uri()).unwrap();

    let url_id = "example-url-id";
    
    Mock::given(method("POST"))
        .and(path(format!("/urls/{}/analyse", url_id)))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": {
                "type": "analysis",
                "id": "rescan-analysis-id"
            }
        })))
        .mount(&mock_server)
        .await;

    let result = client.urls().rescan(url_id).await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_urls_get_comments() {
    let mock_server = create_mock_server().await;
    let client = create_test_client().with_base_url(&mock_server.uri()).unwrap();

    let url_id = "example-url-id";
    
    Mock::given(method("GET"))
        .and(path(format!("/urls/{}/comments", url_id)))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": [
                {
                    "type": "comment",
                    "id": "comment-1",
                    "attributes": {
                        "text": "This URL is suspicious",
                        "date": 1640995200
                    }
                }
            ]
        })))
        .mount(&mock_server)
        .await;

    let result = client.urls().get_comments(url_id).await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_urls_add_comment() {
    let mock_server = create_mock_server().await;
    let client = create_test_client().with_base_url(&mock_server.uri()).unwrap();

    let url_id = "example-url-id";
    
    Mock::given(method("POST"))
        .and(path(format!("/urls/{}/comments", url_id)))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": {
                "type": "comment",
                "id": "new-comment-id",
                "attributes": {
                    "text": "Added comment"
                }
            }
        })))
        .mount(&mock_server)
        .await;

    let result = client.urls().add_comment(url_id, "Added comment").await;
    assert!(result.is_ok());
}

// Collections Tests
#[tokio::test]
async fn test_collections_client_create() {
    let mock_server = create_mock_server().await;
    let client = create_test_client().with_base_url(&mock_server.uri()).unwrap();

    Mock::given(method("POST"))
        .and(path("/collections"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": {
                "type": "collection",
                "id": "new-collection-id",
                "attributes": {
                    "name": "Test Collection",
                    "description": "A test collection"
                }
            }
        })))
        .mount(&mock_server)
        .await;

    let create_request = CreateCollectionRequest {
        data: CreateCollectionData {
            attributes: CreateCollectionAttributes {
                name: "Test Collection".to_string(),
                description: Some("A test collection".to_string()),
            },
            relationships: None,
            object_type: "collection".to_string(),
            raw_items: None,
        },
    };

    let result = client.collections().create(&create_request).await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_collections_client_get() {
    let mock_server = create_mock_server().await;
    let client = create_test_client().with_base_url(&mock_server.uri()).unwrap();

    let collection_id = "test-collection-id";
    
    Mock::given(method("GET"))
        .and(path(format!("/collections/{}", collection_id)))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": {
                "type": "collection",
                "id": collection_id,
                "attributes": {
                    "name": "Test Collection",
                    "description": "A test collection",
                    "items_count": 10
                }
            }
        })))
        .mount(&mock_server)
        .await;

    let result = client.collections().get(collection_id).await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_collections_update() {
    let mock_server = create_mock_server().await;
    let client = create_test_client().with_base_url(&mock_server.uri()).unwrap();

    let collection_id = "test-collection-id";
    
    Mock::given(method("PATCH"))
        .and(path(format!("/collections/{}", collection_id)))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": {
                "type": "collection",
                "id": collection_id,
                "attributes": {
                    "name": "Updated Collection",
                    "description": "Updated description"
                }
            }
        })))
        .mount(&mock_server)
        .await;

    let update_request = UpdateCollectionRequest {
        data: UpdateCollectionData {
            attributes: Some(UpdateCollectionAttributes {
                name: Some("Updated Collection".to_string()),
                description: Some("Updated description".to_string()),
            }),
            raw_items: None,
            object_type: "collection".to_string(),
        },
    };

    let result = client.collections().update(collection_id, &update_request).await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_collections_delete() {
    let mock_server = create_mock_server().await;
    let client = create_test_client().with_base_url(&mock_server.uri()).unwrap();

    let collection_id = "test-collection-id";
    
    Mock::given(method("DELETE"))
        .and(path(format!("/collections/{}", collection_id)))
        .respond_with(ResponseTemplate::new(204))
        .mount(&mock_server)
        .await;

    let result = client.collections().delete(collection_id).await;
    assert!(result.is_ok());
}

// LiveHunt Tests
#[tokio::test]
async fn test_livehunt_client_get_ruleset() {
    let mock_server = create_mock_server().await;
    let client = create_test_client().with_base_url(&mock_server.uri()).unwrap();

    let ruleset_id = "test-ruleset-id";
    
    Mock::given(method("GET"))
        .and(path(format!("/intelligence/hunting_rulesets/{}", ruleset_id)))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": {
                "type": "hunting_ruleset",
                "id": ruleset_id,
                "attributes": {
                    "name": "Test Ruleset",
                    "rules": "rule test { condition: true }",
                    "enabled": true
                }
            }
        })))
        .mount(&mock_server)
        .await;

    let result = client.livehunt().get_ruleset(ruleset_id).await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_livehunt_create_ruleset() {
    let mock_server = create_mock_server().await;
    let client = create_test_client().with_base_url(&mock_server.uri()).unwrap();

    Mock::given(method("POST"))
        .and(path("/intelligence/hunting_rulesets"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": {
                "type": "hunting_ruleset",
                "id": "new-ruleset-id",
                "attributes": {
                    "name": "New Ruleset"
                }
            }
        })))
        .mount(&mock_server)
        .await;

    let create_request = CreateLivehuntRulesetRequest {
        data: CreateLivehuntRulesetData {
            object_type: "hunting_ruleset".to_string(),
            attributes: CreateLivehuntRulesetAttributes {
                name: "New Ruleset".to_string(),
                rules: "rule test { condition: true }".to_string(),
                enabled: Some(true),
                limit: None,
                notification_emails: Some(vec!["test@example.com".to_string()]),
                match_object_type: None,
            },
        },
    };

    let result = client.livehunt().create_ruleset(&create_request).await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_livehunt_get_notifications() {
    let mock_server = create_mock_server().await;
    let client = create_test_client().with_base_url(&mock_server.uri()).unwrap();

    let ruleset_id = "test-ruleset-id";
    
    Mock::given(method("GET"))
        .and(path_regex(format!(r"^/intelligence/hunting_rulesets/{}/notifications", ruleset_id)))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": [
                {
                    "type": "hunting_notification",
                    "id": "notification-1",
                    "attributes": {
                        "date": 1640995200,
                        "rule_name": "test_rule",
                        "matched_file": "malware.exe"
                    }
                }
            ]
        })))
        .mount(&mock_server)
        .await;

    let result = client.livehunt().get_notifications(ruleset_id).await;
    assert!(result.is_ok());
}

// RetroHunt Tests  
#[tokio::test]
async fn test_retrohunt_client_get_job() {
    let mock_server = create_mock_server().await;
    let client = create_test_client().with_base_url(&mock_server.uri()).unwrap();

    let job_id = "test-job-id";
    
    Mock::given(method("GET"))
        .and(path(format!("/intelligence/retrohunt_jobs/{}", job_id)))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": {
                "type": "retrohunt_job",
                "id": job_id,
                "attributes": {
                    "rules": "rule test { condition: true }",
                    "status": "running",
                    "progress": 50
                }
            }
        })))
        .mount(&mock_server)
        .await;

    let result = client.retrohunt().get_job(job_id).await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_retrohunt_create_job() {
    let mock_server = create_mock_server().await;
    let client = create_test_client().with_base_url(&mock_server.uri()).unwrap();

    Mock::given(method("POST"))
        .and(path("/intelligence/retrohunt_jobs"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": {
                "type": "retrohunt_job",
                "id": "new-job-id",
                "attributes": {
                    "status": "queued"
                }
            }
        })))
        .mount(&mock_server)
        .await;

    let create_request = CreateRetrohuntJobRequest {
        data: CreateRetrohuntJobData {
            object_type: "retrohunt_job".to_string(),
            attributes: CreateRetrohuntJobAttributes {
                rules: "rule test { condition: true }".to_string(),
                notification_email: Some("test@example.com".to_string()),
                corpus: Some("goodware".to_string()),
                time_range: Some(TimeRange {
                    start: Some(1640995200),
                    end: Some(1672531200),
                }),
            },
        },
    };

    let result = client.retrohunt().create_job(&create_request).await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_retrohunt_delete_job() {
    let mock_server = create_mock_server().await;
    let client = create_test_client().with_base_url(&mock_server.uri()).unwrap();

    let job_id = "test-job-id";
    
    Mock::given(method("DELETE"))
        .and(path(format!("/intelligence/retrohunt_jobs/{}", job_id)))
        .respond_with(ResponseTemplate::new(204))
        .mount(&mock_server)
        .await;

    let result = client.retrohunt().delete_job(job_id).await;
    assert!(result.is_ok());
}

// Search Tests
#[tokio::test]
async fn test_search_client_search() {
    let mock_server = create_mock_server().await;
    let client = create_test_client().with_base_url(&mock_server.uri()).unwrap();

    Mock::given(method("GET"))
        .and(path("/intelligence/search"))
        .and(query_param("query", "test search"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": [
                {
                    "type": "file",
                    "id": "result-hash",
                    "attributes": {
                        "meaningful_name": "result.exe",
                        "size": 2048
                    }
                }
            ]
        })))
        .mount(&mock_server)
        .await;

    let result = client.search().search("test search").await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_search_with_limit() {
    let mock_server = create_mock_server().await;
    let client = create_test_client().with_base_url(&mock_server.uri()).unwrap();

    Mock::given(method("GET"))
        .and(path("/intelligence/search"))
        .and(query_param("query", "test search"))
        .and(query_param("limit", "10"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": [],
            "meta": {
                "count": 0
            }
        })))
        .mount(&mock_server)
        .await;

    let result = client.search().search_with_limit("test search", 10).await;
    assert!(result.is_ok());
}

// Comments Tests
#[tokio::test]
async fn test_comments_client_get() {
    let mock_server = create_mock_server().await;
    let client = create_test_client().with_base_url(&mock_server.uri()).unwrap();

    let comment_id = "test-comment-id";
    
    Mock::given(method("GET"))
        .and(path(format!("/comments/{}", comment_id)))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": {
                "type": "comment",
                "id": comment_id,
                "attributes": {
                    "text": "Test comment",
                    "date": 1640995200,
                    "tags": ["malware"]
                }
            }
        })))
        .mount(&mock_server)
        .await;

    let result = client.comments().get(comment_id).await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_comments_update() {
    let mock_server = create_mock_server().await;
    let client = create_test_client().with_base_url(&mock_server.uri()).unwrap();

    let comment_id = "test-comment-id";
    
    Mock::given(method("PATCH"))
        .and(path(format!("/comments/{}", comment_id)))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": {
                "type": "comment",
                "id": comment_id,
                "attributes": {
                    "text": "Updated comment"
                }
            }
        })))
        .mount(&mock_server)
        .await;

    let result = client.comments().update(comment_id, "Updated comment").await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_comments_delete() {
    let mock_server = create_mock_server().await;
    let client = create_test_client().with_base_url(&mock_server.uri()).unwrap();

    let comment_id = "test-comment-id";
    
    Mock::given(method("DELETE"))
        .and(path(format!("/comments/{}", comment_id)))
        .respond_with(ResponseTemplate::new(204))
        .mount(&mock_server)
        .await;

    let result = client.comments().delete(comment_id).await;
    assert!(result.is_ok());
}

// Test data structure creation and serialization
#[test]
fn test_data_structures_creation() {
    // Test AttackTacticAttributes
    let tactic_attrs = AttackTacticAttributes {
        name: Some("Initial Access".to_string()),
        description: Some("The adversary is trying to get into your network".to_string()),
        external_id: Some("TA0001".to_string()),
        url: None,
        platforms: Some(vec!["Windows".to_string(), "Linux".to_string()]),
        techniques_count: Some(5),
        additional_attributes: HashMap::new(),
    };
    
    assert_eq!(tactic_attrs.name.as_ref().unwrap(), "Initial Access");
    assert_eq!(tactic_attrs.external_id.as_ref().unwrap(), "TA0001");
    assert_eq!(tactic_attrs.platforms.as_ref().unwrap().len(), 2);
    
    // Test AttackTechniqueAttributes
    let technique_attrs = AttackTechniqueAttributes {
        name: Some("Phishing".to_string()),
        description: Some("Adversaries may send phishing messages".to_string()),
        external_id: Some("T1566".to_string()),
        url: None,
        platforms: Some(vec!["Windows".to_string()]),
        data_sources: None,
        defense_bypassed: None,
        permissions_required: None,
        effective_permissions: None,
        system_requirements: None,
        tactics: Some(vec!["initial-access".to_string()]),
        subtechniques_count: None,
        parent_technique: None,
        is_subtechnique: Some(false),
        additional_attributes: HashMap::new(),
    };
    
    assert_eq!(technique_attrs.name.as_ref().unwrap(), "Phishing");
    assert_eq!(technique_attrs.external_id.as_ref().unwrap(), "T1566");
    assert_eq!(technique_attrs.is_subtechnique, Some(false));
    
    // Test CreateCollectionRequest
    let collection_request = CreateCollectionRequest {
        data: CreateCollectionData {
            attributes: CreateCollectionAttributes {
                name: "Test Collection".to_string(),
                description: Some("A test collection".to_string()),
            },
            relationships: Some(CollectionRelationships {
                files: Some(RelationshipData {
                    data: vec![FileDescriptor {
                        object_type: "file".to_string(),
                        id: "example-hash".to_string(),
                    }],
                }),
                domains: None,
                urls: None,
                ip_addresses: None,
            }),
            object_type: "collection".to_string(),
            raw_items: None,
        },
    };
    
    assert_eq!(collection_request.data.attributes.name, "Test Collection");
    assert!(collection_request.data.relationships.is_some());
}

#[test]
fn test_url_descriptor_variants() {
    let descriptors = vec![
        UrlDescriptor::WithUrl {
            object_type: "url".to_string(),
            url: "https://example.com".to_string(),
        },
        UrlDescriptor::WithId {
            object_type: "url".to_string(),
            id: "url-id-123".to_string(),
        },
    ];
    
    for descriptor in descriptors {
        let serialized = serde_json::to_string(&descriptor).unwrap();
        assert!(!serialized.is_empty());
        
        let deserialized: UrlDescriptor = serde_json::from_str(&serialized).unwrap();
        // Note: We can't directly compare due to the untagged enum nature
        assert!(!format!("{:?}", deserialized).is_empty());
    }
}

#[test]
fn test_enum_string_conversions() {
    // Test ExportFormat
    let export_formats = vec![
        ExportFormat::Json,
        ExportFormat::Csv,
        ExportFormat::Stix,
    ];
    
    for format in export_formats {
        let string_val = format.to_string();
        assert!(!string_val.is_empty());
    }
    
    // Test CollectionOrder
    let collection_orders = vec![
        CollectionOrder::CreationDateAsc,
        CollectionOrder::CreationDateDesc,
        CollectionOrder::LastModificationDateAsc,
        CollectionOrder::FilesAsc,
        CollectionOrder::DomainsDesc,
    ];
    
    for order in collection_orders {
        let string_val = order.to_string();
        assert!(!string_val.is_empty());
    }
    
    // Test Corpus
    let corpuses = vec![
        Corpus::Goodware,
        Corpus::Main,
    ];
    
    for corpus in corpuses {
        let string_val = corpus.to_string();
        assert!(!string_val.is_empty());
    }
}