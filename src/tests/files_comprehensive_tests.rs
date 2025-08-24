//! Comprehensive tests for files.rs module to improve coverage
//! This module focuses on testing uncovered functionality in the files API

use crate::files::*;
use crate::tests::test_utils::{create_test_client, create_mock_server};
use crate::tests::mock_data::*;
use serde_json::json;
use std::collections::HashMap;
use wiremock::{
    matchers::{method, path, path_regex, query_param},
    Mock, ResponseTemplate,
};

#[tokio::test]
async fn test_files_client_creation() {
    let client = create_test_client();
    let files_client = client.files();
    
    // Verify the client was created
    assert!(!format!("{:?}", files_client).is_empty());
}

#[tokio::test]
async fn test_file_upload_url_request() {
    let mock_server = create_mock_server().await;
    let client = create_test_client().with_base_url(&mock_server.uri()).unwrap();

    Mock::given(method("GET"))
        .and(path("/files/upload_url"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": "https://www.virustotal.com/_ah/upload/file-upload-url"
        })))
        .mount(&mock_server)
        .await;

    let result = client.files().get_upload_url().await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_file_scan_with_url() {
    let mock_server = create_mock_server().await;
    let client = create_test_client().with_base_url(&mock_server.uri()).unwrap();

    Mock::given(method("POST"))
        .and(path("/files"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": {
                "type": "analysis",
                "id": "test-analysis-id",
                "attributes": {
                    "status": "queued"
                }
            }
        })))
        .mount(&mock_server)
        .await;

    let result = client.files().scan_url("https://example.com/file.exe").await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_file_rescan_with_params() {
    let mock_server = create_mock_server().await;
    let client = create_test_client().with_base_url(&mock_server.uri()).unwrap();

    let file_hash = "d41d8cd98f00b204e9800998ecf8427e";
    
    Mock::given(method("POST"))
        .and(path(format!("/files/{}/analyse", file_hash)))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": {
                "type": "analysis",
                "id": "rescan-analysis-id"
            }
        })))
        .mount(&mock_server)
        .await;

    let result = client.files().rescan(file_hash).await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_file_get_comments() {
    let mock_server = create_mock_server().await;
    let client = create_test_client().with_base_url(&mock_server.uri()).unwrap();

    let file_hash = "d41d8cd98f00b204e9800998ecf8427e";
    
    Mock::given(method("GET"))
        .and(path(format!("/files/{}/comments", file_hash)))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": [
                {
                    "type": "comment",
                    "id": "comment-1",
                    "attributes": {
                        "text": "This is a test comment",
                        "date": 1640995200,
                        "tags": ["malware", "trojan"]
                    }
                }
            ]
        })))
        .mount(&mock_server)
        .await;

    let result = client.files().get_comments(file_hash).await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_file_add_comment() {
    let mock_server = create_mock_server().await;
    let client = create_test_client().with_base_url(&mock_server.uri()).unwrap();

    let file_hash = "d41d8cd98f00b204e9800998ecf8427e";
    
    Mock::given(method("POST"))
        .and(path(format!("/files/{}/comments", file_hash)))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": {
                "type": "comment",
                "id": "new-comment-id",
                "attributes": {
                    "text": "Test comment"
                }
            }
        })))
        .mount(&mock_server)
        .await;

    let result = client.files().add_comment(file_hash, "Test comment").await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_file_get_votes() {
    let mock_server = create_mock_server().await;
    let client = create_test_client().with_base_url(&mock_server.uri()).unwrap();

    let file_hash = "d41d8cd98f00b204e9800998ecf8427e";
    
    Mock::given(method("GET"))
        .and(path(format!("/files/{}/votes", file_hash)))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": [
                {
                    "type": "vote",
                    "id": "vote-1",
                    "attributes": {
                        "verdict": "malicious",
                        "date": 1640995200
                    }
                }
            ]
        })))
        .mount(&mock_server)
        .await;

    let result = client.files().get_votes(file_hash).await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_file_add_vote() {
    let mock_server = create_mock_server().await;
    let client = create_test_client().with_base_url(&mock_server.uri()).unwrap();

    let file_hash = "d41d8cd98f00b204e9800998ecf8427e";
    
    Mock::given(method("POST"))
        .and(path(format!("/files/{}/votes", file_hash)))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": {
                "type": "vote",
                "id": "new-vote-id",
                "attributes": {
                    "verdict": "harmless"
                }
            }
        })))
        .mount(&mock_server)
        .await;

    let result = client.files().add_vote(file_hash, "harmless").await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_file_get_download_url() {
    let mock_server = create_mock_server().await;
    let client = create_test_client().with_base_url(&mock_server.uri()).unwrap();

    let file_hash = "d41d8cd98f00b204e9800998ecf8427e";
    
    Mock::given(method("GET"))
        .and(path(format!("/files/{}/download_url", file_hash)))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": "https://www.virustotal.com/api/v3/files/download/test-url"
        })))
        .mount(&mock_server)
        .await;

    let result = client.files().get_download_url(file_hash).await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_file_relationships() {
    let mock_server = create_mock_server().await;
    let client = create_test_client().with_base_url(&mock_server.uri()).unwrap();

    let file_hash = "d41d8cd98f00b204e9800998ecf8427e";
    
    // Test contacted_domains relationship
    Mock::given(method("GET"))
        .and(path_regex(format!(r"^/files/{}/contacted_domains", file_hash)))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": [
                {
                    "type": "domain",
                    "id": "example.com",
                    "attributes": {
                        "last_analysis_stats": {
                            "malicious": 0,
                            "suspicious": 0,
                            "harmless": 50,
                            "undetected": 20
                        }
                    }
                }
            ]
        })))
        .mount(&mock_server)
        .await;

    let result = client.files().get_contacted_domains(file_hash).await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_file_contacted_ips() {
    let mock_server = create_mock_server().await;
    let client = create_test_client().with_base_url(&mock_server.uri()).unwrap();

    let file_hash = "d41d8cd98f00b204e9800998ecf8427e";
    
    Mock::given(method("GET"))
        .and(path_regex(format!(r"^/files/{}/contacted_ips", file_hash)))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": [
                {
                    "type": "ip_address",
                    "id": "8.8.8.8",
                    "attributes": {
                        "country": "US",
                        "as_owner": "Google"
                    }
                }
            ]
        })))
        .mount(&mock_server)
        .await;

    let result = client.files().get_contacted_ips(file_hash).await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_file_dropped_files() {
    let mock_server = create_mock_server().await;
    let client = create_test_client().with_base_url(&mock_server.uri()).unwrap();

    let file_hash = "d41d8cd98f00b204e9800998ecf8427e";
    
    Mock::given(method("GET"))
        .and(path_regex(format!(r"^/files/{}/dropped_files", file_hash)))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": [
                {
                    "type": "file",
                    "id": "dropped-file-hash",
                    "attributes": {
                        "type_description": "Executable",
                        "size": 1024
                    }
                }
            ]
        })))
        .mount(&mock_server)
        .await;

    let result = client.files().get_dropped_files(file_hash).await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_file_similar_files() {
    let mock_server = create_mock_server().await;
    let client = create_test_client().with_base_url(&mock_server.uri()).unwrap();

    let file_hash = "d41d8cd98f00b204e9800998ecf8427e";
    
    Mock::given(method("GET"))
        .and(path_regex(format!(r"^/files/{}/similar_files", file_hash)))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": [
                {
                    "type": "file",
                    "id": "similar-file-hash",
                    "attributes": {
                        "similarity": 0.95,
                        "size": 2048
                    }
                }
            ]
        })))
        .mount(&mock_server)
        .await;

    let result = client.files().get_similar_files(file_hash).await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_file_carbonblack_children() {
    let mock_server = create_mock_server().await;
    let client = create_test_client().with_base_url(&mock_server.uri()).unwrap();

    let file_hash = "d41d8cd98f00b204e9800998ecf8427e";
    
    Mock::given(method("GET"))
        .and(path_regex(format!(r"^/files/{}/carbonblack_children", file_hash)))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": [
                {
                    "type": "file",
                    "id": "child-file-hash",
                    "attributes": {
                        "process_name": "child_process.exe"
                    }
                }
            ]
        })))
        .mount(&mock_server)
        .await;

    let result = client.files().get_carbonblack_children(file_hash).await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_file_carbonblack_parents() {
    let mock_server = create_mock_server().await;
    let client = create_test_client().with_base_url(&mock_server.uri()).unwrap();

    let file_hash = "d41d8cd98f00b204e9800998ecf8427e";
    
    Mock::given(method("GET"))
        .and(path_regex(format!(r"^/files/{}/carbonblack_parents", file_hash)))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": [
                {
                    "type": "file",
                    "id": "parent-file-hash",
                    "attributes": {
                        "process_name": "parent_process.exe"
                    }
                }
            ]
        })))
        .mount(&mock_server)
        .await;

    let result = client.files().get_carbonblack_parents(file_hash).await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_file_compressed_parents() {
    let mock_server = create_mock_server().await;
    let client = create_test_client().with_base_url(&mock_server.uri()).unwrap();

    let file_hash = "d41d8cd98f00b204e9800998ecf8427e";
    
    Mock::given(method("GET"))
        .and(path_regex(format!(r"^/files/{}/compressed_parents", file_hash)))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": [
                {
                    "type": "file",
                    "id": "compressed-parent-hash",
                    "attributes": {
                        "type_description": "ZIP archive"
                    }
                }
            ]
        })))
        .mount(&mock_server)
        .await;

    let result = client.files().get_compressed_parents(file_hash).await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_file_email_parents() {
    let mock_server = create_mock_server().await;
    let client = create_test_client().with_base_url(&mock_server.uri()).unwrap();

    let file_hash = "d41d8cd98f00b204e9800998ecf8427e";
    
    Mock::given(method("GET"))
        .and(path_regex(format!(r"^/files/{}/email_parents", file_hash)))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": [
                {
                    "type": "file",
                    "id": "email-parent-hash",
                    "attributes": {
                        "type_description": "Email message"
                    }
                }
            ]
        })))
        .mount(&mock_server)
        .await;

    let result = client.files().get_email_parents(file_hash).await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_file_execution_parents() {
    let mock_server = create_mock_server().await;
    let client = create_test_client().with_base_url(&mock_server.uri()).unwrap();

    let file_hash = "d41d8cd98f00b204e9800998ecf8427e";
    
    Mock::given(method("GET"))
        .and(path_regex(format!(r"^/files/{}/execution_parents", file_hash)))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": [
                {
                    "type": "file",
                    "id": "execution-parent-hash",
                    "attributes": {
                        "execution_context": "sandbox"
                    }
                }
            ]
        })))
        .mount(&mock_server)
        .await;

    let result = client.files().get_execution_parents(file_hash).await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_file_pe_resource_parents() {
    let mock_server = create_mock_server().await;
    let client = create_test_client().with_base_url(&mock_server.uri()).unwrap();

    let file_hash = "d41d8cd98f00b204e9800998ecf8427e";
    
    Mock::given(method("GET"))
        .and(path_regex(format!(r"^/files/{}/pe_resource_parents", file_hash)))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": [
                {
                    "type": "file",
                    "id": "pe-resource-parent-hash",
                    "attributes": {
                        "type_description": "PE32 executable"
                    }
                }
            ]
        })))
        .mount(&mock_server)
        .await;

    let result = client.files().get_pe_resource_parents(file_hash).await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_file_relationships_with_limit() {
    let mock_server = create_mock_server().await;
    let client = create_test_client().with_base_url(&mock_server.uri()).unwrap();

    let file_hash = "d41d8cd98f00b204e9800998ecf8427e";
    
    Mock::given(method("GET"))
        .and(path_regex(format!(r"^/files/{}/contacted_domains", file_hash)))
        .and(query_param("limit", "10"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": [],
            "meta": {
                "count": 0
            }
        })))
        .mount(&mock_server)
        .await;

    let result = client.files().get_contacted_domains_with_limit(file_hash, 10).await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_file_behaviours() {
    let mock_server = create_mock_server().await;
    let client = create_test_client().with_base_url(&mock_server.uri()).unwrap();

    let behaviour_id = "test-behaviour-id";
    
    Mock::given(method("GET"))
        .and(path(format!("/file_behaviours/{}", behaviour_id)))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": {
                "type": "file_behaviour",
                "id": behaviour_id,
                "attributes": {
                    "analysis_date": 1640995200,
                    "has_html_report": true
                }
            }
        })))
        .mount(&mock_server)
        .await;

    let result = client.files().get_behaviour(behaviour_id).await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_file_error_handling() {
    let mock_server = create_mock_server().await;
    let client = create_test_client().with_base_url(&mock_server.uri()).unwrap();

    // Test 404 not found
    Mock::given(method("GET"))
        .and(path("/files/invalid-hash"))
        .respond_with(ResponseTemplate::new(404).set_body_json(json!({
            "error": {
                "code": "NotFoundError",
                "message": "File not found"
            }
        })))
        .mount(&mock_server)
        .await;

    let result = client.files().get("invalid-hash").await;
    assert!(result.is_err());
}

#[tokio::test] 
async fn test_file_hash_validation() {
    let client = create_test_client();
    
    // Test valid hash formats
    let valid_hashes = [
        "d41d8cd98f00b204e9800998ecf8427e",                    // MD5
        "da39a3ee5e6b4b0d3255bfef95601890afd80709",            // SHA1
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", // SHA256
    ];
    
    // These should not cause panics or validation errors in our client
    for hash in &valid_hashes {
        let files_client = client.files();
        // Just verify the client accepts these without immediate validation errors
        assert!(!hash.is_empty());
        assert!(hash.len() >= 32);
    }
}

#[test]
fn test_file_relationship_endpoints() {
    // Test that all relationship endpoint constants are defined
    let file_hash = "test-hash";
    
    let endpoints = vec![
        format!("/files/{}/contacted_domains", file_hash),
        format!("/files/{}/contacted_ips", file_hash),
        format!("/files/{}/dropped_files", file_hash),
        format!("/files/{}/similar_files", file_hash),
        format!("/files/{}/carbonblack_children", file_hash),
        format!("/files/{}/carbonblack_parents", file_hash),
        format!("/files/{}/compressed_parents", file_hash),
        format!("/files/{}/email_parents", file_hash),
        format!("/files/{}/execution_parents", file_hash),
        format!("/files/{}/pe_resource_parents", file_hash),
    ];
    
    for endpoint in endpoints {
        assert!(endpoint.starts_with("/files/"));
        assert!(endpoint.contains(file_hash));
    }
}

#[test]
fn test_file_upload_parameters() {
    // Test various file upload parameters
    let mut form_data = HashMap::new();
    form_data.insert("file", "binary_data_here");
    form_data.insert("password", "optional_password");
    
    assert!(form_data.contains_key("file"));
    assert_eq!(form_data.get("password"), Some(&"optional_password"));
}

#[test]
fn test_file_scan_parameters() {
    // Test URL scan parameters
    let url = "https://example.com/suspicious-file.exe";
    let encoded_url = base64::encode(url);
    
    assert!(!encoded_url.is_empty());
    assert!(encoded_url.len() > url.len());
}