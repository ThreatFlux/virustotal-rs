use reqwest::header::{HeaderMap, HeaderValue};
use serde_json::{Value, json};
use std::collections::HashMap;
use std::time::Duration;
use virustotal_rs::{ApiKey, ApiTier, EnhancedClientBuilder, HeaderUtils};
use wiremock::matchers::{header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

#[tokio::test]
async fn settings_apply_to_every_request_format_and_survive_timeout_changes() {
    let server = MockServer::start().await;
    let client = EnhancedClientBuilder::new()
        .api_key("fixture-api-key")
        .tier(ApiTier::Premium)
        .base_url(format!("{}/api/v3/", server.uri()))
        .header("x-sdk-fixture", "configured")
        .header("user-agent", "overridden")
        .user_agent("sdk-test/1")
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap()
        .with_timeout(Duration::from_secs(10))
        .unwrap();
    for (verb, endpoint) in [
        ("GET", "json"),
        ("POST", "json"),
        ("POST", "form"),
        ("POST", "multipart"),
        ("GET", "raw"),
        ("GET", "bytes"),
        ("DELETE", "empty"),
        ("DELETE", "header"),
    ] {
        Mock::given(method(verb))
            .and(path(format!("/api/v3/{endpoint}")))
            .and(header("x-apikey", "fixture-api-key"))
            .and(header("x-sdk-fixture", "configured"))
            .and(header("user-agent", "sdk-test/1"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"ok": true})))
            .expect(1)
            .mount(&server)
            .await;
    }
    client.get::<Value>("json").await.unwrap();
    client
        .post::<_, Value>("json", &json!({"value": 1}))
        .await
        .unwrap();
    client
        .post_form::<Value>("form", &HashMap::from([("field", "value")]))
        .await
        .unwrap();
    client
        .post_multipart::<Value>(
            "multipart",
            reqwest::multipart::Form::new().text("field", "value"),
        )
        .await
        .unwrap();
    client.get_raw("raw").await.unwrap();
    client.get_bytes("bytes").await.unwrap();
    client.delete("empty").await.unwrap();
    client
        .delete_with_header("header", "x-operation", "fixture")
        .await
        .unwrap();
}

#[test]
fn invalid_credentials_and_header_overrides_fail_without_echoing_values() {
    for name in ["x-apikey", "authorization", "host", "content-length"] {
        let result = EnhancedClientBuilder::new()
            .api_key("fixture-api-key")
            .header(name, "private-marker")
            .build();
        let error = result.err().unwrap().to_string();
        assert!(!error.contains("private-marker"));
    }
    let result = EnhancedClientBuilder::new()
        .api_key("private-marker\n")
        .build();
    assert!(!result.err().unwrap().to_string().contains("private-marker"));
    let result = EnhancedClientBuilder::new()
        .api_key("fixture-api-key")
        .user_agent("private-marker\n")
        .build();
    assert!(!result.err().unwrap().to_string().contains("private-marker"));
}

#[test]
fn api_key_debug_and_headers_are_redacted() {
    let key = ApiKey::new("private-marker");
    assert_eq!(format!("{key:?}"), "ApiKey(***)");
    assert_eq!(format!("{key}"), "ApiKey(***)");
    let headers = HeaderUtils::standard_headers(&key);
    assert!(headers["x-apikey"].is_sensitive());
    assert!(!format!("{headers:?}").contains("private-marker"));
}

#[tokio::test]
async fn delete_header_cannot_override_credentials() {
    let server = MockServer::start().await;
    let client = EnhancedClientBuilder::new()
        .api_key("fixture-api-key")
        .tier(ApiTier::Premium)
        .base_url(server.uri())
        .build()
        .unwrap();
    assert!(
        client
            .delete_with_header("unused", "X-APIKEY", "private-marker")
            .await
            .is_err()
    );
    assert!(server.received_requests().await.unwrap().is_empty());
}

#[tokio::test]
async fn header_map_configuration_is_applied() {
    let server = MockServer::start().await;
    let mut headers = HeaderMap::new();
    headers.insert("x-sdk-fixture", HeaderValue::from_static("configured"));
    let client = EnhancedClientBuilder::new()
        .api_key("fixture-api-key")
        .tier(ApiTier::Premium)
        .base_url(server.uri())
        .headers(headers)
        .build()
        .unwrap();
    Mock::given(method("GET"))
        .and(path("/fixture"))
        .and(header("x-sdk-fixture", "configured"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({})))
        .expect(1)
        .mount(&server)
        .await;
    client.get::<Value>("fixture").await.unwrap();
}

#[tokio::test]
async fn file_upload_uses_the_shared_base_path_headers_and_error_mapping() {
    let server = MockServer::start().await;
    let client = EnhancedClientBuilder::new()
        .api_key("fixture-api-key")
        .tier(ApiTier::Premium)
        .base_url(format!("{}/api/v3/", server.uri()))
        .header("x-sdk-fixture", "configured")
        .user_agent("sdk-test/1")
        .build()
        .unwrap();
    Mock::given(method("POST"))
        .and(path("/api/v3/files"))
        .and(header("x-apikey", "fixture-api-key"))
        .and(header("x-sdk-fixture", "configured"))
        .and(header("user-agent", "sdk-test/1"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({"data": {"type": "analysis", "id": "fixture"}})),
        )
        .up_to_n_times(1)
        .expect(1)
        .mount(&server)
        .await;
    let analysis = client
        .files()
        .upload_bytes_with_password(
            b"fixture bytes".to_vec(),
            "fixture.txt",
            Some("archive-fixture"),
        )
        .await
        .unwrap();
    assert_eq!(analysis.data.id, "fixture");
    let requests = server.received_requests().await.unwrap();
    let body = String::from_utf8_lossy(&requests[0].body);
    assert!(body.contains("fixture bytes"));
    assert!(body.contains("fixture.txt"));
    assert!(body.contains("archive-fixture"));
    Mock::given(method("POST"))
        .and(path("/api/v3/files"))
        .respond_with(ResponseTemplate::new(429).set_body_json(
            json!({"error": {"code": "TooManyRequestsError", "message": "limited"}}),
        ))
        .expect(1)
        .mount(&server)
        .await;
    assert!(matches!(
        client.files().upload_bytes(vec![1], "fixture.bin").await,
        Err(virustotal_rs::Error::TooManyRequests)
    ));
}

#[tokio::test]
async fn large_file_upload_uses_the_provider_url_with_shared_headers() {
    let server = MockServer::start().await;
    let client = EnhancedClientBuilder::new()
        .api_key("fixture-api-key")
        .tier(ApiTier::Premium)
        .base_url(format!("{}/api/v3/", server.uri()))
        .header("x-sdk-fixture", "configured")
        .build()
        .unwrap();
    Mock::given(method("GET"))
        .and(path("/api/v3/files/upload_url"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({"data": format!("{}/upload-target", server.uri())})),
        )
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/upload-target"))
        .and(header("x-apikey", "fixture-api-key"))
        .and(header("x-sdk-fixture", "configured"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({"data": {"type": "analysis", "id": "large-fixture"}})),
        )
        .expect(1)
        .mount(&server)
        .await;
    let analysis = client
        .files()
        .upload_bytes(vec![0; 32 * 1024 * 1024 + 1], "fixture.bin")
        .await
        .unwrap();
    assert_eq!(analysis.data.id, "large-fixture");
}
