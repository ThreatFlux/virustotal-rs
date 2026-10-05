//! Analysis payload, resource, and finite polling regressions.

use super::client;
use serde_json::{Value, json};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;
use virustotal_rs::Error;
use virustotal_rs::analysis::{AnalysisPollOptions, AnalysisReport, AnalysisStatus};
use wiremock::matchers::{header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn report(status: &str) -> Value {
    json!({"data": {
        "type": "analysis", "id": "analysis-id",
        "attributes": {"status": status, "stats": {}, "results": {}}
    }})
}

fn polling(attempts: u32) -> AnalysisPollOptions {
    AnalysisPollOptions::new(Duration::from_millis(1), Duration::from_secs(10), attempts).unwrap()
}

#[test]
fn current_analysis_accepts_null_verdicts_and_retains_extensions() {
    let value = json!({
        "type": "analysis", "id": "id", "extension": {"new": true},
        "attributes": {
            "status": "in-progress", "stats": {"future-category": 1}, "new": "attribute",
            "results": {"engine": {
                "category": "undetected", "engine_name": "engine", "method": "blacklist",
                "result": null, "new": {"opaque": [1, 2]}
            }}
        }
    });
    let analysis: AnalysisReport = serde_json::from_value(value.clone()).unwrap();
    assert!(!analysis.is_completed());
    assert!(
        analysis.attributes.results.as_ref().unwrap()["engine"]
            .result
            .is_none()
    );
    assert_eq!(serde_json::to_value(analysis).unwrap(), value);
}

#[test]
fn future_analysis_status_is_preserved_without_implying_completion() {
    let analysis: AnalysisReport =
        serde_json::from_value(report("future-state")["data"].clone()).unwrap();
    assert_eq!(analysis.attributes.status.as_deref(), Some("future-state"));
    assert!(!analysis.is_completed());
}

#[test]
fn current_analysis_rejects_malformed_recognized_fields() {
    let mut missing_method = report("completed")["data"].clone();
    missing_method["attributes"]["results"] = json!({"engine": {
        "category": "undetected", "engine_name": "engine", "result": null
    }});
    let mut wrong_status = report("queued")["data"].clone();
    wrong_status["attributes"]["status"] = json!(42);
    let mut negative_stats = report("queued")["data"].clone();
    negative_stats["attributes"]["stats"] = json!({"malicious": -1});
    for value in [missing_method, wrong_status, negative_stats] {
        assert!(serde_json::from_value::<AnalysisReport>(value).is_err());
    }
}

#[test]
fn legacy_analysis_uses_current_hyphenated_status_and_empty_queued_stats() {
    assert_eq!(
        serde_json::to_value(AnalysisStatus::InProgress).unwrap(),
        "in-progress"
    );
    for value in ["in-progress", "inprogress"] {
        assert_eq!(
            serde_json::from_value::<AnalysisStatus>(json!(value)).unwrap(),
            AnalysisStatus::InProgress
        );
    }
    let analysis: virustotal_rs::objects::ObjectResponse<
        virustotal_rs::analysis::AnalysisAttributes,
    > = serde_json::from_value(report("queued")).unwrap();
    assert_eq!(analysis.data.attributes.stats.unwrap().malicious, 0);
    assert!(
        serde_json::from_value::<virustotal_rs::common::AnalysisStats>(json!({"malicious": "bad"}))
            .is_err()
    );
}

#[test]
fn polling_rejects_zero_limits() {
    for (interval, timeout, attempts) in [
        (Duration::ZERO, Duration::from_secs(1), 1),
        (Duration::from_secs(1), Duration::ZERO, 1),
        (Duration::from_secs(1), Duration::from_secs(1), 0),
    ] {
        assert!(AnalysisPollOptions::new(interval, timeout, attempts).is_err());
    }
}

#[tokio::test]
async fn retrieve_analysis_encodes_identifier_and_uses_authenticated_route() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v3/analyses/id%2F%2B%3F%23%3D"))
        .and(header("x-apikey", "offline-fixture"))
        .respond_with(ResponseTemplate::new(200).set_body_json(report("completed")))
        .expect(1)
        .mount(&server)
        .await;
    let analysis = client(&server)
        .analyses()
        .get_report("id/+?#=")
        .await
        .unwrap();
    assert!(analysis.is_completed());
}

#[tokio::test]
async fn retrieve_legacy_analysis_get_and_file_convenience_use_encoded_route() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v3/analyses/id%2Fone"))
        .respond_with(ResponseTemplate::new(200).set_body_json(report("queued")))
        .expect(2)
        .mount(&server)
        .await;
    let client = client(&server);
    assert!(
        !client
            .analyses()
            .get("id/one")
            .await
            .unwrap()
            .is_completed()
    );
    assert!(
        !client
            .files()
            .get_analysis("id/one")
            .await
            .unwrap()
            .is_completed()
    );
}

#[tokio::test]
async fn retrieve_analysis_rejects_wrong_object_type() {
    let server = MockServer::start().await;
    let mut payload = report("completed");
    payload["data"]["type"] = json!("file");
    Mock::given(method("GET"))
        .and(path("/api/v3/analyses/id"))
        .respond_with(ResponseTemplate::new(200).set_body_json(payload))
        .mount(&server)
        .await;
    assert!(matches!(
        client(&server).analyses().get_report("id").await,
        Err(Error::BadRequest(_))
    ));
}

#[tokio::test]
async fn analysis_item_and_descriptor_are_single_objects() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v3/analyses/id/item"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"data": {
            "type": "url", "id": "url-id", "attributes": {"url": "https://example.test"}
        }})))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/v3/analyses/id/relationships/item"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"data": {
            "type": "url", "id": "url-id"
        }})))
        .expect(1)
        .mount(&server)
        .await;
    let client = client(&server);
    let item: Value = client.analyses().get_item("id").await.unwrap();
    assert_eq!(item["attributes"]["url"], "https://example.test");
    assert_eq!(
        client
            .analyses()
            .get_item_descriptor("id")
            .await
            .unwrap()
            .id,
        "url-id"
    );
}

#[tokio::test]
async fn polling_only_returns_after_explicit_completion() {
    let server = MockServer::start().await;
    let requests = Arc::new(AtomicUsize::new(0));
    let observed = Arc::clone(&requests);
    Mock::given(method("GET"))
        .and(path("/api/v3/analyses/id"))
        .respond_with(move |_: &wiremock::Request| {
            let statuses = ["queued", "in-progress", "completed"];
            let index = observed.fetch_add(1, Ordering::SeqCst).min(2);
            ResponseTemplate::new(200).set_body_json(report(statuses[index]))
        })
        .expect(3)
        .mount(&server)
        .await;
    let completed = client(&server)
        .analyses()
        .wait_for_completion("id", polling(5))
        .await
        .unwrap();
    assert!(completed.is_completed());
    assert_eq!(requests.load(Ordering::SeqCst), 3);
}

#[tokio::test]
async fn unknown_status_exhausts_attempts_without_partial_success() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v3/analyses/id"))
        .respond_with(ResponseTemplate::new(200).set_body_json(report("future-state")))
        .expect(3)
        .mount(&server)
        .await;
    let result = client(&server)
        .analyses()
        .wait_for_completion("id", polling(3))
        .await;
    assert!(matches!(result, Err(Error::DeadlineExceeded)));
}

#[tokio::test]
async fn polling_deadline_includes_inflight_request() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v3/analyses/id"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(report("completed"))
                .set_delay(Duration::from_secs(2)),
        )
        .mount(&server)
        .await;
    let options =
        AnalysisPollOptions::new(Duration::from_millis(1), Duration::from_millis(20), 5).unwrap();
    assert!(matches!(
        client(&server)
            .analyses()
            .wait_for_completion("id", options)
            .await,
        Err(Error::DeadlineExceeded)
    ));
}

#[tokio::test]
async fn polling_stops_on_api_failure_without_retrying() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v3/analyses/id"))
        .respond_with(ResponseTemplate::new(403).set_body_json(json!({"error": {
            "code": "ForbiddenError", "message": "Privilege required"
        }})))
        .expect(1)
        .mount(&server)
        .await;
    assert!(matches!(
        client(&server)
            .analyses()
            .wait_for_completion("id", polling(5))
            .await,
        Err(Error::Forbidden)
    ));
}

#[tokio::test]
async fn dropped_polling_future_does_not_spawn_later_requests() {
    let server = MockServer::start().await;
    let count = Arc::new(AtomicUsize::new(0));
    let observed = Arc::clone(&count);
    Mock::given(method("GET"))
        .and(path("/api/v3/analyses/id"))
        .respond_with(move |_: &wiremock::Request| {
            observed.fetch_add(1, Ordering::SeqCst);
            ResponseTemplate::new(200).set_body_json(report("queued"))
        })
        .mount(&server)
        .await;
    let client = client(&server);
    let analyses = client.analyses();
    let options =
        AnalysisPollOptions::new(Duration::from_secs(1), Duration::from_secs(30), 5).unwrap();
    let mut pending = Box::pin(analyses.wait_for_completion("id", options));
    tokio::select! {
        result = &mut pending => panic!("Unexpected polling completion: {result:?}"),
        () = async {
            while count.load(Ordering::SeqCst) == 0 {
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        } => {},
    }
    drop(pending);
    tokio::time::sleep(Duration::from_millis(20)).await;
    assert_eq!(count.load(Ordering::SeqCst), 1);
}
