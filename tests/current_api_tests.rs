//! Offline regressions based on the documented VirusTotal API v3 wire contracts.

use serde_json::{Value, json};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;
use virustotal_rs::analysis::{AnalysisPollOptions, AnalysisReport, AnalysisStatus};
use virustotal_rs::search::{SearchObject, SearchResult};
use virustotal_rs::{ApiTier, Client, ClientBuilder, Error};
use wiremock::matchers::{header, method, path, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn client(server: &MockServer) -> Client {
    ClientBuilder::new()
        .api_key("offline-fixture")
        .tier(ApiTier::Premium)
        .base_url(format!("{}/api/v3/", server.uri()))
        .build()
        .unwrap()
}

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
fn legacy_search_dispatches_all_documented_discriminators() {
    let fixtures = ["file", "url", "domain", "ip_address", "comment"];
    for kind in fixtures {
        let result: SearchResult =
            serde_json::from_value(json!({"type": kind, "id": "object-id"})).unwrap();
        let actual = match result {
            SearchResult::File(_) => "file",
            SearchResult::Url(_) => "url",
            SearchResult::Domain(_) => "domain",
            SearchResult::IpAddress(_) => "ip_address",
            SearchResult::Comment(_) => "comment",
        };
        assert_eq!(actual, kind);
    }
}

#[test]
fn malformed_known_search_objects_do_not_fall_back_to_files() {
    for value in [
        json!({"type": "comment", "id": "id", "attributes": {"text": 42}}),
        json!({"type": "url"}),
        json!({"type": 3, "id": "id"}),
        json!({"type": "future-object", "id": "id"}),
    ] {
        assert!(serde_json::from_value::<SearchResult>(value).is_err());
    }
}

#[test]
fn future_search_objects_retain_nested_payloads_and_context() {
    let value = json!({
        "type": "future-object", "id": "id", "attributes": {"new": [1, 2]},
        "context_attributes": {"new_context": {"opaque": true}}, "extension": "retained"
    });
    let object: SearchObject = serde_json::from_value(value.clone()).unwrap();
    assert_eq!(serde_json::to_value(object).unwrap(), value);
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

#[tokio::test]
async fn current_intelligence_search_preserves_objects_metadata_and_encoded_sort() {
    let server = MockServer::start().await;
    let response = json!({
        "data": [{"type": "domain", "id": "example.test", "attributes": {"new": true}}],
        "meta": {"days_back": 365, "cursor": "next", "new": {"opaque": true}},
        "new_top_level": [1, 2]
    });
    Mock::given(method("GET"))
        .and(path("/api/v3/intelligence/search"))
        .and(query_param("query", "entity:domain foo & bar"))
        .and(query_param("order", "first_submission_date+"))
        .and(query_param("cursor", "a+b/c?=&next"))
        .and(query_param("limit", "40"))
        .and(query_param("descriptors_only", "false"))
        .respond_with(ResponseTemplate::new(200).set_body_json(response.clone()))
        .expect(1)
        .mount(&server)
        .await;
    let result = client(&server)
        .search()
        .intelligence_search_objects(
            "entity:domain foo & bar",
            Some(virustotal_rs::SearchOrder::FirstSubmissionDateAsc),
            Some(40),
            Some("a+b/c?=&next"),
            false,
        )
        .await
        .unwrap();
    assert_eq!(serde_json::to_value(result).unwrap(), response);
}

#[tokio::test]
async fn general_search_current_and_legacy_keep_the_expected_object_kinds() {
    let server = MockServer::start().await;
    let payload = json!({"data": [
        {"type": "url", "id": "url-id", "attributes": {"url": "https://example.test"}},
        {"type": "comment", "id": "comment-id", "attributes": {"text": "fixture"}}
    ], "meta": {"new": "retained"}});
    Mock::given(method("GET"))
        .and(path("/api/v3/search"))
        .and(query_param("query", "tag:a+b & c"))
        .respond_with(ResponseTemplate::new(200).set_body_json(payload.clone()))
        .expect(2)
        .mount(&server)
        .await;
    let client = client(&server);
    let page = client.search().search_objects("tag:a+b & c").await.unwrap();
    assert_eq!(serde_json::to_value(page).unwrap(), payload);
    let legacy = client.search().search("tag:a+b & c").await.unwrap();
    assert!(matches!(&legacy.data[0], SearchResult::Url(_)));
    assert!(matches!(&legacy.data[1], SearchResult::Comment(_)));
}

#[tokio::test]
async fn current_intelligence_iterator_preserves_query_sort_and_opaque_cursor() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v3/intelligence/search"))
        .and(query_param("query", "entity:domain tag:a+b"))
        .and(query_param("order", "last_update_date+"))
        .and(query_param("descriptors_only", "true"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": [], "meta": {"cursor": "a+/=&? #"}
        })))
        .up_to_n_times(1)
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/v3/intelligence/search"))
        .and(query_param("query", "entity:domain tag:a+b"))
        .and(query_param("order", "last_update_date+"))
        .and(query_param("descriptors_only", "true"))
        .and(query_param("cursor", "a+/=&? #"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": [{"type": "domain", "id": "example.test"}]
        })))
        .expect(1)
        .mount(&server)
        .await;
    let client = client(&server);
    let search = client.search();
    let items = search
        .intelligence_search_objects_iterator(
            "entity:domain tag:a+b",
            Some(virustotal_rs::SearchOrder::LastUpdateDateAsc),
            true,
        )
        .collect_all()
        .await
        .unwrap();
    assert_eq!(items[0].object_type, "domain");
    assert_eq!(items.len(), 1);
}

#[tokio::test]
async fn current_search_propagates_privilege_errors_without_retrying() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v3/intelligence/search"))
        .respond_with(ResponseTemplate::new(403).set_body_json(json!({"error": {
            "code": "ForbiddenError", "message": "Privilege required"
        }})))
        .expect(1)
        .mount(&server)
        .await;
    let result = client(&server)
        .search()
        .intelligence_search_objects("query", None, None, None, false)
        .await;
    assert!(matches!(result, Err(Error::Forbidden)));
}

#[tokio::test]
async fn invalid_current_search_limit_sends_no_request() {
    let server = MockServer::start().await;
    let client = client(&server);
    for limit in [0, 301, u32::MAX] {
        assert!(matches!(
            client
                .search()
                .intelligence_search_objects("query", None, Some(limit), None, false)
                .await,
            Err(Error::InvalidArgument(_))
        ));
    }
    assert!(server.received_requests().await.unwrap().is_empty());
}

#[tokio::test]
async fn legacy_intelligence_sort_plus_is_not_decoded_as_space() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v3/intelligence/search"))
        .and(query_param("order", "size+"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"data": []})))
        .expect(1)
        .mount(&server)
        .await;
    client(&server)
        .search()
        .intelligence_search(
            "query",
            Some(virustotal_rs::SearchOrder::SizeAsc),
            None,
            false,
        )
        .await
        .unwrap();
}

#[tokio::test]
async fn snippets_encode_opaque_identifier_as_one_path_segment() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v3/intelligence/search/snippets/id%2F%2B%3F%23"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"data": ["snippet"]})))
        .expect(1)
        .mount(&server)
        .await;
    assert_eq!(
        client(&server)
            .search()
            .get_snippet("id/+?#")
            .await
            .unwrap()
            .data,
        ["snippet"]
    );
}

#[tokio::test]
async fn url_single_ip_and_network_location_accept_single_object_envelopes() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v3/urls/url%2Fid/last_serving_ip_address"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"data": {
            "type": "ip_address", "id": "192.0.2.1", "attributes": {"country": "XX"}
        }, "meta": {"count": 1}})))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/v3/urls/url%2Fid/network_location"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"data": {
            "type": "domain", "id": "example.test", "attributes": {"future": "retained"}
        }})))
        .expect(1)
        .mount(&server)
        .await;
    let client = client(&server);
    assert_eq!(
        client
            .urls()
            .get_last_serving_ip_address_object("url/id")
            .await
            .unwrap()
            .object
            .id,
        "192.0.2.1"
    );
    let domain: Value = client.urls().get_network_location("url/id").await.unwrap();
    assert_eq!(domain["attributes"]["future"], "retained");
}

#[tokio::test]
async fn url_single_ip_rejects_wrong_discriminator_and_api_errors() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v3/urls/id/last_serving_ip_address"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"data": {
            "type": "domain", "id": "example.test", "attributes": {}
        }})))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/v3/urls/missing/network_location"))
        .respond_with(ResponseTemplate::new(404).set_body_json(json!({"error": {
            "code": "NotFoundError", "message": "Missing"
        }})))
        .mount(&server)
        .await;
    let client = client(&server);
    assert!(matches!(
        client.urls().get_last_serving_ip_address_object("id").await,
        Err(Error::BadRequest(_))
    ));
    assert!(matches!(
        client.urls().get_network_location::<Value>("missing").await,
        Err(Error::NotFound)
    ));
}
