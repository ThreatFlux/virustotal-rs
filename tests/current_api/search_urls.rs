//! Heterogeneous search and single-object URL relationship regressions.

use super::client;
use serde_json::{Value, json};
use virustotal_rs::Error;
use virustotal_rs::search::{SearchObject, SearchResult};
use wiremock::matchers::{method, path, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

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
