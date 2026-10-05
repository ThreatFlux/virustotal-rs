use serde_json::json;
use std::num::NonZeroUsize;
use virustotal_rs::{
    ApiTier, Client, ClientBuilder, CollectionIterator, CollectionIteratorAdapter,
    EnhancedCollectionIterator, PaginatedIterator,
};
use wiremock::matchers::{method, path, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

async fn fixture() -> (MockServer, Client) {
    let server = MockServer::start().await;
    let client = ClientBuilder::new()
        .api_key("fixture-api-key")
        .tier(ApiTier::Premium)
        .base_url(format!("{}/api/v3/", server.uri()))
        .build()
        .unwrap();
    (server, client)
}

fn iterator<'a>(
    client: &'a Client,
    enhanced: bool,
    url: &str,
    pages: usize,
    items: usize,
    size: u32,
) -> Box<dyn PaginatedIterator<String, Error = virustotal_rs::Error> + Send + 'a> {
    let pages = NonZeroUsize::new(pages).unwrap();
    let items = NonZeroUsize::new(items).unwrap();
    if enhanced {
        Box::new(
            EnhancedCollectionIterator::new(client, url)
                .with_limit(size)
                .with_bounds(pages, items),
        )
    } else {
        Box::new(CollectionIteratorAdapter::from(
            CollectionIterator::new(client, url)
                .with_limit(size)
                .with_bounds(pages, items),
        ))
    }
}

fn filtered_search_request() -> wiremock::MockBuilder {
    Mock::given(method("GET"))
        .and(path("/api/v3/intelligence/search"))
        .and(query_param("query", "type:file tag:a+b&c"))
        .and(query_param("limit", "2"))
}

#[tokio::test]
async fn opaque_cursor_and_existing_query_survive_an_empty_continuing_page() {
    for enhanced in [false, true] {
        let (server, client) = fixture().await;
        filtered_search_request()
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(json!({"data": [], "meta": {"cursor": "a+/=&? #"}})),
            )
            .up_to_n_times(1)
            .expect(1)
            .mount(&server)
            .await;
        filtered_search_request()
            .and(query_param("cursor", "a+/=&? #"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(json!({"data": ["found"], "meta": {"cursor": null}})),
            )
            .expect(1)
            .mount(&server)
            .await;
        let mut pager = iterator(
            &client,
            enhanced,
            "intelligence/search?query=type%3Afile+tag%3Aa%2Bb%26c&limit=99",
            3,
            10,
            2,
        );
        let mut items = Vec::new();
        while pager.has_more() {
            items.extend(pager.next_batch().await.unwrap());
        }
        assert_eq!(items, ["found"]);
        let requests = server.received_requests().await.unwrap();
        assert!(requests.iter().all(|request| {
            request
                .url
                .query_pairs()
                .filter(|(name, _)| name == "limit")
                .count()
                == 1
        }));
    }
}

#[tokio::test]
async fn repeated_cursor_and_longer_cycles_fail_before_repeating_a_request() {
    for enhanced in [false, true] {
        for cycle in [false, true] {
            let (server, client) = fixture().await;
            Mock::given(method("GET"))
                .and(path("/api/v3/fixture"))
                .respond_with(
                    ResponseTemplate::new(200)
                        .set_body_json(json!({"data": ["first"], "meta": {"cursor": "a"}})),
                )
                .up_to_n_times(1)
                .mount(&server)
                .await;
            Mock::given(method("GET"))
                .and(path("/api/v3/fixture"))
                .and(query_param("cursor", "a"))
                .respond_with(ResponseTemplate::new(200).set_body_json(
                    json!({"data": ["second"], "meta": {"cursor": if cycle { "b" } else { "a" }}}),
                ))
                .expect(1)
                .mount(&server)
                .await;
            if cycle {
                Mock::given(method("GET"))
                    .and(path("/api/v3/fixture"))
                    .and(query_param("cursor", "b"))
                    .respond_with(
                        ResponseTemplate::new(200)
                            .set_body_json(json!({"data": ["third"], "meta": {"cursor": "a"}})),
                    )
                    .expect(1)
                    .mount(&server)
                    .await;
            }
            let mut pager = iterator(&client, enhanced, "fixture", 10, 10, 2);
            assert_eq!(pager.next_batch().await.unwrap(), ["first"]);
            assert_eq!(pager.next_batch().await.unwrap(), ["second"]);
            if cycle {
                assert_eq!(pager.next_batch().await.unwrap(), ["third"]);
            }
            let error = pager.next_batch().await.unwrap_err().to_string();
            assert!(!error.contains("second"));
            assert_eq!(
                server.received_requests().await.unwrap().len(),
                if cycle { 3 } else { 2 }
            );
        }
    }
}

#[tokio::test]
async fn page_and_item_budgets_fail_instead_of_returning_partial_success() {
    for enhanced in [false, true] {
        let (server, client) = fixture().await;
        Mock::given(method("GET"))
            .and(path("/api/v3/fixture"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(json!({"data": ["one", "two"], "meta": {"cursor": "next"}})),
            )
            .mount(&server)
            .await;
        let mut pager = iterator(&client, enhanced, "fixture", 1, 10, 2);
        assert_eq!(pager.next_batch().await.unwrap().len(), 2);
        assert!(pager.next_batch().await.is_err());
        assert_eq!(server.received_requests().await.unwrap().len(), 1);
        let mut pager = iterator(&client, enhanced, "fixture", 10, 1, 2);
        assert!(pager.next_batch().await.is_err());
    }
}

#[tokio::test]
async fn zero_page_size_fails_before_http() {
    for enhanced in [false, true] {
        let (server, client) = fixture().await;
        let mut pager = iterator(&client, enhanced, "fixture", 2, 10, 0);
        assert!(pager.next_batch().await.is_err());
        assert!(server.received_requests().await.unwrap().is_empty());
    }
}

#[tokio::test]
async fn empty_cursor_terminates_and_next_links_are_not_followed() {
    for enhanced in [false, true] {
        let (server, client) = fixture().await;
        Mock::given(method("GET")).and(path("/api/v3/fixture"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"data": ["one"], "meta": {"cursor": ""}, "links": {"self": "fixture", "next": "https://invalid.example/unused"}})))
            .expect(1).mount(&server).await;
        let mut pager = iterator(&client, enhanced, "fixture", 2, 10, 2);
        assert_eq!(pager.next_batch().await.unwrap(), ["one"]);
        assert!(!pager.has_more());
        assert!(pager.next_batch().await.unwrap().is_empty());
    }
}

#[tokio::test]
async fn core_collect_all_continues_through_empty_pages() {
    let (server, client) = fixture().await;
    Mock::given(method("GET"))
        .and(path("/api/v3/fixture"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({"data": [], "meta": {"cursor": "next"}})),
        )
        .up_to_n_times(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/v3/fixture"))
        .and(query_param("cursor", "next"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"data": ["one"]})))
        .expect(1)
        .mount(&server)
        .await;
    assert_eq!(
        CollectionIterator::<String>::new(&client, "fixture")
            .collect_all()
            .await
            .unwrap(),
        ["one"]
    );
}

#[tokio::test]
async fn initial_endpoint_cursor_is_included_in_cycle_detection() {
    for enhanced in [false, true] {
        let (server, client) = fixture().await;
        Mock::given(method("GET"))
            .and(path("/api/v3/fixture"))
            .and(query_param("cursor", "initial+/="))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(json!({"data": ["one"], "meta": {"cursor": "initial+/="}})),
            )
            .expect(1)
            .mount(&server)
            .await;
        let mut pager = iterator(
            &client,
            enhanced,
            "fixture?cursor=initial%2B%2F%3D",
            10,
            10,
            2,
        );
        assert_eq!(pager.next_batch().await.unwrap(), ["one"]);
        assert!(pager.next_batch().await.is_err());
        assert_eq!(server.received_requests().await.unwrap().len(), 1);
    }
}
