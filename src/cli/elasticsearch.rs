//! Minimal Elasticsearch REST operations used by the CLI examples.
//!
//! This uses the SDK's stable HTTP dependency rather than the upstream
//! Elasticsearch Rust client, which currently publishes only alpha releases.

use anyhow::{Context, Result, bail};
use reqwest::{Client, Method, RequestBuilder, Response, StatusCode};
use serde_json::Value;
use std::time::Duration;
use url::Url;

/// HTTP client for the Elasticsearch operations used by the report indexer.
#[derive(Clone)]
pub struct ElasticsearchClient {
    client: Client,
    base_url: Url,
    credentials: Option<(String, Option<String>)>,
}

impl std::fmt::Debug for ElasticsearchClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ElasticsearchClient")
            .finish_non_exhaustive()
    }
}

impl ElasticsearchClient {
    /// Connect to an HTTP or HTTPS base URL, optionally with Basic authentication.
    ///
    /// Credentials belong in the separate arguments, never in the URL. Redirects
    /// are disabled so indexing requests cannot be redirected to another server.
    pub fn new(url: &str, username: Option<&str>, password: Option<&str>) -> Result<Self> {
        let base_url = Url::parse(url).map_err(|_| anyhow::anyhow!("Invalid Elasticsearch URL"))?;
        if !matches!(base_url.scheme(), "http" | "https")
            || base_url.host_str().is_none()
            || !base_url.username().is_empty()
            || base_url.password().is_some()
            || base_url.query().is_some()
            || base_url.fragment().is_some()
        {
            bail!("Elasticsearch URL must be HTTP(S) without credentials, query, or fragment");
        }
        if password.is_some() && username.is_none() {
            bail!("Elasticsearch password requires a username");
        }
        let client = Client::builder()
            .timeout(Duration::from_secs(30))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .context("Failed to build Elasticsearch HTTP client")?;
        Ok(Self {
            client,
            base_url,
            credentials: username.map(|name| (name.to_owned(), password.map(str::to_owned))),
        })
    }

    fn request(&self, method: Method, segments: &[&str]) -> Result<RequestBuilder> {
        let mut url = self.base_url.clone();
        let mut path = url
            .path_segments_mut()
            .map_err(|_| anyhow::anyhow!("Elasticsearch URL cannot contain path segments"))?;
        path.pop_if_empty();
        for segment in segments {
            if segment.is_empty() || matches!(*segment, "." | "..") {
                bail!("Elasticsearch path segment must be nonempty and cannot be a dot segment");
            }
            path.push(segment);
        }
        drop(path);
        let request = self.client.request(method, url);
        Ok(match &self.credentials {
            Some((username, password)) => request.basic_auth(username, password.as_deref()),
            None => request,
        })
    }

    async fn send(request: RequestBuilder) -> Result<Response> {
        request
            .send()
            .await
            .map_err(reqwest::Error::without_url)
            .context("Elasticsearch HTTP request failed")
    }

    async fn checked(request: RequestBuilder) -> Result<Response> {
        let response = Self::send(request).await?;
        if !response.status().is_success() {
            bail!("Elasticsearch returned HTTP {}", response.status());
        }
        Ok(response)
    }

    /// Check the connection and reject unsuccessful HTTP statuses.
    pub async fn ping(&self) -> Result<()> {
        Self::checked(self.request(Method::HEAD, &[])?).await?;
        Ok(())
    }

    /// Check whether an index exists. Only HTTP 404 means it is absent.
    pub async fn index_exists(&self, index: &str) -> Result<bool> {
        let response = Self::send(self.request(Method::HEAD, &[index])?).await?;
        match response.status() {
            StatusCode::NOT_FOUND => Ok(false),
            status if status.is_success() => Ok(true),
            status => bail!("Elasticsearch index check returned HTTP {status}"),
        }
    }

    /// Create an index with a JSON mapping.
    pub async fn create_index(&self, index: &str, mapping: &Value) -> Result<Response> {
        Self::checked(self.request(Method::PUT, &[index])?.json(mapping)).await
    }

    /// Delete an index, reporting unsuccessful HTTP statuses.
    pub async fn delete_index(&self, index: &str) -> Result<()> {
        Self::checked(self.request(Method::DELETE, &[index])?).await?;
        Ok(())
    }

    /// Submit newline-delimited bulk JSON with the required final newline.
    ///
    /// Callers must also inspect the response's `errors` field: individual bulk
    /// failures can be reported within an HTTP 200 response.
    pub async fn bulk(&self, body: String) -> Result<Response> {
        if !body.ends_with('\n') {
            bail!("Elasticsearch bulk body must end with a newline");
        }
        let request = self
            .request(Method::POST, &["_bulk"])?
            .header(reqwest::header::CONTENT_TYPE, "application/x-ndjson")
            .body(body);
        Self::checked(request).await
    }

    /// Search one index using a JSON query.
    pub async fn search(&self, index: &str, query: &Value) -> Result<Response> {
        Self::checked(self.request(Method::POST, &[index, "_search"])?.json(query)).await
    }

    /// Count the documents in one index.
    pub async fn count(&self, index: &str) -> Result<Response> {
        Self::checked(self.request(Method::GET, &[index, "_count"])?).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;
    use serde_json::json;
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{body_string, header, method, path},
    };

    #[tokio::test]
    async fn bulk_preserves_ndjson_and_basic_auth() {
        let server = MockServer::start().await;
        let body = "{\"index\":{\"_index\":\"reports\"}}\n{\"name\":\"résumé\"}\n";
        let password = uuid::Uuid::new_v4().to_string();
        let authorization = format!(
            "Basic {}",
            base64::engine::general_purpose::STANDARD.encode(format!("user:{password}"))
        );
        Mock::given(method("POST"))
            .and(path("/proxy/_bulk"))
            .and(header("content-type", "application/x-ndjson"))
            .and(header("authorization", authorization))
            .and(body_string(body))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"errors": true})))
            .expect(1)
            .mount(&server)
            .await;
        let client = ElasticsearchClient::new(
            &format!("{}/proxy/", server.uri()),
            Some("user"),
            Some(&password),
        )
        .unwrap();
        let response = client.bulk(body.into()).await.unwrap();
        assert_eq!(response.json::<Value>().await.unwrap()["errors"], true);
        assert_eq!(format!("{client:?}"), "ElasticsearchClient { .. }");
    }

    #[tokio::test]
    async fn status_errors_are_not_successful_connections_or_existing_indexes() {
        let server = MockServer::start().await;
        Mock::given(method("HEAD"))
            .and(path("/"))
            .respond_with(ResponseTemplate::new(401))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("HEAD"))
            .and(path("/missing"))
            .respond_with(ResponseTemplate::new(404))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("HEAD"))
            .and(path("/forbidden"))
            .respond_with(ResponseTemplate::new(403))
            .expect(1)
            .mount(&server)
            .await;
        let client = ElasticsearchClient::new(&server.uri(), None, None).unwrap();
        assert!(client.ping().await.unwrap_err().to_string().contains("401"));
        assert!(!client.index_exists("missing").await.unwrap());
        assert!(
            client
                .index_exists("forbidden")
                .await
                .unwrap_err()
                .to_string()
                .contains("403")
        );
    }

    #[tokio::test]
    async fn index_and_query_operations_use_expected_methods_and_encoded_segments() {
        let server = MockServer::start().await;
        for (verb, route) in [
            ("PUT", "/index%2Fname"),
            ("DELETE", "/index%2Fname"),
            ("POST", "/index%2Fname/_search"),
            ("GET", "/index%2Fname/_count"),
        ] {
            Mock::given(method(verb))
                .and(path(route))
                .respond_with(ResponseTemplate::new(200).set_body_json(json!({})))
                .expect(1)
                .mount(&server)
                .await;
        }
        let client = ElasticsearchClient::new(&server.uri(), None, None).unwrap();
        client
            .create_index("index/name", &json!({"mappings": {}}))
            .await
            .unwrap();
        client.delete_index("index/name").await.unwrap();
        client
            .search("index/name", &json!({"query": {"match_all": {}}}))
            .await
            .unwrap();
        client.count("index/name").await.unwrap();
    }

    #[tokio::test]
    async fn redirects_and_mutating_http_failures_are_rejected() {
        let server = MockServer::start().await;
        Mock::given(method("HEAD"))
            .and(path("/"))
            .respond_with(ResponseTemplate::new(302).insert_header("location", "/destination"))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("DELETE"))
            .and(path("/reports"))
            .respond_with(ResponseTemplate::new(503))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/_bulk"))
            .respond_with(ResponseTemplate::new(429))
            .expect(1)
            .mount(&server)
            .await;
        let client = ElasticsearchClient::new(&server.uri(), None, None).unwrap();
        assert!(client.ping().await.unwrap_err().to_string().contains("302"));
        assert!(
            client
                .delete_index("reports")
                .await
                .unwrap_err()
                .to_string()
                .contains("503")
        );
        assert!(
            client
                .bulk("{}\n".into())
                .await
                .unwrap_err()
                .to_string()
                .contains("429")
        );
        assert!(client.bulk("{}".into()).await.is_err());
        assert!(client.count("..").await.is_err());
    }

    #[test]
    fn rejects_credential_urls_without_retaining_the_input() {
        for url in [
            "http://user:private-password@localhost:9200",
            "http://localhost:9200?token=private-password",
            "ftp://localhost",
            "private-password",
        ] {
            let error = ElasticsearchClient::new(url, None, None).unwrap_err();
            assert!(!format!("{error:#?}").contains("private-password"));
        }
        assert!(ElasticsearchClient::new("http://localhost:9200", None, Some("password")).is_err());
    }
}
