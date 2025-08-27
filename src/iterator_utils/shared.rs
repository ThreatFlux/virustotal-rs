//! Shared iterator patterns and utilities to reduce code duplication

use crate::objects::{CollectionIterator, ObjectOperations};
use crate::Client;
use serde::de::DeserializeOwned;

/// Common iterator creation utilities for API relationships
pub struct RelationshipIteratorBuilder;

impl RelationshipIteratorBuilder {
    /// Create a standard relationship iterator for any object type that implements ObjectOperations
    pub fn create<'a, T, R>(
        client: &'a Client,
        object_id: &str,
        relationship: &str,
    ) -> CollectionIterator<'a, R>
    where
        T: ObjectOperations,
        R: DeserializeOwned + Clone,
    {
        let url = T::relationship_objects_url(object_id, relationship);
        CollectionIterator::new(client, url)
    }

    /// Create a relationship iterator with custom URL building
    pub fn create_with_url<'a, R>(client: &'a Client, url: String) -> CollectionIterator<'a, R>
    where
        R: DeserializeOwned + Clone,
    {
        CollectionIterator::new(client, url)
    }
}

/// Builder pattern for constructing paginated API URLs with query parameters
pub struct QueryUrlBuilder {
    base_url: String,
    params: Vec<(String, String)>,
}

impl QueryUrlBuilder {
    /// Create a new builder with a base URL
    pub fn new(base_url: impl Into<String>) -> Self {
        Self {
            base_url: base_url.into(),
            params: Vec::new(),
        }
    }

    /// Add a filter parameter
    pub fn filter(mut self, filter: &str) -> Self {
        self.params.push((
            "filter".to_string(),
            urlencoding::encode(filter).to_string(),
        ));
        self
    }

    /// Add an order parameter
    pub fn order(mut self, order: &str) -> Self {
        self.params.push(("order".to_string(), order.to_string()));
        self
    }

    /// Add a limit parameter
    pub fn limit(mut self, limit: u32) -> Self {
        self.params.push(("limit".to_string(), limit.to_string()));
        self
    }

    /// Add a cursor parameter
    pub fn cursor(mut self, cursor: &str) -> Self {
        self.params.push((
            "cursor".to_string(),
            urlencoding::encode(cursor).to_string(),
        ));
        self
    }

    /// Add any custom parameter
    pub fn param<K, V>(mut self, key: K, value: V) -> Self
    where
        K: Into<String>,
        V: ToString,
    {
        self.params.push((key.into(), value.to_string()));
        self
    }

    /// Add an optional parameter if the value is Some
    pub fn optional_param<K, V>(self, key: K, value: Option<V>) -> Self
    where
        K: Into<String>,
        V: ToString,
    {
        match value {
            Some(v) => self.param(key, v),
            None => self,
        }
    }

    /// Build the final URL with query parameters
    pub fn build(self) -> String {
        if self.params.is_empty() {
            self.base_url
        } else {
            let query_string = self
                .params
                .into_iter()
                .map(|(k, v)| format!("{}={}", k, v))
                .collect::<Vec<_>>()
                .join("&");
            format!("{}?{}", self.base_url, query_string)
        }
    }

    /// Build the URL and remove trailing '&' or '?' if present
    pub fn build_clean(self) -> String {
        let mut url = self.build();
        if url.ends_with('&') || url.ends_with('?') {
            url.pop();
        }
        url
    }
}

/// Generic iterator creation pattern for listing APIs with optional parameters
pub struct ListIteratorBuilder<'a> {
    client: &'a Client,
    base_endpoint: String,
}

impl<'a> ListIteratorBuilder<'a> {
    pub fn new(client: &'a Client, base_endpoint: impl Into<String>) -> Self {
        Self {
            client,
            base_endpoint: base_endpoint.into(),
        }
    }

    /// Create an iterator with optional filter and order parameters
    pub fn create<T>(self, filter: Option<&str>, order: Option<&str>) -> CollectionIterator<'a, T>
    where
        T: DeserializeOwned + Clone,
    {
        let mut builder = QueryUrlBuilder::new(self.base_endpoint);

        if let Some(f) = filter {
            builder = builder.filter(f);
        }

        if let Some(o) = order {
            builder = builder.order(o);
        }

        let url = builder.build_clean();
        CollectionIterator::new(self.client, url)
    }

    /// Create an iterator with custom query builder
    pub fn create_with_builder<T>(
        self,
        query_builder: impl FnOnce(QueryUrlBuilder) -> QueryUrlBuilder,
    ) -> CollectionIterator<'a, T>
    where
        T: DeserializeOwned + Clone,
    {
        let builder = QueryUrlBuilder::new(self.base_endpoint);
        let url = query_builder(builder).build_clean();
        CollectionIterator::new(self.client, url)
    }
}

/// Common pattern for building relationship descriptor URLs
pub struct RelationshipUrlBuilder;

impl RelationshipUrlBuilder {
    /// Build a relationship URL for object relationships
    pub fn build_objects_url(collection: &str, object_id: &str, relationship: &str) -> String {
        format!(
            "{}/{}/{}",
            collection,
            urlencoding::encode(object_id),
            relationship
        )
    }

    /// Build a relationship descriptors URL
    pub fn build_descriptors_url(collection: &str, object_id: &str, relationship: &str) -> String {
        format!(
            "{}/{}/relationships/{}",
            collection,
            urlencoding::encode(object_id),
            relationship
        )
    }

    /// Build a URL with optional pagination parameters
    pub fn build_paginated_url(
        base_url: String,
        limit: Option<u32>,
        cursor: Option<&str>,
    ) -> String {
        QueryUrlBuilder::new(base_url)
            .optional_param("limit", limit)
            .optional_param("cursor", cursor)
            .build_clean()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_query_url_builder() {
        let url = QueryUrlBuilder::new("api/test")
            .filter("status:active")
            .order("date-")
            .limit(100)
            .cursor("next_page")
            .build();

        assert!(url.contains("filter=status%3Aactive"));
        assert!(url.contains("order=date-"));
        assert!(url.contains("limit=100"));
        assert!(url.contains("cursor=next_page"));
    }

    #[test]
    fn test_query_url_builder_clean() {
        let url = QueryUrlBuilder::new("api/test").build_clean();
        assert_eq!(url, "api/test");

        let url_with_params = QueryUrlBuilder::new("api/test")
            .param("key", "value")
            .build_clean();
        assert_eq!(url_with_params, "api/test?key=value");
    }

    #[test]
    fn test_relationship_url_builder() {
        let objects_url = RelationshipUrlBuilder::build_objects_url("files", "test_id", "comments");
        assert_eq!(objects_url, "files/test_id/comments");

        let descriptors_url =
            RelationshipUrlBuilder::build_descriptors_url("files", "test_id", "comments");
        assert_eq!(descriptors_url, "files/test_id/relationships/comments");
    }

    #[test]
    fn test_optional_param() {
        let url = QueryUrlBuilder::new("api/test")
            .optional_param("limit", Some(50))
            .optional_param("cursor", None::<&str>)
            .build();

        assert!(url.contains("limit=50"));
        assert!(!url.contains("cursor"));
    }
}
