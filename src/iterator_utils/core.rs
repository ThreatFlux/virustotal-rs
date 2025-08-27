//! Core iterator implementations

use super::traits::PaginatedIterator;
use crate::client_utils::RateLimiter;
use crate::{Client, Error, Result};
use serde::de::DeserializeOwned;
use std::marker::PhantomData;
use std::sync::Arc;

/// Configuration for enhanced collection iterator
#[derive(Clone, Default)]
pub struct IteratorConfig {
    pub cursor: Option<String>,
    pub limit: Option<u32>,
    pub rate_limiter: Option<Arc<crate::client_utils::TokenBucketLimiter>>,
}

impl std::fmt::Debug for IteratorConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IteratorConfig")
            .field("cursor", &self.cursor)
            .field("limit", &self.limit)
            .field(
                "rate_limiter",
                &self.rate_limiter.as_ref().map(|_| "TokenBucketLimiter"),
            )
            .finish()
    }
}

/// Enhanced collection iterator with rate limiting and progress tracking
pub struct EnhancedCollectionIterator<'a, T> {
    client: &'a Client,
    url: String,
    config: IteratorConfig,
    finished: bool,
    total_fetched: u64,
    batch_count: u32,
    _phantom: PhantomData<T>,
}

/// Constructor methods for EnhancedCollectionIterator
impl<'a, T> EnhancedCollectionIterator<'a, T>
where
    T: DeserializeOwned + Clone,
{
    /// Create a new enhanced iterator with default configuration
    pub fn new(client: &'a Client, url: impl Into<String>) -> Self {
        Self::with_config(client, url, IteratorConfig::default())
    }

    /// Create a new enhanced iterator with custom configuration
    pub fn with_config(client: &'a Client, url: impl Into<String>, config: IteratorConfig) -> Self {
        Self {
            client,
            url: url.into(),
            config,
            finished: false,
            total_fetched: 0,
            batch_count: 0,
            _phantom: PhantomData,
        }
    }
}

/// Builder pattern methods for EnhancedCollectionIterator
impl<'a, T> EnhancedCollectionIterator<'a, T>
where
    T: DeserializeOwned + Clone,
{
    /// Set batch size limit
    pub fn with_limit(mut self, limit: u32) -> Self {
        self.config.limit = Some(limit);
        self
    }

    /// Set custom rate limiter
    pub fn with_rate_limiter(
        mut self,
        limiter: Arc<crate::client_utils::TokenBucketLimiter>,
    ) -> Self {
        self.config.rate_limiter = Some(limiter);
        self
    }
}

/// Accessor methods for EnhancedCollectionIterator
impl<'a, T> EnhancedCollectionIterator<'a, T>
where
    T: DeserializeOwned + Clone,
{
    /// Get total items fetched so far
    pub fn total_fetched(&self) -> u64 {
        self.total_fetched
    }

    /// Get number of batches fetched
    pub fn batch_count(&self) -> u32 {
        self.batch_count
    }
}

/// Internal utility methods for EnhancedCollectionIterator
impl<'a, T> EnhancedCollectionIterator<'a, T>
where
    T: DeserializeOwned + Clone,
{
    /// Build the API URL with query parameters
    fn build_url(&self) -> String {
        let mut url = self.url.clone();
        let mut query_params = Vec::new();

        if let Some(cursor) = &self.config.cursor {
            query_params.push(format!("cursor={}", cursor));
        }

        if let Some(limit) = self.config.limit {
            query_params.push(format!("limit={}", limit));
        }

        if !query_params.is_empty() {
            url = format!("{}?{}", url, query_params.join("&"));
        }

        url
    }

    /// Process API response and update iterator state
    fn process_response(&mut self, response: crate::objects::Collection<T>) -> Vec<T> {
        let items = response.data;
        self.total_fetched += items.len() as u64;
        self.batch_count += 1;

        if let Some(meta) = response.meta {
            self.config.cursor = meta.cursor;
            if self.config.cursor.is_none() {
                self.finished = true;
            }
        } else {
            self.finished = true;
        }

        items
    }
}

#[async_trait::async_trait]
impl<'a, T> PaginatedIterator<T> for EnhancedCollectionIterator<'a, T>
where
    T: DeserializeOwned + Clone + Send + Sync,
{
    type Error = Error;

    async fn next_batch(&mut self) -> Result<Vec<T>> {
        if self.finished {
            return Ok(Vec::new());
        }

        // Apply rate limiting if configured
        if let Some(ref limiter) = self.config.rate_limiter {
            limiter.check_rate_limit().await?;
        }

        let url = self.build_url();
        let response: crate::objects::Collection<T> = self.client.get(&url).await?;
        let items = self.process_response(response);

        Ok(items)
    }

    fn has_more(&self) -> bool {
        !self.finished
    }

    fn hint_remaining(&self) -> Option<usize> {
        // We don't have enough info to estimate remaining items
        None
    }

    fn stats(&self) -> super::traits::IteratorStats {
        super::traits::IteratorStats {
            batches_fetched: self.batch_count as u64,
            items_fetched: self.total_fetched,
            ..Default::default()
        }
    }
}

// Note: Extension methods for CollectionIterator would need public fields
// or accessor methods. For now, use EnhancedCollectionIterator directly.

/// Adapter to convert CollectionIterator to PaginatedIterator
pub struct CollectionIteratorAdapter<'a, T> {
    inner: crate::objects::CollectionIterator<'a, T>,
}

#[async_trait::async_trait]
impl<'a, T> PaginatedIterator<T> for CollectionIteratorAdapter<'a, T>
where
    T: DeserializeOwned + Clone + Send + Sync,
{
    type Error = Error;

    async fn next_batch(&mut self) -> Result<Vec<T>> {
        if self.inner.is_finished() {
            return Ok(Vec::new());
        }

        self.inner.next_batch().await
    }

    fn has_more(&self) -> bool {
        !self.inner.is_finished()
    }
}

impl<'a, T> From<crate::objects::CollectionIterator<'a, T>> for CollectionIteratorAdapter<'a, T> {
    fn from(inner: crate::objects::CollectionIterator<'a, T>) -> Self {
        Self { inner }
    }
}
