//! Iterator utilities and patterns for VirusTotal API
//!
//! This module provides comprehensive iterator utilities that eliminate duplication
//! across the library by providing reusable patterns for:
//!
//! - Paginated API responses
//! - Rate limit-aware iteration
//! - Batch processing
//! - Stream conversion
//! - Retry logic
//! - Progress tracking
//!
//! # Examples
//!
//! ## Basic paginated iteration
//!
//! ```ignore
//! use virustotal_rs::iterator_utils::PaginatedIterator;
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! # use virustotal_rs::{Client, ApiTier, Result};
//! # let client = Client::new("api_key".into(), ApiTier::Public)?;
//! // Use the enhanced iterator utilities with existing iterators
//! let collection_iter = client.comments().get_latest_iterator(None);
//! let mut enhanced_iter = collection_iter.into_enhanced();
//!
//! while enhanced_iter.has_more() {
//!     let batch = enhanced_iter.next_batch().await?;
//!     for comment in &batch {
//!         println!("Comment: {}", comment.object.attributes.text);
//!     }
//! }
//! # Ok(())
//! # }
//! ```
//!
//! ## Throttled iteration with progress
//!
//! ```ignore
//! use virustotal_rs::iterator_utils::{IteratorExt, ProgressTracker};
//! use std::time::Duration;
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! # use virustotal_rs::{Client, ApiTier, Result};
//! # let client = Client::new("api_key".into(), ApiTier::Public)?;
//! let collection_iter = client.comments().get_latest_iterator(None);
//! let iter = collection_iter.into_enhanced()
//!     .throttle(Duration::from_millis(500))
//!     .with_progress(ProgressTracker::new("Processing comments"));
//!     
//! let all_comments = iter.collect_all().await?;
//! # Ok(())
//! # }
//! ```

use crate::{Client, Error, Result};
use serde::de::DeserializeOwned;
use std::collections::HashSet;
use std::marker::PhantomData;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};
use tokio::sync::RwLock;
use tokio::time::sleep;

/// Generic paginated iterator trait for API responses
#[async_trait::async_trait]
pub trait PaginatedIterator<T: Send> {
    type Error: std::error::Error + Send + Sync + 'static;

    /// Fetch the next batch of items
    async fn next_batch(&mut self) -> std::result::Result<Vec<T>, Self::Error>;

    /// Check if there are more items to fetch
    fn has_more(&self) -> bool;

    /// Collect all remaining items
    async fn collect_all(mut self) -> std::result::Result<Vec<T>, Self::Error>
    where
        Self: Sized,
    {
        let mut all_items = Vec::new();

        while self.has_more() {
            let batch = self.next_batch().await?;
            if batch.is_empty() {
                break;
            }
            all_items.extend(batch);
        }

        Ok(all_items)
    }

    /// Collect into a HashSet (useful for deduplication)
    async fn collect_set(self) -> std::result::Result<HashSet<T>, Self::Error>
    where
        Self: Sized,
        T: Eq + std::hash::Hash,
    {
        let items = self.collect_all().await?;
        Ok(items.into_iter().collect())
    }
}

/// Trait for types that support pagination
pub trait Pageable<T>
where
    T: DeserializeOwned + Clone + Send,
{
    /// Convert into a paginated iterator
    fn into_iterator(self) -> Box<dyn PaginatedIterator<T, Error = Error> + Send>;

    /// Set the batch size for pagination
    fn with_limit(self, limit: u32) -> Self;
}

/// Extension trait for iterator utilities
pub trait IteratorExt<T: Send>: PaginatedIterator<T> {
    /// Map items during iteration
    fn map<U, F>(self, f: F) -> MappedIterator<Self, T, U, F>
    where
        Self: Sized,
        F: Fn(T) -> U + Send + Sync,
        U: Send,
    {
        MappedIterator::new(self, f)
    }

    /// Filter items during iteration
    fn filter<F>(self, predicate: F) -> FilteredIterator<Self, T, F>
    where
        Self: Sized,
        F: Fn(&T) -> bool + Send + Sync,
    {
        FilteredIterator::new(self, predicate)
    }

    /// Take items until condition is met
    fn take_until<F>(self, condition: F) -> TakeUntilIterator<Self, T, F>
    where
        Self: Sized,
        F: Fn(&T) -> bool + Send + Sync,
    {
        TakeUntilIterator::new(self, condition)
    }

    /// Group items into batches
    fn batch(self, size: usize) -> BatchIterator<Self, T>
    where
        Self: Sized,
    {
        BatchIterator::new(self, size)
    }

    /// Add throttling between batches
    fn throttle(self, delay: Duration) -> ThrottledIterator<Self, T>
    where
        Self: Sized,
    {
        ThrottledIterator::new(self, delay)
    }

    /// Add retry logic for failures
    fn retry_on_error(self, max_retries: u32, delay: Duration) -> RetryIterator<Self, T>
    where
        Self: Sized,
    {
        RetryIterator::new(self, max_retries, delay)
    }

    /// Add progress tracking
    fn with_progress(self, tracker: ProgressTracker) -> ProgressIterator<Self, T>
    where
        Self: Sized,
    {
        ProgressIterator::new(self, tracker)
    }

    /// Cache results for reuse
    fn cached(self) -> CachedIterator<Self, T>
    where
        Self: Sized,
        T: Clone,
    {
        CachedIterator::new(self)
    }
}

// Implement IteratorExt for all PaginatedIterator types
impl<I, T: Send> IteratorExt<T> for I where I: PaginatedIterator<T> {}

/// Progress tracker for iterator operations
#[derive(Debug, Clone)]
pub struct ProgressTracker {
    pub name: String,
    pub items_processed: Arc<RwLock<u64>>,
    pub batches_processed: Arc<RwLock<u32>>,
    pub start_time: SystemTime,
    pub last_update: Arc<RwLock<SystemTime>>,
    pub update_interval: Duration,
}

impl ProgressTracker {
    /// Create a new progress tracker
    pub fn new(name: impl Into<String>) -> Self {
        let now = SystemTime::now();
        Self {
            name: name.into(),
            items_processed: Arc::new(RwLock::new(0)),
            batches_processed: Arc::new(RwLock::new(0)),
            start_time: now,
            last_update: Arc::new(RwLock::new(now)),
            update_interval: Duration::from_secs(1),
        }
    }

    /// Set the update interval for progress reports
    pub fn with_update_interval(mut self, interval: Duration) -> Self {
        self.update_interval = interval;
        self
    }

    /// Update progress with new batch
    pub async fn update_batch(&self, batch_size: usize) {
        let mut items = self.items_processed.write().await;
        let mut batches = self.batches_processed.write().await;
        let mut last_update = self.last_update.write().await;

        *items += batch_size as u64;
        *batches += 1;

        let now = SystemTime::now();
        if now.duration_since(*last_update).unwrap_or(Duration::ZERO) >= self.update_interval {
            let elapsed = now
                .duration_since(self.start_time)
                .unwrap_or(Duration::ZERO);
            let rate = *items as f64 / elapsed.as_secs_f64();

            println!(
                "[{}] Processed {} items in {} batches ({:.2} items/sec)",
                self.name, *items, *batches, rate
            );

            *last_update = now;
        }
    }

    /// Get current statistics
    pub async fn stats(&self) -> ProgressStats {
        let items = *self.items_processed.read().await;
        let batches = *self.batches_processed.read().await;
        let elapsed = SystemTime::now()
            .duration_since(self.start_time)
            .unwrap_or(Duration::ZERO);
        let rate = items as f64 / elapsed.as_secs_f64();

        ProgressStats {
            items_processed: items,
            batches_processed: batches,
            elapsed,
            items_per_second: rate,
        }
    }
}

/// Progress statistics
#[derive(Debug, Clone)]
pub struct ProgressStats {
    pub items_processed: u64,
    pub batches_processed: u32,
    pub elapsed: Duration,
    pub items_per_second: f64,
}

/// Enhanced collection iterator with pagination state management
pub struct EnhancedCollectionIterator<'a, T> {
    client: &'a Client,
    url: String,
    cursor: Option<String>,
    finished: bool,
    limit: Option<u32>,
    total_fetched: u64,
    batch_count: u32,
    rate_limiter: Option<Arc<crate::client_utils::TokenBucketLimiter>>,
    _phantom: PhantomData<T>,
}

impl<'a, T> EnhancedCollectionIterator<'a, T>
where
    T: DeserializeOwned + Clone,
{
    /// Create a new enhanced iterator
    pub fn new(client: &'a Client, url: impl Into<String>) -> Self {
        Self {
            client,
            url: url.into(),
            cursor: None,
            finished: false,
            limit: None,
            total_fetched: 0,
            batch_count: 0,
            rate_limiter: None,
            _phantom: PhantomData,
        }
    }

    /// Set batch size limit
    pub fn with_limit(mut self, limit: u32) -> Self {
        self.limit = Some(limit);
        self
    }

    /// Set custom rate limiter
    pub fn with_rate_limiter(
        mut self,
        limiter: Arc<crate::client_utils::TokenBucketLimiter>,
    ) -> Self {
        self.rate_limiter = Some(limiter);
        self
    }

    /// Get total items fetched so far
    pub fn total_fetched(&self) -> u64 {
        self.total_fetched
    }

    /// Get number of batches fetched
    pub fn batch_count(&self) -> u32 {
        self.batch_count
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
        if let Some(ref limiter) = self.rate_limiter {
            use crate::client_utils::RateLimiter;
            limiter.check_rate_limit().await?;
        }

        let mut url = self.url.clone();
        let mut query_params = Vec::new();

        if let Some(cursor) = &self.cursor {
            query_params.push(format!("cursor={}", cursor));
        }

        if let Some(limit) = self.limit {
            query_params.push(format!("limit={}", limit));
        }

        if !query_params.is_empty() {
            url = format!("{}?{}", url, query_params.join("&"));
        }

        let response: crate::objects::Collection<T> = self.client.get(&url).await?;

        let items = response.data;
        self.total_fetched += items.len() as u64;
        self.batch_count += 1;

        if let Some(meta) = response.meta {
            self.cursor = meta.cursor;
            if self.cursor.is_none() {
                self.finished = true;
            }
        } else {
            self.finished = true;
        }

        Ok(items)
    }

    fn has_more(&self) -> bool {
        !self.finished
    }
}

// Extension methods for CollectionIterator
impl<'a, T> crate::objects::CollectionIterator<'a, T>
where
    T: DeserializeOwned + Clone + Send + Sync + 'static,
{
    /// Convert to enhanced iterator utilities
    pub fn into_enhanced(self) -> CollectionIteratorAdapter<'a, T> {
        CollectionIteratorAdapter { inner: self }
    }
}

/// Adapter to make CollectionIterator work with PaginatedIterator
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
        self.inner.next_batch().await
    }

    fn has_more(&self) -> bool {
        !self.inner.is_finished()
    }
}

/// Mapped iterator adapter
pub struct MappedIterator<I, T, U, F> {
    inner: I,
    mapper: F,
    _phantom: PhantomData<(T, U)>,
}

impl<I, T, U, F> MappedIterator<I, T, U, F> {
    pub fn new(inner: I, mapper: F) -> Self {
        Self {
            inner,
            mapper,
            _phantom: PhantomData,
        }
    }
}

#[async_trait::async_trait]
impl<I, T, U, F> PaginatedIterator<U> for MappedIterator<I, T, U, F>
where
    I: PaginatedIterator<T> + Send,
    T: Send,
    U: Send,
    F: Fn(T) -> U + Send + Sync,
    I::Error: Send + Sync,
{
    type Error = I::Error;

    async fn next_batch(&mut self) -> std::result::Result<Vec<U>, Self::Error> {
        let batch = self.inner.next_batch().await?;
        Ok(batch.into_iter().map(&self.mapper).collect())
    }

    fn has_more(&self) -> bool {
        self.inner.has_more()
    }
}

/// Filtered iterator adapter
pub struct FilteredIterator<I, T, F> {
    inner: I,
    predicate: F,
    _phantom: PhantomData<T>,
}

impl<I, T, F> FilteredIterator<I, T, F> {
    pub fn new(inner: I, predicate: F) -> Self {
        Self {
            inner,
            predicate,
            _phantom: PhantomData,
        }
    }
}

#[async_trait::async_trait]
impl<I, T, F> PaginatedIterator<T> for FilteredIterator<I, T, F>
where
    I: PaginatedIterator<T> + Send,
    T: Send,
    F: Fn(&T) -> bool + Send + Sync,
    I::Error: Send + Sync,
{
    type Error = I::Error;

    async fn next_batch(&mut self) -> std::result::Result<Vec<T>, Self::Error> {
        // Keep fetching until we have items or no more data
        loop {
            let batch = self.inner.next_batch().await?;
            if batch.is_empty() {
                return Ok(batch);
            }

            let filtered: Vec<T> = batch.into_iter().filter(&self.predicate).collect();
            if !filtered.is_empty() || !self.inner.has_more() {
                return Ok(filtered);
            }
        }
    }

    fn has_more(&self) -> bool {
        self.inner.has_more()
    }
}

/// Take until condition iterator adapter
pub struct TakeUntilIterator<I, T, F> {
    inner: I,
    condition: F,
    finished: bool,
    _phantom: PhantomData<T>,
}

impl<I, T, F> TakeUntilIterator<I, T, F> {
    pub fn new(inner: I, condition: F) -> Self {
        Self {
            inner,
            condition,
            finished: false,
            _phantom: PhantomData,
        }
    }
}

#[async_trait::async_trait]
impl<I, T, F> PaginatedIterator<T> for TakeUntilIterator<I, T, F>
where
    I: PaginatedIterator<T> + Send,
    T: Send,
    F: Fn(&T) -> bool + Send + Sync,
    I::Error: Send + Sync,
{
    type Error = I::Error;

    async fn next_batch(&mut self) -> std::result::Result<Vec<T>, Self::Error> {
        if self.finished {
            return Ok(Vec::new());
        }

        let batch = self.inner.next_batch().await?;
        let mut result = Vec::new();

        for item in batch {
            if (self.condition)(&item) {
                self.finished = true;
                break;
            }
            result.push(item);
        }

        Ok(result)
    }

    fn has_more(&self) -> bool {
        !self.finished && self.inner.has_more()
    }
}

/// Batch iterator adapter
pub struct BatchIterator<I, T> {
    inner: I,
    batch_size: usize,
    buffer: Vec<T>,
    _phantom: PhantomData<T>,
}

impl<I, T> BatchIterator<I, T> {
    pub fn new(inner: I, batch_size: usize) -> Self {
        Self {
            inner,
            batch_size,
            buffer: Vec::new(),
            _phantom: PhantomData,
        }
    }
}

#[async_trait::async_trait]
impl<I, T> PaginatedIterator<Vec<T>> for BatchIterator<I, T>
where
    I: PaginatedIterator<T> + Send,
    T: Send,
    I::Error: Send + Sync,
{
    type Error = I::Error;

    async fn next_batch(&mut self) -> std::result::Result<Vec<Vec<T>>, Self::Error> {
        let mut batches = Vec::new();

        // Fill buffer from inner iterator
        while self.buffer.len() < self.batch_size && self.inner.has_more() {
            let inner_batch = self.inner.next_batch().await?;
            if inner_batch.is_empty() {
                break;
            }
            self.buffer.extend(inner_batch);
        }

        // Create batches from buffer
        while self.buffer.len() >= self.batch_size {
            let batch = self.buffer.drain(..self.batch_size).collect();
            batches.push(batch);
        }

        // Return remaining items if no more data coming
        if !self.inner.has_more() && !self.buffer.is_empty() {
            let remaining = self.buffer.drain(..).collect();
            batches.push(remaining);
        }

        Ok(batches)
    }

    fn has_more(&self) -> bool {
        self.inner.has_more() || !self.buffer.is_empty()
    }
}

/// Throttled iterator adapter
pub struct ThrottledIterator<I, T> {
    inner: I,
    delay: Duration,
    last_fetch: Option<Instant>,
    _phantom: PhantomData<T>,
}

impl<I, T> ThrottledIterator<I, T> {
    pub fn new(inner: I, delay: Duration) -> Self {
        Self {
            inner,
            delay,
            last_fetch: None,
            _phantom: PhantomData,
        }
    }
}

#[async_trait::async_trait]
impl<I, T> PaginatedIterator<T> for ThrottledIterator<I, T>
where
    I: PaginatedIterator<T> + Send,
    T: Send,
    I::Error: Send + Sync,
{
    type Error = I::Error;

    async fn next_batch(&mut self) -> std::result::Result<Vec<T>, Self::Error> {
        // Wait if needed to respect throttling
        if let Some(last) = self.last_fetch {
            let elapsed = last.elapsed();
            if elapsed < self.delay {
                sleep(self.delay - elapsed).await;
            }
        }

        let result = self.inner.next_batch().await?;
        self.last_fetch = Some(Instant::now());

        Ok(result)
    }

    fn has_more(&self) -> bool {
        self.inner.has_more()
    }
}

/// Retry iterator adapter
pub struct RetryIterator<I, T> {
    inner: I,
    max_retries: u32,
    base_delay: Duration,
    _phantom: PhantomData<T>,
}

impl<I, T> RetryIterator<I, T> {
    pub fn new(inner: I, max_retries: u32, base_delay: Duration) -> Self {
        Self {
            inner,
            max_retries,
            base_delay,
            _phantom: PhantomData,
        }
    }
}

#[async_trait::async_trait]
impl<I, T> PaginatedIterator<T> for RetryIterator<I, T>
where
    I: PaginatedIterator<T> + Send,
    T: Send,
    I::Error: Send + Sync + std::fmt::Debug,
{
    type Error = I::Error;

    async fn next_batch(&mut self) -> std::result::Result<Vec<T>, Self::Error> {
        let mut last_error = None;

        for attempt in 0..=self.max_retries {
            match self.inner.next_batch().await {
                Ok(batch) => return Ok(batch),
                Err(err) => {
                    last_error = Some(err);
                    if attempt < self.max_retries {
                        let delay = self.base_delay * 2_u32.pow(attempt);
                        sleep(delay).await;
                    }
                }
            }
        }

        Err(last_error.unwrap())
    }

    fn has_more(&self) -> bool {
        self.inner.has_more()
    }
}

/// Progress iterator adapter
pub struct ProgressIterator<I, T> {
    inner: I,
    tracker: ProgressTracker,
    _phantom: PhantomData<T>,
}

impl<I, T> ProgressIterator<I, T> {
    pub fn new(inner: I, tracker: ProgressTracker) -> Self {
        Self {
            inner,
            tracker,
            _phantom: PhantomData,
        }
    }

    /// Get the progress tracker
    pub fn tracker(&self) -> &ProgressTracker {
        &self.tracker
    }
}

#[async_trait::async_trait]
impl<I, T> PaginatedIterator<T> for ProgressIterator<I, T>
where
    I: PaginatedIterator<T> + Send,
    T: Send,
    I::Error: Send + Sync,
{
    type Error = I::Error;

    async fn next_batch(&mut self) -> std::result::Result<Vec<T>, Self::Error> {
        let batch = self.inner.next_batch().await?;
        self.tracker.update_batch(batch.len()).await;
        Ok(batch)
    }

    fn has_more(&self) -> bool {
        self.inner.has_more()
    }
}

/// Cached iterator adapter
pub struct CachedIterator<I, T> {
    inner: Option<I>,
    cache: Vec<Vec<T>>,
    cache_index: usize,
    finished_caching: bool,
    _phantom: PhantomData<T>,
}

impl<I, T> CachedIterator<I, T>
where
    T: Clone,
{
    pub fn new(inner: I) -> Self {
        Self {
            inner: Some(inner),
            cache: Vec::new(),
            cache_index: 0,
            finished_caching: false,
            _phantom: PhantomData,
        }
    }

    /// Reset to beginning of cached data
    pub fn reset(&mut self) {
        self.cache_index = 0;
    }

    /// Get total number of cached batches
    pub fn cached_batch_count(&self) -> usize {
        self.cache.len()
    }
}

#[async_trait::async_trait]
impl<I, T> PaginatedIterator<T> for CachedIterator<I, T>
where
    I: PaginatedIterator<T> + Send,
    T: Clone + Send,
    I::Error: Send + Sync,
{
    type Error = I::Error;

    async fn next_batch(&mut self) -> std::result::Result<Vec<T>, Self::Error> {
        // Return from cache if available
        if self.cache_index < self.cache.len() {
            let batch = self.cache[self.cache_index].clone();
            self.cache_index += 1;
            return Ok(batch);
        }

        // Fetch and cache new batch
        if let Some(ref mut inner) = self.inner {
            if !self.finished_caching {
                let batch = inner.next_batch().await?;
                if batch.is_empty() && !inner.has_more() {
                    self.finished_caching = true;
                    self.inner = None;
                } else {
                    self.cache.push(batch.clone());
                    self.cache_index += 1;
                    return Ok(batch);
                }
            }
        }

        Ok(Vec::new())
    }

    fn has_more(&self) -> bool {
        self.cache_index < self.cache.len()
            || self.inner.as_ref().is_some_and(|i| i.has_more())
            || !self.finished_caching
    }
}

/// Utility trait for easy collection into different container types
#[async_trait::async_trait]
pub trait Collectable<T: Send> {
    /// Collect into Vec
    async fn collect_vec(self) -> Result<Vec<T>>;

    /// Collect into HashSet (deduplicates)
    async fn collect_set(self) -> Result<HashSet<T>>
    where
        T: Eq + std::hash::Hash;

    /// Take first N items
    async fn take(self, n: usize) -> Result<Vec<T>>;

    /// Skip first N items
    fn skip(self, n: usize) -> SkippedIterator<Self, T>
    where
        Self: Sized;
}

#[async_trait::async_trait]
impl<I, T> Collectable<T> for I
where
    I: PaginatedIterator<T, Error = Error> + Send,
    T: Send,
{
    async fn collect_vec(self) -> Result<Vec<T>> {
        self.collect_all().await
    }

    async fn collect_set(self) -> Result<HashSet<T>>
    where
        T: Eq + std::hash::Hash,
    {
        let items = self.collect_all().await?;
        Ok(items.into_iter().collect())
    }

    async fn take(mut self, n: usize) -> Result<Vec<T>> {
        let mut result = Vec::with_capacity(n.min(1000));

        while result.len() < n && self.has_more() {
            let batch = self.next_batch().await?;
            if batch.is_empty() {
                break;
            }

            for item in batch {
                if result.len() >= n {
                    break;
                }
                result.push(item);
            }
        }

        Ok(result)
    }

    fn skip(self, n: usize) -> SkippedIterator<Self, T>
    where
        Self: Sized,
    {
        SkippedIterator::new(self, n)
    }
}

/// Skipped iterator adapter
pub struct SkippedIterator<I, T> {
    inner: I,
    skip_count: usize,
    skipped: usize,
    _phantom: PhantomData<T>,
}

impl<I, T> SkippedIterator<I, T> {
    pub fn new(inner: I, skip_count: usize) -> Self {
        Self {
            inner,
            skip_count,
            skipped: 0,
            _phantom: PhantomData,
        }
    }
}

#[async_trait::async_trait]
impl<I, T> PaginatedIterator<T> for SkippedIterator<I, T>
where
    I: PaginatedIterator<T> + Send,
    T: Send,
    I::Error: Send + Sync,
{
    type Error = I::Error;

    async fn next_batch(&mut self) -> std::result::Result<Vec<T>, Self::Error> {
        while self.skipped < self.skip_count && self.inner.has_more() {
            let batch = self.inner.next_batch().await?;
            let remaining_to_skip = self.skip_count - self.skipped;

            if batch.len() <= remaining_to_skip {
                self.skipped += batch.len();
                continue;
            } else {
                self.skipped = self.skip_count;
                return Ok(batch.into_iter().skip(remaining_to_skip).collect());
            }
        }

        self.inner.next_batch().await
    }

    fn has_more(&self) -> bool {
        self.inner.has_more()
    }
}

#[cfg(test)]
mod tests {
    #![allow(dead_code)]
    use super::*;
    use std::collections::VecDeque;

    // Mock iterator for testing
    struct MockIterator {
        batches: VecDeque<Vec<i32>>,
        error_on_batch: Option<usize>,
        current_batch: usize,
    }

    impl MockIterator {
        fn new(batches: Vec<Vec<i32>>) -> Self {
            Self {
                batches: VecDeque::from(batches),
                error_on_batch: None,
                current_batch: 0,
            }
        }

        #[allow(dead_code)]
        fn with_error_on_batch(mut self, batch: usize) -> Self {
            self.error_on_batch = Some(batch);
            self
        }
    }

    #[async_trait::async_trait]
    impl PaginatedIterator<i32> for MockIterator {
        type Error = Error;

        async fn next_batch(&mut self) -> Result<Vec<i32>> {
            if let Some(error_batch) = self.error_on_batch {
                if self.current_batch == error_batch {
                    return Err(Error::Io {
                        message: "Mock error".to_string(),
                    });
                }
            }

            self.current_batch += 1;
            Ok(self.batches.pop_front().unwrap_or_default())
        }

        fn has_more(&self) -> bool {
            !self.batches.is_empty()
        }
    }

    #[tokio::test]
    async fn test_basic_iteration() {
        let mut iter = MockIterator::new(vec![vec![1, 2, 3], vec![4, 5, 6], vec![7, 8, 9]]);

        let batch1 = iter.next_batch().await.unwrap();
        assert_eq!(batch1, vec![1, 2, 3]);

        let batch2 = iter.next_batch().await.unwrap();
        assert_eq!(batch2, vec![4, 5, 6]);

        let batch3 = iter.next_batch().await.unwrap();
        assert_eq!(batch3, vec![7, 8, 9]);

        assert!(!iter.has_more());
    }

    #[tokio::test]
    async fn test_collect_all() {
        let iter = MockIterator::new(vec![vec![1, 2, 3], vec![4, 5, 6], vec![7, 8, 9]]);

        let all_items = iter.collect_all().await.unwrap();
        assert_eq!(all_items, vec![1, 2, 3, 4, 5, 6, 7, 8, 9]);
    }

    #[tokio::test]
    async fn test_map_iterator() {
        let iter = MockIterator::new(vec![vec![1, 2, 3], vec![4, 5, 6]]);

        let mapped = iter.map(|x| x * 2);
        let all_items = mapped.collect_all().await.unwrap();
        assert_eq!(all_items, vec![2, 4, 6, 8, 10, 12]);
    }

    #[tokio::test]
    async fn test_filter_iterator() {
        let iter = MockIterator::new(vec![vec![1, 2, 3, 4, 5, 6]]);

        let filtered = iter.filter(|x| *x % 2 == 0);
        let all_items = filtered.collect_all().await.unwrap();
        assert_eq!(all_items, vec![2, 4, 6]);
    }

    #[tokio::test]
    async fn test_take_until_iterator() {
        let iter = MockIterator::new(vec![vec![1, 2, 3, 4, 5, 6, 7, 8, 9]]);

        let take_until = iter.take_until(|x| *x > 5);
        let all_items = take_until.collect_all().await.unwrap();
        assert_eq!(all_items, vec![1, 2, 3, 4, 5]);
    }

    #[tokio::test]
    async fn test_throttled_iterator() {
        let iter = MockIterator::new(vec![vec![1, 2, 3], vec![4, 5, 6]]);

        let start = Instant::now();
        let throttled = iter.throttle(Duration::from_millis(100));
        let _all_items = throttled.collect_all().await.unwrap();
        let elapsed = start.elapsed();

        // Should take at least 100ms for throttling
        assert!(elapsed >= Duration::from_millis(90)); // Allow for some timing variance
    }

    #[tokio::test]
    async fn test_cached_iterator() {
        let iter = MockIterator::new(vec![vec![1, 2, 3], vec![4, 5, 6]]);

        let mut cached = iter.cached();

        // First pass - collect batches one by one to avoid consuming self
        let mut all_items1 = Vec::new();
        while cached.has_more() {
            let batch = cached.next_batch().await.unwrap();
            all_items1.extend(batch);
        }
        assert_eq!(all_items1, vec![1, 2, 3, 4, 5, 6]);

        // Reset and read again (should use cache)
        cached.reset();
        let mut all_items2 = Vec::new();
        while cached.has_more() {
            let batch = cached.next_batch().await.unwrap();
            all_items2.extend(batch);
        }
        assert_eq!(all_items2, vec![1, 2, 3, 4, 5, 6]);
    }

    #[tokio::test]
    async fn test_progress_tracker() {
        let tracker = ProgressTracker::new("test").with_update_interval(Duration::from_millis(10));

        tracker.update_batch(5).await;
        tracker.update_batch(3).await;

        let stats = tracker.stats().await;
        assert_eq!(stats.items_processed, 8);
        assert_eq!(stats.batches_processed, 2);
    }

    #[tokio::test]
    async fn test_collectable_take() {
        let iter = MockIterator::new(vec![vec![1, 2, 3, 4, 5, 6, 7, 8, 9]]);

        let items = iter.take(5).await.unwrap();
        assert_eq!(items, vec![1, 2, 3, 4, 5]);
    }

    #[tokio::test]
    async fn test_collectable_skip() {
        let iter = MockIterator::new(vec![vec![1, 2, 3, 4, 5, 6, 7, 8, 9]]);

        let skipped = iter.skip(3);
        let items = skipped.collect_all().await.unwrap();
        assert_eq!(items, vec![4, 5, 6, 7, 8, 9]);
    }

    #[tokio::test]
    async fn test_collect_set() {
        let iter = MockIterator::new(vec![vec![1, 2, 2, 3, 3, 3]]);

        let set = PaginatedIterator::collect_set(iter).await.unwrap();
        assert_eq!(set.len(), 3);
        assert!(set.contains(&1));
        assert!(set.contains(&2));
        assert!(set.contains(&3));
    }

    #[tokio::test]
    async fn test_chained_operations() {
        let iter = MockIterator::new(vec![vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10]]);

        // Chain multiple operations
        let result = iter
            .filter(|x| *x % 2 == 0) // Even numbers: 2, 4, 6, 8, 10
            .map(|x| x * 2) // Double them: 4, 8, 12, 16, 20
            .take_until(|x| *x > 15) // Take until > 15: 4, 8, 12
            .collect_all()
            .await
            .unwrap();

        assert_eq!(result, vec![4, 8, 12]);
    }
}
