//! Iterator adapters for transformation and control flow

use super::{progress::ProgressTracker, traits::PaginatedIterator};
use std::time::{Duration, Instant};
use tokio::time::sleep;

/// Iterator that maps items to a different type
pub struct MappedIterator<I, T, U, F> {
    inner: I,
    mapper: F,
    _phantom: std::marker::PhantomData<(T, U)>,
}

impl<I, T, U, F> MappedIterator<I, T, U, F> {
    pub fn new(inner: I, mapper: F) -> Self {
        Self {
            inner,
            mapper,
            _phantom: std::marker::PhantomData,
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

/// Iterator that filters items based on a predicate
pub struct FilteredIterator<I, T, F> {
    inner: I,
    predicate: F,
    _phantom: std::marker::PhantomData<T>,
}

impl<I, T, F> FilteredIterator<I, T, F> {
    pub fn new(inner: I, predicate: F) -> Self {
        Self {
            inner,
            predicate,
            _phantom: std::marker::PhantomData,
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
        loop {
            let batch = self.inner.next_batch().await?;
            if batch.is_empty() {
                return Ok(batch);
            }

            let filtered: Vec<T> = batch.into_iter().filter(&self.predicate).collect();

            // If we got some filtered results or inner iterator is exhausted, return
            if !filtered.is_empty() || !self.inner.has_more() {
                return Ok(filtered);
            }

            // Continue to next batch if current filtered to nothing and more available
        }
    }

    fn has_more(&self) -> bool {
        self.inner.has_more()
    }
}

/// Iterator that takes items until a condition is met
pub struct TakeUntilIterator<I, T, F> {
    inner: I,
    condition: F,
    finished: bool,
    _phantom: std::marker::PhantomData<T>,
}

impl<I, T, F> TakeUntilIterator<I, T, F> {
    pub fn new(inner: I, condition: F) -> Self {
        Self {
            inner,
            condition,
            finished: false,
            _phantom: std::marker::PhantomData,
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

/// Iterator that batches items into chunks
pub struct BatchIterator<I, T> {
    inner: I,
    batch_size: usize,
    buffer: Vec<T>,
}

impl<I, T> BatchIterator<I, T> {
    pub fn new(inner: I, batch_size: usize) -> Self {
        Self {
            inner,
            batch_size: batch_size.max(1), // Ensure batch size is at least 1
            buffer: Vec::new(),
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

        // Create output batches
        while self.buffer.len() >= self.batch_size {
            let batch = self.buffer.drain(..self.batch_size).collect();
            batches.push(batch);
        }

        // If no more items and buffer has remaining, include it
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

/// Iterator that throttles requests with delays
pub struct ThrottledIterator<I, T> {
    inner: I,
    delay: Duration,
    last_fetch: Option<Instant>,
    _phantom: std::marker::PhantomData<T>,
}

impl<I, T> ThrottledIterator<I, T> {
    pub fn new(inner: I, delay: Duration) -> Self {
        Self {
            inner,
            delay,
            last_fetch: None,
            _phantom: std::marker::PhantomData,
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

/// Iterator that retries failed requests
pub struct RetryIterator<I, T> {
    inner: I,
    max_retries: u32,
    base_delay: Duration,
    _phantom: std::marker::PhantomData<T>,
}

impl<I, T> RetryIterator<I, T> {
    pub fn new(inner: I, max_retries: u32, base_delay: Duration) -> Self {
        Self {
            inner,
            max_retries,
            base_delay,
            _phantom: std::marker::PhantomData,
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

/// Iterator that tracks progress
pub struct ProgressIterator<I, T> {
    inner: I,
    tracker: ProgressTracker,
    _phantom: std::marker::PhantomData<T>,
}

impl<I, T> ProgressIterator<I, T> {
    pub fn new(inner: I, tracker: ProgressTracker) -> Self {
        Self {
            inner,
            tracker,
            _phantom: std::marker::PhantomData,
        }
    }

    /// Get a reference to the progress tracker
    pub fn progress(&self) -> &ProgressTracker {
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

/// Iterator that caches results for repeated iteration
pub struct CachedIterator<I, T> {
    inner: Option<I>,
    cache: Vec<Vec<T>>,
    cache_index: usize,
    finished_caching: bool,
}

impl<I, T> CachedIterator<I, T> {
    pub fn new(inner: I) -> Self {
        Self {
            inner: Some(inner),
            cache: Vec::new(),
            cache_index: 0,
            finished_caching: false,
        }
    }

    /// Reset iterator to beginning of cached data
    pub fn reset(&mut self) {
        self.cache_index = 0;
    }

    /// Clear the cache and start fresh
    pub fn clear_cache(&mut self) {
        self.cache.clear();
        self.cache_index = 0;
        self.finished_caching = false;
    }

    /// Get the number of cached batches
    pub fn cached_batches(&self) -> usize {
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
        // Has more if we haven't reached end of cache or inner iterator still has items
        self.cache_index < self.cache.len()
            || (!self.finished_caching && self.inner.as_ref().is_some_and(|i| i.has_more()))
    }
}

/// Iterator that skips a number of items
pub struct SkippedIterator<I, T> {
    inner: I,
    skip_count: usize,
    skipped: usize,
    _phantom: std::marker::PhantomData<T>,
}

impl<I, T> SkippedIterator<I, T> {
    pub fn new(inner: I, skip_count: usize) -> Self {
        Self {
            inner,
            skip_count,
            skipped: 0,
            _phantom: std::marker::PhantomData,
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
