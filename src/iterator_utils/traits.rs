//! Core traits for iterator utilities

use std::time::Duration;

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

    /// Get an approximation of items remaining if available
    fn hint_remaining(&self) -> Option<usize> {
        None
    }

    /// Get statistics about fetching
    fn stats(&self) -> IteratorStats {
        IteratorStats::default()
    }
}

/// Trait for items that can be paged
pub trait Pageable<T>
where
    T: Send,
{
    /// Get items for a specific page
    fn get_page(
        &self,
        page: u32,
        page_size: Option<u32>,
    ) -> impl std::future::Future<
        Output = std::result::Result<Vec<T>, Box<dyn std::error::Error + Send + Sync>>,
    > + Send;
}

/// Extension trait providing additional iterator functionality
#[async_trait::async_trait]
pub trait IteratorExt<T: Send>: PaginatedIterator<T> {
    /// Map items to a different type
    fn map<U, F>(self, mapper: F) -> super::adapters::MappedIterator<Self, T, U, F>
    where
        Self: Sized,
        U: Send,
        F: Fn(T) -> U + Send + Sync,
    {
        super::adapters::MappedIterator::new(self, mapper)
    }

    /// Filter items based on a predicate
    fn filter<F>(self, predicate: F) -> super::adapters::FilteredIterator<Self, T, F>
    where
        Self: Sized,
        F: Fn(&T) -> bool + Send + Sync,
    {
        super::adapters::FilteredIterator::new(self, predicate)
    }

    /// Take items until a condition is met
    fn take_until<F>(self, condition: F) -> super::adapters::TakeUntilIterator<Self, T, F>
    where
        Self: Sized,
        F: Fn(&T) -> bool + Send + Sync,
    {
        super::adapters::TakeUntilIterator::new(self, condition)
    }

    /// Batch items into chunks
    fn batch(self, size: usize) -> super::adapters::BatchIterator<Self, T>
    where
        Self: Sized,
    {
        super::adapters::BatchIterator::new(self, size)
    }

    /// Throttle iteration with delays
    fn throttle(self, delay: Duration) -> super::adapters::ThrottledIterator<Self, T>
    where
        Self: Sized,
    {
        super::adapters::ThrottledIterator::new(self, delay)
    }

    /// Add retry logic to iterations
    fn retry(
        self,
        max_retries: u32,
        base_delay: Duration,
    ) -> super::adapters::RetryIterator<Self, T>
    where
        Self: Sized,
    {
        super::adapters::RetryIterator::new(self, max_retries, base_delay)
    }

    /// Add progress tracking
    fn with_progress(
        self,
        tracker: super::progress::ProgressTracker,
    ) -> super::adapters::ProgressIterator<Self, T>
    where
        Self: Sized,
    {
        super::adapters::ProgressIterator::new(self, tracker)
    }

    /// Cache results for repeated iteration
    fn cached(self) -> super::adapters::CachedIterator<Self, T>
    where
        Self: Sized,
    {
        super::adapters::CachedIterator::new(self)
    }

    /// Skip a number of items
    fn skip(self, count: usize) -> super::adapters::SkippedIterator<Self, T>
    where
        Self: Sized,
    {
        super::adapters::SkippedIterator::new(self, count)
    }
}

/// Blanket implementation of IteratorExt for all PaginatedIterator types
impl<I, T: Send> IteratorExt<T> for I where I: PaginatedIterator<T> {}

/// Statistics for iterator performance
#[derive(Debug, Clone, Default)]
pub struct IteratorStats {
    /// Number of batches fetched
    pub batches_fetched: u64,
    /// Total items fetched
    pub items_fetched: u64,
    /// Total time spent fetching
    pub fetch_duration: Duration,
    /// Number of retries performed
    pub retries: u32,
}

/// Trait for collecting iterator results
#[async_trait::async_trait]
pub trait Collectable<T: Send> {
    type Error: std::error::Error + Send + Sync + 'static;

    /// Take a specific number of items
    async fn take(self, n: usize) -> std::result::Result<Vec<T>, Self::Error>
    where
        Self: Sized;

    /// Take items while a condition is true
    async fn take_while<F>(self, predicate: F) -> std::result::Result<Vec<T>, Self::Error>
    where
        Self: Sized,
        F: Fn(&T) -> bool + Send;

    /// Collect all items
    async fn collect_all(self) -> std::result::Result<Vec<T>, Self::Error>
    where
        Self: Sized;
}

/// Implementation of Collectable for all PaginatedIterator types
#[async_trait::async_trait]
impl<I, T> Collectable<T> for I
where
    I: PaginatedIterator<T> + Send,
    T: Send,
{
    type Error = I::Error;

    async fn take(mut self, n: usize) -> std::result::Result<Vec<T>, Self::Error> {
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

    async fn take_while<F>(mut self, predicate: F) -> std::result::Result<Vec<T>, Self::Error>
    where
        Self: Sized,
        F: Fn(&T) -> bool + Send,
    {
        let mut result = Vec::new();

        while self.has_more() {
            let batch = self.next_batch().await?;
            if batch.is_empty() {
                break;
            }

            for item in batch {
                if !predicate(&item) {
                    return Ok(result);
                }
                result.push(item);
            }
        }

        Ok(result)
    }

    async fn collect_all(self) -> std::result::Result<Vec<T>, Self::Error>
    where
        Self: Sized,
    {
        PaginatedIterator::collect_all(self).await
    }
}
