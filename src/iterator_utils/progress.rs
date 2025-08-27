//! Progress tracking utilities for iterators

use std::sync::Arc;
use std::time::{Duration, SystemTime};
use tokio::sync::RwLock;

/// Progress tracker for iterator operations
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
            let rate = if elapsed.as_secs_f64() > 0.0 {
                *items as f64 / elapsed.as_secs_f64()
            } else {
                0.0
            };

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
        let rate = if elapsed.as_secs_f64() > 0.0 {
            items as f64 / elapsed.as_secs_f64()
        } else {
            0.0
        };

        ProgressStats {
            items_processed: items,
            batches_processed: batches,
            elapsed,
            items_per_second: rate,
        }
    }

    /// Reset progress statistics
    pub async fn reset(&self) {
        *self.items_processed.write().await = 0;
        *self.batches_processed.write().await = 0;
        let now = SystemTime::now();
        *self.last_update.write().await = now;
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

impl ProgressStats {
    /// Create empty progress stats
    pub fn new() -> Self {
        Self {
            items_processed: 0,
            batches_processed: 0,
            elapsed: Duration::ZERO,
            items_per_second: 0.0,
        }
    }

    /// Get estimated time remaining based on current rate and target
    pub fn estimated_remaining(&self, target_items: u64) -> Duration {
        if self.items_per_second <= 0.0 || self.items_processed >= target_items {
            return Duration::ZERO;
        }

        let remaining_items = target_items - self.items_processed;
        let seconds = remaining_items as f64 / self.items_per_second;
        Duration::from_secs_f64(seconds)
    }
}

impl Default for ProgressStats {
    fn default() -> Self {
        Self::new()
    }
}
