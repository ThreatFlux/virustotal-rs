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
//! // Process with automatic rate limiting and progress reporting
//! let all_comments = iter.collect_all().await?;
//! # Ok(())
//! # }
//! ```

pub mod adapters;
pub mod core;
pub mod progress;
pub mod traits;

#[cfg(test)]
mod tests;

// Re-export key types and traits for public API
pub use adapters::*;
pub use core::*;
pub use progress::*;
pub use traits::*;
