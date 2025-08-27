//! Collections management for VirusTotal threat intelligence
//!
//! This module provides comprehensive collection operations including:
//! - Creating and managing IOC collections
//! - Adding/removing domains, URLs, IPs, and files
//! - Exporting collections in various formats
//! - Searching and filtering collections
//! - Builder patterns for easy collection creation

pub mod builder;
pub mod client;
pub mod descriptors;
pub mod enums;
pub mod requests;
pub mod types;

#[cfg(test)]
mod tests;

// Re-export all public types for backward compatibility
// pub use builder::*;  // Commented out unused import
pub use client::*;
pub use descriptors::*;
pub use enums::*;
pub use requests::*;
pub use types::*;
