//! Enhanced error handling for VirusTotal API operations
//!
//! This module provides comprehensive error types and utilities including:
//! - Categorized error types with severity levels
//! - Error context for debugging
//! - Retry policies and detection utilities
//! - Macros for error handling boilerplate
//! - Extensive error analysis methods

pub mod context;
pub mod implementation;
pub mod macros;
pub mod types;
pub mod utils;

#[cfg(test)]
mod tests;

// Re-export all public types for backward compatibility
pub use context::*;
// pub use implementation::*;  // Commented out unused import
// pub use macros::*;  // Commented out unused import
pub use types::*;
pub use utils::*;

// Note: chrono dependency is included in the context module
