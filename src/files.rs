//! File analysis and upload functionality for VirusTotal API
//!
//! This module provides comprehensive file operations including:
//! - File analysis and retrieval
//! - File upload and download
//! - Behavior analysis reports
//! - MITRE ATT&CK technique mapping
//! - File relationship analysis

pub mod behavior;
pub mod client;
pub mod mitre;
pub mod network;
pub mod types;

#[cfg(test)]
mod tests;

// Re-export all public types for backward compatibility
pub use behavior::*;
pub use client::*;
pub use mitre::*;
pub use network::*;
pub use types::*;
