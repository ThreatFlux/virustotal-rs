//! Private file operations for the VirusTotal API
//!
//! This module provides functionality for uploading and analyzing private files,
//! managing file reports, retrieving behavior analysis, and working with ZIP archives
//! of private files.

pub mod analysis;
pub mod behavior;
pub mod client;
pub mod types;
pub mod upload;
pub mod zip;

#[cfg(test)]
mod tests;

// Re-export all public types for backwards compatibility
pub use analysis::*;
pub use behavior::*;
pub use client::*;
pub use types::*;
pub use upload::*;
pub use zip::*;

use crate::Client;

impl Client {
    /// Get the Private Files client
    pub fn private_files(&self) -> PrivateFilesClient<'_> {
        PrivateFilesClient::new(self)
    }
}
