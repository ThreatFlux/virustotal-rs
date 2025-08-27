//! Private Files Client - Modular implementation
//!
//! This module contains the refactored PrivateFilesClient split into
//! focused submodules for better maintainability and code organization.

use crate::{Client, Result};

// Import all the operation modules
mod analysis_ops;
mod upload_ops;
mod file_mgmt;
mod file_analysis;
mod behavior_ops;
mod misc_ops;
mod helpers;

/// Client for Private File Scanning operations
pub struct PrivateFilesClient<'a> {
    pub(crate) client: &'a Client,
}

impl<'a> PrivateFilesClient<'a> {
    pub fn new(client: &'a Client) -> Self {
        Self { client }
    }
}