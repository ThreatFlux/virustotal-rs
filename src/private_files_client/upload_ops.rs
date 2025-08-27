//! Upload operations for private files
//!
//! This module contains methods for uploading files for private scanning,
//! including both regular and large file uploads.

use super::{PrivateFilesClient, Result};
use crate::private_files::{PrivateFileUploadParams, PrivateFileUploadResponse, UploadUrlResponse};

impl<'a> PrivateFilesClient<'a> {
    /// Upload a file for private scanning (files up to 32MB)
    ///
    /// POST /private/files
    ///
    /// The file contents should be provided as bytes.
    /// For files larger than 32MB, use `upload_large_file` instead.
    pub async fn upload_file(
        &self,
        file_data: &[u8],
        params: Option<PrivateFileUploadParams>,
    ) -> Result<PrivateFileUploadResponse> {
        let mut form = reqwest::multipart::Form::new().part(
            "file",
            reqwest::multipart::Part::bytes(file_data.to_vec()).file_name("file"),
        );

        // Add optional parameters
        if let Some(p) = params {
            form = self.add_upload_params_to_form(form, p)?;
        }

        self.client.post_multipart("private/files", form).await
    }

    /// Helper method to add upload parameters to multipart form
    fn add_upload_params_to_form(
        &self,
        mut form: reqwest::multipart::Form,
        params: PrivateFileUploadParams,
    ) -> Result<reqwest::multipart::Form> {
        if let Some(disable_sandbox) = params.disable_sandbox {
            form = form.text("disable_sandbox", disable_sandbox.to_string());
        }
        if let Some(enable_internet) = params.enable_internet {
            form = form.text("enable_internet", enable_internet.to_string());
        }
        if let Some(intercept_tls) = params.intercept_tls {
            form = form.text("intercept_tls", intercept_tls.to_string());
        }
        if let Some(command_line) = params.command_line {
            form = form.text("command_line", command_line);
        }
        if let Some(password) = params.password {
            form = form.text("password", password);
        }
        if let Some(retention_period_days) = params.retention_period_days {
            form = form.text("retention_period_days", retention_period_days.to_string());
        }
        if let Some(storage_region) = params.storage_region {
            form = form.text("storage_region", storage_region);
        }
        if let Some(interaction_sandbox) = params.interaction_sandbox {
            form = form.text("interaction_sandbox", interaction_sandbox);
        }
        if let Some(interaction_timeout) = params.interaction_timeout {
            form = form.text("interaction_timeout", interaction_timeout.to_string());
        }
        if let Some(locale) = params.locale {
            form = form.text("locale", locale);
        }
        Ok(form)
    }

    /// Create an upload URL for large files (>32MB, up to 650MB)
    ///
    /// GET /private/files/upload_url
    ///
    /// Returns a URL that can be used to upload large files directly.
    pub async fn create_upload_url(&self) -> Result<UploadUrlResponse> {
        self.client.get("private/files/upload_url").await
    }

    /// Upload a large file using the upload URL
    ///
    /// This method handles the upload to the URL obtained from `create_upload_url`.
    /// The actual upload is done via PUT request to the provided URL.
    pub async fn upload_large_file(
        &self,
        _upload_url: &str,
        _file_data: &[u8],
    ) -> Result<PrivateFileUploadResponse> {
        // Note: This would need special handling to upload directly to the
        // provided URL and then confirm the upload
        // This is a placeholder showing the expected interface

        // 1. PUT file_data to upload_url
        // 2. Confirm upload by calling the confirmation endpoint

        unimplemented!("Large file upload requires special HTTP client handling")
    }
}