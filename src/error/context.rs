//! Error context for debugging and error reporting

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;

/// Context information for errors to help with debugging and error reporting
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorContext {
    /// The operation that was being performed when the error occurred
    pub operation: Option<String>,
    /// The endpoint or resource being accessed
    pub resource: Option<String>,
    /// Additional key-value pairs for context
    pub metadata: HashMap<String, String>,
    /// Timestamp when the error occurred
    pub timestamp: Option<String>,
    /// Request ID if available
    pub request_id: Option<String>,
}

impl ErrorContext {
    /// Create a new empty error context
    pub fn new() -> Self {
        Self {
            operation: None,
            resource: None,
            metadata: HashMap::new(),
            timestamp: None,
            request_id: None,
        }
    }

    /// Create error context with an operation
    pub fn with_operation(operation: impl Into<String>) -> Self {
        Self {
            operation: Some(operation.into()),
            resource: None,
            metadata: HashMap::new(),
            timestamp: Some(chrono::Utc::now().to_rfc3339()),
            request_id: None,
        }
    }

    /// Add a resource to the context
    pub fn with_resource(mut self, resource: impl Into<String>) -> Self {
        self.resource = Some(resource.into());
        self
    }

    /// Add metadata to the context
    pub fn with_metadata(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.metadata.insert(key.into(), value.into());
        self
    }

    /// Add a request ID to the context
    pub fn with_request_id(mut self, request_id: impl Into<String>) -> Self {
        self.request_id = Some(request_id.into());
        self
    }
}

impl Default for ErrorContext {
    fn default() -> Self {
        Self::new()
    }
}

impl ErrorContext {
    /// Helper to format operation field
    fn format_operation(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(op) = &self.operation {
            write!(f, " operation: {}", op)?;
        }
        Ok(())
    }

    /// Helper to format resource field
    fn format_resource(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(res) = &self.resource {
            write!(f, " resource: {}", res)?;
        }
        Ok(())
    }

    /// Helper to format request_id field
    fn format_request_id(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(req_id) = &self.request_id {
            write!(f, " request_id: {}", req_id)?;
        }
        Ok(())
    }

    /// Helper to format metadata field
    fn format_metadata(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if !self.metadata.is_empty() {
            write!(f, " metadata: {:?}", self.metadata)?;
        }
        Ok(())
    }
}

impl fmt::Display for ErrorContext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ErrorContext {{")?;
        self.format_operation(f)?;
        self.format_resource(f)?;
        self.format_request_id(f)?;
        self.format_metadata(f)?;
        write!(f, " }}")
    }
}
