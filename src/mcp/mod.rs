//! Model Context Protocol (MCP) integration for `VirusTotal` SDK
//!
//! This module provides MCP server functionality that allows Language Models
//! to interact with the `VirusTotal` API through standardized tool calls.

#[cfg(feature = "mcp-jwt")]
pub mod auth;
#[cfg(feature = "mcp")]
pub mod client_ext;
#[cfg(feature = "mcp")]
pub mod indicators;
#[cfg(feature = "mcp-oauth")]
pub mod oauth;
#[cfg(feature = "mcp")]
pub mod search;
#[cfg(feature = "mcp")]
pub mod server;
#[cfg(feature = "mcp")]
pub mod transport;

#[cfg(feature = "mcp")]
pub use search::{vti_search, DetectionSummary, ThreatContext, ThreatIntelligence};
#[cfg(feature = "mcp")]
pub use server::VtMcpServer;
#[cfg(feature = "mcp")]
pub use transport::{run_http_server, run_stdio_server};

#[cfg(feature = "mcp")]
pub use indicators::{detect_indicator_type, IndicatorType};

#[cfg(feature = "mcp-jwt")]
pub use auth::{AuthError, JwtAuthLayer, JwtClaims, JwtConfig, JwtManager};

#[cfg(feature = "mcp-oauth")]
pub use oauth::{
    AuthServerMetadata, CallbackParams, OAuthClaims, OAuthConfig, OAuthCredentials, OAuthError,
    OAuthState,
};

/// Result type for MCP operations
#[cfg(feature = "mcp")]
pub type McpResult<T> = anyhow::Result<T>;

/// Error handling for MCP operations
#[cfg(feature = "mcp")]
pub fn convert_vt_error(err: crate::Error) -> anyhow::Error {
    match err {
        crate::Error::BadRequest(msg) => anyhow::anyhow!("Bad Request: {}", msg),
        crate::Error::AuthenticationRequired => {
            anyhow::anyhow!("Authentication Required: Invalid API key")
        }
        crate::Error::Forbidden => anyhow::anyhow!("Forbidden: Access denied"),
        crate::Error::NotFound => anyhow::anyhow!("Not Found: Resource not found"),
        crate::Error::RateLimit(msg) => anyhow::anyhow!("Rate Limited: {}", msg),
        crate::Error::QuotaExceeded(msg) => anyhow::anyhow!("Quota Exceeded: {}", msg),
        crate::Error::Http(err) => anyhow::anyhow!("HTTP Error: {}", err),
        crate::Error::Json(err) => anyhow::anyhow!("JSON Error: {}", err),
        crate::Error::Unknown(msg) => anyhow::anyhow!("Unknown Error: {}", msg),
        crate::Error::InvalidArgument(msg) => anyhow::anyhow!("Invalid Argument: {}", msg),
        crate::Error::NotAvailableYet => anyhow::anyhow!("Resource not available yet"),
        crate::Error::UnselectiveContentQuery => {
            anyhow::anyhow!("Content search query is not selective enough")
        }
        crate::Error::UnsupportedContentQuery => {
            anyhow::anyhow!("Unsupported content search query")
        }
        crate::Error::UserNotActive => anyhow::anyhow!("User account is not active"),
        crate::Error::WrongCredentials => anyhow::anyhow!("Wrong credentials provided"),
        crate::Error::AlreadyExists => anyhow::anyhow!("Resource already exists"),
        crate::Error::FailedDependency => anyhow::anyhow!("Failed dependency"),
        crate::Error::TooManyRequests => anyhow::anyhow!("Too many requests"),
        crate::Error::TransientError => anyhow::anyhow!("Transient server error"),
        crate::Error::DeadlineExceeded => anyhow::anyhow!("Operation deadline exceeded"),
        crate::Error::Configuration { message } => {
            anyhow::anyhow!("Configuration error: {}", message)
        }
        crate::Error::Validation { message, .. } => {
            anyhow::anyhow!("Validation error: {}", message)
        }
        crate::Error::Io { message } => anyhow::anyhow!("IO error: {}", message),
    }
}

#[cfg(test)]
mod tests {
    #[cfg(feature = "mcp")]
    #[test]
    fn test_error_conversion() {
        use super::convert_vt_error;
        use crate::Error;

        let vt_error = Error::BadRequest("test error".to_string());
        let mcp_error = convert_vt_error(vt_error);
        assert!(mcp_error.to_string().contains("Bad Request: test error"));
    }
}
