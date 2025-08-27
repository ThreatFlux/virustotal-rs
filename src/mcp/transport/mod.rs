//! Transport layer implementations for MCP server
//!
//! Provides both STDIO and HTTP transport modes for the MCP server.

mod common;
pub mod config;
pub mod http;
pub mod stdio;

pub use config::{run_server_from_env, run_server_simple, ServerConfig};
#[cfg(feature = "mcp-oauth")]
pub use http::run_http_server_with_oauth;
pub use http::{run_http_server, run_http_server_with_config};
pub use stdio::run_stdio_server;
