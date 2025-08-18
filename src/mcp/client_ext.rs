//! Client extensions for MCP functionality

use crate::mcp::server::VtMcpServer;
use crate::mcp::transport::ServerConfig;
use crate::Client;

#[cfg(feature = "mcp")]
impl Client {
    /// Create an MCP server instance using this client
    pub fn create_mcp_server(&self) -> VtMcpServer {
        VtMcpServer::new(self.clone())
    }

    /// Create a server configuration for MCP server
    /// This is a convenience method for setting up MCP servers
    pub fn mcp_config(&self) -> ServerConfig {
        ServerConfig::new()
    }
}
