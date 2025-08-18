//! MCP Server implementation for VirusTotal SDK
//!
//! This module provides a simple MCP server for threat intelligence queries.

use crate::mcp::search::vti_search;
use crate::mcp::{convert_vt_error, McpResult};
use crate::Client;
use serde_json::{json, Value as JsonValue};

/// VirusTotal MCP Server implementation
#[derive(Clone)]
pub struct VtMcpServer {
    client: Client,
}

impl VtMcpServer {
    /// Create a new VirusTotal MCP server instance
    pub fn new(client: Client) -> Self {
        Self { client }
    }

    /// Handle a tool call request
    pub async fn handle_tool_call(
        &self,
        tool_name: &str,
        arguments: &JsonValue,
    ) -> McpResult<JsonValue> {
        match tool_name {
            "vti_search" => self.handle_vti_search(arguments).await,
            "get_file_report" => self.handle_get_file_report(arguments).await,
            "get_url_report" => self.handle_get_url_report(arguments).await,
            "get_ip_report" => self.handle_get_ip_report(arguments).await,
            "get_domain_report" => self.handle_get_domain_report(arguments).await,
            _ => Err(anyhow::anyhow!("Unknown tool: {}", tool_name)),
        }
    }

    /// Get server information
    pub fn get_server_info(&self) -> JsonValue {
        json!({
            "name": "virustotal-sdk",
            "version": "0.1.0",
            "description": "VirusTotal threat intelligence MCP server"
        })
    }

    /// Get server capabilities
    pub fn get_server_capabilities(&self) -> JsonValue {
        json!({
            "tools": {
                "listChanged": false
            }
        })
    }

    /// List available tools
    pub fn list_tools(&self) -> Vec<JsonValue> {
        vec![
            json!({
                "name": "vti_search",
                "description": "Search VirusTotal for threat intelligence on any indicator (hash, IP, domain, or URL). Automatically detects indicator type and returns comprehensive threat analysis.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "indicator": {
                            "type": "string",
                            "description": "The indicator to search for (file hash, IP address, domain, or URL)"
                        }
                    },
                    "required": ["indicator"]
                }
            }),
            json!({
                "name": "get_file_report",
                "description": "Get detailed file analysis report from VirusTotal using a file hash (MD5, SHA1, SHA256, or SHA512).",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "hash": {
                            "type": "string",
                            "description": "File hash (MD5, SHA1, SHA256, or SHA512)"
                        }
                    },
                    "required": ["hash"]
                }
            }),
            json!({
                "name": "get_url_report",
                "description": "Get detailed URL analysis report from VirusTotal for a specific URL.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "url": {
                            "type": "string",
                            "description": "The URL to analyze"
                        }
                    },
                    "required": ["url"]
                }
            }),
            json!({
                "name": "get_ip_report",
                "description": "Get detailed IP address analysis report from VirusTotal.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "ip": {
                            "type": "string",
                            "description": "IP address (IPv4 or IPv6)"
                        }
                    },
                    "required": ["ip"]
                }
            }),
            json!({
                "name": "get_domain_report",
                "description": "Get detailed domain analysis report from VirusTotal.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "domain": {
                            "type": "string",
                            "description": "Domain name to analyze"
                        }
                    },
                    "required": ["domain"]
                }
            }),
        ]
    }

    /// Handle vti_search tool call
    async fn handle_vti_search(&self, arguments: &JsonValue) -> McpResult<JsonValue> {
        let indicator = arguments["indicator"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("Missing required parameter: indicator"))?;

        let result = vti_search(&self.client, indicator.to_string()).await?;
        Ok(serde_json::to_value(result)?)
    }

    /// Handle get_file_report tool call
    async fn handle_get_file_report(&self, arguments: &JsonValue) -> McpResult<JsonValue> {
        let hash = arguments["hash"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("Missing required parameter: hash"))?;

        let file = self
            .client
            .files()
            .get(hash)
            .await
            .map_err(convert_vt_error)?;

        Ok(serde_json::to_value(file)?)
    }

    /// Handle get_url_report tool call
    async fn handle_get_url_report(&self, arguments: &JsonValue) -> McpResult<JsonValue> {
        let url = arguments["url"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("Missing required parameter: url"))?;

        // Encode URL for VirusTotal API
        use base64::{engine::general_purpose, Engine as _};
        let url_id = general_purpose::STANDARD.encode(url);
        let url_info = self
            .client
            .urls()
            .get(&url_id)
            .await
            .map_err(convert_vt_error)?;

        Ok(serde_json::to_value(url_info)?)
    }

    /// Handle get_ip_report tool call
    async fn handle_get_ip_report(&self, arguments: &JsonValue) -> McpResult<JsonValue> {
        let ip = arguments["ip"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("Missing required parameter: ip"))?;

        let ip_info = self
            .client
            .ip_addresses()
            .get(ip)
            .await
            .map_err(convert_vt_error)?;

        Ok(serde_json::to_value(ip_info)?)
    }

    /// Handle get_domain_report tool call
    async fn handle_get_domain_report(&self, arguments: &JsonValue) -> McpResult<JsonValue> {
        let domain = arguments["domain"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("Missing required parameter: domain"))?;

        let domain_info = self
            .client
            .domains()
            .get(domain)
            .await
            .map_err(convert_vt_error)?;

        Ok(serde_json::to_value(domain_info)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ApiTier, ClientBuilder};

    #[tokio::test]
    async fn test_server_creation() {
        let client = ClientBuilder::new()
            .api_key("test_key")
            .tier(ApiTier::Public)
            .build()
            .unwrap();

        let server = VtMcpServer::new(client);

        // Test server info
        let info = server.get_server_info();
        assert!(info["name"].as_str().unwrap() == "virustotal-sdk");
        assert!(info["version"].as_str().unwrap() == "0.1.0");

        // Test capabilities
        let capabilities = server.get_server_capabilities();
        assert!(capabilities["tools"].is_object());

        // Test tools list
        let tools = server.list_tools();
        assert_eq!(tools.len(), 5);

        let tool_names: Vec<String> = tools
            .iter()
            .map(|t| t["name"].as_str().unwrap().to_string())
            .collect();
        assert!(tool_names.contains(&"vti_search".to_string()));
        assert!(tool_names.contains(&"get_file_report".to_string()));
        assert!(tool_names.contains(&"get_url_report".to_string()));
        assert!(tool_names.contains(&"get_ip_report".to_string()));
        assert!(tool_names.contains(&"get_domain_report".to_string()));
    }
}
