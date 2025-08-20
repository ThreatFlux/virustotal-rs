//! MCP HTTP Server Example for VirusTotal SDK
//!
//! This example demonstrates how to run a VirusTotal MCP server using HTTP transport.
//! This mode is suitable for remote access and web-based integrations.
//!
//! Note: This example runs without authentication. For production use with JWT authentication,
//! see the mcp_http_server_jwt example.
//!
//! Usage:
//!   VIRUSTOTAL_API_KEY=your_api_key cargo run --example mcp_http_server --features mcp
//!   HTTP_ADDR=127.0.0.1:3000 VIRUSTOTAL_API_KEY=your_api_key cargo run --example mcp_http_server --features mcp
//!
//! Test with MCP Inspector:
//!   npx @modelcontextprotocol/inspector http://localhost:3000
//!
//! For JWT-enabled version:
//!   cargo run --example mcp_http_server_jwt --features mcp-jwt

#[cfg(feature = "mcp")]
use std::env;
#[cfg(feature = "mcp")]
use std::net::SocketAddr;
#[cfg(feature = "mcp")]
use virustotal_rs::{ApiTier, ClientBuilder};

#[cfg(feature = "mcp")]
use virustotal_rs::mcp::run_http_server;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    #[cfg(not(feature = "mcp"))]
    {
        eprintln!("This example requires the 'mcp' feature to be enabled.");
        eprintln!("Run with: cargo run --example mcp_http_server --features mcp");
        std::process::exit(1);
    }

    #[cfg(feature = "mcp")]
    {
        // Initialize logging
        tracing_subscriber::fmt()
            .with_env_filter(
                tracing_subscriber::EnvFilter::from_default_env()
                    .add_directive("virustotal_rs=info".parse().unwrap())
                    .add_directive("mcp_http_server=info".parse().unwrap())
                    .add_directive("axum=info".parse().unwrap()),
            )
            .with_target(false)
            .init();

        // Get API key from environment
        let api_key = env::var("VIRUSTOTAL_API_KEY")
            .map_err(|_| "VIRUSTOTAL_API_KEY environment variable is required")?;

        // Get HTTP address from environment (default to localhost:3000)
        let addr: SocketAddr = env::var("HTTP_ADDR")
            .unwrap_or_else(|_| "127.0.0.1:3000".to_string())
            .parse()
            .map_err(|e| format!("Invalid HTTP_ADDR: {}", e))?;

        // Determine API tier from environment (default to Public)
        let api_tier = match env::var("VIRUSTOTAL_API_TIER").as_deref() {
            Ok("Premium") => ApiTier::Premium,
            _ => {
                tracing::info!(
                    "Using Public API tier. Set VIRUSTOTAL_API_TIER=Premium for higher tier"
                );
                ApiTier::Public
            }
        };

        tracing::info!("Starting VirusTotal MCP HTTP server...");
        tracing::info!("API Tier: {:?}", api_tier);
        tracing::info!("Server will listen on: http://{}", addr);
        tracing::info!(
            "Connect using: npx @modelcontextprotocol/inspector http://{}",
            addr
        );
        tracing::info!("Health check: curl http://{}/health", addr);

        // Create VirusTotal client
        let client = ClientBuilder::new()
            .api_key(api_key)
            .tier(api_tier)
            .build()?;

        // Run the HTTP server
        tracing::info!("Server starting...");
        run_http_server(client, addr).await?;

        Ok(())
    }
}

#[cfg(all(feature = "mcp", test))]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn test_example_compiles() {
        // This test just ensures the example compiles correctly
        // when the MCP feature is enabled
    }

    #[test]
    fn test_default_address_parsing() {
        let addr: SocketAddr = "127.0.0.1:3000".parse().unwrap();
        assert_eq!(addr.ip(), IpAddr::V4(Ipv4Addr::LOCALHOST));
        assert_eq!(addr.port(), 3000);
    }

    #[test]
    fn test_custom_address_parsing() {
        let addr: SocketAddr = "0.0.0.0:8080".parse().unwrap();
        assert_eq!(addr.ip(), IpAddr::V4(Ipv4Addr::UNSPECIFIED));
        assert_eq!(addr.port(), 8080);
    }
}
