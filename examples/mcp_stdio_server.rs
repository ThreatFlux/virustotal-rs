//! MCP STDIO Server Example for VirusTotal SDK
//!
//! This example demonstrates how to run a VirusTotal MCP server using STDIO transport.
//! This is the recommended mode for local usage and integration with MCP Inspector.
//!
//! Usage:
//!   VIRUSTOTAL_API_KEY=your_api_key cargo run --example mcp_stdio_server --features mcp
//!
//! Test with MCP Inspector:
//!   npx @modelcontextprotocol/inspector cargo run --example mcp_stdio_server --features mcp

use std::env;
use virustotal_rs::{ApiTier, ClientBuilder};

#[cfg(feature = "mcp")]
use virustotal_rs::mcp::run_stdio_server;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    #[cfg(not(feature = "mcp"))]
    {
        eprintln!("This example requires the 'mcp' feature to be enabled.");
        eprintln!("Run with: cargo run --example mcp_stdio_server --features mcp");
        std::process::exit(1);
    }

    #[cfg(feature = "mcp")]
    {
        // Initialize logging
        tracing_subscriber::fmt()
            .with_env_filter(
                tracing_subscriber::EnvFilter::from_default_env()
                    .add_directive("virustotal_rs=info".parse().unwrap())
                    .add_directive("mcp_stdio_server=info".parse().unwrap()),
            )
            .with_target(false)
            .init();

        // Get API key from environment
        let api_key = env::var("VIRUSTOTAL_API_KEY")
            .map_err(|_| "VIRUSTOTAL_API_KEY environment variable is required")?;

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

        tracing::info!("Starting VirusTotal MCP STDIO server...");
        tracing::info!("API Tier: {:?}", api_tier);
        tracing::info!("Connect using: npx @modelcontextprotocol/inspector <this-command>");

        // Create VirusTotal client
        let client = ClientBuilder::new()
            .api_key(api_key)
            .tier(api_tier)
            .build()?;

        // Run the STDIO server
        run_stdio_server(client).await?;
    }

    Ok(())
}

#[cfg(all(feature = "mcp", test))]
mod tests {
    use super::*;

    #[test]
    fn test_example_compiles() {
        // This test just ensures the example compiles correctly
        // when the MCP feature is enabled
    }
}
