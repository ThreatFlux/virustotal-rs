//! MCP Server Command Module
//!
//! This module provides CLI integration for running the VirusTotal MCP server
//! in both STDIO and HTTP transport modes.

use anyhow::Result;
use clap::{Args, Subcommand};
use std::net::SocketAddr;
use std::str::FromStr;

use crate::{ApiTier, ClientBuilder};

/// Command line arguments for MCP server configuration
#[derive(Args, Debug, Clone)]
pub struct McpCommand {
    /// API key (can also be set via VIRUSTOTAL_API_KEY environment variable)
    #[arg(short = 'k', long, env = "VIRUSTOTAL_API_KEY")]
    pub api_key: Option<String>,

    /// API tier (public or premium)
    #[arg(
        short = 't',
        long,
        default_value = "public",
        env = "VIRUSTOTAL_API_TIER"
    )]
    pub tier: String,

    #[command(subcommand)]
    pub transport: McpTransport,
}

/// Transport mode for MCP server communication
#[derive(Subcommand, Debug, Clone)]
pub enum McpTransport {
    /// Run MCP server using STDIO transport (recommended for local usage)
    Stdio,
    /// Run MCP server using HTTP transport (for remote access)
    Http {
        /// HTTP server address to bind to
        #[arg(short = 'a', long, default_value = "127.0.0.1:3000", env = "HTTP_ADDR")]
        addr: String,
        /// Enable JWT authentication (requires mcp-jwt feature)
        #[arg(long)]
        #[cfg(feature = "mcp-jwt")]
        jwt: bool,
        /// JWT secret for token signing (required when --jwt is used)
        #[arg(long, env = "JWT_SECRET")]
        #[cfg(feature = "mcp-jwt")]
        jwt_secret: Option<String>,
        /// Enable OAuth authentication (requires mcp-oauth feature)
        #[arg(long)]
        #[cfg(feature = "mcp-oauth")]
        oauth: bool,
        /// OAuth client ID (required when --oauth is used)
        #[arg(long, env = "OAUTH_CLIENT_ID")]
        #[cfg(feature = "mcp-oauth")]
        oauth_client_id: Option<String>,
        /// OAuth client secret (required when --oauth is used)
        #[arg(long, env = "OAUTH_CLIENT_SECRET")]
        #[cfg(feature = "mcp-oauth")]
        oauth_client_secret: Option<String>,
    },
}

/// Execute the MCP command
///
/// # Errors
///
/// Returns an error if:
/// - No API key is provided via command line or environment variable
/// - Invalid API key format
/// - MCP feature is not enabled during compilation
/// - Server startup fails (invalid address, port binding issues, etc.)
/// - JWT/OAuth configuration errors when authentication is enabled
pub async fn execute(cmd: McpCommand, verbose: bool) -> Result<()> {
    // Set up logging
    if verbose {
        tracing_subscriber::fmt()
            .with_env_filter(
                tracing_subscriber::EnvFilter::from_default_env()
                    .add_directive("virustotal_rs=debug".parse()?)
                    .add_directive("vt_cli=debug".parse()?)
                    .add_directive("axum=info".parse()?),
            )
            .with_target(false)
            .init();
    } else {
        tracing_subscriber::fmt()
            .with_env_filter(
                tracing_subscriber::EnvFilter::from_default_env()
                    .add_directive("virustotal_rs=info".parse()?)
                    .add_directive("vt_cli=info".parse()?)
                    .add_directive("axum=info".parse()?),
            )
            .with_target(false)
            .init();
    }

    // Get API key from command line argument or environment variable
    let api_key = cmd
        .api_key
        .or_else(|| std::env::var("VIRUSTOTAL_API_KEY").ok())
        .ok_or_else(|| {
            anyhow::anyhow!(
                "API key required. Use --api-key or set VIRUSTOTAL_API_KEY environment variable"
            )
        })?;

    // Determine API tier
    let api_tier = match cmd.tier.to_lowercase().as_str() {
        "premium" | "private" => {
            tracing::info!("Using Premium API tier");
            ApiTier::Premium
        }
        _ => {
            tracing::info!("Using Public API tier. Use --tier premium for higher tier");
            ApiTier::Public
        }
    };

    // Create VirusTotal client
    let client = ClientBuilder::new()
        .api_key(api_key)
        .tier(api_tier)
        .build()?;

    match cmd.transport {
        McpTransport::Stdio => {
            tracing::info!("Starting VirusTotal MCP STDIO server...");
            tracing::info!("API Tier: {:?}", api_tier);
            tracing::info!("Connect using: npx @modelcontextprotocol/inspector <this-command>");

            #[cfg(feature = "mcp")]
            {
                use crate::mcp::run_stdio_server;
                run_stdio_server(client).await?;
            }
            #[cfg(not(feature = "mcp"))]
            {
                return Err(anyhow::anyhow!(
                    "MCP feature not enabled. Rebuild with --features mcp"
                ));
            }
        }
        McpTransport::Http {
            addr,
            #[cfg(feature = "mcp-jwt")]
            jwt,
            #[cfg(feature = "mcp-jwt")]
            jwt_secret,
            #[cfg(feature = "mcp-oauth")]
            oauth,
            #[cfg(feature = "mcp-oauth")]
            oauth_client_id,
            #[cfg(feature = "mcp-oauth")]
            oauth_client_secret,
        } => {
            let socket_addr = SocketAddr::from_str(&addr)
                .map_err(|e| anyhow::anyhow!("Invalid address '{addr}': {e}"))?;

            tracing::info!("Starting VirusTotal MCP HTTP server...");
            tracing::info!("API Tier: {:?}", api_tier);
            tracing::info!("Server will listen on: http://{socket_addr}");
            tracing::info!(
                "Connect using: npx @modelcontextprotocol/inspector http://{socket_addr}"
            );
            tracing::info!("Health check: curl http://{socket_addr}/health");

            #[cfg(feature = "mcp")]
            {
                #[cfg(feature = "mcp-jwt")]
                if jwt {
                    let secret = jwt_secret.ok_or_else(|| anyhow::anyhow!(
                        "JWT secret required when --jwt is enabled. Use --jwt-secret or set JWT_SECRET"
                    ))?;

                    use crate::mcp::JwtConfig;
                    let jwt_config = JwtConfig::new(secret);

                    tracing::info!("JWT authentication enabled");

                    use crate::mcp::transport::http::run_http_server_with_config;

                    run_http_server_with_config(client, socket_addr, Some(jwt_config)).await?;
                    return Ok(());
                }

                #[cfg(feature = "mcp-oauth")]
                if oauth {
                    let client_id = oauth_client_id.ok_or_else(|| anyhow::anyhow!(
                        "OAuth client ID required when --oauth is enabled. Use --oauth-client-id or set OAUTH_CLIENT_ID"
                    ))?;
                    let client_secret = oauth_client_secret.ok_or_else(|| anyhow::anyhow!(
                        "OAuth client secret required when --oauth is enabled. Use --oauth-client-secret or set OAUTH_CLIENT_SECRET"
                    ))?;

                    use crate::mcp::OAuthConfig;
                    let mut oauth_config = OAuthConfig::new(client_id, "http://localhost:8080");
                    oauth_config = oauth_config
                        .with_client_secret(client_secret)
                        .with_redirect_uri(format!("http://{socket_addr}/oauth/callback"));

                    tracing::info!("OAuth authentication enabled");

                    use crate::mcp::transport::run_http_server_with_oauth;
                    run_http_server_with_oauth(client, socket_addr, oauth_config).await?;
                    return Ok(());
                }

                // Run basic HTTP server without authentication
                use crate::mcp::run_http_server;
                run_http_server(client, socket_addr).await?;
            }
            #[cfg(not(feature = "mcp"))]
            {
                return Err(anyhow::anyhow!(
                    "MCP feature not enabled. Rebuild with --features mcp"
                ));
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_api_tier_parsing() {
        assert!(matches!(
            parse_api_tier("premium".to_string()),
            ApiTier::Premium
        ));
        assert!(matches!(
            parse_api_tier("private".to_string()),
            ApiTier::Premium
        ));
        assert!(matches!(
            parse_api_tier("public".to_string()),
            ApiTier::Public
        ));
        assert!(matches!(
            parse_api_tier("invalid".to_string()),
            ApiTier::Public
        ));
    }

    fn parse_api_tier(tier: String) -> ApiTier {
        match tier.to_lowercase().as_str() {
            "premium" | "private" => ApiTier::Premium,
            _ => ApiTier::Public,
        }
    }
}
