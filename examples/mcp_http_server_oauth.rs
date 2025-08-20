//! VirusTotal MCP HTTP Server with OAuth 2.1 Authentication
//!
//! This example demonstrates how to run the VirusTotal MCP server with OAuth 2.1
//! authentication support, providing secure access through the OAuth 2.1 authorization
//! flow with PKCE (Proof Key for Code Exchange).
//!
//! # Features
//!
//! - **OAuth 2.1 Flow**: Complete authorization code flow with PKCE
//! - **Session Management**: Secure session handling with CSRF protection
//! - **Token Management**: Access token and refresh token support
//! - **MCP Inspector Compatible**: Works with MCP Inspector and other OAuth-capable clients
//!
//! # Usage
//!
//! ```bash
//! # Set required environment variables
//! export VIRUSTOTAL_API_KEY="your_virustotal_api_key"
//! export HTTP_ADDR="127.0.0.1:3000"
//! export OAUTH_CLIENT_ID="virustotal-mcp-client"
//! export OAUTH_AUTH_SERVER_URL="http://localhost:8080"
//! export OAUTH_REDIRECT_URI="http://localhost:3000/oauth/callback"
//!
//! # Run the server
//! cargo run --example mcp_http_server_oauth --features mcp-oauth
//! ```
//!
//! # OAuth Flow
//!
//! 1. Start authorization: GET /oauth/authorize
//! 2. User is redirected to authorization server
//! 3. Authorization server redirects back to /oauth/callback with code
//! 4. Server exchanges code for access token
//! 5. Client uses access token for MCP requests
//!
//! # Environment Variables
//!
//! | Variable | Description | Default |
//! |----------|-------------|---------|
//! | `VIRUSTOTAL_API_KEY` | VirusTotal API key | Required |
//! | `HTTP_ADDR` | Server bind address | `127.0.0.1:3000` |
//! | `OAUTH_CLIENT_ID` | OAuth client ID | `virustotal-mcp-client` |
//! | `OAUTH_CLIENT_SECRET` | OAuth client secret | None (public client) |
//! | `OAUTH_AUTH_SERVER_URL` | Authorization server URL | `http://localhost:8080` |
//! | `OAUTH_REDIRECT_URI` | OAuth redirect URI | `http://localhost:3000/oauth/callback` |
//! | `OAUTH_SCOPES` | Comma-separated scopes | `mcp,profile` |

#[cfg(feature = "mcp-oauth")]
use std::{env, net::SocketAddr};
#[cfg(feature = "mcp-oauth")]
use virustotal_rs::{
    mcp::{oauth::OAuthConfig, transport::ServerConfig},
    ApiTier,
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    #[cfg(not(feature = "mcp-oauth"))]
    {
        eprintln!("This example requires the 'mcp-oauth' feature to be enabled.");
        eprintln!("Run with: cargo run --example mcp_http_server_oauth --features mcp-oauth");
        std::process::exit(1);
    }

    #[cfg(feature = "mcp-oauth")]
    {
        // Initialize logging
        tracing_subscriber::fmt()
            .with_target(false)
            .with_thread_ids(true)
            .with_level(true)
            .with_ansi(true)
            .init();

        // Get configuration from environment
        let api_key = env::var("VIRUSTOTAL_API_KEY")
            .expect("VIRUSTOTAL_API_KEY environment variable is required");

        let http_addr = env::var("HTTP_ADDR")
            .unwrap_or_else(|_| "127.0.0.1:3000".to_string())
            .parse::<SocketAddr>()
            .expect("Invalid HTTP_ADDR format");

        let api_tier = match env::var("VIRUSTOTAL_API_TIER").as_deref() {
            Ok("Premium") => ApiTier::Premium,
            _ => ApiTier::Public,
        };

        // Configure OAuth
        let client_id =
            env::var("OAUTH_CLIENT_ID").unwrap_or_else(|_| "virustotal-mcp-client".to_string());

        let auth_server_url = env::var("OAUTH_AUTH_SERVER_URL")
            .unwrap_or_else(|_| "http://localhost:8080".to_string());

        let mut oauth_config = OAuthConfig::new(client_id, auth_server_url);

        // Optional client secret for confidential clients
        if let Ok(client_secret) = env::var("OAUTH_CLIENT_SECRET") {
            oauth_config = oauth_config.with_client_secret(client_secret);
        }

        // Optional custom redirect URI
        if let Ok(redirect_uri) = env::var("OAUTH_REDIRECT_URI") {
            oauth_config = oauth_config.with_redirect_uri(redirect_uri);
        } else {
            // Default to server's callback endpoint
            oauth_config =
                oauth_config.with_redirect_uri(format!("http://{}/oauth/callback", http_addr));
        }

        // Optional custom scopes
        if let Ok(scopes_str) = env::var("OAUTH_SCOPES") {
            let scopes: Vec<String> = scopes_str
                .split(',')
                .map(|s| s.trim().to_string())
                .collect();
            oauth_config = oauth_config.with_scopes(scopes);
        }

        // Enable debug mode if requested
        let debug = env::var("DEBUG").is_ok();

        println!("🚀 Starting VirusTotal MCP Server with OAuth 2.1 Authentication");
        println!("📍 Server Address: {}", http_addr);
        println!("🔐 OAuth Client ID: {}", oauth_config.client_id);
        println!("🔗 Auth Server: {}", oauth_config.auth_server_url);
        println!("↩️  Redirect URI: {}", oauth_config.redirect_uri);
        println!("🎯 Scopes: {}", oauth_config.scopes.join(", "));
        println!(
            "🔒 PKCE: {}",
            if oauth_config.use_pkce {
                "Enabled"
            } else {
                "Disabled"
            }
        );
        println!();
        println!("📋 Available endpoints:");
        println!("  GET  /health              - Health check");
        println!("  GET  /oauth/authorize     - Start OAuth flow");
        println!("  GET  /oauth/callback      - OAuth callback");
        println!("  POST /oauth/token         - Token exchange/refresh");
        println!("  GET  /oauth/metadata      - OAuth server metadata");
        println!("  POST /                    - MCP requests (requires auth)");
        println!();
        println!("🔧 Example OAuth flow:");
        println!("  1. GET http://{}/oauth/authorize", http_addr);
        println!("  2. Complete authorization on auth server");
        println!("  3. Use returned access token for MCP requests");
        println!();
        println!("💡 For testing with curl:");
        println!("  curl http://{}/oauth/metadata", http_addr);
        println!();

        // Create and run server
        let config = ServerConfig::new()
            .api_key(api_key)
            .api_tier(api_tier)
            .http_addr(http_addr)
            .debug(debug)
            .with_oauth(oauth_config);

        if let Err(e) = config.run().await {
            eprintln!("❌ Server error: {}", e);
            std::process::exit(1);
        }
        
        Ok(())
    }
}
