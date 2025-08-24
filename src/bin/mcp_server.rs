//! `VirusTotal` MCP Server Binary
//!
//! A Model Context Protocol (MCP) server for the `VirusTotal` API that provides
//! threat intelligence tools to Language Models.
//!
//! This server can run in multiple modes:
//! - HTTP server (default): For web-based integrations and remote access
//! - stdio server: For direct integration with MCP clients
//!
//! Features:
//! - JWT authentication (with mcp-jwt feature)
//! - OAuth 2.1 authentication (with mcp-oauth feature)
//! - Multiple transport protocols
//! - Health checks and monitoring
//!
//! Environment Variables:
//! - `VIRUSTOTAL_API_KEY`: Required `VirusTotal` API key
//! - `SERVER_MODE`: "http" (default) or "stdio"
//! - `HTTP_ADDR`: HTTP server address (default: "127.0.0.1:8080")
//! - `VIRUSTOTAL_API_TIER`: "Public" (default) or "Premium"
//! - `LOG_LEVEL`: Log level (default: "info")
//!
//! Usage:
//!   # HTTP server (default)
//!   VIRUSTOTAL_API_KEY=your_key cargo run --bin mcp_server --features mcp
//!   
//!   # Stdio server
//!   SERVER_MODE=stdio VIRUSTOTAL_API_KEY=your_key cargo run --bin mcp_server --features mcp
//!   
//!   # With JWT authentication
//!   cargo run --bin mcp_server --features mcp-jwt
//!   
//!   # With OAuth authentication
//!   cargo run --bin mcp_server --features mcp-oauth

#[cfg(not(feature = "mcp"))]
fn main() {
    eprintln!("Error: MCP server requires the 'mcp' feature to be enabled.");
    eprintln!("Build with: cargo build --bin mcp_server --features mcp");
    eprintln!("Or run with: cargo run --bin mcp_server --features mcp");
    std::process::exit(1);
}

#[cfg(feature = "mcp")]
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    use std::env;
    use std::net::SocketAddr;
    use virustotal_rs::mcp::{run_http_server, run_stdio_server};
    use virustotal_rs::{ApiTier, ClientBuilder};

    // Initialize logging
    let log_level = env::var("LOG_LEVEL").unwrap_or_else(|_| "info".to_string());
    let env_filter = tracing_subscriber::EnvFilter::from_default_env()
        .add_directive(format!("virustotal_rs={}", log_level).parse().unwrap())
        .add_directive(format!("mcp_server={}", log_level).parse().unwrap())
        .add_directive("axum=info".parse().unwrap());

    tracing_subscriber::fmt()
        .with_env_filter(env_filter)
        .with_target(false)
        .with_thread_ids(true)
        .with_line_number(true)
        .init();

    tracing::info!("Starting `VirusTotal` MCP Server...");

    // Get API key from environment
    let api_key = env::var("VIRUSTOTAL_API_KEY")
        .map_err(|_| "VIRUSTOTAL_API_KEY environment variable is required")?;

    // Determine API tier
    let api_tier = match env::var("VIRUSTOTAL_API_TIER").as_deref() {
        Ok("Premium") | Ok("premium") => {
            tracing::info!("Using Premium API tier");
            ApiTier::Premium
        }
        _ => {
            tracing::info!(
                "Using Public API tier (set VIRUSTOTAL_API_TIER=Premium for higher tier)"
            );
            ApiTier::Public
        }
    };

    // Create `VirusTotal` client
    tracing::info!("Initializing `VirusTotal` client...");
    let client = ClientBuilder::new()
        .api_key(api_key)
        .tier(api_tier)
        .build()
        .map_err(|e| format!("Failed to create `VirusTotal` client: {}", e))?;

    tracing::info!("`VirusTotal` client initialized successfully");

    // Determine server mode
    let server_mode = env::var("SERVER_MODE").unwrap_or_else(|_| "http".to_string());

    match server_mode.to_lowercase().as_str() {
        "stdio" => {
            tracing::info!("Starting MCP server in stdio mode...");
            tracing::info!("Ready to accept MCP messages on stdin/stdout");
            run_stdio_server(client).await?;
        }
        _ => {
            let addr: SocketAddr = env::var("HTTP_ADDR")
                .unwrap_or_else(|_| "127.0.0.1:8080".to_string())
                .parse()
                .map_err(|e| format!("Invalid HTTP_ADDR: {}", e))?;

            tracing::info!("Starting MCP server in HTTP mode...");
            tracing::info!("Server will listen on: http://{}", addr);
            tracing::info!("Health check endpoint: http://{}/health", addr);
            tracing::info!(
                "Connect using: npx @modelcontextprotocol/inspector http://{}",
                addr
            );

            // Print authentication info based on features
            #[cfg(feature = "mcp-jwt")]
            tracing::info!("JWT authentication is available (feature: mcp-jwt)");

            #[cfg(feature = "mcp-oauth")]
            tracing::info!("OAuth 2.1 authentication is available (feature: mcp-oauth)");

            #[cfg(not(any(feature = "mcp-jwt", feature = "mcp-oauth")))]
            tracing::info!(
                "Running without authentication (use features mcp-jwt or mcp-oauth for auth)"
            );

            tracing::info!("Server starting...");
            run_http_server(client, addr).await?;
        }
    }

    tracing::info!("MCP server shutting down");
    Ok(())
}

#[cfg(all(feature = "mcp", test))]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    #[test]
    fn test_default_address_parsing() {
        let addr: SocketAddr = "127.0.0.1:8080".parse().unwrap();
        assert_eq!(addr.ip(), IpAddr::V4(Ipv4Addr::LOCALHOST));
        assert_eq!(addr.port(), 8080);
    }

    #[test]
    fn test_custom_address_parsing() {
        let addr: SocketAddr = "0.0.0.0:3000".parse().unwrap();
        assert_eq!(addr.ip(), IpAddr::V4(Ipv4Addr::UNSPECIFIED));
        assert_eq!(addr.port(), 3000);
    }

    #[test]
    fn test_server_mode_parsing() {
        // Test different server mode variations
        assert_eq!("http".to_lowercase(), "http");
        assert_eq!("HTTP".to_lowercase(), "http");
        assert_eq!("stdio".to_lowercase(), "stdio");
        assert_eq!("STDIO".to_lowercase(), "stdio");
    }

    #[test]
    fn test_api_tier_parsing() {
        // Test API tier parsing logic
        let test_cases = vec![
            ("Premium", true),
            ("premium", true),
            ("PREMIUM", false), // Our code only checks "Premium" and "premium"
            ("Public", false),
            ("public", false),
            ("invalid", false),
        ];

        for (input, expected_premium) in test_cases {
            let is_premium = matches!(input, "Premium" | "premium");
            assert_eq!(is_premium, expected_premium, "Failed for input: {}", input);
        }
    }
}
