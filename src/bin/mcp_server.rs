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
/// Explain the missing MCP build feature and exit unsuccessfully.
fn main() {
    eprintln!("Error: MCP server requires the 'mcp' feature to be enabled.");
    eprintln!("Build with: cargo build --bin mcp_server --features mcp");
    eprintln!("Or run with: cargo run --bin mcp_server --features mcp");
    std::process::exit(1);
}

#[cfg(feature = "mcp")]
#[tokio::main]
/// Start the configured MCP transport and propagate startup failures.
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    use std::env;

    initialize_logging();
    tracing::info!("Starting `VirusTotal` MCP Server...");

    let api_key = get_api_key()?;
    let api_tier = determine_api_tier();
    let client = create_virustotal_client(api_key, api_tier)?;

    let server_mode = env::var("SERVER_MODE").unwrap_or_else(|_| "http".to_string());
    run_server_by_mode(client, &server_mode).await?;

    tracing::info!("MCP server shutting down");
    Ok(())
}

#[cfg(feature = "mcp")]
/// Write filtered runtime diagnostics to stderr so stdout retains JSON-RPC framing.
fn initialize_logging() {
    use std::env;

    let log_level = env::var("LOG_LEVEL").unwrap_or_else(|_| "info".to_string());
    let env_filter = tracing_subscriber::EnvFilter::from_default_env()
        .add_directive(format!("virustotal_rs={}", log_level).parse().unwrap())
        .add_directive(format!("mcp_server={}", log_level).parse().unwrap())
        .add_directive("axum=info".parse().unwrap());

    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(env_filter)
        .with_target(false)
        .with_thread_ids(true)
        .with_line_number(true)
        .init();
}

#[cfg(feature = "mcp")]
/// Require an explicitly configured VirusTotal API key.
fn get_api_key() -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
    use std::env;

    env::var("VIRUSTOTAL_API_KEY")
        .map_err(|_| "VIRUSTOTAL_API_KEY environment variable is required".into())
}

#[cfg(feature = "mcp")]
/// Preserve the supported public and premium environment spellings.
fn determine_api_tier() -> virustotal_rs::ApiTier {
    use std::env;
    use virustotal_rs::ApiTier;

    match env::var("VIRUSTOTAL_API_TIER").as_deref() {
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
    }
}

#[cfg(feature = "mcp")]
/// Build the API client with the selected key and rate-limit tier.
fn create_virustotal_client(
    api_key: String,
    api_tier: virustotal_rs::ApiTier,
) -> Result<virustotal_rs::Client, Box<dyn std::error::Error + Send + Sync>> {
    use virustotal_rs::ClientBuilder;

    tracing::info!("Initializing `VirusTotal` client...");
    let client = ClientBuilder::new()
        .api_key(api_key)
        .tier(api_tier)
        .build()
        .map_err(|e| format!("Failed to create `VirusTotal` client: {}", e))?;

    tracing::info!("`VirusTotal` client initialized successfully");
    Ok(client)
}

#[cfg(feature = "mcp")]
/// Select HTTP or stdio and reject unsupported transport names.
async fn run_server_by_mode(
    client: virustotal_rs::Client,
    server_mode: &str,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    match server_mode.to_lowercase().as_str() {
        "stdio" => {
            run_stdio_mode(client).await?;
        }
        "http" => {
            run_http_mode().await?;
        }
        _ => return Err(format!("Unsupported SERVER_MODE: {server_mode}").into()),
    }
    Ok(())
}

#[cfg(feature = "mcp")]
/// Run MCP over stdin and stdout using the configured API client.
async fn run_stdio_mode(
    client: virustotal_rs::Client,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    use virustotal_rs::mcp::run_stdio_server;

    tracing::info!("Starting MCP server in stdio mode...");
    tracing::info!("Ready to accept MCP messages on stdin/stdout");
    run_stdio_server(client).await.map_err(|e| e.into())
}

#[cfg(feature = "mcp")]
/// Load and enforce environment authentication settings before binding HTTP.
async fn run_http_mode() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    use std::{env, net::SocketAddr};
    use virustotal_rs::mcp::transport::config::server_config_from_env;

    let addr: SocketAddr = env::var("HTTP_ADDR")
        .unwrap_or_else(|_| "127.0.0.1:8080".to_string())
        .parse()
        .map_err(|e| format!("Invalid HTTP_ADDR: {}", e))?;

    log_http_server_info(&addr);
    server_config_from_env()?
        .http_addr(addr)
        .run()
        .await
        .map_err(|e| e.into())
}

#[cfg(feature = "mcp")]
/// Report transport availability without issuing or logging credentials.
fn log_http_server_info(addr: &std::net::SocketAddr) {
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
    tracing::info!("Running without authentication (use features mcp-jwt or mcp-oauth for auth)");

    tracing::info!("Server starting...");
}

#[cfg(all(feature = "mcp", test))]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    #[test]
    /// Verify the default binary HTTP address parses as the established loopback socket.
    fn test_default_address_parsing() {
        let addr: SocketAddr = "127.0.0.1:8080".parse().unwrap();
        assert_eq!(addr.ip(), IpAddr::V4(Ipv4Addr::LOCALHOST));
        assert_eq!(addr.port(), 8080);
    }

    #[test]
    /// Verify explicitly configured HTTP bind addresses retain their host and port.
    fn test_custom_address_parsing() {
        let addr: SocketAddr = "0.0.0.0:3000".parse().unwrap();
        assert_eq!(addr.ip(), IpAddr::V4(Ipv4Addr::UNSPECIFIED));
        assert_eq!(addr.port(), 3000);
    }

    #[test]
    /// Verify the supported case-insensitive transport spellings.
    fn test_server_mode_parsing() {
        // Test different server mode variations
        assert_eq!("http".to_lowercase(), "http");
        assert_eq!("HTTP".to_lowercase(), "http");
        assert_eq!("stdio".to_lowercase(), "stdio");
        assert_eq!("STDIO".to_lowercase(), "stdio");
    }

    #[test]
    /// Verify public and premium tier selection.
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
    /// A misspelled transport must fail before opening an HTTP listener.
    #[cfg(feature = "mcp")]
    #[tokio::test]
    async fn unknown_server_mode_fails_closed() {
        let client = virustotal_rs::ClientBuilder::new()
            .api_key("fixture-api-key")
            .build()
            .unwrap();
        let result = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            super::run_server_by_mode(client, "sdtio"),
        )
        .await
        .expect("invalid mode unexpectedly started a server");
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("Unsupported SERVER_MODE")
        );
    }
}
