//! VirusTotal MCP HTTP Server with JWT Authentication
//!
//! This example demonstrates how to run the VirusTotal MCP server in HTTP mode
//! with JWT authentication enabled for secure access.
//!
//! ## Usage
//!
//! ### Environment Variables:
//! - `VIRUSTOTAL_API_KEY`: Your VirusTotal API key (required)
//! - `HTTP_ADDR`: Server address (default: 127.0.0.1:3000)  
//! - `JWT_SECRET`: Custom JWT secret (optional, auto-generated if not set)
//! - `JWT_EXPIRY_SECONDS`: Token expiration in seconds (default: 86400/24 hours)
//! - `DEBUG`: Enable debug logging (optional)
//!
//! ### Running:
//! ```bash
//! VIRUSTOTAL_API_KEY=your_key cargo run --example mcp_http_server_jwt --features mcp-jwt
//! ```
//!
//! ### Authentication:
//! 1. Get a token: `curl -X POST http://127.0.0.1:3000/auth/token -H "Content-Type: application/json" -d '{"username": "admin", "password": "admin123"}'`
//! 2. Use token: `curl -X POST http://127.0.0.1:3000/ -H "Authorization: Bearer <token>" -H "Content-Type: application/json" -d '{"jsonrpc": "2.0", "method": "tools/list", "id": 1}'`
//!
//! ### Default Credentials:
//! - Admin: `admin` / `admin123` (full permissions)
//! - User: `user` / `user123` (read-only permissions)
//!
//! ### Test with MCP Inspector:
//! ```bash
//! # First get a token
//! TOKEN=$(curl -s -X POST http://127.0.0.1:3000/auth/token -H "Content-Type: application/json" -d '{"username": "admin", "password": "admin123"}' | jq -r '.access_token')
//!
//! # Then use with inspector (note: inspector may need manual token configuration)
//! npx @modelcontextprotocol/inspector http://127.0.0.1:3000
//! ```

#[cfg(feature = "mcp-jwt")]
use anyhow::Result;
#[cfg(feature = "mcp-jwt")]
use virustotal_rs::mcp::{transport::ServerConfig, JwtConfig};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    #[cfg(not(feature = "mcp-jwt"))]
    {
        print_feature_error();
        std::process::exit(1);
    }

    #[cfg(feature = "mcp-jwt")]
    {
        let config = setup_server_config()?;
        run_server(config).await?;
        Ok(())
    }
}

/// Print feature error message
#[cfg(not(feature = "mcp-jwt"))]
fn print_feature_error() {
    eprintln!("This example requires the 'mcp-jwt' feature to be enabled.");
    eprintln!("Run with: cargo run --example mcp_http_server_jwt --features mcp-jwt");
}

/// Setup server configuration
#[cfg(feature = "mcp-jwt")]
fn setup_server_config() -> Result<ServerConfig, Box<dyn std::error::Error>> {
    let api_key = get_api_key()?;
    let addr = get_server_address()?;
    let jwt_config = setup_jwt_config();
    let debug = is_debug_enabled();

    print_startup_info(&addr, debug);

    Ok(ServerConfig::new()
        .api_key(api_key)
        .http_addr(addr)
        .with_jwt(jwt_config)
        .debug(debug))
}

/// Get API key from environment
#[cfg(feature = "mcp-jwt")]
fn get_api_key() -> Result<String, Box<dyn std::error::Error>> {
    std::env::var("VIRUSTOTAL_API_KEY")
        .map_err(|_| "VIRUSTOTAL_API_KEY environment variable is required".into())
}

/// Get server address from environment
#[cfg(feature = "mcp-jwt")]
fn get_server_address() -> Result<std::net::SocketAddr, Box<dyn std::error::Error>> {
    let addr_str = std::env::var("HTTP_ADDR").unwrap_or_else(|_| "127.0.0.1:3000".to_string());

    addr_str
        .parse()
        .map_err(|_| "Invalid HTTP_ADDR format".into())
}

/// Setup JWT configuration
#[cfg(feature = "mcp-jwt")]
fn setup_jwt_config() -> JwtConfig {
    let jwt_config = create_jwt_config();
    configure_jwt_expiry(jwt_config)
}

/// Create JWT configuration with secret
#[cfg(feature = "mcp-jwt")]
fn create_jwt_config() -> JwtConfig {
    if let Ok(secret) = std::env::var("JWT_SECRET") {
        println!("Using custom JWT secret");
        JwtConfig::new(secret)
    } else {
        println!("Using auto-generated JWT secret");
        JwtConfig::default()
    }
}

/// Configure JWT token expiry
#[cfg(feature = "mcp-jwt")]
fn configure_jwt_expiry(jwt_config: JwtConfig) -> JwtConfig {
    if let Ok(expiry_str) = std::env::var("JWT_EXPIRY_SECONDS") {
        if let Ok(expiry) = expiry_str.parse::<u64>() {
            println!("JWT tokens will expire in {} seconds", expiry);
            return jwt_config.with_expiration(expiry);
        }
    }
    println!("JWT tokens will expire in 24 hours (default)");
    jwt_config
}

/// Check if debug mode is enabled
#[cfg(feature = "mcp-jwt")]
fn is_debug_enabled() -> bool {
    let debug = std::env::var("DEBUG").is_ok();
    if debug {
        println!("Debug logging enabled");
    }
    debug
}

/// Print startup information
#[cfg(feature = "mcp-jwt")]
fn print_startup_info(addr: &std::net::SocketAddr, _debug: bool) {
    print_server_header(addr);
    print_endpoints_info();
    print_credentials_info();
    print_usage_examples(addr);
    print_startup_footer();
}

/// Print server header
#[cfg(feature = "mcp-jwt")]
fn print_server_header(addr: &std::net::SocketAddr) {
    println!("🚀 Starting VirusTotal MCP HTTP Server with JWT Authentication");
    println!("📡 Server will listen on: http://{}", addr);
    println!("🔒 JWT Authentication: ENABLED");
    println!();
}

/// Print available endpoints
#[cfg(feature = "mcp-jwt")]
fn print_endpoints_info() {
    println!("📋 Available endpoints:");
    println!("   POST /auth/token     - Get access token");
    println!("   POST /auth/refresh   - Refresh access token");
    println!("   POST /               - MCP requests (requires auth)");
    println!("   GET  /health         - Health check (no auth)");
    println!();
}

/// Print default credentials
#[cfg(feature = "mcp-jwt")]
fn print_credentials_info() {
    println!("🔑 Default credentials:");
    println!("   Admin: admin / admin123 (full permissions)");
    println!("   User:  user / user123   (read-only permissions)");
    println!();
}

/// Print usage examples
#[cfg(feature = "mcp-jwt")]
fn print_usage_examples(addr: &std::net::SocketAddr) {
    print_token_example(addr);
    print_mcp_call_example(addr);
}

/// Print token acquisition example
#[cfg(feature = "mcp-jwt")]
fn print_token_example(addr: &std::net::SocketAddr) {
    println!("💡 Get a token:");
    println!("   curl -X POST http://{}/auth/token \\", addr);
    println!("        -H \"Content-Type: application/json\" \\");
    println!("        -d '{{\"username\": \"admin\", \"password\": \"admin123\"}}'");
    println!();
}

/// Print MCP call example
#[cfg(feature = "mcp-jwt")]
fn print_mcp_call_example(addr: &std::net::SocketAddr) {
    println!("🛠️  Test MCP call:");
    println!("   curl -X POST http://{0}/ \\", addr);
    println!("        -H \"Authorization: Bearer <token>\" \\");
    println!("        -H \"Content-Type: application/json\" \\");
    println!("        -d '{{\"jsonrpc\": \"2.0\", \"method\": \"tools/list\", \"id\": 1}}'");
    println!();
}

/// Print startup footer
#[cfg(feature = "mcp-jwt")]
fn print_startup_footer() {
    println!("Press Ctrl+C to stop the server");
    println!("{}", "=".repeat(80));
}

/// Run the server with configuration
#[cfg(feature = "mcp-jwt")]
async fn run_server(config: ServerConfig) -> Result<(), Box<dyn std::error::Error>> {
    config.run().await?;
    Ok(())
}
