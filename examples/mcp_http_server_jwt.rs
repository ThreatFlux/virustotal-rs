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

use anyhow::Result;
use virustotal_rs::mcp::{transport::ServerConfig, JwtConfig};

#[tokio::main]
async fn main() -> Result<()> {
    // Get API key from environment
    let api_key = std::env::var("VIRUSTOTAL_API_KEY")
        .expect("VIRUSTOTAL_API_KEY environment variable is required");

    // Get server address
    let addr = std::env::var("HTTP_ADDR")
        .unwrap_or_else(|_| "127.0.0.1:3000".to_string())
        .parse()
        .expect("Invalid HTTP_ADDR format");

    // Configure JWT
    let jwt_config = if let Ok(secret) = std::env::var("JWT_SECRET") {
        println!("Using custom JWT secret");
        JwtConfig::new(secret)
    } else {
        println!("Using auto-generated JWT secret");
        JwtConfig::default()
    };

    let jwt_config = if let Ok(expiry_str) = std::env::var("JWT_EXPIRY_SECONDS") {
        if let Ok(expiry) = expiry_str.parse::<u64>() {
            println!("JWT tokens will expire in {} seconds", expiry);
            jwt_config.with_expiration(expiry)
        } else {
            jwt_config
        }
    } else {
        println!("JWT tokens will expire in 24 hours (default)");
        jwt_config
    };

    // Enable debug if requested
    let debug = std::env::var("DEBUG").is_ok();
    if debug {
        println!("Debug logging enabled");
    }

    println!("🚀 Starting VirusTotal MCP HTTP Server with JWT Authentication");
    println!("📡 Server will listen on: http://{}", addr);
    println!("🔒 JWT Authentication: ENABLED");
    println!();
    println!("📋 Available endpoints:");
    println!("   POST /auth/token     - Get access token");
    println!("   POST /auth/refresh   - Refresh access token");
    println!("   POST /               - MCP requests (requires auth)");
    println!("   GET  /health         - Health check (no auth)");
    println!();
    println!("🔑 Default credentials:");
    println!("   Admin: admin / admin123 (full permissions)");
    println!("   User:  user / user123   (read-only permissions)");
    println!();
    println!("💡 Get a token:");
    println!("   curl -X POST http://{}/auth/token \\", addr);
    println!("        -H \"Content-Type: application/json\" \\");
    println!("        -d '{{\"username\": \"admin\", \"password\": \"admin123\"}}'");
    println!();
    println!("🛠️  Test MCP call:");
    println!("   curl -X POST http://{0}/ \\", addr);
    println!("        -H \"Authorization: Bearer <token>\" \\");
    println!("        -H \"Content-Type: application/json\" \\");
    println!("        -d '{{\"jsonrpc\": \"2.0\", \"method\": \"tools/list\", \"id\": 1}}'");
    println!();
    println!("Press Ctrl+C to stop the server");
    println!("{}", "=".repeat(80));

    // Create and run server
    ServerConfig::new()
        .api_key(api_key)
        .http_addr(addr)
        .with_jwt(jwt_config)
        .debug(debug)
        .run()
        .await
}
