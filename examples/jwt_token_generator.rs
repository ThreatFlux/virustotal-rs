//! JWT Token Generator for VirusTotal MCP Server
//!
//! This utility generates JWT tokens that can be used with the JWT-enabled MCP HTTP server.
//! Useful for testing and integration purposes.
//!
//! Usage:
//!   cargo run --example jwt_token_generator --features mcp-jwt
//!   cargo run --example jwt_token_generator --features mcp-jwt -- --user admin --role admin
//!   cargo run --example jwt_token_generator --features mcp-jwt -- --secret my-secret --expiry 3600

use anyhow::Result;
use virustotal_rs::mcp::auth::{JwtConfig, JwtManager};

#[cfg(feature = "clap")]
use clap::Parser;

#[cfg(feature = "clap")]
#[derive(Parser)]
#[command(name = "jwt-token-generator")]
#[command(about = "Generate JWT tokens for VirusTotal MCP server")]
struct Args {
    /// User ID for the token
    #[arg(short, long, default_value = "admin")]
    user: String,

    /// Role for the user (admin, user, readonly)
    #[arg(short, long, default_value = "admin")]
    role: String,

    /// JWT secret key (if not provided, a random one is generated)
    #[arg(short, long)]
    secret: Option<String>,

    /// Token expiration in seconds
    #[arg(short, long, default_value = "86400")]
    expiry: u64,

    /// Custom permissions (comma-separated)
    #[arg(short, long)]
    permissions: Option<String>,

    /// Output format (token, json, full)
    #[arg(short, long, default_value = "token")]
    output: String,
}

#[cfg(not(feature = "clap"))]
struct Args {
    user: String,
    role: String,
    secret: Option<String>,
    expiry: u64,
    permissions: Option<String>,
    output: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    #[cfg(feature = "clap")]
    let args = Args::parse();
    
    #[cfg(not(feature = "clap"))]
    let args = parse_args();

    // Create JWT configuration
    let jwt_config = if let Some(secret) = &args.secret {
        JwtConfig::new(secret.clone())
    } else {
        JwtConfig::default()
    }
    .with_expiration(args.expiry);

    let jwt_manager = JwtManager::new(jwt_config.clone());

    // Generate token based on role and permissions
    let token = match args.role.as_str() {
        "admin" => jwt_manager.generate_admin_token(&args.user)?,
        "readonly" => jwt_manager.generate_readonly_token(&args.user)?,
        _ => {
            // Custom role with optional permissions
            let permissions = if let Some(perms) = &args.permissions {
                perms.split(',').map(|s| s.trim().to_string()).collect()
            } else {
                vec!["mcp:access".to_string()]
            };
            jwt_manager.generate_token_with_permissions(&args.user, &args.role, permissions)?
        }
    };

    // Validate the token to get claims
    let claims = jwt_manager.validate_token(&token)?;

    // Output in requested format
    match args.output.as_str() {
        "json" => {
            let output = serde_json::json!({
                "access_token": token,
                "token_type": "Bearer",
                "expires_in": args.expiry,
                "user_id": claims.sub,
                "role": claims.role,
                "permissions": claims.permissions,
                "issued_at": claims.iat,
                "expires_at": claims.exp
            });
            println!("{}", serde_json::to_string_pretty(&output)?);
        }
        "full" => {
            println!("🔑 JWT Token Generated");
            println!("======================");
            println!("User ID:      {}", claims.sub);
            println!("Role:         {}", claims.role);
            println!("Permissions:  {}", claims.permissions.join(", "));
            println!(
                "Issued At:    {} ({})",
                claims.iat,
                format_timestamp(claims.iat)
            );
            println!(
                "Expires At:   {} ({})",
                claims.exp,
                format_timestamp(claims.exp)
            );
            println!(
                "Secret:       {}",
                if args.secret.is_some() {
                    "Custom"
                } else {
                    "Auto-generated"
                }
            );
            println!("Valid For:    {} seconds", args.expiry);
            println!();
            println!("Token:");
            println!("{}", token);
            println!();
            println!("Usage:");
            println!(
                "curl -H \"Authorization: Bearer {}\" http://localhost:3000/",
                token
            );
        }
        _ => {
            // Default: just output the token
            println!("{}", token);
        }
    }

    Ok(())
}

fn format_timestamp(timestamp: usize) -> String {
    use chrono::DateTime;
    match DateTime::from_timestamp(timestamp as i64, 0) {
        Some(dt) => dt.format("%Y-%m-%d %H:%M:%S UTC").to_string(),
        None => "Invalid timestamp".to_string(),
    }
}

// Simple argument parser if clap is not available
#[cfg(not(feature = "clap"))]
fn parse_args() -> Args {
    let args: Vec<String> = std::env::args().collect();
    let mut parsed_args = Args {
        user: "admin".to_string(),
        role: "admin".to_string(),
        secret: None,
        expiry: 86400,
        permissions: None,
        output: "token".to_string(),
    };

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--user" | "-u" => {
                if i + 1 < args.len() {
                    parsed_args.user = args[i + 1].clone();
                    i += 2;
                } else {
                    i += 1;
                }
            }
            "--role" | "-r" => {
                if i + 1 < args.len() {
                    parsed_args.role = args[i + 1].clone();
                    i += 2;
                } else {
                    i += 1;
                }
            }
            "--secret" | "-s" => {
                if i + 1 < args.len() {
                    parsed_args.secret = Some(args[i + 1].clone());
                    i += 2;
                } else {
                    i += 1;
                }
            }
            "--expiry" | "-e" => {
                if i + 1 < args.len() {
                    parsed_args.expiry = args[i + 1].parse().unwrap_or(86400);
                    i += 2;
                } else {
                    i += 1;
                }
            }
            "--output" | "-o" => {
                if i + 1 < args.len() {
                    parsed_args.output = args[i + 1].clone();
                    i += 2;
                } else {
                    i += 1;
                }
            }
            "--permissions" | "-p" => {
                if i + 1 < args.len() {
                    parsed_args.permissions = Some(args[i + 1].clone());
                    i += 2;
                } else {
                    i += 1;
                }
            }
            _ => i += 1,
        }
    }

    parsed_args
}

