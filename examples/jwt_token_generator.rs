#![allow(unexpected_cfgs)]

//! JWT Token Generator for VirusTotal MCP Server
//!
//! This utility generates JWT tokens that can be used with the JWT-enabled MCP HTTP server.
//! Useful for testing and integration purposes.
//!
//! Usage:
//!   cargo run --example jwt_token_generator --features mcp-jwt
//!   cargo run --example jwt_token_generator --features mcp-jwt -- --user admin --role admin
//!   cargo run --example jwt_token_generator --features mcp-jwt -- --secret my-secret --expiry 3600

#[cfg(feature = "mcp-jwt")]
use anyhow::Result;
#[cfg(feature = "mcp-jwt")]
use virustotal_rs::mcp::auth::{Claims, JwtConfig, JwtManager};

#[allow(unexpected_cfgs)]
#[cfg(feature = "clap")]
use clap::Parser;

#[allow(unexpected_cfgs)]
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

#[allow(unexpected_cfgs)]
#[cfg(not(feature = "clap"))]
#[allow(dead_code)]
struct Args {
    user: String,
    role: String,
    secret: Option<String>,
    expiry: u64,
    permissions: Option<String>,
    output: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    #[cfg(not(feature = "mcp-jwt"))]
    {
        eprintln!("This example requires the 'mcp-jwt' feature to be enabled.");
        eprintln!("Run with: cargo run --example jwt_token_generator --features mcp-jwt");
        std::process::exit(1);
    }

    #[cfg(feature = "mcp-jwt")]
    run().await
}

#[cfg(feature = "mcp-jwt")]
async fn run() -> Result<(), Box<dyn std::error::Error>> {
    #[allow(unexpected_cfgs)]
    #[cfg(feature = "clap")]
    let args = Args::parse();

    #[allow(unexpected_cfgs)]
    #[cfg(not(feature = "clap"))]
    let args = parse_args();

    let jwt_manager = build_manager(&args);
    let token = generate_token(&jwt_manager, &args)?;
    let claims = jwt_manager.validate_token(&token)?;
    output_token(&args, &token, &claims)?;
    Ok(())
}

#[cfg(feature = "mcp-jwt")]
fn output_token(
    args: &Args,
    token: &str,
    claims: &Claims,
) -> Result<(), Box<dyn std::error::Error>> {
    match args.output.as_str() {
        "json" => print_json(args, token, claims)?,
        "full" => print_full(args, token, claims),
        _ => print_plain(token),
    }
    Ok(())
}

#[cfg(feature = "mcp-jwt")]
fn build_manager(args: &Args) -> JwtManager {
    let jwt_config = if let Some(secret) = &args.secret {
        JwtConfig::new(secret.clone())
    } else {
        JwtConfig::default()
    }
    .with_expiration(args.expiry);
    JwtManager::new(jwt_config)
}

#[cfg(feature = "mcp-jwt")]
fn generate_token(manager: &JwtManager, args: &Args) -> Result<String, Box<dyn std::error::Error>> {
    Ok(match args.role.as_str() {
        "admin" => manager.generate_admin_token(&args.user)?,
        "readonly" => manager.generate_readonly_token(&args.user)?,
        _ => {
            let permissions = args
                .permissions
                .as_deref()
                .map(|p| p.split(',').map(|s| s.trim().to_string()).collect())
                .unwrap_or_else(|| vec!["mcp:access".to_string()]);
            manager.generate_token_with_permissions(&args.user, &args.role, permissions)?
        }
    })
}

#[cfg(feature = "mcp-jwt")]
fn print_json(args: &Args, token: &str, claims: &Claims) -> Result<(), Box<dyn std::error::Error>> {
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
    Ok(())
}

#[cfg(feature = "mcp-jwt")]
fn print_full(args: &Args, token: &str, claims: &Claims) {
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

#[cfg(feature = "mcp-jwt")]
fn print_plain(token: &str) {
    println!("{}", token);
}

#[cfg(feature = "mcp-jwt")]
fn format_timestamp(timestamp: usize) -> String {
    use chrono::DateTime;
    match DateTime::from_timestamp(timestamp as i64, 0) {
        Some(dt) => dt.format("%Y-%m-%d %H:%M:%S UTC").to_string(),
        None => "Invalid timestamp".to_string(),
    }
}

// Simple argument parser if clap is not available
#[allow(unexpected_cfgs)]
#[cfg(all(feature = "mcp-jwt", not(feature = "clap")))]
fn parse_args() -> Args {
    let args: Vec<String> = std::env::args().collect();
    let mut parsed_args = create_default_args();

    parse_command_line_arguments(&args, &mut parsed_args);
    parsed_args
}

/// Create default argument values
fn create_default_args() -> Args {
    Args {
        user: "admin".to_string(),
        role: "admin".to_string(),
        secret: None,
        expiry: 86400,
        permissions: None,
        output: "token".to_string(),
    }
}

/// Parse command line arguments
fn parse_command_line_arguments(args: &[String], parsed_args: &mut Args) {
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--user" | "-u" => i = parse_string_arg(args, i, &mut parsed_args.user),
            "--role" | "-r" => i = parse_string_arg(args, i, &mut parsed_args.role),
            "--secret" | "-s" => i = parse_optional_string_arg(args, i, &mut parsed_args.secret),
            "--expiry" | "-e" => i = parse_expiry_arg(args, i, &mut parsed_args.expiry),
            "--output" | "-o" => i = parse_string_arg(args, i, &mut parsed_args.output),
            "--permissions" | "-p" => {
                i = parse_optional_string_arg(args, i, &mut parsed_args.permissions)
            }
            _ => i += 1,
        }
    }
}

/// Parse string argument
fn parse_string_arg(args: &[String], i: usize, target: &mut String) -> usize {
    if i + 1 < args.len() {
        *target = args[i + 1].clone();
        i + 2
    } else {
        i + 1
    }
}

/// Parse optional string argument
fn parse_optional_string_arg(args: &[String], i: usize, target: &mut Option<String>) -> usize {
    if i + 1 < args.len() {
        *target = Some(args[i + 1].clone());
        i + 2
    } else {
        i + 1
    }
}

/// Parse expiry argument
fn parse_expiry_arg(args: &[String], i: usize, target: &mut u64) -> usize {
    if i + 1 < args.len() {
        *target = args[i + 1].parse().unwrap_or(86400);
        i + 2
    } else {
        i + 1
    }
}
