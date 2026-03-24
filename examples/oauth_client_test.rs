//! OAuth 2.1 Client Test Example
//!
//! This example demonstrates how to interact with the OAuth-enabled MCP server
//! as a client, showing the complete OAuth flow and subsequent MCP API usage.
//!
//! # Usage
//!
//! ```bash
//! # First start the OAuth server
//! cargo run --example mcp_http_server_oauth --features mcp-oauth
//!
//! # Then run this client test (in another terminal)
//! cargo run --example oauth_client_test --features mcp-oauth
//! ```

use reqwest::Client as HttpClient;
use serde_json::{Value, json};
use std::io::{self, Write};

/// Fetches and displays server metadata
async fn fetch_server_metadata(
    client: &HttpClient,
    server_base: &str,
) -> Result<bool, Box<dyn std::error::Error>> {
    println!("📋 Step 1: Fetching OAuth server metadata...");
    let response = client
        .get(format!("{}/oauth/metadata", server_base))
        .send()
        .await?;

    if response.status().is_success() {
        let metadata: Value = response.json().await?;
        println!("✅ Server metadata:");
        println!("{}", serde_json::to_string_pretty(&metadata)?);
        Ok(true)
    } else {
        println!("❌ Failed to fetch metadata: {}", response.status());
        Ok(false)
    }
}

/// Performs health check on the server
async fn check_server_health(
    client: &HttpClient,
    server_base: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    println!("🏥 Step 2: Checking server health...");
    let response = client.get(format!("{}/health", server_base)).send().await?;

    if response.status().is_success() {
        let health_text = response.text().await?;
        println!("✅ Health check: {}", health_text);
    } else {
        println!("❌ Health check failed: {}", response.status());
    }
    Ok(())
}

/// Displays OAuth flow instructions to the user
fn display_oauth_instructions(server_base: &str) {
    println!("🔐 Step 3: OAuth Authorization Flow");
    println!("To complete the OAuth flow, you need to:");
    println!();
    println!("1. Open this URL in your browser:");
    println!("   {}/oauth/authorize", server_base);
    println!();
    println!("2. Complete the authorization on the auth server");
    println!("3. You'll be redirected back with an access token");
    println!();
}

/// Prompts user for access token input
fn get_access_token() -> Result<String, Box<dyn std::error::Error>> {
    print!("🔑 Enter access token (or press Enter to skip MCP testing): ");
    io::stdout().flush()?;

    let mut token_input = String::new();
    io::stdin().read_line(&mut token_input)?;
    Ok(token_input.trim().to_string())
}

/// Makes an MCP request and handles the response
async fn make_mcp_request(
    client: &HttpClient,
    server_base: &str,
    access_token: &str,
    request_body: Value,
    request_name: &str,
    success_message: &str,
    error_message: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    println!("🔍 Testing {}...", request_name);

    let response = client
        .post(format!("{}/", server_base))
        .header("Authorization", format!("Bearer {}", access_token))
        .header("Content-Type", "application/json")
        .json(&request_body)
        .send()
        .await?;

    if response.status().is_success() {
        let response_json: Value = response.json().await?;
        println!("✅ {}", success_message);
        println!("{}", serde_json::to_string_pretty(&response_json)?);
    } else {
        println!("❌ {}: {}", error_message, response.status());
        let error_text = response.text().await?;
        println!("Error: {}", error_text);
    }
    println!();
    Ok(())
}

/// Tests MCP API functionality with the provided access token
async fn test_mcp_api(
    client: &HttpClient,
    server_base: &str,
    access_token: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    println!("🧬 Step 4: Testing MCP API with access token...");

    // Test MCP tools/list
    let tools_request = json!({
        "jsonrpc": "2.0",
        "method": "tools/list",
        "id": 1
    });

    make_mcp_request(
        client,
        server_base,
        access_token,
        tools_request,
        "tools/list",
        "MCP tools/list response:",
        "MCP request failed",
    )
    .await?;

    // Test MCP vti_search tool
    let search_request = json!({
        "jsonrpc": "2.0",
        "method": "tools/call",
        "params": {
            "name": "vti_search",
            "arguments": {
                "indicator": "malware.example.com"
            }
        },
        "id": 2
    });

    make_mcp_request(
        client,
        server_base,
        access_token,
        search_request,
        "vti_search tool",
        "MCP vti_search response:",
        "MCP search request failed",
    )
    .await?;

    Ok(())
}

/// Displays final completion messages and notes
fn display_completion_notes() {
    println!("🎉 OAuth client test completed!");
    println!();
    println!("💡 Notes:");
    println!("- This example shows manual OAuth flow testing");
    println!("- In production, use an OAuth 2.1 client library");
    println!("- Store tokens securely and handle refresh automatically");
    println!("- Always use HTTPS in production environments");
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = HttpClient::new();
    let server_base = "http://127.0.0.1:3000";

    println!("🧪 OAuth 2.1 Client Test for VirusTotal MCP Server");
    println!("🌐 Server: {}", server_base);
    println!();

    // Step 1: Check server metadata
    let metadata_ok = fetch_server_metadata(&client, server_base).await?;
    println!();

    if !metadata_ok {
        return Ok(());
    }

    // Step 2: Check health endpoint
    check_server_health(&client, server_base).await?;
    println!();

    // Step 3: Display OAuth flow instructions
    display_oauth_instructions(server_base);

    // Step 4: Get access token from user
    let access_token = get_access_token()?;

    if access_token.is_empty() {
        println!("⏭️  Skipping MCP API testing");
        return Ok(());
    }

    println!();

    // Step 5: Test MCP API
    test_mcp_api(&client, server_base, &access_token).await?;

    // Display completion notes
    display_completion_notes();

    Ok(())
}
