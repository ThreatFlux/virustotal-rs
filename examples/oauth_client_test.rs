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
use serde_json::{json, Value};
use std::io::{self, Write};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = HttpClient::new();
    let server_base = "http://127.0.0.1:3000";

    println!("🧪 OAuth 2.1 Client Test for VirusTotal MCP Server");
    println!("🌐 Server: {}", server_base);
    println!();

    // Step 1: Check server metadata
    println!("📋 Step 1: Fetching OAuth server metadata...");
    let metadata_response = client
        .get(format!("{}/oauth/metadata", server_base))
        .send()
        .await?;

    if metadata_response.status().is_success() {
        let metadata: Value = metadata_response.json().await?;
        println!("✅ Server metadata:");
        println!("{}", serde_json::to_string_pretty(&metadata)?);
    } else {
        println!(
            "❌ Failed to fetch metadata: {}",
            metadata_response.status()
        );
        return Ok(());
    }
    println!();

    // Step 2: Check health endpoint
    println!("🏥 Step 2: Checking server health...");
    let health_response = client.get(format!("{}/health", server_base)).send().await?;

    if health_response.status().is_success() {
        let health_text = health_response.text().await?;
        println!("✅ Health check: {}", health_text);
    } else {
        println!("❌ Health check failed: {}", health_response.status());
    }
    println!();

    // Step 3: Manual OAuth flow instruction
    println!("🔐 Step 3: OAuth Authorization Flow");
    println!("To complete the OAuth flow, you need to:");
    println!();
    println!("1. Open this URL in your browser:");
    println!("   {}/oauth/authorize", server_base);
    println!();
    println!("2. Complete the authorization on the auth server");
    println!("3. You'll be redirected back with an access token");
    println!();

    // Step 4: Manual token input for testing
    print!("🔑 Enter access token (or press Enter to skip MCP testing): ");
    io::stdout().flush()?;

    let mut token_input = String::new();
    io::stdin().read_line(&mut token_input)?;
    let access_token = token_input.trim();

    if access_token.is_empty() {
        println!("⏭️  Skipping MCP API testing");
        return Ok(());
    }

    println!();
    println!("🧬 Step 4: Testing MCP API with access token...");

    // Test MCP tools/list
    println!("📚 Testing tools/list...");
    let mcp_request = json!({
        "jsonrpc": "2.0",
        "method": "tools/list",
        "id": 1
    });

    let mcp_response = client
        .post(format!("{}/", server_base))
        .header("Authorization", format!("Bearer {}", access_token))
        .header("Content-Type", "application/json")
        .json(&mcp_request)
        .send()
        .await?;

    if mcp_response.status().is_success() {
        let response_json: Value = mcp_response.json().await?;
        println!("✅ MCP tools/list response:");
        println!("{}", serde_json::to_string_pretty(&response_json)?);
    } else {
        println!("❌ MCP request failed: {}", mcp_response.status());
        let error_text = mcp_response.text().await?;
        println!("Error: {}", error_text);
    }
    println!();

    // Test MCP vti_search tool
    println!("🔍 Testing vti_search tool...");
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

    let search_response = client
        .post(format!("{}/", server_base))
        .header("Authorization", format!("Bearer {}", access_token))
        .header("Content-Type", "application/json")
        .json(&search_request)
        .send()
        .await?;

    if search_response.status().is_success() {
        let response_json: Value = search_response.json().await?;
        println!("✅ MCP vti_search response:");
        println!("{}", serde_json::to_string_pretty(&response_json)?);
    } else {
        println!("❌ MCP search request failed: {}", search_response.status());
        let error_text = search_response.text().await?;
        println!("Error: {}", error_text);
    }
    println!();

    println!("🎉 OAuth client test completed!");
    println!();
    println!("💡 Notes:");
    println!("- This example shows manual OAuth flow testing");
    println!("- In production, use an OAuth 2.1 client library");
    println!("- Store tokens securely and handle refresh automatically");
    println!("- Always use HTTPS in production environments");

    Ok(())
}
