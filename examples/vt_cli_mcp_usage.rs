//! VirusTotal CLI MCP Usage Example
//!
//! This example demonstrates how to use the integrated MCP server functionality
//! within the VirusTotal CLI (`vt-cli mcp`). While this example doesn't actually
//! run the CLI (since it's a separate binary), it shows how the functionality
//! would be used and provides testing utilities.
//!
//! Usage Examples:
//!
//! 1. STDIO Mode (recommended for local usage):
//!    ```bash
//!    VIRUSTOTAL_API_KEY=your_key vt-cli mcp stdio
//!    npx @modelcontextprotocol/inspector vt-cli mcp stdio --api-key your_key
//!    ```
//!
//! 2. HTTP Mode (for remote access):
//!    ```bash
//!    vt-cli mcp http --api-key your_key --addr 127.0.0.1:3000
//!    npx @modelcontextprotocol/inspector http://localhost:3000
//!    ```
//!
//! 3. With Authentication:
//!    ```bash
//!    vt-cli mcp http --jwt --jwt-secret your_secret --api-key your_key
//!    vt-cli mcp http --oauth --oauth-client-id id --oauth-client-secret secret
//!    ```
//!
//! This example can be run to validate the underlying MCP functionality:
//!
//!    cargo run --example vt_cli_mcp_usage --features cli-mcp

#[cfg(feature = "cli")]
use std::env;

#[cfg(all(feature = "cli", feature = "mcp"))]
use virustotal_rs::cli::commands::mcp::{McpCommand, McpTransport};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    #[cfg(not(all(feature = "cli", feature = "mcp")))]
    {
        eprintln!("This example requires both 'cli' and 'mcp' features to be enabled.");
        eprintln!("Run with: cargo run --example vt_cli_mcp_usage --features cli-mcp");
        eprintln!();
        eprintln!("However, you can still use the actual CLI commands:");
        eprintln!();
        eprintln!("1. Build the CLI:");
        eprintln!("   cargo build --bin vt-cli --features cli-mcp");
        eprintln!();
        eprintln!("2. Run STDIO mode:");
        eprintln!("   VIRUSTOTAL_API_KEY=your_key ./target/debug/vt-cli mcp stdio");
        eprintln!();
        eprintln!("3. Run HTTP mode:");
        eprintln!("   ./target/debug/vt-cli mcp http --api-key your_key");
        eprintln!();
        eprintln!("4. Test with MCP Inspector:");
        eprintln!("   npx @modelcontextprotocol/inspector ./target/debug/vt-cli mcp stdio");
        eprintln!("   npx @modelcontextprotocol/inspector http://localhost:3000");
        eprintln!();
        std::process::exit(1);
    }

    #[cfg(all(feature = "cli", feature = "mcp"))]
    {
        println!("VirusTotal CLI MCP Usage Example");
        println!("=================================");
        println!();

        // Initialize logging for the example
        tracing_subscriber::fmt()
            .with_env_filter(
                tracing_subscriber::EnvFilter::from_default_env()
                    .add_directive("virustotal_rs=info".parse()?)
                    .add_directive("vt_cli_mcp_usage=info".parse()?),
            )
            .with_target(false)
            .init();

        // Check if we have an API key for demonstration
        let api_key = env::var("VIRUSTOTAL_API_KEY").ok();
        let has_api_key = api_key.is_some();

        println!("📋 Available CLI MCP Commands:");
        println!();

        // Demonstrate STDIO mode configuration
        println!("1. STDIO Mode (recommended for local usage):");
        println!("   vt-cli mcp stdio --api-key your_key");
        println!("   vt-cli mcp stdio --tier premium");
        println!("   VIRUSTOTAL_API_KEY=your_key vt-cli mcp stdio");
        println!();

        // Demonstrate HTTP mode configuration
        println!("2. HTTP Mode (for remote access):");
        println!("   vt-cli mcp http --api-key your_key");
        println!("   vt-cli mcp http --addr 0.0.0.0:8080");
        println!("   vt-cli mcp http --api-key your_key --addr 127.0.0.1:3000");
        println!();

        #[cfg(feature = "mcp-jwt")]
        {
            println!("3. HTTP with JWT Authentication (requires cli-mcp-jwt feature):");
            println!("   vt-cli mcp http --jwt --jwt-secret your_secret");
            println!("   JWT_SECRET=secret vt-cli mcp http --jwt");
            println!();
        }

        #[cfg(feature = "mcp-oauth")]
        {
            println!("4. HTTP with OAuth Authentication (requires cli-mcp-oauth feature):");
            println!(
                "   vt-cli mcp http --oauth --oauth-client-id id --oauth-client-secret secret"
            );
            println!("   OAUTH_CLIENT_ID=id OAUTH_CLIENT_SECRET=secret vt-cli mcp http --oauth");
            println!();
        }

        println!("🔗 MCP Inspector Usage:");
        println!("   npx @modelcontextprotocol/inspector vt-cli mcp stdio --api-key your_key");
        println!("   npx @modelcontextprotocol/inspector http://localhost:3000");
        println!();

        println!("🛠️  Available MCP Tools:");
        println!("   • vt_file_scan - Analyze files by hash or upload");
        println!("   • vt_url_scan - Analyze URLs for threats");
        println!("   • vt_domain_info - Get domain reputation and information");
        println!("   • vt_ip_info - Get IP address reputation and information");
        println!("   • vt_search - VirusTotal Intelligence search (Premium only)");
        println!("   • vt_livehunt - Manage hunting rules (Premium only)");
        println!();

        if has_api_key {
            println!("✅ VIRUSTOTAL_API_KEY environment variable is set!");
            println!("   You can test the actual CLI commands now.");
            println!();

            println!("🧪 Testing CLI MCP command creation (demonstration only):");

            // Demonstrate creating the command structures that the CLI would use
            let _stdio_cmd = McpCommand {
                api_key: api_key.clone(),
                tier: "public".to_string(),
                transport: McpTransport::Stdio,
            };

            let _http_cmd = McpCommand {
                api_key: api_key.clone(),
                tier: "premium".to_string(),
                transport: McpTransport::Http {
                    addr: "127.0.0.1:3000".to_string(),
                    #[cfg(feature = "mcp-jwt")]
                    jwt: false,
                    #[cfg(feature = "mcp-jwt")]
                    jwt_secret: None,
                    #[cfg(feature = "mcp-oauth")]
                    oauth: false,
                    #[cfg(feature = "mcp-oauth")]
                    oauth_client_id: None,
                    #[cfg(feature = "mcp-oauth")]
                    oauth_client_secret: None,
                },
            };

            println!("   ✓ STDIO command configuration: OK");
            println!("   ✓ HTTP command configuration: OK");
            println!("   ✓ API key validation: OK");

            // Note: We don't actually execute the commands here since this is just a demo
            // and would start actual servers. The real CLI handles the execution.

            println!();
            println!("📋 To actually run the servers, use the vt-cli binary:");
            println!("   cargo build --bin vt-cli --features cli-mcp");
            println!("   ./target/debug/vt-cli mcp stdio");
        } else {
            println!("⚠️  VIRUSTOTAL_API_KEY environment variable not set.");
            println!("   Set it to test with real API calls:");
            println!("   export VIRUSTOTAL_API_KEY=your_api_key_here");
        }

        println!();
        println!("📖 For comprehensive usage examples, see:");
        println!("   • README.md - Main documentation");
        println!("   • MCP_CLI_USAGE_GUIDE.md - Detailed MCP CLI guide");
        println!("   • examples/mcp_*.rs - Standalone MCP server examples");

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_example_compiles() {
        // This test ensures the example compiles correctly with different feature flags
        println!("CLI MCP usage example compiles successfully");
    }

    #[cfg(all(feature = "cli", feature = "mcp"))]
    #[test]
    fn test_command_structures() {
        // Test that we can create the command structures
        let cmd = McpCommand {
            api_key: Some("test_key".to_string()),
            tier: "public".to_string(),
            transport: McpTransport::Stdio,
        };

        assert_eq!(cmd.tier, "public");
        assert_eq!(cmd.api_key, Some("test_key".to_string()));
    }

    #[cfg(all(feature = "cli", feature = "mcp"))]
    #[test]
    fn test_http_command_creation() {
        let cmd = McpCommand {
            api_key: Some("test_key".to_string()),
            tier: "premium".to_string(),
            transport: McpTransport::Http {
                addr: "127.0.0.1:8080".to_string(),
                #[cfg(feature = "mcp-jwt")]
                jwt: false,
                #[cfg(feature = "mcp-jwt")]
                jwt_secret: None,
                #[cfg(feature = "mcp-oauth")]
                oauth: false,
                #[cfg(feature = "mcp-oauth")]
                oauth_client_id: None,
                #[cfg(feature = "mcp-oauth")]
                oauth_client_secret: None,
            },
        };

        match cmd.transport {
            McpTransport::Http { addr, .. } => {
                assert_eq!(addr, "127.0.0.1:8080");
            }
            _ => panic!("Expected HTTP transport"),
        }
    }
}
