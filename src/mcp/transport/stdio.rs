use crate::mcp::server::VtMcpServer;
use crate::mcp::McpResult;
use crate::Client;
use serde_json::{json, Value as JsonValue};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader as TokioBufReader};

use super::common::handle_request;

/// Simple STDIO MCP server
pub async fn run_stdio_server(client: Client) -> McpResult<()> {
    tracing::info!("Starting `VirusTotal` MCP server with STDIO transport");

    let server = VtMcpServer::new(client);
    let stdin = tokio::io::stdin();
    let mut stdout = tokio::io::stdout();
    let mut reader = TokioBufReader::new(stdin);
    let mut line = String::new();

    // Send initial server info
    let init_response = json!({
        "jsonrpc": "2.0",
        "result": {
            "capabilities": server.get_server_capabilities(),
            "serverInfo": server.get_server_info()
        }
    });
    stdout
        .write_all(format!("{}\n", init_response).as_bytes())
        .await?;
    stdout.flush().await?;

    loop {
        line.clear();
        match reader.read_line(&mut line).await {
            Ok(0) => break, // EOF
            Ok(_) => {
                if let Ok(request) = serde_json::from_str::<JsonValue>(line.trim()) {
                    let response = handle_request(&server, request).await;
                    stdout
                        .write_all(format!("{}\n", response).as_bytes())
                        .await?;
                    stdout.flush().await?;
                }
            }
            Err(e) => {
                tracing::error!("Error reading from stdin: {}", e);
                break;
            }
        }
    }

    Ok(())
}
