use crate::mcp::server::VtMcpServer;
use serde_json::{json, Value as JsonValue};

/// Handle an MCP request
pub async fn handle_request(server: &VtMcpServer, request: JsonValue) -> JsonValue {
    let id = request.get("id").cloned().unwrap_or(json!(null));

    if let Some(method) = request.get("method").and_then(|v| v.as_str()) {
        match method {
            "tools/list" => {
                json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "result": {"tools": server.list_tools()}
                })
            }
            "tools/call" => {
                if let Some(params) = request.get("params") {
                    if let (Some(name), Some(arguments)) = (
                        params.get("name").and_then(|v| v.as_str()),
                        params.get("arguments"),
                    ) {
                        match server.handle_tool_call(name, arguments).await {
                            Ok(result) => json!({
                                "jsonrpc": "2.0",
                                "id": id,
                                "result": {
                                    "content": [{
                                        "type": "text",
                                        "text": serde_json::to_string_pretty(&result)
                                            .unwrap_or_else(|_| result.to_string())
                                    }]}
                            }),
                            Err(error) => json!({
                                "jsonrpc": "2.0",
                                "id": id,
                                "error": {"code": -1, "message": error.to_string()}
                            }),
                        }
                    } else {
                        json!({
                            "jsonrpc": "2.0",
                            "id": id,
                            "error": {"code": -32602, "message": "Invalid params"}
                        })
                    }
                } else {
                    json!({
                        "jsonrpc": "2.0",
                        "id": id,
                        "error": {"code": -32602, "message": "Missing params"}
                    })
                }
            }
            "initialize" => {
                json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "result": {
                        "protocolVersion": "2024-11-05",
                        "capabilities": server.get_server_capabilities(),
                        "serverInfo": server.get_server_info()
                    }
                })
            }
            _ => json!({
                "jsonrpc": "2.0",
                "id": id,
                "error": {
                    "code": -32601,
                    "message": format!("Method not found: {}", method)
                }
            }),
        }
    } else {
        json!({
            "jsonrpc": "2.0",
            "id": id,
            "error": {"code": -32600, "message": "Invalid request"}
        })
    }
}
