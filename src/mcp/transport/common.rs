use crate::mcp::server::VtMcpServer;
use serde_json::{json, Value as JsonValue};

/// Handle an MCP request
pub async fn handle_request(server: &VtMcpServer, request: JsonValue) -> JsonValue {
    let id = request.get("id").cloned().unwrap_or(json!(null));
    match request.get("method").and_then(|v| v.as_str()) {
        Some("tools/list") => tools_list(server, id).await,
        Some("tools/call") => tools_call(server, id, request.get("params")).await,
        Some("initialize") => initialize(server, id),
        Some(method) => method_not_found(id, method),
        None => invalid_request(id),
    }
}

async fn tools_list(server: &VtMcpServer, id: JsonValue) -> JsonValue {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "result": {"tools": server.list_tools()}
    })
}

async fn tools_call(server: &VtMcpServer, id: JsonValue, params: Option<&JsonValue>) -> JsonValue {
    match params.and_then(|p| {
        p.get("name")
            .and_then(|v| v.as_str())
            .zip(p.get("arguments"))
    }) {
        Some((name, args)) => match server.handle_tool_call(name, args).await {
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
        },
        None => json!({
            "jsonrpc": "2.0",
            "id": id,
            "error": {"code": -32602, "message": "Invalid params"},
        }),
    }
}

fn initialize(server: &VtMcpServer, id: JsonValue) -> JsonValue {
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

fn method_not_found(id: JsonValue, method: &str) -> JsonValue {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": {
            "code": -32601,
            "message": format!("Method not found: {}", method),
        }
    })
}

fn invalid_request(id: JsonValue) -> JsonValue {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": {"code": -32600, "message": "Invalid request"},
    })
}
