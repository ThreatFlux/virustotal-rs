use serde_json;

/// Create sample nodes for the test graph
pub fn create_sample_nodes() -> Vec<serde_json::Value> {
    vec![
        serde_json::json!({
            "id": "file_1",
            "type": "file",
            "label": "malware.exe",
            "attributes": {
                "sha256": "abc123def456",
                "size": 1024000
            }
        }),
        serde_json::json!({
            "id": "domain_1",
            "type": "domain",
            "label": "malicious.com",
            "attributes": {
                "reputation": -50
            }
        }),
        serde_json::json!({
            "id": "ip_1",
            "type": "ip_address",
            "label": "192.168.1.1",
            "attributes": {
                "country": "US"
            }
        }),
    ]
}

/// Create sample edges for the test graph
pub fn create_sample_edges() -> Vec<serde_json::Value> {
    vec![
        serde_json::json!({
            "from": "file_1",
            "to": "domain_1",
            "label": "communicates_with",
            "type": "network"
        }),
        serde_json::json!({
            "from": "domain_1",
            "to": "ip_1",
            "label": "resolves_to",
            "type": "dns"
        }),
    ]
}

/// Create sample graph data
pub fn create_sample_graph_data() -> serde_json::Value {
    serde_json::json!({
        "nodes": create_sample_nodes(),
        "edges": create_sample_edges()
    })
}
