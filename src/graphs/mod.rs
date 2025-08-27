//! Graph module for VirusTotal API
//!
//! This module provides functionality for working with graphs in VirusTotal,
//! including creating, updating, deleting graphs, managing permissions,
//! and handling relationships.

pub mod builders;
pub mod operations;
pub mod types;

// Re-export all public types
pub use types::*;

// Re-export the client
pub use operations::GraphClient;

use crate::Client;

impl Client {
    /// Get the Graph client
    pub fn graphs(&self) -> GraphClient<'_> {
        GraphClient::new(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn test_graph_attributes() {
        let attrs = GraphAttributes {
            name: Some("Test Graph".to_string()),
            description: Some("A test graph".to_string()),
            graph_type: Some("malware_analysis".to_string()),
            visibility: Some("public".to_string()),
            nodes_count: Some(10),
            edges_count: Some(15),
            ..Default::default()
        };

        assert_eq!(attrs.name.unwrap(), "Test Graph");
        assert_eq!(attrs.description.unwrap(), "A test graph");
        assert_eq!(attrs.graph_type.unwrap(), "malware_analysis");
        assert_eq!(attrs.visibility.unwrap(), "public");
        assert_eq!(attrs.nodes_count.unwrap(), 10);
        assert_eq!(attrs.edges_count.unwrap(), 15);
    }

    #[test]
    fn test_create_graph_request() {
        let request = CreateGraphRequest::new("My Graph".to_string())
            .with_description("Graph description".to_string())
            .with_visibility(GraphVisibility::Private)
            .with_tags(vec!["tag1".to_string(), "tag2".to_string()]);

        assert_eq!(request.data.attributes.name, "My Graph");
        assert_eq!(
            request.data.attributes.description.unwrap(),
            "Graph description"
        );
        assert_eq!(request.data.attributes.visibility.unwrap(), "private");
        assert_eq!(request.data.attributes.tags.unwrap().len(), 2);
    }

    #[test]
    fn test_update_graph_request() {
        let request = UpdateGraphRequest::new("graph_123".to_string())
            .with_name("Updated Graph".to_string())
            .with_visibility(GraphVisibility::Public)
            .with_tags(vec!["updated".to_string()]);

        assert_eq!(request.data.id, "graph_123");
        assert_eq!(request.data.attributes.name.unwrap(), "Updated Graph");
        assert_eq!(request.data.attributes.visibility.unwrap(), "public");
        assert_eq!(request.data.attributes.tags.unwrap().len(), 1);
    }

    #[test]
    fn test_graph_visibility_strings() {
        assert_eq!(GraphVisibility::Public.to_string(), "public");
        assert_eq!(GraphVisibility::Private.to_string(), "private");
    }

    #[test]
    fn test_graph_order_strings() {
        assert_eq!(GraphOrder::NameAsc.to_string(), "name+");
        assert_eq!(GraphOrder::NameDesc.to_string(), "name-");
        assert_eq!(GraphOrder::CreationDateAsc.to_string(), "creation_date+");
        assert_eq!(GraphOrder::CreationDateDesc.to_string(), "creation_date-");
        assert_eq!(GraphOrder::NodesCountAsc.to_string(), "nodes_count+");
        assert_eq!(GraphOrder::NodesCountDesc.to_string(), "nodes_count-");
    }

    #[test]
    fn test_add_graph_comment_request() {
        let request = AddGraphCommentRequest {
            data: AddGraphCommentData {
                object_type: "comment".to_string(),
                attributes: AddGraphCommentAttributes {
                    text: "This is a comment".to_string(),
                },
            },
        };

        assert_eq!(request.data.object_type, "comment");
        assert_eq!(request.data.attributes.text, "This is a comment");
    }

    #[test]
    fn test_graph_with_data() {
        let graph_data = serde_json::json!({
            "nodes": [
                {"id": "1", "label": "Node 1"},
                {"id": "2", "label": "Node 2"}
            ],
            "edges": [
                {"from": "1", "to": "2", "label": "connects"}
            ]
        });

        let request =
            CreateGraphRequest::new("Data Graph".to_string()).with_graph_data(graph_data.clone());

        assert!(request.data.attributes.graph_data.is_some());
        let data = request.data.attributes.graph_data.unwrap();
        assert!(data["nodes"].is_array());
        assert_eq!(data["nodes"].as_array().unwrap().len(), 2);
    }

    #[test]
    fn test_graph_owner_attributes() {
        let owner_attrs = GraphOwnerAttributes {
            first_name: Some("Richard".to_string()),
            last_name: Some("Hendricks".to_string()),
            profile_phrase: Some("CEO of Pied Piper".to_string()),
            reputation: Some(1),
            status: Some("active".to_string()),
            user_since: Some(1528111032),
            additional_attributes: HashMap::new(),
        };

        assert_eq!(owner_attrs.first_name.unwrap(), "Richard");
        assert_eq!(owner_attrs.last_name.unwrap(), "Hendricks");
        assert_eq!(owner_attrs.profile_phrase.unwrap(), "CEO of Pied Piper");
        assert_eq!(owner_attrs.reputation.unwrap(), 1);
        assert_eq!(owner_attrs.status.unwrap(), "active");
        assert_eq!(owner_attrs.user_since.unwrap(), 1528111032);
    }

    #[test]
    fn test_graph_relationship_descriptor() {
        let descriptor = GraphRelationshipDescriptor {
            object_type: "user".to_string(),
            id: "user123".to_string(),
            context_attributes: Some(serde_json::json!({
                "role": "editor",
                "added_at": 1234567890
            })),
        };

        assert_eq!(descriptor.object_type, "user");
        assert_eq!(descriptor.id, "user123");
        assert!(descriptor.context_attributes.is_some());

        let context = descriptor.context_attributes.unwrap();
        assert_eq!(context["role"], "editor");
        assert_eq!(context["added_at"], 1234567890);
    }

    #[test]
    fn test_permission_descriptor() {
        let user_perm = PermissionDescriptor::user("hendricks".to_string());
        assert_eq!(user_perm.object_type, "user");
        assert_eq!(user_perm.id, "hendricks");

        let group_perm = PermissionDescriptor::group("piedpiper".to_string());
        assert_eq!(group_perm.object_type, "group");
        assert_eq!(group_perm.id, "piedpiper");
    }

    #[test]
    fn test_grant_permission_request() {
        let permissions = vec![
            PermissionDescriptor::user("gilfoyle".to_string()),
            PermissionDescriptor::user("dinesh".to_string()),
            PermissionDescriptor::group("engineers".to_string()),
        ];

        let request = GrantPermissionRequest { data: permissions };
        assert_eq!(request.data.len(), 3);
        assert_eq!(request.data[0].id, "gilfoyle");
        assert_eq!(request.data[1].id, "dinesh");
        assert_eq!(request.data[2].object_type, "group");
    }

    #[test]
    fn test_permission_check_response() {
        let response = GraphPermissionCheckResponse { data: true };
        assert!(response.data);

        let response_false = GraphPermissionCheckResponse { data: false };
        assert!(!response_false.data);
    }
}
