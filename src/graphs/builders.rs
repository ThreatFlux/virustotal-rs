use super::types::*;

/// Helper methods for creating graphs
impl CreateGraphRequest {
    /// Create a new graph request
    pub fn new(name: String) -> Self {
        Self {
            data: CreateGraphData {
                object_type: "graph".to_string(),
                attributes: CreateGraphAttributes {
                    name,
                    description: None,
                    graph_type: None,
                    visibility: None,
                    tags: None,
                    graph_data: None,
                },
            },
        }
    }

    /// Set description
    pub fn with_description(mut self, description: String) -> Self {
        self.data.attributes.description = Some(description);
        self
    }

    /// Set graph type
    pub fn with_graph_type(mut self, graph_type: String) -> Self {
        self.data.attributes.graph_type = Some(graph_type);
        self
    }

    /// Set visibility
    pub fn with_visibility(mut self, visibility: GraphVisibility) -> Self {
        self.data.attributes.visibility = Some(visibility.to_string().to_owned());
        self
    }

    /// Set tags
    pub fn with_tags(mut self, tags: Vec<String>) -> Self {
        self.data.attributes.tags = Some(tags);
        self
    }

    /// Set graph data
    pub fn with_graph_data(mut self, data: serde_json::Value) -> Self {
        self.data.attributes.graph_data = Some(data);
        self
    }
}

/// Helper methods for updating graphs
impl UpdateGraphRequest {
    /// Create a new update request
    pub fn new(graph_id: String) -> Self {
        Self {
            data: UpdateGraphData {
                object_type: "graph".to_string(),
                id: graph_id,
                attributes: UpdateGraphAttributes::default(),
            },
        }
    }

    /// Update name
    pub fn with_name(mut self, name: String) -> Self {
        self.data.attributes.name = Some(name);
        self
    }

    /// Update description
    pub fn with_description(mut self, description: String) -> Self {
        self.data.attributes.description = Some(description);
        self
    }

    /// Update graph type
    pub fn with_graph_type(mut self, graph_type: String) -> Self {
        self.data.attributes.graph_type = Some(graph_type);
        self
    }

    /// Update visibility
    pub fn with_visibility(mut self, visibility: GraphVisibility) -> Self {
        self.data.attributes.visibility = Some(visibility.to_string().to_owned());
        self
    }

    /// Update tags
    pub fn with_tags(mut self, tags: Vec<String>) -> Self {
        self.data.attributes.tags = Some(tags);
        self
    }

    /// Update graph data
    pub fn with_graph_data(mut self, data: serde_json::Value) -> Self {
        self.data.attributes.graph_data = Some(data);
        self
    }
}

/// Helper methods for permission management
impl PermissionDescriptor {
    /// Create a new user permission descriptor
    pub fn user(user_id: String) -> Self {
        Self {
            object_type: "user".to_string(),
            id: user_id,
        }
    }

    /// Create a new group permission descriptor
    pub fn group(group_id: String) -> Self {
        Self {
            object_type: "group".to_string(),
            id: group_id,
        }
    }
}
