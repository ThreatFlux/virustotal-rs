use crate::{Client, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// VirusTotal metadata response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetadataResponse {
    pub data: Metadata,
}

/// VirusTotal metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Metadata {
    /// Dictionary of all antivirus engines
    #[serde(skip_serializing_if = "Option::is_none")]
    pub engines: Option<HashMap<String, EngineInfo>>,

    /// List of available privileges
    #[serde(skip_serializing_if = "Option::is_none")]
    pub privileges: Option<Vec<String>>,

    /// Relationships between different object types
    #[serde(skip_serializing_if = "Option::is_none")]
    pub relationships: Option<HashMap<String, Vec<RelationshipInfo>>>,

    /// File types and their descriptions
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file_types: Option<HashMap<String, String>>,

    /// Supported platforms
    #[serde(skip_serializing_if = "Option::is_none")]
    pub platforms: Option<Vec<String>>,

    /// Available scan engines categories
    #[serde(skip_serializing_if = "Option::is_none")]
    pub engine_categories: Option<Vec<String>>,

    /// Additional metadata fields
    #[serde(flatten)]
    pub additional_fields: HashMap<String, serde_json::Value>,
}

/// Information about an antivirus engine
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct EngineInfo {
    /// Engine display name
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,

    /// Engine category
    #[serde(skip_serializing_if = "Option::is_none")]
    pub category: Option<String>,

    /// Whether the engine is enabled
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,

    /// Engine version
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,

    /// Last update timestamp
    #[serde(skip_serializing_if = "Option::is_none")]
    pub update: Option<i64>,

    /// Additional engine properties
    #[serde(flatten)]
    pub additional_properties: HashMap<String, serde_json::Value>,
}

/// Information about a relationship
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelationshipInfo {
    /// Name of the relationship
    pub name: String,

    /// Description of what the relationship represents
    pub description: String,
}

impl Client {
    /// Get VirusTotal metadata
    ///
    /// This endpoint returns a dictionary with metadata related to VirusTotal,
    /// which includes:
    /// - A full list of engines in use
    /// - A list of existing privileges
    /// - Relationships between different object types
    /// - File types and their descriptions
    /// - And more...
    pub async fn get_metadata(&self) -> Result<MetadataResponse> {
        self.get("metadata").await
    }
}

/// Helper methods for working with metadata
impl Metadata {
    /// Get a specific engine's information
    pub fn get_engine(&self, engine_name: &str) -> Option<&EngineInfo> {
        self.engines.as_ref()?.get(engine_name)
    }

    /// Check if a privilege is available
    pub fn has_privilege(&self, privilege: &str) -> bool {
        self.privileges
            .as_ref()
            .map(|privs| privs.iter().any(|p| p == privilege))
            .unwrap_or(false)
    }

    /// Get relationships for a specific object type
    pub fn get_relationships(&self, object_type: &str) -> Option<&Vec<RelationshipInfo>> {
        self.relationships.as_ref()?.get(object_type)
    }

    /// Get all engine names
    pub fn get_engine_names(&self) -> Vec<String> {
        self.engines
            .as_ref()
            .map(|engines| engines.keys().cloned().collect())
            .unwrap_or_default()
    }

    /// Count total number of engines
    pub fn engine_count(&self) -> usize {
        self.engines.as_ref().map(|e| e.len()).unwrap_or(0)
    }

    /// Get engines by category
    pub fn get_engines_by_category(&self, category: &str) -> Vec<String> {
        let mut result = Vec::new();
        if let Some(engines) = &self.engines {
            for (name, info) in engines {
                if let Some(eng_category) = &info.category {
                    if eng_category == category {
                        result.push(name.clone());
                    }
                }
            }
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_engine_info() {
        let engine = EngineInfo {
            name: Some("TestEngine".to_string()),
            category: Some("antivirus".to_string()),
            enabled: Some(true),
            version: Some("1.2.3".to_string()),
            update: Some(1234567890),
            ..Default::default()
        };

        assert_eq!(engine.name.unwrap(), "TestEngine");
        assert_eq!(engine.category.unwrap(), "antivirus");
        assert!(engine.enabled.unwrap());
        assert_eq!(engine.version.unwrap(), "1.2.3");
    }

    #[test]
    fn test_relationship_info() {
        let rel = RelationshipInfo {
            name: "files".to_string(),
            description: "Files associated with this object".to_string(),
        };

        assert_eq!(rel.name, "files");
        assert_eq!(rel.description, "Files associated with this object");
    }

    #[test]
    fn test_metadata_helpers() {
        let mut engines = HashMap::new();
        engines.insert(
            "Engine1".to_string(),
            EngineInfo {
                name: Some("Engine One".to_string()),
                category: Some("antivirus".to_string()),
                enabled: Some(true),
                ..Default::default()
            },
        );
        engines.insert(
            "Engine2".to_string(),
            EngineInfo {
                name: Some("Engine Two".to_string()),
                category: Some("sandbox".to_string()),
                enabled: Some(true),
                ..Default::default()
            },
        );

        let metadata = Metadata {
            engines: Some(engines),
            privileges: Some(vec!["premium".to_string(), "intelligence".to_string()]),
            relationships: None,
            file_types: None,
            platforms: None,
            engine_categories: None,
            additional_fields: HashMap::new(),
        };

        // Test get_engine
        assert!(metadata.get_engine("Engine1").is_some());
        assert!(metadata.get_engine("NonExistent").is_none());

        // Test has_privilege
        assert!(metadata.has_privilege("premium"));
        assert!(metadata.has_privilege("intelligence"));
        assert!(!metadata.has_privilege("nonexistent"));

        // Test get_engine_names
        let names = metadata.get_engine_names();
        assert_eq!(names.len(), 2);
        assert!(names.contains(&"Engine1".to_string()));
        assert!(names.contains(&"Engine2".to_string()));

        // Test engine_count
        assert_eq!(metadata.engine_count(), 2);

        // Test get_engines_by_category
        let av_engines = metadata.get_engines_by_category("antivirus");
        assert_eq!(av_engines.len(), 1);
        assert_eq!(av_engines[0], "Engine1");

        let sandbox_engines = metadata.get_engines_by_category("sandbox");
        assert_eq!(sandbox_engines.len(), 1);
        assert_eq!(sandbox_engines[0], "Engine2");
    }

    #[test]
    fn test_metadata_with_relationships() {
        let mut relationships = HashMap::new();
        relationships.insert(
            "file".to_string(),
            vec![
                RelationshipInfo {
                    name: "analyses".to_string(),
                    description: "Analyses for the file".to_string(),
                },
                RelationshipInfo {
                    name: "comments".to_string(),
                    description: "Comments on the file".to_string(),
                },
            ],
        );

        let metadata = Metadata {
            engines: None,
            privileges: None,
            relationships: Some(relationships),
            file_types: None,
            platforms: None,
            engine_categories: None,
            additional_fields: HashMap::new(),
        };

        let file_rels = metadata.get_relationships("file");
        assert!(file_rels.is_some());
        assert_eq!(file_rels.unwrap().len(), 2);
        assert_eq!(file_rels.unwrap()[0].name, "analyses");
        assert_eq!(file_rels.unwrap()[1].name, "comments");
    }

    #[test]
    fn test_common_engines() {
        // Test that common engine names are properly handled
        let common_engines = vec![
            "ALYac",
            "APEX",
            "AVG",
            "Avast",
            "Avira",
            "BitDefender",
            "ClamAV",
            "Comodo",
            "DrWeb",
            "ESET-NOD32",
            "F-Secure",
            "Fortinet",
            "GData",
            "Ikarus",
            "K7AntiVirus",
            "Kaspersky",
            "MAX",
            "McAfee",
            "Microsoft",
            "Panda",
            "Sophos",
            "Symantec",
            "Tencent",
            "TrendMicro",
            "ZoneAlarm",
        ];

        for engine_name in common_engines {
            let mut engines = HashMap::new();
            engines.insert(engine_name.to_string(), EngineInfo::default());

            let metadata = Metadata {
                engines: Some(engines),
                privileges: None,
                relationships: None,
                file_types: None,
                platforms: None,
                engine_categories: None,
                additional_fields: HashMap::new(),
            };

            assert!(metadata.get_engine(engine_name).is_some());
        }
    }

    #[test]
    fn test_common_privileges() {
        let privileges = vec![
            "cases",
            "click_to_accept",
            "creditcards",
            "dogfooder",
            "file-behaviour-feed",
            "downloads-tier-1",
            "downloads-tier-2",
            "intelligence",
            "premium",
            "enterprise",
        ];

        let metadata = Metadata {
            engines: None,
            privileges: Some(privileges.iter().map(|s| s.to_string()).collect()),
            relationships: None,
            file_types: None,
            platforms: None,
            engine_categories: None,
            additional_fields: HashMap::new(),
        };

        for privilege in privileges {
            assert!(metadata.has_privilege(privilege));
        }
    }
}
