use crate::objects::{Collection, CollectionIterator, Object, ObjectOperations, ObjectResponse};
use crate::{Client, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Represents a MITRE ATT&CK Technique object
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackTechnique {
    #[serde(flatten)]
    pub object: Object<AttackTechniqueAttributes>,
}

/// Attributes for an Attack Technique object
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AttackTechniqueAttributes {
    /// The technique's name
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,

    /// The technique's description
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

    /// External ID (e.g., T1055)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub external_id: Option<String>,

    /// Technique URL in MITRE ATT&CK framework
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,

    /// Associated platforms
    #[serde(skip_serializing_if = "Option::is_none")]
    pub platforms: Option<Vec<String>>,

    /// Data sources for detection
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data_sources: Option<Vec<String>>,

    /// Defense bypassed
    #[serde(skip_serializing_if = "Option::is_none")]
    pub defense_bypassed: Option<Vec<String>>,

    /// Permissions required
    #[serde(skip_serializing_if = "Option::is_none")]
    pub permissions_required: Option<Vec<String>>,

    /// Effective permissions
    #[serde(skip_serializing_if = "Option::is_none")]
    pub effective_permissions: Option<Vec<String>>,

    /// System requirements
    #[serde(skip_serializing_if = "Option::is_none")]
    pub system_requirements: Option<Vec<String>>,

    /// Tactics this technique belongs to
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tactics: Option<Vec<String>>,

    /// Sub-techniques count
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subtechniques_count: Option<u32>,

    /// Parent technique ID (for sub-techniques)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_technique: Option<String>,

    /// Whether this is a sub-technique
    #[serde(skip_serializing_if = "Option::is_none")]
    pub is_subtechnique: Option<bool>,

    /// Additional attributes
    #[serde(flatten)]
    pub additional_attributes: HashMap<String, serde_json::Value>,
}

impl ObjectOperations for AttackTechnique {
    type Attributes = AttackTechniqueAttributes;

    fn collection_name() -> &'static str {
        "attack_techniques"
    }
}

/// Client for interacting with Attack Techniques API endpoints
pub struct AttackTechniqueClient<'a> {
    pub(crate) client: &'a Client,
}

impl<'a> AttackTechniqueClient<'a> {
    pub fn new(client: &'a Client) -> Self {
        Self { client }
    }

    /// Get an attack technique by ID
    pub async fn get(&self, technique_id: &str) -> Result<AttackTechnique> {
        let url = AttackTechnique::object_url(technique_id);
        let response: ObjectResponse<AttackTechniqueAttributes> = self.client.get(&url).await?;
        Ok(AttackTechnique {
            object: response.data,
        })
    }

    /// Get objects related to an attack technique
    pub async fn get_relationship<T>(
        &self,
        technique_id: &str,
        relationship: &str,
    ) -> Result<Collection<T>>
    where
        T: for<'de> Deserialize<'de>,
    {
        let url = AttackTechnique::relationship_objects_url(technique_id, relationship);
        self.client.get(&url).await
    }

    /// Get object descriptors related to an attack technique
    pub async fn get_relationship_descriptors(
        &self,
        technique_id: &str,
        relationship: &str,
    ) -> Result<Collection<serde_json::Value>> {
        let url = AttackTechnique::relationships_url(technique_id, relationship);
        self.client.get(&url).await
    }

    /// Get relationship iterator for paginated results
    pub fn get_relationship_iterator<T>(
        &self,
        technique_id: &str,
        relationship: &str,
    ) -> CollectionIterator<'_, T>
    where
        T: for<'de> Deserialize<'de> + Clone,
    {
        let url = AttackTechnique::relationship_objects_url(technique_id, relationship);
        CollectionIterator::new(self.client, url)
    }

    // Convenience methods for common relationships

    /// Get attack tactics associated with this technique
    pub async fn get_tactics(&self, technique_id: &str) -> Result<Collection<serde_json::Value>> {
        self.get_relationship(technique_id, "attack_tactics").await
    }

    /// Get sub-techniques of this technique
    pub async fn get_subtechniques(
        &self,
        technique_id: &str,
    ) -> Result<Collection<serde_json::Value>> {
        self.get_relationship(technique_id, "subtechniques").await
    }

    /// Get parent technique (for sub-techniques)
    pub async fn get_parent_technique(
        &self,
        technique_id: &str,
    ) -> Result<Collection<serde_json::Value>> {
        self.get_relationship(technique_id, "parent_technique")
            .await
    }

    /// Get files associated with this technique
    pub async fn get_files(&self, technique_id: &str) -> Result<Collection<serde_json::Value>> {
        self.get_relationship(technique_id, "files").await
    }

    /// Get threat actors associated with this technique
    pub async fn get_threat_actors(
        &self,
        technique_id: &str,
    ) -> Result<Collection<serde_json::Value>> {
        self.get_relationship(technique_id, "threat_actors").await
    }

    /// Get campaigns associated with this technique
    pub async fn get_campaigns(&self, technique_id: &str) -> Result<Collection<serde_json::Value>> {
        self.get_relationship(technique_id, "campaigns").await
    }

    /// Get mitigations for this technique
    pub async fn get_mitigations(
        &self,
        technique_id: &str,
    ) -> Result<Collection<serde_json::Value>> {
        self.get_relationship(technique_id, "mitigations").await
    }

    /// Get detections for this technique
    pub async fn get_detections(
        &self,
        technique_id: &str,
    ) -> Result<Collection<serde_json::Value>> {
        self.get_relationship(technique_id, "detections").await
    }
}

impl Client {
    /// Get the Attack Techniques client
    pub fn attack_techniques(&self) -> AttackTechniqueClient<'_> {
        AttackTechniqueClient::new(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_attack_technique_collection_name() {
        assert_eq!(AttackTechnique::collection_name(), "attack_techniques");
    }

    #[test]
    fn test_attack_technique_url() {
        let technique_id = "T1055";
        assert_eq!(
            AttackTechnique::object_url(technique_id),
            "attack_techniques/T1055"
        );
    }

    #[test]
    fn test_attack_technique_relationships_url() {
        let technique_id = "T1055";
        assert_eq!(
            AttackTechnique::relationships_url(technique_id, "tactics"),
            "attack_techniques/T1055/relationships/tactics"
        );
    }

    #[test]
    fn test_attack_technique_relationship_objects_url() {
        let technique_id = "T1055";
        assert_eq!(
            AttackTechnique::relationship_objects_url(technique_id, "files"),
            "attack_techniques/T1055/files"
        );
    }

    #[test]
    fn test_attack_technique_attributes() {
        let attrs = AttackTechniqueAttributes {
            name: Some("Process Injection".to_string()),
            description: Some("Adversaries may inject code into processes".to_string()),
            external_id: Some("T1055".to_string()),
            url: Some("https://attack.mitre.org/techniques/T1055/".to_string()),
            platforms: Some(vec![
                "Windows".to_string(),
                "Linux".to_string(),
                "macOS".to_string(),
            ]),
            tactics: Some(vec![
                "Defense Evasion".to_string(),
                "Privilege Escalation".to_string(),
            ]),
            is_subtechnique: Some(false),
            subtechniques_count: Some(12),
            ..Default::default()
        };

        assert_eq!(attrs.name.unwrap(), "Process Injection");
        assert_eq!(attrs.external_id.unwrap(), "T1055");
        assert!(!attrs.is_subtechnique.unwrap());
        assert_eq!(attrs.subtechniques_count.unwrap(), 12);
    }

    #[test]
    fn test_subtechnique_attributes() {
        let attrs = AttackTechniqueAttributes {
            name: Some("Dynamic-link Library Injection".to_string()),
            external_id: Some("T1055.001".to_string()),
            parent_technique: Some("T1055".to_string()),
            is_subtechnique: Some(true),
            ..Default::default()
        };

        assert_eq!(attrs.external_id.unwrap(), "T1055.001");
        assert_eq!(attrs.parent_technique.unwrap(), "T1055");
        assert!(attrs.is_subtechnique.unwrap());
    }
}
