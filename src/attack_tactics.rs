use crate::objects::{Collection, CollectionIterator, Object, ObjectOperations, ObjectResponse};
use crate::{Client, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Represents a MITRE ATT&CK Tactic object
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackTactic {
    #[serde(flatten)]
    pub object: Object<AttackTacticAttributes>,
}

/// Attributes for an Attack Tactic object
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AttackTacticAttributes {
    /// The tactic's name
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,

    /// The tactic's description
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

    /// External ID (e.g., TA0001)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub external_id: Option<String>,

    /// Tactic URL in MITRE ATT&CK framework
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,

    /// Associated platforms
    #[serde(skip_serializing_if = "Option::is_none")]
    pub platforms: Option<Vec<String>>,

    /// Related techniques count
    #[serde(skip_serializing_if = "Option::is_none")]
    pub techniques_count: Option<u32>,

    /// Additional attributes
    #[serde(flatten)]
    pub additional_attributes: HashMap<String, serde_json::Value>,
}

impl ObjectOperations for AttackTactic {
    type Attributes = AttackTacticAttributes;

    fn collection_name() -> &'static str {
        "attack_tactics"
    }
}

/// Client for interacting with Attack Tactics API endpoints
pub struct AttackTacticClient<'a> {
    pub(crate) client: &'a Client,
}

impl<'a> AttackTacticClient<'a> {
    pub fn new(client: &'a Client) -> Self {
        Self { client }
    }

    /// Get an attack tactic by ID
    pub async fn get(&self, tactic_id: &str) -> Result<AttackTactic> {
        let url = AttackTactic::object_url(tactic_id);
        let response: ObjectResponse<AttackTacticAttributes> = self.client.get(&url).await?;
        Ok(AttackTactic {
            object: response.data,
        })
    }

    /// Get objects related to an attack tactic
    pub async fn get_relationship<T>(
        &self,
        tactic_id: &str,
        relationship: &str,
    ) -> Result<Collection<T>>
    where
        T: for<'de> Deserialize<'de>,
    {
        let url = AttackTactic::relationship_objects_url(tactic_id, relationship);
        self.client.get(&url).await
    }

    /// Get object descriptors related to an attack tactic
    pub async fn get_relationship_descriptors(
        &self,
        tactic_id: &str,
        relationship: &str,
    ) -> Result<Collection<serde_json::Value>> {
        let url = AttackTactic::relationships_url(tactic_id, relationship);
        self.client.get(&url).await
    }

    /// Get relationship iterator for paginated results
    pub fn get_relationship_iterator<T>(
        &self,
        tactic_id: &str,
        relationship: &str,
    ) -> CollectionIterator<'_, T>
    where
        T: for<'de> Deserialize<'de> + Clone,
    {
        let url = AttackTactic::relationship_objects_url(tactic_id, relationship);
        CollectionIterator::new(self.client, url)
    }

    // Convenience methods for common relationships

    /// Get attack techniques associated with this tactic
    pub async fn get_techniques(&self, tactic_id: &str) -> Result<Collection<serde_json::Value>> {
        self.get_relationship(tactic_id, "attack_techniques").await
    }

    /// Get files associated with this tactic
    pub async fn get_files(&self, tactic_id: &str) -> Result<Collection<serde_json::Value>> {
        self.get_relationship(tactic_id, "files").await
    }

    /// Get threat actors associated with this tactic
    pub async fn get_threat_actors(
        &self,
        tactic_id: &str,
    ) -> Result<Collection<serde_json::Value>> {
        self.get_relationship(tactic_id, "threat_actors").await
    }

    /// Get campaigns associated with this tactic
    pub async fn get_campaigns(&self, tactic_id: &str) -> Result<Collection<serde_json::Value>> {
        self.get_relationship(tactic_id, "campaigns").await
    }
}

impl Client {
    /// Get the Attack Tactics client
    pub fn attack_tactics(&self) -> AttackTacticClient<'_> {
        AttackTacticClient::new(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_attack_tactic_collection_name() {
        assert_eq!(AttackTactic::collection_name(), "attack_tactics");
    }

    #[test]
    fn test_attack_tactic_url() {
        let tactic_id = "TA0001";
        assert_eq!(AttackTactic::object_url(tactic_id), "attack_tactics/TA0001");
    }

    #[test]
    fn test_attack_tactic_relationships_url() {
        let tactic_id = "TA0001";
        assert_eq!(
            AttackTactic::relationships_url(tactic_id, "attack_techniques"),
            "attack_tactics/TA0001/relationships/attack_techniques"
        );
    }

    #[test]
    fn test_attack_tactic_relationship_objects_url() {
        let tactic_id = "TA0001";
        assert_eq!(
            AttackTactic::relationship_objects_url(tactic_id, "files"),
            "attack_tactics/TA0001/files"
        );
    }

    #[test]
    fn test_attack_tactic_attributes() {
        let attrs = AttackTacticAttributes {
            name: Some("Initial Access".to_string()),
            description: Some("The adversary is trying to get into your network".to_string()),
            external_id: Some("TA0001".to_string()),
            url: Some("https://attack.mitre.org/tactics/TA0001/".to_string()),
            platforms: Some(vec!["Windows".to_string(), "Linux".to_string()]),
            techniques_count: Some(10),
            ..Default::default()
        };

        assert_eq!(attrs.name.unwrap(), "Initial Access");
        assert_eq!(attrs.external_id.unwrap(), "TA0001");
        assert_eq!(attrs.techniques_count.unwrap(), 10);
    }
}
