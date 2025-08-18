use crate::objects::{Collection, Object};
use crate::{Client, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Represents a Reference in VirusTotal
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Reference {
    #[serde(flatten)]
    pub object: Object<ReferenceAttributes>,
}

/// Attributes for a Reference
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ReferenceAttributes {
    /// Reference title
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,

    /// Reference description
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

    /// Reference URL
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,

    /// Author of the reference
    #[serde(skip_serializing_if = "Option::is_none")]
    pub author: Option<String>,

    /// Source of the reference
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,

    /// Publication date (UTC timestamp)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub publication_date: Option<i64>,

    /// Creation date (UTC timestamp)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub creation_date: Option<i64>,

    /// Last modification date (UTC timestamp)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_modification_date: Option<i64>,

    /// Tags associated with the reference
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tags: Option<Vec<String>>,

    /// Additional attributes
    #[serde(flatten)]
    pub additional_attributes: HashMap<String, serde_json::Value>,
}

/// Request to create a new reference
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateReferenceRequest {
    pub data: CreateReferenceData,
}

/// Data for creating a reference
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateReferenceData {
    pub attributes: CreateReferenceAttributes,
    #[serde(rename = "type")]
    pub object_type: String,
}

/// Attributes for creating a reference
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateReferenceAttributes {
    pub title: String,
    pub url: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub author: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tags: Option<Vec<String>>,
}

/// Client for References operations
pub struct ReferencesClient<'a> {
    pub(crate) client: &'a Client,
}

impl<'a> ReferencesClient<'a> {
    pub fn new(client: &'a Client) -> Self {
        Self { client }
    }

    /// Create a new reference (requires special privileges)
    pub async fn create(&self, request: &CreateReferenceRequest) -> Result<Reference> {
        self.client.post("references", request).await
    }

    /// Get a reference by ID (requires special privileges)
    pub async fn get(&self, reference_id: &str) -> Result<Reference> {
        let url = format!("references/{}", reference_id);
        self.client.get(&url).await
    }

    /// Delete a reference (requires special privileges)
    pub async fn delete(&self, reference_id: &str) -> Result<()> {
        let url = format!("references/{}", reference_id);
        self.client.delete(&url).await
    }

    /// Get objects related to a reference
    pub async fn get_relationship<T>(
        &self,
        reference_id: &str,
        relationship: &str,
        limit: Option<u32>,
        cursor: Option<&str>,
    ) -> Result<Collection<T>>
    where
        T: serde::de::DeserializeOwned,
    {
        let mut url = format!("references/{}/{}?", reference_id, relationship);

        if let Some(l) = limit {
            url.push_str(&format!("limit={}&", l));
        }

        if let Some(c) = cursor {
            url.push_str(&format!("cursor={}&", c));
        }

        // Remove trailing '&' or '?'
        url.pop();

        self.client.get(&url).await
    }

    /// Get object descriptors related to a reference
    pub async fn get_relationship_descriptors<T>(
        &self,
        reference_id: &str,
        relationship: &str,
        limit: Option<u32>,
        cursor: Option<&str>,
    ) -> Result<Collection<T>>
    where
        T: serde::de::DeserializeOwned,
    {
        let mut url = format!(
            "references/{}/relationships/{}?",
            reference_id, relationship
        );

        if let Some(l) = limit {
            url.push_str(&format!("limit={}&", l));
        }

        if let Some(c) = cursor {
            url.push_str(&format!("cursor={}&", c));
        }

        // Remove trailing '&' or '?'
        url.pop();

        self.client.get(&url).await
    }
}

/// Helper methods for creating references
impl CreateReferenceRequest {
    /// Create a new reference request
    pub fn new(title: String, url: String) -> Self {
        Self {
            data: CreateReferenceData {
                attributes: CreateReferenceAttributes {
                    title,
                    url,
                    description: None,
                    author: None,
                    source: None,
                    tags: None,
                },
                object_type: "reference".to_string(),
            },
        }
    }

    /// Set description
    pub fn with_description(mut self, description: String) -> Self {
        self.data.attributes.description = Some(description);
        self
    }

    /// Set author
    pub fn with_author(mut self, author: String) -> Self {
        self.data.attributes.author = Some(author);
        self
    }

    /// Set source
    pub fn with_source(mut self, source: String) -> Self {
        self.data.attributes.source = Some(source);
        self
    }

    /// Set tags
    pub fn with_tags(mut self, tags: Vec<String>) -> Self {
        self.data.attributes.tags = Some(tags);
        self
    }
}

impl Client {
    /// Get the References client for reference operations
    pub fn references(&self) -> ReferencesClient<'_> {
        ReferencesClient::new(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_reference_attributes() {
        let attrs = ReferenceAttributes {
            title: Some("APT1 Report".to_string()),
            description: Some("Detailed analysis of APT1 activities".to_string()),
            url: Some("https://example.com/apt1-report".to_string()),
            author: Some("Security Research Team".to_string()),
            source: Some("Example Security".to_string()),
            tags: Some(vec![
                "apt".to_string(),
                "china".to_string(),
                "espionage".to_string(),
            ]),
            ..Default::default()
        };

        assert_eq!(attrs.title.unwrap(), "APT1 Report");
        assert_eq!(attrs.url.unwrap(), "https://example.com/apt1-report");
        assert_eq!(attrs.tags.unwrap().len(), 3);
    }

    #[test]
    fn test_create_reference_request() {
        let request = CreateReferenceRequest::new(
            "Malware Analysis Report".to_string(),
            "https://example.com/report".to_string(),
        )
        .with_description("Comprehensive malware analysis".to_string())
        .with_author("John Doe".to_string())
        .with_source("Security Lab".to_string())
        .with_tags(vec!["malware".to_string(), "analysis".to_string()]);

        assert_eq!(request.data.attributes.title, "Malware Analysis Report");
        assert_eq!(request.data.attributes.url, "https://example.com/report");
        assert_eq!(
            request.data.attributes.description.unwrap(),
            "Comprehensive malware analysis"
        );
        assert_eq!(request.data.attributes.author.unwrap(), "John Doe");
        assert_eq!(request.data.attributes.source.unwrap(), "Security Lab");
        assert_eq!(request.data.attributes.tags.unwrap().len(), 2);
        assert_eq!(request.data.object_type, "reference");
    }

    #[test]
    fn test_reference_dates() {
        let attrs = ReferenceAttributes {
            publication_date: Some(1609459200),       // 2021-01-01
            creation_date: Some(1609545600),          // 2021-01-02
            last_modification_date: Some(1609632000), // 2021-01-03
            ..Default::default()
        };

        assert_eq!(attrs.publication_date.unwrap(), 1609459200);
        assert_eq!(attrs.creation_date.unwrap(), 1609545600);
        assert_eq!(attrs.last_modification_date.unwrap(), 1609632000);
    }
}
