use crate::comments::{Comment, CommentIterator};
use crate::objects::{Collection as ObjectCollection, CollectionIterator, Object};
use crate::{Client, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Represents a Collection of IOCs in `VirusTotal`
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Collection {
    #[serde(flatten)]
    pub object: Object<CollectionAttributes>,
}

/// Attributes for a Collection
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CollectionAttributes {
    /// Collection name
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,

    /// Collection description
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

    /// Creation date (unix timestamp)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub creation_date: Option<i64>,

    /// Last modification date (unix timestamp)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_modification_date: Option<i64>,

    /// Collection owner
    #[serde(skip_serializing_if = "Option::is_none")]
    pub owner: Option<String>,

    /// Tags associated with the collection
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tags: Option<Vec<String>>,

    /// Source region (ISO 3166-1 alpha-2 country code)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_region: Option<String>,

    /// Targeted regions
    #[serde(skip_serializing_if = "Option::is_none")]
    pub targeted_regions: Option<Vec<String>>,

    /// Targeted industries
    #[serde(skip_serializing_if = "Option::is_none")]
    pub targeted_industries: Option<Vec<String>>,

    /// Threat category
    #[serde(skip_serializing_if = "Option::is_none")]
    pub threat_category: Option<String>,

    /// Number of domains in the collection
    #[serde(skip_serializing_if = "Option::is_none")]
    pub domains_count: Option<u32>,

    /// Number of files in the collection
    #[serde(skip_serializing_if = "Option::is_none")]
    pub files_count: Option<u32>,

    /// Number of IP addresses in the collection
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ip_addresses_count: Option<u32>,

    /// Number of URLs in the collection
    #[serde(skip_serializing_if = "Option::is_none")]
    pub urls_count: Option<u32>,

    /// Number of references in the collection
    #[serde(skip_serializing_if = "Option::is_none")]
    pub references_count: Option<u32>,

    /// Additional attributes
    #[serde(flatten)]
    pub additional_attributes: HashMap<String, serde_json::Value>,
}

/// Request to create a new collection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateCollectionRequest {
    pub data: CreateCollectionData,
}

/// Data for creating a collection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateCollectionData {
    pub attributes: CreateCollectionAttributes,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub relationships: Option<CollectionRelationships>,
    #[serde(rename = "type")]
    pub object_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub raw_items: Option<String>,
}

/// Attributes for creating a collection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateCollectionAttributes {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

/// Relationships for a collection
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CollectionRelationships {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub domains: Option<RelationshipData<DomainDescriptor>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub urls: Option<RelationshipData<UrlDescriptor>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub ip_addresses: Option<RelationshipData<IpAddressDescriptor>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub files: Option<RelationshipData<FileDescriptor>>,
}

/// Wrapper for relationship data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelationshipData<T> {
    pub data: Vec<T>,
}

/// Domain descriptor for relationships
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DomainDescriptor {
    #[serde(rename = "type")]
    pub object_type: String,
    pub id: String,
}

/// URL descriptor for relationships (can use URL or ID)
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum UrlDescriptor {
    WithUrl {
        #[serde(rename = "type")]
        object_type: String,
        url: String,
    },
    WithId {
        #[serde(rename = "type")]
        object_type: String,
        id: String,
    },
}

/// IP Address descriptor for relationships
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpAddressDescriptor {
    #[serde(rename = "type")]
    pub object_type: String,
    pub id: String,
}

/// File descriptor for relationships
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileDescriptor {
    #[serde(rename = "type")]
    pub object_type: String,
    pub id: String,
}

/// Request to update a collection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateCollectionRequest {
    pub data: UpdateCollectionData,
}

/// Data for updating a collection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateCollectionData {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attributes: Option<UpdateCollectionAttributes>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub raw_items: Option<String>,
    #[serde(rename = "type")]
    pub object_type: String,
}

/// Attributes for updating a collection
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct UpdateCollectionAttributes {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

/// Request for adding/removing items from a collection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CollectionItemsRequest<T> {
    pub data: Vec<T>,
}

/// Options for collection ordering
#[derive(Debug, Clone, Copy)]
pub enum CollectionOrder {
    CreationDateAsc,
    CreationDateDesc,
    CreationDayAsc,
    CreationDayDesc,
    DomainsAsc,
    DomainsDesc,
    FilesAsc,
    FilesDesc,
    IpAddressesAsc,
    IpAddressesDesc,
    LastModificationDateAsc,
    LastModificationDateDesc,
    LastModificationDayAsc,
    LastModificationDayDesc,
    ReferencesAsc,
    ReferencesDesc,
    UrlsAsc,
    UrlsDesc,
}

impl CollectionOrder {
    /// Convert to API parameter string
    pub fn to_string(&self) -> &'static str {
        match self {
            CollectionOrder::CreationDateAsc => "creation_date+",
            CollectionOrder::CreationDateDesc => "creation_date-",
            CollectionOrder::CreationDayAsc => "creation_day+",
            CollectionOrder::CreationDayDesc => "creation_day-",
            CollectionOrder::DomainsAsc => "domains+",
            CollectionOrder::DomainsDesc => "domains-",
            CollectionOrder::FilesAsc => "files+",
            CollectionOrder::FilesDesc => "files-",
            CollectionOrder::IpAddressesAsc => "ip_addresses+",
            CollectionOrder::IpAddressesDesc => "ip_addresses-",
            CollectionOrder::LastModificationDateAsc => "last_modification_date+",
            CollectionOrder::LastModificationDateDesc => "last_modification_date-",
            CollectionOrder::LastModificationDayAsc => "last_modification_day+",
            CollectionOrder::LastModificationDayDesc => "last_modification_day-",
            CollectionOrder::ReferencesAsc => "references+",
            CollectionOrder::ReferencesDesc => "references-",
            CollectionOrder::UrlsAsc => "urls+",
            CollectionOrder::UrlsDesc => "urls-",
        }
    }
}

/// Export format for collections
#[derive(Debug, Clone, Copy)]
pub enum ExportFormat {
    Json,
    Csv,
    Stix,
}

impl ExportFormat {
    /// Convert to API parameter string
    pub fn to_string(&self) -> &'static str {
        match self {
            ExportFormat::Json => "json",
            ExportFormat::Csv => "csv",
            ExportFormat::Stix => "stix",
        }
    }
}

/// Client for Collections operations
pub struct CollectionsClient<'a> {
    pub(crate) client: &'a Client,
}

impl<'a> CollectionsClient<'a> {
    pub fn new(client: &'a Client) -> Self {
        Self { client }
    }

    /// Create a new collection
    pub async fn create(&self, request: &CreateCollectionRequest) -> Result<Collection> {
        self.client.post("collections", request).await
    }

    /// Get a collection by ID
    pub async fn get(&self, collection_id: &str) -> Result<Collection> {
        let url = format!("collections/{}", collection_id);
        self.client.get(&url).await
    }

    /// Update a collection
    pub async fn update(
        &self,
        collection_id: &str,
        request: &UpdateCollectionRequest,
    ) -> Result<Collection> {
        let url = format!("collections/{}", collection_id);
        self.client.patch(&url, request).await
    }

    /// Delete a collection
    pub async fn delete(&self, collection_id: &str) -> Result<()> {
        let url = format!("collections/{}", collection_id);
        self.client.delete(&url).await
    }

    /// List collections (requires special privileges)
    pub async fn list(
        &self,
        filter: Option<&str>,
        order: Option<CollectionOrder>,
        limit: Option<u32>,
        cursor: Option<&str>,
    ) -> Result<ObjectCollection<Collection>> {
        let mut url = String::from("collections?");

        if let Some(f) = filter {
            url.push_str(&format!("filter={}&", urlencoding::encode(f)));
        }

        if let Some(o) = order {
            url.push_str(&format!("order={}&", o.to_string()));
        }

        if let Some(l) = limit {
            url.push_str(&format!("limit={}&", l.min(40))); // Max 40
        }

        if let Some(c) = cursor {
            url.push_str(&format!("cursor={}&", c));
        }

        // Remove trailing '&' or '?'
        url.pop();

        self.client.get(&url).await
    }

    /// List collections with pagination support
    pub fn list_iterator(
        &self,
        filter: Option<&str>,
        order: Option<CollectionOrder>,
    ) -> CollectionIterator<'_, Collection> {
        let mut url = String::from("collections?");

        if let Some(f) = filter {
            url.push_str(&format!("filter={}&", urlencoding::encode(f)));
        }

        if let Some(o) = order {
            url.push_str(&format!("order={}&", o.to_string()));
        }

        // Remove trailing '&' or '?'
        url.pop();

        CollectionIterator::new(self.client, url)
    }

    /// Get comments on a collection
    pub async fn get_comments(&self, collection_id: &str) -> Result<ObjectCollection<Comment>> {
        let url = format!("collections/{}/comments", collection_id);
        self.client.get(&url).await
    }

    /// Get comments on a collection with pagination
    pub fn get_comments_iterator(&self, collection_id: &str) -> CommentIterator<'_> {
        let url = format!("collections/{}/comments", collection_id);
        CommentIterator::new(self.client, url)
    }

    /// Add a comment to a collection
    pub async fn add_comment(&self, collection_id: &str, text: &str) -> Result<Comment> {
        let url = format!("collections/{}/comments", collection_id);
        let request = serde_json::json!({
            "data": {
                "type": "comment",
                "attributes": {
                    "text": text
                }
            }
        });
        self.client.post(&url, &request).await
    }

    /// Get objects related to a collection
    pub async fn get_relationship<T>(
        &self,
        collection_id: &str,
        relationship: &str,
    ) -> Result<ObjectCollection<T>>
    where
        T: serde::de::DeserializeOwned,
    {
        let url = format!("collections/{}/{}", collection_id, relationship);
        self.client.get(&url).await
    }

    /// Get object descriptors related to a collection
    pub async fn get_relationship_descriptors<T>(
        &self,
        collection_id: &str,
        relationship: &str,
    ) -> Result<ObjectCollection<T>>
    where
        T: serde::de::DeserializeOwned,
    {
        let url = format!(
            "collections/{}/relationships/{}",
            collection_id, relationship
        );
        self.client.get(&url).await
    }

    /// Add items to a collection relationship (domains, urls, `ip_addresses`, or files)
    pub async fn add_items<T>(
        &self,
        collection_id: &str,
        relationship: &str,
        items: &CollectionItemsRequest<T>,
    ) -> Result<()>
    where
        T: Serialize,
    {
        let url = format!("collections/{}/{}", collection_id, relationship);
        self.client.post(&url, items).await
    }

    /// Remove items from a collection relationship
    pub async fn remove_items<T>(
        &self,
        collection_id: &str,
        relationship: &str,
        items: &CollectionItemsRequest<T>,
    ) -> Result<()>
    where
        T: Serialize,
    {
        let url = format!("collections/{}/{}", collection_id, relationship);
        self.client.delete_with_body(&url, items).await
    }

    /// Export IOCs from a collection (requires special privileges)
    pub async fn export(&self, collection_id: &str, format: ExportFormat) -> Result<Vec<u8>> {
        let url = format!(
            "collections/{}/download/{}",
            collection_id,
            format.to_string()
        );
        self.client.get_bytes(&url).await
    }

    /// Export IOCs from a collection relationship
    pub async fn export_relationship(
        &self,
        collection_id: &str,
        relationship: &str,
        format: ExportFormat,
    ) -> Result<Vec<u8>> {
        let url = format!(
            "collections/{}/{}/download/{}",
            collection_id,
            relationship,
            format.to_string()
        );
        self.client.get_bytes(&url).await
    }

    /// Export aggregations from a collection
    pub async fn export_aggregations(
        &self,
        collection_id: &str,
        format: ExportFormat,
    ) -> Result<Vec<u8>> {
        let url = format!(
            "collections/{}/aggregations/download/{}",
            collection_id,
            format.to_string()
        );
        self.client.get_bytes(&url).await
    }

    /// Search IOCs inside a collection (requires special privileges)
    pub async fn search<T>(
        &self,
        collection_id: &str,
        query: &str,
        order: Option<&str>,
        limit: Option<u32>,
        cursor: Option<&str>,
    ) -> Result<ObjectCollection<T>>
    where
        T: serde::de::DeserializeOwned,
    {
        let mut url = format!(
            "collections/{}/search?query={}",
            collection_id,
            urlencoding::encode(query)
        );

        if let Some(o) = order {
            url.push_str(&format!("&order={}", o));
        }

        if let Some(l) = limit {
            url.push_str(&format!("&limit={}", l.min(40))); // Max 40
        }

        if let Some(c) = cursor {
            url.push_str(&format!("&cursor={}", c));
        }

        self.client.get(&url).await
    }
}

/// Helper methods for creating collections
impl CreateCollectionRequest {
    /// Create a new collection request with name and optional description
    pub fn new(name: String, description: Option<String>) -> Self {
        Self {
            data: CreateCollectionData {
                attributes: CreateCollectionAttributes { name, description },
                relationships: None,
                object_type: "collection".to_string(),
                raw_items: None,
            },
        }
    }

    /// Add domain relationships
    pub fn with_domains(mut self, domains: Vec<String>) -> Self {
        let domain_descriptors: Vec<DomainDescriptor> = domains
            .into_iter()
            .map(|id| DomainDescriptor {
                object_type: "domain".to_string(),
                id,
            })
            .collect();

        if let Some(ref mut relationships) = self.data.relationships {
            relationships.domains = Some(RelationshipData {
                data: domain_descriptors,
            });
        } else {
            let relationships = CollectionRelationships {
                domains: Some(RelationshipData {
                    data: domain_descriptors,
                }),
                ..Default::default()
            };
            self.data.relationships = Some(relationships);
        }
        self
    }

    /// Add URL relationships (using URLs)
    pub fn with_urls(mut self, urls: Vec<String>) -> Self {
        let url_descriptors: Vec<UrlDescriptor> = urls
            .into_iter()
            .map(|url| UrlDescriptor::WithUrl {
                object_type: "url".to_string(),
                url,
            })
            .collect();

        if let Some(ref mut relationships) = self.data.relationships {
            relationships.urls = Some(RelationshipData {
                data: url_descriptors,
            });
        } else {
            let relationships = CollectionRelationships {
                urls: Some(RelationshipData {
                    data: url_descriptors,
                }),
                ..Default::default()
            };
            self.data.relationships = Some(relationships);
        }
        self
    }

    /// Add URL relationships (using IDs)
    pub fn with_url_ids(mut self, url_ids: Vec<String>) -> Self {
        let url_descriptors: Vec<UrlDescriptor> = url_ids
            .into_iter()
            .map(|id| UrlDescriptor::WithId {
                object_type: "url".to_string(),
                id,
            })
            .collect();

        if let Some(ref mut relationships) = self.data.relationships {
            relationships.urls = Some(RelationshipData {
                data: url_descriptors,
            });
        } else {
            let relationships = CollectionRelationships {
                urls: Some(RelationshipData {
                    data: url_descriptors,
                }),
                ..Default::default()
            };
            self.data.relationships = Some(relationships);
        }
        self
    }

    /// Add IP address relationships
    pub fn with_ip_addresses(mut self, ips: Vec<String>) -> Self {
        let ip_descriptors: Vec<IpAddressDescriptor> = ips
            .into_iter()
            .map(|id| IpAddressDescriptor {
                object_type: "ip_address".to_string(),
                id,
            })
            .collect();

        if let Some(ref mut relationships) = self.data.relationships {
            relationships.ip_addresses = Some(RelationshipData {
                data: ip_descriptors,
            });
        } else {
            let relationships = CollectionRelationships {
                ip_addresses: Some(RelationshipData {
                    data: ip_descriptors,
                }),
                ..Default::default()
            };
            self.data.relationships = Some(relationships);
        }
        self
    }

    /// Add file relationships
    pub fn with_files(mut self, file_hashes: Vec<String>) -> Self {
        let file_descriptors: Vec<FileDescriptor> = file_hashes
            .into_iter()
            .map(|id| FileDescriptor {
                object_type: "file".to_string(),
                id,
            })
            .collect();

        if let Some(ref mut relationships) = self.data.relationships {
            relationships.files = Some(RelationshipData {
                data: file_descriptors,
            });
        } else {
            let relationships = CollectionRelationships {
                files: Some(RelationshipData {
                    data: file_descriptors,
                }),
                ..Default::default()
            };
            self.data.relationships = Some(relationships);
        }
        self
    }

    /// Add raw items text for extraction
    pub fn with_raw_items(mut self, raw_text: String) -> Self {
        self.data.raw_items = Some(raw_text);
        self
    }
}

impl Client {
    /// Get the Collections client for collection operations
    pub fn collections(&self) -> CollectionsClient<'_> {
        CollectionsClient::new(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_collection_request() {
        let request = CreateCollectionRequest::new(
            "Test Collection".to_string(),
            Some("A test collection description".to_string()),
        )
        .with_domains(vec!["example.com".to_string(), "test.com".to_string()])
        .with_urls(vec!["https://example.com".to_string()])
        .with_ip_addresses(vec!["8.8.8.8".to_string()])
        .with_files(vec!["abc123def456".to_string()]);

        assert_eq!(request.data.attributes.name, "Test Collection");
        assert_eq!(
            request.data.attributes.description.unwrap(),
            "A test collection description"
        );
        assert!(request.data.relationships.is_some());

        let relationships = request.data.relationships.unwrap();
        assert_eq!(relationships.domains.unwrap().data.len(), 2);
        assert_eq!(relationships.urls.unwrap().data.len(), 1);
        assert_eq!(relationships.ip_addresses.unwrap().data.len(), 1);
        assert_eq!(relationships.files.unwrap().data.len(), 1);
    }

    #[test]
    fn test_url_descriptor_variants() {
        let url_desc = UrlDescriptor::WithUrl {
            object_type: "url".to_string(),
            url: "https://example.com".to_string(),
        };

        let id_desc = UrlDescriptor::WithId {
            object_type: "url".to_string(),
            id: "abc123".to_string(),
        };

        // Test serialization
        let url_json = serde_json::to_string(&url_desc).unwrap();
        assert!(url_json.contains("\"url\""));
        assert!(url_json.contains("https://example.com"));

        let id_json = serde_json::to_string(&id_desc).unwrap();
        assert!(id_json.contains("\"id\""));
        assert!(id_json.contains("abc123"));
    }

    #[test]
    fn test_collection_order_strings() {
        assert_eq!(
            CollectionOrder::CreationDateAsc.to_string(),
            "creation_date+"
        );
        assert_eq!(
            CollectionOrder::CreationDateDesc.to_string(),
            "creation_date-"
        );
        assert_eq!(CollectionOrder::FilesAsc.to_string(), "files+");
        assert_eq!(CollectionOrder::FilesDesc.to_string(), "files-");
        assert_eq!(CollectionOrder::DomainsAsc.to_string(), "domains+");
        assert_eq!(CollectionOrder::DomainsDesc.to_string(), "domains-");
    }

    #[test]
    fn test_export_format_strings() {
        assert_eq!(ExportFormat::Json.to_string(), "json");
        assert_eq!(ExportFormat::Csv.to_string(), "csv");
        assert_eq!(ExportFormat::Stix.to_string(), "stix");
    }

    #[test]
    fn test_update_collection_request() {
        let request = UpdateCollectionRequest {
            data: UpdateCollectionData {
                attributes: Some(UpdateCollectionAttributes {
                    name: Some("Updated Name".to_string()),
                    description: Some("Updated description".to_string()),
                }),
                raw_items: Some("example.com, 8.8.8.8, malware.exe".to_string()),
                object_type: "collection".to_string(),
            },
        };

        assert!(request.data.attributes.is_some());
        let attrs = request.data.attributes.unwrap();
        assert_eq!(attrs.name.unwrap(), "Updated Name");
        assert_eq!(attrs.description.unwrap(), "Updated description");
        assert_eq!(
            request.data.raw_items.unwrap(),
            "example.com, 8.8.8.8, malware.exe"
        );
    }

    #[test]
    fn test_collection_attributes() {
        let attrs = CollectionAttributes {
            name: Some("Threat Intel Collection".to_string()),
            description: Some("APT campaign IOCs".to_string()),
            creation_date: Some(1234567890),
            owner: Some("analyst@example.com".to_string()),
            tags: Some(vec!["apt".to_string(), "malware".to_string()]),
            source_region: Some("US".to_string()),
            targeted_regions: Some(vec!["EU".to_string(), "ASIA".to_string()]),
            threat_category: Some("ransomware".to_string()),
            domains_count: Some(10),
            files_count: Some(25),
            ip_addresses_count: Some(5),
            urls_count: Some(15),
            ..Default::default()
        };

        assert_eq!(attrs.name.unwrap(), "Threat Intel Collection");
        assert_eq!(attrs.tags.unwrap().len(), 2);
        assert_eq!(attrs.source_region.unwrap(), "US");
        assert_eq!(attrs.files_count.unwrap(), 25);
    }

    #[test]
    fn test_collection_items_request() {
        let domains = vec![
            DomainDescriptor {
                object_type: "domain".to_string(),
                id: "example.com".to_string(),
            },
            DomainDescriptor {
                object_type: "domain".to_string(),
                id: "test.com".to_string(),
            },
        ];

        let request = CollectionItemsRequest { data: domains };
        assert_eq!(request.data.len(), 2);
        assert_eq!(request.data[0].id, "example.com");
        assert_eq!(request.data[1].id, "test.com");
    }

    #[test]
    fn test_create_collection_with_raw_items() {
        let request = CreateCollectionRequest::new("Raw Items Collection".to_string(), None)
            .with_raw_items(
                "This text contains IOCs: example.com, 192.168.1.1, https://malware.com"
                    .to_string(),
            );

        assert_eq!(request.data.attributes.name, "Raw Items Collection");
        assert!(request.data.raw_items.is_some());
        assert!(request.data.raw_items.unwrap().contains("example.com"));
    }
}
