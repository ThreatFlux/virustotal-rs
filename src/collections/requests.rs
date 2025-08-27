//! Request and response structures for collection operations

use super::descriptors::*;
use serde::{Deserialize, Serialize};

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
