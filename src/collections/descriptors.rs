//! Descriptors for collection relationship objects

use serde::{Deserialize, Serialize};

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
