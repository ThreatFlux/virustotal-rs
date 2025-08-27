//! Core collection types and attributes

use crate::objects::Object;
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
