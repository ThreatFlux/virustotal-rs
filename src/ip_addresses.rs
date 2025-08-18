use crate::comments::CommentIterator;
use crate::common::{AnalysisResult, AnalysisStats, VoteStats};
use crate::objects::{Collection, CollectionIterator, Object, ObjectOperations, ObjectResponse};
use crate::{Client, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpAddress {
    #[serde(flatten)]
    pub object: Object<IpAddressAttributes>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct IpAddressAttributes {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub asn: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub as_owner: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub country: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub continent: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub network: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub whois: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub whois_date: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub regional_internet_registry: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reputation: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub harmless: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub malicious: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub suspicious: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub undetected: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timeout: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_analysis_date: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_analysis_stats: Option<AnalysisStats>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_analysis_results: Option<HashMap<String, AnalysisResult>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_modification_date: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub total_votes: Option<VoteStats>,
    #[serde(flatten)]
    pub additional_attributes: HashMap<String, serde_json::Value>,
}

impl ObjectOperations for IpAddress {
    type Attributes = IpAddressAttributes;

    fn collection_name() -> &'static str {
        "ip_addresses"
    }
}

pub struct IpAddressClient<'a> {
    pub(crate) client: &'a Client,
}

impl<'a> IpAddressClient<'a> {
    pub async fn get(&self, ip: &str) -> Result<IpAddress> {
        let url = IpAddress::object_url(ip);
        let response: ObjectResponse<IpAddressAttributes> = self.client.get(&url).await?;
        Ok(IpAddress {
            object: response.data,
        })
    }

    pub async fn get_with_relationships(
        &self,
        ip: &str,
        relationships: &[&str],
    ) -> Result<IpAddress> {
        let url = format!(
            "{}?relationships={}",
            IpAddress::object_url(ip),
            relationships.join(",")
        );
        let response: ObjectResponse<IpAddressAttributes> = self.client.get(&url).await?;
        Ok(IpAddress {
            object: response.data,
        })
    }

    pub async fn get_comments_iterator(&self, ip: &str) -> CommentIterator<'_> {
        let url = IpAddress::relationship_objects_url(ip, "comments");
        CommentIterator::new(self.client, url)
    }

    pub fn get_relationship_iterator<T>(
        &self,
        ip: &str,
        relationship: &str,
    ) -> CollectionIterator<'_, T>
    where
        T: for<'de> Deserialize<'de> + Clone,
    {
        let url = IpAddress::relationship_objects_url(ip, relationship);
        CollectionIterator::new(self.client, url)
    }

    // IP-specific convenience methods
    pub async fn get_historical_whois(&self, ip: &str) -> Result<Collection<serde_json::Value>> {
        self.get_relationship(ip, "historical_whois").await
    }

    pub async fn get_urls(&self, ip: &str) -> Result<Collection<serde_json::Value>> {
        self.get_relationship(ip, "urls").await
    }

    pub async fn get_resolutions(&self, ip: &str) -> Result<Collection<serde_json::Value>> {
        self.get_relationship(ip, "resolutions").await
    }

    pub async fn get_communicating_files(&self, ip: &str) -> Result<Collection<serde_json::Value>> {
        self.get_relationship(ip, "communicating_files").await
    }

    pub async fn get_downloaded_files(&self, ip: &str) -> Result<Collection<serde_json::Value>> {
        self.get_relationship(ip, "downloaded_files").await
    }

    pub async fn get_referrer_files(&self, ip: &str) -> Result<Collection<serde_json::Value>> {
        self.get_relationship(ip, "referrer_files").await
    }
}

// Apply the macro to generate common methods
crate::impl_common_client_methods!(IpAddressClient<'a>, "ip_addresses");

impl Client {
    pub fn ip_addresses(&self) -> IpAddressClient<'_> {
        IpAddressClient::new(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ip_address_collection_name() {
        assert_eq!(IpAddress::collection_name(), "ip_addresses");
    }

    #[test]
    fn test_ip_address_url() {
        assert_eq!(IpAddress::object_url("8.8.8.8"), "ip_addresses/8.8.8.8");
    }

    #[test]
    fn test_vote_verdict_serialization() {
        use crate::votes::VoteVerdict;

        let harmless = serde_json::to_string(&VoteVerdict::Harmless).unwrap();
        assert_eq!(harmless, "\"harmless\"");

        let malicious = serde_json::to_string(&VoteVerdict::Malicious).unwrap();
        assert_eq!(malicious, "\"malicious\"");
    }
}
