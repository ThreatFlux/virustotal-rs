use crate::comments::CommentIterator;
use crate::common::{AnalysisResult, AnalysisStats, VoteStats};
use crate::objects::{Collection, CollectionIterator, Object, ObjectOperations, ObjectResponse};
use crate::{Client, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Domain {
    #[serde(flatten)]
    pub object: Object<DomainAttributes>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DomainAttributes {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub categories: Option<HashMap<String, String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub creation_date: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_update_date: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_modification_date: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_dns_records_date: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_analysis_date: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_analysis_stats: Option<AnalysisStats>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_analysis_results: Option<HashMap<String, AnalysisResult>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_https_certificate_date: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_https_certificate: Option<HttpsCertificate>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dns_records: Option<Vec<DnsRecord>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub popularity_ranks: Option<HashMap<String, PopularityRank>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub registrar: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reputation: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub total_votes: Option<VoteStats>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tags: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub whois: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub whois_date: Option<i64>,
    #[serde(flatten)]
    pub additional_attributes: HashMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpsCertificate {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cert_signature: Option<CertSignature>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub extensions: Option<HashMap<String, serde_json::Value>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issuer: Option<HashMap<String, String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_key: Option<PublicKey>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub serial_number: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature_algorithm: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub size: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subject: Option<HashMap<String, String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub thumbprint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub thumbprint_sha256: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub validity: Option<Validity>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertSignature {
    pub signature: String,
    pub signature_algorithm: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicKey {
    pub algorithm: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rsa: Option<RsaKey>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ec: Option<EcKey>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RsaKey {
    pub key_size: u32,
    pub modulus: String,
    pub exponent: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EcKey {
    pub key_size: u32,
    pub pub_x: String,
    pub pub_y: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Validity {
    pub not_after: String,
    pub not_before: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsRecord {
    #[serde(rename = "type")]
    pub record_type: String,
    pub value: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ttl: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PopularityRank {
    pub rank: u32,
    pub timestamp: i64,
}

impl ObjectOperations for Domain {
    type Attributes = DomainAttributes;

    fn collection_name() -> &'static str {
        "domains"
    }
}

pub struct DomainClient<'a> {
    pub(crate) client: &'a Client,
}

impl<'a> DomainClient<'a> {
    pub async fn get(&self, domain: &str) -> Result<Domain> {
        let url = Domain::object_url(domain);
        let response: ObjectResponse<DomainAttributes> = self.client.get(&url).await?;
        Ok(Domain {
            object: response.data,
        })
    }

    pub async fn get_with_relationships(
        &self,
        domain: &str,
        relationships: &[&str],
    ) -> Result<Domain> {
        let url = format!(
            "{}?relationships={}",
            Domain::object_url(domain),
            relationships.join(",")
        );
        let response: ObjectResponse<DomainAttributes> = self.client.get(&url).await?;
        Ok(Domain {
            object: response.data,
        })
    }

    pub async fn get_comments_iterator(&self, domain: &str) -> CommentIterator<'_> {
        let url = Domain::relationship_objects_url(domain, "comments");
        CommentIterator::new(self.client, url)
    }

    pub fn get_relationship_iterator<T>(
        &self,
        domain: &str,
        relationship: &str,
    ) -> CollectionIterator<'_, T>
    where
        T: for<'de> Deserialize<'de> + Clone,
    {
        let url = Domain::relationship_objects_url(domain, relationship);
        CollectionIterator::new(self.client, url)
    }

    // Domain-specific convenience methods
    pub async fn get_subdomains(&self, domain: &str) -> Result<Collection<serde_json::Value>> {
        self.get_relationship(domain, "subdomains").await
    }

    pub async fn get_urls(&self, domain: &str) -> Result<Collection<serde_json::Value>> {
        self.get_relationship(domain, "urls").await
    }

    pub async fn get_resolutions(&self, domain: &str) -> Result<Collection<serde_json::Value>> {
        self.get_relationship(domain, "resolutions").await
    }

    pub async fn get_communicating_files(
        &self,
        domain: &str,
    ) -> Result<Collection<serde_json::Value>> {
        self.get_relationship(domain, "communicating_files").await
    }

    pub async fn get_downloaded_files(
        &self,
        domain: &str,
    ) -> Result<Collection<serde_json::Value>> {
        self.get_relationship(domain, "downloaded_files").await
    }

    pub async fn get_referrer_files(&self, domain: &str) -> Result<Collection<serde_json::Value>> {
        self.get_relationship(domain, "referrer_files").await
    }

    pub async fn get_parent(&self, domain: &str) -> Result<serde_json::Value> {
        let url = Domain::relationship_objects_url(domain, "parent");
        self.client.get(&url).await
    }

    pub async fn get_siblings(&self, domain: &str) -> Result<Collection<serde_json::Value>> {
        self.get_relationship(domain, "siblings").await
    }
}

// Apply the macro to generate common methods
crate::impl_common_client_methods!(DomainClient<'a>, "domains");

impl Client {
    pub fn domains(&self) -> DomainClient<'_> {
        DomainClient::new(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_domain_collection_name() {
        assert_eq!(Domain::collection_name(), "domains");
    }

    #[test]
    fn test_domain_url() {
        assert_eq!(Domain::object_url("example.com"), "domains/example.com");
    }

    #[test]
    fn test_domain_relationships_url() {
        assert_eq!(
            Domain::relationships_url("example.com", "subdomains"),
            "domains/example.com/relationships/subdomains"
        );
    }
}
