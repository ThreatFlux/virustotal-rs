#[cfg(test)]
use crate::common::AnalysisStats;
#[cfg(test)]
use serde_json::{json, Value};
#[cfg(test)]
use std::collections::HashMap;

#[cfg(test)]
use super::constants;

#[cfg(test)]
/// Builder pattern for creating test AnalysisStats
#[derive(Debug, Clone)]
pub struct AnalysisStatsBuilder {
    harmless: u32,
    malicious: u32,
    suspicious: u32,
    undetected: u32,
    timeout: u32,
    confirmed_timeout: Option<u32>,
    failure: Option<u32>,
    type_unsupported: Option<u32>,
}

#[cfg(test)]
impl AnalysisStatsBuilder {
    pub fn new() -> Self {
        Self {
            harmless: 70,
            malicious: 0,
            suspicious: 0,
            undetected: 3,
            timeout: 0,
            confirmed_timeout: Some(0),
            failure: Some(0),
            type_unsupported: Some(2),
        }
    }

    pub fn clean() -> Self {
        Self::new().with_malicious(0).with_suspicious(0)
    }

    pub fn malicious() -> Self {
        Self::new()
            .with_malicious(15)
            .with_suspicious(5)
            .with_harmless(50)
    }

    pub fn suspicious() -> Self {
        Self::new()
            .with_suspicious(20)
            .with_malicious(2)
            .with_harmless(50)
    }

    pub fn with_harmless(mut self, count: u32) -> Self {
        self.harmless = count;
        self
    }

    pub fn with_malicious(mut self, count: u32) -> Self {
        self.malicious = count;
        self
    }

    pub fn with_suspicious(mut self, count: u32) -> Self {
        self.suspicious = count;
        self
    }

    pub fn with_undetected(mut self, count: u32) -> Self {
        self.undetected = count;
        self
    }

    pub fn with_timeout(mut self, count: u32) -> Self {
        self.timeout = count;
        self
    }

    pub fn with_confirmed_timeout(mut self, count: Option<u32>) -> Self {
        self.confirmed_timeout = count;
        self
    }

    pub fn with_failure(mut self, count: Option<u32>) -> Self {
        self.failure = count;
        self
    }

    pub fn with_type_unsupported(mut self, count: Option<u32>) -> Self {
        self.type_unsupported = count;
        self
    }

    pub fn build(self) -> AnalysisStats {
        AnalysisStats {
            harmless: self.harmless,
            malicious: self.malicious,
            suspicious: self.suspicious,
            undetected: self.undetected,
            timeout: self.timeout,
            confirmed_timeout: self.confirmed_timeout,
            failure: self.failure,
            type_unsupported: self.type_unsupported,
        }
    }
}

#[cfg(test)]
impl Default for AnalysisStatsBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
/// Builder pattern for creating test File objects
#[derive(Debug, Clone)]
pub struct FileResponseBuilder {
    id: String,
    md5: Option<String>,
    sha1: Option<String>,
    sha256: Option<String>,
    size: Option<u64>,
    type_description: Option<String>,
    type_tag: Option<String>,
    names: Option<Vec<String>>,
    reputation: Option<i32>,
    stats: Option<AnalysisStats>,
    tags: Option<Vec<String>>,
    creation_date: Option<i64>,
    last_analysis_date: Option<i64>,
}

#[cfg(test)]
impl FileResponseBuilder {
    pub fn new(id: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            md5: Some(constants::SAMPLE_MD5.to_string()),
            sha1: Some(constants::SAMPLE_SHA1.to_string()),
            sha256: Some(constants::SAMPLE_SHA256.to_string()),
            size: Some(1024),
            type_description: Some("ASCII text".to_string()),
            type_tag: Some("text".to_string()),
            names: Some(vec!["test.txt".to_string()]),
            reputation: Some(0),
            stats: Some(AnalysisStatsBuilder::clean().build()),
            tags: None,
            creation_date: Some(constants::SAMPLE_TIMESTAMP),
            last_analysis_date: Some(constants::SAMPLE_TIMESTAMP),
        }
    }

    pub fn clean_file() -> Self {
        Self::new(constants::CLEAN_HASH)
    }

    pub fn malicious_file() -> Self {
        Self::new(constants::MALICIOUS_HASH)
            .with_stats(AnalysisStatsBuilder::malicious().build())
            .with_reputation(-50)
            .with_tags(vec!["malware".to_string(), "trojan".to_string()])
    }

    pub fn with_md5(mut self, md5: impl Into<String>) -> Self {
        self.md5 = Some(md5.into());
        self
    }

    pub fn with_sha1(mut self, sha1: impl Into<String>) -> Self {
        self.sha1 = Some(sha1.into());
        self
    }

    pub fn with_sha256(mut self, sha256: impl Into<String>) -> Self {
        self.sha256 = Some(sha256.into());
        self
    }

    pub fn with_size(mut self, size: u64) -> Self {
        self.size = Some(size);
        self
    }

    pub fn with_type_description(mut self, desc: impl Into<String>) -> Self {
        self.type_description = Some(desc.into());
        self
    }

    pub fn with_reputation(mut self, reputation: i32) -> Self {
        self.reputation = Some(reputation);
        self
    }

    pub fn with_stats(mut self, stats: AnalysisStats) -> Self {
        self.stats = Some(stats);
        self
    }

    pub fn with_tags(mut self, tags: Vec<String>) -> Self {
        self.tags = Some(tags);
        self
    }

    pub fn with_names(mut self, names: Vec<String>) -> Self {
        self.names = Some(names);
        self
    }

    pub fn build(self) -> Value {
        json!({
            "type": "file",
            "id": self.id,
            "attributes": {
                "md5": self.md5,
                "sha1": self.sha1,
                "sha256": self.sha256,
                "size": self.size,
                "type_description": self.type_description,
                "type_tag": self.type_tag,
                "names": self.names,
                "reputation": self.reputation,
                "last_analysis_stats": self.stats,
                "tags": self.tags,
                "creation_date": self.creation_date,
                "last_analysis_date": self.last_analysis_date
            }
        })
    }
}

#[cfg(test)]
/// Builder pattern for creating test Domain objects
#[derive(Debug, Clone)]
pub struct DomainResponseBuilder {
    id: String,
    reputation: Option<i32>,
    stats: Option<AnalysisStats>,
    tags: Option<Vec<String>>,
    creation_date: Option<i64>,
    last_analysis_date: Option<i64>,
    whois: Option<String>,
    categories: Option<HashMap<String, String>>,
}

#[cfg(test)]
impl DomainResponseBuilder {
    pub fn new(id: impl Into<String>) -> Self {
        let mut categories = HashMap::new();
        categories.insert(
            "Forcepoint ThreatSeeker".to_string(),
            "search engines and portals".to_string(),
        );

        Self {
            id: id.into(),
            reputation: Some(0),
            stats: Some(AnalysisStatsBuilder::clean().build()),
            tags: None,
            creation_date: Some(820454400), // 1996-01-01
            last_analysis_date: Some(constants::SAMPLE_TIMESTAMP),
            whois: Some(
                "Domain Name: EXAMPLE.COM\\nRegistry Domain ID: 2336799_DOMAIN_COM-VRSN"
                    .to_string(),
            ),
            categories: Some(categories),
        }
    }

    pub fn clean_domain() -> Self {
        Self::new(constants::SAMPLE_DOMAIN)
    }

    pub fn malicious_domain() -> Self {
        Self::new("malicious-example.com")
            .with_stats(AnalysisStatsBuilder::malicious().build())
            .with_reputation(-80)
            .with_tags(vec!["malware".to_string(), "phishing".to_string()])
    }

    pub fn with_reputation(mut self, reputation: i32) -> Self {
        self.reputation = Some(reputation);
        self
    }

    pub fn with_stats(mut self, stats: AnalysisStats) -> Self {
        self.stats = Some(stats);
        self
    }

    pub fn with_tags(mut self, tags: Vec<String>) -> Self {
        self.tags = Some(tags);
        self
    }

    pub fn with_whois(mut self, whois: impl Into<String>) -> Self {
        self.whois = Some(whois.into());
        self
    }

    pub fn build(self) -> Value {
        json!({
            "type": "domain",
            "id": self.id,
            "attributes": {
                "reputation": self.reputation,
                "last_analysis_stats": self.stats,
                "tags": self.tags,
                "creation_date": self.creation_date,
                "last_analysis_date": self.last_analysis_date,
                "whois": self.whois,
                "categories": self.categories
            }
        })
    }
}

#[cfg(test)]
/// Builder pattern for creating test IP Address objects
#[derive(Debug, Clone)]
pub struct IpResponseBuilder {
    id: String,
    country: Option<String>,
    as_owner: Option<String>,
    asn: Option<u32>,
    network: Option<String>,
    reputation: Option<i32>,
    stats: Option<AnalysisStats>,
    tags: Option<Vec<String>>,
    last_analysis_date: Option<i64>,
    whois: Option<String>,
}

#[cfg(test)]
impl IpResponseBuilder {
    pub fn new(id: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            country: Some("US".to_string()),
            as_owner: Some("Google LLC".to_string()),
            asn: Some(15169),
            network: Some("8.8.8.0/24".to_string()),
            reputation: Some(0),
            stats: Some(AnalysisStatsBuilder::clean().build()),
            tags: None,
            last_analysis_date: Some(constants::SAMPLE_TIMESTAMP),
            whois: Some("NetRange: 8.8.8.0 - 8.8.8.255".to_string()),
        }
    }

    pub fn clean_ip() -> Self {
        Self::new(constants::SAMPLE_IP)
    }

    pub fn malicious_ip() -> Self {
        Self::new("192.168.1.100")
            .with_stats(AnalysisStatsBuilder::malicious().build())
            .with_reputation(-60)
            .with_tags(vec!["malware".to_string(), "botnet".to_string()])
            .with_country("RU".to_string())
    }

    pub fn with_country(mut self, country: impl Into<String>) -> Self {
        self.country = Some(country.into());
        self
    }

    pub fn with_as_owner(mut self, as_owner: impl Into<String>) -> Self {
        self.as_owner = Some(as_owner.into());
        self
    }

    pub fn with_asn(mut self, asn: u32) -> Self {
        self.asn = Some(asn);
        self
    }

    pub fn with_reputation(mut self, reputation: i32) -> Self {
        self.reputation = Some(reputation);
        self
    }

    pub fn with_stats(mut self, stats: AnalysisStats) -> Self {
        self.stats = Some(stats);
        self
    }

    pub fn with_tags(mut self, tags: Vec<String>) -> Self {
        self.tags = Some(tags);
        self
    }

    pub fn build(self) -> Value {
        json!({
            "type": "ip_address",
            "id": self.id,
            "attributes": {
                "country": self.country,
                "as_owner": self.as_owner,
                "asn": self.asn,
                "network": self.network,
                "reputation": self.reputation,
                "last_analysis_stats": self.stats,
                "tags": self.tags,
                "last_analysis_date": self.last_analysis_date,
                "whois": self.whois
            }
        })
    }
}
