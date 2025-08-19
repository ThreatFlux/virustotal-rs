use crate::objects::{Collection, CollectionIterator, Object};
use crate::{Client, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Represents a Crowdsourced YARA rule in VirusTotal
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrowdsourcedYaraRule {
    #[serde(flatten)]
    pub object: Object<CrowdsourcedYaraRuleAttributes>,
}

/// Attributes for a Crowdsourced YARA rule
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CrowdsourcedYaraRuleAttributes {
    /// Rule name
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,

    /// Tags associated with the rule
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tags: Option<Vec<String>>,

    /// Number of matches
    #[serde(skip_serializing_if = "Option::is_none")]
    pub matches: Option<u64>,

    /// Rule author
    #[serde(skip_serializing_if = "Option::is_none")]
    pub author: Option<String>,

    /// Whether the rule is enabled
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,

    /// The YARA rule content
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rule: Option<String>,

    /// Creation date (UTC timestamp)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub creation_date: Option<i64>,

    /// Last modification date (UTC timestamp)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_modification_date: Option<i64>,

    /// Date when the rule was included (UTC timestamp)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub included_date: Option<i64>,

    /// Rule metadata
    #[serde(skip_serializing_if = "Option::is_none")]
    pub meta: Option<Vec<YaraRuleMeta>>,

    /// Threat category
    #[serde(skip_serializing_if = "Option::is_none")]
    pub threat_category: Option<String>,

    /// Additional attributes
    #[serde(flatten)]
    pub additional_attributes: HashMap<String, serde_json::Value>,
}

/// Metadata for a YARA rule
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct YaraRuleMeta {
    pub key: String,
    pub value: String,
}

/// Options for YARA rule ordering
#[derive(Debug, Clone, Copy)]
pub enum YaraRuleOrder {
    MatchesAsc,
    MatchesDesc,
    CreationDateAsc,
    CreationDateDesc,
    IncludedDateAsc,
    IncludedDateDesc,
    ModificationDateAsc,
    ModificationDateDesc,
    NameAsc,
    NameDesc,
}

impl YaraRuleOrder {
    /// Convert to API parameter string
    pub fn to_string(&self) -> &'static str {
        match self {
            YaraRuleOrder::MatchesAsc => "matches+",
            YaraRuleOrder::MatchesDesc => "matches-",
            YaraRuleOrder::CreationDateAsc => "creation_date+",
            YaraRuleOrder::CreationDateDesc => "creation_date-",
            YaraRuleOrder::IncludedDateAsc => "included_date+",
            YaraRuleOrder::IncludedDateDesc => "included_date-",
            YaraRuleOrder::ModificationDateAsc => "modification_date+",
            YaraRuleOrder::ModificationDateDesc => "modification_date-",
            YaraRuleOrder::NameAsc => "name+",
            YaraRuleOrder::NameDesc => "name-",
        }
    }
}

/// Client for Crowdsourced YARA Rules operations
pub struct CrowdsourcedYaraRulesClient<'a> {
    pub(crate) client: &'a Client,
}

impl<'a> CrowdsourcedYaraRulesClient<'a> {
    pub fn new(client: &'a Client) -> Self {
        Self { client }
    }

    /// List crowdsourced YARA rules
    ///
    /// Allowed filters:
    /// - author: Rule author
    /// - creation_date: Creation date
    /// - enabled: Whether the rule is enabled (enabled:true or enabled:false)
    /// - included_date: Included date
    /// - last_modification_date: Last modification date
    /// - name: Rule name (full word match)
    /// - tag: Rule tag
    /// - threat_category: Threat category
    pub async fn list(
        &self,
        filter: Option<&str>,
        order: Option<YaraRuleOrder>,
        limit: Option<u32>,
        cursor: Option<&str>,
    ) -> Result<Collection<CrowdsourcedYaraRule>> {
        let mut url = String::from("yara_rules?");

        if let Some(f) = filter {
            url.push_str(&format!("filter={}&", urlencoding::encode(f)));
        }

        if let Some(o) = order {
            url.push_str(&format!("order={}&", o.to_string()));
        }

        if let Some(l) = limit {
            url.push_str(&format!("limit={}&", l));
        }

        if let Some(c) = cursor {
            url.push_str(&format!("cursor={}&", urlencoding::encode(c)));
        }

        // Remove trailing '&' or '?'
        url.pop();

        self.client.get(&url).await
    }

    /// List YARA rules with pagination support
    pub fn list_iterator(
        &self,
        filter: Option<&str>,
        order: Option<YaraRuleOrder>,
    ) -> CollectionIterator<'_, CrowdsourcedYaraRule> {
        let mut url = String::from("yara_rules?");

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

    /// Get a crowdsourced YARA rule by ID
    pub async fn get(&self, rule_id: &str) -> Result<CrowdsourcedYaraRule> {
        let url = format!("yara_rules/{}", urlencoding::encode(rule_id));
        self.client.get(&url).await
    }

    /// Get objects related to a YARA rule
    pub async fn get_relationship<T>(
        &self,
        rule_id: &str,
        relationship: &str,
        limit: Option<u32>,
        cursor: Option<&str>,
    ) -> Result<Collection<T>>
    where
        T: serde::de::DeserializeOwned,
    {
        let mut url = format!(
            "yara_rules/{}/{}?",
            urlencoding::encode(rule_id),
            relationship
        );

        if let Some(l) = limit {
            url.push_str(&format!("limit={}&", l));
        }

        if let Some(c) = cursor {
            url.push_str(&format!("cursor={}&", urlencoding::encode(c)));
        }

        // Remove trailing '&' or '?'
        url.pop();

        self.client.get(&url).await
    }

    /// Get relationship with pagination support
    pub fn get_relationship_iterator<T>(
        &self,
        rule_id: &str,
        relationship: &str,
    ) -> CollectionIterator<'_, T>
    where
        T: serde::de::DeserializeOwned + Clone + Send + 'static,
    {
        let url = format!(
            "yara_rules/{}/{}",
            urlencoding::encode(rule_id),
            relationship
        );

        CollectionIterator::new(self.client, url)
    }

    /// Get object descriptors related to a YARA rule
    pub async fn get_relationship_descriptors<T>(
        &self,
        rule_id: &str,
        relationship: &str,
        limit: Option<u32>,
        cursor: Option<&str>,
    ) -> Result<Collection<T>>
    where
        T: serde::de::DeserializeOwned,
    {
        let mut url = format!(
            "yara_rules/{}/relationships/{}?",
            urlencoding::encode(rule_id),
            relationship
        );

        if let Some(l) = limit {
            url.push_str(&format!("limit={}&", l));
        }

        if let Some(c) = cursor {
            url.push_str(&format!("cursor={}&", urlencoding::encode(c)));
        }

        // Remove trailing '&' or '?'
        url.pop();

        self.client.get(&url).await
    }
}

impl Client {
    /// Get the Crowdsourced YARA Rules client
    pub fn crowdsourced_yara_rules(&self) -> CrowdsourcedYaraRulesClient<'_> {
        CrowdsourcedYaraRulesClient::new(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_yara_rule_attributes() {
        let attrs = CrowdsourcedYaraRuleAttributes {
            name: Some("PK_AXA_fun".to_string()),
            tags: Some(vec!["AXA".to_string(), "phishing".to_string()]),
            matches: Some(42),
            author: Some("Security Researcher".to_string()),
            enabled: Some(true),
            rule: Some("rule PK_AXA_fun : AXA { ... }".to_string()),
            threat_category: Some("phishing".to_string()),
            ..Default::default()
        };

        assert_eq!(attrs.name.unwrap(), "PK_AXA_fun");
        assert_eq!(attrs.tags.unwrap().len(), 2);
        assert_eq!(attrs.matches.unwrap(), 42);
        assert!(attrs.enabled.unwrap());
    }

    #[test]
    fn test_yara_rule_meta() {
        let meta = YaraRuleMeta {
            key: "description".to_string(),
            value: "Phishing Kit impersonating AXA banque".to_string(),
        };

        assert_eq!(meta.key, "description");
        assert_eq!(meta.value, "Phishing Kit impersonating AXA banque");
    }

    #[test]
    fn test_yara_rule_order_strings() {
        assert_eq!(YaraRuleOrder::MatchesAsc.to_string(), "matches+");
        assert_eq!(YaraRuleOrder::MatchesDesc.to_string(), "matches-");
        assert_eq!(YaraRuleOrder::CreationDateAsc.to_string(), "creation_date+");
        assert_eq!(
            YaraRuleOrder::CreationDateDesc.to_string(),
            "creation_date-"
        );
        assert_eq!(
            YaraRuleOrder::ModificationDateDesc.to_string(),
            "modification_date-"
        );
        assert_eq!(YaraRuleOrder::NameAsc.to_string(), "name+");
    }

    #[test]
    fn test_yara_rule_with_meta() {
        let attrs = CrowdsourcedYaraRuleAttributes {
            name: Some("TestRule".to_string()),
            meta: Some(vec![
                YaraRuleMeta {
                    key: "author".to_string(),
                    value: "John Doe".to_string(),
                },
                YaraRuleMeta {
                    key: "date".to_string(),
                    value: "2023-05-02".to_string(),
                },
                YaraRuleMeta {
                    key: "licence".to_string(),
                    value: "GPL-3.0".to_string(),
                },
            ]),
            ..Default::default()
        };

        let meta = attrs.meta.unwrap();
        assert_eq!(meta.len(), 3);
        assert_eq!(meta[0].key, "author");
        assert_eq!(meta[1].key, "date");
        assert_eq!(meta[2].key, "licence");
    }

    #[test]
    fn test_yara_rule_dates() {
        let attrs = CrowdsourcedYaraRuleAttributes {
            creation_date: Some(1682985600),
            last_modification_date: Some(1683185194),
            included_date: Some(1683000000),
            ..Default::default()
        };

        assert_eq!(attrs.creation_date.unwrap(), 1682985600);
        assert_eq!(attrs.last_modification_date.unwrap(), 1683185194);
        assert_eq!(attrs.included_date.unwrap(), 1683000000);
    }
}
