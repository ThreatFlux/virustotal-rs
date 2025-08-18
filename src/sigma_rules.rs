use crate::{client::Client, error::Result, objects::Object};
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct SigmaRule {
    #[serde(flatten)]
    pub object: Object<SigmaRuleAttributes>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct SigmaRuleAttributes {
    pub rule_name: Option<String>,
    pub rule_source: Option<String>,
    pub rule_title: Option<String>,
    pub rule_description: Option<String>,
    pub rule_author: Option<String>,
    pub rule_date: Option<String>,
    pub rule_modified: Option<String>,
    pub rule_tags: Option<Vec<String>>,
    pub rule_references: Option<Vec<String>>,
    pub rule_level: Option<String>,
    pub rule_status: Option<String>,
    pub rule_falsepositives: Option<Vec<String>>,
    pub rule_raw: Option<String>,
    pub source_severity: Option<u32>,
    pub ruleset_name: Option<String>,
    pub ruleset_version: Option<String>,
    pub threat_hunting_ruleset: Option<bool>,
    pub stats: Option<SigmaRuleStats>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct SigmaRuleStats {
    pub rule_matches: Option<u32>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct SigmaRuleResponse {
    pub data: SigmaRule,
}

pub struct SigmaRulesClient<'a> {
    client: &'a Client,
}

impl<'a> SigmaRulesClient<'a> {
    pub(crate) fn new(client: &'a Client) -> Self {
        Self { client }
    }

    pub async fn get(&self, id: impl Into<String>) -> Result<SigmaRuleResponse> {
        let url = format!("sigma_rules/{}", id.into());
        self.client.get(&url).await
    }
}

impl crate::Client {
    pub fn sigma_rules(&self) -> SigmaRulesClient<'_> {
        SigmaRulesClient::new(self)
    }
}
