use crate::{client::Client, error::Result, objects::Object};
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct YaraRuleset {
    #[serde(flatten)]
    pub object: Object<YaraRulesetAttributes>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct YaraRulesetAttributes {
    pub name: Option<String>,
    pub rules: Option<Vec<YaraRule>>,
    pub source: Option<String>,
    pub ruleset_name: Option<String>,
    pub ruleset_version: Option<String>,
    pub author: Option<String>,
    pub description: Option<String>,
    pub reference: Option<String>,
    pub creation_date: Option<i64>,
    pub modification_date: Option<i64>,
    pub enabled: Option<bool>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct YaraRule {
    pub rule_name: Option<String>,
    pub meta: Option<YaraRuleMeta>,
    pub strings: Option<Vec<YaraRuleString>>,
    pub condition: Option<String>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct YaraRuleMeta {
    pub author: Option<String>,
    pub description: Option<String>,
    pub reference: Option<String>,
    pub date: Option<String>,
    pub hash: Option<String>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct YaraRuleString {
    pub identifier: Option<String>,
    pub value: Option<String>,
    pub string_type: Option<String>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct YaraRulesetResponse {
    pub data: YaraRuleset,
}

pub struct YaraRulesetsClient<'a> {
    client: &'a Client,
}

impl<'a> YaraRulesetsClient<'a> {
    pub(crate) fn new(client: &'a Client) -> Self {
        Self { client }
    }

    pub async fn get(&self, id: impl Into<String>) -> Result<YaraRulesetResponse> {
        let url = format!("yara_rulesets/{}", id.into());
        self.client.get(&url).await
    }
}

impl crate::Client {
    pub fn yara_rulesets(&self) -> YaraRulesetsClient<'_> {
        YaraRulesetsClient::new(self)
    }
}
