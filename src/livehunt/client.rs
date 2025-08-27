use super::types::*;
use crate::objects::{Collection, CollectionIterator};
use crate::{Client, Result};

/// Client for interacting with Livehunt APIs
pub struct LivehuntClient<'a> {
    pub(crate) client: &'a Client,
}

impl<'a> LivehuntClient<'a> {
    pub(crate) fn new(client: &'a Client) -> Self {
        Self { client }
    }

    fn build_rulesets_url(
        filter: Option<&str>,
        order: Option<LivehuntRulesetOrder>,
        limit: Option<u32>,
        cursor: Option<&str>,
    ) -> String {
        let mut params = Vec::new();
        if let Some(f) = filter {
            params.push(format!("filter={}", urlencoding::encode(f)));
        }
        if let Some(o) = order {
            params.push(format!("order={}", o.to_string()));
        }
        if let Some(l) = limit {
            params.push(format!("limit={}&", l));
        }
        if let Some(c) = cursor {
            params.push(format!("cursor={}", urlencoding::encode(c)));
        }
        let query = if params.is_empty() {
            String::new()
        } else {
            format!("?{}", params.join("&"))
        };
        format!("intelligence/hunting_rulesets{}", query)
    }

    pub async fn list_rulesets(
        &self,
        filter: Option<&str>,
        order: Option<LivehuntRulesetOrder>,
        limit: Option<u32>,
        cursor: Option<&str>,
    ) -> Result<Collection<LivehuntRuleset>> {
        let url = Self::build_rulesets_url(filter, order, limit, cursor);
        self.client.get(&url).await
    }

    pub fn list_rulesets_iterator(
        &self,
        filter: Option<&str>,
        order: Option<LivehuntRulesetOrder>,
    ) -> CollectionIterator<'_, LivehuntRuleset> {
        let url = Self::build_rulesets_url(filter, order, None, None);
        CollectionIterator::new(self.client, url)
    }

    pub async fn create_ruleset(
        &self,
        request: &CreateLivehuntRulesetRequest,
    ) -> Result<LivehuntRuleset> {
        self.client
            .post("intelligence/hunting_rulesets", request)
            .await
    }

    pub async fn get_ruleset(&self, ruleset_id: &str) -> Result<LivehuntRuleset> {
        let url = format!(
            "intelligence/hunting_rulesets/{}",
            urlencoding::encode(ruleset_id)
        );
        self.client.get(&url).await
    }

    pub async fn update_ruleset(
        &self,
        ruleset_id: &str,
        request: &UpdateLivehuntRulesetRequest,
    ) -> Result<LivehuntRuleset> {
        let url = format!(
            "intelligence/hunting_rulesets/{}",
            urlencoding::encode(ruleset_id)
        );
        self.client.patch(&url, request).await
    }

    pub async fn delete_ruleset(&self, ruleset_id: &str) -> Result<()> {
        let url = format!(
            "intelligence/hunting_rulesets/{}",
            urlencoding::encode(ruleset_id)
        );
        self.client.delete(&url).await
    }

    pub async fn delete_all_rulesets(&self, _username: &str) -> Result<OperationResponse> {
        Err(crate::Error::Unknown(
            "delete_all_rulesets requires x-confirm-delete header support".to_string(),
        ))
    }

    pub async fn check_editor_permission(
        &self,
        ruleset_id: &str,
        user_or_group_id: &str,
    ) -> Result<PermissionCheckResponse> {
        let url = format!(
            "intelligence/hunting_rulesets/{}/relationships/editors/{}",
            urlencoding::encode(ruleset_id),
            urlencoding::encode(user_or_group_id)
        );
        self.client.get(&url).await
    }

    pub async fn grant_edit_permissions(
        &self,
        ruleset_id: &str,
        request: &AddEditorsRequest,
    ) -> Result<()> {
        let url = format!(
            "intelligence/hunting_rulesets/{}/relationships/editors",
            urlencoding::encode(ruleset_id)
        );
        self.client.post(&url, request).await
    }

    pub async fn revoke_edit_permission(
        &self,
        ruleset_id: &str,
        user_or_group_id: &str,
    ) -> Result<()> {
        let url = format!(
            "intelligence/hunting_rulesets/{}/relationships/editors/{}",
            urlencoding::encode(ruleset_id),
            urlencoding::encode(user_or_group_id)
        );
        self.client.delete(&url).await
    }

    pub async fn transfer_ownership(
        &self,
        ruleset_id: &str,
        request: &TransferOwnershipRequest,
    ) -> Result<()> {
        let url = format!(
            "intelligence/hunting_rulesets/{}/relationships/owner",
            urlencoding::encode(ruleset_id)
        );
        self.client.post(&url, request).await
    }

    pub async fn get_relationship_descriptors<T>(
        &self,
        ruleset_id: &str,
        relationship: &str,
        limit: Option<u32>,
        cursor: Option<&str>,
    ) -> Result<Collection<T>>
    where
        T: serde::de::DeserializeOwned,
    {
        let mut url = format!(
            "intelligence/hunting_rulesets/{}/relationships/{}?",
            urlencoding::encode(ruleset_id),
            relationship
        );

        if let Some(l) = limit {
            url.push_str(&format!("limit={}&", l));
        }

        if let Some(c) = cursor {
            url.push_str(&format!("cursor={}&", urlencoding::encode(c)));
        }

        url.pop();
        self.client.get(&url).await
    }
}

impl Client {
    pub fn livehunt(&self) -> LivehuntClient<'_> {
        LivehuntClient::new(self)
    }
}
