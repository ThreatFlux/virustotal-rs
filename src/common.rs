use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// Common base attributes that appear in multiple resource types
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct BaseAttributes {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_analysis_date: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_analysis_stats: Option<AnalysisStats>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_analysis_results: Option<HashMap<String, AnalysisResult>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reputation: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub total_votes: Option<VoteStats>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tags: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_modification_date: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_submission_date: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub first_submission_date: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AnalysisStats {
    pub harmless: u32,
    pub malicious: u32,
    pub suspicious: u32,
    pub undetected: u32,
    pub timeout: u32,
    #[serde(rename = "confirmed-timeout")]
    pub confirmed_timeout: Option<u32>,
    pub failure: Option<u32>,
    #[serde(rename = "type-unsupported")]
    pub type_unsupported: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VoteStats {
    pub harmless: u32,
    pub malicious: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisResult {
    pub category: String,
    pub result: Option<String>,
    pub method: String,
    pub engine_name: String,
    pub engine_version: Option<String>,
    pub engine_update: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Reputation {
    pub value: i32,
}

#[async_trait::async_trait]
pub trait CommentOperations {
    async fn get_comments_impl(
        &self,
        client: &crate::Client,
        resource_type: &str,
        resource_id: &str,
    ) -> crate::Result<crate::Collection<crate::Comment>>;

    async fn get_comments_with_limit_impl(
        &self,
        client: &crate::Client,
        resource_type: &str,
        resource_id: &str,
        limit: u32,
    ) -> crate::Result<crate::Collection<crate::Comment>>;

    async fn add_comment_impl(
        &self,
        client: &crate::Client,
        resource_type: &str,
        resource_id: &str,
        text: impl Into<String> + Send,
    ) -> crate::Result<crate::Comment>;
}

#[async_trait::async_trait]
pub trait VoteOperations {
    async fn get_votes_impl(
        &self,
        client: &crate::Client,
        resource_type: &str,
        resource_id: &str,
    ) -> crate::Result<crate::votes::VoteCollection>;

    async fn add_vote_impl(
        &self,
        client: &crate::Client,
        resource_type: &str,
        resource_id: &str,
        verdict: crate::VoteVerdict,
    ) -> crate::Result<crate::Vote>;
}

#[async_trait::async_trait]
pub trait AnalysisOperations {
    async fn analyse_impl(
        &self,
        client: &crate::Client,
        resource_type: &str,
        resource_id: &str,
    ) -> crate::Result<crate::AnalysisResponse>;

    async fn get_analysis_impl(
        &self,
        client: &crate::Client,
        analysis_id: &str,
    ) -> crate::Result<crate::Analysis>;
}

#[async_trait::async_trait]
pub trait RelationshipOperations {
    async fn get_relationship_impl<T>(
        &self,
        client: &crate::Client,
        resource_type: &str,
        resource_id: &str,
        relationship: &str,
    ) -> crate::Result<crate::Collection<T>>
    where
        T: for<'de> Deserialize<'de> + Send;

    async fn get_relationship_with_limit_impl<T>(
        &self,
        client: &crate::Client,
        resource_type: &str,
        resource_id: &str,
        relationship: &str,
        limit: u32,
    ) -> crate::Result<crate::Collection<T>>
    where
        T: for<'de> Deserialize<'de> + Send;

    async fn get_relationship_descriptors_impl(
        &self,
        client: &crate::Client,
        resource_type: &str,
        resource_id: &str,
        relationship: &str,
    ) -> crate::Result<crate::Collection<crate::objects::ObjectDescriptor>>;

    async fn get_relationship_descriptors_with_limit_impl(
        &self,
        client: &crate::Client,
        resource_type: &str,
        resource_id: &str,
        relationship: &str,
        limit: u32,
    ) -> crate::Result<crate::Collection<crate::objects::ObjectDescriptor>>;
}

pub struct BaseResourceClient;

#[async_trait::async_trait]
impl CommentOperations for BaseResourceClient {
    async fn get_comments_impl(
        &self,
        client: &crate::Client,
        resource_type: &str,
        resource_id: &str,
    ) -> crate::Result<crate::Collection<crate::Comment>> {
        let url = format!("{}/{}/comments", resource_type, resource_id);
        client.get(&url).await
    }

    async fn get_comments_with_limit_impl(
        &self,
        client: &crate::Client,
        resource_type: &str,
        resource_id: &str,
        limit: u32,
    ) -> crate::Result<crate::Collection<crate::Comment>> {
        let url = format!("{}/{}/comments?limit={}", resource_type, resource_id, limit);
        client.get(&url).await
    }

    async fn add_comment_impl(
        &self,
        client: &crate::Client,
        resource_type: &str,
        resource_id: &str,
        text: impl Into<String> + Send,
    ) -> crate::Result<crate::Comment> {
        use crate::comments::CreateCommentRequest;
        use crate::objects::ObjectResponse;

        let url = format!("{}/{}/comments", resource_type, resource_id);
        let request = CreateCommentRequest::new(text);
        let response: ObjectResponse<crate::comments::CommentAttributes> =
            client.post(&url, &request).await?;
        Ok(crate::Comment {
            object: response.data,
        })
    }
}

#[async_trait::async_trait]
impl VoteOperations for BaseResourceClient {
    async fn get_votes_impl(
        &self,
        client: &crate::Client,
        resource_type: &str,
        resource_id: &str,
    ) -> crate::Result<crate::votes::VoteCollection> {
        let url = format!("{}/{}/votes", resource_type, resource_id);
        client.get(&url).await
    }

    async fn add_vote_impl(
        &self,
        client: &crate::Client,
        resource_type: &str,
        resource_id: &str,
        verdict: crate::VoteVerdict,
    ) -> crate::Result<crate::Vote> {
        use crate::objects::ObjectResponse;
        use crate::votes::VoteRequest;

        let url = format!("{}/{}/votes", resource_type, resource_id);
        let request = VoteRequest::new(verdict);
        let response: ObjectResponse<crate::votes::VoteAttributes> =
            client.post(&url, &request).await?;
        Ok(crate::Vote {
            object: response.data,
        })
    }
}

#[async_trait::async_trait]
impl AnalysisOperations for BaseResourceClient {
    async fn analyse_impl(
        &self,
        client: &crate::Client,
        resource_type: &str,
        resource_id: &str,
    ) -> crate::Result<crate::AnalysisResponse> {
        let url = format!("{}/{}/analyse", resource_type, resource_id);
        client.post(&url, &serde_json::json!({})).await
    }

    async fn get_analysis_impl(
        &self,
        client: &crate::Client,
        analysis_id: &str,
    ) -> crate::Result<crate::Analysis> {
        use crate::objects::ObjectResponse;

        let url = format!("analyses/{}", analysis_id);
        let response: ObjectResponse<crate::analysis::AnalysisAttributes> =
            client.get(&url).await?;
        Ok(crate::Analysis {
            object: response.data,
        })
    }
}

#[async_trait::async_trait]
impl RelationshipOperations for BaseResourceClient {
    async fn get_relationship_impl<T>(
        &self,
        client: &crate::Client,
        resource_type: &str,
        resource_id: &str,
        relationship: &str,
    ) -> crate::Result<crate::Collection<T>>
    where
        T: for<'de> Deserialize<'de> + Send,
    {
        let url = format!("{}/{}/{}", resource_type, resource_id, relationship);
        client.get(&url).await
    }

    async fn get_relationship_with_limit_impl<T>(
        &self,
        client: &crate::Client,
        resource_type: &str,
        resource_id: &str,
        relationship: &str,
        limit: u32,
    ) -> crate::Result<crate::Collection<T>>
    where
        T: for<'de> Deserialize<'de> + Send,
    {
        let url = format!(
            "{}/{}/{}?limit={}",
            resource_type, resource_id, relationship, limit
        );
        client.get(&url).await
    }

    async fn get_relationship_descriptors_impl(
        &self,
        client: &crate::Client,
        resource_type: &str,
        resource_id: &str,
        relationship: &str,
    ) -> crate::Result<crate::Collection<crate::objects::ObjectDescriptor>> {
        let url = format!(
            "{}/{}/relationships/{}",
            resource_type, resource_id, relationship
        );
        client.get(&url).await
    }

    async fn get_relationship_descriptors_with_limit_impl(
        &self,
        client: &crate::Client,
        resource_type: &str,
        resource_id: &str,
        relationship: &str,
        limit: u32,
    ) -> crate::Result<crate::Collection<crate::objects::ObjectDescriptor>> {
        let url = format!(
            "{}/{}/relationships/{}?limit={}",
            resource_type, resource_id, relationship, limit
        );
        client.get(&url).await
    }
}

#[macro_export]
macro_rules! impl_common_client_methods {
    ($client_type:ty, $resource_type:expr) => {
        impl<'a> $client_type {
            pub fn new(client: &'a $crate::Client) -> Self {
                Self { client }
            }

            pub async fn get_comments(
                &self,
                id: &str,
            ) -> $crate::Result<$crate::Collection<$crate::Comment>> {
                use $crate::common::{BaseResourceClient, CommentOperations};
                let base = BaseResourceClient;
                base.get_comments_impl(self.client, $resource_type, id)
                    .await
            }

            pub async fn get_comments_with_limit(
                &self,
                id: &str,
                limit: u32,
            ) -> $crate::Result<$crate::Collection<$crate::Comment>> {
                use $crate::common::{BaseResourceClient, CommentOperations};
                let base = BaseResourceClient;
                base.get_comments_with_limit_impl(self.client, $resource_type, id, limit)
                    .await
            }

            pub async fn add_comment(
                &self,
                id: &str,
                text: impl Into<String> + Send,
            ) -> $crate::Result<$crate::Comment> {
                use $crate::common::{BaseResourceClient, CommentOperations};
                let base = BaseResourceClient;
                base.add_comment_impl(self.client, $resource_type, id, text)
                    .await
            }

            pub async fn get_votes(
                &self,
                id: &str,
            ) -> $crate::Result<$crate::votes::VoteCollection> {
                use $crate::common::{BaseResourceClient, VoteOperations};
                let base = BaseResourceClient;
                base.get_votes_impl(self.client, $resource_type, id).await
            }

            pub async fn add_vote(
                &self,
                id: &str,
                verdict: $crate::VoteVerdict,
            ) -> $crate::Result<$crate::Vote> {
                use $crate::common::{BaseResourceClient, VoteOperations};
                let base = BaseResourceClient;
                base.add_vote_impl(self.client, $resource_type, id, verdict)
                    .await
            }

            pub async fn analyse(&self, id: &str) -> $crate::Result<$crate::AnalysisResponse> {
                use $crate::common::{AnalysisOperations, BaseResourceClient};
                let base = BaseResourceClient;
                base.analyse_impl(self.client, $resource_type, id).await
            }

            pub async fn get_analysis(
                &self,
                analysis_id: &str,
            ) -> $crate::Result<$crate::Analysis> {
                use $crate::common::{AnalysisOperations, BaseResourceClient};
                let base = BaseResourceClient;
                base.get_analysis_impl(self.client, analysis_id).await
            }

            pub async fn get_relationship<T>(
                &self,
                id: &str,
                relationship: &str,
            ) -> $crate::Result<$crate::Collection<T>>
            where
                T: for<'de> serde::Deserialize<'de> + Send,
            {
                use $crate::common::{BaseResourceClient, RelationshipOperations};
                let base = BaseResourceClient;
                base.get_relationship_impl(self.client, $resource_type, id, relationship)
                    .await
            }

            pub async fn get_relationship_with_limit<T>(
                &self,
                id: &str,
                relationship: &str,
                limit: u32,
            ) -> $crate::Result<$crate::Collection<T>>
            where
                T: for<'de> serde::Deserialize<'de> + Send,
            {
                use $crate::common::{BaseResourceClient, RelationshipOperations};
                let base = BaseResourceClient;
                base.get_relationship_with_limit_impl(
                    self.client,
                    $resource_type,
                    id,
                    relationship,
                    limit,
                )
                .await
            }

            pub async fn get_relationship_descriptors(
                &self,
                id: &str,
                relationship: &str,
            ) -> $crate::Result<$crate::Collection<$crate::objects::ObjectDescriptor>> {
                use $crate::common::{BaseResourceClient, RelationshipOperations};
                let base = BaseResourceClient;
                base.get_relationship_descriptors_impl(
                    self.client,
                    $resource_type,
                    id,
                    relationship,
                )
                .await
            }

            pub async fn get_relationship_descriptors_with_limit(
                &self,
                id: &str,
                relationship: &str,
                limit: u32,
            ) -> $crate::Result<$crate::Collection<$crate::objects::ObjectDescriptor>> {
                use $crate::common::{BaseResourceClient, RelationshipOperations};
                let base = BaseResourceClient;
                base.get_relationship_descriptors_with_limit_impl(
                    self.client,
                    $resource_type,
                    id,
                    relationship,
                    limit,
                )
                .await
            }
        }
    };
}
