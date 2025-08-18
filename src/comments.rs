use crate::objects::{Collection, CollectionIterator, Object, ObjectOperations, ObjectResponse};
use crate::{Client, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Comment {
    #[serde(flatten)]
    pub object: Object<CommentAttributes>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommentAttributes {
    pub text: String,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub date: Option<i64>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub votes: Option<CommentVotes>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub html: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub tags: Option<Vec<String>>,

    #[serde(flatten)]
    pub additional_attributes: HashMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommentVotes {
    pub positive: u32,
    pub negative: u32,
    pub abuse: u32,
}

impl ObjectOperations for Comment {
    type Attributes = CommentAttributes;

    fn collection_name() -> &'static str {
        "comments"
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateCommentRequest {
    pub data: CreateCommentData,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateCommentData {
    #[serde(rename = "type")]
    pub object_type: String,
    pub attributes: CreateCommentAttributes,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateCommentAttributes {
    pub text: String,
}

impl CreateCommentRequest {
    pub fn new(text: impl Into<String>) -> Self {
        Self {
            data: CreateCommentData {
                object_type: "comment".to_string(),
                attributes: CreateCommentAttributes { text: text.into() },
            },
        }
    }
}

pub struct CommentIterator<'a> {
    inner: CollectionIterator<'a, Comment>,
}

impl<'a> CommentIterator<'a> {
    pub fn new(client: &'a crate::Client, url: impl Into<String>) -> Self {
        Self {
            inner: CollectionIterator::new(client, url),
        }
    }

    pub fn with_limit(mut self, limit: u32) -> Self {
        self.inner = self.inner.with_limit(limit);
        self
    }

    pub async fn next_batch(&mut self) -> crate::Result<Vec<Comment>> {
        self.inner.next_batch().await
    }

    pub async fn collect_all(self) -> crate::Result<Vec<Comment>> {
        self.inner.collect_all().await
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CommentVoteType {
    Positive,
    Negative,
    Abuse,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VoteCommentRequest {
    pub data: String,
}

impl VoteCommentRequest {
    pub fn new(vote_type: CommentVoteType) -> Self {
        let vote_str = match vote_type {
            CommentVoteType::Positive => "positive",
            CommentVoteType::Negative => "negative",
            CommentVoteType::Abuse => "abuse",
        };
        Self {
            data: vote_str.to_string(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VoteCommentResponse {
    pub data: CommentVotes,
}

/// Client for interacting with Comments API endpoints
pub struct CommentsClient<'a> {
    pub(crate) client: &'a Client,
}

impl<'a> CommentsClient<'a> {
    pub fn new(client: &'a Client) -> Self {
        Self { client }
    }

    /// Get latest comments with optional filtering
    /// Filter examples: "tag:malware", "tag:phishing"
    pub async fn get_latest(
        &self,
        filter: Option<&str>,
        limit: Option<u32>,
    ) -> Result<Collection<Comment>> {
        let mut endpoint = "comments".to_string();
        let mut params = Vec::new();

        if let Some(f) = filter {
            params.push(format!("filter={}", f));
        }
        if let Some(l) = limit {
            params.push(format!("limit={}", l));
        }

        if !params.is_empty() {
            endpoint.push('?');
            endpoint.push_str(&params.join("&"));
        }

        self.client.get(&endpoint).await
    }

    /// Get latest comments iterator for paginated results
    pub fn get_latest_iterator(&self, filter: Option<String>) -> CommentIterator<'_> {
        let mut url = "comments".to_string();
        if let Some(f) = filter {
            url.push_str(&format!("?filter={}", f));
        }
        CommentIterator::new(self.client, url)
    }

    /// Get a specific comment by ID
    pub async fn get(&self, comment_id: &str) -> Result<Comment> {
        let url = Comment::object_url(comment_id);
        let response: ObjectResponse<CommentAttributes> = self.client.get(&url).await?;
        Ok(Comment {
            object: response.data,
        })
    }

    /// Delete a comment by ID
    pub async fn delete(&self, comment_id: &str) -> Result<()> {
        let url = Comment::object_url(comment_id);
        self.client.delete(&url).await
    }

    /// Add a vote to a comment
    pub async fn vote(
        &self,
        comment_id: &str,
        vote_type: CommentVoteType,
    ) -> Result<VoteCommentResponse> {
        let endpoint = format!("{}/{}/vote", Comment::collection_name(), comment_id);
        let request = VoteCommentRequest::new(vote_type);
        self.client.post(&endpoint, &request).await
    }

    /// Get objects related to a comment
    pub async fn get_relationship<T>(
        &self,
        comment_id: &str,
        relationship: &str,
    ) -> Result<Collection<T>>
    where
        T: for<'de> Deserialize<'de>,
    {
        let url = Comment::relationship_objects_url(comment_id, relationship);
        self.client.get(&url).await
    }

    /// Get object descriptors related to a comment
    pub async fn get_relationship_descriptors(
        &self,
        comment_id: &str,
        relationship: &str,
    ) -> Result<Collection<serde_json::Value>> {
        let url = Comment::relationships_url(comment_id, relationship);
        self.client.get(&url).await
    }

    /// Get relationship iterator for paginated results
    pub fn get_relationship_iterator<T>(
        &self,
        comment_id: &str,
        relationship: &str,
    ) -> CollectionIterator<'_, T>
    where
        T: for<'de> Deserialize<'de> + Clone,
    {
        let url = Comment::relationship_objects_url(comment_id, relationship);
        CollectionIterator::new(self.client, url)
    }

    /// Parse comment ID to extract item type and item ID
    /// Returns (item_type_char, item_id, random_string)
    pub fn parse_comment_id(comment_id: &str) -> Option<(char, String, String)> {
        let parts: Vec<&str> = comment_id.splitn(3, '-').collect();
        if parts.len() == 3 {
            let item_type = parts[0].chars().next()?;
            let item_id = parts[1].to_string();
            let random_string = parts[2].to_string();
            Some((item_type, item_id, random_string))
        } else {
            None
        }
    }

    /// Get the item type from a comment ID
    /// Returns: 'd' for domain, 'f' for file, 'g' for graph, 'i' for IP address, 'u' for URL
    pub fn get_item_type(comment_id: &str) -> Option<char> {
        comment_id.chars().next()
    }
}

impl Client {
    /// Get the Comments client for comment-related operations
    pub fn comments(&self) -> CommentsClient<'_> {
        CommentsClient::new(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_comment_request() {
        let request = CreateCommentRequest::new("This is a test comment");
        assert_eq!(request.data.object_type, "comment");
        assert_eq!(request.data.attributes.text, "This is a test comment");
    }

    #[test]
    fn test_comment_vote_serialization() {
        let vote = CommentVoteType::Positive;
        let json = serde_json::to_string(&vote).unwrap();
        assert_eq!(json, "\"positive\"");
    }

    #[test]
    fn test_vote_comment_request() {
        let request = VoteCommentRequest::new(CommentVoteType::Abuse);
        assert_eq!(request.data, "abuse");
    }

    #[test]
    fn test_comment_collection_name() {
        assert_eq!(Comment::collection_name(), "comments");
    }

    #[test]
    fn test_parse_comment_id() {
        let comment_id = "f-abc123-random456";
        let parsed = CommentsClient::parse_comment_id(comment_id);
        assert!(parsed.is_some());
        let (item_type, item_id, random_string) = parsed.unwrap();
        assert_eq!(item_type, 'f');
        assert_eq!(item_id, "abc123");
        assert_eq!(random_string, "random456");
    }

    #[test]
    fn test_parse_comment_id_domain() {
        let comment_id = "d-example.com-xyz789";
        let parsed = CommentsClient::parse_comment_id(comment_id);
        assert!(parsed.is_some());
        let (item_type, item_id, _) = parsed.unwrap();
        assert_eq!(item_type, 'd');
        assert_eq!(item_id, "example.com");
    }

    #[test]
    fn test_parse_comment_id_url() {
        let comment_id =
            "u-011915942db556bbab5137f761efe61fed2b00598fea900360b800b193a7bf31-d94d7c8a";
        let parsed = CommentsClient::parse_comment_id(comment_id);
        assert!(parsed.is_some());
        let (item_type, item_id, random_string) = parsed.unwrap();
        assert_eq!(item_type, 'u');
        assert_eq!(
            item_id,
            "011915942db556bbab5137f761efe61fed2b00598fea900360b800b193a7bf31"
        );
        assert_eq!(random_string, "d94d7c8a");
    }

    #[test]
    fn test_get_item_type() {
        assert_eq!(CommentsClient::get_item_type("f-abc123-random"), Some('f'));
        assert_eq!(
            CommentsClient::get_item_type("d-example.com-xyz"),
            Some('d')
        );
        assert_eq!(
            CommentsClient::get_item_type("i-192.168.1.1-abc"),
            Some('i')
        );
        assert_eq!(CommentsClient::get_item_type("g-graph123-def"), Some('g'));
        assert_eq!(CommentsClient::get_item_type("u-url123-ghi"), Some('u'));
        assert_eq!(CommentsClient::get_item_type(""), None);
    }

    #[test]
    fn test_comment_votes_structure() {
        let votes = CommentVotes {
            positive: 10,
            negative: 2,
            abuse: 1,
        };
        assert_eq!(votes.positive, 10);
        assert_eq!(votes.negative, 2);
        assert_eq!(votes.abuse, 1);
    }

    #[test]
    fn test_vote_comment_response() {
        let response = VoteCommentResponse {
            data: CommentVotes {
                positive: 5,
                negative: 0,
                abuse: 0,
            },
        };
        assert_eq!(response.data.positive, 5);
        assert_eq!(response.data.negative, 0);
        assert_eq!(response.data.abuse, 0);
    }
}
