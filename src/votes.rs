use crate::objects::{Collection, Object};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Vote {
    #[serde(flatten)]
    pub object: Object<VoteAttributes>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VoteAttributes {
    pub verdict: VoteVerdict,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub date: Option<i64>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<i32>,

    #[serde(flatten)]
    pub additional_attributes: HashMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum VoteVerdict {
    Harmless,
    Malicious,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VoteRequest {
    pub data: VoteRequestData,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VoteRequestData {
    #[serde(rename = "type")]
    pub object_type: String,
    pub attributes: VoteRequestAttributes,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VoteRequestAttributes {
    pub verdict: VoteVerdict,
}

impl VoteRequest {
    pub fn new(verdict: VoteVerdict) -> Self {
        Self {
            data: VoteRequestData {
                object_type: "vote".to_string(),
                attributes: VoteRequestAttributes { verdict },
            },
        }
    }
}

pub type VoteCollection = Collection<Vote>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vote_verdict_serialization() {
        let verdict = VoteVerdict::Harmless;
        let json = serde_json::to_string(&verdict).unwrap();
        assert_eq!(json, "\"harmless\"");

        let verdict = VoteVerdict::Malicious;
        let json = serde_json::to_string(&verdict).unwrap();
        assert_eq!(json, "\"malicious\"");
    }

    #[test]
    fn test_vote_request_creation() {
        let request = VoteRequest::new(VoteVerdict::Harmless);
        assert_eq!(request.data.object_type, "vote");
        assert_eq!(request.data.attributes.verdict, VoteVerdict::Harmless);
    }
}
