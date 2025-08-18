use crate::common::AnalysisStats;
use crate::objects::Object;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Analysis {
    #[serde(flatten)]
    pub object: Object<AnalysisAttributes>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisAttributes {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub date: Option<i64>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<AnalysisStatus>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub stats: Option<AnalysisStats>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub results: Option<HashMap<String, EngineResult>>,

    #[serde(flatten)]
    pub additional_attributes: HashMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum AnalysisStatus {
    Queued,
    InProgress,
    Completed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EngineResult {
    pub category: String,
    pub result: String,
    pub method: String,
    pub engine_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub engine_version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub engine_update: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisResponse {
    pub data: AnalysisDescriptor,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisDescriptor {
    #[serde(rename = "type")]
    pub object_type: String,
    pub id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub links: Option<crate::objects::Links>,
}

impl Analysis {
    pub fn is_completed(&self) -> bool {
        matches!(
            self.object.attributes.status,
            Some(AnalysisStatus::Completed)
        )
    }

    pub fn get_verdict(&self) -> Option<Verdict> {
        let stats = self.object.attributes.stats.as_ref()?;

        if stats.malicious > 0 {
            Some(Verdict::Malicious)
        } else if stats.suspicious > 0 {
            Some(Verdict::Suspicious)
        } else if stats.harmless > 0 {
            Some(Verdict::Harmless)
        } else {
            Some(Verdict::Undetected)
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    Harmless,
    Suspicious,
    Malicious,
    Undetected,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_analysis_status_serialization() {
        let status = AnalysisStatus::Completed;
        let json = serde_json::to_string(&status).unwrap();
        assert_eq!(json, "\"completed\"");
    }

    #[test]
    fn test_verdict_detection() {
        let mut analysis = Analysis {
            object: Object {
                object_type: "analysis".to_string(),
                id: "test".to_string(),
                links: None,
                attributes: AnalysisAttributes {
                    date: None,
                    status: Some(AnalysisStatus::Completed),
                    stats: Some(AnalysisStats {
                        harmless: 10,
                        malicious: 2,
                        suspicious: 0,
                        undetected: 5,
                        timeout: 0,
                        confirmed_timeout: None,
                        failure: None,
                        type_unsupported: None,
                    }),
                    results: None,
                    additional_attributes: HashMap::new(),
                },
                relationships: None,
            },
        };

        assert_eq!(analysis.get_verdict(), Some(Verdict::Malicious));

        if let Some(ref mut stats) = analysis.object.attributes.stats {
            stats.malicious = 0;
            stats.suspicious = 1;
        }
        assert_eq!(analysis.get_verdict(), Some(Verdict::Suspicious));
    }
}
