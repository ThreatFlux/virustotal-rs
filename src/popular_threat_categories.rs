use crate::{Client, Result};
use serde::{Deserialize, Serialize};

/// Response containing popular threat categories
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PopularThreatCategoriesResponse {
    pub data: Vec<ThreatCategory>,
}

/// Represents a threat category
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatCategory {
    /// The category name (e.g., "trojan", "ransomware", "dropper")
    pub value: String,

    /// Human-readable label for the category
    #[serde(skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,

    /// Description of the threat category
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

    /// Count of files with this category
    #[serde(skip_serializing_if = "Option::is_none")]
    pub count: Option<u64>,
}

impl Client {
    /// Get a list of popular threat categories
    ///
    /// This returns a list of malware categories commonly used in AV verdicts
    /// (e.g., trojan, dropper, ransomware, etc.). The AV verdicts from every file
    /// are processed for these categories, normalized (e.g., "ransom" becomes "ransomware"),
    /// and set as part of their popular_threat_classification.
    pub async fn get_popular_threat_categories(&self) -> Result<PopularThreatCategoriesResponse> {
        self.get("popular_threat_categories").await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_threat_category_structure() {
        let category = ThreatCategory {
            value: "trojan".to_string(),
            label: Some("Trojan".to_string()),
            description: Some(
                "A type of malware that disguises itself as legitimate software".to_string(),
            ),
            count: Some(150000),
        };

        assert_eq!(category.value, "trojan");
        assert_eq!(category.label.unwrap(), "Trojan");
        assert!(category.description.unwrap().contains("malware"));
        assert_eq!(category.count.unwrap(), 150000);
    }

    #[test]
    fn test_threat_category_minimal() {
        let category = ThreatCategory {
            value: "ransomware".to_string(),
            label: None,
            description: None,
            count: None,
        };

        assert_eq!(category.value, "ransomware");
        assert!(category.label.is_none());
        assert!(category.description.is_none());
        assert!(category.count.is_none());
    }

    #[test]
    fn test_popular_threat_categories_response() {
        let response = PopularThreatCategoriesResponse {
            data: vec![
                ThreatCategory {
                    value: "trojan".to_string(),
                    label: Some("Trojan".to_string()),
                    description: None,
                    count: Some(100000),
                },
                ThreatCategory {
                    value: "ransomware".to_string(),
                    label: Some("Ransomware".to_string()),
                    description: None,
                    count: Some(50000),
                },
                ThreatCategory {
                    value: "dropper".to_string(),
                    label: Some("Dropper".to_string()),
                    description: None,
                    count: Some(30000),
                },
            ],
        };

        assert_eq!(response.data.len(), 3);
        assert_eq!(response.data[0].value, "trojan");
        assert_eq!(response.data[1].value, "ransomware");
        assert_eq!(response.data[2].value, "dropper");
    }

    #[test]
    fn test_common_threat_categories() {
        // Test that common threat categories are properly represented
        let common_categories = vec![
            "trojan",
            "ransomware",
            "dropper",
            "backdoor",
            "rootkit",
            "worm",
            "adware",
            "spyware",
            "keylogger",
            "botnet",
            "miner",
            "downloader",
            "exploit",
            "hacktool",
            "riskware",
            "grayware",
        ];

        for category in common_categories {
            let threat_cat = ThreatCategory {
                value: category.to_string(),
                label: None,
                description: None,
                count: None,
            };
            assert_eq!(threat_cat.value, category);
        }
    }
}
