use crate::common::{AnalysisResult, AnalysisStats, BaseAttributes, VoteStats};

#[test]
fn test_analysis_stats_creation() {
    let stats = AnalysisStats {
        harmless: 50,
        malicious: 2,
        suspicious: 1,
        undetected: 10,
        timeout: 0,
        confirmed_timeout: Some(0),
        failure: Some(0),
        type_unsupported: Some(0),
    };

    assert_eq!(stats.harmless, 50);
    assert_eq!(stats.malicious, 2);
    assert_eq!(stats.suspicious, 1);
    assert_eq!(stats.undetected, 10);
    assert_eq!(stats.timeout, 0);
}

#[test]
fn test_vote_stats_creation() {
    let votes = VoteStats {
        harmless: 100,
        malicious: 5,
    };

    assert_eq!(votes.harmless, 100);
    assert_eq!(votes.malicious, 5);
}

#[test]
fn test_analysis_result_creation() {
    let result = AnalysisResult {
        category: "malicious".to_string(),
        result: Some("Trojan.Generic".to_string()),
        method: "signature".to_string(),
        engine_name: "TestEngine".to_string(),
        engine_version: Some("1.0.0".to_string()),
        engine_update: Some("20240101".to_string()),
    };

    assert_eq!(result.category, "malicious");
    assert_eq!(result.result, Some("Trojan.Generic".to_string()));
    assert_eq!(result.method, "signature");
    assert_eq!(result.engine_name, "TestEngine");
}

#[test]
fn test_base_attributes_default() {
    let attrs = BaseAttributes::default();
    assert!(attrs.last_analysis_date.is_none());
    assert!(attrs.last_analysis_stats.is_none());
    assert!(attrs.last_analysis_results.is_none());
    assert!(attrs.reputation.is_none());
    assert!(attrs.total_votes.is_none());
    assert!(attrs.tags.is_none());
}

#[test]
fn test_base_attributes_with_values() {
    let attrs = BaseAttributes {
        reputation: Some(100),
        tags: Some(vec!["test".to_string(), "sample".to_string()]),
        ..Default::default()
    };

    assert_eq!(attrs.reputation, Some(100));
    assert_eq!(
        attrs.tags,
        Some(vec!["test".to_string(), "sample".to_string()])
    );
}

#[test]
fn test_analysis_stats_clone() {
    let stats1 = AnalysisStats {
        harmless: 50,
        malicious: 2,
        suspicious: 1,
        undetected: 10,
        timeout: 0,
        confirmed_timeout: None,
        failure: None,
        type_unsupported: None,
    };

    let stats2 = stats1.clone();
    assert_eq!(stats1.harmless, stats2.harmless);
    assert_eq!(stats1.malicious, stats2.malicious);
}

#[test]
fn test_vote_stats_clone() {
    let votes1 = VoteStats {
        harmless: 100,
        malicious: 5,
    };

    let votes2 = votes1.clone();
    assert_eq!(votes1.harmless, votes2.harmless);
    assert_eq!(votes1.malicious, votes2.malicious);
}

#[test]
fn test_analysis_result_with_none_values() {
    let result = AnalysisResult {
        category: "undetected".to_string(),
        result: None,
        method: "none".to_string(),
        engine_name: "TestEngine".to_string(),
        engine_version: None,
        engine_update: None,
    };

    assert_eq!(result.category, "undetected");
    assert!(result.result.is_none());
    assert!(result.engine_version.is_none());
    assert!(result.engine_update.is_none());
}

#[test]
fn test_base_attributes_serialization() {
    let attrs = BaseAttributes {
        last_analysis_date: Some(1234567890),
        reputation: Some(50),
        tags: Some(vec!["test".to_string()]),
        ..Default::default()
    };

    // Test that it can be serialized
    let serialized = serde_json::to_string(&attrs);
    assert!(serialized.is_ok());

    // Test that None fields are skipped
    let json = serialized.unwrap();
    assert!(json.contains("\"last_analysis_date\":1234567890"));
    assert!(json.contains("\"reputation\":50"));
    assert!(!json.contains("\"last_analysis_stats\":null"));
}

#[test]
fn test_analysis_stats_total_calculation() {
    let stats = AnalysisStats {
        harmless: 50,
        malicious: 2,
        suspicious: 1,
        undetected: 10,
        timeout: 0,
        confirmed_timeout: Some(0),
        failure: Some(0),
        type_unsupported: Some(0),
    };

    let total = stats.harmless + stats.malicious + stats.suspicious + stats.undetected;
    assert_eq!(total, 63);
}
