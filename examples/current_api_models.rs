//! Decode current analysis and heterogeneous search payloads without an API key.
//! For HTTP requests use `client.analyses().get_report(id)` and
//! `client.search().intelligence_search_objects(...)`.

use serde_json::json;
use virustotal_rs::analysis::AnalysisReport;
use virustotal_rs::search::SearchPage;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let analysis: AnalysisReport = serde_json::from_value(json!({
        "type": "analysis", "id": "offline-analysis", "attributes": {
            "status": "in-progress", "stats": {}, "results": {
                "example-engine": {
                    "category": "undetected", "engine_name": "example-engine",
                    "method": "blacklist", "result": null
                }
            }
        }
    }))?;
    assert!(!analysis.is_completed());
    assert!(
        analysis.attributes.results.as_ref().unwrap()["example-engine"]
            .result
            .is_none()
    );

    let page: SearchPage = serde_json::from_value(json!({
        "data": [{"type": "domain", "id": "example.test", "attributes": {}}],
        "meta": {"days_back": 365, "cursor": "continuation"}
    }))?;
    assert_eq!(page.data[0].object_type, "domain");
    assert_eq!(page.meta.as_ref().unwrap()["days_back"], 365);
    println!("Current analysis and search payloads decoded successfully.");
    Ok(())
}
