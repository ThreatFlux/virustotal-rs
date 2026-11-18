//! Hosted CI checks the shipped nested component rather than a root-only patch.

use sha2::{Digest, Sha256};
use std::path::Path;

fn sha256(raw: &[u8]) -> String {
    Sha256::digest(raw)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

#[test]
fn public_oauth_original_and_adapted_module_match_the_reviewed_inventory() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let notice = root.join("third_party/oauth2");
    let metadata: serde_json::Value =
        serde_json::from_slice(&std::fs::read(notice.join("SOURCE.json")).unwrap()).unwrap();
    let raw = std::fs::read(notice.join("oauth2-5.0.0.crate")).unwrap();
    assert_eq!(
        sha256(&raw),
        "51e219e79014df21a225b1860a479e2dcd7cbd9130f4defd4bd0e191ea31d67d"
    );
    for entry in metadata["source_files"].as_array().unwrap() {
        let path = root
            .join("src/mcp/oauth_protocol")
            .join(entry["path"].as_str().unwrap());
        let normalized = std::fs::read_to_string(path).unwrap().replace("\r\n", "\n");
        assert_eq!(
            sha256(normalized.as_bytes()),
            entry["owned_sha256_lf"].as_str().unwrap(),
            "nested component changed without updating its source inventory: {}",
            entry["path"]
        );
    }
    assert!(notice.join("LICENSE-MIT").is_file());
    assert!(notice.join("LICENSE-APACHE").is_file());
    assert!(!include_str!("../Cargo.lock").contains("\nname = \"chrono\"\n"));
}

#[test]
fn timestamp_display_preserves_utc_whole_seconds_and_rejects_extreme_inputs() {
    use virustotal_rs::display::format_timestamp;
    assert_eq!(format_timestamp(-1), "1969-12-31 23:59:59 UTC");
    assert_eq!(format_timestamp(0), "1970-01-01 00:00:00 UTC");
    assert_eq!(
        format_timestamp(i64::MAX),
        format!("Invalid timestamp: {}", i64::MAX)
    );
}
