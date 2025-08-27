//! URL encoding and query string utilities

use std::collections::HashMap;

/// Encode a path segment for URL safety
pub fn encode_path_segment(segment: &str) -> String {
    urlencoding::encode(segment).into_owned()
}

/// Build a query string from parameters
pub fn build_query_string(params: &HashMap<String, String>) -> String {
    if params.is_empty() {
        return String::new();
    }

    let mut pairs: Vec<_> = params.iter().collect();
    pairs.sort_by_key(|(k, _)| *k); // Sort for consistency

    pairs
        .into_iter()
        .map(|(k, v)| format!("{}={}", urlencoding::encode(k), urlencoding::encode(v)))
        .collect::<Vec<_>>()
        .join("&")
}
