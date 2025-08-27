//! Structured data display utilities
//!
//! This module provides functions for displaying structured data like JSON,
//! tables, and lists in formatted ways.

use serde_json::Value;
use std::collections::HashMap;

/// Pretty print JSON value with indentation
///
/// Formats JSON values for readable display.
///
/// # Arguments
///
/// * `value` - JSON value to format
///
/// # Returns
///
/// Formatted JSON string
///
/// # Examples
///
/// ```rust
/// use virustotal_rs::display::pretty_print_json;
/// use serde_json::json;
///
/// let data = json!({"name": "test", "value": 42});
/// let formatted = pretty_print_json(&data);
/// assert!(formatted.contains("\"name\""));
/// ```
pub fn pretty_print_json(value: &Value) -> String {
    serde_json::to_string_pretty(value).unwrap_or_else(|_| "Invalid JSON".to_string())
}

/// Format key-value pairs as a table
///
/// Creates a formatted table from key-value pairs.
///
/// # Arguments
///
/// * `data` - HashMap of key-value pairs
/// * `title` - Optional table title
///
/// # Returns
///
/// Formatted table string
///
/// # Examples
///
/// ```rust
/// use virustotal_rs::display::format_table;
/// use std::collections::HashMap;
///
/// let mut data = HashMap::new();
/// data.insert("Name".to_string(), "Example File".to_string());
/// data.insert("Size".to_string(), "1024 bytes".to_string());
///
/// let table = format_table(&data, Some("File Information"));
/// assert!(table.contains("Name"));
/// assert!(table.contains("Example File"));
/// ```
pub fn format_table(data: &HashMap<String, String>, title: Option<&str>) -> String {
    let mut result = String::new();

    if let Some(t) = title {
        result.push_str(&format!("{}\n", t));
        result.push_str(&format!("{}\n", "-".repeat(t.len())));
    }

    let max_key_len = data.keys().map(|k| k.len()).max().unwrap_or(0);

    for (key, value) in data {
        result.push_str(&format!(
            "{:width$} : {}\n",
            key,
            value,
            width = max_key_len
        ));
    }

    result.trim_end().to_string()
}

/// Format a list with bullets and indentation
///
/// Creates a formatted bulleted list.
///
/// # Arguments
///
/// * `items` - Vector of items to display
/// * `bullet` - Bullet character/string (default: "•")
/// * `indent` - Indentation string (default: "  ")
///
/// # Returns
///
/// Formatted list string
///
/// # Examples
///
/// ```rust
/// use virustotal_rs::display::format_list;
///
/// let items = vec!["First item".to_string(), "Second item".to_string()];
/// let list = format_list(&items, Some("•"), Some("  "));
/// assert!(list.contains("• First item"));
/// ```
pub fn format_list(items: &[String], bullet: Option<&str>, indent: Option<&str>) -> String {
    let bullet_char = bullet.unwrap_or("•");
    let indent_str = indent.unwrap_or("  ");

    items
        .iter()
        .map(|item| format!("{}{} {}", indent_str, bullet_char, item))
        .collect::<Vec<_>>()
        .join("\n")
}
