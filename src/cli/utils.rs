use crate::{ApiKey, ApiTier, Client, Error as VtError};
use anyhow::{Context, Result};
use indicatif::{ProgressBar, ProgressStyle};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::fs;
use std::io::{self, Write};
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[derive(Debug, Deserialize, Serialize)]
pub struct VtExportEntity {
    pub entity_id: String,
    pub entity_type: String,
    pub notification_date: Option<u64>,
    pub origin: Option<String>,
    pub sources: Option<Vec<VtExportSource>>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct VtExportSource {
    pub id: Option<String>,
    #[serde(rename = "type")]
    pub source_type: Option<String>,
    pub label: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct VtExportFile {
    pub data: Vec<VtExportEntity>,
}

pub struct ProgressTracker {
    pub bar: ProgressBar,
    pub start_time: SystemTime,
}

impl ProgressTracker {
    pub fn new(total: u64, message: &str) -> Self {
        let bar = ProgressBar::new(total);
        bar.set_style(
            ProgressStyle::default_bar()
                .template("{spinner:.green} [{elapsed_precise}] [{wide_bar:.cyan/blue}] {pos}/{len} ({eta}) {msg}")
                .unwrap_or_else(|_| ProgressStyle::default_bar())
                .progress_chars("#>-"),
        );
        bar.set_message(message.to_string());

        Self {
            bar,
            start_time: SystemTime::now(),
        }
    }

    pub fn inc(&self, delta: u64) {
        self.bar.inc(delta);
    }

    pub fn set_message(&self, msg: &str) {
        self.bar.set_message(msg.to_string());
    }

    pub fn finish_with_message(&self, msg: &str) {
        self.bar.finish_with_message(msg.to_string());
    }

    pub fn elapsed(&self) -> Duration {
        self.start_time.elapsed().unwrap_or(Duration::from_secs(0))
    }
}

pub fn setup_client(api_key: Option<String>, tier: &str) -> Result<Client> {
    let api_key_str = api_key
        .or_else(|| std::env::var("VTI_API_KEY").ok())
        .context("API key required: use --api-key or set VTI_API_KEY environment variable")?;

    let api_key = ApiKey::new(api_key_str);
    let api_tier = match tier.to_lowercase().as_str() {
        "premium" | "private" => ApiTier::Premium,
        _ => ApiTier::Public,
    };

    Client::new(api_key, api_tier).context("Failed to create VirusTotal client")
}

pub fn read_hashes_from_file<P: AsRef<Path>>(path: P) -> Result<Vec<String>> {
    let content = fs::read_to_string(&path)
        .with_context(|| format!("Failed to read file: {}", path.as_ref().display()))?;

    let hashes: Vec<String> = content
        .lines()
        .map(|line| line.trim())
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .map(String::from)
        .collect();

    if hashes.is_empty() {
        return Err(anyhow::anyhow!(
            "No valid hashes found in {}",
            path.as_ref().display()
        ));
    }

    Ok(hashes)
}

pub fn read_hashes_from_json_export<P: AsRef<Path>>(path: P) -> Result<Vec<String>> {
    let content = fs::read_to_string(&path)
        .with_context(|| format!("Failed to read JSON file: {}", path.as_ref().display()))?;

    let export_file: VtExportFile = serde_json::from_str(&content).with_context(|| {
        format!(
            "Failed to parse JSON export file: {}",
            path.as_ref().display()
        )
    })?;

    let mut hashes = Vec::new();
    let mut invalid_count = 0;

    for entity in export_file.data {
        // Filter for file entities only
        if entity.entity_type != "file" {
            continue;
        }

        // Validate the hash format
        if validate_hash(&entity.entity_id).is_err() {
            invalid_count += 1;
            continue;
        }

        hashes.push(entity.entity_id);
    }

    if hashes.is_empty() {
        return Err(anyhow::anyhow!(
            "No valid file hashes found in JSON export file: {}",
            path.as_ref().display()
        ));
    }

    if invalid_count > 0 {
        eprintln!(
            "Warning: Skipped {} invalid hashes from JSON export file",
            invalid_count
        );
    }

    Ok(hashes)
}

/// Check if the filename represents a single hash
fn is_single_hash_filename(filename: &str) -> bool {
    (filename.len() == 32 || filename.len() == 40 || filename.len() == 64)
        && filename.chars().all(|c| c.is_ascii_hexdigit())
}

/// Detect input type based on file extension
fn detect_type_by_extension(path: &Path) -> Option<InputType> {
    let extension = path.extension()?.to_string_lossy().to_lowercase();
    match extension.as_str() {
        "json" => Some(InputType::JsonExport),
        "txt" | "list" => Some(InputType::TextFile),
        _ => None,
    }
}

/// Detect input type by analyzing file content
fn detect_type_by_content(path: &Path) -> Result<InputType> {
    let content = fs::read_to_string(path)
        .with_context(|| format!("Failed to read file for type detection: {}", path.display()))?;

    let content_trimmed = content.trim();

    // Check if it looks like JSON
    if (content_trimmed.starts_with('{') || content_trimmed.starts_with('['))
        && serde_json::from_str::<Value>(content_trimmed).is_ok()
    {
        return Ok(InputType::JsonExport);
    }

    // Default to text file for existing files
    Ok(InputType::TextFile)
}

pub fn detect_input_type<P: AsRef<Path>>(path: P) -> Result<InputType> {
    let path_ref = path.as_ref();

    // Check if it's a single hash (32, 40, or 64 hex characters)
    if let Some(filename) = path_ref.file_name() {
        let filename_str = filename.to_string_lossy();
        if is_single_hash_filename(&filename_str) {
            return Ok(InputType::SingleHash);
        }
    }

    // Check file extension
    if let Some(input_type) = detect_type_by_extension(path_ref) {
        return Ok(input_type);
    }

    // If no extension or unknown extension, try to detect by content
    if path_ref.exists() {
        return detect_type_by_content(path_ref);
    }

    // Default to single hash if it doesn't exist (might be a hash string)
    Ok(InputType::SingleHash)
}

#[derive(Debug, Clone, PartialEq)]
pub enum InputType {
    SingleHash,
    TextFile,
    JsonExport,
}

pub fn validate_hash(hash: &str) -> Result<()> {
    let hash = hash.trim();

    // Check common hash lengths
    match hash.len() {
        32 => {
            // MD5
            if !hash.chars().all(|c| c.is_ascii_hexdigit()) {
                return Err(anyhow::anyhow!("Invalid MD5 hash format: {}", hash));
            }
        }
        40 => {
            // SHA1
            if !hash.chars().all(|c| c.is_ascii_hexdigit()) {
                return Err(anyhow::anyhow!("Invalid SHA1 hash format: {}", hash));
            }
        }
        64 => {
            // SHA256
            if !hash.chars().all(|c| c.is_ascii_hexdigit()) {
                return Err(anyhow::anyhow!("Invalid SHA256 hash format: {}", hash));
            }
        }
        _ => {
            return Err(anyhow::anyhow!(
                "Invalid hash length: {} (expected 32, 40, or 64 characters)",
                hash.len()
            ));
        }
    }

    Ok(())
}

pub fn format_file_size(bytes: u64) -> String {
    const UNITS: &[&str] = &["B", "KB", "MB", "GB", "TB"];
    let mut size = bytes as f64;
    let mut unit_index = 0;

    while size >= 1024.0 && unit_index < UNITS.len() - 1 {
        size /= 1024.0;
        unit_index += 1;
    }

    if unit_index == 0 {
        format!("{} {}", size as u64, UNITS[unit_index])
    } else {
        format!("{:.1} {}", size, UNITS[unit_index])
    }
}

pub fn format_timestamp(timestamp: Option<u64>) -> String {
    match timestamp {
        Some(ts) => {
            let time = UNIX_EPOCH + Duration::from_secs(ts);
            match time.duration_since(UNIX_EPOCH) {
                Ok(_) => {
                    // Simple formatting - in a real implementation you might want chrono
                    format!("{}", ts) // Just show the timestamp for now
                }
                Err(_) => "Invalid timestamp".to_string(),
            }
        }
        None => "Unknown".to_string(),
    }
}

pub fn truncate_hash(hash: &str, len: usize) -> String {
    if hash.len() <= len {
        hash.to_string()
    } else {
        format!("{}...", &hash[..len])
    }
}

pub fn print_json(value: &Value, pretty: bool) -> Result<()> {
    let output = if pretty {
        serde_json::to_string_pretty(value)?
    } else {
        serde_json::to_string(value)?
    };
    println!("{}", output);
    Ok(())
}

pub fn print_table_row(columns: &[&str], widths: &[usize]) {
    for (i, (col, width)) in columns.iter().zip(widths).enumerate() {
        if i > 0 {
            print!(" | ");
        }
        print!("{:<width$}", col, width = width);
    }
    println!();
}

pub fn print_table_separator(widths: &[usize]) {
    for (i, width) in widths.iter().enumerate() {
        if i > 0 {
            print!("-+-");
        }
        print!("{}", "-".repeat(*width));
    }
    println!();
}

/// Handle HTTP status code errors
fn handle_http_status_error(status_code: u16) -> String {
    match status_code {
        401 => "Authentication failed - check your API key".to_string(),
        403 => "Access forbidden - check your API tier permissions".to_string(),
        404 => "Resource not found".to_string(),
        429 => "Rate limit exceeded - please wait and try again".to_string(),
        500..=599 => "Server error - please try again later".to_string(),
        _ => format!("HTTP error: {}", status_code),
    }
}

/// Handle network-level HTTP errors (no status code)
fn handle_network_error(error_str: &str) -> String {
    if error_str.contains("timeout") {
        "Network timeout - try again later".to_string()
    } else if error_str.contains("connection") {
        "Network connection error - check your internet connection".to_string()
    } else if error_str.contains("decode") {
        format!(
            "Network error: error decoding response body - {}",
            error_str
        )
    } else {
        format!("Network error: {}", error_str)
    }
}

/// Handle JSON parsing errors
fn handle_json_error(json_error_str: &str) -> String {
    let truncated_error = json_error_str.chars().take(100).collect::<String>();

    if json_error_str.contains("EOF while parsing") {
        "Failed to parse response from VirusTotal (incomplete response)".to_string()
    } else if json_error_str.contains("expected") {
        format!(
            "Failed to parse response from VirusTotal (unexpected format): {}",
            truncated_error
        )
    } else {
        format!(
            "Failed to parse response from VirusTotal: {}",
            truncated_error
        )
    }
}

/// Handle unknown/generic errors
fn handle_unknown_error(msg: &str) -> String {
    if msg.contains("HTML response") {
        "VirusTotal returned HTML instead of JSON (possible rate limiting or maintenance)"
            .to_string()
    } else if msg.contains("Empty response") {
        "VirusTotal returned empty response (possible rate limiting)".to_string()
    } else {
        format!("Unknown error: {}", msg)
    }
}

pub fn handle_vt_error(error: &VtError) -> String {
    match error {
        VtError::Http(http_error) => {
            if let Some(status) = http_error.status() {
                handle_http_status_error(status.as_u16())
            } else {
                handle_network_error(&http_error.to_string())
            }
        }
        VtError::Json(json_err) => handle_json_error(&json_err.to_string()),
        VtError::RateLimit(_) => "Rate limit exceeded".to_string(),
        VtError::TooManyRequests => "Rate limit exceeded - please wait and try again".to_string(),
        VtError::NotFound => "Resource not found".to_string(),
        VtError::AuthenticationRequired => "Authentication failed - check your API key".to_string(),
        VtError::Forbidden => "Access forbidden - check your API tier permissions".to_string(),
        VtError::DeadlineExceeded => "Request timed out".to_string(),
        VtError::Unknown(msg) => handle_unknown_error(msg),
        _ => error.to_string(),
    }
}

pub fn confirm_action(message: &str) -> Result<bool> {
    print!("{} (y/N): ", message);
    io::stdout().flush()?;

    let mut input = String::new();
    io::stdin().read_line(&mut input)?;

    Ok(matches!(input.trim().to_lowercase().as_str(), "y" | "yes"))
}

/// Extract a u32 value from a JSON field, returning None if missing or invalid
fn extract_stat_value(stats: &Value, field: &str) -> Option<u32> {
    stats.get(field)?.as_u64().map(|v| v as u32)
}

/// Calculate total and detected counts from individual stat values
fn calculate_detection_counts(
    malicious: u32,
    suspicious: u32,
    harmless: u32,
    undetected: u32,
) -> (u32, u32) {
    let total = malicious + suspicious + harmless + undetected;
    let detected = malicious + suspicious;
    (detected, total)
}

pub fn get_detection_ratio(stats: &Value) -> Option<(u32, u32)> {
    let malicious = extract_stat_value(stats, "malicious")?;
    let suspicious = extract_stat_value(stats, "suspicious")?;
    let harmless = extract_stat_value(stats, "harmless")?;
    let undetected = extract_stat_value(stats, "undetected")?;

    let (detected, total) = calculate_detection_counts(malicious, suspicious, harmless, undetected);
    Some((detected, total))
}

pub fn format_detection_ratio(detected: u32, total: u32) -> String {
    if total == 0 {
        "0/0".to_string()
    } else {
        let percentage = (detected as f64 / total as f64) * 100.0;
        format!("{}/{} ({:.1}%)", detected, total, percentage)
    }
}

pub fn colorize_text(text: &str, color: &str, enabled: bool) -> String {
    if !enabled {
        return text.to_string();
    }

    match color {
        "red" => format!("\x1b[31m{}\x1b[0m", text),
        "green" => format!("\x1b[32m{}\x1b[0m", text),
        "yellow" => format!("\x1b[33m{}\x1b[0m", text),
        "blue" => format!("\x1b[34m{}\x1b[0m", text),
        "magenta" => format!("\x1b[35m{}\x1b[0m", text),
        "cyan" => format!("\x1b[36m{}\x1b[0m", text),
        "white" => format!("\x1b[37m{}\x1b[0m", text),
        "bold" => format!("\x1b[1m{}\x1b[0m", text),
        "dim" => format!("\x1b[2m{}\x1b[0m", text),
        _ => text.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_hash() {
        // Valid hashes
        assert!(validate_hash("5d41402abc4b2a76b9719d911017c592").is_ok()); // MD5
        assert!(validate_hash("356a192b7913b04c54574d18c28d46e6395428ab").is_ok()); // SHA1
        assert!(
            validate_hash("2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae")
                .is_ok()
        ); // SHA256

        // Invalid hashes
        assert!(validate_hash("invalid").is_err());
        assert!(validate_hash("5d41402abc4b2a76b9719d911017c59g").is_err()); // Invalid hex
        assert!(validate_hash("5d41402abc4b2a76b9719d911017c5").is_err()); // Too short
    }

    #[test]
    fn test_format_file_size() {
        assert_eq!(format_file_size(0), "0 B");
        assert_eq!(format_file_size(1024), "1.0 KB");
        assert_eq!(format_file_size(1536), "1.5 KB");
        assert_eq!(format_file_size(1048576), "1.0 MB");
    }

    #[test]
    fn test_truncate_hash() {
        let hash = "2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae";
        assert_eq!(truncate_hash(hash, 16), "2c26b46b68ffc68f...");
        assert_eq!(truncate_hash("short", 10), "short");
    }

    #[test]
    fn test_input_type_detection() {
        use std::path::Path;

        // Single hash detection
        assert_eq!(
            detect_input_type("5d41402abc4b2a76b9719d911017c592").unwrap(),
            InputType::SingleHash
        );

        // File extension detection
        assert_eq!(
            detect_input_type(Path::new("test.json")).unwrap(),
            InputType::JsonExport
        );
        assert_eq!(
            detect_input_type(Path::new("hashes.txt")).unwrap(),
            InputType::TextFile
        );
    }
}
