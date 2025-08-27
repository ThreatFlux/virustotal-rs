//! Common utilities for VirusTotal examples
//!
//! This module provides reusable functions and utilities to eliminate code duplication
//! across example files. It includes API key handling, client creation, formatting
//! utilities, and common result handling patterns.

#![allow(dead_code)] // Utility functions may not be used in all examples

use std::env;
use tokio::time::{sleep, Duration};
use virustotal_rs::common::AnalysisStats;
use virustotal_rs::{ApiTier, Client, ClientUtils};

/// Type alias for commonly used Result type in examples
pub type ExampleResult<T> = Result<T, Box<dyn std::error::Error>>;

/// Sample file hash for testing purposes
#[allow(dead_code)]
pub const SAMPLE_FILE_HASH: &str =
    "02032ea322036e66f2825a0342979ad942ad5e201a674dc1c0085617467d661c";

/// Sample domain for testing purposes
#[allow(dead_code)]
pub const SAMPLE_DOMAIN: &str = "virustotal.com";

/// Sample IP address for testing purposes
#[allow(dead_code)]
pub const SAMPLE_IP: &str = "8.8.8.8";

/// Sample URL for testing purposes
#[allow(dead_code)]
pub const SAMPLE_URL: &str = "http://www.google.com";

/// API key environment variable names used across examples
#[allow(dead_code)]
pub const API_KEY_VARS: &[&str] = &[
    "VT_API_KEY",
    "VTI_API_KEY",
    "VT_PRIVATE_API_KEY",
    "VT_FEEDS_API_KEY",
    "VT_SANDBOX_API_KEY",
    "VIRUSTOTAL_API_KEY",
];

/// Get API key from environment variable with fallback options
///
/// This function tries multiple common environment variable names
/// and provides a default fallback for testing.
///
/// # Arguments
///
/// * `primary_var` - Primary environment variable to check
///
/// # Returns
///
/// Returns the API key string, or "test_key" as fallback
///
/// # Examples
///
/// ```rust
/// use common::get_api_key;
/// let api_key = get_api_key("VT_API_KEY");
/// ```
#[allow(dead_code)]
pub fn get_api_key(primary_var: &str) -> String {
    env::var(primary_var)
        .or_else(|_| env::var("VT_API_KEY"))
        .or_else(|_| env::var("VTI_API_KEY"))
        .unwrap_or_else(|_| {
            println!("⚠️  Warning: Using fallback API key 'test_key'. Set {} environment variable for actual testing.", primary_var);
            "test_key".to_string()
        })
}

/// Get API key with panic on missing variable (for strict examples)
///
/// Use this when you want the example to fail if no proper API key is provided.
///
/// # Arguments
///
/// * `var_name` - Environment variable name
///
/// # Returns
///
/// Returns the API key string
///
/// # Panics
///
/// Panics if the environment variable is not set
///
/// # Examples
///
/// ```rust
/// use common::get_api_key_strict;
/// let api_key = get_api_key_strict("VTI_API_KEY");
/// ```
#[allow(dead_code)]
pub fn get_api_key_strict(var_name: &str) -> String {
    env::var(var_name).unwrap_or_else(|_| panic!("{} environment variable not set", var_name))
}

/// Get API key with multiple fallback options for private APIs
///
/// Tries private API key first, then falls back to regular API key,
/// then to test key.
///
/// # Arguments
///
/// * `private_var` - Private API key environment variable
///
/// # Returns
///
/// Returns the API key string
///
/// # Examples
///
/// ```rust
/// use common::get_private_api_key;
/// let api_key = get_private_api_key("VT_PRIVATE_API_KEY");
/// ```
#[allow(dead_code)]
pub fn get_private_api_key(private_var: &str) -> String {
    env::var(private_var)
        .or_else(|_| env::var("VT_API_KEY"))
        .or_else(|_| env::var("VTI_API_KEY"))
        .unwrap_or_else(|_| {
            println!(
                "⚠️  Warning: Using fallback API key 'test_key'. Set {} for private API access.",
                private_var
            );
            "test_key".to_string()
        })
}

/// Create a VirusTotal client with standard configuration
///
/// Creates a client using the provided API key and tier with standard settings.
/// Now uses the enhanced ClientUtils for better configuration and functionality.
///
/// # Arguments
///
/// * `api_key` - API key string
/// * `tier` - API tier (Public or Premium)
///
/// # Returns
///
/// Returns a configured Client instance
///
/// # Examples
///
/// ```rust
/// use common::{get_api_key, create_client};
/// use virustotal_rs::ApiTier;
///
/// let api_key = get_api_key("VT_API_KEY");
/// let client = create_client(api_key, ApiTier::Public)?;
/// ```
pub fn create_client(api_key: String, tier: ApiTier) -> ExampleResult<Client> {
    // Use enhanced client utilities for better functionality
    let client = ClientUtils::builder()
        .api_key(api_key)
        .tier(tier)
        .timeout(std::time::Duration::from_secs(30))
        .retry_config(3, std::time::Duration::from_millis(1000))
        .build()?;
    Ok(client)
}

/// Create a VirusTotal client from environment variable
///
/// Combines API key retrieval and client creation in one step.
/// Now leverages the enhanced ClientUtils for environment variable handling.
///
/// # Arguments
///
/// * `var_name` - Environment variable name
/// * `tier` - API tier
///
/// # Returns
///
/// Returns a configured Client instance
///
/// # Examples
///
/// ```rust
/// use common::create_client_from_env;
/// use virustotal_rs::ApiTier;
///
/// let client = create_client_from_env("VT_API_KEY", ApiTier::Public)?;
/// ```
#[allow(dead_code)]
pub fn create_client_from_env(var_name: &str, tier: ApiTier) -> ExampleResult<Client> {
    // Try to use enhanced client utils first, with fallback to legacy approach
    match ClientUtils::from_env(var_name) {
        Ok(builder) => {
            println!("Using API key from {} environment variable", var_name);
            let client = builder
                .tier(tier)
                .timeout(std::time::Duration::from_secs(30))
                .retry_config(3, std::time::Duration::from_millis(1000))
                .build()?;
            Ok(client)
        }
        Err(_) => {
            // Fallback to legacy approach for backward compatibility
            println!("⚠️  Falling back to legacy client creation");
            let api_key = get_api_key(var_name);
            println!("Using API key from {} environment variable", var_name);
            create_client(api_key, tier)
        }
    }
}

/// Legacy function for backward compatibility
///
/// Maintains compatibility with existing code that uses build_client_from_env.
///
/// # Arguments
///
/// * `var` - Environment variable name
/// * `tier` - API tier
///
/// # Returns
///
/// Returns a configured Client instance
#[allow(dead_code)]
pub fn build_client_from_env(
    var: &str,
    tier: ApiTier,
) -> Result<Client, Box<dyn std::error::Error>> {
    create_client_from_env(var, tier)
}

/// Print a formatted section header
///
/// Prints a header with a title surrounded by equals signs for visual separation.
///
/// # Arguments
///
/// * `title` - Section title to display
/// * `width` - Width of the header line (default: 60)
///
/// # Examples
///
/// ```rust
/// use common::print_section_header;
///
/// print_section_header("Testing File API", 60);
/// ```
#[allow(dead_code)]
pub fn print_section_header(title: &str, width: usize) {
    println!("\n{}", "=".repeat(width));
    println!("{}", title);
    println!("{}", "=".repeat(width));
}

/// Print a test section header with step number
#[allow(dead_code)]
pub fn print_step_header(step: u8, title: &str) {
    println!("\n{}. {}", step, title);
    println!("{}", "-".repeat(title.len() + 4));
}

/// Simple function to create a client
#[allow(dead_code)]
pub fn setup_client(
    tier: virustotal_rs::ApiTier,
) -> Result<virustotal_rs::Client, Box<dyn std::error::Error>> {
    let api_key = std::env::var("VT_PRIVATE_API_KEY")
        .or_else(|_| std::env::var("VT_API_KEY"))
        .unwrap_or_else(|_| "test_key".to_string());

    Ok(virustotal_rs::ClientBuilder::new()
        .api_key(api_key)
        .tier(tier)
        .build()?)
}

/// Print a formatted section header with default width
///
/// Convenience function that uses a default width of 60 characters.
///
/// # Arguments
///
/// * `title` - Section title to display
///
/// # Examples
///
/// ```rust
/// use common::print_header;
///
/// print_header("Testing File API");
/// ```
#[allow(dead_code)]
pub fn print_header(title: &str) {
    print_section_header(title, 60);
}

/// Print a formatted test header
///
/// Prints a smaller test header for individual test sections.
///
/// # Arguments
///
/// * `test_name` - Name of the test
///
/// # Examples
///
/// ```rust
/// use common::print_test_header;
///
/// print_test_header("Getting file comments");
/// ```
pub fn print_test_header(test_name: &str) {
    println!("\n=== {} ===", test_name);
}

/// Handle and display API results in a consistent way
///
/// Generic function to handle API results with consistent success/error messaging.
///
/// # Arguments
///
/// * `result` - The Result to handle
/// * `success_msg` - Message to display on success
/// * `error_msg` - Message prefix to display on error
///
/// # Returns
///
/// Returns the inner value on success, or None on error
///
/// # Examples
///
/// ```rust
/// use common::handle_result;
///
/// let file_result = client.files().get("hash").await;
/// if let Some(file) = handle_result(file_result, "File retrieved", "Failed to get file") {
///     println!("File: {:?}", file.object.attributes.type_description);
/// }
/// ```
pub fn handle_result<T, E: std::fmt::Display>(
    result: Result<T, E>,
    success_msg: &str,
    error_msg: &str,
) -> Option<T> {
    match result {
        Ok(value) => {
            println!("✓ {}", success_msg);
            Some(value)
        }
        Err(e) => {
            println!("✗ {}: {}", error_msg, e);
            None
        }
    }
}

/// Handle and display API results with custom success handler
///
/// Generic function that allows custom processing of successful results.
///
/// # Arguments
///
/// * `result` - The Result to handle
/// * `success_handler` - Closure to handle successful results
/// * `error_msg` - Message prefix to display on error
///
/// # Examples
///
/// ```rust
/// use common::handle_result_with;
///
/// let file_result = client.files().get("hash").await;
/// handle_result_with(
///     file_result,
///     |file| println!("Retrieved file with {} bytes", file.object.attributes.size.unwrap_or(0)),
///     "Failed to get file"
/// );
/// ```
pub fn handle_result_with<T, E: std::fmt::Display, F>(
    result: Result<T, E>,
    success_handler: F,
    error_msg: &str,
) where
    F: FnOnce(T),
{
    match result {
        Ok(value) => success_handler(value),
        Err(e) => println!("✗ {}: {}", error_msg, e),
    }
}

/// Wait for rate limiting with a standardized delay
///
/// Implements a standard rate limiting delay for public API usage.
/// Uses 15 seconds as the standard delay between requests.
///
/// # Arguments
///
/// * `seconds` - Number of seconds to wait (optional, defaults to 15)
///
/// # Examples
///
/// ```rust
/// use common::rate_limit_wait;
///
/// // Wait with default 15 second delay
/// rate_limit_wait(None).await;
///
/// // Wait with custom delay
/// rate_limit_wait(Some(30)).await;
/// ```
pub async fn rate_limit_wait(seconds: Option<u64>) {
    let delay = seconds.unwrap_or(15);
    println!("⏱️  Waiting {} seconds to respect rate limit...", delay);
    sleep(Duration::from_secs(delay)).await;
}

/// Wait for rate limiting with progress indication
///
/// Shows a countdown while waiting for rate limiting.
///
/// # Arguments
///
/// * `seconds` - Number of seconds to wait
///
/// # Examples
///
/// ```rust
/// use common::rate_limit_wait_with_progress;
///
/// rate_limit_wait_with_progress(15).await;
/// ```
pub async fn rate_limit_wait_with_progress(seconds: u64) {
    println!("⏱️  Rate limiting: waiting {} seconds...", seconds);
    for i in (1..=seconds).rev() {
        if i % 5 == 0 || i <= 3 {
            println!("  {} seconds remaining...", i);
        }
        sleep(Duration::from_secs(1)).await;
    }
    println!("  ✓ Rate limit wait complete");
}

/// Truncate a string to a maximum length with ellipsis
///
/// Truncates long strings for display purposes, adding "..." if truncated.
/// This function now uses the display utilities from the main library.
///
/// # Arguments
///
/// * `s` - String to truncate
/// * `max_len` - Maximum length before truncation
///
/// # Returns
///
/// Returns the truncated string
///
/// # Examples
///
/// ```rust
/// use common::truncate_string;
///
/// let long_text = "This is a very long comment that should be truncated";
/// let short = truncate_string(&long_text, 20);
/// println!("Truncated: {}", short);
/// ```
pub fn truncate_string(s: &str, max_len: usize) -> String {
    virustotal_rs::truncate_text(s, max_len)
}

/// Truncate a string for comment display (100 chars default)
///
/// Convenience function for truncating comments with a standard length.
///
/// # Arguments
///
/// * `comment` - Comment text to truncate
///
/// # Returns
///
/// Returns the truncated comment
///
/// # Examples
///
/// ```rust
/// use common::truncate_comment;
///
/// let comment = "This is a long comment that should be shortened for display";
/// let short = truncate_comment(&comment);
/// ```
pub fn truncate_comment(comment: &str) -> String {
    truncate_string(comment, 100)
}

/// Print analysis statistics in a formatted way
///
/// Displays VirusTotal analysis statistics with consistent formatting.
/// This function now uses the display utilities from the main library.
///
/// # Arguments
///
/// * `label` - Label to display for the statistics
/// * `stats` - AnalysisStats to display
///
/// # Examples
///
/// ```rust
/// use common::print_analysis_stats;
///
/// if let Some(stats) = &file.object.attributes.last_analysis_stats {
///     print_analysis_stats("Last Analysis Stats", stats);
/// }
/// ```
pub fn print_analysis_stats(label: &str, stats: &AnalysisStats) {
    use virustotal_rs::DisplayStats;
    println!("\n  {}:", label);
    let formatted = stats.display_formatted("    ", false);
    println!("{}", formatted);
}

/// Print analysis statistics with detection summary
///
/// Enhanced version that also shows detection percentages and summary.
/// This function now uses the display utilities from the main library.
///
/// # Arguments
///
/// * `label` - Label to display for the statistics
/// * `stats` - AnalysisStats to display
///
/// # Examples
///
/// ```rust
/// use common::print_analysis_stats_detailed;
///
/// if let Some(stats) = &file.object.attributes.last_analysis_stats {
///     print_analysis_stats_detailed("Security Analysis", stats);
/// }
/// ```
pub fn print_analysis_stats_detailed(label: &str, stats: &AnalysisStats) {
    use virustotal_rs::DisplayStats;
    println!("\n🛡️  {}", label);
    let detailed = stats.display_detailed();
    println!("{}", detailed);
}

/// Print vote statistics
///
/// Displays voting statistics in a consistent format.
/// This function now uses the display utilities from the main library.
///
/// # Arguments
///
/// * `label` - Label for the votes (e.g., "Total Votes")
/// * `harmless` - Number of harmless votes
/// * `malicious` - Number of malicious votes
///
/// # Examples
///
/// ```rust
/// use common::print_vote_stats;
///
/// if let Some(votes) = &file.object.attributes.total_votes {
///     print_vote_stats("Community Votes", votes.harmless, votes.malicious);
/// }
/// ```
pub fn print_vote_stats(label: &str, harmless: i32, malicious: i32) {
    use virustotal_rs::{common::VoteStats, DisplayVotes};
    let votes = VoteStats {
        harmless: harmless as u32,
        malicious: malicious as u32,
    };
    println!("  {}: {}", label, votes.display_summary());
}

/// Format file size in human-readable format
///
/// Converts byte sizes to human-readable format (B, KB, MB, GB).
/// This function now uses the display utilities from the main library.
///
/// # Arguments
///
/// * `bytes` - Size in bytes
///
/// # Returns
///
/// Returns formatted string with appropriate unit
///
/// # Examples
///
/// ```rust
/// use common::format_file_size;
///
/// println!("File size: {}", format_file_size(1024000));
/// // Output: "File size: 1000.0 KB"
/// ```
pub fn format_file_size(bytes: u64) -> String {
    virustotal_rs::format_file_size(bytes)
}

/// Print a simple separator line
///
/// Prints a line of dashes for visual separation.
///
/// # Arguments
///
/// * `width` - Width of the separator (optional, defaults to 40)
///
/// # Examples
///
/// ```rust
/// use common::print_separator;
///
/// print_separator(Some(80));
/// print_separator(None); // Uses default width of 40
/// ```
pub fn print_separator(width: Option<usize>) {
    let w = width.unwrap_or(40);
    println!("{}", "-".repeat(w));
}

/// Print success message with checkmark
///
/// Prints a success message with a green checkmark (✓).
///
/// # Arguments
///
/// * `message` - Success message to display
///
/// # Examples
///
/// ```rust
/// use common::print_success;
///
/// print_success("File uploaded successfully");
/// ```
pub fn print_success(message: &str) {
    println!("✓ {}", message);
}

/// Print error message with X mark
///
/// Prints an error message with a red X mark (✗).
///
/// # Arguments
///
/// * `message` - Error message to display
///
/// # Examples
///
/// ```rust
/// use common::print_error;
///
/// print_error("Failed to upload file");
/// ```
pub fn print_error(message: &str) {
    println!("✗ {}", message);
}

/// Print warning message with warning symbol
///
/// Prints a warning message with a warning symbol (⚠️).
///
/// # Arguments
///
/// * `message` - Warning message to display
///
/// # Examples
///
/// ```rust
/// use common::print_warning;
///
/// print_warning("API key not found, using test key");
/// ```
pub fn print_warning(message: &str) {
    println!("⚠️  {}", message);
}

/// Print info message with info symbol
///
/// Prints an informational message with an info symbol (ℹ️).
///
/// # Arguments
///
/// * `message` - Info message to display
///
/// # Examples
///
/// ```rust
/// use common::print_info;
///
/// print_info("This is an informational message");
/// ```
pub fn print_info(message: &str) {
    println!("ℹ️  {}", message);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_truncate_string() {
        assert_eq!(truncate_string("short", 10), "short");
        assert_eq!(truncate_string("this is a long string", 10), "this is...");
        assert_eq!(truncate_string("exactly10c", 10), "exactly10c");
        assert_eq!(truncate_string("", 10), "");
    }

    #[test]
    fn test_truncate_comment() {
        let long_comment = "a".repeat(150);
        let truncated = truncate_comment(&long_comment);
        assert!(truncated.len() <= 100);
        assert!(truncated.ends_with("..."));
    }

    #[test]
    fn test_format_file_size() {
        assert_eq!(format_file_size(0), "0 B");
        assert_eq!(format_file_size(1023), "1023 B");
        assert_eq!(format_file_size(1024), "1.0 KB");
        assert_eq!(format_file_size(1048576), "1.0 MB");
        assert_eq!(format_file_size(1073741824), "1.0 GB");
    }

    #[test]
    fn test_constants() {
        assert!(!SAMPLE_FILE_HASH.is_empty());
        assert!(!SAMPLE_DOMAIN.is_empty());
        assert!(!SAMPLE_IP.is_empty());
        assert!(!SAMPLE_URL.is_empty());
        assert!(!API_KEY_VARS.is_empty());
    }
}
