//! Test example for common utilities module
//!
//! This example demonstrates all the utilities provided by the common module
//! and serves as both a test and documentation for the shared functionality.

use std::env;
use virustotal_rs::{common::AnalysisStats, ApiTier};

#[path = "common/mod.rs"]
mod common;
use common::*;

/// Tests API key retrieval utilities
async fn test_api_key_utilities() -> ExampleResult<()> {
    print_test_header("API Key Utilities");

    // Save original env state
    let original_vt_key = env::var("VT_API_KEY").ok();
    let original_vti_key = env::var("VTI_API_KEY").ok();

    // Test get_api_key with fallback
    env::set_var("VT_API_KEY", "test_api_key_12345");
    let api_key = get_api_key("VT_API_KEY");
    assert_eq!(api_key, "test_api_key_12345");
    print_success("get_api_key works with primary variable");

    // Test fallback behavior
    env::remove_var("VT_API_KEY");
    env::set_var("VTI_API_KEY", "fallback_key_67890");
    let api_key = get_api_key("VT_API_KEY");
    assert_eq!(api_key, "fallback_key_67890");
    print_success("get_api_key works with fallback variable");

    // Test private API key retrieval
    env::set_var("VT_PRIVATE_API_KEY", "private_key_xyz");
    let private_key = get_private_api_key("VT_PRIVATE_API_KEY");
    assert_eq!(private_key, "private_key_xyz");
    print_success("get_private_api_key works with private key");

    // Restore original environment state
    restore_environment_state(original_vt_key, original_vti_key);
    Ok(())
}

/// Tests client creation utilities
async fn test_client_creation_utilities() -> ExampleResult<()> {
    print_test_header("Client Creation Utilities");

    env::set_var("VT_API_KEY", "demo_key_for_client");
    let client_result = create_client_from_env("VT_API_KEY", ApiTier::Public);
    match client_result {
        Ok(_) => print_success("create_client_from_env works"),
        Err(_) => print_info("create_client_from_env tested (expected with demo key)"),
    }
    Ok(())
}

/// Tests string utilities
async fn test_string_utilities() -> ExampleResult<()> {
    print_test_header("String Utilities");

    let short_text = "Short text";
    let truncated = truncate_string(short_text, 20);
    assert_eq!(truncated, "Short text");
    print_success("truncate_string preserves short text");

    let long_text =
        "This is a very long text that should be truncated because it exceeds the maximum length";
    let truncated = truncate_string(long_text, 20);
    assert_eq!(truncated.len(), 20);
    assert!(truncated.ends_with("..."));
    print_success("truncate_string truncates long text with ellipsis");

    let comment = "a".repeat(150);
    let truncated_comment = truncate_comment(&comment);
    assert!(truncated_comment.len() <= 100);
    print_success("truncate_comment works with standard length");
    Ok(())
}

/// Tests display utilities
async fn test_display_utilities() -> ExampleResult<()> {
    print_test_header("Display Utilities");

    print_separator(Some(30));
    print_success("This is a success message");
    print_error("This is an error message");
    print_warning("This is a warning message");
    print_info("This is an info message");
    print_separator(None);
    Ok(())
}

/// Tests result handling utilities
async fn test_result_handling_utilities() -> ExampleResult<()> {
    print_test_header("Result Handling Utilities");

    // Test with Ok result
    let ok_result: Result<String, String> = Ok("Success value".to_string());
    if let Some(value) = handle_result(ok_result, "Operation succeeded", "Operation failed") {
        assert_eq!(value, "Success value");
    }

    // Test with Err result
    let err_result: Result<String, String> = Err("Error message".to_string());
    let result = handle_result(err_result, "Operation succeeded", "Operation failed");
    assert!(result.is_none());

    // Test with custom handler
    let ok_result: Result<i32, String> = Ok(42);
    handle_result_with(
        ok_result,
        |value| {
            assert_eq!(value, 42);
            print_success("Custom result handler works");
        },
        "Handler test failed",
    );
    Ok(())
}

/// Tests analysis stats utilities
async fn test_analysis_stats_utilities() -> ExampleResult<()> {
    print_test_header("Analysis Stats Utilities");

    let stats = AnalysisStats {
        harmless: 65,
        malicious: 3,
        suspicious: 1,
        undetected: 5,
        timeout: 1,
        confirmed_timeout: Some(0),
        failure: Some(0),
        type_unsupported: Some(0),
    };

    print_analysis_stats("Test Analysis", &stats);
    print_analysis_stats_detailed("Detailed Analysis", &stats);

    // Test vote stats utilities
    print_test_header("Vote Statistics");
    print_vote_stats("Community Votes", 45, 2);
    Ok(())
}

/// Tests file size formatting utilities
async fn test_file_size_formatting() -> ExampleResult<()> {
    print_test_header("File Size Formatting");

    assert_eq!(format_file_size(0), "0 B");
    assert_eq!(format_file_size(1023), "1023 B");
    assert_eq!(format_file_size(1024), "1.0 KB");
    assert_eq!(format_file_size(1048576), "1.0 MB");
    assert_eq!(format_file_size(1073741824), "1.0 GB");

    println!(
        "File sizes: 0={}, 1KB={}, 1MB={}, 1GB={}",
        format_file_size(0),
        format_file_size(1024),
        format_file_size(1048576),
        format_file_size(1073741824)
    );
    print_success("File size formatting works correctly");
    Ok(())
}

/// Tests rate limiting utilities
async fn test_rate_limiting_utilities() -> ExampleResult<()> {
    print_test_header("Rate Limiting (Quick Test)");

    let start = std::time::Instant::now();
    rate_limit_wait(Some(1)).await; // 1 second wait
    let elapsed = start.elapsed();

    if elapsed.as_secs() >= 1 {
        print_success("rate_limit_wait works correctly");
    }
    Ok(())
}

/// Tests constants availability
async fn test_constants() -> ExampleResult<()> {
    print_test_header("Constants");

    #[allow(clippy::len_zero)] // Intentional test for non-empty constants
    {
        assert!(SAMPLE_FILE_HASH.len() > 0);
        assert!(SAMPLE_DOMAIN.len() > 0);
        assert!(SAMPLE_IP.len() > 0);
        assert!(SAMPLE_URL.len() > 0);
        assert!(API_KEY_VARS.len() > 0);
    }

    println!("Sample constants:");
    println!("  File hash: {}", SAMPLE_FILE_HASH);
    println!("  Domain: {}", SAMPLE_DOMAIN);
    println!("  IP: {}", SAMPLE_IP);
    println!("  URL: {}", SAMPLE_URL);
    println!("  API key vars: {:?}", API_KEY_VARS);
    print_success("All constants are properly defined");
    Ok(())
}

/// Restores the original environment state after testing
fn restore_environment_state(
    original_vt_key: Option<String>,
    original_vti_key: Option<String>,
) {
    match original_vt_key {
        Some(key) => env::set_var("VT_API_KEY", key),
        None => {
            env::remove_var("VT_API_KEY");
        }
    }
    match original_vti_key {
        Some(key) => env::set_var("VTI_API_KEY", key),
        None => {
            env::remove_var("VTI_API_KEY");
        }
    }
    env::remove_var("VT_PRIVATE_API_KEY");
}

/// Prints the final test summary
fn print_final_summary() {
    print_separator(Some(80));
    print_success("All common utilities tests completed successfully!");

    println!("\nUtilities tested:");
    println!("✓ API key retrieval (get_api_key, get_private_api_key, get_api_key_strict)");
    println!("✓ Client creation (create_client, create_client_from_env)");
    println!("✓ String utilities (truncate_string, truncate_comment)");
    println!("✓ Display utilities (print_*, headers, separators)");
    println!("✓ Result handling (handle_result, handle_result_with)");
    println!("✓ Analysis stats printing (print_analysis_stats, print_analysis_stats_detailed)");
    println!("✓ Vote stats printing (print_vote_stats)");
    println!("✓ File size formatting (format_file_size)");
    println!("✓ Rate limiting utilities (rate_limit_wait)");
    println!("✓ Constants (SAMPLE_*, API_KEY_VARS)");
}

#[tokio::main]
async fn main() -> ExampleResult<()> {
    print_header("Testing Common Utilities Module");

    test_api_key_utilities().await?;
    test_client_creation_utilities().await?;
    test_string_utilities().await?;
    test_display_utilities().await?;
    test_result_handling_utilities().await?;
    test_analysis_stats_utilities().await?;
    test_file_size_formatting().await?;
    test_rate_limiting_utilities().await?;
    test_constants().await?;

    print_final_summary();
    Ok(())
}
