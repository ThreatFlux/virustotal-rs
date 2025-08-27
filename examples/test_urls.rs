use virustotal_rs::{ApiTier, UrlClient, VoteVerdict};

#[path = "common/mod.rs"]
mod common;
use common::*;

/// Demonstrate URL identifier generation
fn demo_url_identifier_generation(_url_client: &UrlClient, test_url: &str) -> String {
    print_test_header("1. URL Identifier Generation");
    let base64_id = UrlClient::generate_url_id(test_url);
    let sha256_id = UrlClient::generate_url_sha256(test_url);
    println!("   URL: {}", test_url);
    println!("   Base64 ID (no padding): {}", base64_id);
    println!("   SHA256 ID: {}", sha256_id);
    base64_id
}

/// Test scanning a URL
async fn test_scan_url(url_client: &UrlClient<'_>, test_url: &str) {
    print_test_header("2. Scanning URL");
    handle_result_with(
        url_client.scan(test_url).await,
        |analysis| {
            print_success("URL submitted for scanning");
            println!("   - Analysis ID: {}", analysis.data.id);
            println!("   - Type: {}", analysis.data.object_type);
        },
        "Failed to scan URL",
    );
}

/// Test getting URL report by ID
async fn test_get_url_report_by_id(url_client: &UrlClient<'_>, base64_id: &str) {
    print_test_header("3. Getting URL report");
    handle_result_with(
        url_client.get(base64_id).await,
        |url_report| {
            print_success("Successfully retrieved URL report");
            display_url_report_details(&url_report.object.attributes);
        },
        "Failed to get URL report",
    );
}

use virustotal_rs::urls::UrlAttributes;

/// Display URL report details
fn display_url_report_details(attributes: &UrlAttributes) {
    println!("   - URL: {:?}", attributes.url);
    println!("   - Final URL: {:?}", attributes.final_url);
    println!("   - Title: {:?}", attributes.title);
    println!("   - Reputation: {:?}", attributes.reputation);
    println!("   - Times submitted: {:?}", attributes.times_submitted);

    if let Some(stats) = &attributes.last_analysis_stats {
        print_analysis_stats("Last analysis stats", stats);
    }

    if let Some(votes) = &attributes.total_votes {
        print_vote_stats("Total votes", votes.harmless, votes.malicious);
    }
}

/// Test getting URL report by actual URL (convenience method)
async fn test_get_url_report_by_url(url_client: &UrlClient<'_>, test_url: &str) {
    print_test_header("4. Getting URL report by actual URL");
    handle_result_with(
        url_client.get_by_url(test_url).await,
        |url_report| {
            print_success("Retrieved URL report using actual URL");
            println!("   - ID: {}", url_report.object.id);
        },
        "Failed to get URL report by URL",
    );
}

/// Test rescanning a URL
async fn test_rescan_url(url_client: &UrlClient<'_>, base64_id: &str) {
    print_test_header("5. Requesting URL rescan");
    handle_result_with(
        url_client.rescan(base64_id).await,
        |analysis| {
            print_success("URL rescan requested");
            println!("   - New analysis ID: {}", analysis.data.id);
        },
        "Failed to request rescan",
    );
}

/// Test basic URL operations (scan, get report, rescan)
async fn test_basic_url_operations(url_client: &UrlClient<'_>, test_url: &str, base64_id: &str) {
    test_scan_url(url_client, test_url).await;
    test_get_url_report_by_id(url_client, base64_id).await;
    test_get_url_report_by_url(url_client, test_url).await;
    test_rescan_url(url_client, base64_id).await;
}

/// Test comment and voting functionality
async fn test_comments_and_votes(url_client: &UrlClient<'_>, base64_id: &str) {
    // Test getting comments
    print_test_header("6. Getting comments on URL");
    handle_result_with(
        url_client.get_comments(base64_id).await,
        |comments| {
            print_success("Successfully retrieved comments");
            if let Some(meta) = &comments.meta {
                if let Some(count) = meta.count {
                    println!("   - Total comments: {}", count);
                }
            }
            for comment in comments.data.iter().take(3) {
                let truncated = truncate_comment(&comment.object.attributes.text);
                println!("   - Comment: {}", truncated);
            }
        },
        "Failed to get comments",
    );

    // Test adding a comment
    print_test_header("7. Adding a comment");
    handle_result_with(
        url_client
            .add_comment(base64_id, "This is a test comment #testing")
            .await,
        |comment| {
            print_success("Successfully added comment");
            println!("   - Comment ID: {}", comment.object.id);
            println!("   - Text: {}", comment.object.attributes.text);
            if let Some(tags) = &comment.object.attributes.tags {
                println!("   - Tags: {:?}", tags);
            }
        },
        "Failed to add comment",
    );

    // Test getting votes
    print_test_header("8. Getting votes on URL");
    handle_result_with(
        url_client.get_votes(base64_id).await,
        |votes| {
            print_success("Successfully retrieved votes");
            if let Some(meta) = &votes.meta {
                if let Some(count) = meta.count {
                    println!("   - Total votes: {}", count);
                }
            }
        },
        "Failed to get votes",
    );

    // Test adding a vote
    print_test_header("9. Adding a vote (harmless)");
    handle_result_with(
        url_client.add_vote(base64_id, VoteVerdict::Harmless).await,
        |vote| {
            print_success("Successfully added vote");
            println!("   - Vote verdict: {:?}", vote.object.attributes.verdict);
        },
        "Failed to add vote",
    );
}

/// Get URL analyses
async fn get_url_analyses(url_client: &UrlClient<'_>, base64_id: &str) {
    handle_result_with(
        url_client.get_analyses(base64_id).await,
        |analyses| {
            print_success("Retrieved analyses");
            if let Some(meta) = &analyses.meta {
                if let Some(count) = meta.count {
                    println!("   - Number of analyses: {}", count);
                }
            }
        },
        "Error getting analyses",
    );
}

/// Get URL downloaded files
async fn get_url_downloaded_files(url_client: &UrlClient<'_>, base64_id: &str) {
    handle_result_with(
        url_client.get_downloaded_files(base64_id).await,
        |files| {
            print_success("Retrieved downloaded files");
            if let Some(meta) = &files.meta {
                if let Some(count) = meta.count {
                    println!("   - Number of downloaded files: {}", count);
                }
            }
        },
        "Error getting downloaded files",
    );
}

/// Get URL redirecting URLs
async fn get_url_redirecting_urls(url_client: &UrlClient<'_>, base64_id: &str) {
    handle_result_with(
        url_client.get_redirecting_urls(base64_id).await,
        |urls| {
            print_success("Retrieved redirecting URLs");
            if let Some(meta) = &urls.meta {
                if let Some(count) = meta.count {
                    println!("   - Number of redirecting URLs: {}", count);
                }
            }
        },
        "Error getting redirecting URLs",
    );
}

/// Test URL relationship retrieval
async fn test_url_relationships(url_client: &UrlClient<'_>, base64_id: &str) {
    print_test_header("10. Getting URL relationships");
    get_url_analyses(url_client, base64_id).await;
    get_url_downloaded_files(url_client, base64_id).await;
    get_url_redirecting_urls(url_client, base64_id).await;
}

/// Test paginated results with iterators
async fn test_pagination(url_client: &UrlClient<'_>, base64_id: &str) {
    print_test_header("11. Testing pagination with comments iterator");
    let mut comments_iter = url_client.get_comments_iterator(base64_id);
    handle_result_with(
        comments_iter.next_batch().await,
        |batch| {
            if batch.is_empty() {
                print_info("No comments found");
            } else {
                print_success("Retrieved first batch of comments");
                println!("   - Batch size: {}", batch.len());
            }
        },
        "Failed to get comments batch",
    );
}

#[tokio::main]
async fn main() -> ExampleResult<()> {
    let client = create_client_from_env("VT_API_KEY", ApiTier::Public)?;
    let url_client = client.urls();
    let test_url = "http://www.example.com/test";

    print_header("Testing URL API methods");

    // Generate URL identifiers
    let base64_id = demo_url_identifier_generation(&url_client, test_url);

    // Test basic operations
    test_basic_url_operations(&url_client, test_url, &base64_id).await;

    // Test comments and voting
    test_comments_and_votes(&url_client, &base64_id).await;

    // Test relationships
    test_url_relationships(&url_client, &base64_id).await;

    // Test pagination
    test_pagination(&url_client, &base64_id).await;

    print_separator(Some(60));
    print_success("URL API testing complete!");

    Ok(())
}
