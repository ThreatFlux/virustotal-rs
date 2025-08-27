use crate::common::*;
use virustotal_rs::ReanalyzeParams;

/// Test re-analysis with parameters
pub async fn test_reanalysis(private_client: &virustotal_rs::PrivateFilesClient<'_>, hash: &str) {
    print_step_header(9, "RE-ANALYSIS");

    println!("Requesting re-analysis of file with custom parameters...");
    let reanalyze_params = ReanalyzeParams::new()
        .enable_internet(true)
        .interaction_sandbox("cape".to_string())
        .interaction_timeout(120);

    match private_client.reanalyze(hash, Some(reanalyze_params)).await {
        Ok(analysis) => {
            print_success("Re-analysis requested");
            println!("  Analysis ID: {}", analysis.object.id);
            if let Some(status) = &analysis.object.attributes.status {
                println!("  Status: {}", status);
            }
        }
        Err(e) => print_error(&format!("Error requesting re-analysis: {}", e)),
    }
}

/// Test comment operations
pub async fn test_comments(private_client: &virustotal_rs::PrivateFilesClient<'_>, hash: &str) {
    print_step_header(10, "COMMENTS");

    add_test_comment(private_client, hash).await;
    retrieve_comments(private_client, hash).await;
}

/// Add a test comment
pub async fn add_test_comment(private_client: &virustotal_rs::PrivateFilesClient<'_>, hash: &str) {
    println!("Adding comment to file...");
    match private_client
        .add_comment(hash, "Test comment from private file scanning API")
        .await
    {
        Ok(comment) => {
            print_success("Comment added");
            println!("  Comment ID: {}", comment.object.id);
        }
        Err(e) => print_error(&format!("Error adding comment: {}", e)),
    }
}

/// Retrieve and display comments
pub async fn retrieve_comments(private_client: &virustotal_rs::PrivateFilesClient<'_>, hash: &str) {
    println!("\nRetrieving comments...");
    match private_client.get_comments(hash, Some(5), None).await {
        Ok(comments) => {
            print_success(&format!("Retrieved {} comments", comments.data.len()));
            display_comment_list(&comments.data);
        }
        Err(e) => print_error(&format!("Error getting comments: {}", e)),
    }
}

/// Display list of comments
pub fn display_comment_list(comments: &[virustotal_rs::Comment]) {
    for comment in comments.iter().take(2) {
        println!(
            "  - {}",
            truncate_string(&comment.object.attributes.text, 50)
        );
    }
}

/// Test pagination with analyses
pub async fn test_pagination(private_client: &virustotal_rs::PrivateFilesClient<'_>, hash: &str) {
    print_step_header(12, "ANALYSES PAGINATION");

    fetch_analysis_batch(private_client, hash).await;
}

/// Fetch and display analysis batch
pub async fn fetch_analysis_batch(private_client: &virustotal_rs::PrivateFilesClient<'_>, hash: &str) {
    println!("Getting analysis history with pagination...");
    let mut analyses_iterator = private_client.get_analyses_iterator(hash);

    match analyses_iterator.next_batch().await {
        Ok(batch) => {
            print_success(&format!(
                "Retrieved {} analyses in first batch",
                batch.len()
            ));
            display_analyses_batch(&batch);
        }
        Err(e) => print_error(&format!("Error fetching analyses: {}", e)),
    }
}

/// Display analyses batch information
pub fn display_analyses_batch(batch: &[virustotal_rs::PrivateAnalysis]) {
    for analysis in batch.iter().take(2) {
        println!("  - Analysis ID: {}", analysis.object.id);
        display_analysis_metadata(analysis);
    }
}

/// Display analysis metadata
pub fn display_analysis_metadata(analysis: &virustotal_rs::PrivateAnalysis) {
    if let Some(date) = &analysis.object.attributes.date {
        println!("    Date: {}", date);
    }
    if let Some(status) = &analysis.object.attributes.status {
        println!("    Status: {:?}", status);
    }
}

/// Test file relationships
pub async fn test_relationships(private_client: &virustotal_rs::PrivateFilesClient<'_>, hash: &str) {
    print_step_header(13, "FILE RELATIONSHIPS");

    println!("Getting file relationships...");

    // Similar files
    match private_client
        .get_relationship::<serde_json::Value>(hash, "similar_files", Some(5), None)
        .await
    {
        Ok(similar) => print_success(&format!("Found {} similar files", similar.data.len())),
        Err(e) => print_error(&format!("Error getting similar files: {}", e)),
    }

    // Contacted domains
    match private_client
        .get_relationship::<serde_json::Value>(hash, "contacted_domains", Some(5), None)
        .await
    {
        Ok(domains) => print_success(&format!("Found {} contacted domains", domains.data.len())),
        Err(e) => print_error(&format!("Error getting contacted domains: {}", e)),
    }

    // Relationship descriptors
    println!("\nGetting relationship descriptors...");
    match private_client
        .get_relationship_descriptors(hash, "contacted_urls", Some(5), None)
        .await
    {
        Ok(descriptors) => {
            print_success(&format!("Found {} URL descriptors", descriptors.data.len()));
            for descriptor in descriptors.data.iter().take(2) {
                if let Some(id) = descriptor.get("id") {
                    println!("  - ID: {}", id);
                }
            }
        }
        Err(e) => print_error(&format!("Error getting URL descriptors: {}", e)),
    }
}