use virustotal_rs::{ApiTier, PrivateFileUploadParams, ReanalyzeParams};

mod common;
use common::*;

const EICAR_HASH: &str = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f";

/// Create upload parameters for private file scanning
fn create_upload_params() -> PrivateFileUploadParams {
    PrivateFileUploadParams::new()
        .disable_sandbox(false)
        .enable_internet(false)
        .retention_period_days(7)
        .storage_region("US".to_string())
        .locale("EN_US".to_string())
}

/// Print analysis statistics in standardized format
fn print_analysis_stats(stats: &serde_json::Value, prefix: &str) {
    use virustotal_rs::{common::AnalysisStats, DisplayStats};

    if let Ok(analysis_stats) = serde_json::from_value::<AnalysisStats>(stats.clone()) {
        let formatted = analysis_stats.display_formatted(prefix, false);
        println!("{}", formatted);
    } else {
        print_fallback_stats(stats, prefix);
    }
}

/// Print fallback stats when conversion fails
fn print_fallback_stats(stats: &serde_json::Value, prefix: &str) {
    if let Some(malicious) = stats.get("malicious").and_then(|v| v.as_u64()) {
        println!("{}  - Malicious: {}", prefix, malicious);
    }
    if let Some(suspicious) = stats.get("suspicious").and_then(|v| v.as_u64()) {
        println!("{}  - Suspicious: {}", prefix, suspicious);
    }
    if let Some(undetected) = stats.get("undetected").and_then(|v| v.as_u64()) {
        println!("{}  - Undetected: {}", prefix, undetected);
    }
}

/// Print file information using display utilities
fn print_file_info(file: &serde_json::Value, prefix: &str) {
    use virustotal_rs::{format_file_size, format_reputation};

    if let Some(size) = file.get("size").and_then(|v| v.as_u64()) {
        println!("{}Size: {}", prefix, format_file_size(size));
    }
    if let Some(type_desc) = file.get("type_description").and_then(|v| v.as_str()) {
        println!("{}Type: {}", prefix, type_desc);
    }
    if let Some(reputation) = file.get("reputation").and_then(|v| v.as_i64()) {
        println!(
            "{}Reputation: {}",
            prefix,
            format_reputation(reputation as i32)
        );
    }
}

/// Test small file upload with parameters
async fn test_file_upload(private_client: &virustotal_rs::PrivateFilesClient<'_>) {
    print_step_header(1, "SMALL FILE UPLOAD TEST");

    let test_content = b"This is a test file for private scanning";
    let upload_params = create_upload_params();

    println!(
        "Uploading small test file ({} bytes) with parameters...",
        test_content.len()
    );
    println!("  - Sandbox: enabled");
    println!("  - Internet: disabled");
    println!("  - Retention: 7 days");
    println!("  - Storage: US");

    match private_client
        .upload_file(test_content, Some(upload_params))
        .await
    {
        Ok(response) => {
            print_success("File uploaded successfully");
            println!("  Analysis ID: {}", response.data.id);
            println!("  Type: {}", response.data.object_type);

            tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
            check_analysis_status(private_client, &response.data.id).await;
        }
        Err(e) => {
            print_error(&format!("Error uploading file: {}", e));
            println!("  Note: Private scanning requires special API privileges");
        }
    }
}

/// Check analysis status for uploaded file
async fn check_analysis_status(
    private_client: &virustotal_rs::PrivateFilesClient<'_>,
    analysis_id: &str,
) {
    println!("\nChecking analysis status...");

    match private_client.get_analysis(analysis_id, analysis_id).await {
        Ok(analysis) => {
            print_success("Analysis status retrieved");
            if let Some(status) = &analysis.object.attributes.status {
                println!("  Status: {}", status);
            }
            if let Some(stats) = &analysis.object.attributes.stats {
                println!("  Detection stats:");
                let stats_json = serde_json::to_value(stats).unwrap_or_default();
                print_analysis_stats(&stats_json, "    ");
            }
        }
        Err(e) => print_error(&format!("Could not get analysis status: {}", e)),
    }
}

/// Test large file upload URL creation
async fn test_upload_url_creation(private_client: &virustotal_rs::PrivateFilesClient<'_>) {
    print_step_header(2, "LARGE FILE UPLOAD URL TEST");

    println!("Creating upload URL for large files...");
    match private_client.create_upload_url().await {
        Ok(response) => {
            print_success("Upload URL created successfully");
            println!("  URL: {}", truncate_string(&response.data, 50));
            println!("  (URL truncated for display)");
            println!("\n  To upload a large file:");
            println!("  1. PUT your file data to the provided URL");
            println!("  2. The response will contain the analysis ID");
        }
        Err(e) => print_error(&format!("Error creating upload URL: {}", e)),
    }
}

/// Test listing private files
async fn test_list_files(private_client: &virustotal_rs::PrivateFilesClient<'_>) {
    print_step_header(3, "LIST PRIVATE FILES");

    println!("Listing previously analyzed private files...");
    match private_client.list_files(Some(10), None).await {
        Ok(files) => {
            print_success(&format!("Retrieved {} private files", files.data.len()));
            display_file_list(&files);
        }
        Err(e) => {
            print_error(&format!("Error listing files: {}", e));
            println!("  Note: This requires private scanning privileges");
        }
    }
}

/// Display file list information
fn display_file_list(files: &virustotal_rs::Collection<virustotal_rs::PrivateFile>) {
    for file in files.data.iter().take(3) {
        println!("\n  File: {}", file.object.id);
        let attrs_json = serde_json::to_value(&file.object.attributes).unwrap_or_default();
        print_file_info(&attrs_json, "    ");

        if let Some(tags) = &file.object.attributes.tags {
            if !tags.is_empty() {
                println!("    Tags: {}", tags.join(", "));
            }
        }
    }

    if let Some(meta) = &files.meta {
        if let Some(cursor) = &meta.cursor {
            println!("\n  Cursor for pagination: {}", truncate_string(cursor, 20));
        }
    }
}

/// Test file report and behavior analysis
async fn test_file_operations(private_client: &virustotal_rs::PrivateFilesClient<'_>) {
    test_file_report(private_client, EICAR_HASH).await;
    test_behavior_analysis(private_client, EICAR_HASH).await;
    test_behavior_summary(private_client, EICAR_HASH).await;
    test_mitre_attack_data(private_client, EICAR_HASH).await;
    test_dropped_files(private_client, EICAR_HASH).await;
}

/// Test file report retrieval
async fn test_file_report(
    private_client: &virustotal_rs::PrivateFilesClient<'_>,
    eicar_hash: &str,
) {
    print_step_header(4, "FILE REPORT RETRIEVAL");
    println!("Getting private file report for EICAR test file...");
    println!("  SHA256: {}", eicar_hash);

    match private_client.get_file(eicar_hash).await {
        Ok(file) => {
            print_success("File report retrieved");
            let attrs_json = serde_json::to_value(&file.object.attributes).unwrap_or_default();
            print_file_info(&attrs_json, "  ");

            if let Some(stats) = &file.object.attributes.last_analysis_stats {
                println!("  Last analysis stats:");
                let stats_json = serde_json::to_value(stats).unwrap_or_default();
                print_analysis_stats(&stats_json, "    ");
            }
        }
        Err(e) => {
            print_error(&format!("Error getting file report: {}", e));
            println!("  Note: This may require the file to be previously scanned privately");
        }
    }
}

/// Test behavior analysis
async fn test_behavior_analysis(
    private_client: &virustotal_rs::PrivateFilesClient<'_>,
    hash: &str,
) {
    print_step_header(5, "BEHAVIOR ANALYSIS");

    println!("Getting behavior analysis for file...");
    match private_client.get_behaviors(hash, Some(5), None).await {
        Ok(behaviors) => {
            print_success(&format!(
                "Retrieved {} behavior reports",
                behaviors.data.len()
            ));
            display_behavior_reports(&behaviors.data);
        }
        Err(e) => print_error(&format!("Error getting behaviors: {}", e)),
    }
}

/// Display behavior reports
fn display_behavior_reports(behaviors: &[virustotal_rs::FileBehavior]) {
    for (i, behavior) in behaviors.iter().enumerate().take(3) {
        println!("\n  Behavior #{}", i + 1);
        if let Some(sandbox_name) = &behavior.data.attributes.sandbox_name {
            println!("    Sandbox: {}", sandbox_name);
        }
        if let Some(analysis_date) = &behavior.data.attributes.analysis_date {
            println!("    Date: {}", analysis_date);
        }
    }
}

/// Test behavior summary
async fn test_behavior_summary(private_client: &virustotal_rs::PrivateFilesClient<'_>, hash: &str) {
    print_step_header(6, "BEHAVIOR SUMMARY");

    match private_client.get_behavior_summary(hash).await {
        Ok(summary) => {
            print_success("Retrieved behavior summary");
            display_behavior_summary(&summary);
        }
        Err(e) => print_error(&format!("Error getting behavior summary: {}", e)),
    }
}

/// Display behavior summary information
fn display_behavior_summary(summary: &virustotal_rs::FileBehaviorSummary) {
    if let Some(processes) = &summary.processes_tree {
        println!("  Processes spawned: {}", processes.len());
    }
    if let Some(files) = &summary.files_written {
        println!("  Files written: {}", files.len());
    }
    if let Some(tags) = &summary.tags {
        if !tags.is_empty() {
            println!("  Tags: {}", tags.join(", "));
        }
    }
}

/// Test MITRE ATT&CK data
async fn test_mitre_attack_data(
    private_client: &virustotal_rs::PrivateFilesClient<'_>,
    hash: &str,
) {
    print_step_header(7, "MITRE ATT&CK DATA");

    match private_client.get_mitre_attack_data(hash).await {
        Ok(mitre_data) => {
            print_success("Retrieved MITRE ATT&CK data");
            display_mitre_data(&mitre_data);
        }
        Err(e) => print_error(&format!("Error getting MITRE ATT&CK data: {}", e)),
    }
}

/// Display MITRE ATT&CK data
fn display_mitre_data(mitre_data: &virustotal_rs::MitreTrees) {
    println!("  Sandboxes analyzed: {}", mitre_data.data.len());

    for (sandbox_name, sandbox_data) in mitre_data.data.iter().take(2) {
        println!("\n  Sandbox: {}", sandbox_name);
        println!("    Tactics: {}", sandbox_data.tactics.len());
        display_tactics(&sandbox_data.tactics);
    }
}

/// Display MITRE tactics
fn display_tactics(tactics: &[virustotal_rs::MitreTactic]) {
    for tactic in tactics.iter().take(3) {
        println!("      - {} ({})", tactic.name, tactic.id);
        if !tactic.techniques.is_empty() {
            println!("        Techniques: {}", tactic.techniques.len());
            display_techniques(&tactic.techniques);
        }
    }
}

/// Display MITRE techniques
fn display_techniques(techniques: &[virustotal_rs::MitreTechnique]) {
    for technique in techniques.iter().take(2) {
        println!("          - {} ({})", technique.name, technique.id);
    }
}

/// Test dropped files retrieval
async fn test_dropped_files(private_client: &virustotal_rs::PrivateFilesClient<'_>, hash: &str) {
    print_step_header(8, "DROPPED FILES");

    match private_client.get_dropped_files(hash, Some(10), None).await {
        Ok(dropped) => {
            if dropped.data.is_empty() {
                println!("  No dropped files found");
            } else {
                print_success(&format!("Found {} dropped files", dropped.data.len()));
                display_dropped_files(&dropped.data);
            }
        }
        Err(e) => print_error(&format!("Error getting dropped files: {}", e)),
    }
}

/// Display dropped files information
fn display_dropped_files(files: &[virustotal_rs::DroppedFile]) {
    for (i, file) in files.iter().enumerate().take(3) {
        println!("\n  Dropped file #{}", i + 1);
        if let Some(sha256) = &file.object.attributes.sha256 {
            println!("    SHA256: {}", sha256);
        }
        if let Some(size) = &file.object.attributes.size {
            println!("    Size: {} bytes", size);
        }
    }
}

/// Test file management operations
async fn test_file_management(private_client: &virustotal_rs::PrivateFilesClient<'_>) {
    test_reanalysis(private_client, EICAR_HASH).await;
    test_comments(private_client, EICAR_HASH).await;
    test_file_download(private_client, EICAR_HASH).await;
    test_pagination(private_client, EICAR_HASH).await;
    test_relationships(private_client, EICAR_HASH).await;
}

/// Test re-analysis with parameters
async fn test_reanalysis(private_client: &virustotal_rs::PrivateFilesClient<'_>, hash: &str) {
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
async fn test_comments(private_client: &virustotal_rs::PrivateFilesClient<'_>, hash: &str) {
    print_step_header(10, "COMMENTS");

    // Add comment
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

    // Retrieve comments
    println!("\nRetrieving comments...");
    match private_client.get_comments(hash, Some(5), None).await {
        Ok(comments) => {
            print_success(&format!("Retrieved {} comments", comments.data.len()));
            for comment in comments.data.iter().take(2) {
                println!(
                    "  - {}",
                    truncate_string(&comment.object.attributes.text, 50)
                );
            }
        }
        Err(e) => print_error(&format!("Error getting comments: {}", e)),
    }
}

/// Test file download
async fn test_file_download(private_client: &virustotal_rs::PrivateFilesClient<'_>, hash: &str) {
    print_step_header(11, "FILE DOWNLOAD");

    println!("Downloading file content...");
    match private_client.download(hash).await {
        Ok(file_bytes) => {
            print_success("File downloaded successfully");
            println!("  Size: {} bytes", file_bytes.len());
            println!(
                "  First 20 bytes (hex): {:02x?}",
                &file_bytes[..20.min(file_bytes.len())]
            );
        }
        Err(e) => {
            print_error(&format!("Error downloading file: {}", e));
            println!("  Note: File download may require special permissions");
        }
    }
}

/// Test pagination with analyses
async fn test_pagination(private_client: &virustotal_rs::PrivateFilesClient<'_>, hash: &str) {
    print_step_header(12, "ANALYSES PAGINATION");

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
fn display_analyses_batch(batch: &[virustotal_rs::PrivateAnalysis]) {
    for analysis in batch.iter().take(2) {
        println!("  - Analysis ID: {}", analysis.object.id);
        if let Some(date) = &analysis.object.attributes.date {
            println!("    Date: {}", date);
        }
        if let Some(status) = &analysis.object.attributes.status {
            println!("    Status: {:?}", status);
        }
    }
}

/// Test file relationships
async fn test_relationships(private_client: &virustotal_rs::PrivateFilesClient<'_>, hash: &str) {
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

/// Print important notes about the private API
fn print_completion_notes() {
    print_step_header(14, "IMPORTANT NOTES");

    println!("⚠️  SHA-256 ONLY: Private file endpoints only accept SHA-256 hashes");
    println!("   MD5 and SHA-1 are NOT supported (unlike public file endpoints)");
    println!("   Example SHA-256: {}", EICAR_HASH);
    println!("   Length: {} characters", EICAR_HASH.len());

    println!("\n   Delete functionality available with:");
    println!("    - delete_file(sha256, false) - Delete file and all data");
    println!("    - delete_file(sha256, true)  - Delete only from storage, keep reports");
}

#[tokio::main]
async fn main() -> ExampleResult<()> {
    let client = create_client_from_env("VT_PRIVATE_API_KEY", ApiTier::Premium)?;

    print_header("Testing VirusTotal Private File Scanning API");
    println!("⚠️  NOTE: Requires Private Scanning License");
    println!("==============================================\n");

    let private_client = client.private_files();

    // Execute all test scenarios
    test_file_upload(&private_client).await;
    test_upload_url_creation(&private_client).await;
    test_list_files(&private_client).await;
    test_file_operations(&private_client).await;
    test_file_management(&private_client).await;

    print_completion_notes();

    println!("\n==============================================");
    println!("Private File Scanning API Testing Complete!");
    println!("\nNOTE: Many features require a Private Scanning License.");
    println!("Without proper privileges, most operations will fail.");

    Ok(())
}
