use virustotal_rs::{ApiTier, PrivateFileUploadParams, ReanalyzeParams};

mod common;
use common::{print_step_header, setup_client};

type BoxError = Box<dyn std::error::Error>;

/// Handle API result with standardized success/error messaging
fn handle_result<T>(result: Result<T, BoxError>, success_msg: &str, error_msg: &str) -> Option<T> {
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

/// Print analysis statistics if available
fn print_analysis_stats(stats: &serde_json::Value, prefix: &str) {
    use virustotal_rs::{common::AnalysisStats, DisplayStats};

    // Try to convert JSON to AnalysisStats for better formatting
    if let Ok(analysis_stats) = serde_json::from_value::<AnalysisStats>(stats.clone()) {
        let formatted = analysis_stats.display_formatted(prefix, false);
        println!("{}", formatted);
    } else {
        // Fallback to manual parsing if conversion fails
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
}

/// Print file information in a standardized format
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

/// Truncate a string for display
fn truncate_for_display(s: &str, max_len: usize) -> String {
    use virustotal_rs::truncate_text;
    truncate_text(s, max_len)
}

/// Print the application header
fn print_header() {
    println!("Testing VirusTotal Private File Scanning API");
    println!("==============================================");
    println!("⚠️  NOTE: Requires Private Scanning License");
    println!("==============================================\n");
}

/// Test small file upload with parameters
async fn test_file_upload(private_client: &virustotal_rs::PrivateFilesClient<'_>) {
    print_step_header(1, "SMALL FILE UPLOAD TEST");

    let test_content = b"This is a test file for private scanning";
    let upload_params = create_upload_params();

    print_upload_info(test_content.len());

    if let Some(response) = handle_result(
        private_client
            .upload_file(test_content, Some(upload_params))
            .await
            .map_err(|e| e.into()),
        "File uploaded successfully",
        "Error uploading file",
    ) {
        display_upload_response(&response);
        tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
        check_analysis_status(private_client, &response.data.id).await;
    } else {
        println!("  Note: Private scanning requires special API privileges");
    }
}

fn create_upload_params() -> PrivateFileUploadParams {
    PrivateFileUploadParams::new()
        .disable_sandbox(false)
        .enable_internet(false)
        .retention_period_days(7)
        .storage_region("US".to_string())
        .locale("EN_US".to_string())
}

fn print_upload_info(content_len: usize) {
    println!(
        "Uploading small test file ({} bytes) with parameters...",
        content_len
    );
    println!("  - Sandbox: enabled");
    println!("  - Internet: disabled");
    println!("  - Retention: 7 days");
    println!("  - Storage: US");
}

fn display_upload_response(response: &virustotal_rs::PrivateFileUploadResponse) {
    println!("  Analysis ID: {}", response.data.id);
    println!("  Type: {}", response.data.object_type);
}

/// Check analysis status for uploaded file
async fn check_analysis_status(
    private_client: &virustotal_rs::PrivateFilesClient<'_>,
    analysis_id: &str,
) {
    println!("\nChecking analysis status...");
    if let Some(analysis) = handle_result(
        private_client
            .get_analysis(analysis_id, analysis_id)
            .await
            .map_err(|e| e.into()),
        "Analysis status retrieved",
        "Could not get analysis status",
    ) {
        if let Some(status) = &analysis.object.attributes.status {
            println!("  Status: {}", status);
        }
        if let Some(stats) = &analysis.object.attributes.stats {
            println!("  Detection stats:");
            let stats_json = serde_json::to_value(stats).unwrap_or_default();
            print_analysis_stats(&stats_json, "    ");
        }
    }
}

/// Test large file upload URL creation
async fn test_upload_url_creation(private_client: &virustotal_rs::PrivateFilesClient<'_>) {
    print_step_header(2, "LARGE FILE UPLOAD URL TEST");

    println!("Creating upload URL for large files...");
    if let Some(response) = handle_result(
        private_client
            .create_upload_url()
            .await
            .map_err(|e| e.into()),
        "Upload URL created successfully",
        "Error creating upload URL",
    ) {
        display_upload_url_info(&response.data);
    }
}

fn display_upload_url_info(url: &str) {
    println!("  URL: {}", truncate_for_display(url, 50));
    println!("  (URL truncated for display)");
    println!("\n  To upload a large file:");
    println!("  1. PUT your file data to the provided URL");
    println!("  2. The response will contain the analysis ID");
}

/// Test listing private files
async fn test_list_files(private_client: &virustotal_rs::PrivateFilesClient<'_>) {
    print_step_header(3, "LIST PRIVATE FILES");

    println!("Listing previously analyzed private files...");
    if let Some(files) = handle_result(
        private_client
            .list_files(Some(10), None)
            .await
            .map_err(|e| e.into()),
        &format!("Retrieved {} private files", "files"),
        "Error listing files",
    ) {
        println!("✓ Retrieved {} private files", files.data.len());
        display_file_list(&files);
    } else {
        println!("  Note: This requires private scanning privileges");
    }
}

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
            println!(
                "\n  Cursor for pagination: {}",
                truncate_for_display(cursor, 20)
            );
        }
    }
}

/// Test file report and related operations
async fn test_file_operations(
    private_client: &virustotal_rs::PrivateFilesClient<'_>,
    eicar_hash: &str,
) {
    test_file_report(private_client, eicar_hash).await;
    run_behavior_tests(private_client, eicar_hash).await;
    run_file_management_tests(private_client, eicar_hash).await;
}

async fn test_file_report(
    private_client: &virustotal_rs::PrivateFilesClient<'_>,
    eicar_hash: &str,
) {
    print_step_header(4, "FILE REPORT RETRIEVAL");
    println!("Getting private file report for EICAR test file...");
    println!("  SHA256: {}", eicar_hash);

    if let Some(file) = handle_result(
        private_client
            .get_file(eicar_hash)
            .await
            .map_err(|e| e.into()),
        "File report retrieved",
        "Error getting file report",
    ) {
        display_file_report(&file);
    } else {
        println!("  Note: This may require the file to be previously scanned privately");
    }
}

fn display_file_report(file: &virustotal_rs::PrivateFile) {
    let attrs_json = serde_json::to_value(&file.object.attributes).unwrap_or_default();
    print_file_info(&attrs_json, "  ");

    if let Some(stats) = &file.object.attributes.last_analysis_stats {
        println!("  Last analysis stats:");
        let stats_json = serde_json::to_value(stats).unwrap_or_default();
        print_analysis_stats(&stats_json, "    ");
    }
}

async fn run_behavior_tests(
    private_client: &virustotal_rs::PrivateFilesClient<'_>,
    eicar_hash: &str,
) {
    test_behavior_analysis(private_client, eicar_hash).await;
    test_behavior_summary(private_client, eicar_hash).await;
    test_mitre_attack_data(private_client, eicar_hash).await;
    test_dropped_files(private_client, eicar_hash).await;
}

async fn run_file_management_tests(
    private_client: &virustotal_rs::PrivateFilesClient<'_>,
    eicar_hash: &str,
) {
    test_reanalysis(private_client, eicar_hash).await;
    test_comments(private_client, eicar_hash).await;
    test_file_download(private_client, eicar_hash).await;
    test_pagination(private_client, eicar_hash).await;
    test_relationships(private_client, eicar_hash).await;
}

/// Test behavior analysis
async fn test_behavior_analysis(
    private_client: &virustotal_rs::PrivateFilesClient<'_>,
    hash: &str,
) {
    print_step_header(5, "BEHAVIOR ANALYSIS");

    println!("Getting behavior analysis for file...");
    if let Some(behaviors) = handle_result(
        private_client
            .get_behaviors(hash, Some(5), None)
            .await
            .map_err(|e| e.into()),
        &format!("Retrieved {} behavior reports", "behaviors"),
        "Error getting behaviors",
    ) {
        println!("✓ Retrieved {} behavior reports", behaviors.data.len());
        display_behavior_reports(&behaviors.data);
    }
}

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

    if let Some(summary) = handle_result(
        private_client
            .get_behavior_summary(hash)
            .await
            .map_err(|e| e.into()),
        "Retrieved behavior summary",
        "Error getting behavior summary",
    ) {
        display_behavior_summary(&summary);
    }
}

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

    if let Some(mitre_data) = handle_result(
        private_client
            .get_mitre_attack_data(hash)
            .await
            .map_err(|e| e.into()),
        "Retrieved MITRE ATT&CK data",
        "Error getting MITRE ATT&CK data",
    ) {
        display_mitre_data(&mitre_data);
    }
}

fn display_mitre_data(mitre_data: &virustotal_rs::MitreTrees) {
    println!("  Sandboxes analyzed: {}", mitre_data.data.len());

    for (sandbox_name, sandbox_data) in mitre_data.data.iter().take(2) {
        println!("\n  Sandbox: {}", sandbox_name);
        println!("    Tactics: {}", sandbox_data.tactics.len());
        display_tactics(&sandbox_data.tactics);
    }
}

fn display_tactics(tactics: &[virustotal_rs::MitreTactic]) {
    for tactic in tactics.iter().take(3) {
        println!("      - {} ({})", tactic.name, tactic.id);
        if !tactic.techniques.is_empty() {
            println!("        Techniques: {}", tactic.techniques.len());
            display_techniques(&tactic.techniques);
        }
    }
}

fn display_techniques(techniques: &[virustotal_rs::MitreTechnique]) {
    for technique in techniques.iter().take(2) {
        println!("          - {} ({})", technique.name, technique.id);
    }
}

/// Test dropped files retrieval
async fn test_dropped_files(private_client: &virustotal_rs::PrivateFilesClient<'_>, hash: &str) {
    print_step_header(8, "DROPPED FILES");

    if let Some(dropped) = handle_result(
        private_client
            .get_dropped_files(hash, Some(10), None)
            .await
            .map_err(|e| e.into()),
        &format!("Found {} dropped files", "dropped"),
        "Error getting dropped files",
    ) {
        display_dropped_files(&dropped);
    }
}

fn display_dropped_files(dropped: &virustotal_rs::Collection<virustotal_rs::DroppedFile>) {
    if dropped.data.is_empty() {
        println!("  No dropped files found");
    } else {
        println!("✓ Found {} dropped files", dropped.data.len());

        for (i, file) in dropped.data.iter().enumerate().take(3) {
            display_dropped_file_info(i + 1, file);
        }
    }
}

fn display_dropped_file_info(index: usize, file: &virustotal_rs::DroppedFile) {
    println!("\n  Dropped file #{}", index);
    if let Some(sha256) = &file.object.attributes.sha256 {
        println!("    SHA256: {}", sha256);
    }
    // Path field is not available in FileAttributes
    // if let Some(path) = &file.object.attributes.path {
    //     println!("    Path: {}", path);
    // }
    if let Some(size) = &file.object.attributes.size {
        println!("    Size: {} bytes", size);
    }
}

/// Test re-analysis with parameters
async fn test_reanalysis(private_client: &virustotal_rs::PrivateFilesClient<'_>, hash: &str) {
    print_step_header(9, "RE-ANALYSIS");

    println!("Requesting re-analysis of file with custom parameters...");
    let reanalyze_params = ReanalyzeParams::new()
        .enable_internet(true)
        .interaction_sandbox("cape".to_string())
        .interaction_timeout(120);

    if let Some(analysis) = handle_result(
        private_client
            .reanalyze(hash, Some(reanalyze_params))
            .await
            .map_err(|e| e.into()),
        "Re-analysis requested",
        "Error requesting re-analysis",
    ) {
        println!("  Analysis ID: {}", analysis.object.id);
        if let Some(status) = &analysis.object.attributes.status {
            println!("  Status: {}", status);
        }
    }
}

/// Test comment operations
async fn test_comments(private_client: &virustotal_rs::PrivateFilesClient<'_>, hash: &str) {
    print_step_header(10, "COMMENTS");

    add_test_comment(private_client, hash).await;
    retrieve_comments(private_client, hash).await;
}

async fn add_test_comment(private_client: &virustotal_rs::PrivateFilesClient<'_>, hash: &str) {
    println!("Adding comment to file...");
    if let Some(comment) = handle_result(
        private_client
            .add_comment(hash, "Test comment from private file scanning API")
            .await
            .map_err(|e| e.into()),
        "Comment added",
        "Error adding comment",
    ) {
        println!("  Comment ID: {}", comment.object.id);
    }
}

async fn retrieve_comments(private_client: &virustotal_rs::PrivateFilesClient<'_>, hash: &str) {
    println!("\nRetrieving comments...");
    if let Some(comments) = handle_result(
        private_client
            .get_comments(hash, Some(5), None)
            .await
            .map_err(|e| e.into()),
        &format!("Retrieved {} comments", "comments"),
        "Error getting comments",
    ) {
        println!("✓ Retrieved {} comments", comments.data.len());
        display_comment_list(&comments.data);
    }
}

fn display_comment_list(comments: &[virustotal_rs::comments::Comment]) {
    for comment in comments.iter().take(2) {
        println!(
            "  - {}",
            truncate_for_display(&comment.object.attributes.text, 50)
        );
    }
}

/// Test file download
async fn test_file_download(private_client: &virustotal_rs::PrivateFilesClient<'_>, hash: &str) {
    print_step_header(11, "FILE DOWNLOAD");

    println!("Downloading file content...");
    if let Some(file_bytes) = handle_result(
        private_client.download(hash).await.map_err(|e| e.into()),
        "File downloaded successfully",
        "Error downloading file",
    ) {
        println!("  Size: {} bytes", file_bytes.len());
        println!(
            "  First 20 bytes (hex): {:02x?}",
            &file_bytes[..20.min(file_bytes.len())]
        );
    } else {
        println!("  Note: File download may require special permissions");
    }
}

/// Test pagination with analyses
async fn test_pagination(private_client: &virustotal_rs::PrivateFilesClient<'_>, hash: &str) {
    print_step_header(12, "ANALYSES PAGINATION");

    println!("Getting analysis history with pagination...");
    let mut analyses_iterator = private_client.get_analyses_iterator(hash);

    if let Some(batch) = handle_result(
        analyses_iterator.next_batch().await.map_err(|e| e.into()),
        &format!("Retrieved {} analyses in first batch", "batch"),
        "Error fetching analyses",
    ) {
        println!("✓ Retrieved {} analyses in first batch", batch.len());
        display_analyses_batch(&batch);
    }
}

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
    if let Some(similar) = handle_result(
        private_client
            .get_relationship::<serde_json::Value>(hash, "similar_files", Some(5), None)
            .await
            .map_err(|e| e.into()),
        &format!("Found {} similar files", "similar"),
        "Error getting similar files",
    ) {
        println!("✓ Found {} similar files", similar.data.len());
    }

    // Contacted domains
    if let Some(domains) = handle_result(
        private_client
            .get_relationship::<serde_json::Value>(hash, "contacted_domains", Some(5), None)
            .await
            .map_err(|e| e.into()),
        &format!("Found {} contacted domains", "domains"),
        "Error getting contacted domains",
    ) {
        println!("✓ Found {} contacted domains", domains.data.len());
    }

    // Relationship descriptors
    println!("\nGetting relationship descriptors...");
    if let Some(descriptors) = handle_result(
        private_client
            .get_relationship_descriptors(hash, "contacted_urls", Some(5), None)
            .await
            .map_err(|e| e.into()),
        &format!("Found {} URL descriptors", "descriptors"),
        "Error getting URL descriptors",
    ) {
        println!("✓ Found {} URL descriptors", descriptors.data.len());
        for descriptor in descriptors.data.iter().take(2) {
            if let Some(id) = descriptor.get("id") {
                println!("  - ID: {}", id);
            }
        }
    }
}

/// Print file deletion information
fn print_deletion_info() {
    print_step_header(14, "FILE DELETION");

    println!("Testing delete functionality (dry run - not actually deleting)...");
    println!("  Delete functionality available with:");
    println!("    - delete_file(sha256, false) - Delete file and all data");
    println!("    - delete_file(sha256, true)  - Delete only from storage, keep reports");
}

/// Print important notes about SHA-256 requirement
fn print_important_notes(eicar_hash: &str) {
    print_step_header(15, "IMPORTANT NOTES");

    println!("⚠️  SHA-256 ONLY: Private file endpoints only accept SHA-256 hashes");
    println!("   MD5 and SHA-1 are NOT supported (unlike public file endpoints)");
    println!("   Example SHA-256: {}", eicar_hash);
    println!("   Length: {} characters", eicar_hash.len());
}

/// Print completion message
fn print_completion() {
    println!("\n==============================================");
    println!("Private File Scanning API Testing Complete!");
    println!("\nNOTE: Many features require a Private Scanning License.");
    println!("Without proper privileges, most operations will fail.");
}

#[tokio::main]
async fn main() -> Result<(), BoxError> {
    let client = setup_client(ApiTier::Premium)?;
    print_header();
    let private_client = client.private_files();

    let eicar_hash = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f";

    execute_all_tests(&private_client, eicar_hash).await;
    print_completion_info(eicar_hash);

    Ok(())
}

async fn execute_all_tests(
    private_client: &virustotal_rs::PrivateFilesClient<'_>,
    eicar_hash: &str,
) {
    test_file_upload(private_client).await;
    test_upload_url_creation(private_client).await;
    test_list_files(private_client).await;
    test_file_operations(private_client, eicar_hash).await;
}

fn print_completion_info(eicar_hash: &str) {
    print_deletion_info();
    print_important_notes(eicar_hash);
    print_completion();
}
