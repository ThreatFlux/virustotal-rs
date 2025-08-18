use virustotal_rs::{ApiTier, ClientBuilder, PrivateFileUploadParams, ReanalyzeParams};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // NOTE: Private file scanning requires special privileges
    // This example assumes you have a valid API key with private scanning license
    let api_key = std::env::var("VT_PRIVATE_API_KEY")
        .or_else(|_| std::env::var("VT_API_KEY"))
        .unwrap_or_else(|_| "test_key".to_string());

    let client = ClientBuilder::new()
        .api_key(api_key)
        .tier(ApiTier::Premium) // Private scanning requires premium tier
        .build()?;

    println!("Testing VirusTotal Private File Scanning API");
    println!("=============================================");
    println!("⚠️  NOTE: Requires Private Scanning License");
    println!("=============================================\n");

    let private_client = client.private_files();

    // 1. Test small file upload (< 32MB) with parameters
    println!("1. SMALL FILE UPLOAD TEST");
    println!("-------------------------");

    // Create a test file for demonstration
    let test_content = b"This is a test file for private scanning";

    // Create upload parameters
    let upload_params = PrivateFileUploadParams::new()
        .disable_sandbox(false)
        .enable_internet(false)
        .retention_period_days(7)
        .storage_region("US".to_string())
        .locale("EN_US".to_string());

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
            println!("✓ File uploaded successfully");
            println!("  Analysis ID: {}", response.data.id);
            println!("  Type: {}", response.data.object_type);
            if let Some(links) = &response.data.links {
                println!("  Self link: {}", links.self_link);
            }

            // Wait a bit for analysis to start
            tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;

            // Try to get the analysis status
            println!("\nChecking analysis status...");
            match private_client
                .get_analysis(&response.data.id, &response.data.id)
                .await
            {
                Ok(analysis) => {
                    if let Some(status) = &analysis.object.attributes.status {
                        println!("  Status: {}", status);
                    }
                    if let Some(stats) = &analysis.object.attributes.stats {
                        println!("  Detection stats:");
                        if let Some(malicious) = stats.malicious {
                            println!("    - Malicious: {}", malicious);
                        }
                        if let Some(suspicious) = stats.suspicious {
                            println!("    - Suspicious: {}", suspicious);
                        }
                        if let Some(undetected) = stats.undetected {
                            println!("    - Undetected: {}", undetected);
                        }
                    }
                }
                Err(e) => {
                    println!("  Could not get analysis status: {}", e);
                }
            }
        }
        Err(e) => {
            println!("✗ Error uploading file: {}", e);
            println!("  Note: Private scanning requires special API privileges");
        }
    }

    // 2. Test large file upload URL creation (> 32MB)
    println!("\n2. LARGE FILE UPLOAD URL TEST");
    println!("------------------------------");

    println!("Creating upload URL for large files...");

    match private_client.create_upload_url().await {
        Ok(response) => {
            println!("✓ Upload URL created successfully");
            println!("  URL: {}", &response.data[..50.min(response.data.len())]);
            println!("  (URL truncated for display)");
            println!("\n  To upload a large file:");
            println!("  1. PUT your file data to the provided URL");
            println!("  2. The response will contain the analysis ID");
        }
        Err(e) => {
            println!("✗ Error creating upload URL: {}", e);
        }
    }

    // 3. Test listing private files
    println!("\n3. LIST PRIVATE FILES");
    println!("---------------------");

    println!("Listing previously analyzed private files...");

    match private_client.list_files(Some(10), None).await {
        Ok(files) => {
            println!("✓ Retrieved {} private files", files.data.len());

            for file in files.data.iter().take(3) {
                println!("\n  File: {}", file.object.id);
                if let Some(size) = file.object.attributes.size {
                    println!("    Size: {} bytes", size);
                }
                if let Some(type_desc) = &file.object.attributes.type_description {
                    println!("    Type: {}", type_desc);
                }
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
                        &cursor[..20.min(cursor.len())]
                    );
                }
            }
        }
        Err(e) => {
            println!("✗ Error listing files: {}", e);
            println!("  Note: This requires private scanning privileges");
        }
    }

    // 4. Test file report retrieval
    println!("\n4. FILE REPORT RETRIEVAL");
    println!("------------------------");

    // Use a known file hash for testing (EICAR test file)
    let eicar_hash = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f";

    println!("Getting private file report for EICAR test file...");
    println!("  SHA256: {}", eicar_hash);

    match private_client.get_file(eicar_hash).await {
        Ok(file) => {
            println!("✓ File report retrieved");

            if let Some(type_desc) = &file.object.attributes.type_description {
                println!("  Type: {}", type_desc);
            }
            if let Some(size) = &file.object.attributes.size {
                println!("  Size: {} bytes", size);
            }
            if let Some(reputation) = &file.object.attributes.reputation {
                println!("  Reputation: {}", reputation);
            }
            if let Some(stats) = &file.object.attributes.last_analysis_stats {
                println!("  Last analysis stats:");
                if let Some(malicious) = stats.malicious {
                    println!("    - Malicious: {}", malicious);
                }
                if let Some(undetected) = stats.undetected {
                    println!("    - Undetected: {}", undetected);
                }
            }
        }
        Err(e) => {
            println!("✗ Error getting file report: {}", e);
            println!("  Note: This may require the file to be previously scanned privately");
        }
    }

    // 5. Test behavior analysis retrieval
    println!("\n5. BEHAVIOR ANALYSIS");
    println!("--------------------");

    println!("Getting behavior analysis for file...");

    match private_client
        .get_behaviors(eicar_hash, Some(5), None)
        .await
    {
        Ok(behaviors) => {
            println!("✓ Retrieved {} behavior reports", behaviors.data.len());

            for (i, behavior) in behaviors.data.iter().enumerate().take(3) {
                println!("\n  Behavior #{}", i + 1);
                if let Some(sandbox_name) = &behavior.data.attributes.sandbox_name {
                    println!("    Sandbox: {}", sandbox_name);
                }
                if let Some(analysis_date) = &behavior.data.attributes.analysis_date {
                    println!("    Date: {}", analysis_date);
                }
            }
        }
        Err(e) => {
            println!("✗ Error getting behaviors: {}", e);
        }
    }

    // 6. Test behavior summary
    println!("\n6. BEHAVIOR SUMMARY");
    println!("-------------------");

    match private_client.get_behavior_summary(eicar_hash).await {
        Ok(summary) => {
            println!("✓ Retrieved behavior summary");

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
        Err(e) => {
            println!("✗ Error getting behavior summary: {}", e);
        }
    }

    // 7. Test MITRE ATT&CK data
    println!("\n7. MITRE ATT&CK DATA");
    println!("--------------------");

    match private_client.get_mitre_attack_data(eicar_hash).await {
        Ok(mitre_data) => {
            println!("✓ Retrieved MITRE ATT&CK data");

            println!("  Sandboxes analyzed: {}", mitre_data.data.len());

            for (sandbox_name, sandbox_data) in mitre_data.data.iter().take(2) {
                println!("\n  Sandbox: {}", sandbox_name);

                println!("    Tactics: {}", sandbox_data.tactics.len());
                for tactic in sandbox_data.tactics.iter().take(3) {
                    println!("      - {} ({})", tactic.name, tactic.id);
                    if !tactic.techniques.is_empty() {
                        println!("        Techniques: {}", tactic.techniques.len());
                        for technique in tactic.techniques.iter().take(2) {
                            println!("          - {} ({})", technique.name, technique.id);
                        }
                    }
                }
            }
        }
        Err(e) => {
            println!("✗ Error getting MITRE ATT&CK data: {}", e);
        }
    }

    // 8. Test dropped files retrieval
    println!("\n8. DROPPED FILES");
    println!("----------------");

    match private_client
        .get_dropped_files(eicar_hash, Some(10), None)
        .await
    {
        Ok(dropped) => {
            if dropped.data.is_empty() {
                println!("  No dropped files found");
            } else {
                println!("✓ Found {} dropped files", dropped.data.len());

                for (i, file) in dropped.data.iter().enumerate().take(3) {
                    println!("\n  Dropped file #{}", i + 1);
                    if let Some(sha256) = &file.object.attributes.sha256 {
                        println!("    SHA256: {}", sha256);
                    }
                    if let Some(path) = &file.object.attributes.path {
                        println!("    Path: {}", path);
                    }
                    if let Some(size) = &file.object.attributes.size {
                        println!("    Size: {} bytes", size);
                    }
                }
            }
        }
        Err(e) => {
            println!("✗ Error getting dropped files: {}", e);
        }
    }

    // 9. Test re-analysis with parameters
    println!("\n9. RE-ANALYSIS");
    println!("--------------");

    println!("Requesting re-analysis of file with custom parameters...");

    let reanalyze_params = ReanalyzeParams::new()
        .enable_internet(true)
        .interaction_sandbox("cape".to_string())
        .interaction_timeout(120);

    match private_client
        .reanalyze(eicar_hash, Some(reanalyze_params))
        .await
    {
        Ok(analysis) => {
            println!("✓ Re-analysis requested");
            println!("  Analysis ID: {}", analysis.object.id);
            if let Some(status) = &analysis.object.attributes.status {
                println!("  Status: {}", status);
            }
        }
        Err(e) => {
            println!("✗ Error requesting re-analysis: {}", e);
        }
    }

    // 10. Test comment operations
    println!("\n10. COMMENTS");
    println!("------------");

    // Add a comment
    println!("Adding comment to file...");
    match private_client
        .add_comment(eicar_hash, "Test comment from private file scanning API")
        .await
    {
        Ok(comment) => {
            println!("✓ Comment added");
            println!("  Comment ID: {}", comment.object.id);
        }
        Err(e) => {
            println!("✗ Error adding comment: {}", e);
        }
    }

    // Get comments
    println!("\nRetrieving comments...");
    match private_client.get_comments(eicar_hash, Some(5), None).await {
        Ok(comments) => {
            println!("✓ Retrieved {} comments", comments.data.len());
            for comment in comments.data.iter().take(2) {
                println!(
                    "  - {}",
                    &comment.object.attributes.text[..50.min(comment.object.attributes.text.len())]
                );
            }
        }
        Err(e) => {
            println!("✗ Error getting comments: {}", e);
        }
    }

    // 11. Test file download
    println!("\n11. FILE DOWNLOAD");
    println!("-----------------");

    println!("Downloading file content...");
    match private_client.download(eicar_hash).await {
        Ok(file_bytes) => {
            println!("✓ File downloaded successfully");
            println!("  Size: {} bytes", file_bytes.len());
            println!(
                "  First 20 bytes (hex): {:02x?}",
                &file_bytes[..20.min(file_bytes.len())]
            );
        }
        Err(e) => {
            println!("✗ Error downloading file: {}", e);
            println!("  Note: File download may require special permissions");
        }
    }

    // 12. Test pagination with analyses
    println!("\n12. ANALYSES PAGINATION");
    println!("------------------------");

    println!("Getting analysis history with pagination...");
    let mut analyses_iterator = private_client.get_analyses_iterator(eicar_hash);

    match analyses_iterator.next_batch().await {
        Ok(batch) => {
            println!("✓ Retrieved {} analyses in first batch", batch.len());
            for analysis in batch.iter().take(2) {
                println!("  - Analysis ID: {}", analysis.object.id);
                if let Some(date) = &analysis.object.attributes.date {
                    println!("    Date: {}", date);
                }
                if let Some(status) = &analysis.object.attributes.status {
                    println!("    Status: {}", status);
                }
            }
        }
        Err(e) => {
            println!("✗ Error fetching analyses: {}", e);
        }
    }

    // 13. Test relationships
    println!("\n13. FILE RELATIONSHIPS");
    println!("-----------------------");

    println!("Getting file relationships...");

    // Try to get similar files
    match private_client
        .get_relationship::<serde_json::Value>(eicar_hash, "similar_files", Some(5), None)
        .await
    {
        Ok(similar) => {
            println!("✓ Found {} similar files", similar.data.len());
        }
        Err(e) => {
            println!("✗ Error getting similar files: {}", e);
        }
    }

    // Try to get contacted domains
    match private_client
        .get_relationship::<serde_json::Value>(eicar_hash, "contacted_domains", Some(5), None)
        .await
    {
        Ok(domains) => {
            println!("✓ Found {} contacted domains", domains.data.len());
        }
        Err(e) => {
            println!("✗ Error getting contacted domains: {}", e);
        }
    }

    // Get relationship descriptors (just IDs)
    println!("\nGetting relationship descriptors...");
    match private_client
        .get_relationship_descriptors(eicar_hash, "contacted_urls", Some(5), None)
        .await
    {
        Ok(descriptors) => {
            println!("✓ Found {} URL descriptors", descriptors.data.len());
            for descriptor in descriptors.data.iter().take(2) {
                if let Some(id) = descriptor.get("id") {
                    println!("  - ID: {}", id);
                }
            }
        }
        Err(e) => {
            println!("✗ Error getting URL descriptors: {}", e);
        }
    }

    // 14. Test file deletion
    println!("\n14. FILE DELETION");
    println!("-----------------");

    // Note: Be careful with this in production!
    // This would delete the file and all associated data
    println!("Testing delete functionality (dry run - not actually deleting)...");

    // Example of how to delete (commented out to prevent accidental deletion)
    /*
    match private_client.delete_file(eicar_hash, false).await {
        Ok(_) => {
            println!("✓ File and all associated data deleted");
        }
        Err(e) => {
            println!("✗ Error deleting file: {}", e);
        }
    }

    // Delete only from storage, keep reports
    match private_client.delete_file(eicar_hash, true).await {
        Ok(_) => {
            println!("✓ File deleted from storage (reports kept)");
        }
        Err(e) => {
            println!("✗ Error deleting file from storage: {}", e);
        }
    }
    */

    println!("  Delete functionality available with:");
    println!("    - delete_file(sha256, false) - Delete file and all data");
    println!("    - delete_file(sha256, true)  - Delete only from storage, keep reports");

    // 15. Important notes about SHA-256 requirement
    println!("\n15. IMPORTANT NOTES");
    println!("-------------------");

    println!("⚠️  SHA-256 ONLY: Private file endpoints only accept SHA-256 hashes");
    println!("   MD5 and SHA-1 are NOT supported (unlike public file endpoints)");
    println!("   Example SHA-256: {}", eicar_hash);
    println!("   Length: {} characters", eicar_hash.len());

    println!("\n=============================================");
    println!("Private File Scanning API Testing Complete!");
    println!("\nNOTE: Many features require a Private Scanning License.");
    println!("Without proper privileges, most operations will fail.");

    Ok(())
}
