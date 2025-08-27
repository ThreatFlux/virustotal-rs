use super::display_utils::{print_analysis_stats, print_file_info};
use crate::common::*;

/// Test listing private files
pub async fn test_list_files(private_client: &virustotal_rs::PrivateFilesClient<'_>) {
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
pub fn display_file_list(files: &virustotal_rs::Collection<virustotal_rs::PrivateFile>) {
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

/// Test file report retrieval
pub async fn test_file_report(
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

/// Test file download
pub async fn test_file_download(
    private_client: &virustotal_rs::PrivateFilesClient<'_>,
    hash: &str,
) {
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
