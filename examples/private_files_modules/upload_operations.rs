use super::display_utils::print_analysis_stats;
use crate::common::*;
use virustotal_rs::PrivateFileUploadParams;

/// Create upload parameters for private file scanning
pub fn create_upload_params() -> PrivateFileUploadParams {
    PrivateFileUploadParams::new()
        .disable_sandbox(false)
        .enable_internet(false)
        .retention_period_days(7)
        .storage_region("US".to_string())
        .locale("EN_US".to_string())
}

/// Test small file upload with parameters
pub async fn test_file_upload(private_client: &virustotal_rs::PrivateFilesClient<'_>) {
    print_step_header(1, "SMALL FILE UPLOAD TEST");

    let test_content = b"This is a test file for private scanning";
    let upload_params = create_upload_params();

    print_upload_info(test_content.len());

    match upload_test_file(private_client, test_content, upload_params).await {
        Ok(response) => {
            print_upload_success(&response);
            tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
            check_analysis_status(private_client, &response.data.id).await;
        }
        Err(e) => print_upload_error(&e),
    }
}

/// Print upload information
pub fn print_upload_info(content_len: usize) {
    println!(
        "Uploading small test file ({} bytes) with parameters...",
        content_len
    );
    println!("  - Sandbox: enabled");
    println!("  - Internet: disabled");
    println!("  - Retention: 7 days");
    println!("  - Storage: US");
}

/// Upload test file with parameters
pub async fn upload_test_file(
    private_client: &virustotal_rs::PrivateFilesClient<'_>,
    test_content: &[u8],
    upload_params: virustotal_rs::PrivateFileUploadParams,
) -> Result<virustotal_rs::PrivateFileUploadResponse, virustotal_rs::Error> {
    private_client
        .upload_file(test_content, Some(upload_params))
        .await
}

/// Print successful upload result
pub fn print_upload_success(response: &virustotal_rs::PrivateFileUploadResponse) {
    print_success("File uploaded successfully");
    println!("  Analysis ID: {}", response.data.id);
    println!("  Type: {}", response.data.object_type);
}

/// Print upload error
pub fn print_upload_error(error: &virustotal_rs::Error) {
    print_error(&format!("Error uploading file: {}", error));
    println!("  Note: Private scanning requires special API privileges");
}

/// Check analysis status for uploaded file
pub async fn check_analysis_status(
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
pub async fn test_upload_url_creation(private_client: &virustotal_rs::PrivateFilesClient<'_>) {
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
