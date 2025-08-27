use virustotal_rs::{ApiTier, CreatePrivateZipRequest, PrivateFilesClient};

mod common;
use common::{print_step_header, setup_client};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

/// Create and process a password-protected ZIP file
async fn test_password_protected_zip(private_files: &PrivateFilesClient<'_>) -> Result<()> {
    print_step_header(1, "CREATE PASSWORD-PROTECTED ZIP");

    let hashes = get_sample_hashes();
    let request = CreatePrivateZipRequest::new(hashes.clone())
        .with_password("mysecretpassword123".to_string());

    print_zip_creation_info(&request);

    match private_files.create_zip(&request).await {
        Ok(zip_file) => {
            display_zip_creation_result(&zip_file);
            let zip_id = zip_file.data.id.clone();
            process_zip_workflow(private_files, &zip_id).await?;
        }
        Err(e) => {
            println!("✗ Error creating ZIP file: {}", e);
            println!("  Note: This requires a Private Scanning License");
        }
    }

    Ok(())
}

fn print_zip_creation_info(request: &CreatePrivateZipRequest) {
    println!("Creating ZIP file with:");
    println!("  - {} files", request.data.hashes.len());
    println!("  - Password protection: Yes");
}

fn display_zip_creation_result(zip_file: &virustotal_rs::PrivateZipFile) {
    println!("✓ ZIP file creation initiated");
    println!("  ZIP ID: {}", zip_file.data.id);
    println!("  Status: {}", zip_file.data.attributes.status);
    println!("  Progress: {}%", zip_file.data.attributes.progress);
}

/// Process the complete ZIP workflow: status check, wait, download
async fn process_zip_workflow(private_files: &PrivateFilesClient<'_>, zip_id: &str) -> Result<()> {
    check_zip_status(private_files, zip_id).await?;
    wait_for_completion(private_files, zip_id).await?;
    Ok(())
}

/// Check ZIP file status
async fn check_zip_status(private_files: &PrivateFilesClient<'_>, zip_id: &str) -> Result<()> {
    print_step_header(2, "CHECK ZIP STATUS");

    tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;

    match private_files.get_zip_status(zip_id).await {
        Ok(status) => {
            display_zip_status(&status);
        }
        Err(e) => {
            println!("✗ Error checking status: {}", e);
        }
    }

    Ok(())
}

fn display_zip_status(status: &virustotal_rs::PrivateZipFile) {
    println!("✓ Retrieved ZIP status");
    println!("  Status: {}", status.data.attributes.status);
    println!("  Progress: {}%", status.data.attributes.progress);
    println!("  Files OK: {}", status.data.attributes.files_ok);
    println!("  Files Error: {}", status.data.attributes.files_error);
}

/// Wait for ZIP completion and handle download
async fn wait_for_completion(private_files: &PrivateFilesClient<'_>, zip_id: &str) -> Result<()> {
    print_step_header(3, "WAIT FOR COMPLETION");

    println!("Waiting for ZIP file to be ready (max 60 seconds)...");

    match private_files.wait_for_zip_completion(zip_id, 5, 2).await {
        Ok(completed) => {
            display_completion_status(&completed);
            handle_download(private_files, zip_id).await?;
        }
        Err(e) => {
            println!("✗ Error waiting for completion: {}", e);
            println!("  The ZIP may still be processing or have encountered an error");
        }
    }

    Ok(())
}

fn display_completion_status(completed: &virustotal_rs::PrivateZipFile) {
    println!("✓ ZIP file ready!");
    println!("  Final status: {}", completed.data.attributes.status);
    println!("  Files processed: {}", completed.data.attributes.files_ok);
}

/// Handle ZIP download process
async fn handle_download(private_files: &PrivateFilesClient<'_>, zip_id: &str) -> Result<()> {
    print_step_header(4, "GET DOWNLOAD URL");

    match private_files.get_zip_download_url(zip_id).await {
        Ok(url_response) => {
            display_download_url(&url_response.data);
            download_zip_file(private_files, zip_id).await?;
        }
        Err(e) => {
            println!("✗ Error getting download URL: {}", e);
        }
    }

    Ok(())
}

fn display_download_url(url: &str) {
    println!("✓ Got download URL");
    println!("  URL: {}...", &url[..50.min(url.len())]);
    println!("  (URL expires in 1 hour)");
}

/// Download ZIP file
async fn download_zip_file(private_files: &PrivateFilesClient<'_>, zip_id: &str) -> Result<()> {
    print_step_header(5, "DOWNLOAD ZIP FILE");

    match private_files.download_zip(zip_id).await {
        Ok(zip_bytes) => {
            display_download_result(&zip_bytes);
        }
        Err(e) => {
            println!("✗ Error downloading ZIP: {}", e);
        }
    }

    Ok(())
}

fn display_download_result(zip_bytes: &[u8]) {
    println!("✓ Downloaded ZIP file");
    println!("  Size: {} bytes", zip_bytes.len());
    // In production, you would save this to a file
    // std::fs::write("downloaded_files.zip", zip_bytes)?;
}

/// Test creating ZIP without password
async fn test_simple_zip(private_files: &PrivateFilesClient<'_>) -> Result<()> {
    print_step_header(6, "CREATE ZIP WITHOUT PASSWORD");

    let simple_request = CreatePrivateZipRequest::new(vec![
        "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f".to_string(),
    ]);

    println!("Creating simple ZIP file (no password)...");

    match private_files.create_zip(&simple_request).await {
        Ok(zip_file) => {
            display_simple_zip_result(&zip_file);
        }
        Err(e) => {
            println!("✗ Error creating simple ZIP: {}", e);
        }
    }

    Ok(())
}

fn display_simple_zip_result(zip_file: &virustotal_rs::PrivateZipFile) {
    println!("✓ Simple ZIP creation initiated");
    println!("  ZIP ID: {}", zip_file.data.id);
    println!("  Status: {}", zip_file.data.attributes.status);
}

/// Demonstrate builder pattern usage
fn test_builder_pattern() {
    print_step_header(7, "ZIP REQUEST BUILDER");

    let builder_request = create_sample_builder_request();
    display_builder_result(&builder_request);
}

fn create_sample_builder_request() -> CreatePrivateZipRequest {
    CreatePrivateZipRequest::new(vec![])
        .add_hash("abc123def456789".to_string())
        .add_hash("def456abc789123".to_string())
        .add_hashes(vec![
            "111222333444555".to_string(),
            "666777888999000".to_string(),
        ])
        .with_password("builder_password".to_string())
}

fn display_builder_result(builder_request: &CreatePrivateZipRequest) {
    println!("Built request with:");
    println!("  - {} hashes", builder_request.data.hashes.len());
    println!("  - Password: {}", builder_request.data.password.is_some());

    for (i, hash) in builder_request.data.hashes.iter().enumerate() {
        println!("    {}. {}", i + 1, hash);
    }
}

/// Test error handling scenarios
async fn test_error_handling(private_files: &PrivateFilesClient<'_>) -> Result<()> {
    print_step_header(8, "ERROR HANDLING");

    test_invalid_zip_status(private_files).await;
    test_invalid_zip_download(private_files).await;

    Ok(())
}

async fn test_invalid_zip_status(private_files: &PrivateFilesClient<'_>) {
    println!("Checking non-existent ZIP ID...");
    match private_files.get_zip_status("invalid_zip_id_12345").await {
        Ok(_) => println!("  Unexpected success"),
        Err(e) => println!("  Expected error: {}", e),
    }
}

async fn test_invalid_zip_download(private_files: &PrivateFilesClient<'_>) {
    println!("\nTrying to download non-existent ZIP...");
    match private_files.download_zip("not_ready_zip_id").await {
        Ok(_) => println!("  Unexpected success"),
        Err(e) => println!("  Expected error: {}", e),
    }
}

/// Print API documentation and usage notes
fn print_api_documentation() {
    print_step_header(9, "IMPORTANT NOTES");

    print_zip_features();
    print_status_values();
    print_download_info();
    print_security_notes();
}

fn print_zip_features() {
    println!("📦 ZIP File Creation:");
    println!("  - Supports SHA-256, SHA-1, and MD5 hashes");
    println!("  - Optional password protection");
    println!("  - Asynchronous processing");
    println!("  - Check status before downloading");
}

fn print_status_values() {
    println!("\n⏱️ Status Values:");
    println!("  - starting: Initial state");
    println!("  - creating: ZIP being generated");
    println!("  - finished: Ready for download");
    println!("  - timeout: Operation timed out");
    println!("  - error-starting: Failed to start");
    println!("  - error-creating: Failed during creation");
}

fn print_download_info() {
    println!("\n📥 Download:");
    println!("  - Download URL expires after 1 hour");
    println!("  - URL can be reused during validity period");
    println!("  - Direct download returns file bytes");
}

fn print_security_notes() {
    println!("\n🔒 Security:");
    println!("  - Password-protected ZIPs for sensitive data");
    println!("  - Private files never exposed publicly");
    println!("  - Requires Private Scanning License");
}

/// Get sample hash values for testing
fn get_sample_hashes() -> Vec<String> {
    vec![
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".to_string(), // Empty file SHA256
        "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f".to_string(), // EICAR test file
        "ed1707bf39a62b0efd40e76f55409ee99db0289dc5027d0a5e5337b4e7a61ccc".to_string(), // Another test hash
    ]
}

/// Print header information
fn print_header() {
    println!("Testing VirusTotal Private ZIP Files API");
    println!("=========================================");
    println!("⚠️  NOTE: Requires Private Scanning License");
    println!("=========================================\n");
}

/// Print footer information
fn print_footer() {
    println!("\n=========================================");
    println!("Private ZIP Files API Testing Complete!");
    println!("\nNOTE: All operations require a Private Scanning License.");
    println!("Without proper privileges, operations will fail.");
}

#[tokio::main]
async fn main() -> Result<()> {
    let client = setup_client(ApiTier::Premium)?;

    print_header();
    let private_files = client.private_files();

    execute_all_tests(&private_files).await?;
    print_completion_info();

    Ok(())
}

async fn execute_all_tests(private_files: &PrivateFilesClient<'_>) -> Result<()> {
    test_password_protected_zip(private_files).await?;
    test_simple_zip(private_files).await?;
    test_builder_pattern();
    test_error_handling(private_files).await?;
    Ok(())
}

fn print_completion_info() {
    print_api_documentation();
    print_footer();
}
