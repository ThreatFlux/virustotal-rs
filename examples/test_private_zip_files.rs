use virustotal_rs::{ApiTier, ClientBuilder, CreatePrivateZipRequest, PrivateFilesClient};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

/// Create and process a password-protected ZIP file
async fn test_password_protected_zip(private_files: &PrivateFilesClient<'_>) -> Result<()> {
    println!("1. CREATE PASSWORD-PROTECTED ZIP");
    println!("---------------------------------");

    let hashes = get_sample_hashes();
    let request = CreatePrivateZipRequest::new(hashes.clone())
        .with_password("mysecretpassword123".to_string());

    println!("Creating ZIP file with:");
    println!("  - {} files", request.data.hashes.len());
    println!("  - Password protection: Yes");

    match private_files.create_zip(&request).await {
        Ok(zip_file) => {
            println!("✓ ZIP file creation initiated");
            println!("  ZIP ID: {}", zip_file.data.id);
            println!("  Status: {}", zip_file.data.attributes.status);
            println!("  Progress: {}%", zip_file.data.attributes.progress);

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

/// Process the complete ZIP workflow: status check, wait, download
async fn process_zip_workflow(private_files: &PrivateFilesClient<'_>, zip_id: &str) -> Result<()> {
    check_zip_status(private_files, zip_id).await?;
    wait_for_completion(private_files, zip_id).await?;
    Ok(())
}

/// Check ZIP file status
async fn check_zip_status(private_files: &PrivateFilesClient<'_>, zip_id: &str) -> Result<()> {
    println!("\n2. CHECK ZIP STATUS");
    println!("-------------------");

    tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;

    match private_files.get_zip_status(zip_id).await {
        Ok(status) => {
            println!("✓ Retrieved ZIP status");
            println!("  Status: {}", status.data.attributes.status);
            println!("  Progress: {}%", status.data.attributes.progress);
            println!("  Files OK: {}", status.data.attributes.files_ok);
            println!("  Files Error: {}", status.data.attributes.files_error);
        }
        Err(e) => {
            println!("✗ Error checking status: {}", e);
        }
    }

    Ok(())
}

/// Wait for ZIP completion and handle download
async fn wait_for_completion(private_files: &PrivateFilesClient<'_>, zip_id: &str) -> Result<()> {
    println!("\n3. WAIT FOR COMPLETION");
    println!("----------------------");

    println!("Waiting for ZIP file to be ready (max 60 seconds)...");

    match private_files
        .wait_for_zip_completion(zip_id, Some(60))
        .await
    {
        Ok(completed) => {
            println!("✓ ZIP file ready!");
            println!("  Final status: {}", completed.data.attributes.status);
            println!("  Files processed: {}", completed.data.attributes.files_ok);
            handle_download(private_files, zip_id).await?;
        }
        Err(e) => {
            println!("✗ Error waiting for completion: {}", e);
            println!("  The ZIP may still be processing or have encountered an error");
        }
    }

    Ok(())
}

/// Handle ZIP download process
async fn handle_download(private_files: &PrivateFilesClient<'_>, zip_id: &str) -> Result<()> {
    println!("\n4. GET DOWNLOAD URL");
    println!("-------------------");

    match private_files.get_zip_download_url(zip_id).await {
        Ok(url_response) => {
            println!("✓ Got download URL");
            println!(
                "  URL: {}...",
                &url_response.data[..50.min(url_response.data.len())]
            );
            println!("  (URL expires in 1 hour)");
            download_zip_file(private_files, zip_id).await?;
        }
        Err(e) => {
            println!("✗ Error getting download URL: {}", e);
        }
    }

    Ok(())
}

/// Download ZIP file
async fn download_zip_file(private_files: &PrivateFilesClient<'_>, zip_id: &str) -> Result<()> {
    println!("\n5. DOWNLOAD ZIP FILE");
    println!("--------------------");

    match private_files.download_zip(zip_id).await {
        Ok(zip_bytes) => {
            println!("✓ Downloaded ZIP file");
            println!("  Size: {} bytes", zip_bytes.len());
            // In production, you would save this to a file
            // std::fs::write("downloaded_files.zip", zip_bytes)?;
        }
        Err(e) => {
            println!("✗ Error downloading ZIP: {}", e);
        }
    }

    Ok(())
}

/// Test creating ZIP without password
async fn test_simple_zip(private_files: &PrivateFilesClient<'_>) -> Result<()> {
    println!("\n6. CREATE ZIP WITHOUT PASSWORD");
    println!("------------------------------");

    let simple_request = CreatePrivateZipRequest::new(vec![
        "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f".to_string(),
    ]);

    println!("Creating simple ZIP file (no password)...");

    match private_files.create_zip(&simple_request).await {
        Ok(zip_file) => {
            println!("✓ Simple ZIP creation initiated");
            println!("  ZIP ID: {}", zip_file.data.id);
            println!("  Status: {}", zip_file.data.attributes.status);
        }
        Err(e) => {
            println!("✗ Error creating simple ZIP: {}", e);
        }
    }

    Ok(())
}

/// Demonstrate builder pattern usage
fn test_builder_pattern() {
    println!("\n7. ZIP REQUEST BUILDER");
    println!("----------------------");

    let builder_request = CreatePrivateZipRequest::new(vec![])
        .add_hash("abc123def456789".to_string())
        .add_hash("def456abc789123".to_string())
        .add_hashes(vec![
            "111222333444555".to_string(),
            "666777888999000".to_string(),
        ])
        .with_password("builder_password".to_string());

    println!("Built request with:");
    println!("  - {} hashes", builder_request.data.hashes.len());
    println!("  - Password: {}", builder_request.data.password.is_some());

    for (i, hash) in builder_request.data.hashes.iter().enumerate() {
        println!("    {}. {}", i + 1, hash);
    }
}

/// Test error handling scenarios
async fn test_error_handling(private_files: &PrivateFilesClient<'_>) -> Result<()> {
    println!("\n8. ERROR HANDLING");
    println!("-----------------");

    // Check status of non-existent ZIP
    println!("Checking non-existent ZIP ID...");
    match private_files.get_zip_status("invalid_zip_id_12345").await {
        Ok(_) => println!("  Unexpected success"),
        Err(e) => println!("  Expected error: {}", e),
    }

    // Try to download before ready
    println!("\nTrying to download non-existent ZIP...");
    match private_files.download_zip("not_ready_zip_id").await {
        Ok(_) => println!("  Unexpected success"),
        Err(e) => println!("  Expected error: {}", e),
    }

    Ok(())
}

/// Print API documentation and usage notes
fn print_api_documentation() {
    println!("\n9. IMPORTANT NOTES");
    println!("------------------");

    println!("📦 ZIP File Creation:");
    println!("  - Supports SHA-256, SHA-1, and MD5 hashes");
    println!("  - Optional password protection");
    println!("  - Asynchronous processing");
    println!("  - Check status before downloading");

    println!("\n⏱️ Status Values:");
    println!("  - starting: Initial state");
    println!("  - creating: ZIP being generated");
    println!("  - finished: Ready for download");
    println!("  - timeout: Operation timed out");
    println!("  - error-starting: Failed to start");
    println!("  - error-creating: Failed during creation");

    println!("\n📥 Download:");
    println!("  - Download URL expires after 1 hour");
    println!("  - URL can be reused during validity period");
    println!("  - Direct download returns file bytes");

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
    // NOTE: Private ZIP file creation requires special privileges
    let api_key = std::env::var("VT_PRIVATE_API_KEY")
        .or_else(|_| std::env::var("VT_API_KEY"))
        .unwrap_or_else(|_| "test_key".to_string());

    let client = ClientBuilder::new()
        .api_key(api_key)
        .tier(ApiTier::Premium)
        .build()?;

    print_header();

    let private_files = client.private_files();

    // Execute all test scenarios
    test_password_protected_zip(&private_files).await?;
    test_simple_zip(&private_files).await?;
    test_builder_pattern();
    test_error_handling(&private_files).await?;
    print_api_documentation();
    print_footer();

    Ok(())
}
