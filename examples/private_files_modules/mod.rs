use virustotal_rs::ApiTier;

mod constants;
mod display_utils;
mod upload_operations;
mod file_operations;
mod analysis_operations;
mod management_operations;

pub use constants::*;
pub use upload_operations::*;
pub use file_operations::*;
pub use analysis_operations::*;
pub use management_operations::*;

use crate::common::*;

/// Test file operations (wrapper function)
async fn test_file_operations(private_client: &virustotal_rs::PrivateFilesClient<'_>) {
    test_file_report(private_client, EICAR_HASH).await;
    test_behavior_analysis(private_client, EICAR_HASH).await;
    test_behavior_summary(private_client, EICAR_HASH).await;
    test_mitre_attack_data(private_client, EICAR_HASH).await;
    test_dropped_files(private_client, EICAR_HASH).await;
}

/// Test file management operations (wrapper function)
async fn test_file_management(private_client: &virustotal_rs::PrivateFilesClient<'_>) {
    test_reanalysis(private_client, EICAR_HASH).await;
    test_comments(private_client, EICAR_HASH).await;
    test_file_download(private_client, EICAR_HASH).await;
    test_pagination(private_client, EICAR_HASH).await;
    test_relationships(private_client, EICAR_HASH).await;
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

/// Main function for private files testing
pub async fn run_private_files_test() -> crate::common::ExampleResult<()> {
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