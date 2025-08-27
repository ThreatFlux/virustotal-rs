use virustotal_rs::{
    ApiTier, ClientBuilder, CreateReferenceRequest, CreateZipFileRequest, RelationshipOrder,
    ThreatActorOrder, ZipFileStatus,
};

/// Prints a formatted section header
fn print_section_header(number: u32, title: &str) {
    println!("\n{}. {}", number, title);
    println!("{}", "-".repeat(title.len() + 4));
}

/// Displays threat actor list information
fn display_threat_actors_list(
    actors: &virustotal_rs::objects::Collection<virustotal_rs::ThreatActor>,
) {
    println!("   ✓ Retrieved threat actors");
    if let Some(meta) = &actors.meta {
        if let Some(count) = meta.count {
            println!("   - Total threat actors: {}", count);
        }
    }
    for actor in actors.data.iter().take(5) {
        if let Some(name) = &actor.object.attributes.name {
            print!("   - {}", name);
            if let Some(aliases) = &actor.object.attributes.aliases {
                if !aliases.is_empty() {
                    print!(" (aka: {})", aliases.join(", "));
                }
            }
            println!();
        }
    }
}

/// Displays detailed threat actor information
fn display_threat_actor_details(actor: &virustotal_rs::ThreatActor) {
    println!("   ✓ Retrieved threat actor");
    let attrs = &actor.object.attributes;

    if let Some(name) = &attrs.name {
        println!("   - Name: {}", name);
    }
    if let Some(description) = &attrs.description {
        println!(
            "   - Description: {}",
            &description[..100.min(description.len())]
        );
    }
    if let Some(source_region) = &attrs.source_region {
        println!("   - Source region: {}", source_region);
    }
    if let Some(targeted_regions) = &attrs.targeted_regions {
        println!("   - Targeted regions: {}", targeted_regions.join(", "));
    }
    if let Some(targeted_industries) = &attrs.targeted_industries {
        println!(
            "   - Targeted industries: {}",
            targeted_industries.join(", ")
        );
    }
    if let Some(related_count) = &attrs.related_entities_count {
        println!("   - Related entities: {}", related_count);
    }
}

/// Tests threat actors API functionality
async fn test_threat_actors_api(
    client: &virustotal_rs::Client,
) -> Result<(), Box<dyn std::error::Error>> {
    print_section_header(1, "THREAT ACTORS API");
    let threat_actors_client = client.threat_actors();

    // List threat actors
    println!("\nListing threat actors:");
    match threat_actors_client
        .list(
            Some("targeted_region:US"),
            Some(ThreatActorOrder::LastSeenDateDesc),
            Some(10),
            None,
        )
        .await
    {
        Ok(actors) => display_threat_actors_list(&actors),
        Err(e) => {
            println!("   ✗ Error listing threat actors: {}", e);
            println!("   Note: This API requires Threat Landscape module privileges");
        }
    }

    // Get specific threat actor
    println!("\nGetting APT1 threat actor:");
    match threat_actors_client.get("APT1").await {
        Ok(actor) => display_threat_actor_details(&actor),
        Err(e) => println!("   ✗ Error getting threat actor: {}", e),
    }

    // Get related files
    println!("\nGetting related files for APT1:");
    match threat_actors_client
        .get_relationship::<serde_json::Value>(
            "APT1",
            "related_files",
            Some(RelationshipOrder::LastSubmissionDateDesc),
            Some(5),
            None,
        )
        .await
    {
        Ok(files) => {
            println!("   ✓ Retrieved related files");
            if let Some(meta) = &files.meta {
                if let Some(count) = meta.count {
                    println!("   - Total related files: {}", count);
                }
            }
        }
        Err(e) => println!("   ✗ Error getting related files: {}", e),
    }

    Ok(())
}

/// Creates a sample reference request
fn create_sample_reference_request() -> CreateReferenceRequest {
    CreateReferenceRequest::new(
        "APT Campaign Analysis Report".to_string(),
        "https://example.com/apt-report".to_string(),
    )
    .with_description("Detailed analysis of recent APT campaign".to_string())
    .with_author("Security Research Team".to_string())
    .with_source("Example Security Lab".to_string())
    .with_tags(vec![
        "apt".to_string(),
        "malware".to_string(),
        "analysis".to_string(),
    ])
}

/// Helper function to create a reference
async fn create_reference(
    references_client: &virustotal_rs::ReferencesClient<'_>,
    reference_request: &CreateReferenceRequest,
) -> Result<String, Box<dyn std::error::Error>> {
    match references_client.create(reference_request).await {
        Ok(reference) => {
            println!("   ✓ Reference created successfully");
            println!("   - ID: {}", reference.object.id);
            Ok(reference.object.id)
        }
        Err(e) => {
            println!("   ✗ Error creating reference: {}", e);
            println!(
                "   Note: Creating references requires special VT partner/contributor privileges"
            );
            Err(e.into())
        }
    }
}

/// Helper function to retrieve and display a reference
async fn get_and_display_reference(
    references_client: &virustotal_rs::ReferencesClient<'_>,
    ref_id: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    println!("\nGetting the reference:");
    match references_client.get(ref_id).await {
        Ok(ref_data) => {
            println!("   ✓ Retrieved reference");
            if let Some(title) = &ref_data.object.attributes.title {
                println!("   - Title: {}", title);
            }
            if let Some(url) = &ref_data.object.attributes.url {
                println!("   - URL: {}", url);
            }
            Ok(())
        }
        Err(e) => {
            println!("   ✗ Error getting reference: {}", e);
            Err(e.into())
        }
    }
}

/// Helper function to delete a reference
async fn delete_reference(
    references_client: &virustotal_rs::ReferencesClient<'_>,
    ref_id: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    println!("\nDeleting the reference:");
    match references_client.delete(ref_id).await {
        Ok(_) => {
            println!("   ✓ Reference deleted successfully");
            Ok(())
        }
        Err(e) => {
            println!("   ✗ Error deleting reference: {}", e);
            Err(e.into())
        }
    }
}

/// Tests the full reference lifecycle (create, get, delete)
async fn test_reference_lifecycle(
    references_client: &virustotal_rs::ReferencesClient<'_>,
    reference_request: &CreateReferenceRequest,
) -> Result<(), Box<dyn std::error::Error>> {
    if let Ok(ref_id) = create_reference(references_client, reference_request).await {
        let _ = get_and_display_reference(references_client, &ref_id).await;
        let _ = delete_reference(references_client, &ref_id).await;
    }
    Ok(())
}

/// Tests references API functionality
async fn test_references_api(
    client: &virustotal_rs::Client,
) -> Result<(), Box<dyn std::error::Error>> {
    print_section_header(2, "REFERENCES API");
    let references_client = client.references();
    let reference_request = create_sample_reference_request();

    println!("\nCreating a new reference:");
    test_reference_lifecycle(&references_client, &reference_request).await?;
    Ok(())
}

/// Displays ZIP file status information
fn display_zip_status(status: &virustotal_rs::ZipFile, attempt: usize) -> Option<&ZipFileStatus> {
    if let Some(file_status) = &status.object.attributes.status {
        print!("   - Attempt {}: Status = {:?}", attempt + 1, file_status);
        if let Some(progress) = &status.object.attributes.progress {
            print!(", Progress = {}%", progress);
        }
        if let Some(files_ok) = &status.object.attributes.files_ok {
            print!(", Files OK = {}", files_ok);
        }
        if let Some(files_error) = &status.object.attributes.files_error {
            print!(", Files Error = {}", files_error);
        }
        println!();
        Some(file_status)
    } else {
        None
    }
}

/// Polls ZIP file status and handles completion
async fn poll_zip_status(
    zip_files_client: &virustotal_rs::ZipFilesClient<'_>,
    zip_id: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    for i in 0..3 {
        tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;

        match zip_files_client.get_status(zip_id).await {
            Ok(status) => {
                if let Some(file_status) = display_zip_status(&status, i) {
                    if file_status == &ZipFileStatus::Finished {
                        println!("   ✓ ZIP file creation completed!");

                        // Get download URL
                        println!("\nGetting download URL:");
                        match zip_files_client.get_download_url(zip_id).await {
                            Ok(url_response) => {
                                println!("   ✓ Download URL obtained");
                                println!(
                                    "   - URL: {}",
                                    &url_response.data[..50.min(url_response.data.len())]
                                );
                                println!("   - Note: URL expires after 1 hour");
                            }
                            Err(e) => println!("   ✗ Error getting download URL: {}", e),
                        }
                        break;
                    } else if matches!(
                        file_status,
                        ZipFileStatus::Timeout
                            | ZipFileStatus::ErrorStarting
                            | ZipFileStatus::ErrorCreating
                    ) {
                        println!("   ✗ ZIP file creation failed");
                        break;
                    }
                }
            }
            Err(e) => {
                println!("   ✗ Error checking status: {}", e);
                break;
            }
        }
    }
    Ok(())
}

/// Tests ZIP files API functionality
async fn test_zip_files_api(
    client: &virustotal_rs::Client,
) -> Result<(), Box<dyn std::error::Error>> {
    print_section_header(3, "ZIP FILES API");
    let zip_files_client = client.zip_files();

    // Create ZIP file with status polling
    println!("\nCreating a password-protected ZIP file:");
    let zip_request = CreateZipFileRequest::new_with_password(
        vec![
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".to_string(),
            "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f".to_string(),
        ],
        "infected".to_string(),
    );

    match zip_files_client.create(&zip_request).await {
        Ok(zip_file) => {
            println!("   ✓ ZIP file creation started");
            println!("   - ID: {}", zip_file.object.id);
            println!("\nChecking ZIP file status:");
            poll_zip_status(&zip_files_client, &zip_file.object.id).await?;
        }
        Err(e) => {
            println!("   ✗ Error creating ZIP file: {}", e);
            println!("   Note: This may be due to invalid hashes or API key limitations");
        }
    }

    // Test convenience method
    println!("\nTesting wait_for_completion convenience method:");
    let another_zip_request =
        CreateZipFileRequest::new(vec!["d41d8cd98f00b204e9800998ecf8427e".to_string()])
            .with_password("password123".to_string());

    match zip_files_client.create(&another_zip_request).await {
        Ok(zip_file) => {
            println!("   - ZIP file ID: {}", zip_file.object.id);
            println!("   - Waiting for completion (max 10 seconds)...");

            match zip_files_client
                .wait_for_completion(&zip_file.object.id, Some(10))
                .await
            {
                Ok(final_status) => {
                    if let Some(status) = &final_status.object.attributes.status {
                        println!("   ✓ Final status: {:?}", status);
                    }
                }
                Err(e) => println!("   ✗ Error waiting for completion: {}", e),
            }
        }
        Err(e) => println!("   ✗ Error creating second ZIP file: {}", e),
    }

    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let api_key = std::env::var("VT_API_KEY").unwrap_or_else(|_| "test_key".to_string());
    let client = ClientBuilder::new()
        .api_key(api_key)
        .tier(ApiTier::Premium)
        .build()?;

    println!("Testing Threat Actors, References, and ZIP Files APIs");
    println!("====================================================");

    test_threat_actors_api(&client).await?;
    test_references_api(&client).await?;
    test_zip_files_api(&client).await?;

    println!("\n====================================================");
    println!("Testing complete!");
    Ok(())
}
