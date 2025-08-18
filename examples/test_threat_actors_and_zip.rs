use virustotal_rs::{
    ApiTier, ClientBuilder, CreateReferenceRequest, CreateZipFileRequest, RelationshipOrder,
    ThreatActorOrder, ZipFileStatus,
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let api_key = std::env::var("VT_API_KEY").unwrap_or_else(|_| "test_key".to_string());

    let client = ClientBuilder::new()
        .api_key(api_key)
        .tier(ApiTier::Premium) // These APIs require premium privileges
        .build()?;

    println!("Testing Threat Actors, References, and ZIP Files APIs");
    println!("====================================================\n");

    // 1. Test Threat Actors API
    println!("1. THREAT ACTORS API");
    println!("--------------------");

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
        Ok(actors) => {
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
        Err(e) => {
            println!("   ✗ Error listing threat actors: {}", e);
            println!("   Note: This API requires Threat Landscape module privileges");
        }
    }

    // Get a specific threat actor
    println!("\nGetting APT1 threat actor:");
    match threat_actors_client.get("APT1").await {
        Ok(actor) => {
            println!("   ✓ Retrieved threat actor");
            if let Some(name) = &actor.object.attributes.name {
                println!("   - Name: {}", name);
            }
            if let Some(description) = &actor.object.attributes.description {
                println!(
                    "   - Description: {}",
                    &description[..100.min(description.len())]
                );
            }
            if let Some(source_region) = &actor.object.attributes.source_region {
                println!("   - Source region: {}", source_region);
            }
            if let Some(targeted_regions) = &actor.object.attributes.targeted_regions {
                println!("   - Targeted regions: {}", targeted_regions.join(", "));
            }
            if let Some(targeted_industries) = &actor.object.attributes.targeted_industries {
                println!(
                    "   - Targeted industries: {}",
                    targeted_industries.join(", ")
                );
            }
            if let Some(related_count) = &actor.object.attributes.related_entities_count {
                println!("   - Related entities: {}", related_count);
            }
        }
        Err(e) => {
            println!("   ✗ Error getting threat actor: {}", e);
        }
    }

    // Get related objects
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
        Err(e) => {
            println!("   ✗ Error getting related files: {}", e);
        }
    }

    // 2. Test References API
    println!("\n2. REFERENCES API");
    println!("-----------------");

    let references_client = client.references();

    // Create a reference (requires special privileges)
    println!("\nCreating a new reference:");
    let reference_request = CreateReferenceRequest::new(
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
    ]);

    match references_client.create(&reference_request).await {
        Ok(reference) => {
            println!("   ✓ Reference created successfully");
            println!("   - ID: {}", reference.object.id);

            // Get the reference
            println!("\nGetting the reference:");
            match references_client.get(&reference.object.id).await {
                Ok(ref_data) => {
                    println!("   ✓ Retrieved reference");
                    if let Some(title) = &ref_data.object.attributes.title {
                        println!("   - Title: {}", title);
                    }
                    if let Some(url) = &ref_data.object.attributes.url {
                        println!("   - URL: {}", url);
                    }
                }
                Err(e) => println!("   ✗ Error getting reference: {}", e),
            }

            // Delete the reference
            println!("\nDeleting the reference:");
            match references_client.delete(&reference.object.id).await {
                Ok(_) => println!("   ✓ Reference deleted successfully"),
                Err(e) => println!("   ✗ Error deleting reference: {}", e),
            }
        }
        Err(e) => {
            println!("   ✗ Error creating reference: {}", e);
            println!(
                "   Note: Creating references requires special VT partner/contributor privileges"
            );
        }
    }

    // 3. Test ZIP Files API
    println!("\n3. ZIP FILES API");
    println!("----------------");

    let zip_files_client = client.zip_files();

    // Create a ZIP file with sample hashes
    println!("\nCreating a password-protected ZIP file:");
    let zip_request = CreateZipFileRequest::new_with_password(
        vec![
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".to_string(), // Empty file SHA256
            "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f".to_string(),
        ],
        "infected".to_string(), // Standard malware archive password
    );

    match zip_files_client.create(&zip_request).await {
        Ok(zip_file) => {
            println!("   ✓ ZIP file creation started");
            println!("   - ID: {}", zip_file.object.id);

            // Check status
            println!("\nChecking ZIP file status:");
            let zip_id = &zip_file.object.id;

            // Poll status a few times
            for i in 0..3 {
                tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;

                match zip_files_client.get_status(zip_id).await {
                    Ok(status) => {
                        if let Some(file_status) = &status.object.attributes.status {
                            print!("   - Attempt {}: Status = {:?}", i + 1, file_status);
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
        }
        Err(e) => {
            println!("   ✗ Error creating ZIP file: {}", e);
            println!("   Note: This may be due to invalid hashes or API key limitations");
        }
    }

    // Test convenience method
    println!("\nTesting wait_for_completion convenience method:");
    let another_zip_request = CreateZipFileRequest::new(vec![
        "d41d8cd98f00b204e9800998ecf8427e".to_string(), // Empty file MD5
    ])
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

    println!("\n====================================================");
    println!("Testing complete!");

    Ok(())
}
