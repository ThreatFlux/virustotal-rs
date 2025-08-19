use virustotal_rs::{
    ApiTier, ClientBuilder, CollectionItemsRequest, CollectionOrder, CreateCollectionRequest,
    DomainDescriptor, ExportFormat, UpdateCollectionRequest, UrlDescriptor,
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let api_key = std::env::var("VT_API_KEY").unwrap_or_else(|_| "test_key".to_string());

    let client = ClientBuilder::new()
        .api_key(api_key)
        .tier(ApiTier::Premium) // Collections API requires premium privileges for some features
        .build()?;

    println!("Testing VirusTotal Collections API");
    println!("===================================\n");

    let collections_client = client.collections();

    // 1. Create a new collection
    println!("1. Creating a new collection");
    println!("-----------------------------");

    let create_request = CreateCollectionRequest::new(
        "APT Campaign IOCs".to_string(),
        Some("Collection of indicators from recent APT campaign".to_string()),
    )
    .with_domains(vec![
        "malicious-domain.com".to_string(),
        "c2-server.net".to_string(),
    ])
    .with_urls(vec!["https://phishing-site.com/payload".to_string()])
    .with_ip_addresses(vec!["192.168.1.100".to_string(), "10.0.0.5".to_string()])
    .with_files(vec![
        "abc123def456789012345678901234567890123456789012345678901234567".to_string(),
    ]);

    match collections_client.create(&create_request).await {
        Ok(collection) => {
            println!("   ✓ Collection created successfully");
            if let Some(name) = &collection.object.attributes.name {
                println!("   - Name: {}", name);
            }
            println!("   - ID: {}", &collection.object.id);

            // Store the ID for further operations
            test_collection_operations(&collections_client, &collection.object.id).await?;
        }
        Err(e) => {
            println!("   ✗ Error creating collection: {}", e);

            // Test with a mock collection ID
            println!("\n   Using mock collection ID for demonstration...");
            test_collection_operations(&collections_client, "mock-collection-id").await?;
        }
    }

    // 2. List collections (requires special privileges)
    println!("\n2. Listing collections");
    println!("----------------------");

    match collections_client
        .list(
            Some("threat_category:ransomware"),
            Some(CollectionOrder::CreationDateDesc),
            Some(10),
            None,
        )
        .await
    {
        Ok(collections) => {
            println!("   ✓ Retrieved collections");
            if let Some(meta) = &collections.meta {
                if let Some(count) = meta.count {
                    println!("   - Total collections: {}", count);
                }
            }
            for collection in collections.data.iter().take(5) {
                if let Some(name) = &collection.object.attributes.name {
                    println!("   - {}", name);
                }
            }
        }
        Err(e) => {
            println!("   ✗ Error listing collections: {}", e);
            println!("   Note: This endpoint requires special Threat Landscape privileges");
        }
    }

    println!("\n===================================");
    println!("Collections API testing complete!");

    Ok(())
}

async fn test_collection_operations(
    client: &virustotal_rs::CollectionsClient<'_>,
    collection_id: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    // 3. Update the collection
    println!("\n3. Updating collection");
    println!("----------------------");

    let update_request = UpdateCollectionRequest {
        data: virustotal_rs::collections::UpdateCollectionData {
            attributes: Some(virustotal_rs::collections::UpdateCollectionAttributes {
                name: Some("Updated APT Campaign IOCs".to_string()),
                description: Some("Updated description with new findings".to_string()),
            }),
            raw_items: Some("Additional IOCs: evil.com, 192.168.2.100".to_string()),
            object_type: "collection".to_string(),
        },
    };

    match client.update(collection_id, &update_request).await {
        Ok(updated) => {
            println!("   ✓ Collection updated successfully");
            if let Some(name) = &updated.object.attributes.name {
                println!("   - New name: {}", name);
            }
        }
        Err(e) => println!("   ✗ Error updating collection: {}", e),
    }

    // 4. Add items to the collection
    println!("\n4. Adding items to collection");
    println!("-----------------------------");

    let new_domains = CollectionItemsRequest {
        data: vec![
            DomainDescriptor {
                object_type: "domain".to_string(),
                id: "new-malicious.com".to_string(),
            },
            DomainDescriptor {
                object_type: "domain".to_string(),
                id: "another-c2.net".to_string(),
            },
        ],
    };

    match client
        .add_items(collection_id, "domains", &new_domains)
        .await
    {
        Ok(_) => println!("   ✓ Added 2 new domains to collection"),
        Err(e) => println!("   ✗ Error adding domains: {}", e),
    }

    // Add URLs using both methods (URL string and ID)
    let new_urls = CollectionItemsRequest {
        data: vec![
            UrlDescriptor::WithUrl {
                object_type: "url".to_string(),
                url: "https://another-phishing.com".to_string(),
            },
            UrlDescriptor::WithId {
                object_type: "url".to_string(),
                id: "f11f7cc900638fae209f68498a90158fbfb067fc4191549ddb657e39cc4428c2".to_string(),
            },
        ],
    };

    match client.add_items(collection_id, "urls", &new_urls).await {
        Ok(_) => println!("   ✓ Added 2 new URLs to collection"),
        Err(e) => println!("   ✗ Error adding URLs: {}", e),
    }

    // 5. Get comments on the collection
    println!("\n5. Managing comments");
    println!("--------------------");

    match client
        .add_comment(
            collection_id,
            "This collection contains high-priority IOCs #apt #critical",
        )
        .await
    {
        Ok(comment) => {
            println!("   ✓ Added comment to collection");
            println!("   - Comment: {}", &comment.object.attributes.text);
        }
        Err(e) => println!("   ✗ Error adding comment: {}", e),
    }

    match client.get_comments(collection_id).await {
        Ok(comments) => {
            println!("   ✓ Retrieved comments");
            if let Some(meta) = &comments.meta {
                if let Some(count) = meta.count {
                    println!("   - Total comments: {}", count);
                }
            }
        }
        Err(e) => println!("   ✗ Error getting comments: {}", e),
    }

    // 6. Get related objects
    println!("\n6. Getting related objects");
    println!("--------------------------");

    match client
        .get_relationship::<serde_json::Value>(collection_id, "domains")
        .await
    {
        Ok(domains) => {
            println!("   ✓ Retrieved domains from collection");
            if let Some(meta) = &domains.meta {
                if let Some(count) = meta.count {
                    println!("   - Number of domains: {}", count);
                }
            }
        }
        Err(e) => println!("   ✗ Error getting domains: {}", e),
    }

    match client
        .get_relationship::<serde_json::Value>(collection_id, "files")
        .await
    {
        Ok(files) => {
            println!("   ✓ Retrieved files from collection");
            if let Some(meta) = &files.meta {
                if let Some(count) = meta.count {
                    println!("   - Number of files: {}", count);
                }
            }
        }
        Err(e) => println!("   ✗ Error getting files: {}", e),
    }

    // 7. Export collection (requires special privileges)
    println!("\n7. Exporting collection");
    println!("-----------------------");

    match client.export(collection_id, ExportFormat::Json).await {
        Ok(data) => {
            println!("   ✓ Exported collection to JSON");
            println!("   - Export size: {} bytes", data.len());
        }
        Err(e) => {
            println!("   ✗ Error exporting collection: {}", e);
            println!("   Note: Export requires special Threat Landscape privileges");
        }
    }

    // 8. Search within collection (requires special privileges)
    println!("\n8. Searching within collection");
    println!("------------------------------");

    match client
        .search::<serde_json::Value>(
            collection_id,
            "entity:domain",
            Some("creation_date-"),
            Some(10),
            None,
        )
        .await
    {
        Ok(results) => {
            println!("   ✓ Search completed");
            if let Some(meta) = &results.meta {
                if let Some(count) = meta.count {
                    println!("   - Results found: {}", count);
                }
            }
        }
        Err(e) => {
            println!("   ✗ Error searching collection: {}", e);
            println!("   Note: Search requires special Threat Landscape privileges");
        }
    }

    // 9. Remove items from collection
    println!("\n9. Removing items from collection");
    println!("---------------------------------");

    let domains_to_remove = CollectionItemsRequest {
        data: vec![DomainDescriptor {
            object_type: "domain".to_string(),
            id: "malicious-domain.com".to_string(),
        }],
    };

    match client
        .remove_items(collection_id, "domains", &domains_to_remove)
        .await
    {
        Ok(_) => println!("   ✓ Removed domain from collection"),
        Err(e) => println!("   ✗ Error removing domain: {}", e),
    }

    Ok(())
}
