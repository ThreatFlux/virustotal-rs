use virustotal_rs::{
    ApiTier, CollectionItemsRequest, CollectionOrder, CreateCollectionRequest, DomainDescriptor,
    ExportFormat, UpdateCollectionRequest, UrlDescriptor,
};

mod common;
use common::*;

/// Create a sample collection with test data
async fn create_test_collection(
    collections_client: &virustotal_rs::CollectionsClient<'_>,
) -> ExampleResult<String> {
    print_test_header("1. Creating a new collection");

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
            print_success("Collection created successfully");
            if let Some(name) = &collection.object.attributes.name {
                println!("   - Name: {}", name);
            }
            println!("   - ID: {}", &collection.object.id);
            Ok(collection.object.id)
        }
        Err(e) => {
            print_error(&format!("Error creating collection: {}", e));
            println!("\n   Using mock collection ID for demonstration...");
            Ok("mock-collection-id".to_string())
        }
    }
}

/// List existing collections
async fn list_collections(collections_client: &virustotal_rs::CollectionsClient<'_>) {
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
            print_success("Retrieved collections");
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
            print_error(&format!("Error listing collections: {}", e));
            println!("   Note: This endpoint requires special Threat Landscape privileges");
        }
    }
}

/// Update an existing collection
async fn test_update_collection(
    client: &virustotal_rs::CollectionsClient<'_>,
    collection_id: &str,
) {
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
            print_success("Collection updated successfully");
            if let Some(name) = &updated.object.attributes.name {
                println!("   - New name: {}", name);
            }
        }
        Err(e) => print_error(&format!("Error updating collection: {}", e)),
    }
}

/// Add items to a collection
async fn test_add_items(client: &virustotal_rs::CollectionsClient<'_>, collection_id: &str) {
    println!("\n4. Adding items to collection");
    println!("-----------------------------");

    // Add domains
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
        Ok(_) => print_success("Added 2 new domains to collection"),
        Err(e) => print_error(&format!("Error adding domains: {}", e)),
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
        Ok(_) => print_success("Added 2 new URLs to collection"),
        Err(e) => print_error(&format!("Error adding URLs: {}", e)),
    }
}

/// Test comment management
async fn test_comment_management(
    client: &virustotal_rs::CollectionsClient<'_>,
    collection_id: &str,
) {
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
            print_success("Added comment to collection");
            println!("   - Comment: {}", &comment.object.attributes.text);
        }
        Err(e) => print_error(&format!("Error adding comment: {}", e)),
    }

    match client.get_comments(collection_id).await {
        Ok(comments) => {
            print_success("Retrieved comments");
            if let Some(meta) = &comments.meta {
                if let Some(count) = meta.count {
                    println!("   - Total comments: {}", count);
                }
            }
        }
        Err(e) => print_error(&format!("Error getting comments: {}", e)),
    }
}

/// Test relationship retrieval
async fn test_relationships(client: &virustotal_rs::CollectionsClient<'_>, collection_id: &str) {
    println!("\n6. Getting related objects");
    println!("--------------------------");

    match client
        .get_relationship::<serde_json::Value>(collection_id, "domains")
        .await
    {
        Ok(domains) => {
            print_success("Retrieved domains from collection");
            if let Some(meta) = &domains.meta {
                if let Some(count) = meta.count {
                    println!("   - Number of domains: {}", count);
                }
            }
        }
        Err(e) => print_error(&format!("Error getting domains: {}", e)),
    }

    match client
        .get_relationship::<serde_json::Value>(collection_id, "files")
        .await
    {
        Ok(files) => {
            print_success("Retrieved files from collection");
            if let Some(meta) = &files.meta {
                if let Some(count) = meta.count {
                    println!("   - Number of files: {}", count);
                }
            }
        }
        Err(e) => print_error(&format!("Error getting files: {}", e)),
    }
}

/// Test advanced collection operations
async fn test_advanced_operations(
    client: &virustotal_rs::CollectionsClient<'_>,
    collection_id: &str,
) {
    // Export collection
    println!("\n7. Exporting collection");
    println!("-----------------------");

    match client.export(collection_id, ExportFormat::Json).await {
        Ok(data) => {
            print_success("Exported collection to JSON");
            println!("   - Export size: {} bytes", data.len());
        }
        Err(e) => {
            print_error(&format!("Error exporting collection: {}", e));
            println!("   Note: Export requires special Threat Landscape privileges");
        }
    }

    // Search within collection
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
            print_success("Search completed");
            if let Some(meta) = &results.meta {
                if let Some(count) = meta.count {
                    println!("   - Results found: {}", count);
                }
            }
        }
        Err(e) => {
            print_error(&format!("Error searching collection: {}", e));
            println!("   Note: Search requires special Threat Landscape privileges");
        }
    }
}

/// Test item removal from collection
async fn test_remove_items(client: &virustotal_rs::CollectionsClient<'_>, collection_id: &str) {
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
        Ok(_) => print_success("Removed domain from collection"),
        Err(e) => print_error(&format!("Error removing domain: {}", e)),
    }
}

/// Execute all collection operations with the created collection
async fn execute_collection_operations(
    client: &virustotal_rs::CollectionsClient<'_>,
    collection_id: &str,
) {
    test_update_collection(client, collection_id).await;
    test_add_items(client, collection_id).await;
    test_comment_management(client, collection_id).await;
    test_relationships(client, collection_id).await;
    test_advanced_operations(client, collection_id).await;
    test_remove_items(client, collection_id).await;
}

#[tokio::main]
async fn main() -> ExampleResult<()> {
    let client = create_client_from_env("VT_API_KEY", ApiTier::Premium)?; // Collections API requires premium privileges

    print_header("Testing VirusTotal Collections API");

    let collections_client = client.collections();

    // Create collection and get its ID
    let collection_id = create_test_collection(&collections_client).await?;

    // Test collection operations
    execute_collection_operations(&collections_client, &collection_id).await;

    // List existing collections
    list_collections(&collections_client).await;

    println!("\n===================================");
    println!("Collections API testing complete!");

    Ok(())
}
