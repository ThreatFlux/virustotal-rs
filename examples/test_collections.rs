use virustotal_rs::{
    ApiTier, CollectionItemsRequest, CollectionOrder, CreateCollectionRequest, DomainDescriptor,
    ExportFormat, UpdateCollectionRequest, UrlDescriptor,
};

mod common;
use common::*;

/// Create sample IOCs for the collection
fn create_sample_iocs() -> (
    Vec<String>, // domains
    Vec<String>, // urls
    Vec<String>, // ip_addresses
    Vec<String>, // files
) {
    let domains = vec![
        "malicious-domain.com".to_string(),
        "c2-server.net".to_string(),
    ];
    let urls = vec!["https://phishing-site.com/payload".to_string()];
    let ip_addresses = vec!["192.168.1.100".to_string(), "10.0.0.5".to_string()];
    let files = vec!["abc123def456789012345678901234567890123456789012345678901234567".to_string()];
    (domains, urls, ip_addresses, files)
}

/// Build collection creation request
fn build_collection_request() -> CreateCollectionRequest {
    let (domains, urls, ip_addresses, files) = create_sample_iocs();

    CreateCollectionRequest::new(
        "APT Campaign IOCs".to_string(),
        Some("Collection of indicators from recent APT campaign".to_string()),
    )
    .with_domains(domains)
    .with_urls(urls)
    .with_ip_addresses(ip_addresses)
    .with_files(files)
}

/// Handle collection creation result
fn handle_collection_creation_result(
    result: Result<virustotal_rs::IocCollection, virustotal_rs::Error>,
) -> ExampleResult<String> {
    match result {
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

/// Create a sample collection with test data
async fn create_test_collection(
    collections_client: &virustotal_rs::CollectionsClient<'_>,
) -> ExampleResult<String> {
    print_test_header("1. Creating a new collection");

    let create_request = build_collection_request();
    let result = collections_client.create(&create_request).await;
    handle_collection_creation_result(result)
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

/// Build collection update request
fn build_update_request() -> UpdateCollectionRequest {
    UpdateCollectionRequest {
        data: virustotal_rs::collections::UpdateCollectionData {
            attributes: Some(virustotal_rs::collections::UpdateCollectionAttributes {
                name: Some("Updated APT Campaign IOCs".to_string()),
                description: Some("Updated description with new findings".to_string()),
            }),
            raw_items: Some("Additional IOCs: evil.com, 192.168.2.100".to_string()),
            object_type: "collection".to_string(),
        },
    }
}

/// Handle collection update result
fn handle_update_result(result: Result<virustotal_rs::IocCollection, virustotal_rs::Error>) {
    match result {
        Ok(updated) => {
            print_success("Collection updated successfully");
            if let Some(name) = &updated.object.attributes.name {
                println!("   - New name: {}", name);
            }
        }
        Err(e) => print_error(&format!("Error updating collection: {}", e)),
    }
}

/// Update an existing collection
async fn test_update_collection(
    client: &virustotal_rs::CollectionsClient<'_>,
    collection_id: &str,
) {
    println!("\n3. Updating collection");
    println!("----------------------");

    let update_request = build_update_request();
    let result = client.update(collection_id, &update_request).await;
    handle_update_result(result);
}

/// Create domain items for collection
fn create_domain_items() -> CollectionItemsRequest<DomainDescriptor> {
    CollectionItemsRequest {
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
    }
}

/// Create URL items for collection
fn create_url_items() -> CollectionItemsRequest<UrlDescriptor> {
    CollectionItemsRequest {
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
    }
}

/// Add domains to collection
async fn add_domains_to_collection(
    client: &virustotal_rs::CollectionsClient<'_>,
    collection_id: &str,
) {
    let new_domains = create_domain_items();
    match client
        .add_items(collection_id, "domains", &new_domains)
        .await
    {
        Ok(_) => print_success("Added 2 new domains to collection"),
        Err(e) => print_error(&format!("Error adding domains: {}", e)),
    }
}

/// Add URLs to collection
async fn add_urls_to_collection(
    client: &virustotal_rs::CollectionsClient<'_>,
    collection_id: &str,
) {
    let new_urls = create_url_items();
    match client.add_items(collection_id, "urls", &new_urls).await {
        Ok(_) => print_success("Added 2 new URLs to collection"),
        Err(e) => print_error(&format!("Error adding URLs: {}", e)),
    }
}

/// Add items to a collection
async fn test_add_items(client: &virustotal_rs::CollectionsClient<'_>, collection_id: &str) {
    println!("\n4. Adding items to collection");
    println!("-----------------------------");

    // Add domains
    add_domains_to_collection(client, collection_id).await;

    // Add URLs using both methods (URL string and ID)
    add_urls_to_collection(client, collection_id).await;
}

/// Add a comment to a collection
async fn add_collection_comment(
    client: &virustotal_rs::CollectionsClient<'_>,
    collection_id: &str,
    comment_text: &str,
) {
    match client.add_comment(collection_id, comment_text).await {
        Ok(comment) => {
            print_success("Added comment to collection");
            println!("   - Comment: {}", &comment.object.attributes.text);
        }
        Err(e) => print_error(&format!("Error adding comment: {}", e)),
    }
}

/// Retrieve and display comments from a collection
async fn retrieve_collection_comments(
    client: &virustotal_rs::CollectionsClient<'_>,
    collection_id: &str,
) {
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

/// Test comment management
async fn test_comment_management(
    client: &virustotal_rs::CollectionsClient<'_>,
    collection_id: &str,
) {
    println!("\n5. Managing comments");
    println!("--------------------");

    // Add a comment with important tags
    add_collection_comment(
        client,
        collection_id,
        "This collection contains high-priority IOCs #apt #critical",
    )
    .await;

    // Retrieve and display all comments
    retrieve_collection_comments(client, collection_id).await;
}

/// Retrieve and display relationship data
async fn retrieve_relationship_data(
    client: &virustotal_rs::CollectionsClient<'_>,
    collection_id: &str,
    relationship_type: &str,
    success_message: &str,
    count_label: &str,
) {
    match client
        .get_relationship::<serde_json::Value>(collection_id, relationship_type)
        .await
    {
        Ok(data) => {
            print_success(success_message);
            if let Some(meta) = &data.meta {
                if let Some(count) = meta.count {
                    println!("   - {}: {}", count_label, count);
                }
            }
        }
        Err(e) => print_error(&format!("Error getting {}: {}", relationship_type, e)),
    }
}

/// Test relationship retrieval
async fn test_relationships(client: &virustotal_rs::CollectionsClient<'_>, collection_id: &str) {
    println!("\n6. Getting related objects");
    println!("--------------------------");

    retrieve_relationship_data(
        client,
        collection_id,
        "domains",
        "Retrieved domains from collection",
        "Number of domains",
    )
    .await;

    retrieve_relationship_data(
        client,
        collection_id,
        "files",
        "Retrieved files from collection",
        "Number of files",
    )
    .await;
}

/// Test collection export functionality
async fn test_collection_export(
    client: &virustotal_rs::CollectionsClient<'_>,
    collection_id: &str,
) {
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
}

/// Test collection search functionality
async fn test_collection_search(
    client: &virustotal_rs::CollectionsClient<'_>,
    collection_id: &str,
) {
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

/// Test advanced collection operations
async fn test_advanced_operations(
    client: &virustotal_rs::CollectionsClient<'_>,
    collection_id: &str,
) {
    test_collection_export(client, collection_id).await;
    test_collection_search(client, collection_id).await;
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
