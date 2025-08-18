use virustotal_rs::{
    ApiTier, ClientBuilder, EntityType, IocStreamOrder, SourceType, YaraRuleOrder,
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let api_key = std::env::var("VT_API_KEY").unwrap_or_else(|_| "test_key".to_string());

    let client = ClientBuilder::new()
        .api_key(api_key)
        .tier(ApiTier::Premium)
        .build()?;

    println!("Testing Crowdsourced YARA Rules and IoC Stream APIs");
    println!("===================================================\n");

    // 1. Test Crowdsourced YARA Rules API
    println!("1. CROWDSOURCED YARA RULES API");
    println!("-------------------------------");

    let yara_client = client.crowdsourced_yara_rules();

    // List YARA rules
    println!("\nListing crowdsourced YARA rules:");
    match yara_client
        .list(
            Some("enabled:true"),
            Some(YaraRuleOrder::MatchesDesc),
            Some(10),
            None,
        )
        .await
    {
        Ok(rules) => {
            println!("   ✓ Retrieved YARA rules");
            if let Some(meta) = &rules.meta {
                if let Some(cursor) = &meta.cursor {
                    println!(
                        "   - Cursor available for pagination: {}",
                        &cursor[..20.min(cursor.len())]
                    );
                }
            }

            for rule in rules.data.iter().take(5) {
                if let Some(name) = &rule.object.attributes.name {
                    print!("   - {}", name);
                    if let Some(author) = &rule.object.attributes.author {
                        print!(" by {}", author);
                    }
                    if let Some(matches) = &rule.object.attributes.matches {
                        print!(" ({} matches)", matches);
                    }
                    println!();

                    if let Some(tags) = &rule.object.attributes.tags {
                        if !tags.is_empty() {
                            println!("     Tags: {}", tags.join(", "));
                        }
                    }
                }
            }
        }
        Err(e) => {
            println!("   ✗ Error listing YARA rules: {}", e);
            println!("   Note: This may require specific API privileges");
        }
    }

    // Get a specific YARA rule
    println!("\nGetting a specific YARA rule:");
    let rule_id = "example_rule_id"; // You would need a real rule ID
    match yara_client.get(rule_id).await {
        Ok(rule) => {
            println!("   ✓ Retrieved YARA rule");
            if let Some(name) = &rule.object.attributes.name {
                println!("   - Name: {}", name);
            }
            if let Some(author) = &rule.object.attributes.author {
                println!("   - Author: {}", author);
            }
            if let Some(enabled) = &rule.object.attributes.enabled {
                println!("   - Enabled: {}", enabled);
            }
            if let Some(meta_list) = &rule.object.attributes.meta {
                println!("   - Metadata:");
                for meta in meta_list.iter().take(3) {
                    println!("     {}: {}", meta.key, meta.value);
                }
            }
            if let Some(rule_content) = &rule.object.attributes.rule {
                println!(
                    "   - Rule preview: {}",
                    &rule_content[..100.min(rule_content.len())]
                );
            }
        }
        Err(e) => {
            println!("   ✗ Error getting YARA rule: {}", e);
        }
    }

    // Test filtering
    println!("\nSearching for phishing-related YARA rules:");
    match yara_client
        .list(
            Some("name:phishing"),
            Some(YaraRuleOrder::CreationDateDesc),
            Some(5),
            None,
        )
        .await
    {
        Ok(rules) => {
            println!("   ✓ Found {} rules", rules.data.len());
            for rule in &rules.data {
                if let Some(name) = &rule.object.attributes.name {
                    println!("   - {}", name);
                }
            }
        }
        Err(e) => {
            println!("   ✗ Error searching rules: {}", e);
        }
    }

    // 2. Test IoC Stream API
    println!("\n2. IoC STREAM API");
    println!("-----------------");

    let ioc_stream_client = client.ioc_stream();

    // Get IoC Stream
    println!("\nGetting IoC Stream (recent notifications):");
    match ioc_stream_client
        .get_stream(
            Some("origin:hunting"),
            Some(IocStreamOrder::DateDesc),
            Some(10),
            Some(false), // Get full objects, not just descriptors
            None,
        )
        .await
    {
        Ok(stream) => {
            println!("   ✓ Retrieved IoC Stream");
            if let Some(meta) = &stream.meta {
                if let Some(cursor) = &meta.cursor {
                    println!(
                        "   - Cursor for pagination: {}",
                        &cursor[..20.min(cursor.len())]
                    );
                }
            }

            println!("   - Found {} objects", stream.data.len());

            for (i, obj) in stream.data.iter().take(5).enumerate() {
                println!("   {}. Object #{}", i + 1, i + 1);

                if let Some(context) = &obj.context_attributes {
                    println!("      Notification ID: {}", context.notification_id);
                    println!("      Origin: {}", context.origin);
                    println!("      Date: {}", context.notification_date);

                    if !context.sources.is_empty() {
                        println!("      Sources:");
                        for source in &context.sources {
                            print!("        - Type: {}, ID: {}", source.source_type, source.id);
                            if let Some(name) = &source.name {
                                print!(" ({})", name);
                            }
                            println!();
                        }
                    }

                    if let Some(tags) = &context.tags {
                        if !tags.is_empty() {
                            println!("      Tags: {}", tags.join(", "));
                        }
                    }

                    if let Some(hunting) = &context.hunting_info {
                        println!("      Hunting Info:");
                        if let Some(rule_name) = &hunting.rule_name {
                            println!("        Rule: {}", rule_name);
                        }
                        if let Some(country) = &hunting.source_country {
                            println!("        Source Country: {}", country);
                        }
                    }
                }
            }
        }
        Err(e) => {
            println!("   ✗ Error getting IoC Stream: {}", e);
            println!("   Note: IoC Stream requires special privileges");
        }
    }

    // Test filtering by date and entity type
    println!("\nGetting file objects from the last 7 days:");
    let filter = virustotal_rs::IocStreamClient::build_filter(
        Some("2024-01-01T00:00:00"), // Adjust date as needed
        None,
        Some("hunting"),
        Some(EntityType::File),
        None,
        None,
        None,
    );

    match ioc_stream_client
        .get_stream(
            Some(&filter),
            Some(IocStreamOrder::DateDesc),
            Some(5),
            Some(true), // Just descriptors
            None,
        )
        .await
    {
        Ok(stream) => {
            println!("   ✓ Retrieved filtered IoC Stream");
            println!("   - Found {} file objects", stream.data.len());
        }
        Err(e) => {
            println!("   ✗ Error getting filtered stream: {}", e);
        }
    }

    // Test getting a specific notification
    println!("\nGetting a specific notification:");
    let notification_id = "example_notification_id"; // You would need a real notification ID
    match ioc_stream_client.get_notification(notification_id).await {
        Ok(notification) => {
            println!("   ✓ Retrieved notification");
            if let Some(date) = &notification.object.attributes.notification_date {
                println!("   - Date: {}", date);
            }
            if let Some(origin) = &notification.object.attributes.origin {
                println!("   - Origin: {}", origin);
            }
            if let Some(tags) = &notification.object.attributes.tags {
                if !tags.is_empty() {
                    println!("   - Tags: {}", tags.join(", "));
                }
            }
        }
        Err(e) => {
            println!("   ✗ Error getting notification: {}", e);
        }
    }

    // Test deleting notifications
    println!("\nDeleting old notifications (demo):");
    let delete_filter = "date:2023-01-01- origin:hunting"; // Delete notifications before 2023
    match ioc_stream_client.delete_notifications(delete_filter).await {
        Ok(_) => {
            println!("   ✓ Successfully deleted matching notifications");
        }
        Err(e) => {
            println!("   ✗ Error deleting notifications: {}", e);
        }
    }

    // Test helper methods
    println!("\n3. HELPER METHODS");
    println!("-----------------");

    // Build date filter
    let date_filter = virustotal_rs::IocStreamClient::build_date_filter(
        Some("2024-01-01T00:00:00"),
        Some("2024-01-31T23:59:59"),
    );
    println!("Date filter: {}", date_filter);

    // Build complex filter
    let complex_filter = virustotal_rs::IocStreamClient::build_filter(
        Some("2024-01-01T00:00:00"),
        None,
        Some("hunting"),
        Some(EntityType::File),
        Some(SourceType::HuntingRuleset),
        Some("ruleset_123"),
        Some("malware"),
    );
    println!("Complex filter: {}", complex_filter);

    // Test pagination with iterator
    println!("\n4. PAGINATION TEST");
    println!("------------------");

    let mut yara_iterator =
        yara_client.list_iterator(Some("enabled:true"), Some(YaraRuleOrder::NameAsc));

    println!("Fetching first batch of YARA rules:");
    match yara_iterator.next_batch().await {
        Ok(batch) => {
            println!("   ✓ Retrieved {} rules in first batch", batch.len());
            for rule in batch.iter().take(3) {
                if let Some(name) = &rule.object.attributes.name {
                    println!("   - {}", name);
                }
            }
        }
        Err(e) => {
            println!("   ✗ Error fetching batch: {}", e);
        }
    }

    println!("\n===================================================");
    println!("Testing complete!");

    Ok(())
}
