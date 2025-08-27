use virustotal_rs::crowdsourced_yara_rules::CrowdsourcedYaraRule;
use virustotal_rs::ioc_stream::{
    HuntingInfo, IocStreamContext, IocStreamNotification, IocStreamObject, NotificationSource,
};
use virustotal_rs::objects::Meta;
use virustotal_rs::{ApiTier, EntityType, IocStreamOrder, SourceType, YaraRuleOrder};

#[path = "common/mod.rs"]
mod common;
use common::build_client_from_env;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = build_client_from_env("VT_API_KEY", ApiTier::Premium)?;

    print_header();
    run_yara_tests(&client).await;
    run_ioc_stream_tests(&client).await;
    run_helper_tests();
    run_pagination_tests(&client).await;
    print_completion();

    Ok(())
}

/// Print application header
fn print_header() {
    println!("Testing Crowdsourced YARA Rules and IoC Stream APIs");
    println!("===================================================\n");
}

/// Run YARA rule tests
async fn run_yara_tests(client: &virustotal_rs::Client) {
    println!("1. CROWDSOURCED YARA RULES API");
    println!("-------------------------------");

    let yara_client = client.crowdsourced_yara_rules();

    test_list_yara_rules(&yara_client).await;
    test_get_specific_yara_rule(&yara_client).await;
    test_search_yara_rules(&yara_client).await;
}

/// Test listing YARA rules
async fn test_list_yara_rules(yara_client: &virustotal_rs::CrowdsourcedYaraRulesClient<'_>) {
    println!("\nListing crowdsourced YARA rules:");

    match fetch_yara_rules(yara_client).await {
        Ok(rules) => {
            println!("   ✓ Retrieved YARA rules");
            display_yara_pagination(&rules.meta);
            display_yara_rules(&rules.data);
        }
        Err(e) => print_yara_error("listing YARA rules", &e),
    }
}

/// Fetch YARA rules
async fn fetch_yara_rules(
    yara_client: &virustotal_rs::CrowdsourcedYaraRulesClient<'_>,
) -> Result<virustotal_rs::Collection<CrowdsourcedYaraRule>, virustotal_rs::Error> {
    yara_client
        .list(
            Some("enabled:true"),
            Some(YaraRuleOrder::MatchesDesc),
            Some(10),
            None,
        )
        .await
}

/// Display YARA pagination info
fn display_yara_pagination(meta: &Option<Meta>) {
    if let Some(meta) = meta {
        if let Some(cursor) = &meta.cursor {
            println!(
                "   - Cursor available for pagination: {}",
                &cursor[..20.min(cursor.len())]
            );
        }
    }
}

/// Display YARA rules
fn display_yara_rules(rules: &[CrowdsourcedYaraRule]) {
    for rule in rules.iter().take(5) {
        if let Some(name) = &rule.object.attributes.name {
            display_yara_rule_info(rule, name);
        }
    }
}

/// Display individual YARA rule info
fn display_yara_rule_info(rule: &CrowdsourcedYaraRule, name: &str) {
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

/// Test getting a specific YARA rule
async fn test_get_specific_yara_rule(yara_client: &virustotal_rs::CrowdsourcedYaraRulesClient<'_>) {
    println!("\nGetting a specific YARA rule:");
    let rule_id = "example_rule_id"; // You would need a real rule ID

    match yara_client.get(rule_id).await {
        Ok(rule) => {
            println!("   ✓ Retrieved YARA rule");
            display_yara_rule_details(&rule);
        }
        Err(e) => print_yara_error("getting YARA rule", &e),
    }
}

/// Display detailed YARA rule information
fn display_yara_rule_details(rule: &CrowdsourcedYaraRule) {
    let attrs = &rule.object.attributes;

    if let Some(name) = &attrs.name {
        println!("   - Name: {}", name);
    }
    if let Some(author) = &attrs.author {
        println!("   - Author: {}", author);
    }
    if let Some(enabled) = &attrs.enabled {
        println!("   - Enabled: {}", enabled);
    }

    display_yara_metadata(&attrs.meta);
    display_yara_rule_content(&attrs.rule);
}

/// Display YARA rule metadata
fn display_yara_metadata(meta_list: &Option<Vec<virustotal_rs::YaraMetadata>>) {
    if let Some(meta_list) = meta_list {
        println!("   - Metadata:");
        for meta in meta_list.iter().take(3) {
            println!("     {}: {}", meta.key, meta.value);
        }
    }
}

/// Display YARA rule content
fn display_yara_rule_content(rule_content: &Option<String>) {
    if let Some(rule_content) = rule_content {
        println!(
            "   - Rule preview: {}",
            &rule_content[..100.min(rule_content.len())]
        );
    }
}

/// Test searching YARA rules
async fn test_search_yara_rules(yara_client: &virustotal_rs::CrowdsourcedYaraRulesClient<'_>) {
    println!("\nSearching for phishing-related YARA rules:");

    match search_yara_rules(yara_client).await {
        Ok(rules) => {
            println!("   ✓ Found {} rules", rules.data.len());
            for rule in &rules.data {
                if let Some(name) = &rule.object.attributes.name {
                    println!("   - {}", name);
                }
            }
        }
        Err(e) => print_yara_error("searching rules", &e),
    }
}

/// Search YARA rules
async fn search_yara_rules(
    yara_client: &virustotal_rs::CrowdsourcedYaraRulesClient<'_>,
) -> Result<virustotal_rs::Collection<CrowdsourcedYaraRule>, virustotal_rs::Error> {
    yara_client
        .list(
            Some("name:phishing"),
            Some(YaraRuleOrder::CreationDateDesc),
            Some(5),
            None,
        )
        .await
}

/// Print YARA error
fn print_yara_error(operation: &str, error: &virustotal_rs::Error) {
    println!("   ✗ Error {}: {}", operation, error);
    if operation.contains("listing") {
        println!("   Note: This may require specific API privileges");
    }
}

/// Run IoC Stream tests
async fn run_ioc_stream_tests(client: &virustotal_rs::Client) {
    println!("\n2. IoC STREAM API");
    println!("-----------------");

    let ioc_stream_client = client.ioc_stream();

    test_get_ioc_stream(&ioc_stream_client).await;
    test_filtered_ioc_stream(&ioc_stream_client).await;
    test_get_specific_notification(&ioc_stream_client).await;
    test_delete_notifications(&ioc_stream_client).await;
}

/// Test getting IoC Stream
async fn test_get_ioc_stream(ioc_stream_client: &virustotal_rs::IocStreamClient<'_>) {
    println!("\nGetting IoC Stream (recent notifications):");

    match fetch_ioc_stream(ioc_stream_client).await {
        Ok(stream) => {
            println!("   ✓ Retrieved IoC Stream");
            display_ioc_stream_info(&stream);
            display_ioc_objects(&stream.data);
        }
        Err(e) => print_ioc_error("getting IoC Stream", &e),
    }
}

/// Fetch IoC stream
async fn fetch_ioc_stream(
    ioc_stream_client: &virustotal_rs::IocStreamClient<'_>,
) -> Result<virustotal_rs::Collection<IocStreamObject>, virustotal_rs::Error> {
    ioc_stream_client
        .get_stream(
            Some("origin:hunting"),
            Some(IocStreamOrder::DateDesc),
            Some(10),
            Some(false), // Get full objects, not just descriptors
            None,
        )
        .await
}

/// Display IoC stream info
fn display_ioc_stream_info(stream: &virustotal_rs::Collection<IocStreamObject>) {
    if let Some(meta) = &stream.meta {
        if let Some(cursor) = &meta.cursor {
            println!(
                "   - Cursor for pagination: {}",
                &cursor[..20.min(cursor.len())]
            );
        }
    }
    println!("   - Found {} objects", stream.data.len());
}

/// Display IoC objects
fn display_ioc_objects(objects: &[IocStreamObject]) {
    for (i, obj) in objects.iter().take(5).enumerate() {
        println!("   {}. Object #{}", i + 1, i + 1);
        display_ioc_object_details(obj);
    }
}

/// Display IoC object details
fn display_ioc_object_details(obj: &IocStreamObject) {
    if let Some(context) = &obj.context_attributes {
        display_notification_info(context);
        display_sources_info(&context.sources);
        display_tags_info(&context.tags);
        display_hunting_info(&context.hunting_info);
    }
}

/// Display notification info
fn display_notification_info(context: &IocStreamContext) {
    println!("      Notification ID: {}", context.notification_id);
    println!("      Origin: {}", context.origin);
    println!("      Date: {}", context.notification_date);
}

/// Display sources info
fn display_sources_info(sources: &[NotificationSource]) {
    if !sources.is_empty() {
        println!("      Sources:");
        for source in sources {
            display_source_info(source);
        }
    }
}

/// Display individual source info
fn display_source_info(source: &NotificationSource) {
    print!("        - Type: {}, ID: {}", source.source_type, source.id);
    if let Some(name) = &source.name {
        print!(" ({})", name);
    }
    println!();
}

/// Display tags info
fn display_tags_info(tags: &Option<Vec<String>>) {
    if let Some(tags) = tags {
        if !tags.is_empty() {
            println!("      Tags: {}", tags.join(", "));
        }
    }
}

/// Display hunting info
fn display_hunting_info(hunting: &Option<HuntingInfo>) {
    if let Some(hunting) = hunting {
        println!("      Hunting Info:");
        if let Some(rule_name) = &hunting.rule_name {
            println!("        Rule: {}", rule_name);
        }
        if let Some(country) = &hunting.source_country {
            println!("        Source Country: {}", country);
        }
    }
}

/// Test filtered IoC stream
async fn test_filtered_ioc_stream(ioc_stream_client: &virustotal_rs::IocStreamClient<'_>) {
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

    match fetch_filtered_ioc_stream(ioc_stream_client, &filter).await {
        Ok(stream) => {
            println!("   ✓ Retrieved filtered IoC Stream");
            println!("   - Found {} file objects", stream.data.len());
        }
        Err(e) => print_ioc_error("getting filtered stream", &e),
    }
}

/// Fetch filtered IoC stream
async fn fetch_filtered_ioc_stream(
    ioc_stream_client: &virustotal_rs::IocStreamClient<'_>,
    filter: &str,
) -> Result<virustotal_rs::Collection<IocStreamObject>, virustotal_rs::Error> {
    ioc_stream_client
        .get_stream(
            Some(filter),
            Some(IocStreamOrder::DateDesc),
            Some(5),
            Some(true), // Just descriptors
            None,
        )
        .await
}

/// Test getting a specific notification
async fn test_get_specific_notification(ioc_stream_client: &virustotal_rs::IocStreamClient<'_>) {
    println!("\nGetting a specific notification:");
    let notification_id = "example_notification_id"; // You would need a real notification ID

    match ioc_stream_client.get_notification(notification_id).await {
        Ok(notification) => {
            println!("   ✓ Retrieved notification");
            display_notification_details(&notification);
        }
        Err(e) => print_ioc_error("getting notification", &e),
    }
}

/// Display notification details
fn display_notification_details(notification: &IocStreamNotification) {
    let attrs = &notification.object.attributes;

    if let Some(date) = &attrs.notification_date {
        println!("   - Date: {}", date);
    }
    if let Some(origin) = &attrs.origin {
        println!("   - Origin: {}", origin);
    }
    if let Some(tags) = &attrs.tags {
        if !tags.is_empty() {
            println!("   - Tags: {}", tags.join(", "));
        }
    }
}

/// Test deleting notifications
async fn test_delete_notifications(ioc_stream_client: &virustotal_rs::IocStreamClient<'_>) {
    println!("\nDeleting old notifications (demo):");
    let delete_filter = "date:2023-01-01- origin:hunting"; // Delete notifications before 2023

    match ioc_stream_client.delete_notifications(delete_filter).await {
        Ok(_) => println!("   ✓ Successfully deleted matching notifications"),
        Err(e) => print_ioc_error("deleting notifications", &e),
    }
}

/// Print IoC error
fn print_ioc_error(operation: &str, error: &virustotal_rs::Error) {
    println!("   ✗ Error {}: {}", operation, error);
    if operation.contains("getting IoC Stream") {
        println!("   Note: IoC Stream requires special privileges");
    }
}

/// Run helper method tests
fn run_helper_tests() {
    println!("\n3. HELPER METHODS");
    println!("-----------------");

    test_date_filter_helper();
    test_complex_filter_helper();
}

/// Test date filter helper
fn test_date_filter_helper() {
    let date_filter = virustotal_rs::IocStreamClient::build_date_filter(
        Some("2024-01-01T00:00:00"),
        Some("2024-01-31T23:59:59"),
    );
    println!("Date filter: {}", date_filter);
}

/// Test complex filter helper
fn test_complex_filter_helper() {
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
}

/// Run pagination tests
async fn run_pagination_tests(client: &virustotal_rs::Client) {
    println!("\n4. PAGINATION TEST");
    println!("------------------");

    let yara_client = client.crowdsourced_yara_rules();
    test_yara_pagination(&yara_client).await;
}

/// Test YARA pagination
async fn test_yara_pagination(yara_client: &virustotal_rs::CrowdsourcedYaraRulesClient<'_>) {
    let mut yara_iterator =
        yara_client.list_iterator(Some("enabled:true"), Some(YaraRuleOrder::NameAsc));

    println!("Fetching first batch of YARA rules:");
    match yara_iterator.next_batch().await {
        Ok(batch) => {
            println!("   ✓ Retrieved {} rules in first batch", batch.len());
            display_paginated_rules(&batch);
        }
        Err(e) => print_yara_error("fetching batch", &e),
    }
}

/// Display paginated rules
fn display_paginated_rules(batch: &[CrowdsourcedYaraRule]) {
    for rule in batch.iter().take(3) {
        if let Some(name) = &rule.object.attributes.name {
            println!("   - {}", name);
        }
    }
}

/// Print completion message
fn print_completion() {
    println!("\n===================================================");
    println!("Testing complete!");
}
