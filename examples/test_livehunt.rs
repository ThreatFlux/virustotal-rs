use virustotal_rs::{
    AddEditorsRequest, ApiTier, CreateLivehuntRulesetRequest, EditorDescriptor,
    LivehuntRulesetOrder, MatchObjectType, NotificationFile, NotificationOrder,
    TransferOwnershipRequest, UpdateLivehuntRulesetRequest,
};

mod common;
use common::*;

/// Create a test YARA rule for livehunt
fn create_test_yara_rule() -> String {
    r#"
rule TestMalware {
    meta:
        description = "Test rule for malware detection"
        author = "SDK Test"
    strings:
        $mz = { 4D 5A }
        $str1 = "This program cannot be run in DOS mode"
    condition:
        $mz at 0 and $str1
}
"#
    .to_string()
}

/// Display pagination cursor for rulesets
fn display_rulesets_pagination_cursor(meta: &Option<virustotal_rs::objects::CollectionMeta>) {
    if let Some(meta) = meta {
        if let Some(cursor) = &meta.cursor {
            println!(
                "   - Cursor for pagination: {}",
                truncate_string(cursor, 20)
            );
        }
    }
}

/// Handle ruleset listing result
fn handle_rulesets_result(
    result: Option<virustotal_rs::Collection<virustotal_rs::LivehuntRuleset>>,
) {
    match result {
        Some(rulesets) => {
            display_rulesets_pagination_cursor(&rulesets.meta);
            display_rulesets(&rulesets.data);
        }
        None => {
            print_warning("Livehunt requires premium API privileges");
        }
    }
}

/// Execute the list rulesets API call
async fn execute_list_rulesets_api_call(
    livehunt: &virustotal_rs::LivehuntClient<'_>,
) -> Result<virustotal_rs::Collection<virustotal_rs::LivehuntRuleset>, virustotal_rs::Error> {
    livehunt
        .list_rulesets(
            Some("enabled:true"),
            Some(LivehuntRulesetOrder::ModificationDateDesc),
            Some(10),
            None,
        )
        .await
}

/// Process and display rulesets list result
fn process_rulesets_list_result(
    result: Result<virustotal_rs::Collection<virustotal_rs::LivehuntRuleset>, virustotal_rs::Error>,
) {
    let rulesets_result = handle_result(result, "Retrieved rulesets", "Error listing rulesets");
    handle_rulesets_result(rulesets_result);
}

/// Test listing existing rulesets
async fn test_list_rulesets(livehunt: &virustotal_rs::LivehuntClient<'_>) {
    print_step_header(1, "LISTING RULESETS");
    let result = execute_list_rulesets_api_call(livehunt).await;
    process_rulesets_list_result(result);
}

/// Display ruleset information
fn display_rulesets(rulesets: &[virustotal_rs::LivehuntRuleset]) {
    for ruleset in rulesets.iter().take(5) {
        if let Some(name) = &ruleset.object.attributes.name {
            print!("   - {}", name);
            if let Some(enabled) = &ruleset.object.attributes.enabled {
                print!(" [{}]", if *enabled { "enabled" } else { "disabled" });
            }
            if let Some(limit) = &ruleset.object.attributes.limit {
                print!(" (limit: {})", limit);
            }
            println!();
        }
    }
}

/// Build the ruleset creation request
fn build_create_ruleset_request() -> CreateLivehuntRulesetRequest {
    let yara_rule = create_test_yara_rule();
    CreateLivehuntRulesetRequest::new("SDK Test Ruleset".to_string(), yara_rule)
        .with_enabled(true)
        .with_limit(100)
        .with_notification_emails(vec!["notifications@example.com".to_string()])
        .with_match_object_type(MatchObjectType::File)
}

/// Display created ruleset information
fn display_created_ruleset_info(ruleset: &virustotal_rs::LivehuntRuleset) {
    print_success("Ruleset created successfully");
    println!("   - ID: {}", ruleset.object.id);
    if let Some(name) = &ruleset.object.attributes.name {
        println!("   - Name: {}", name);
    }
    if let Some(creation_date) = &ruleset.object.attributes.creation_date {
        println!("   - Created: {}", creation_date);
    }
}

/// Execute ruleset creation API call
async fn execute_create_ruleset_api_call(
    livehunt: &virustotal_rs::LivehuntClient<'_>,
    request: &CreateLivehuntRulesetRequest,
) -> Result<virustotal_rs::LivehuntRuleset, virustotal_rs::Error> {
    livehunt.create_ruleset(request).await
}

/// Create a test ruleset and return its ID
async fn test_create_ruleset(livehunt: &virustotal_rs::LivehuntClient<'_>) -> Option<String> {
    print_step_header(2, "CREATING RULESET");

    let create_request = build_create_ruleset_request();

    match execute_create_ruleset_api_call(livehunt, &create_request).await {
        Ok(ruleset) => {
            display_created_ruleset_info(&ruleset);
            Some(ruleset.object.id)
        }
        Err(e) => {
            print_error(&format!("Error creating ruleset: {}", e));
            None
        }
    }
}

/// Build the ruleset update request
fn build_update_ruleset_request(ruleset_id: &str) -> UpdateLivehuntRulesetRequest {
    UpdateLivehuntRulesetRequest {
        data: virustotal_rs::livehunt::UpdateLivehuntRulesetData {
            object_type: "hunting_ruleset".to_string(),
            id: ruleset_id.to_string(),
            attributes: virustotal_rs::livehunt::UpdateLivehuntRulesetAttributes {
                name: Some("Updated SDK Test Ruleset".to_string()),
                enabled: Some(false),
                limit: Some(50),
                ..Default::default()
            },
        },
    }
}

/// Display updated ruleset information
fn display_updated_ruleset_info(updated: &virustotal_rs::LivehuntRuleset) {
    print_success("Ruleset updated successfully");
    if let Some(name) = &updated.object.attributes.name {
        println!("   - New name: {}", name);
    }
    if let Some(enabled) = &updated.object.attributes.enabled {
        println!("   - Enabled: {}", enabled);
    }
}

/// Update an existing ruleset
async fn test_update_ruleset(livehunt: &virustotal_rs::LivehuntClient<'_>, ruleset_id: &str) {
    print_step_header(3, "UPDATING RULESET");

    let update_request = build_update_ruleset_request(ruleset_id);

    match livehunt.update_ruleset(ruleset_id, &update_request).await {
        Ok(updated) => display_updated_ruleset_info(&updated),
        Err(e) => print_error(&format!("Error updating ruleset: {}", e)),
    }
}

/// Test permission management operations
async fn test_permission_management(
    livehunt: &virustotal_rs::LivehuntClient<'_>,
    ruleset_id: &str,
) {
    print_step_header(4, "PERMISSION MANAGEMENT");

    let editors_request = AddEditorsRequest {
        data: vec![EditorDescriptor {
            object_type: "user".to_string(),
            id: "example_user".to_string(),
        }],
    };

    // Grant, check, and revoke permissions
    test_permission_operations(livehunt, ruleset_id, &editors_request).await;
}

/// Grant edit permissions to users
async fn grant_permissions(
    livehunt: &virustotal_rs::LivehuntClient<'_>,
    ruleset_id: &str,
    editors_request: &AddEditorsRequest,
) {
    match livehunt
        .grant_edit_permissions(ruleset_id, editors_request)
        .await
    {
        Ok(_) => print_success("Edit permissions granted"),
        Err(e) => print_error(&format!("Error granting permissions: {}", e)),
    }
}

/// Check user permissions
async fn check_permissions(livehunt: &virustotal_rs::LivehuntClient<'_>, ruleset_id: &str) {
    match livehunt
        .check_editor_permission(ruleset_id, "example_user")
        .await
    {
        Ok(response) => {
            println!("   ✓ Permission check result: {}", response.data);
        }
        Err(e) => print_error(&format!("Error checking permissions: {}", e)),
    }
}

/// Revoke user permissions
async fn revoke_permissions(livehunt: &virustotal_rs::LivehuntClient<'_>, ruleset_id: &str) {
    match livehunt
        .revoke_edit_permission(ruleset_id, "example_user")
        .await
    {
        Ok(_) => print_success("Edit permissions revoked"),
        Err(e) => print_error(&format!("Error revoking permissions: {}", e)),
    }
}

/// Test the permission operations sequence
async fn test_permission_operations(
    livehunt: &virustotal_rs::LivehuntClient<'_>,
    ruleset_id: &str,
    editors_request: &AddEditorsRequest,
) {
    grant_permissions(livehunt, ruleset_id, editors_request).await;
    check_permissions(livehunt, ruleset_id).await;
    revoke_permissions(livehunt, ruleset_id).await;
}

/// Execute the list notifications API call
async fn execute_list_notifications_api_call(
    livehunt: &virustotal_rs::LivehuntClient<'_>,
) -> Result<virustotal_rs::Collection<virustotal_rs::LivehuntNotification>, virustotal_rs::Error> {
    livehunt
        .list_notifications(
            Some("date:2024-01-01+"),
            Some(NotificationOrder::DateDesc),
            Some(10),
            Some(100),
            None,
        )
        .await
}

/// Display notifications metadata
fn display_notifications_metadata(
    notifications: &virustotal_rs::Collection<virustotal_rs::LivehuntNotification>,
) {
    if let Some(meta) = &notifications.meta {
        if let Some(count) = meta.count {
            println!("   - Total notifications: {}", count);
        }
    }
}

/// Process and display notifications result
fn process_notifications_result(
    notifications_option: Option<virustotal_rs::Collection<virustotal_rs::LivehuntNotification>>,
) {
    if let Some(notifications) = notifications_option {
        display_notifications_metadata(&notifications);
        display_notifications(&notifications.data);
    }
}

/// Test notifications listing
async fn test_list_notifications(livehunt: &virustotal_rs::LivehuntClient<'_>) {
    print_step_header(5, "NOTIFICATIONS");

    let result = execute_list_notifications_api_call(livehunt).await;
    let notifications_result = handle_result(
        result,
        "Retrieved notifications",
        "Error listing notifications",
    );
    process_notifications_result(notifications_result);
}

/// Display notification information
fn display_notifications(notifications: &[virustotal_rs::LivehuntNotification]) {
    for notification in notifications.iter().take(5) {
        println!("   - Notification ID: {}", notification.object.id);
        if let Some(date) = &notification.object.attributes.date {
            println!("     Date: {}", date);
        }
        if let Some(ruleset_name) = &notification.object.attributes.ruleset_name {
            println!("     Ruleset: {}", ruleset_name);
        }
        if let Some(rule_name) = &notification.object.attributes.rule_name {
            println!("     Rule: {}", rule_name);
        }
        if let Some(sha256) = &notification.object.attributes.sha256 {
            println!("     File: {}", sha256);
        }
    }
}

/// Test notification files listing
async fn test_notification_files(livehunt: &virustotal_rs::LivehuntClient<'_>) {
    print_step_header(6, "NOTIFICATION FILES");

    let result = livehunt
        .list_notification_files(None, Some(10), Some(100), None)
        .await;

    if let Some(files) = handle_result(
        result,
        "Retrieved notification files",
        "Error getting notification files",
    ) {
        display_notification_files(&files.data);
    }
}

/// Display notification file information
fn display_notification_files(files: &[NotificationFile]) {
    for file in files.iter().take(3) {
        if let Some(context) = &file.context_attributes {
            println!("   - Notification: {}", context.notification_id);
            println!("     Ruleset: {}", context.ruleset_name);
            println!("     Rule: {}", context.rule_name);
            println!("     Match in subfile: {}", context.match_in_subfile);
            if let Some(snippet) = &context.notification_snippet {
                println!("     Snippet: {}", truncate_string(snippet, 50));
            }
        }
    }
}

/// Test notification management operations
async fn test_notification_management(livehunt: &virustotal_rs::LivehuntClient<'_>) {
    print_step_header(7, "NOTIFICATION MANAGEMENT");

    match livehunt.delete_notifications(Some("old_tag")).await {
        Ok(_) => print_success("Deleted notifications with tag 'old_tag'"),
        Err(e) => print_error(&format!("Error deleting notifications: {}", e)),
    }
}

/// Clean up created resources
async fn test_cleanup(livehunt: &virustotal_rs::LivehuntClient<'_>, ruleset_id: &str) {
    print_step_header(8, "CLEANUP");

    match livehunt.delete_ruleset(ruleset_id).await {
        Ok(_) => print_success("Deleted test ruleset"),
        Err(e) => print_error(&format!("Error deleting ruleset: {}", e)),
    }
}

/// Create a rulesets iterator for pagination
fn create_rulesets_iterator<'a>(
    livehunt: &'a virustotal_rs::LivehuntClient<'a>,
) -> virustotal_rs::CollectionIterator<'a, virustotal_rs::LivehuntRuleset> {
    livehunt.list_rulesets_iterator(Some("enabled:true"), Some(LivehuntRulesetOrder::NameAsc))
}

/// Display batch results
fn display_pagination_batch_results(batch: &[virustotal_rs::LivehuntRuleset]) {
    print_success(&format!(
        "Retrieved {} rulesets in first batch",
        batch.len()
    ));
    for ruleset in batch.iter().take(3) {
        if let Some(name) = &ruleset.object.attributes.name {
            println!("   - {}", name);
        }
    }
}

/// Execute pagination batch fetch
async fn execute_pagination_batch_fetch(
    iterator: &mut virustotal_rs::CollectionIterator<'_, virustotal_rs::LivehuntRuleset>,
) -> Result<Vec<virustotal_rs::LivehuntRuleset>, virustotal_rs::Error> {
    iterator.next_batch().await
}

/// Test pagination with iterators
async fn test_pagination(livehunt: &virustotal_rs::LivehuntClient<'_>) {
    print_step_header(9, "PAGINATION TEST");

    let mut ruleset_iterator = create_rulesets_iterator(livehunt);

    println!("Fetching first batch of rulesets:");
    match execute_pagination_batch_fetch(&mut ruleset_iterator).await {
        Ok(batch) => display_pagination_batch_results(&batch),
        Err(e) => print_error(&format!("Error fetching batch: {}", e)),
    }
}

/// Demonstrate ownership transfer functionality
fn test_ownership_transfer() {
    print_step_header(10, "OWNERSHIP TRANSFER");

    let _transfer_request = TransferOwnershipRequest {
        data: EditorDescriptor {
            object_type: "user".to_string(),
            id: "new_owner_id".to_string(),
        },
    };

    println!("   Note: Ownership transfer requires valid ruleset and user in same group");
}

/// Execute all main test scenarios with a created ruleset
async fn execute_ruleset_tests(livehunt: &virustotal_rs::LivehuntClient<'_>, ruleset_id: &str) {
    test_update_ruleset(livehunt, ruleset_id).await;
    test_permission_management(livehunt, ruleset_id).await;
    test_cleanup(livehunt, ruleset_id).await;
}

/// Execute all notification and general tests
async fn execute_general_tests(livehunt: &virustotal_rs::LivehuntClient<'_>) {
    test_list_notifications(livehunt).await;
    test_notification_files(livehunt).await;
    test_notification_management(livehunt).await;
    test_pagination(livehunt).await;
    test_ownership_transfer();
}

#[tokio::main]
async fn main() -> ExampleResult<()> {
    let client = create_client_from_env("VT_API_KEY", ApiTier::Premium)?;

    print_header("Testing VirusTotal Livehunt API");

    let livehunt = client.livehunt();

    // Execute all test scenarios
    test_list_rulesets(&livehunt).await;

    let created_ruleset_id = test_create_ruleset(&livehunt).await;

    if let Some(ruleset_id) = &created_ruleset_id {
        execute_ruleset_tests(&livehunt, ruleset_id).await;
    }

    execute_general_tests(&livehunt).await;

    println!("\n================================");
    println!("Livehunt API testing complete!");

    Ok(())
}
