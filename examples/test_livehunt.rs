use virustotal_rs::{
    AddEditorsRequest, ApiTier, ClientBuilder, CreateLivehuntRulesetRequest, EditorDescriptor,
    LivehuntRulesetOrder, MatchObjectType, NotificationOrder, TransferOwnershipRequest,
    UpdateLivehuntRulesetRequest,
};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

/// Initialize and configure the VirusTotal client
fn setup_client() -> Result<virustotal_rs::Client> {
    let api_key = std::env::var("VT_API_KEY").unwrap_or_else(|_| "test_key".to_string());

    ClientBuilder::new()
        .api_key(api_key)
        .tier(ApiTier::Premium)
        .build()
        .map_err(Into::into)
}

/// Print section header with title and separator
fn print_section_header(step: u8, title: &str) {
    println!("\n{}. {}", step, title);
    println!("{}", "-".repeat(title.len() + 4));
}

/// Test listing existing rulesets
async fn test_list_rulesets(livehunt: &virustotal_rs::LivehuntClient<'_>) {
    print_section_header(1, "LISTING RULESETS");

    match livehunt
        .list_rulesets(
            Some("enabled:true"),
            Some(LivehuntRulesetOrder::ModificationDateDesc),
            Some(10),
            None,
        )
        .await
    {
        Ok(rulesets) => {
            println!("   ✓ Retrieved rulesets");
            if let Some(meta) = &rulesets.meta {
                if let Some(cursor) = &meta.cursor {
                    println!(
                        "   - Cursor for pagination: {}",
                        &cursor[..20.min(cursor.len())]
                    );
                }
            }

            for ruleset in rulesets.data.iter().take(5) {
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
        Err(e) => {
            println!("   ✗ Error listing rulesets: {}", e);
            println!("   Note: Livehunt requires premium API privileges");
        }
    }
}

/// Create a test ruleset and return its ID
async fn test_create_ruleset(livehunt: &virustotal_rs::LivehuntClient<'_>) -> Option<String> {
    print_section_header(2, "CREATING RULESET");

    let yara_rule = r#"
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
"#;

    let create_request =
        CreateLivehuntRulesetRequest::new("SDK Test Ruleset".to_string(), yara_rule.to_string())
            .with_enabled(true)
            .with_limit(100)
            .with_notification_emails(vec!["notifications@example.com".to_string()])
            .with_match_object_type(MatchObjectType::File);

    match livehunt.create_ruleset(&create_request).await {
        Ok(ruleset) => {
            println!("   ✓ Ruleset created successfully");
            println!("   - ID: {}", ruleset.object.id);
            if let Some(name) = &ruleset.object.attributes.name {
                println!("   - Name: {}", name);
            }
            if let Some(creation_date) = &ruleset.object.attributes.creation_date {
                println!("   - Created: {}", creation_date);
            }
            Some(ruleset.object.id)
        }
        Err(e) => {
            println!("   ✗ Error creating ruleset: {}", e);
            None
        }
    }
}

/// Update an existing ruleset
async fn test_update_ruleset(livehunt: &virustotal_rs::LivehuntClient<'_>, ruleset_id: &str) {
    print_section_header(3, "UPDATING RULESET");

    let update_request = UpdateLivehuntRulesetRequest {
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
    };

    match livehunt.update_ruleset(ruleset_id, &update_request).await {
        Ok(updated) => {
            println!("   ✓ Ruleset updated successfully");
            if let Some(name) = &updated.object.attributes.name {
                println!("   - New name: {}", name);
            }
            if let Some(enabled) = &updated.object.attributes.enabled {
                println!("   - Enabled: {}", enabled);
            }
        }
        Err(e) => println!("   ✗ Error updating ruleset: {}", e),
    }
}

/// Test permission management operations
async fn test_permission_management(
    livehunt: &virustotal_rs::LivehuntClient<'_>,
    ruleset_id: &str,
) {
    print_section_header(4, "PERMISSION MANAGEMENT");

    let editors_request = AddEditorsRequest {
        data: vec![EditorDescriptor {
            object_type: "user".to_string(),
            id: "example_user".to_string(),
        }],
    };

    // Grant permissions
    match livehunt
        .grant_edit_permissions(ruleset_id, &editors_request)
        .await
    {
        Ok(_) => println!("   ✓ Edit permissions granted"),
        Err(e) => println!("   ✗ Error granting permissions: {}", e),
    }

    // Check permissions
    match livehunt
        .check_editor_permission(ruleset_id, "example_user")
        .await
    {
        Ok(response) => {
            println!("   ✓ Permission check result: {}", response.data);
        }
        Err(e) => println!("   ✗ Error checking permissions: {}", e),
    }

    // Revoke permissions
    match livehunt
        .revoke_edit_permission(ruleset_id, "example_user")
        .await
    {
        Ok(_) => println!("   ✓ Edit permissions revoked"),
        Err(e) => println!("   ✗ Error revoking permissions: {}", e),
    }
}

/// Test notifications listing
async fn test_list_notifications(livehunt: &virustotal_rs::LivehuntClient<'_>) {
    print_section_header(5, "NOTIFICATIONS");

    match livehunt
        .list_notifications(
            Some("date:2024-01-01+"),
            Some(NotificationOrder::DateDesc),
            Some(10),
            Some(100),
            None,
        )
        .await
    {
        Ok(notifications) => {
            println!("   ✓ Retrieved notifications");
            if let Some(meta) = &notifications.meta {
                if let Some(count) = meta.count {
                    println!("   - Total notifications: {}", count);
                }
            }

            for notification in notifications.data.iter().take(5) {
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
        Err(e) => {
            println!("   ✗ Error listing notifications: {}", e);
        }
    }
}

/// Test notification files listing
async fn test_notification_files(livehunt: &virustotal_rs::LivehuntClient<'_>) {
    print_section_header(6, "NOTIFICATION FILES");

    match livehunt
        .list_notification_files(None, Some(10), Some(100), None)
        .await
    {
        Ok(files) => {
            println!("   ✓ Retrieved notification files");

            for file in files.data.iter().take(3) {
                if let Some(context) = &file.context_attributes {
                    println!("   - Notification: {}", context.notification_id);
                    println!("     Ruleset: {}", context.ruleset_name);
                    println!("     Rule: {}", context.rule_name);
                    println!("     Match in subfile: {}", context.match_in_subfile);
                    if let Some(snippet) = &context.notification_snippet {
                        println!("     Snippet: {}", &snippet[..50.min(snippet.len())]);
                    }
                }
            }
        }
        Err(e) => {
            println!("   ✗ Error getting notification files: {}", e);
        }
    }
}

/// Test notification management operations
async fn test_notification_management(livehunt: &virustotal_rs::LivehuntClient<'_>) {
    print_section_header(7, "NOTIFICATION MANAGEMENT");

    match livehunt.delete_notifications(Some("old_tag")).await {
        Ok(_) => println!("   ✓ Deleted notifications with tag 'old_tag'"),
        Err(e) => println!("   ✗ Error deleting notifications: {}", e),
    }
}

/// Clean up created resources
async fn test_cleanup(livehunt: &virustotal_rs::LivehuntClient<'_>, ruleset_id: &str) {
    print_section_header(8, "CLEANUP");

    match livehunt.delete_ruleset(ruleset_id).await {
        Ok(_) => println!("   ✓ Deleted test ruleset"),
        Err(e) => println!("   ✗ Error deleting ruleset: {}", e),
    }
}

/// Test pagination with iterators
async fn test_pagination(livehunt: &virustotal_rs::LivehuntClient<'_>) {
    print_section_header(9, "PAGINATION TEST");

    let mut ruleset_iterator =
        livehunt.list_rulesets_iterator(Some("enabled:true"), Some(LivehuntRulesetOrder::NameAsc));

    println!("Fetching first batch of rulesets:");
    match ruleset_iterator.next_batch().await {
        Ok(batch) => {
            println!("   ✓ Retrieved {} rulesets in first batch", batch.len());
            for ruleset in batch.iter().take(3) {
                if let Some(name) = &ruleset.object.attributes.name {
                    println!("   - {}", name);
                }
            }
        }
        Err(e) => {
            println!("   ✗ Error fetching batch: {}", e);
        }
    }
}

/// Demonstrate ownership transfer functionality
fn test_ownership_transfer() {
    print_section_header(10, "OWNERSHIP TRANSFER");

    let _transfer_request = TransferOwnershipRequest {
        data: EditorDescriptor {
            object_type: "user".to_string(),
            id: "new_owner_id".to_string(),
        },
    };

    println!("   Note: Ownership transfer requires valid ruleset and user in same group");
}

#[tokio::main]
async fn main() -> Result<()> {
    let client = setup_client()?;

    println!("Testing VirusTotal Livehunt API");
    println!("================================\n");

    let livehunt = client.livehunt();

    // Execute all test scenarios
    test_list_rulesets(&livehunt).await;

    let created_ruleset_id = test_create_ruleset(&livehunt).await;

    if let Some(ruleset_id) = &created_ruleset_id {
        test_update_ruleset(&livehunt, ruleset_id).await;
        test_permission_management(&livehunt, ruleset_id).await;
    }

    test_list_notifications(&livehunt).await;
    test_notification_files(&livehunt).await;
    test_notification_management(&livehunt).await;

    if let Some(ruleset_id) = &created_ruleset_id {
        test_cleanup(&livehunt, ruleset_id).await;
    }

    test_pagination(&livehunt).await;
    test_ownership_transfer();

    println!("\n================================");
    println!("Livehunt API testing complete!");

    Ok(())
}
