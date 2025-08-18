use virustotal_rs::{
    AddEditorsRequest, ApiTier, ClientBuilder, CreateLivehuntRulesetRequest, EditorDescriptor,
    LivehuntRulesetOrder, MatchObjectType, NotificationOrder, TransferOwnershipRequest,
    UpdateLivehuntRulesetRequest,
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let api_key = std::env::var("VT_API_KEY").unwrap_or_else(|_| "test_key".to_string());

    let client = ClientBuilder::new()
        .api_key(api_key)
        .tier(ApiTier::Premium) // Livehunt requires premium privileges
        .build()?;

    println!("Testing VirusTotal Livehunt API");
    println!("================================\n");

    let livehunt = client.livehunt();

    // 1. List existing rulesets
    println!("1. LISTING RULESETS");
    println!("-------------------");

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

    // 2. Create a new ruleset
    println!("\n2. CREATING RULESET");
    println!("-------------------");

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

    let created_ruleset_id = match livehunt.create_ruleset(&create_request).await {
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
    };

    // 3. Update the ruleset
    if let Some(ruleset_id) = &created_ruleset_id {
        println!("\n3. UPDATING RULESET");
        println!("-------------------");

        let update_request = UpdateLivehuntRulesetRequest {
            data: virustotal_rs::livehunt::UpdateLivehuntRulesetData {
                object_type: "hunting_ruleset".to_string(),
                id: ruleset_id.clone(),
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

    // 4. Permission management
    if let Some(ruleset_id) = &created_ruleset_id {
        println!("\n4. PERMISSION MANAGEMENT");
        println!("------------------------");

        // Grant edit permissions
        let editors_request = AddEditorsRequest {
            data: vec![EditorDescriptor {
                object_type: "user".to_string(),
                id: "example_user".to_string(),
            }],
        };

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

    // 5. List notifications
    println!("\n5. NOTIFICATIONS");
    println!("----------------");

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

    // 6. Get notification files
    println!("\n6. NOTIFICATION FILES");
    println!("---------------------");

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

    // 7. Delete notifications by tag
    println!("\n7. NOTIFICATION MANAGEMENT");
    println!("--------------------------");

    match livehunt.delete_notifications(Some("old_tag")).await {
        Ok(_) => println!("   ✓ Deleted notifications with tag 'old_tag'"),
        Err(e) => println!("   ✗ Error deleting notifications: {}", e),
    }

    // 8. Clean up - delete the created ruleset
    if let Some(ruleset_id) = &created_ruleset_id {
        println!("\n8. CLEANUP");
        println!("----------");

        match livehunt.delete_ruleset(ruleset_id).await {
            Ok(_) => println!("   ✓ Deleted test ruleset"),
            Err(e) => println!("   ✗ Error deleting ruleset: {}", e),
        }
    }

    // 9. Test pagination with iterators
    println!("\n9. PAGINATION TEST");
    println!("------------------");

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

    // 10. Transfer ownership example (would fail without proper setup)
    println!("\n10. OWNERSHIP TRANSFER");
    println!("----------------------");

    let transfer_request = TransferOwnershipRequest {
        data: EditorDescriptor {
            object_type: "user".to_string(),
            id: "new_owner_id".to_string(),
        },
    };

    // This would transfer ownership if we had a valid ruleset and user
    println!("   Note: Ownership transfer requires valid ruleset and user in same group");

    println!("\n================================");
    println!("Livehunt API testing complete!");

    Ok(())
}
