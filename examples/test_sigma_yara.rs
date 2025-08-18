use std::env;
use virustotal_rs::{ApiTier, ClientBuilder};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Get API key from environment variable
    let api_key = env::var("VTI_API_KEY").expect("VTI_API_KEY environment variable not set");

    println!("Using API key from VTI_API_KEY environment variable");

    // Create client
    let client = ClientBuilder::new()
        .api_key(api_key)
        .tier(ApiTier::Public)
        .build()?;

    println!("\n{}", "=".repeat(60));
    println!("🎯 SIGMA RULES & YARA RULESETS TEST");
    println!("{}", "=".repeat(60));

    // Note: These IDs are examples - in a real scenario you would get these
    // from search results or other API responses

    // Test Sigma Rule (example ID - may not exist)
    println!("\n📋 Testing Sigma Rule Retrieval...");
    let sigma_rule_id = "example_sigma_rule_id"; // Replace with actual ID
    match client.sigma_rules().get(sigma_rule_id).await {
        Ok(rule) => {
            println!("✅ Sigma rule retrieved!");
            println!("\n📊 Sigma Rule Details:");
            println!("  ID: {}", rule.data.object.id);
            println!("  Type: {}", rule.data.object.object_type);

            if let Some(name) = &rule.data.object.attributes.rule_name {
                println!("  Name: {}", name);
            }
            if let Some(title) = &rule.data.object.attributes.rule_title {
                println!("  Title: {}", title);
            }
            if let Some(author) = &rule.data.object.attributes.rule_author {
                println!("  Author: {}", author);
            }
            if let Some(desc) = &rule.data.object.attributes.rule_description {
                println!("  Description: {}", desc);
            }
            if let Some(level) = &rule.data.object.attributes.rule_level {
                println!("  Level: {}", level);
            }
            if let Some(status) = &rule.data.object.attributes.rule_status {
                println!("  Status: {}", status);
            }
            if let Some(tags) = &rule.data.object.attributes.rule_tags {
                println!("  Tags: {}", tags.join(", "));
            }
            if let Some(source) = &rule.data.object.attributes.rule_source {
                println!("  Source: {}", source);
            }
            if let Some(ruleset) = &rule.data.object.attributes.ruleset_name {
                println!("  Ruleset: {}", ruleset);
            }
            if let Some(version) = &rule.data.object.attributes.ruleset_version {
                println!("  Ruleset Version: {}", version);
            }
            if let Some(is_threat_hunting) = &rule.data.object.attributes.threat_hunting_ruleset {
                if *is_threat_hunting {
                    println!("  🎯 This is a threat hunting ruleset!");
                }
            }

            if let Some(stats) = &rule.data.object.attributes.stats {
                if let Some(matches) = stats.rule_matches {
                    println!("  Matches: {}", matches);
                }
            }

            // Show raw rule if available
            if let Some(raw) = &rule.data.object.attributes.rule_raw {
                println!("\n📝 Raw Rule (first 500 chars):");
                let preview = if raw.len() > 500 {
                    format!("{}...", &raw[..500])
                } else {
                    raw.clone()
                };
                println!("{}", preview);
            }
        }
        Err(e) => {
            println!("⚠️ Could not retrieve Sigma rule: {}", e);
            println!("   Note: You need a valid Sigma rule ID from the API");
        }
    }

    // Test YARA Ruleset (example ID - may not exist)
    println!("\n\n📋 Testing YARA Ruleset Retrieval...");
    let yara_ruleset_id = "example_yara_ruleset_id"; // Replace with actual ID
    match client.yara_rulesets().get(yara_ruleset_id).await {
        Ok(ruleset) => {
            println!("✅ YARA ruleset retrieved!");
            println!("\n📊 YARA Ruleset Details:");
            println!("  ID: {}", ruleset.data.object.id);
            println!("  Type: {}", ruleset.data.object.object_type);

            if let Some(name) = &ruleset.data.object.attributes.name {
                println!("  Name: {}", name);
            }
            if let Some(ruleset_name) = &ruleset.data.object.attributes.ruleset_name {
                println!("  Ruleset Name: {}", ruleset_name);
            }
            if let Some(version) = &ruleset.data.object.attributes.ruleset_version {
                println!("  Version: {}", version);
            }
            if let Some(author) = &ruleset.data.object.attributes.author {
                println!("  Author: {}", author);
            }
            if let Some(desc) = &ruleset.data.object.attributes.description {
                println!("  Description: {}", desc);
            }
            if let Some(source) = &ruleset.data.object.attributes.source {
                println!("  Source: {}", source);
            }
            if let Some(enabled) = &ruleset.data.object.attributes.enabled {
                println!("  Enabled: {}", enabled);
            }

            // Display individual rules in the ruleset
            if let Some(rules) = &ruleset.data.object.attributes.rules {
                println!("\n📜 Rules in Ruleset ({}):", rules.len());
                for (i, rule) in rules.iter().enumerate().take(5) {
                    if let Some(rule_name) = &rule.rule_name {
                        println!("  {}. {}", i + 1, rule_name);

                        // Show rule metadata
                        if let Some(meta) = &rule.meta {
                            if let Some(author) = &meta.author {
                                println!("     Author: {}", author);
                            }
                            if let Some(desc) = &meta.description {
                                let preview = if desc.len() > 100 {
                                    format!("{}...", &desc[..100])
                                } else {
                                    desc.clone()
                                };
                                println!("     Description: {}", preview);
                            }
                        }

                        // Show strings if available
                        if let Some(strings) = &rule.strings {
                            println!("     Strings: {} defined", strings.len());
                            for string in strings.iter().take(3) {
                                if let (Some(id), Some(val)) = (&string.identifier, &string.value) {
                                    let val_preview = if val.len() > 50 {
                                        format!("{}...", &val[..50])
                                    } else {
                                        val.clone()
                                    };
                                    println!("       • {} = {}", id, val_preview);
                                }
                            }
                        }

                        // Show condition
                        if let Some(condition) = &rule.condition {
                            let cond_preview = if condition.len() > 100 {
                                format!("{}...", &condition[..100])
                            } else {
                                condition.clone()
                            };
                            println!("     Condition: {}", cond_preview);
                        }
                    }
                }

                if rules.len() > 5 {
                    println!("  ... and {} more rules", rules.len() - 5);
                }
            }
        }
        Err(e) => {
            println!("⚠️ Could not retrieve YARA ruleset: {}", e);
            println!("   Note: You need a valid YARA ruleset ID from the API");
        }
    }

    println!("\n{}", "=".repeat(60));
    println!("💡 How to Find Rule IDs:");
    println!("{}", "=".repeat(60));
    println!("• Sigma rule IDs can be found in file analysis results");
    println!("• YARA ruleset IDs can be found in crowdsourced YARA results");
    println!("• Both can be discovered through search endpoints");
    println!("• Check VirusTotal web interface for example IDs");

    Ok(())
}
