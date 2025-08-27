use virustotal_rs::{
    sigma_rules::{SigmaRuleAttributes, SigmaRuleResponse},
    yara_rulesets::{YaraRule, YaraRulesetAttributes, YaraRulesetResponse},
    ApiTier,
};

mod common;
use common::*;

/// Test Sigma Rule retrieval and display
async fn test_sigma_rule(client: &virustotal_rs::Client, rule_id: &str) {
    print_test_header("Testing Sigma Rule Retrieval");

    match client.sigma_rules().get(rule_id).await {
        Ok(rule) => {
            print_success("Sigma rule retrieved!");
            display_sigma_rule_details(&rule);
        }
        Err(e) => {
            print_error(&format!("Could not retrieve Sigma rule: {}", e));
            println!("   Note: You need a valid Sigma rule ID from the API");
        }
    }
}

/// Display comprehensive Sigma rule information
fn display_sigma_rule_details(rule: &SigmaRuleResponse) {
    println!("\n📊 Sigma Rule Details:");
    println!("  ID: {}", rule.data.object.id);
    println!("  Type: {}", rule.data.object.object_type);

    display_sigma_rule_attributes(&rule.data.object.attributes);
    display_sigma_rule_statistics(&rule.data.object.attributes);
    display_raw_sigma_rule(&rule.data.object.attributes);
}

/// Display Sigma rule attributes
fn display_sigma_rule_attributes(attributes: &SigmaRuleAttributes) {
    display_basic_rule_info(attributes);
    display_rule_metadata(attributes);
    display_ruleset_info(attributes);
    display_threat_hunting_flag(attributes);
}

/// Display basic rule information
fn display_basic_rule_info(attributes: &SigmaRuleAttributes) {
    print_optional_field("Name", &attributes.rule_name);
    print_optional_field("Title", &attributes.rule_title);
    print_optional_field("Author", &attributes.rule_author);
    print_optional_field("Description", &attributes.rule_description);
}

/// Display rule metadata information
fn display_rule_metadata(attributes: &SigmaRuleAttributes) {
    print_optional_field("Level", &attributes.rule_level);
    print_optional_field("Status", &attributes.rule_status);
    print_optional_field("Source", &attributes.rule_source);

    if let Some(tags) = &attributes.rule_tags {
        println!("  Tags: {}", tags.join(", "));
    }
}

/// Display ruleset information
fn display_ruleset_info(attributes: &SigmaRuleAttributes) {
    print_optional_field("Ruleset", &attributes.ruleset_name);
    print_optional_field("Ruleset Version", &attributes.ruleset_version);
}

/// Display threat hunting flag if applicable
fn display_threat_hunting_flag(attributes: &SigmaRuleAttributes) {
    if let Some(is_threat_hunting) = &attributes.threat_hunting_ruleset {
        if *is_threat_hunting {
            println!("  🎯 This is a threat hunting ruleset!");
        }
    }
}

/// Helper function to print optional string fields
fn print_optional_field(label: &str, value: &Option<String>) {
    if let Some(v) = value {
        println!("  {}: {}", label, v);
    }
}

/// Display Sigma rule statistics
fn display_sigma_rule_statistics(attributes: &SigmaRuleAttributes) {
    if let Some(stats) = &attributes.stats {
        if let Some(matches) = stats.rule_matches {
            println!("  Matches: {}", matches);
        }
    }
}

/// Display raw Sigma rule content
fn display_raw_sigma_rule(attributes: &SigmaRuleAttributes) {
    if let Some(raw) = &attributes.rule_raw {
        println!("\n📝 Raw Rule (first 500 chars):");
        let preview = if raw.len() > 500 {
            format!("{}...", &raw[..500])
        } else {
            raw.clone()
        };
        println!("{}", preview);
    }
}

/// Test YARA Ruleset retrieval and display
async fn test_yara_ruleset(client: &virustotal_rs::Client, ruleset_id: &str) {
    print_test_header("Testing YARA Ruleset Retrieval");

    match client.yara_rulesets().get(ruleset_id).await {
        Ok(ruleset) => {
            print_success("YARA ruleset retrieved!");
            display_yara_ruleset_details(&ruleset);
        }
        Err(e) => {
            print_error(&format!("Could not retrieve YARA ruleset: {}", e));
            println!("   Note: You need a valid YARA ruleset ID from the API");
        }
    }
}

/// Display comprehensive YARA ruleset information
fn display_yara_ruleset_details(ruleset: &YaraRulesetResponse) {
    println!("\n📊 YARA Ruleset Details:");
    println!("  ID: {}", ruleset.data.object.id);
    println!("  Type: {}", ruleset.data.object.object_type);

    display_yara_ruleset_attributes(&ruleset.data.object.attributes);
    display_yara_rules(&ruleset.data.object.attributes);
}

/// Display YARA ruleset attributes
fn display_yara_ruleset_attributes(attributes: &YaraRulesetAttributes) {
    if let Some(name) = &attributes.name {
        println!("  Name: {}", name);
    }
    if let Some(ruleset_name) = &attributes.ruleset_name {
        println!("  Ruleset Name: {}", ruleset_name);
    }
    if let Some(version) = &attributes.ruleset_version {
        println!("  Version: {}", version);
    }
    if let Some(author) = &attributes.author {
        println!("  Author: {}", author);
    }
    if let Some(desc) = &attributes.description {
        println!("  Description: {}", desc);
    }
    if let Some(source) = &attributes.source {
        println!("  Source: {}", source);
    }
    if let Some(enabled) = &attributes.enabled {
        println!("  Enabled: {}", enabled);
    }
}

/// Display individual YARA rules in the ruleset
fn display_yara_rules(attributes: &YaraRulesetAttributes) {
    if let Some(rules) = &attributes.rules {
        println!("\n📜 Rules in Ruleset ({}):", rules.len());

        for (i, rule) in rules.iter().enumerate().take(5) {
            if let Some(rule_name) = &rule.rule_name {
                println!("  {}. {}", i + 1, rule_name);
                display_yara_rule_metadata(rule);
                display_yara_rule_strings(rule);
                display_yara_rule_condition(rule);
            }
        }

        if rules.len() > 5 {
            println!("  ... and {} more rules", rules.len() - 5);
        }
    }
}

/// Display YARA rule metadata
fn display_yara_rule_metadata(rule: &YaraRule) {
    if let Some(meta) = &rule.meta {
        if let Some(author) = &meta.author {
            println!("     Author: {}", author);
        }
        if let Some(desc) = &meta.description {
            let preview = truncate_string(desc, 100);
            println!("     Description: {}", preview);
        }
    }
}

/// Display YARA rule strings
fn display_yara_rule_strings(rule: &YaraRule) {
    if let Some(strings) = &rule.strings {
        println!("     Strings: {} defined", strings.len());
        for string in strings.iter().take(3) {
            if let (Some(id), Some(val)) = (&string.identifier, &string.value) {
                let val_preview = truncate_string(val, 50);
                println!("       • {} = {}", id, val_preview);
            }
        }
    }
}

/// Display YARA rule condition
fn display_yara_rule_condition(rule: &YaraRule) {
    if let Some(condition) = &rule.condition {
        let cond_preview = truncate_string(condition, 100);
        println!("     Condition: {}", cond_preview);
    }
}

/// Print guidance on how to find rule IDs
fn print_rule_id_guidance() {
    print_section_header("How to Find Rule IDs", 60);
    println!("• Sigma rule IDs can be found in file analysis results");
    println!("• YARA ruleset IDs can be found in crowdsourced YARA results");
    println!("• Both can be discovered through search endpoints");
    println!("• Check VirusTotal web interface for example IDs");
}

#[tokio::main]
async fn main() -> ExampleResult<()> {
    // Get API key and create client
    let api_key = std::env::var("VTI_API_KEY").unwrap_or_else(|_| {
        println!("⚠️  Warning: Using VT_API_KEY instead of VTI_API_KEY");
        get_api_key("VT_API_KEY")
    });

    println!("Using API key from environment variable");

    let client = create_client(api_key, ApiTier::Public)?;

    print_header("🎯 SIGMA RULES & YARA RULESETS TEST");

    // Note: These IDs are examples - in a real scenario you would get these
    // from search results or other API responses

    // Test Sigma Rule (example ID - may not exist)
    let sigma_rule_id = "example_sigma_rule_id"; // Replace with actual ID
    test_sigma_rule(&client, sigma_rule_id).await;

    // Test YARA Ruleset (example ID - may not exist)
    let yara_ruleset_id = "example_yara_ruleset_id"; // Replace with actual ID
    test_yara_ruleset(&client, yara_ruleset_id).await;

    print_rule_id_guidance();

    Ok(())
}
