use virustotal_rs::ApiTier;

mod common;
use common::*;

/// Test attack tactics functionality
async fn test_attack_tactics(client: &virustotal_rs::Client) {
    print_step_header(1, "ATTACK TACTICS");

    let tactics_client = client.attack_tactics();
    let tactic_id = "TA0001"; // Initial Access

    // Test getting a specific tactic
    match tactics_client.get(tactic_id).await {
        Ok(tactic) => {
            print_success(&format!("Retrieved tactic: {}", tactic_id));
            display_tactic_details(&tactic);
        }
        Err(e) => print_error(&format!("Error: {}", e)),
    }

    // Get techniques associated with a tactic
    test_tactic_techniques(&tactics_client, tactic_id).await;
}

/// Display tactic details
fn display_tactic_details(tactic: &virustotal_rs::AttackTactic) {
    if let Some(name) = &tactic.object.attributes.name {
        println!("   - Name: {}", name);
    }
    if let Some(description) = &tactic.object.attributes.description {
        println!("   - Description: {}", truncate_string(description, 100));
    }
    if let Some(url) = &tactic.object.attributes.url {
        println!("   - URL: {}", url);
    }
    if let Some(count) = &tactic.object.attributes.techniques_count {
        println!("   - Associated techniques: {}", count);
    }
}

/// Display tactic techniques header
fn display_techniques_header(tactic_id: &str) {
    println!("\n   Getting techniques for tactic {}:", tactic_id);
}

/// Display techniques metadata information
fn display_techniques_metadata(techniques: &virustotal_rs::Collection<serde_json::Value>) {
    if let Some(meta) = &techniques.meta {
        if let Some(count) = meta.count {
            println!("   - Number of techniques: {}", count);
        }
    }
}

/// Handle successful techniques retrieval
fn handle_techniques_success(techniques: &virustotal_rs::Collection<serde_json::Value>) {
    print_success("Retrieved techniques");
    display_techniques_metadata(techniques);
}

/// Test getting techniques for a tactic
async fn test_tactic_techniques(
    tactics_client: &virustotal_rs::AttackTacticClient<'_>,
    tactic_id: &str,
) {
    display_techniques_header(tactic_id);
    match tactics_client.get_techniques(tactic_id).await {
        Ok(techniques) => handle_techniques_success(&techniques),
        Err(e) => print_error(&format!("Error: {}", e)),
    }
}

/// Test attack techniques functionality
async fn test_attack_techniques(client: &virustotal_rs::Client) {
    print_step_header(2, "ATTACK TECHNIQUES");

    let techniques_client = client.attack_techniques();
    let technique_id = "T1055"; // Process Injection

    // Test getting a specific technique
    match techniques_client.get(technique_id).await {
        Ok(technique) => {
            print_success(&format!("Retrieved technique: {}", technique_id));
            display_technique_details(&technique);
        }
        Err(e) => print_error(&format!("Error: {}", e)),
    }

    // Get sub-techniques
    test_subtechniques(&techniques_client, technique_id).await;

    // Test getting a sub-technique
    test_specific_subtechnique(&techniques_client).await;
}

/// Display technique details
fn display_technique_details(technique: &virustotal_rs::AttackTechnique) {
    if let Some(name) = &technique.object.attributes.name {
        println!("   - Name: {}", name);
    }
    if let Some(description) = &technique.object.attributes.description {
        println!("   - Description: {}", truncate_string(description, 100));
    }
    if let Some(platforms) = &technique.object.attributes.platforms {
        println!("   - Platforms: {:?}", platforms);
    }
    if let Some(tactics) = &technique.object.attributes.tactics {
        println!("   - Tactics: {:?}", tactics);
    }
    if let Some(is_sub) = &technique.object.attributes.is_subtechnique {
        println!("   - Is sub-technique: {}", is_sub);
    }
    if let Some(count) = &technique.object.attributes.subtechniques_count {
        println!("   - Sub-techniques count: {}", count);
    }
}

/// Test getting sub-techniques
async fn test_subtechniques(
    techniques_client: &virustotal_rs::AttackTechniqueClient<'_>,
    technique_id: &str,
) {
    println!("\n   Getting sub-techniques for {}:", technique_id);
    match techniques_client.get_subtechniques(technique_id).await {
        Ok(subtechniques) => {
            print_success("Retrieved sub-techniques");
            if let Some(meta) = &subtechniques.meta {
                if let Some(count) = meta.count {
                    println!("   - Number of sub-techniques: {}", count);
                }
            }
        }
        Err(e) => print_error(&format!("Error: {}", e)),
    }
}

/// Test getting a specific sub-technique
async fn test_specific_subtechnique(techniques_client: &virustotal_rs::AttackTechniqueClient<'_>) {
    let subtechnique_id = "T1055.001"; // Dynamic-link Library Injection
    println!("\n   Getting sub-technique {}:", subtechnique_id);

    match techniques_client.get(subtechnique_id).await {
        Ok(technique) => {
            print_success("Retrieved sub-technique");
            if let Some(name) = &technique.object.attributes.name {
                println!("   - Name: {}", name);
            }
            if let Some(parent) = &technique.object.attributes.parent_technique {
                println!("   - Parent technique: {}", parent);
            }
        }
        Err(e) => print_error(&format!("Error: {}", e)),
    }
}

/// Test relationships between techniques and other entities
async fn test_technique_relationships(client: &virustotal_rs::Client) {
    print_step_header(3, "TESTING RELATIONSHIPS");

    let techniques_client = client.attack_techniques();
    let technique_id = "T1055";

    // Get files associated with a technique
    test_technique_files(&techniques_client, technique_id).await;

    // Get threat actors associated with a technique
    test_technique_threat_actors(&techniques_client, technique_id).await;
}

/// Test getting files associated with a technique
async fn test_technique_files(
    techniques_client: &virustotal_rs::AttackTechniqueClient<'_>,
    technique_id: &str,
) {
    println!("\n   Getting files associated with {}:", technique_id);
    match techniques_client.get_files(technique_id).await {
        Ok(files) => {
            print_success("Retrieved associated files");
            if let Some(meta) = &files.meta {
                if let Some(count) = meta.count {
                    println!("   - Number of files: {}", count);
                }
            }
        }
        Err(e) => print_error(&format!("Error: {}", e)),
    }
}

/// Test getting threat actors associated with a technique
async fn test_technique_threat_actors(
    techniques_client: &virustotal_rs::AttackTechniqueClient<'_>,
    technique_id: &str,
) {
    println!("\n   Getting threat actors for {}:", technique_id);
    match techniques_client.get_threat_actors(technique_id).await {
        Ok(actors) => {
            print_success("Retrieved threat actors");
            if let Some(meta) = &actors.meta {
                if let Some(count) = meta.count {
                    println!("   - Number of threat actors: {}", count);
                }
            }
        }
        Err(e) => print_error(&format!("Error: {}", e)),
    }
}

/// Test popular threat categories
async fn test_popular_threat_categories(client: &virustotal_rs::Client) {
    print_step_header(4, "POPULAR THREAT CATEGORIES");

    match client.get_popular_threat_categories().await {
        Ok(categories) => {
            print_success("Retrieved popular threat categories");
            println!("   - Total categories: {}", categories.data.len());
            display_threat_categories(&categories.data);
        }
        Err(e) => print_error(&format!("Error: {}", e)),
    }
}

/// Display top threat categories
fn display_threat_categories(categories: &[virustotal_rs::ThreatCategory]) {
    println!("\n   Top threat categories:");
    for (i, category) in categories.iter().take(10).enumerate() {
        print!("   {}. {}", i + 1, category.value);
        if let Some(label) = &category.label {
            print!(" ({})", label);
        }
        if let Some(count) = &category.count {
            print!(" - {} files", count);
        }
        println!();
    }
}

/// Test pagination with iterators
async fn test_pagination_iterators(client: &virustotal_rs::Client) {
    print_step_header(5, "TESTING PAGINATION");

    let tactics_client = client.attack_tactics();
    let mut techniques_iter = tactics_client.get_relationship_iterator::<serde_json::Value>(
        "TA0002", // Execution
        "attack_techniques",
    );

    match techniques_iter.next_batch().await {
        Ok(batch) => {
            if batch.is_empty() {
                println!("   - No techniques found for TA0002");
            } else {
                print_success(&format!(
                    "Retrieved batch of {} techniques for Execution tactic",
                    batch.len()
                ));
            }
        }
        Err(e) => print_error(&format!("Error: {}", e)),
    }
}

#[tokio::main]
async fn main() -> ExampleResult<()> {
    let client = create_client_from_env("VT_API_KEY", ApiTier::Public)?;

    print_header("Testing MITRE ATT&CK APIs");

    // Execute all test scenarios
    test_attack_tactics(&client).await;
    test_attack_techniques(&client).await;
    test_technique_relationships(&client).await;
    test_popular_threat_categories(&client).await;
    test_pagination_iterators(&client).await;

    println!("\n=========================");
    println!("MITRE ATT&CK API testing complete!");

    Ok(())
}
