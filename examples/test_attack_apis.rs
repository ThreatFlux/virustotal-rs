use virustotal_rs::{ApiTier, ClientBuilder};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let api_key = std::env::var("VT_API_KEY").unwrap_or_else(|_| "test_key".to_string());

    let client = ClientBuilder::new()
        .api_key(api_key)
        .tier(ApiTier::Public)
        .build()?;

    println!("Testing MITRE ATT&CK APIs:");
    println!("=========================");

    // Test Attack Tactics
    println!("\n1. Attack Tactics:");
    println!("------------------");

    let tactics_client = client.attack_tactics();

    // Test getting a specific tactic
    let tactic_id = "TA0001"; // Initial Access
    match tactics_client.get(tactic_id).await {
        Ok(tactic) => {
            println!("   ✓ Retrieved tactic: {}", tactic_id);
            if let Some(name) = &tactic.object.attributes.name {
                println!("   - Name: {}", name);
            }
            if let Some(description) = &tactic.object.attributes.description {
                println!(
                    "   - Description: {}",
                    &description[..100.min(description.len())]
                );
            }
            if let Some(url) = &tactic.object.attributes.url {
                println!("   - URL: {}", url);
            }
            if let Some(count) = &tactic.object.attributes.techniques_count {
                println!("   - Associated techniques: {}", count);
            }
        }
        Err(e) => println!("   ✗ Error: {}", e),
    }

    // Get techniques associated with a tactic
    println!("\n   Getting techniques for tactic {}:", tactic_id);
    match tactics_client.get_techniques(tactic_id).await {
        Ok(techniques) => {
            println!("   ✓ Retrieved techniques");
            if let Some(meta) = &techniques.meta {
                if let Some(count) = meta.count {
                    println!("   - Number of techniques: {}", count);
                }
            }
        }
        Err(e) => println!("   ✗ Error: {}", e),
    }

    // Test Attack Techniques
    println!("\n2. Attack Techniques:");
    println!("--------------------");

    let techniques_client = client.attack_techniques();

    // Test getting a specific technique
    let technique_id = "T1055"; // Process Injection
    match techniques_client.get(technique_id).await {
        Ok(technique) => {
            println!("   ✓ Retrieved technique: {}", technique_id);
            if let Some(name) = &technique.object.attributes.name {
                println!("   - Name: {}", name);
            }
            if let Some(description) = &technique.object.attributes.description {
                println!(
                    "   - Description: {}",
                    &description[..100.min(description.len())]
                );
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
        Err(e) => println!("   ✗ Error: {}", e),
    }

    // Get sub-techniques
    println!("\n   Getting sub-techniques for {}:", technique_id);
    match techniques_client.get_subtechniques(technique_id).await {
        Ok(subtechniques) => {
            println!("   ✓ Retrieved sub-techniques");
            if let Some(meta) = &subtechniques.meta {
                if let Some(count) = meta.count {
                    println!("   - Number of sub-techniques: {}", count);
                }
            }
        }
        Err(e) => println!("   ✗ Error: {}", e),
    }

    // Test getting a sub-technique
    let subtechnique_id = "T1055.001"; // Dynamic-link Library Injection
    println!("\n   Getting sub-technique {}:", subtechnique_id);
    match techniques_client.get(subtechnique_id).await {
        Ok(technique) => {
            println!("   ✓ Retrieved sub-technique");
            if let Some(name) = &technique.object.attributes.name {
                println!("   - Name: {}", name);
            }
            if let Some(parent) = &technique.object.attributes.parent_technique {
                println!("   - Parent technique: {}", parent);
            }
        }
        Err(e) => println!("   ✗ Error: {}", e),
    }

    // Test relationships
    println!("\n3. Testing Relationships:");
    println!("------------------------");

    // Get files associated with a technique
    println!("\n   Getting files associated with {}:", technique_id);
    match techniques_client.get_files(technique_id).await {
        Ok(files) => {
            println!("   ✓ Retrieved associated files");
            if let Some(meta) = &files.meta {
                if let Some(count) = meta.count {
                    println!("   - Number of files: {}", count);
                }
            }
        }
        Err(e) => println!("   ✗ Error: {}", e),
    }

    // Get threat actors associated with a technique
    println!("\n   Getting threat actors for {}:", technique_id);
    match techniques_client.get_threat_actors(technique_id).await {
        Ok(actors) => {
            println!("   ✓ Retrieved threat actors");
            if let Some(meta) = &actors.meta {
                if let Some(count) = meta.count {
                    println!("   - Number of threat actors: {}", count);
                }
            }
        }
        Err(e) => println!("   ✗ Error: {}", e),
    }

    // Test Popular Threat Categories
    println!("\n4. Popular Threat Categories:");
    println!("----------------------------");

    match client.get_popular_threat_categories().await {
        Ok(categories) => {
            println!("   ✓ Retrieved popular threat categories");
            println!("   - Total categories: {}", categories.data.len());

            // Display top categories
            println!("\n   Top threat categories:");
            for (i, category) in categories.data.iter().take(10).enumerate() {
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
        Err(e) => println!("   ✗ Error: {}", e),
    }

    // Test pagination with iterators
    println!("\n5. Testing Pagination:");
    println!("---------------------");

    let mut techniques_iter = tactics_client.get_relationship_iterator::<serde_json::Value>(
        "TA0002", // Execution
        "attack_techniques",
    );

    match techniques_iter.next_batch().await {
        Ok(batch) => {
            if batch.is_empty() {
                println!("   - No techniques found for TA0002");
            } else {
                println!(
                    "   ✓ Retrieved batch of {} techniques for Execution tactic",
                    batch.len()
                );
            }
        }
        Err(e) => println!("   ✗ Error: {}", e),
    }

    println!("\n=========================");
    println!("MITRE ATT&CK API testing complete!");

    Ok(())
}
