use virustotal_rs::{ApiTier, ClientBuilder};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // NOTE: Private file scanning requires special privileges
    let api_key = std::env::var("VT_PRIVATE_API_KEY")
        .or_else(|_| std::env::var("VT_API_KEY"))
        .unwrap_or_else(|_| "test_key".to_string());

    let client = ClientBuilder::new()
        .api_key(api_key)
        .tier(ApiTier::Premium)
        .build()?;

    println!("Testing VirusTotal Private Analyses & Behavior Reports");
    println!("======================================================");
    println!("⚠️  NOTE: Requires Private Scanning License");
    println!("======================================================\n");

    let private_client = client.private_files();

    // 1. List private analyses
    println!("1. LIST PRIVATE ANALYSES");
    println!("------------------------");

    println!("Listing recent private analyses...");

    match private_client
        .list_analyses(Some(10), None, Some("date-"))
        .await
    {
        Ok(analyses) => {
            println!("✓ Retrieved {} analyses", analyses.data.len());

            for analysis in analyses.data.iter().take(3) {
                println!("\n  Analysis ID: {}", analysis.object.id);
                if let Some(status) = &analysis.object.attributes.status {
                    println!("    Status: {}", status);
                }
                if let Some(date) = &analysis.object.attributes.date {
                    println!("    Date: {}", date);
                }
                if let Some(stats) = &analysis.object.attributes.stats {
                    if let Some(malicious_count) = stats.malicious {
                        print!("    Detections: {}", malicious_count);
                        if let Some(total) = stats.undetected {
                            println!(" / {}", malicious_count + total);
                        }
                    }
                }
            }

            // Save first analysis ID for further testing
            if let Some(first_analysis) = analyses.data.first() {
                let analysis_id = &first_analysis.object.id;

                // 2. Get single analysis with file info
                println!("\n2. GET SINGLE ANALYSIS");
                println!("----------------------");

                match private_client.get_single_analysis(analysis_id).await {
                    Ok(response) => {
                        println!("✓ Retrieved analysis details");
                        println!("  Analysis ID: {}", response.data.object.id);

                        if let Some(status) = &response.data.object.attributes.status {
                            println!("  Status: {}", status);
                        }

                        if let Some(meta) = &response.meta {
                            if let Some(file_info) = &meta.file_info {
                                println!("  File Information:");
                                if let Some(sha256) = &file_info.sha256 {
                                    println!("    SHA256: {}", sha256);
                                }
                                if let Some(size) = &file_info.size {
                                    println!("    Size: {} bytes", size);
                                }
                                if let Some(md5) = &file_info.md5 {
                                    println!("    MD5: {}", md5);
                                }
                            }
                        }
                    }
                    Err(e) => {
                        println!("✗ Error getting analysis: {}", e);
                    }
                }

                // 3. Get analysis relationships
                println!("\n3. ANALYSIS RELATIONSHIPS");
                println!("-------------------------");

                match private_client
                    .get_analysis_relationship::<serde_json::Value>(analysis_id, "item")
                    .await
                {
                    Ok(items) => {
                        println!("✓ Retrieved analysis items: {}", items.data.len());
                    }
                    Err(e) => {
                        println!("✗ Error getting analysis relationships: {}", e);
                    }
                }
            }
        }
        Err(e) => {
            println!("✗ Error listing analyses: {}", e);
            println!("  Note: This requires private scanning privileges");
        }
    }

    // 4. Test with a known file (EICAR test file)
    let eicar_hash = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f";

    println!("\n4. MITRE ATT&CK DATA");
    println!("--------------------");

    println!("Getting MITRE ATT&CK tactics and techniques...");

    match private_client.get_mitre_attack_data(eicar_hash).await {
        Ok(_mitre_data) => {
            println!("✓ Retrieved MITRE ATT&CK data");

            // The data structure is different for private files - it's organized by sandbox
            // Let's handle the response properly
            println!("  Data retrieved successfully");
            println!("  (MITRE data contains tactics and techniques organized by sandbox)");
        }
        Err(e) => {
            println!("✗ Error getting MITRE ATT&CK data: {}", e);
        }
    }

    // 5. Get behavior reports
    println!("\n5. BEHAVIOR REPORTS");
    println!("-------------------");

    match private_client
        .get_behaviors(eicar_hash, Some(5), None)
        .await
    {
        Ok(behaviors) => {
            if behaviors.data.is_empty() {
                println!("  No behavior reports found");
            } else {
                println!("✓ Found {} behavior reports", behaviors.data.len());

                // Get first sandbox ID for detailed testing
                if let Some(first_behavior) = behaviors.data.first() {
                    let sandbox_id = &first_behavior.data.id;

                    println!("\n  Testing with sandbox ID: {}", sandbox_id);

                    // 6. Get specific behavior report
                    println!("\n6. SPECIFIC BEHAVIOR REPORT");
                    println!("---------------------------");

                    match private_client.get_file_behavior(sandbox_id).await {
                        Ok(behavior) => {
                            println!("✓ Retrieved behavior report");

                            if let Some(sandbox_name) = &behavior.object.attributes.sandbox_name {
                                println!("  Sandbox: {}", sandbox_name);
                            }

                            if let Some(has_html) = &behavior.object.attributes.has_html_report {
                                println!("  HTML Report Available: {}", has_html);
                            }

                            if let Some(has_pcap) = &behavior.object.attributes.has_pcap {
                                println!("  PCAP Available: {}", has_pcap);
                            }

                            if let Some(calls) = &behavior.object.attributes.calls_highlighted {
                                if !calls.is_empty() {
                                    println!("  Highlighted API Calls: {}", calls.len());
                                    for call in calls.iter().take(3) {
                                        println!("    - {}", call);
                                    }
                                }
                            }

                            if let Some(processes) = &behavior.object.attributes.processes_tree {
                                if !processes.is_empty() {
                                    println!("  Process Tree: {} processes", processes.len());
                                }
                            }

                            if let Some(tags) = &behavior.object.attributes.tags {
                                if !tags.is_empty() {
                                    println!("  Tags: {}", tags.join(", "));
                                }
                            }
                        }
                        Err(e) => {
                            println!("✗ Error getting behavior report: {}", e);
                        }
                    }

                    // 7. Get HTML report
                    println!("\n7. HTML BEHAVIOR REPORT");
                    println!("-----------------------");

                    match private_client.get_behavior_html_report(sandbox_id).await {
                        Ok(html) => {
                            println!("✓ Retrieved HTML report");
                            println!("  Size: {} bytes", html.len());
                            println!("  First 100 chars: {}...", &html[..100.min(html.len())]);
                        }
                        Err(e) => {
                            println!("✗ Error getting HTML report: {}", e);
                        }
                    }

                    // 8. Get EVTX file
                    println!("\n8. EVTX FILE");
                    println!("------------");

                    match private_client.get_behavior_evtx(sandbox_id).await {
                        Ok(evtx) => {
                            println!("✓ Retrieved EVTX file");
                            println!("  Size: {} bytes", evtx.len());
                            println!("  (Windows Event Log data)");
                        }
                        Err(e) => {
                            println!("✗ Error getting EVTX file: {}", e);
                            println!("  Note: EVTX may not be available for all analyses");
                        }
                    }

                    // 9. Get PCAP file
                    println!("\n9. PCAP FILE");
                    println!("------------");

                    match private_client.get_behavior_pcap(sandbox_id).await {
                        Ok(pcap) => {
                            println!("✓ Retrieved PCAP file");
                            println!("  Size: {} bytes", pcap.len());
                            println!("  (Network packet capture data)");
                        }
                        Err(e) => {
                            println!("✗ Error getting PCAP file: {}", e);
                            println!("  Note: PCAP may not be available for all analyses");
                        }
                    }

                    // 10. Get memory dump
                    println!("\n10. MEMORY DUMP");
                    println!("---------------");

                    match private_client.get_behavior_memdump(sandbox_id).await {
                        Ok(memdump) => {
                            println!("✓ Retrieved memory dump");
                            println!("  Size: {} bytes", memdump.len());
                            println!("  (Process memory dump data)");
                        }
                        Err(e) => {
                            println!("✗ Error getting memory dump: {}", e);
                            println!("  Note: Memory dump may not be available for all analyses");
                        }
                    }

                    // 11. Get behavior relationships
                    println!("\n11. BEHAVIOR RELATIONSHIPS");
                    println!("--------------------------");

                    match private_client
                        .get_behavior_relationship::<serde_json::Value>(
                            sandbox_id,
                            "file",
                            Some(5),
                            None,
                        )
                        .await
                    {
                        Ok(relationships) => {
                            println!("✓ Retrieved behavior relationships");
                            println!("  Found {} related objects", relationships.data.len());
                        }
                        Err(e) => {
                            println!("✗ Error getting behavior relationships: {}", e);
                        }
                    }
                }
            }
        }
        Err(e) => {
            println!("✗ Error getting behaviors: {}", e);
        }
    }

    // 12. Test pagination with analysis iterator
    println!("\n12. ANALYSIS PAGINATION");
    println!("------------------------");

    let mut analysis_iterator = private_client.list_analyses_iterator();

    match analysis_iterator.next_batch().await {
        Ok(batch) => {
            println!("✓ Retrieved {} analyses in first batch", batch.len());

            if batch.len() > 10 {
                println!("  Has more pages available for pagination");
            }
        }
        Err(e) => {
            println!("✗ Error with analysis pagination: {}", e);
        }
    }

    // 13. Test alternate behavior endpoint
    println!("\n13. ALTERNATE BEHAVIOR ENDPOINT");
    println!("-------------------------------");

    match private_client.get_file_behaviors_alt(eicar_hash).await {
        Ok(behaviors) => {
            println!("✓ Retrieved behaviors via alternate endpoint");
            println!("  Found {} behavior reports", behaviors.data.len());
        }
        Err(e) => {
            println!("✗ Error with alternate endpoint: {}", e);
            println!("  Note: This endpoint may have different access requirements");
        }
    }

    println!("\n======================================================");
    println!("Private Analyses & Behavior Testing Complete!");
    println!("\nNOTE: Many features require a Private Scanning License.");
    println!("Some behavior artifacts (EVTX, PCAP, memdump) may not");
    println!("be available for all files or sandbox environments.");

    Ok(())
}
