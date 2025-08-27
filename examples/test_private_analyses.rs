use virustotal_rs::private_files::{
    AnalysisStats, FileInfo, PrivateAnalysis, PrivateAnalysisAttributes, PrivateAnalysisMeta,
    PrivateAnalysisResponse, PrivateFileBehaviorAttributes, ProcessInfo,
};
use virustotal_rs::{ApiTier, ClientBuilder, PrivateFilesClient};

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

    // Test core private analysis functionality
    test_private_analyses(&private_client).await;
    test_mitre_attack_data(&private_client).await;
    test_behavior_reports(&private_client).await;
    test_analysis_pagination(&private_client).await;
    test_alternate_endpoints(&private_client).await;

    display_completion_message();

    Ok(())
}

async fn test_private_analyses(private_client: &PrivateFilesClient<'_>) {
    list_private_analyses(private_client).await;
}

async fn list_private_analyses(private_client: &PrivateFilesClient<'_>) {
    println!("1. LIST PRIVATE ANALYSES");
    println!("------------------------");
    println!("Listing recent private analyses...");

    match private_client
        .list_analyses(Some(10), None, Some("date-"))
        .await
    {
        Ok(analyses) => {
            println!("✓ Retrieved {} analyses", analyses.data.len());
            display_analyses_overview(&analyses.data);

            if let Some(first_analysis) = analyses.data.first() {
                test_single_analysis(private_client, &first_analysis.object.id).await;
            }
        }
        Err(e) => {
            println!("✗ Error listing analyses: {}", e);
            println!("  Note: This requires private scanning privileges");
        }
    }
}

fn display_analyses_overview(analyses: &[PrivateAnalysis]) {
    for analysis in analyses.iter().take(3) {
        println!("\n  Analysis ID: {}", analysis.object.id);
        display_analysis_details(&analysis.object.attributes);
    }
}

fn display_analysis_details(attributes: &PrivateAnalysisAttributes) {
    if let Some(status) = &attributes.status {
        println!("    Status: {}", status);
    }
    if let Some(date) = &attributes.date {
        println!("    Date: {}", date);
    }
    display_analysis_stats(&attributes.stats);
}

fn display_analysis_stats(stats: &Option<AnalysisStats>) {
    if let Some(stats) = stats {
        if let Some(malicious_count) = stats.malicious {
            print!("    Detections: {}", malicious_count);
            if let Some(total) = stats.undetected {
                println!(" / {}", malicious_count + total);
            } else {
                println!();
            }
        }
    }
}

async fn test_single_analysis(private_client: &PrivateFilesClient<'_>, analysis_id: &str) {
    println!("\n2. GET SINGLE ANALYSIS");
    println!("----------------------");

    match private_client.get_single_analysis(analysis_id).await {
        Ok(response) => {
            println!("✓ Retrieved analysis details");
            display_single_analysis_info(&response);
        }
        Err(e) => {
            println!("✗ Error getting analysis: {}", e);
        }
    }

    get_analysis_relationships(private_client, analysis_id).await;
}

fn display_single_analysis_info(response: &PrivateAnalysisResponse) {
    println!("  Analysis ID: {}", response.data.object.id);

    if let Some(status) = &response.data.object.attributes.status {
        println!("  Status: {}", status);
    }

    display_file_info_from_meta(&response.meta);
}

fn display_file_info_from_meta(meta: &Option<PrivateAnalysisMeta>) {
    if let Some(meta) = meta {
        if let Some(file_info) = &meta.file_info {
            println!("  File Information:");
            display_file_details(file_info);
        }
    }
}

fn display_file_details(file_info: &FileInfo) {
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

async fn get_analysis_relationships(private_client: &PrivateFilesClient<'_>, analysis_id: &str) {
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

async fn test_mitre_attack_data(private_client: &PrivateFilesClient<'_>) {
    let eicar_hash = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f";

    println!("\n4. MITRE ATT&CK DATA");
    println!("--------------------");
    println!("Getting MITRE ATT&CK tactics and techniques...");

    match private_client.get_mitre_attack_data(eicar_hash).await {
        Ok(_mitre_data) => {
            println!("✓ Retrieved MITRE ATT&CK data");
            println!("  Data retrieved successfully");
            println!("  (MITRE data contains tactics and techniques organized by sandbox)");
        }
        Err(e) => {
            println!("✗ Error getting MITRE ATT&CK data: {}", e);
        }
    }
}

async fn test_behavior_reports(private_client: &PrivateFilesClient<'_>) {
    let eicar_hash = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f";

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

                if let Some(first_behavior) = behaviors.data.first() {
                    test_detailed_behavior_analysis(private_client, &first_behavior.data.id).await;
                }
            }
        }
        Err(e) => {
            println!("✗ Error getting behaviors: {}", e);
        }
    }
}

async fn test_detailed_behavior_analysis(
    private_client: &PrivateFilesClient<'_>,
    sandbox_id: &str,
) {
    println!("\n  Testing with sandbox ID: {}", sandbox_id);

    get_specific_behavior_report(private_client, sandbox_id).await;
    get_behavior_artifacts(private_client, sandbox_id).await;
    get_behavior_relationships(private_client, sandbox_id).await;
}

async fn get_specific_behavior_report(private_client: &PrivateFilesClient<'_>, sandbox_id: &str) {
    println!("\n6. SPECIFIC BEHAVIOR REPORT");
    println!("---------------------------");

    match private_client.get_file_behavior(sandbox_id).await {
        Ok(behavior) => {
            println!("✓ Retrieved behavior report");
            display_behavior_info(&behavior.object.attributes);
        }
        Err(e) => {
            println!("✗ Error getting behavior report: {}", e);
        }
    }
}

fn display_behavior_info(attributes: &PrivateFileBehaviorAttributes) {
    if let Some(sandbox_name) = &attributes.sandbox_name {
        println!("  Sandbox: {}", sandbox_name);
    }

    display_report_availability(attributes);
    display_behavior_details(attributes);
}

fn display_report_availability(attributes: &PrivateFileBehaviorAttributes) {
    if let Some(has_html) = &attributes.has_html_report {
        println!("  HTML Report Available: {}", has_html);
    }
    if let Some(has_pcap) = &attributes.has_pcap {
        println!("  PCAP Available: {}", has_pcap);
    }
}

fn display_behavior_details(attributes: &PrivateFileBehaviorAttributes) {
    display_highlighted_calls(&attributes.calls_highlighted);
    display_process_tree(&attributes.processes_tree);
    display_behavior_tags(&attributes.tags);
}

fn display_highlighted_calls(calls: &Option<Vec<String>>) {
    if let Some(calls) = calls {
        if !calls.is_empty() {
            println!("  Highlighted API Calls: {}", calls.len());
            for call in calls.iter().take(3) {
                println!("    - {}", call);
            }
        }
    }
}

fn display_process_tree(processes: &Option<Vec<ProcessInfo>>) {
    if let Some(processes) = processes {
        if !processes.is_empty() {
            println!("  Process Tree: {} processes", processes.len());
        }
    }
}

fn display_behavior_tags(tags: &Option<Vec<String>>) {
    if let Some(tags) = tags {
        if !tags.is_empty() {
            println!("  Tags: {}", tags.join(", "));
        }
    }
}

async fn get_behavior_artifacts(private_client: &PrivateFilesClient<'_>, sandbox_id: &str) {
    get_html_report(private_client, sandbox_id).await;
    get_evtx_file(private_client, sandbox_id).await;
    get_pcap_file(private_client, sandbox_id).await;
    get_memory_dump(private_client, sandbox_id).await;
}

async fn get_html_report(private_client: &PrivateFilesClient<'_>, sandbox_id: &str) {
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
}

async fn get_evtx_file(private_client: &PrivateFilesClient<'_>, sandbox_id: &str) {
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
}

async fn get_pcap_file(private_client: &PrivateFilesClient<'_>, sandbox_id: &str) {
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
}

async fn get_memory_dump(private_client: &PrivateFilesClient<'_>, sandbox_id: &str) {
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
}

async fn get_behavior_relationships(private_client: &PrivateFilesClient<'_>, sandbox_id: &str) {
    println!("\n11. BEHAVIOR RELATIONSHIPS");
    println!("--------------------------");

    match private_client
        .get_behavior_relationship::<serde_json::Value>(sandbox_id, "file", Some(5), None)
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

async fn test_analysis_pagination(private_client: &PrivateFilesClient<'_>) {
    println!("\n12. ANALYSIS PAGINATION");
    println!("------------------------");

    let mut analysis_iterator = private_client.list_analyses_iterator();

    match analysis_iterator.next_batch().await {
        Ok(batch) => {
            println!("✓ Retrieved {} analyses in first batch", batch.len());
            display_pagination_info(&batch);
        }
        Err(e) => {
            println!("✗ Error with analysis pagination: {}", e);
        }
    }
}

fn display_pagination_info(batch: &[PrivateAnalysis]) {
    if batch.len() > 10 {
        println!("  Has more pages available for pagination");
    }
}

async fn test_alternate_endpoints(private_client: &PrivateFilesClient<'_>) {
    println!("\n13. ALTERNATE BEHAVIOR ENDPOINT");
    println!("-------------------------------");

    let eicar_hash = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f";

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
}

fn display_completion_message() {
    println!("\n======================================================");
    println!("Private Analyses & Behavior Testing Complete!");
    println!("\nNOTE: Many features require a Private Scanning License.");
    println!("Some behavior artifacts (EVTX, PCAP, memdump) may not");
    println!("be available for all files or sandbox environments.");
}
