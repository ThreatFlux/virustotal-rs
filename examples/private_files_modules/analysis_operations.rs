use crate::common::*;

/// Test behavior analysis
pub async fn test_behavior_analysis(
    private_client: &virustotal_rs::PrivateFilesClient<'_>,
    hash: &str,
) {
    print_step_header(5, "BEHAVIOR ANALYSIS");

    println!("Getting behavior analysis for file...");
    match private_client.get_behaviors(hash, Some(5), None).await {
        Ok(behaviors) => {
            print_success(&format!(
                "Retrieved {} behavior reports",
                behaviors.data.len()
            ));
            display_behavior_reports(&behaviors.data);
        }
        Err(e) => print_error(&format!("Error getting behaviors: {}", e)),
    }
}

/// Display behavior reports
pub fn display_behavior_reports(behaviors: &[virustotal_rs::FileBehavior]) {
    for (i, behavior) in behaviors.iter().enumerate().take(3) {
        println!("\n  Behavior #{}", i + 1);
        if let Some(sandbox_name) = &behavior.data.attributes.sandbox_name {
            println!("    Sandbox: {}", sandbox_name);
        }
        if let Some(analysis_date) = &behavior.data.attributes.analysis_date {
            println!("    Date: {}", analysis_date);
        }
    }
}

/// Test behavior summary
pub async fn test_behavior_summary(
    private_client: &virustotal_rs::PrivateFilesClient<'_>,
    hash: &str,
) {
    print_step_header(6, "BEHAVIOR SUMMARY");

    match private_client.get_behavior_summary(hash).await {
        Ok(summary) => {
            print_success("Retrieved behavior summary");
            display_behavior_summary(&summary);
        }
        Err(e) => print_error(&format!("Error getting behavior summary: {}", e)),
    }
}

/// Display behavior summary information
pub fn display_behavior_summary(summary: &virustotal_rs::FileBehaviorSummary) {
    if let Some(processes) = &summary.processes_tree {
        println!("  Processes spawned: {}", processes.len());
    }
    if let Some(files) = &summary.files_written {
        println!("  Files written: {}", files.len());
    }
    if let Some(tags) = &summary.tags {
        if !tags.is_empty() {
            println!("  Tags: {}", tags.join(", "));
        }
    }
}

/// Test MITRE ATT&CK data
pub async fn test_mitre_attack_data(
    private_client: &virustotal_rs::PrivateFilesClient<'_>,
    hash: &str,
) {
    print_step_header(7, "MITRE ATT&CK DATA");

    match private_client.get_mitre_attack_data(hash).await {
        Ok(mitre_data) => {
            print_success("Retrieved MITRE ATT&CK data");
            display_mitre_overview(&mitre_data);
            display_mitre_sandboxes(&mitre_data);
        }
        Err(e) => print_error(&format!("Error getting MITRE ATT&CK data: {}", e)),
    }
}

/// Display MITRE data overview
pub fn display_mitre_overview(mitre_data: &virustotal_rs::MitreTrees) {
    println!("  Sandboxes analyzed: {}", mitre_data.data.len());
}

/// Display MITRE sandbox data
pub fn display_mitre_sandboxes(mitre_data: &virustotal_rs::MitreTrees) {
    for (sandbox_name, sandbox_data) in mitre_data.data.iter().take(2) {
        println!("\n  Sandbox: {}", sandbox_name);
        println!("    Tactics: {}", sandbox_data.tactics.len());
        display_tactics(&sandbox_data.tactics);
    }
}

/// Display MITRE tactics
pub fn display_tactics(tactics: &[virustotal_rs::MitreTactic]) {
    for tactic in tactics.iter().take(3) {
        println!("      - {} ({})", tactic.name, tactic.id);
        if !tactic.techniques.is_empty() {
            println!("        Techniques: {}", tactic.techniques.len());
            display_techniques(&tactic.techniques);
        }
    }
}

/// Display MITRE techniques
pub fn display_techniques(techniques: &[virustotal_rs::MitreTechnique]) {
    for technique in techniques.iter().take(2) {
        println!("          - {} ({})", technique.name, technique.id);
    }
}

/// Test dropped files retrieval
pub async fn test_dropped_files(
    private_client: &virustotal_rs::PrivateFilesClient<'_>,
    hash: &str,
) {
    print_step_header(8, "DROPPED FILES");

    match private_client.get_dropped_files(hash, Some(10), None).await {
        Ok(dropped) => {
            if dropped.data.is_empty() {
                println!("  No dropped files found");
            } else {
                print_success(&format!("Found {} dropped files", dropped.data.len()));
                display_dropped_files(&dropped.data);
            }
        }
        Err(e) => print_error(&format!("Error getting dropped files: {}", e)),
    }
}

/// Display dropped files information
pub fn display_dropped_files(files: &[virustotal_rs::DroppedFile]) {
    for (i, file) in files.iter().enumerate().take(3) {
        println!("\n  Dropped file #{}", i + 1);
        if let Some(sha256) = &file.object.attributes.sha256 {
            println!("    SHA256: {}", sha256);
        }
        if let Some(size) = &file.object.attributes.size {
            println!("    Size: {} bytes", size);
        }
    }
}
