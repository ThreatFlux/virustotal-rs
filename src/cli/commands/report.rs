use crate::cli::utils::{
    colorize_text, format_detection_ratio, format_file_size, format_timestamp, get_detection_ratio,
    handle_vt_error, print_json, print_table_row, print_table_separator, setup_client,
    truncate_hash, validate_hash,
};
use crate::Client;
use anyhow::{Context, Result};
use clap::Args;
use serde_json::Value;
use std::collections::HashMap;

#[derive(Args, Debug)]
pub struct ReportArgs {
    /// File hash to get report for
    #[arg(short = 'H', long)]
    pub hash: String,

    /// Output format (json, table, summary, detailed)
    #[arg(short = 'f', long, default_value = "summary")]
    pub format: String,

    /// Include raw JSON in output
    #[arg(long)]
    pub include_raw: bool,

    /// Show only detection results
    #[arg(long)]
    pub detections_only: bool,

    /// Show only specific sections (comma-separated: basic,detections,sandbox,yara,pe)
    #[arg(long)]
    pub sections: Option<String>,

    /// Filter detections by minimum confidence level
    #[arg(long)]
    pub min_confidence: Option<u32>,

    /// Show only engines that detected the file
    #[arg(long)]
    pub detected_only: bool,

    /// Save report to file
    #[arg(short, long)]
    pub output: Option<String>,

    /// Include metadata about the analysis
    #[arg(long)]
    pub include_metadata: bool,
}

pub async fn execute(
    args: ReportArgs,
    api_key: Option<String>,
    tier: &str,
    verbose: bool,
    dry_run: bool,
    no_color: bool,
) -> Result<()> {
    validate_hash(&args.hash)?;

    if dry_run {
        println!("DRY RUN MODE - Would fetch report for hash: {}", args.hash);
        return Ok(());
    }

    let client = setup_client(api_key, tier)?;

    if verbose {
        println!("Fetching report for hash: {}", args.hash);
    }

    let file_info = match client.files().get(&args.hash).await {
        Ok(info) => info,
        Err(e) => {
            let error_msg = handle_vt_error(&e);
            return Err(anyhow::anyhow!("Failed to get report: {}", error_msg));
        }
    };

    let report_json = serde_json::to_value(&file_info).context("Failed to serialize report")?;

    // Save to file if requested
    if let Some(output_path) = &args.output {
        let content = match args.format.as_str() {
            "json" => serde_json::to_string_pretty(&report_json)?,
            _ => format_report_text(&report_json, &args, !no_color)?,
        };

        tokio::fs::write(output_path, content)
            .await
            .with_context(|| format!("Failed to write report to {}", output_path))?;

        if verbose {
            println!("Report saved to: {}", output_path);
        }
    }

    // Display report
    match args.format.as_str() {
        "json" => {
            print_json(&report_json, true)?;
        }
        "table" => {
            print_table_report(&report_json, &args, !no_color)?;
        }
        "summary" => {
            print_summary_report(&report_json, &args, !no_color)?;
        }
        "detailed" => {
            print_detailed_report(&report_json, &args, !no_color)?;
        }
        _ => {
            return Err(anyhow::anyhow!("Unknown format: {}", args.format));
        }
    }

    if args.include_raw {
        println!("\n{}", colorize_text("=== Raw JSON ===", "bold", !no_color));
        print_json(&report_json, true)?;
    }

    Ok(())
}

fn print_summary_report(report: &Value, args: &ReportArgs, colored: bool) -> Result<()> {
    let attributes = report.get("attributes").unwrap_or(&Value::Null);

    println!(
        "{}",
        colorize_text("=== VirusTotal File Report ===", "bold", colored)
    );

    // Basic file info
    if should_show_section("basic", &args.sections) {
        println!("\n{}", colorize_text("File Information:", "cyan", colored));

        if let Some(sha256) = attributes.get("sha256").and_then(|v| v.as_str()) {
            println!("SHA256:     {}", sha256);
        }
        if let Some(sha1) = attributes.get("sha1").and_then(|v| v.as_str()) {
            println!("SHA1:       {}", sha1);
        }
        if let Some(md5) = attributes.get("md5").and_then(|v| v.as_str()) {
            println!("MD5:        {}", md5);
        }

        if let Some(size) = attributes.get("size").and_then(|v| v.as_u64()) {
            println!("Size:       {}", format_file_size(size));
        }

        if let Some(type_desc) = attributes.get("type_description").and_then(|v| v.as_str()) {
            println!("Type:       {}", type_desc);
        }

        if let Some(magic) = attributes.get("magic").and_then(|v| v.as_str()) {
            println!("Magic:      {}", magic);
        }

        if let Some(names) = attributes.get("names").and_then(|v| v.as_array()) {
            if !names.is_empty() {
                println!(
                    "Names:      {}",
                    names
                        .iter()
                        .filter_map(|v| v.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                );
            }
        }
    }

    // Detection results
    if should_show_section("detections", &args.sections) {
        println!("\n{}", colorize_text("Detection Results:", "cyan", colored));

        if let Some(stats) = attributes.get("last_analysis_stats") {
            if let Some((detected, total)) = get_detection_ratio(stats) {
                let ratio_text = format_detection_ratio(detected, total);
                let color = if detected > 0 { "red" } else { "green" };
                println!("Detection:  {}", colorize_text(&ratio_text, color, colored));

                if let Some(malicious) = stats.get("malicious").and_then(|v| v.as_u64()) {
                    if malicious > 0 {
                        println!(
                            "Malicious:  {}",
                            colorize_text(&malicious.to_string(), "red", colored)
                        );
                    }
                }
                if let Some(suspicious) = stats.get("suspicious").and_then(|v| v.as_u64()) {
                    if suspicious > 0 {
                        println!(
                            "Suspicious: {}",
                            colorize_text(&suspicious.to_string(), "yellow", colored)
                        );
                    }
                }
            }
        }

        // Show top detections
        if let Some(analysis_results) = attributes
            .get("last_analysis_results")
            .and_then(|v| v.as_object())
        {
            let mut detections: Vec<(String, String)> = Vec::new();

            for (engine, result) in analysis_results {
                if let Some(result_obj) = result.as_object() {
                    if let Some(category) = result_obj.get("category").and_then(|v| v.as_str()) {
                        if category == "malicious" || category == "suspicious" {
                            if let Some(result_name) =
                                result_obj.get("result").and_then(|v| v.as_str())
                            {
                                detections.push((engine.clone(), result_name.to_string()));
                            }
                        }
                    }
                }
            }

            if !detections.is_empty() && !args.detections_only {
                println!("\nTop detections:");
                for (engine, detection) in detections.iter().take(5) {
                    println!(
                        "  {} → {}",
                        colorize_text(engine, "dim", colored),
                        colorize_text(detection, "red", colored)
                    );
                }
                if detections.len() > 5 {
                    println!("  ... and {} more", detections.len() - 5);
                }
            }
        }
    }

    // Timestamps
    if should_show_section("basic", &args.sections) {
        println!("\n{}", colorize_text("Timeline:", "cyan", colored));

        if let Some(first_seen) = attributes
            .get("first_submission_date")
            .and_then(|v| v.as_u64())
        {
            println!("First seen: {}", format_timestamp(Some(first_seen)));
        }
        if let Some(last_seen) = attributes
            .get("last_submission_date")
            .and_then(|v| v.as_u64())
        {
            println!("Last seen:  {}", format_timestamp(Some(last_seen)));
        }
        if let Some(last_analysis) = attributes
            .get("last_analysis_date")
            .and_then(|v| v.as_u64())
        {
            println!("Last scan:  {}", format_timestamp(Some(last_analysis)));
        }
    }

    // Additional info if detailed
    if args.include_metadata {
        println!("\n{}", colorize_text("Metadata:", "cyan", colored));

        if let Some(times_submitted) = attributes.get("times_submitted").and_then(|v| v.as_u64()) {
            println!("Submitted:  {} times", times_submitted);
        }
        if let Some(unique_sources) = attributes.get("unique_sources").and_then(|v| v.as_u64()) {
            println!("Sources:    {}", unique_sources);
        }
        if let Some(reputation) = attributes.get("reputation").and_then(|v| v.as_i64()) {
            println!("Reputation: {}", reputation);
        }
    }

    Ok(())
}

fn print_detailed_report(report: &Value, args: &ReportArgs, colored: bool) -> Result<()> {
    // First show summary
    print_summary_report(report, args, colored)?;

    let attributes = report.get("attributes").unwrap_or(&Value::Null);

    // Detailed detection results
    if should_show_section("detections", &args.sections) {
        println!(
            "\n{}",
            colorize_text("=== Detailed Detection Results ===", "bold", colored)
        );

        if let Some(analysis_results) = attributes
            .get("last_analysis_results")
            .and_then(|v| v.as_object())
        {
            let mut engines: Vec<_> = analysis_results.iter().collect();
            engines.sort_by_key(|(name, _)| name.as_str());

            let widths = [20, 12, 30];
            print_table_row(&["Engine", "Category", "Result"], &widths);
            print_table_separator(&widths);

            for (engine, result) in engines {
                if let Some(result_obj) = result.as_object() {
                    let category = result_obj
                        .get("category")
                        .and_then(|v| v.as_str())
                        .unwrap_or("unknown");
                    let result_str = result_obj
                        .get("result")
                        .and_then(|v| v.as_str())
                        .unwrap_or("N/A");

                    // Apply filters
                    if args.detected_only && category != "malicious" && category != "suspicious" {
                        continue;
                    }

                    let colored_category = match category {
                        "malicious" => colorize_text(category, "red", colored),
                        "suspicious" => colorize_text(category, "yellow", colored),
                        "undetected" => colorize_text(category, "green", colored),
                        _ => category.to_string(),
                    };

                    let truncated_result = if result_str.len() > 28 {
                        format!("{}...", &result_str[..25])
                    } else {
                        result_str.to_string()
                    };

                    print_table_row(&[engine, &colored_category, &truncated_result], &widths);
                }
            }
        }
    }

    // Sandbox results
    if should_show_section("sandbox", &args.sections) {
        if let Some(sandbox_verdicts) = attributes
            .get("sandbox_verdicts")
            .and_then(|v| v.as_object())
        {
            if !sandbox_verdicts.is_empty() {
                println!(
                    "\n{}",
                    colorize_text("=== Sandbox Analysis ===", "bold", colored)
                );

                for (sandbox, verdict) in sandbox_verdicts {
                    println!("\n{}:", colorize_text(sandbox, "cyan", colored));
                    if let Some(verdict_obj) = verdict.as_object() {
                        for (key, value) in verdict_obj {
                            println!("  {}: {}", key, value);
                        }
                    }
                }
            }
        }
    }

    // YARA rules
    if should_show_section("yara", &args.sections) {
        if let Some(yara_results) = attributes
            .get("crowdsourced_yara_results")
            .and_then(|v| v.as_array())
        {
            if !yara_results.is_empty() {
                println!("\n{}", colorize_text("=== YARA Rules ===", "bold", colored));

                for (i, yara_result) in yara_results.iter().enumerate() {
                    if let Some(rule_name) = yara_result.get("rule_name").and_then(|v| v.as_str()) {
                        println!("{}. {}", i + 1, colorize_text(rule_name, "yellow", colored));

                        if let Some(description) =
                            yara_result.get("description").and_then(|v| v.as_str())
                        {
                            println!("   {}", description);
                        }
                    }
                }
            }
        }
    }

    // PE info
    if should_show_section("pe", &args.sections) {
        if let Some(pe_info) = attributes.get("pe_info") {
            println!(
                "\n{}",
                colorize_text("=== PE Information ===", "bold", colored)
            );

            if let Some(imphash) = pe_info.get("imphash").and_then(|v| v.as_str()) {
                println!("Imphash: {}", imphash);
            }

            if let Some(sections) = pe_info.get("sections").and_then(|v| v.as_array()) {
                println!("Sections:");
                for section in sections {
                    if let Some(name) = section.get("name").and_then(|v| v.as_str()) {
                        if let Some(entropy) = section.get("entropy").and_then(|v| v.as_f64()) {
                            println!("  {} (entropy: {:.2})", name, entropy);
                        }
                    }
                }
            }
        }
    }

    Ok(())
}

fn print_table_report(report: &Value, args: &ReportArgs, colored: bool) -> Result<()> {
    let attributes = report.get("attributes").unwrap_or(&Value::Null);

    if args.detections_only {
        // Show only detections in table format
        if let Some(analysis_results) = attributes
            .get("last_analysis_results")
            .and_then(|v| v.as_object())
        {
            let widths = [20, 12, 40];
            print_table_row(&["Engine", "Category", "Result"], &widths);
            print_table_separator(&widths);

            let mut engines: Vec<_> = analysis_results.iter().collect();
            engines.sort_by_key(|(name, _)| name.as_str());

            for (engine, result) in engines {
                if let Some(result_obj) = result.as_object() {
                    let category = result_obj
                        .get("category")
                        .and_then(|v| v.as_str())
                        .unwrap_or("unknown");
                    let result_str = result_obj
                        .get("result")
                        .and_then(|v| v.as_str())
                        .unwrap_or("N/A");

                    if args.detected_only && category != "malicious" && category != "suspicious" {
                        continue;
                    }

                    let colored_category = match category {
                        "malicious" => colorize_text(category, "red", colored),
                        "suspicious" => colorize_text(category, "yellow", colored),
                        "undetected" => colorize_text(category, "green", colored),
                        _ => category.to_string(),
                    };

                    let truncated_result = if result_str.len() > 38 {
                        format!("{}...", &result_str[..35])
                    } else {
                        result_str.to_string()
                    };

                    print_table_row(&[engine, &colored_category, &truncated_result], &widths);
                }
            }
        }
    } else {
        // Standard table format
        let widths = [15, 50];
        print_table_row(&["Field", "Value"], &widths);
        print_table_separator(&widths);

        // Basic fields
        let fields = [
            ("SHA256", attributes.get("sha256")),
            ("MD5", attributes.get("md5")),
            ("Size", attributes.get("size")),
            ("Type", attributes.get("type_description")),
            ("Magic", attributes.get("magic")),
        ];

        for (field, value) in &fields {
            if let Some(v) = value {
                let value_str = match v {
                    Value::String(s) => s.clone(),
                    Value::Number(n) => {
                        if field == &"Size" {
                            format_file_size(n.as_u64().unwrap_or(0))
                        } else {
                            n.to_string()
                        }
                    }
                    _ => v.to_string(),
                };

                let truncated_value = if value_str.len() > 48 {
                    format!("{}...", &value_str[..45])
                } else {
                    value_str
                };

                print_table_row(&[field, &truncated_value], &widths);
            }
        }

        // Detection stats
        if let Some(stats) = attributes.get("last_analysis_stats") {
            if let Some((detected, total)) = get_detection_ratio(stats) {
                let ratio = format_detection_ratio(detected, total);
                let colored_ratio = if detected > 0 {
                    colorize_text(&ratio, "red", colored)
                } else {
                    colorize_text(&ratio, "green", colored)
                };
                print_table_row(&["Detections", &colored_ratio], &widths);
            }
        }
    }

    Ok(())
}

fn format_report_text(report: &Value, args: &ReportArgs, colored: bool) -> Result<String> {
    let mut output = String::new();

    match args.format.as_str() {
        "summary" => {
            // Implement text formatting for summary (similar to print_summary_report but returning string)
            output.push_str("=== VirusTotal File Report ===\n");

            let attributes = report.get("attributes").unwrap_or(&Value::Null);

            if let Some(sha256) = attributes.get("sha256").and_then(|v| v.as_str()) {
                output.push_str(&format!("SHA256: {}\n", sha256));
            }

            if let Some(stats) = attributes.get("last_analysis_stats") {
                if let Some((detected, total)) = get_detection_ratio(stats) {
                    let ratio = format_detection_ratio(detected, total);
                    output.push_str(&format!("Detection: {}\n", ratio));
                }
            }
        }
        _ => {
            output = serde_json::to_string_pretty(report)?;
        }
    }

    Ok(output)
}

fn should_show_section(section: &str, filter: &Option<String>) -> bool {
    match filter {
        Some(sections) => {
            let section_list: Vec<&str> = sections.split(',').map(|s| s.trim()).collect();
            section_list.contains(&section)
        }
        None => true,
    }
}
