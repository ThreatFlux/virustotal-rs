use crate::cli::utils::{
    build_table_row, build_table_separator, colorize_text, format_detection_ratio, format_file_size, 
    format_json_output, get_detection_ratio, handle_dry_run_check, handle_vt_error, print_json, 
    print_table_row, print_table_separator, save_output_to_file, setup_client, truncate_hash, ProgressTracker,
};
use crate::{Client, SearchOrder};
use anyhow::{Context, Result};
use clap::Args;
use serde_json::Value;
use std::io::{self, Write};

#[derive(Args, Debug)]
pub struct SearchArgs {
    /// Search query using VirusTotal Intelligence search syntax
    #[arg(short, long)]
    pub query: String,

    /// Maximum number of results to return
    #[arg(short, long, default_value = "20")]
    pub limit: usize,

    /// Output format (json, table, summary)
    #[arg(short = 'f', long, default_value = "table")]
    pub format: String,

    /// Search order (relevance, first_submission, last_submission)  
    #[arg(long, default_value = "relevance")]
    pub order: String,

    /// Save results to file
    #[arg(short, long)]
    pub output: Option<String>,

    /// Show only detected files (at least 1 detection)
    #[arg(long)]
    pub detected_only: bool,

    /// Minimum detection count filter
    #[arg(long)]
    pub min_detections: Option<u32>,

    /// Maximum detection count filter  
    #[arg(long)]
    pub max_detections: Option<u32>,

    /// File size range filter (e.g., 1KB-10MB)
    #[arg(long)]
    pub size_range: Option<String>,

    /// Include file content snippets in results
    #[arg(long)]
    pub include_snippets: bool,

    /// Interactive mode - prompt to continue fetching more results
    #[arg(long)]
    pub interactive: bool,

    /// Export hashes only (one per line)
    #[arg(long)]
    pub hashes_only: bool,
}

pub async fn execute(
    args: SearchArgs,
    api_key: Option<String>,
    tier: &str,
    verbose: bool,
    dry_run: bool,
    no_color: bool,
) -> Result<()> {
    if handle_dry_run_check(dry_run, &format!("Would search for: {}", args.query)).is_err() {
        return Ok(());
    }

    let client = setup_client(api_key, tier)?;
    let search_order = parse_search_order(&args.order);

    if verbose {
        println!("Searching for: {}", args.query);
        println!("Limit: {}, Order: {}", args.limit, args.order);
    }

    let all_results = execute_search(&client, &args, search_order, verbose).await?;

    if all_results.is_empty() {
        println!("No results found for query: {}", args.query);
        return Ok(());
    }

    println!("Found {} results", all_results.len());
    handle_output(&all_results, &args, !no_color, verbose).await?;

    Ok(())
}

async fn execute_search(
    client: &Client,
    args: &SearchArgs,
    search_order: SearchOrder,
    verbose: bool,
) -> Result<Vec<crate::FileSearchResult>> {
    let mut all_results = Vec::new();
    let mut processed = 0;
    let mut continuation_cursor = None;

    loop {
        let search_result = perform_search_request(
            client,
            &args.query,
            std::cmp::min(args.limit - processed, 300),
            &search_order,
            continuation_cursor.as_deref(),
        ).await?;

        let results_count = search_result.data.len();
        if results_count == 0 {
            break;
        }

        processed += process_search_results(
            &mut all_results,
            search_result.data,
            args,
            processed,
        );

        continuation_cursor = search_result.meta.cursor.clone();

        if processed >= args.limit || continuation_cursor.is_none() {
            break;
        }

        if !should_continue_search(args, processed, verbose)? {
            break;
        }

        if verbose {
            println!("Processed {} results...", processed);
        }
    }

    Ok(all_results)
}

async fn perform_search_request(
    client: &Client,
    query: &str,
    limit: usize,
    order: &SearchOrder,
    cursor: Option<&str>,
) -> Result<crate::SearchResponse> {
    match client
        .search()
        .query(query)
        .limit(limit)
        .order(order.clone())
        .cursor(cursor)
        .execute()
        .await
    {
        Ok(result) => Ok(result),
        Err(e) => {
            let error_msg = handle_vt_error(&e);
            Err(anyhow::anyhow!("Search failed: {}", error_msg))
        }
    }
}

fn process_search_results(
    all_results: &mut Vec<crate::FileSearchResult>,
    search_data: Vec<crate::FileSearchResult>,
    args: &SearchArgs,
    processed: usize,
) -> usize {
    let mut count = 0;
    
    for file_result in search_data {
        if should_include_result(&file_result, args) {
            all_results.push(file_result);
            count += 1;

            if processed + count >= args.limit {
                break;
            }
        }
    }
    
    count
}

fn should_continue_search(args: &SearchArgs, processed: usize, verbose: bool) -> Result<bool> {
    if !args.interactive || processed >= args.limit {
        return Ok(true);
    }

    print!(
        "Found {} results so far. Continue searching? (y/N): ",
        processed
    );
    io::stdout().flush()?;

    let mut input = String::new();
    io::stdin().read_line(&mut input)?;

    Ok(matches!(input.trim().to_lowercase().as_str(), "y" | "yes"))
}

fn parse_search_order(order: &str) -> SearchOrder {
    match order.to_lowercase().as_str() {
        "first_submission" | "first" => SearchOrder::FirstSubmissionDate,
        "last_submission" | "last" => SearchOrder::LastSubmissionDate,
        _ => SearchOrder::Relevance,
    }
}

async fn handle_output(
    results: &[crate::FileSearchResult],
    args: &SearchArgs,
    colored: bool,
    verbose: bool,
) -> Result<()> {
    if args.hashes_only {
        print_hashes_only(results);
        return Ok(());
    }

    let output_content = format_output_content(results, args, colored)?;

    if let Some(output_path) = &args.output {
        save_output_to_file(&output_content, output_path, verbose, "Search results").await?;
    } else {
        print!("{}", output_content);
    }

    Ok(())
}

fn print_hashes_only(results: &[crate::FileSearchResult]) {
    for result in results {
        if let Some(sha256) = result.attributes.sha256.as_ref() {
            println!("{}", sha256);
        } else if let Some(md5) = result.attributes.md5.as_ref() {
            println!("{}", md5);
        } else if let Some(sha1) = result.attributes.sha1.as_ref() {
            println!("{}", sha1);
        }
    }
}

fn format_output_content(
    results: &[crate::FileSearchResult],
    args: &SearchArgs,
    colored: bool,
) -> Result<String> {
    match args.format.as_str() {
        "json" => format_json_search_output(results),
        "summary" => format_summary_output(results, colored),
        "table" => format_table_output(results, args, colored),
        _ => Err(anyhow::anyhow!("Unknown format: {}", args.format)),
    }
}


fn should_include_result(result: &crate::FileSearchResult, args: &SearchArgs) -> bool {
    if !passes_detection_filters(result, args) {
        return false;
    }

    if !passes_size_filters(result, args) {
        return false;
    }

    true
}

fn passes_detection_filters(result: &crate::FileSearchResult, args: &SearchArgs) -> bool {
    let Some(attrs) = &result.attributes else {
        return true;
    };

    let Some(stats) = attrs.get("last_analysis_stats") else {
        return true;
    };

    let total_detected = get_total_detections(stats);

    if !passes_detected_only_filter(args, total_detected) {
        return false;
    }

    if !passes_min_detections_filter(args, total_detected) {
        return false;
    }

    if !passes_max_detections_filter(args, total_detected) {
        return false;
    }

    true
}

fn get_total_detections(stats: &Value) -> u32 {
    let malicious = stats.get("malicious").and_then(|v| v.as_u64()).unwrap_or(0) as u32;
    let suspicious = stats.get("suspicious").and_then(|v| v.as_u64()).unwrap_or(0) as u32;
    malicious + suspicious
}

fn passes_detected_only_filter(args: &SearchArgs, total_detected: u32) -> bool {
    !args.detected_only || total_detected > 0
}

fn passes_min_detections_filter(args: &SearchArgs, total_detected: u32) -> bool {
    args.min_detections.map_or(true, |min_det| total_detected >= min_det)
}

fn passes_max_detections_filter(args: &SearchArgs, total_detected: u32) -> bool {
    args.max_detections.map_or(true, |max_det| total_detected <= max_det)
}

fn passes_size_filters(result: &crate::FileSearchResult, args: &SearchArgs) -> bool {
    let Some(size_range) = &args.size_range else {
        return true;
    };

    let Some(attrs) = &result.attributes else {
        return true;
    };

    let Some(file_size) = attrs.get("size").and_then(|v| v.as_u64()) else {
        return true;
    };

    size_matches_range(file_size, size_range)
}

fn size_matches_range(file_size: u64, range: &str) -> bool {
    if let Some(captures) = regex::Regex::new(r"^(\d+)([KMGT]?B?)-(\d+)([KMGT]?B?)$")
        .unwrap()
        .captures(range)
    {
        return matches_size_range_pattern(file_size, &captures);
    }
    
    if range.starts_with('>') {
        return matches_greater_than_pattern(file_size, &range[1..]);
    }
    
    if range.starts_with('<') {
        return matches_less_than_pattern(file_size, &range[1..]);
    }
    
    true
}

fn matches_size_range_pattern(file_size: u64, captures: &regex::Captures) -> bool {
    let min_size = parse_size(&captures[1], &captures[2]).unwrap_or(0);
    let max_size = parse_size(&captures[3], &captures[4]).unwrap_or(u64::MAX);
    file_size >= min_size && file_size <= max_size
}

fn matches_greater_than_pattern(file_size: u64, min_str: &str) -> bool {
    if let Some((num, unit)) = split_size_unit(min_str) {
        let min_size = parse_size(num, unit).unwrap_or(0);
        file_size > min_size
    } else {
        true
    }
}

fn matches_less_than_pattern(file_size: u64, max_str: &str) -> bool {
    if let Some((num, unit)) = split_size_unit(max_str) {
        let max_size = parse_size(num, unit).unwrap_or(u64::MAX);
        file_size < max_size
    } else {
        true
    }
}

fn split_size_unit(size_str: &str) -> Option<(&str, &str)> {
    let size_str = size_str.trim();
    if let Some(pos) = size_str.find(|c: char| c.is_alphabetic()) {
        Some((&size_str[..pos], &size_str[pos..]))
    } else {
        Some((size_str, ""))
    }
}

fn parse_size(num_str: &str, unit: &str) -> Option<u64> {
    let num: u64 = num_str.parse().ok()?;
    let multiplier = match unit.to_uppercase().as_str() {
        "B" | "" => 1,
        "KB" | "K" => 1024,
        "MB" | "M" => 1024 * 1024,
        "GB" | "G" => 1024 * 1024 * 1024,
        "TB" | "T" => 1024 * 1024 * 1024 * 1024,
        _ => 1,
    };

    Some(num * multiplier)
}

fn format_json_search_output(results: &[crate::FileSearchResult]) -> Result<String> {
    format_json_output(results, true)
}

fn format_summary_output(results: &[crate::FileSearchResult], colored: bool) -> Result<String> {
    let mut output = String::new();
    output.push_str(&format!(
        "{}\n",
        colorize_text("=== Search Results ===", "bold", colored)
    ));

    for (i, result) in results.iter().enumerate() {
        format_single_result_summary(&mut output, i, result, colored);
    }

    Ok(output)
}

fn format_single_result_summary(
    output: &mut String,
    index: usize,
    result: &crate::FileSearchResult,
    colored: bool,
) {
    output.push_str(&format!("\n{}. ", index + 1));
    
    let hash = get_preferred_hash(&result.attributes);
    output.push_str(&format!("{}\n", colorize_text(&hash, "cyan", colored)));
    
    format_file_info(output, &result.attributes);
    format_detection_stats(output, &result.attributes, colored);
    format_file_names(output, &result.attributes);
}

fn get_preferred_hash(attributes: &crate::FileAttributes) -> String {
    attributes
        .sha256
        .as_ref()
        .or(attributes.sha1.as_ref())
        .or(attributes.md5.as_ref())
        .map(|h| truncate_hash(h, 16))
        .unwrap_or_else(|| "Unknown".to_string())
}

fn format_file_info(output: &mut String, attributes: &crate::FileAttributes) {
    if let Some(size) = attributes.size {
        output.push_str(&format!("   Size: {}\n", format_file_size(size as u64)));
    }

    if let Some(type_desc) = &attributes.type_description {
        output.push_str(&format!("   Type: {}\n", type_desc));
    }
}

fn format_detection_stats(output: &mut String, attributes: &crate::FileAttributes, colored: bool) {
    if let Some(stats) = &attributes.last_analysis_stats {
        let detection_counts = extract_detection_counts(stats);
        
        if detection_counts.total > 0 {
            let ratio = format_detection_ratio(detection_counts.detected, detection_counts.total);
            let color = if detection_counts.detected > 0 { "red" } else { "green" };
            output.push_str(&format!(
                "   Detections: {}\n",
                colorize_text(&ratio, color, colored)
            ));
        }
    }
}

fn format_file_names(output: &mut String, attributes: &crate::FileAttributes) {
    if let Some(names) = &attributes.names {
        if !names.is_empty() {
            let name = names.first().unwrap_or(&"Unknown".to_string());
            output.push_str(&format!("   Name: {}\n", name));
        }
    }
}

struct DetectionCounts {
    total: u32,
    detected: u32,
}

fn extract_detection_counts(stats: &crate::AnalysisStats) -> DetectionCounts {
    let malicious = stats.malicious.unwrap_or(0);
    let suspicious = stats.suspicious.unwrap_or(0);
    let harmless = stats.harmless.unwrap_or(0);
    let undetected = stats.undetected.unwrap_or(0);
    
    DetectionCounts {
        total: malicious + suspicious + harmless + undetected,
        detected: malicious + suspicious,
    }
}

fn format_table_output(
    results: &[crate::FileSearchResult],
    args: &SearchArgs,
    colored: bool,
) -> Result<String> {
    let widths = get_table_widths(args.include_snippets);
    let headers = get_table_headers(args.include_snippets);
    
    let mut output = String::new();
    output.push_str(&build_table_row(&headers, &widths));
    output.push_str(&build_table_separator(&widths));
    
    for result in results {
        let row_parts = format_table_row(result, args, &widths, colored);
        let row_str_refs: Vec<&str> = row_parts.iter().map(|s| s.as_str()).collect();
        output.push_str(&build_table_row(&row_str_refs, &widths));
    }
    
    Ok(output)
}

fn get_table_widths(include_snippets: bool) -> Vec<usize> {
    if include_snippets {
        vec![16, 10, 12, 20, 30]
    } else {
        vec![20, 12, 15, 25]
    }
}

fn get_table_headers(include_snippets: bool) -> Vec<&'static str> {
    if include_snippets {
        vec!["Hash", "Size", "Detections", "Type", "Snippet"]
    } else {
        vec!["Hash", "Size", "Detections", "Type"]
    }
}



fn format_table_row(
    result: &crate::FileSearchResult,
    args: &SearchArgs,
    widths: &[usize],
    colored: bool,
) -> Vec<String> {
    let mut row_parts = Vec::new();
    
    row_parts.push(format_hash_column(&result.attributes, widths[0]));
    row_parts.push(format_size_column(&result.attributes));
    row_parts.push(format_detection_column(&result.attributes, colored));
    row_parts.push(format_type_column(&result.attributes, widths[3]));
    
    if args.include_snippets {
        row_parts.push(format_snippet_column());
    }
    
    row_parts
}

fn format_hash_column(attributes: &crate::FileAttributes, width: usize) -> String {
    attributes
        .sha256
        .as_ref()
        .or(attributes.sha1.as_ref())
        .or(attributes.md5.as_ref())
        .map(|h| truncate_hash(h, width - 1))
        .unwrap_or_else(|| "Unknown".to_string())
}

fn format_size_column(attributes: &crate::FileAttributes) -> String {
    attributes
        .size
        .map(|s| format_file_size(s as u64))
        .unwrap_or_else(|| "Unknown".to_string())
}

fn format_detection_column(attributes: &crate::FileAttributes, colored: bool) -> String {
    let Some(stats) = &attributes.last_analysis_stats else {
        return "N/A".to_string();
    };
    
    let malicious = stats.malicious.unwrap_or(0);
    let suspicious = stats.suspicious.unwrap_or(0);
    let harmless = stats.harmless.unwrap_or(0);
    let undetected = stats.undetected.unwrap_or(0);
    
    let total = malicious + suspicious + harmless + undetected;
    let detected = malicious + suspicious;
    
    if total > 0 {
        let ratio = format_detection_ratio(detected, total);
        let color = if detected > 0 { "red" } else { "green" };
        colorize_text(&ratio, color, colored)
    } else {
        "N/A".to_string()
    }
}

fn format_type_column(attributes: &crate::FileAttributes, width: usize) -> String {
    attributes
        .type_description
        .as_ref()
        .map(|t| {
            if t.len() > width - 1 {
                format!("{}...", &t[..width - 4])
            } else {
                t.clone()
            }
        })
        .unwrap_or_else(|| "Unknown".to_string())
}

fn format_snippet_column() -> String {
    // Note: Actual snippet fetching would require additional API calls
    "Not implemented".to_string()
}

