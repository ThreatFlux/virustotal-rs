use crate::cli::utils::{
    colorize_text, format_detection_ratio, format_file_size, get_detection_ratio, handle_vt_error,
    print_json, print_table_row, print_table_separator, setup_client, truncate_hash,
    ProgressTracker,
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
    if dry_run {
        println!("DRY RUN MODE - Would search for: {}", args.query);
        return Ok(());
    }

    let client = setup_client(api_key, tier)?;

    if verbose {
        println!("Searching for: {}", args.query);
        println!("Limit: {}, Order: {}", args.limit, args.order);
    }

    let search_order = match args.order.to_lowercase().as_str() {
        "first_submission" | "first" => SearchOrder::FirstSubmissionDate,
        "last_submission" | "last" => SearchOrder::LastSubmissionDate,
        _ => SearchOrder::Relevance,
    };

    let mut all_results = Vec::new();
    let mut processed = 0;
    let mut continuation_cursor = None;

    loop {
        let search_result = match client
            .search()
            .query(&args.query)
            .limit(std::cmp::min(args.limit - processed, 300)) // VirusTotal max per request
            .order(search_order.clone())
            .cursor(continuation_cursor.as_deref())
            .execute()
            .await
        {
            Ok(result) => result,
            Err(e) => {
                let error_msg = handle_vt_error(&e);
                return Err(anyhow::anyhow!("Search failed: {}", error_msg));
            }
        };

        let results_count = search_result.data.len();
        if results_count == 0 {
            break;
        }

        // Apply filters and collect results
        for file_result in search_result.data {
            if should_include_result(&file_result, &args) {
                all_results.push(file_result);
                processed += 1;

                if processed >= args.limit {
                    break;
                }
            }
        }

        // Check if we have more results and should continue
        continuation_cursor = search_result.meta.cursor.clone();

        if processed >= args.limit || continuation_cursor.is_none() {
            break;
        }

        // Interactive mode - ask user if they want to continue
        if args.interactive && processed < args.limit {
            print!(
                "Found {} results so far. Continue searching? (y/N): ",
                processed
            );
            io::stdout().flush()?;

            let mut input = String::new();
            io::stdin().read_line(&mut input)?;

            if !matches!(input.trim().to_lowercase().as_str(), "y" | "yes") {
                break;
            }
        }

        if verbose {
            println!("Processed {} results...", processed);
        }
    }

    if all_results.is_empty() {
        println!("No results found for query: {}", args.query);
        return Ok(());
    }

    println!("Found {} results", all_results.len());

    // Prepare output
    let output_content = match args.format.as_str() {
        "json" => format_json_output(&all_results)?,
        "summary" => format_summary_output(&all_results, !no_color)?,
        "table" => format_table_output(&all_results, &args, !no_color)?,
        _ => return Err(anyhow::anyhow!("Unknown format: {}", args.format)),
    };

    // Save to file if requested
    if let Some(output_path) = &args.output {
        tokio::fs::write(output_path, &output_content)
            .await
            .with_context(|| format!("Failed to write results to {}", output_path))?;

        if verbose {
            println!("Results saved to: {}", output_path);
        }
    } else {
        // Print to stdout
        if args.hashes_only {
            for result in &all_results {
                if let Some(sha256) = result.attributes.sha256.as_ref() {
                    println!("{}", sha256);
                } else if let Some(md5) = result.attributes.md5.as_ref() {
                    println!("{}", md5);
                } else if let Some(sha1) = result.attributes.sha1.as_ref() {
                    println!("{}", sha1);
                }
            }
        } else {
            print!("{}", output_content);
        }
    }

    Ok(())
}

fn should_include_result(result: &crate::FileSearchResult, args: &SearchArgs) -> bool {
    // Apply filters
    if let Some(attrs) = &result.attributes {
        if let Some(stats) = attrs.get("last_analysis_stats") {
            let malicious = stats.get("malicious").and_then(|v| v.as_u64()).unwrap_or(0) as u32;
            let suspicious = stats
                .get("suspicious")
                .and_then(|v| v.as_u64())
                .unwrap_or(0) as u32;
            let total_detected = malicious + suspicious;

            // Detected only filter
            if args.detected_only && total_detected == 0 {
                return false;
            }

            // Min detections filter
            if let Some(min_det) = args.min_detections {
                if total_detected < min_det {
                    return false;
                }
            }

            // Max detections filter
            if let Some(max_det) = args.max_detections {
                if total_detected > max_det {
                    return false;
                }
            }
        }
    }

    // Size range filter
    if let Some(size_range) = &args.size_range {
        if let Some(attrs) = &result.attributes {
            if let Some(file_size) = attrs.get("size").and_then(|v| v.as_u64()) {
                if !size_matches_range(file_size, size_range) {
                    return false;
                }
            }
        }
    }

    true
}

fn size_matches_range(file_size: u64, range: &str) -> bool {
    // Parse ranges like "1KB-10MB", ">1MB", "<500KB"
    if let Some(captures) = regex::Regex::new(r"^(\d+)([KMGT]?B?)-(\d+)([KMGT]?B?)$")
        .unwrap()
        .captures(range)
    {
        let min_size = parse_size(&captures[1], &captures[2]).unwrap_or(0);
        let max_size = parse_size(&captures[3], &captures[4]).unwrap_or(u64::MAX);

        file_size >= min_size && file_size <= max_size
    } else if range.starts_with('>') {
        let min_str = &range[1..];
        if let Some((num, unit)) = split_size_unit(min_str) {
            let min_size = parse_size(num, unit).unwrap_or(0);
            file_size > min_size
        } else {
            true
        }
    } else if range.starts_with('<') {
        let max_str = &range[1..];
        if let Some((num, unit)) = split_size_unit(max_str) {
            let max_size = parse_size(num, unit).unwrap_or(u64::MAX);
            file_size < max_size
        } else {
            true
        }
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

fn format_json_output(results: &[crate::FileSearchResult]) -> Result<String> {
    Ok(serde_json::to_string_pretty(results)?)
}

fn format_summary_output(results: &[crate::FileSearchResult], colored: bool) -> Result<String> {
    let mut output = String::new();

    output.push_str(&format!(
        "{}\n",
        colorize_text("=== Search Results ===", "bold", colored)
    ));

    for (i, result) in results.iter().enumerate() {
        output.push_str(&format!("\n{}. ", i + 1));

        // Hash (prefer SHA256, fall back to others)
        let hash = result
            .attributes
            .sha256
            .as_ref()
            .or(result.attributes.sha1.as_ref())
            .or(result.attributes.md5.as_ref())
            .map(|h| truncate_hash(h, 16))
            .unwrap_or_else(|| "Unknown".to_string());

        output.push_str(&format!("{}\n", colorize_text(&hash, "cyan", colored)));

        // File info
        if let Some(size) = result.attributes.size {
            output.push_str(&format!("   Size: {}\n", format_file_size(size as u64)));
        }

        if let Some(type_desc) = &result.attributes.type_description {
            output.push_str(&format!("   Type: {}\n", type_desc));
        }

        // Detection stats
        if let Some(stats) = &result.attributes.last_analysis_stats {
            let malicious = stats.malicious.unwrap_or(0);
            let suspicious = stats.suspicious.unwrap_or(0);
            let harmless = stats.harmless.unwrap_or(0);
            let undetected = stats.undetected.unwrap_or(0);

            let total = malicious + suspicious + harmless + undetected;
            let detected = malicious + suspicious;

            if total > 0 {
                let ratio = format_detection_ratio(detected, total);
                let color = if detected > 0 { "red" } else { "green" };
                output.push_str(&format!(
                    "   Detections: {}\n",
                    colorize_text(&ratio, color, colored)
                ));
            }
        }

        // File names
        if let Some(names) = &result.attributes.names {
            if !names.is_empty() {
                let name = names.first().unwrap_or(&"Unknown".to_string());
                output.push_str(&format!("   Name: {}\n", name));
            }
        }
    }

    Ok(output)
}

fn format_table_output(
    results: &[crate::FileSearchResult],
    args: &SearchArgs,
    colored: bool,
) -> Result<String> {
    let mut output = String::new();

    let widths = if args.include_snippets {
        vec![16, 10, 12, 20, 30]
    } else {
        vec![20, 12, 15, 25]
    };

    let headers = if args.include_snippets {
        vec!["Hash", "Size", "Detections", "Type", "Snippet"]
    } else {
        vec!["Hash", "Size", "Detections", "Type"]
    };

    // Table header
    let mut header_line = String::new();
    for (i, (header, width)) in headers.iter().zip(&widths).enumerate() {
        if i > 0 {
            header_line.push_str(" | ");
        }
        header_line.push_str(&format!("{:<width$}", header, width = width));
    }
    output.push_str(&format!("{}\n", header_line));

    // Separator
    let mut sep_line = String::new();
    for (i, width) in widths.iter().enumerate() {
        if i > 0 {
            sep_line.push_str("-+-");
        }
        sep_line.push_str(&"-".repeat(*width));
    }
    output.push_str(&format!("{}\n", sep_line));

    // Results
    for result in results {
        let mut row_parts = Vec::new();

        // Hash
        let hash = result
            .attributes
            .sha256
            .as_ref()
            .or(result.attributes.sha1.as_ref())
            .or(result.attributes.md5.as_ref())
            .map(|h| truncate_hash(h, widths[0] - 1))
            .unwrap_or_else(|| "Unknown".to_string());
        row_parts.push(hash);

        // Size
        let size_str = result
            .attributes
            .size
            .map(|s| format_file_size(s as u64))
            .unwrap_or_else(|| "Unknown".to_string());
        row_parts.push(size_str);

        // Detections
        let detection_str = if let Some(stats) = &result.attributes.last_analysis_stats {
            let malicious = stats.malicious.unwrap_or(0);
            let suspicious = stats.suspicious.unwrap_or(0);
            let harmless = stats.harmless.unwrap_or(0);
            let undetected = stats.undetected.unwrap_or(0);

            let total = malicious + suspicious + harmless + undetected;
            let detected = malicious + suspicious;

            if total > 0 {
                let ratio = format_detection_ratio(detected, total);
                if detected > 0 {
                    colorize_text(&ratio, "red", colored)
                } else {
                    colorize_text(&ratio, "green", colored)
                }
            } else {
                "N/A".to_string()
            }
        } else {
            "N/A".to_string()
        };
        row_parts.push(detection_str);

        // Type
        let type_str = result
            .attributes
            .type_description
            .as_ref()
            .map(|t| {
                if t.len() > widths[3] - 1 {
                    format!("{}...", &t[..widths[3] - 4])
                } else {
                    t.clone()
                }
            })
            .unwrap_or_else(|| "Unknown".to_string());
        row_parts.push(type_str);

        // Snippet (if requested)
        if args.include_snippets {
            // Note: Actual snippet fetching would require additional API calls
            let snippet = "Not implemented".to_string();
            row_parts.push(snippet);
        }

        // Format row
        let mut row_line = String::new();
        for (i, (part, width)) in row_parts.iter().zip(&widths).enumerate() {
            if i > 0 {
                row_line.push_str(" | ");
            }
            row_line.push_str(&format!("{:<width$}", part, width = width));
        }
        output.push_str(&format!("{}\n", row_line));
    }

    Ok(output)
}
