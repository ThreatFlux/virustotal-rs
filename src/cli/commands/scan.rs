use crate::cli::utils::{
    colorize_text, format_file_size, handle_vt_error, print_json, setup_client, validate_hash,
    ProgressTracker,
};
use crate::{Analysis, Client};
use anyhow::{Context, Result};
use clap::Args;
use futures::stream::{self, StreamExt};
use serde_json::Value;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::fs;
use tokio::time::sleep;

#[derive(Args, Debug)]
pub struct ScanArgs {
    /// File path to scan or directory to scan recursively
    #[arg(short, long)]
    pub input: String,

    /// Scan directory recursively
    #[arg(short, long)]
    pub recursive: bool,

    /// File patterns to include (e.g., "*.exe,*.dll")
    #[arg(long)]
    pub include: Option<String>,

    /// File patterns to exclude (e.g., "*.txt,*.log")
    #[arg(long)]
    pub exclude: Option<String>,

    /// Maximum file size to scan (in bytes)
    #[arg(long)]
    pub max_size: Option<u64>,

    /// Minimum file size to scan (in bytes)
    #[arg(long)]
    pub min_size: Option<u64>,

    /// Wait for analysis results instead of just submitting
    #[arg(short, long)]
    pub wait: bool,

    /// Timeout for waiting for results (in seconds)
    #[arg(long, default_value = "300")]
    pub timeout: u64,

    /// Poll interval when waiting for results (in seconds)
    #[arg(long, default_value = "5")]
    pub poll_interval: u64,

    /// Output format (json, table, summary)
    #[arg(short = 'f', long, default_value = "summary")]
    pub format: String,

    /// Save results to file
    #[arg(short, long)]
    pub output: Option<PathBuf>,

    /// Number of concurrent uploads
    #[arg(short = 'c', long, default_value = "3")]
    pub concurrency: usize,

    /// Skip files that are already known to VirusTotal
    #[arg(long)]
    pub skip_known: bool,

    /// Rescan files even if they exist in VirusTotal
    #[arg(long)]
    pub force_rescan: bool,

    /// Include file content preview in results
    #[arg(long)]
    pub include_preview: bool,
}

#[derive(Debug, serde::Serialize)]
struct ScanResult {
    file_path: PathBuf,
    file_size: u64,
    analysis_id: Option<String>,
    scan_date: Option<String>,
    error: Option<String>,
    analysis_result: Option<Analysis>,
}

pub async fn execute(
    args: ScanArgs,
    api_key: Option<String>,
    tier: &str,
    verbose: bool,
    dry_run: bool,
    no_color: bool,
) -> Result<()> {
    let client = Arc::new(setup_client(api_key, tier)?);
    let input_path = Path::new(&args.input);

    if !input_path.exists() {
        return Err(anyhow::anyhow!("Input path does not exist: {}", args.input));
    }

    // Collect files to scan
    let files_to_scan = if input_path.is_file() {
        vec![input_path.to_path_buf()]
    } else if input_path.is_dir() {
        collect_files_from_directory(input_path, &args).await?
    } else {
        return Err(anyhow::anyhow!(
            "Input path is neither a file nor a directory"
        ));
    };

    if files_to_scan.is_empty() {
        println!("No files found to scan");
        return Ok(());
    }

    println!("Found {} files to scan", files_to_scan.len());

    if dry_run {
        println!("DRY RUN MODE - Files that would be scanned:");
        for file_path in &files_to_scan {
            println!("  {}", file_path.display());
        }
        return Ok(());
    }

    // Progress tracking
    let progress = if !verbose {
        Some(ProgressTracker::new(
            files_to_scan.len() as u64,
            "Scanning files",
        ))
    } else {
        None
    };

    let successful = Arc::new(AtomicUsize::new(0));
    let failed = Arc::new(AtomicUsize::new(0));
    let skipped = Arc::new(AtomicUsize::new(0));

    // Limit concurrency for file uploads
    let concurrency = args.concurrency.clamp(1, 10);

    if verbose {
        println!("Using {} concurrent uploads", concurrency);
    }

    // Process files concurrently
    let results: Vec<_> = stream::iter(files_to_scan.iter().enumerate())
        .map(|(index, file_path)| {
            let client = Arc::clone(&client);
            let successful = Arc::clone(&successful);
            let failed = Arc::clone(&failed);
            let skipped = Arc::clone(&skipped);
            let file_path = file_path.clone();
            let progress = progress.as_ref();
            let args = &args;

            async move {
                if verbose {
                    println!(
                        "[{}/{}] Scanning: {}",
                        index + 1,
                        files_to_scan.len(),
                        file_path.display()
                    );
                } else if let Some(progress) = progress {
                    progress.set_message(&format!(
                        "Scanning {}",
                        file_path.file_name().unwrap_or_default().to_string_lossy()
                    ));
                }

                let result = scan_single_file(&client, &file_path, args, verbose).await;

                match &result {
                    Ok(scan_result) => {
                        if scan_result.error.is_some() {
                            failed.fetch_add(1, Ordering::SeqCst);
                        } else if scan_result.analysis_id.is_some() {
                            successful.fetch_add(1, Ordering::SeqCst);
                        } else {
                            skipped.fetch_add(1, Ordering::SeqCst);
                        }
                    }
                    Err(_) => {
                        failed.fetch_add(1, Ordering::SeqCst);
                    }
                }

                if let Some(progress) = progress {
                    progress.inc(1);
                }

                result
            }
        })
        .buffer_unordered(concurrency)
        .collect()
        .await;

    if let Some(progress) = progress {
        progress.finish_with_message("Scanning completed");
    }

    // Collect successful results
    let mut scan_results = Vec::new();
    for result in results {
        match result {
            Ok(scan_result) => scan_results.push(scan_result),
            Err(e) => {
                if verbose {
                    eprintln!("Error during scanning: {}", e);
                }
            }
        }
    }

    // Wait for analysis results if requested
    if args.wait && !scan_results.is_empty() {
        println!("\nWaiting for analysis results...");

        let analyses_to_wait: Vec<_> = scan_results
            .iter()
            .filter(|r| r.analysis_id.is_some())
            .collect();

        if !analyses_to_wait.is_empty() {
            wait_for_analysis_results(&client, &mut scan_results, &args, verbose).await?;
        }
    }

    // Display results
    match args.format.as_str() {
        "json" => {
            let json_output = serde_json::to_value(&scan_results)?;
            print_json(&json_output, true)?;
        }
        "table" => {
            print_table_results(&scan_results, !no_color)?;
        }
        "summary" => {
            print_summary_results(&scan_results, !no_color)?;
        }
        _ => {
            return Err(anyhow::anyhow!("Unknown format: {}", args.format));
        }
    }

    // Save results if requested
    if let Some(output_path) = &args.output {
        let output_content = match args.format.as_str() {
            "json" => serde_json::to_string_pretty(&scan_results)?,
            _ => format_results_as_text(&scan_results)?,
        };

        tokio::fs::write(output_path, output_content)
            .await
            .with_context(|| format!("Failed to write results to {}", output_path.display()))?;

        if verbose {
            println!("Results saved to: {}", output_path.display());
        }
    }

    // Print summary statistics
    let successful_count = successful.load(Ordering::SeqCst);
    let failed_count = failed.load(Ordering::SeqCst);
    let skipped_count = skipped.load(Ordering::SeqCst);

    println!(
        "\n{}",
        colorize_text("=== Scan Summary ===", "bold", !no_color)
    );
    println!("Total files:      {}", files_to_scan.len());
    println!(
        "Successfully submitted: {}",
        colorize_text(&successful_count.to_string(), "green", !no_color)
    );
    println!(
        "Failed:          {}",
        colorize_text(&failed_count.to_string(), "red", !no_color)
    );
    if skipped_count > 0 {
        println!(
            "Skipped:         {}",
            colorize_text(&skipped_count.to_string(), "yellow", !no_color)
        );
    }

    Ok(())
}

async fn collect_files_from_directory(dir: &Path, args: &ScanArgs) -> Result<Vec<PathBuf>> {
    let mut files = Vec::new();

    if args.recursive {
        collect_files_recursive(dir, &mut files, args)?;
    } else {
        let mut entries = fs::read_dir(dir).await?;
        while let Some(entry) = entries.next_entry().await? {
            let path = entry.path();
            if path.is_file() && should_include_file(&path, args) {
                files.push(path);
            }
        }
    }

    Ok(files)
}

fn collect_files_recursive(dir: &Path, files: &mut Vec<PathBuf>, args: &ScanArgs) -> Result<()> {
    use std::fs;

    let entries = fs::read_dir(dir)?;

    for entry in entries {
        let entry = entry?;
        let path = entry.path();

        if path.is_file() {
            if should_include_file(&path, args) {
                files.push(path);
            }
        } else if path.is_dir() {
            collect_files_recursive(&path, files, args)?;
        }
    }

    Ok(())
}

fn should_include_file(file_path: &Path, args: &ScanArgs) -> bool {
    // Check file size constraints
    if let Ok(metadata) = std::fs::metadata(file_path) {
        let file_size = metadata.len();

        if let Some(max_size) = args.max_size {
            if file_size > max_size {
                return false;
            }
        }

        if let Some(min_size) = args.min_size {
            if file_size < min_size {
                return false;
            }
        }
    }

    let file_name = file_path.file_name().unwrap_or_default().to_string_lossy();

    // Check include patterns
    if let Some(include_patterns) = &args.include {
        let patterns: Vec<&str> = include_patterns.split(',').map(|s| s.trim()).collect();
        let matches_include = patterns
            .iter()
            .any(|pattern| glob_match(pattern, &file_name));

        if !matches_include {
            return false;
        }
    }

    // Check exclude patterns
    if let Some(exclude_patterns) = &args.exclude {
        let patterns: Vec<&str> = exclude_patterns.split(',').map(|s| s.trim()).collect();
        let matches_exclude = patterns
            .iter()
            .any(|pattern| glob_match(pattern, &file_name));

        if matches_exclude {
            return false;
        }
    }

    true
}

fn glob_match(pattern: &str, text: &str) -> bool {
    // Simple glob matching - supports * and ?
    let pattern_regex = pattern
        .replace(".", r"\.")
        .replace("*", ".*")
        .replace("?", ".");

    if let Ok(regex) = regex::Regex::new(&format!("^{}$", pattern_regex)) {
        regex.is_match(text)
    } else {
        false
    }
}

async fn scan_single_file(
    client: &Client,
    file_path: &Path,
    args: &ScanArgs,
    verbose: bool,
) -> Result<ScanResult> {
    let metadata = fs::metadata(file_path)
        .await
        .with_context(|| format!("Failed to read metadata for {}", file_path.display()))?;

    let file_size = metadata.len();

    // Check if file should be skipped
    if let Some(skip_result) = check_should_skip_file(client, file_path, file_size, args, verbose).await? {
        return Ok(skip_result);
    }

    // Submit file for scanning
    submit_file_for_scan(client, file_path, file_size, verbose).await
}

async fn check_should_skip_file(
    client: &Client,
    file_path: &Path,
    file_size: u64,
    args: &ScanArgs,
    verbose: bool,
) -> Result<Option<ScanResult>> {
    if !args.skip_known || args.force_rescan {
        return Ok(None);
    }

    // Calculate file hash to check if it exists
    let file_content = match fs::read(file_path).await {
        Ok(content) => content,
        Err(_) => return Ok(None),
    };

    let hash = calculate_file_hash(&file_content);
    
    match client.files().get(&hash).await {
        Ok(_existing_report) => {
            if verbose {
                println!(
                    "  File already known to VirusTotal, skipping: {}",
                    file_path.display()
                );
            }
            Ok(Some(ScanResult {
                file_path: file_path.to_path_buf(),
                file_size,
                analysis_id: None,
                scan_date: None,
                error: None,
                analysis_result: None,
            }))
        }
        Err(_) => Ok(None),
    }
}

fn calculate_file_hash(file_content: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(file_content);
    format!("{:x}", hasher.finalize())
}

async fn submit_file_for_scan(
    client: &Client,
    file_path: &Path,
    file_size: u64,
    verbose: bool,
) -> Result<ScanResult> {
    match client.files().upload(file_path).await {
        Ok(upload_response) => {
            if verbose {
                println!("  ✓ Submitted for analysis: {}", upload_response.data.id);
            }

            Ok(ScanResult {
                file_path: file_path.to_path_buf(),
                file_size,
                analysis_id: Some(upload_response.data.id),
                scan_date: Some(chrono::Utc::now().to_rfc3339()),
                error: None,
                analysis_result: None,
            })
        }
        Err(e) => create_error_scan_result(file_path, file_size, &e, verbose),
    }
}

fn create_error_scan_result(
    file_path: &Path,
    file_size: u64,
    error: &crate::Error,
    verbose: bool,
) -> Result<ScanResult> {
    let error_msg = handle_vt_error(error);

    if verbose {
        eprintln!(
            "  ✗ Failed to submit {}: {}",
            file_path.display(),
            error_msg
        );
    }

    Ok(ScanResult {
        file_path: file_path.to_path_buf(),
        file_size,
        analysis_id: None,
        scan_date: None,
        error: Some(error_msg),
        analysis_result: None,
    })
}

async fn wait_for_analysis_results(
    client: &Client,
    scan_results: &mut [ScanResult],
    args: &ScanArgs,
    verbose: bool,
) -> Result<()> {
    let poll_config = PollConfiguration::new(args.timeout, args.poll_interval);
    let pending_analyses = collect_pending_analyses(scan_results);
    
    if pending_analyses.is_empty() {
        return Ok(());
    }

    let progress = create_progress_tracker(&pending_analyses, verbose);
    let mut completed = 0;

    while should_continue_polling(completed, &pending_analyses, &poll_config) {
        completed = poll_analysis_results(
            client,
            scan_results,
            &pending_analyses,
            completed,
            &progress,
            verbose,
        ).await;

        if completed < pending_analyses.len() {
            sleep(poll_config.poll_interval).await;
        }
    }

    finish_polling(&progress, completed, &pending_analyses);
    Ok(())
}

struct PollConfiguration {
    timeout_duration: Duration,
    poll_interval: Duration,
    start_time: std::time::Instant,
}

impl PollConfiguration {
    fn new(timeout_secs: u64, poll_interval_secs: u64) -> Self {
        Self {
            timeout_duration: Duration::from_secs(timeout_secs),
            poll_interval: Duration::from_secs(poll_interval_secs),
            start_time: std::time::Instant::now(),
        }
    }
}

fn collect_pending_analyses(scan_results: &[ScanResult]) -> Vec<usize> {
    scan_results
        .iter()
        .enumerate()
        .filter(|(_, r)| r.analysis_id.is_some() && r.analysis_result.is_none())
        .map(|(i, _)| i)
        .collect()
}

fn create_progress_tracker(pending_analyses: &[usize], verbose: bool) -> Option<ProgressTracker> {
    if !verbose {
        Some(ProgressTracker::new(
            pending_analyses.len() as u64,
            "Waiting for results",
        ))
    } else {
        None
    }
}

fn should_continue_polling(
    completed: usize,
    pending_analyses: &[usize],
    poll_config: &PollConfiguration,
) -> bool {
    completed < pending_analyses.len() 
        && poll_config.start_time.elapsed() < poll_config.timeout_duration
}

async fn poll_analysis_results(
    client: &Client,
    scan_results: &mut [ScanResult],
    pending_analyses: &[usize],
    mut completed: usize,
    progress: &Option<ProgressTracker>,
    verbose: bool,
) -> usize {
    for &index in pending_analyses {
        if scan_results[index].analysis_result.is_some() {
            continue; // Already completed
        }

        if let Some(ref analysis_id) = scan_results[index].analysis_id {
            if let Some(analysis_result) = try_get_analysis_result(client, analysis_id, &scan_results[index], verbose).await {
                scan_results[index].analysis_result = Some(analysis_result);
                completed += 1;
                
                if let Some(ref progress) = progress {
                    progress.inc(1);
                }
            }
        }
    }
    completed
}

async fn try_get_analysis_result(
    client: &Client,
    analysis_id: &str,
    scan_result: &ScanResult,
    verbose: bool,
) -> Option<Analysis> {
    match client.analyses().get(analysis_id).await {
        Ok(analysis_result) => {
            if analysis_result.is_completed() {
                if verbose {
                    println!(
                        "  ✓ Analysis completed for {}",
                        scan_result.file_path.display()
                    );
                }
                Some(analysis_result)
            } else {
                None
            }
        }
        Err(e) => {
            if verbose {
                eprintln!(
                    "  Warning: Failed to get analysis result for {}: {}",
                    scan_result.file_path.display(),
                    handle_vt_error(&e)
                );
            }
            None
        }
    }
}

fn finish_polling(progress: &Option<ProgressTracker>, completed: usize, pending_analyses: &[usize]) {
    if let Some(progress) = progress {
        progress.finish_with_message(&format!(
            "Completed {}/{} analyses",
            completed,
            pending_analyses.len()
        ));
    }

    if completed < pending_analyses.len() {
        println!(
            "Warning: {} analyses did not complete within timeout",
            pending_analyses.len() - completed
        );
    }
}

fn print_summary_results(results: &[ScanResult], colored: bool) -> Result<()> {
    println!("{}", colorize_text("=== Scan Results ===", "bold", colored));

    for (i, result) in results.iter().enumerate() {
        println!("\n{}. {}", i + 1, result.file_path.display());
        println!("   Size: {}", format_file_size(result.file_size));

        if let Some(ref error) = result.error {
            println!(
                "   Status: {}",
                colorize_text(&format!("Failed - {}", error), "red", colored)
            );
        } else if let Some(ref analysis_id) = result.analysis_id {
            if let Some(ref analysis_result) = result.analysis_result {
                let status = if analysis_result.is_completed() {
                    "completed"
                } else {
                    "in_progress"
                };
                let color = match status {
                    "completed" => "green",
                    "in_progress" | "queued" => "yellow",
                    _ => "red",
                };
                println!("   Status: {}", colorize_text(status, color, colored));

                // Show detection results if available
                if let Some(ref stats) = analysis_result.object.attributes.stats {
                    let detected = stats.malicious + stats.suspicious;

                    if detected > 0 {
                        println!(
                            "   Detections: {}",
                            colorize_text(
                                &format!("{} engines detected threats", detected),
                                "red",
                                colored
                            )
                        );
                    } else {
                        println!(
                            "   Detections: {}",
                            colorize_text("Clean", "green", colored)
                        );
                    }
                }
            } else {
                println!(
                    "   Status: {}",
                    colorize_text("Submitted for analysis", "yellow", colored)
                );
                println!("   Analysis ID: {}", analysis_id);
            }
        } else {
            println!("   Status: {}", colorize_text("Skipped", "dim", colored));
        }
    }

    Ok(())
}

fn print_table_results(results: &[ScanResult], colored: bool) -> Result<()> {
    use crate::cli::utils::{print_table_row, print_table_separator};

    let widths = [30, 12, 15, 20];
    let headers = ["File", "Size", "Status", "Detections"];

    print_table_row(&headers, &widths);
    print_table_separator(&widths);

    for result in results {
        let table_row = format_table_row_for_result(result, colored);
        print_table_row(&table_row, &widths);
    }

    Ok(())
}

fn format_table_row_for_result(result: &ScanResult, colored: bool) -> [String; 4] {
    let truncated_name = truncate_filename(&result.file_path);
    let size_str = format_file_size(result.file_size);
    let (status, detections) = determine_status_and_detections(result, colored);
    
    [truncated_name, size_str, status, detections]
}

fn truncate_filename(file_path: &std::path::PathBuf) -> String {
    let file_name = file_path
        .file_name()
        .unwrap_or_default()
        .to_string_lossy();

    if file_name.len() > 28 {
        format!("{}...", &file_name[..25])
    } else {
        file_name.to_string()
    }
}

fn determine_status_and_detections(result: &ScanResult, colored: bool) -> (String, String) {
    if let Some(ref error) = result.error {
        (colorize_text("Failed", "red", colored), error.clone())
    } else if let Some(ref analysis_result) = result.analysis_result {
        format_completed_analysis_status(analysis_result, colored)
    } else if result.analysis_id.is_some() {
        (colorize_text("Submitted", "yellow", colored), "Pending...".to_string())
    } else {
        (colorize_text("Skipped", "dim", colored), "N/A".to_string())
    }
}

fn format_completed_analysis_status(analysis_result: &Analysis, colored: bool) -> (String, String) {
    let status_str = if analysis_result.is_completed() { "completed" } else { "in_progress" };
    let status_color = match status_str {
        "completed" => "green",
        "in_progress" | "queued" => "yellow",
        _ => "red",
    };
    let status = colorize_text(status_str, status_color, colored);

    let detections = if let Some(ref stats) = analysis_result.object.attributes.stats {
        let detected = stats.malicious + stats.suspicious;
        if detected > 0 {
            colorize_text(&format!("{} detected", detected), "red", colored)
        } else {
            colorize_text("Clean", "green", colored)
        }
    } else {
        "Analyzing...".to_string()
    };

    (status, detections)
}

fn format_results_as_text(results: &[ScanResult]) -> Result<String> {
    let mut output = String::new();

    output.push_str("=== Scan Results ===\n\n");

    for (i, result) in results.iter().enumerate() {
        output.push_str(&format!("{}. {}\n", i + 1, result.file_path.display()));
        output.push_str(&format!(
            "   Size: {}\n",
            format_file_size(result.file_size)
        ));

        if let Some(ref error) = result.error {
            output.push_str(&format!("   Status: Failed - {}\n", error));
        } else if let Some(ref analysis_id) = result.analysis_id {
            output.push_str(&format!("   Analysis ID: {}\n", analysis_id));

            if let Some(ref analysis_result) = result.analysis_result {
                let status = if analysis_result.is_completed() {
                    "completed"
                } else {
                    "in_progress"
                };
                output.push_str(&format!("   Status: {}\n", status));
            }
        } else {
            output.push_str("   Status: Skipped\n");
        }

        output.push('\n');
    }

    Ok(output)
}
