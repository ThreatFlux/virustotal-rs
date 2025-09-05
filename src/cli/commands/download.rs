use crate::cli::utils::{
    create_progress_tracker, detect_input_type, format_file_size, format_json_output,
    handle_dry_run_check, handle_vt_error, read_hashes_from_file, read_hashes_from_json_export,
    setup_client_arc, truncate_hash, validate_hash, InputType, ProgressTracker,
};
use crate::{ApiTier, Client};
use anyhow::{Context, Result};
use clap::Args;
use futures::stream::{self, StreamExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::fs;
use tokio::time::sleep;

// Helper structures for organizing download results
#[derive(Debug, Clone)]
struct DownloadCounters {
    successful: Arc<AtomicUsize>,
    failed: Arc<AtomicUsize>,
    skipped: Arc<AtomicUsize>,
    processed: Arc<AtomicUsize>,
    total_size: Arc<AtomicUsize>,
}

impl DownloadCounters {
    fn new() -> Self {
        Self {
            successful: Arc::new(AtomicUsize::new(0)),
            failed: Arc::new(AtomicUsize::new(0)),
            skipped: Arc::new(AtomicUsize::new(0)),
            processed: Arc::new(AtomicUsize::new(0)),
            total_size: Arc::new(AtomicUsize::new(0)),
        }
    }
}

#[derive(Debug, Clone)]
struct DownloadContext {
    download_files: bool,
    download_reports: bool,
}

struct ProcessDownloadsParams {
    client: Arc<Client>,
    output_dir: Arc<PathBuf>,
    reports_dir: Arc<PathBuf>,
    context: DownloadContext,
    args: DownloadArgs,
    counters: DownloadCounters,
    total: usize,
    verbose: bool,
    concurrency: usize,
}

/// Parse input and extract hashes based on input type
fn parse_input_hashes(input: &str, verbose: bool) -> Result<Vec<String>> {
    let input_type = detect_input_type(input)?;
    let hashes = match input_type {
        InputType::SingleHash => {
            validate_hash(input)?;
            vec![input.to_string()]
        }
        InputType::TextFile => read_hashes_from_file(input)?,
        InputType::JsonExport => {
            if verbose {
                println!("Detected JSON export file, extracting file hashes...");
            }
            read_hashes_from_json_export(input)?
        }
    };
    Ok(hashes)
}

/// Create necessary output directories
async fn setup_directories(args: &DownloadArgs, context: &DownloadContext) -> Result<()> {
    if context.download_files {
        fs::create_dir_all(&args.output).await.with_context(|| {
            format!(
                "Failed to create output directory: {}",
                args.output.display()
            )
        })?;
    }

    if context.download_reports {
        fs::create_dir_all(&args.reports_dir)
            .await
            .with_context(|| {
                format!(
                    "Failed to create reports directory: {}",
                    args.reports_dir.display()
                )
            })?;
    }

    Ok(())
}

/// Print directory information if verbose
fn print_directory_info(args: &DownloadArgs, context: &DownloadContext, verbose: bool) {
    if verbose && context.download_reports {
        if args.reports_only {
            println!(
                "Only downloading reports to: {}",
                args.reports_dir.display()
            );
        } else {
            println!("Reports will be saved to: {}", args.reports_dir.display());
        }
    }
}

/// Check if file exists and should be considered for skipping
fn file_exists_for_download(context: &DownloadContext, file_path: &Path) -> bool {
    context.download_files && file_path.exists()
}

/// Check if report exists and should be considered for skipping
fn report_exists_for_download(context: &DownloadContext, report_path: &Path) -> bool {
    context.download_reports && report_path.exists()
}

/// Check if file-only download should be skipped
fn should_skip_files_only(context: &DownloadContext, file_exists: bool) -> bool {
    context.download_files && !context.download_reports && file_exists
}

/// Check if reports-only download should be skipped
fn should_skip_reports_only(context: &DownloadContext, report_exists: bool) -> bool {
    !context.download_files && context.download_reports && report_exists
}

/// Check if both files and reports download should be skipped
fn should_skip_both(context: &DownloadContext, file_exists: bool, report_exists: bool) -> bool {
    context.download_files && context.download_reports && file_exists && report_exists
}

/// Check if a file should be skipped in resume mode
fn should_skip_file(
    args: &DownloadArgs,
    context: &DownloadContext,
    hash: &str,
    output_dir: &Path,
    reports_dir: &Path,
) -> bool {
    if !args.resume {
        return false;
    }

    let file_path = output_dir.join(format!("{}.bin", hash));
    let report_path = reports_dir.join(format!("{}.json", hash));

    let file_exists = file_exists_for_download(context, &file_path);
    let report_exists = report_exists_for_download(context, &report_path);

    should_skip_files_only(context, file_exists)
        || should_skip_reports_only(context, report_exists)
        || should_skip_both(context, file_exists, report_exists)
}

/// Create JSON summary structure
fn create_json_summary(
    args: &DownloadArgs,
    hashes_count: usize,
    successful_count: usize,
    failed_count: usize,
    skipped_count: usize,
    total_bytes: usize,
    context: &DownloadContext,
) -> serde_json::Value {
    serde_json::json!({
        "total": hashes_count,
        "successful": successful_count,
        "failed": failed_count,
        "skipped": skipped_count,
        "total_size": total_bytes,
        "total_size_formatted": format_file_size(total_bytes as u64),
        "output_directory": args.output,
        "reports_directory": if context.download_reports { Some(&args.reports_dir) } else { None }
    })
}

/// Print download summary as table format
fn print_table_summary(
    args: &DownloadArgs,
    hashes_count: usize,
    successful_count: usize,
    failed_count: usize,
    skipped_count: usize,
    total_bytes: usize,
    context: &DownloadContext,
) {
    println!("\n=== Download Summary ===");
    println!("Total hashes:     {}", hashes_count);
    println!("Successfully downloaded: {}", successful_count);
    println!("Failed:          {}", failed_count);
    if skipped_count > 0 {
        println!("Skipped (resume): {}", skipped_count);
    }
    if total_bytes > 0 {
        println!("Total size:      {}", format_file_size(total_bytes as u64));
    }

    if successful_count > 0 {
        if context.download_files {
            println!("Files saved to:  {}", args.output.display());
        }
        if context.download_reports {
            println!("Reports saved to: {}", args.reports_dir.display());
        }
    }
}

/// Print download summary in specified format
fn print_download_summary(
    args: &DownloadArgs,
    hashes_count: usize,
    counters: &DownloadCounters,
    context: &DownloadContext,
) -> Result<()> {
    let successful_count = counters.successful.load(Ordering::SeqCst);
    let failed_count = counters.failed.load(Ordering::SeqCst);
    let skipped_count = counters.skipped.load(Ordering::SeqCst);
    let total_bytes = counters.total_size.load(Ordering::SeqCst);

    match args.format.as_str() {
        "json" => {
            let summary = create_json_summary(
                args,
                hashes_count,
                successful_count,
                failed_count,
                skipped_count,
                total_bytes,
                context,
            );
            let json_output = format_json_output(&summary, true)?;
            println!("{}", json_output);
            Ok(())
        }
        _ => {
            print_table_summary(
                args,
                hashes_count,
                successful_count,
                failed_count,
                skipped_count,
                total_bytes,
                context,
            );
            Ok(())
        }
    }
}

#[derive(Args, Debug, Clone)]
pub struct DownloadArgs {
    /// Path to file containing hashes or single hash. Supports:
    /// - Single hash (MD5, SHA1, or SHA256)
    /// - Text files with hashes (one per line)
    /// - JSON export files from VirusTotal (e.g., hunting results)
    #[arg(short, long)]
    pub input: String,

    /// Output directory for downloaded files
    #[arg(short, long, default_value = "./downloads")]
    pub output: PathBuf,

    /// Directory for JSON reports
    #[arg(long, default_value = "./reports")]
    pub reports_dir: PathBuf,

    /// Number of concurrent downloads (auto-detected based on API tier if not specified)
    #[arg(long)]
    pub concurrency: Option<usize>,

    /// Download and save JSON analysis reports
    #[arg(short = 'r', long)]
    pub reports: bool,

    /// Download only files, skip reports
    #[arg(long)]
    pub files_only: bool,

    /// Download only reports, skip files
    #[arg(long)]
    pub reports_only: bool,

    /// Skip hashes that fail to download instead of stopping
    #[arg(short, long)]
    pub skip_errors: bool,

    /// Resume interrupted downloads by skipping existing files
    #[arg(long)]
    pub resume: bool,

    /// Output format for summary (table, json)
    #[arg(long, default_value = "table")]
    pub format: String,

    /// Enable debug mode for detailed error information
    #[arg(long)]
    pub debug: bool,

    /// Filter by minimum file size (in bytes)
    #[arg(long)]
    pub min_size: Option<u64>,

    /// Filter by maximum file size (in bytes)
    #[arg(long)]
    pub max_size: Option<u64>,

    /// Filter by minimum detection count
    #[arg(long)]
    pub min_detections: Option<u32>,

    /// Filter by file type
    #[arg(long)]
    pub file_type: Option<String>,
}

/// Validate initial conditions and return parsed hashes
async fn validate_and_parse_input(
    args: &DownloadArgs,
    verbose: bool,
    dry_run: bool,
) -> Result<Vec<String>> {
    let hashes = parse_input_hashes(&args.input, verbose)?;

    if hashes.is_empty() {
        println!("No hashes to process");
        return Ok(vec![]);
    }

    println!("Found {} hashes to process", hashes.len());

    if handle_dry_run_check(dry_run, &format!("Would process {} hashes", hashes.len())).is_err() {
        return Ok(vec![]);
    }

    Ok(hashes)
}

/// Create download context based on arguments
fn create_download_context(args: &DownloadArgs) -> DownloadContext {
    DownloadContext {
        download_files: !args.reports_only,
        download_reports: args.reports || args.reports_only,
    }
}

/// Setup concurrency and print tier information
async fn setup_concurrency_and_tier(
    client: &Client,
    tier: &str,
    manual_concurrency: Option<usize>,
    verbose: bool,
) -> Result<usize> {
    let (_api_tier, optimal_concurrency) =
        detect_tier_and_concurrency(client, tier, manual_concurrency, verbose).await?;

    if verbose && optimal_concurrency > 1 {
        println!(
            "Using {} concurrent downloads (premium tier)",
            optimal_concurrency
        );
    }

    Ok(optimal_concurrency)
}

/// Setup progress tracking based on verbosity
fn setup_progress_tracking(hash_count: usize, verbose: bool) -> Option<ProgressTracker> {
    create_progress_tracker(verbose, hash_count, "Downloading")
}

/// Handle error checking and reporting based on skip_errors flag
fn handle_error_results(results: Vec<Result<(), anyhow::Error>>, skip_errors: bool) -> Result<()> {
    if skip_errors {
        return Ok(());
    }

    for result in results {
        if let Err(e) = result {
            eprintln!("\nStopping due to error: {}", e);
            eprintln!("Use --skip-errors to continue on failures.");
            return Err(e);
        }
    }

    Ok(())
}

pub async fn execute(
    args: DownloadArgs,
    api_key: Option<String>,
    tier: &str,
    verbose: bool,
    dry_run: bool,
) -> Result<()> {
    let client = setup_client_arc(api_key, tier)?;

    // Validate input and handle dry run
    let hashes = validate_and_parse_input(&args, verbose, dry_run).await?;
    if hashes.is_empty() {
        return Ok(());
    }

    // Create download context
    let context = create_download_context(&args);

    // Setup directories
    setup_directories(&args, &context).await?;
    print_directory_info(&args, &context, verbose);

    // Setup concurrency
    let concurrency = setup_concurrency_and_tier(&client, tier, args.concurrency, verbose).await?;

    // Setup progress tracking
    let progress = setup_progress_tracking(hashes.len(), verbose);

    // Setup counters and parameters
    let counters = DownloadCounters::new();
    let total = hashes.len();
    let params = ProcessDownloadsParams {
        client,
        output_dir: Arc::new(args.output.clone()),
        reports_dir: Arc::new(args.reports_dir.clone()),
        context: context.clone(),
        args: args.clone(),
        counters: counters.clone(),
        total,
        verbose,
        concurrency,
    };

    // Execute downloads
    let results = process_downloads(&hashes, params, progress.as_ref()).await?;

    // Finish progress tracking
    if let Some(progress) = progress {
        progress.finish_with_message("Download completed");
    }

    // Handle errors
    handle_error_results(results, args.skip_errors)?;

    // Print summary
    print_download_summary(&args, total, &counters, &context)?;

    Ok(())
}

/// Handle successful download result
fn handle_download_success(
    file_size: usize,
    report_saved: bool,
    hash: &str,
    verbose: bool,
    progress: Option<&ProgressTracker>,
    successful: &AtomicUsize,
    total_size: &AtomicUsize,
) {
    successful.fetch_add(1, Ordering::SeqCst);
    if file_size > 0 {
        total_size.fetch_add(file_size, Ordering::SeqCst);
    }

    if verbose {
        let size_msg = if file_size > 0 {
            format!(" ({})", format_file_size(file_size as u64))
        } else {
            String::new()
        };
        let report_msg = if report_saved { " + report" } else { "" };
        println!(
            "  ✓ {} downloaded{}{}",
            truncate_hash(hash, 16),
            size_msg,
            report_msg
        );
    }

    if let Some(progress) = progress {
        progress.inc(1);
    }
}

/// Handle failed download result
fn handle_download_failure(
    error: &crate::Error,
    hash: &str,
    verbose: bool,
    progress: Option<&ProgressTracker>,
    failed: &AtomicUsize,
    skip_errors: bool,
) -> Result<(), anyhow::Error> {
    failed.fetch_add(1, Ordering::SeqCst);
    let error_msg = handle_vt_error(error);

    if verbose {
        eprintln!("  ✗ {} failed: {}", truncate_hash(hash, 16), error_msg);
    } else {
        eprintln!("Failed {}: {}", truncate_hash(hash, 16), error_msg);
    }

    if let Some(progress) = progress {
        progress.inc(1);
    }

    if skip_errors {
        Ok(())
    } else {
        Err(anyhow::anyhow!(
            "Failed to download {}: {}",
            hash,
            error_msg
        ))
    }
}

/// Handle skipped file in resume mode
fn handle_skipped_file(
    hash: &str,
    verbose: bool,
    progress: Option<&ProgressTracker>,
    skipped: &AtomicUsize,
) {
    skipped.fetch_add(1, Ordering::SeqCst);
    if verbose {
        println!("  → {} already exists, skipping", truncate_hash(hash, 16));
    }
    if let Some(progress) = progress {
        progress.inc(1);
    }
}

/// Print progress information for current hash
fn print_progress_info(
    current: usize,
    total: usize,
    hash: &str,
    verbose: bool,
    progress: Option<&ProgressTracker>,
) {
    let progress_msg = format!("[{}/{}]", current, total);

    if verbose {
        println!("{} Processing hash: {}", progress_msg, hash);
    } else if let Some(progress) = progress {
        progress.set_message(&format!("Processing {}", truncate_hash(hash, 16)));
    }
}

/// Process a single hash download with all error handling
async fn process_single_download(
    hash: String,
    params: &ProcessDownloadsParams,
    progress: Option<&ProgressTracker>,
) -> Result<(), anyhow::Error> {
    let current = params.counters.processed.fetch_add(1, Ordering::SeqCst) + 1;

    print_progress_info(current, params.total, &hash, params.verbose, progress);

    // Check if we should skip this file (resume mode)
    if should_skip_file(
        &params.args,
        &params.context,
        &hash,
        &params.output_dir,
        &params.reports_dir,
    ) {
        handle_skipped_file(&hash, params.verbose, progress, &params.counters.skipped);
        return Ok(());
    }

    // Try to download
    match download_with_retry(
        &params.client,
        &hash,
        &params.output_dir,
        &params.reports_dir,
        params.context.download_files,
        params.context.download_reports,
        &params.args,
    )
    .await
    {
        Ok((file_size, report_saved)) => {
            handle_download_success(
                file_size,
                report_saved,
                &hash,
                params.verbose,
                progress,
                &params.counters.successful,
                &params.counters.total_size,
            );
            Ok(())
        }
        Err(e) => handle_download_failure(
            &e,
            &hash,
            params.verbose,
            progress,
            &params.counters.failed,
            params.args.skip_errors,
        ),
    }
}

/// Create async closure for processing a single hash download
async fn create_download_closure(
    hash: String,
    params: Arc<ProcessDownloadsParams>,
    progress: Option<&ProgressTracker>,
) -> Result<(), anyhow::Error> {
    process_single_download(hash, &params, progress).await
}

/// Process all downloads with concurrency control
async fn process_downloads(
    hashes: &[String],
    params: ProcessDownloadsParams,
    progress: Option<&ProgressTracker>,
) -> Result<Vec<Result<(), anyhow::Error>>> {
    let concurrency = params.concurrency;
    let params = Arc::new(params);

    let results: Vec<_> = stream::iter(hashes.iter())
        .map(|hash| {
            let hash = hash.clone();
            let params = Arc::clone(&params);
            async move { create_download_closure(hash, params, progress).await }
        })
        .buffer_unordered(concurrency)
        .collect()
        .await;

    Ok(results)
}

/// Helper function to determine if an error should trigger a retry
fn should_retry_error(error: &crate::Error) -> bool {
    match error {
        crate::Error::TooManyRequests => true,
        crate::Error::Http(http_err) => {
            if let Some(status) = http_err.status() {
                matches!(status.as_u16(), 429 | 502 | 503 | 504)
            } else {
                // Network errors without status (timeouts, connection errors)
                http_err.to_string().contains("timeout")
                    || http_err.to_string().contains("connection")
                    || http_err.to_string().contains("decode")
            }
        }
        crate::Error::Json(_) => {
            // Retry JSON parsing errors as they might be due to incomplete responses
            true
        }
        crate::Error::Unknown(msg) => {
            // Retry if it looks like a temporary issue
            msg.contains("Empty response")
                || msg.contains("HTML response")
                || msg.contains("XML response")
        }
        crate::Error::TransientError => true,
        crate::Error::DeadlineExceeded => true,
        _ => false,
    }
}

/// Calculate retry delay based on error type and attempt number
fn calculate_retry_delay(error: &crate::Error, attempt: u32) -> Duration {
    const BASE_DELAY: Duration = Duration::from_secs(1);

    match error {
        crate::Error::TooManyRequests => {
            // Longer delay for rate limits
            Duration::from_secs(60 * (attempt + 1) as u64)
        }
        crate::Error::Http(http_err) if http_err.to_string().contains("timeout") => {
            // Shorter delay for timeouts
            BASE_DELAY * (attempt + 1)
        }
        _ => {
            // Exponential backoff for other errors
            BASE_DELAY * 2_u32.pow(attempt)
        }
    }
}

/// Download with retry logic for rate limit handling
async fn download_with_retry(
    client: &Client,
    hash: &str,
    output_dir: &Path,
    reports_dir: &Path,
    download_files: bool,
    download_reports: bool,
    args: &DownloadArgs,
) -> Result<(usize, bool), crate::Error> {
    const MAX_RETRIES: u32 = 3;

    for attempt in 0..MAX_RETRIES {
        match download_file_and_report(
            client,
            hash,
            output_dir,
            reports_dir,
            download_files,
            download_reports,
            args,
        )
        .await
        {
            Ok(result) => return Ok(result),
            Err(e) => {
                if should_retry_error(&e) && attempt < MAX_RETRIES - 1 {
                    let delay = calculate_retry_delay(&e, attempt);

                    eprintln!(
                        "  → Retry {}/{} for {} after {:?} ({})",
                        attempt + 1,
                        MAX_RETRIES,
                        truncate_hash(hash, 16),
                        delay,
                        handle_vt_error(&e)
                    );
                    sleep(delay).await;
                    continue;
                }

                // Return the error (either non-retryable error or final retry failure)
                return Err(e);
            }
        }
    }

    // This shouldn't be reached, but just in case
    Err(crate::Error::Unknown("Max retries exceeded".to_string()))
}

/// Apply filters to file info to determine if file should be downloaded
fn apply_file_filters(
    file_info: &crate::files::File,
    args: &DownloadArgs,
) -> Result<(), crate::Error> {
    let attributes = &file_info.object.attributes;

    // Size filters
    if let Some(size) = attributes.size {
        if let Some(min_size) = args.min_size {
            if size < min_size {
                return Err(crate::Error::Unknown("File too small".to_string()));
            }
        }
        if let Some(max_size) = args.max_size {
            if size > max_size {
                return Err(crate::Error::Unknown("File too large".to_string()));
            }
        }
    }

    // Detection count filter
    if let Some(min_detections) = args.min_detections {
        if let Some(stats) = &attributes.last_analysis_stats {
            let detected = stats.malicious + stats.suspicious;
            if detected < min_detections {
                return Err(crate::Error::Unknown("Not enough detections".to_string()));
            }
        }
    }

    // File type filter
    if let Some(ref filter_type) = args.file_type {
        if let Some(ref type_description) = attributes.type_description {
            if !type_description
                .to_lowercase()
                .contains(&filter_type.to_lowercase())
            {
                return Err(crate::Error::Unknown(
                    "File type doesn't match filter".to_string(),
                ));
            }
        }
    }

    Ok(())
}

/// Download file content if requested and allowed
async fn download_file_content(
    client: &Client,
    hash: &str,
    output_dir: &Path,
    file_info: Option<&crate::files::File>,
) -> Result<usize, crate::Error> {
    let is_downloadable = file_info
        .and_then(|info| info.object.attributes.downloadable)
        .unwrap_or(true);

    if !is_downloadable {
        return Err(crate::Error::Unknown("File not downloadable".to_string()));
    }

    match client.files().download(hash).await {
        Ok(file_bytes) => {
            let file_size = file_bytes.len();
            let filename = format!("{}.bin", hash);
            let output_path = output_dir.join(&filename);

            tokio::fs::write(&output_path, file_bytes)
                .await
                .map_err(|e| crate::Error::Unknown(format!("Failed to write file: {}", e)))?;

            Ok(file_size)
        }
        Err(e) => Err(e),
    }
}

/// Save JSON report if requested
async fn save_file_report(
    client: &Client,
    hash: &str,
    reports_dir: &Path,
    file_info: Option<crate::files::File>,
) -> Result<bool, crate::Error> {
    let info = if let Some(info) = file_info {
        info
    } else {
        client.files().get(hash).await?
    };

    let json_report = serde_json::to_string_pretty(&info)
        .map_err(|e| crate::Error::Unknown(format!("Failed to serialize report: {}", e)))?;

    let report_filename = format!("{}.json", hash);
    let report_path = reports_dir.join(&report_filename);

    tokio::fs::write(&report_path, json_report)
        .await
        .map_err(|e| crate::Error::Unknown(format!("Failed to write report: {}", e)))?;

    Ok(true)
}

/// Get and validate file info if needed
async fn get_and_validate_file_info(
    client: &Client,
    hash: &str,
    download_files: bool,
    download_reports: bool,
    args: &DownloadArgs,
) -> Result<Option<crate::files::File>, crate::Error> {
    let file_info = if download_reports || !download_files {
        Some(client.files().get(hash).await?)
    } else {
        None
    };

    // Apply filters if file info is available
    if let Some(ref info) = file_info {
        apply_file_filters(info, args)?;
    }

    Ok(file_info)
}

/// Handle file download operations
async fn handle_file_download(
    client: &Client,
    hash: &str,
    output_dir: &Path,
    download_files: bool,
    file_info: Option<&crate::files::File>,
) -> Result<usize, crate::Error> {
    if download_files {
        download_file_content(client, hash, output_dir, file_info).await
    } else {
        Ok(0)
    }
}

/// Handle report saving operations  
async fn handle_report_saving(
    client: &Client,
    hash: &str,
    reports_dir: &Path,
    download_reports: bool,
    file_info: Option<crate::files::File>,
) -> Result<bool, crate::Error> {
    if download_reports {
        save_file_report(client, hash, reports_dir, file_info).await
    } else {
        Ok(false)
    }
}

async fn download_file_and_report(
    client: &Client,
    hash: &str,
    output_dir: &Path,
    reports_dir: &Path,
    download_files: bool,
    download_reports: bool,
    args: &DownloadArgs,
) -> Result<(usize, bool), crate::Error> {
    // Get and validate file info
    let file_info =
        get_and_validate_file_info(client, hash, download_files, download_reports, args).await?;

    // Download file if requested
    let file_size =
        handle_file_download(client, hash, output_dir, download_files, file_info.as_ref()).await?;

    // Save report if requested
    let report_saved =
        handle_report_saving(client, hash, reports_dir, download_reports, file_info).await?;

    Ok((file_size, report_saved))
}

/// Detect if user has premium privileges
fn has_premium_privileges(user: &crate::users::User) -> bool {
    user.attributes
        .privileges
        .as_ref()
        .map(|p| {
            p.download_file().unwrap_or(false)
                || p.intelligence().unwrap_or(false)
                || p.private_scanning().unwrap_or(false)
        })
        .unwrap_or(false)
}

/// Check if user has high API quotas (indicating premium)
fn has_high_quota(user: &crate::users::User) -> bool {
    user.attributes
        .quotas
        .as_ref()
        .and_then(|q| q.api_requests_monthly.as_ref())
        .map(|monthly| monthly.allowed > 15000) // Public tier is typically 15k/month
        .unwrap_or(false)
}

/// Determine optimal concurrency based on API tier and quotas
fn determine_optimal_concurrency(
    api_tier: ApiTier,
    manual_concurrency: Option<usize>,
    user: Option<&crate::users::User>,
) -> usize {
    if let Some(manual) = manual_concurrency {
        // User specified concurrency manually
        return match api_tier {
            ApiTier::Premium => manual.clamp(1, 200),
            ApiTier::Public => 1,
        };
    }

    // Auto-select based on tier and quotas
    match api_tier {
        ApiTier::Premium => {
            if let Some(user) = user {
                // For premium, use aggressive defaults but be smart about quotas
                let monthly_allowed = user
                    .attributes
                    .quotas
                    .as_ref()
                    .and_then(|q| q.api_requests_monthly.as_ref())
                    .map(|monthly| monthly.allowed)
                    .unwrap_or(100000); // Default assumption

                if monthly_allowed > 100000 {
                    100 // High-tier premium: 100 concurrent
                } else if monthly_allowed > 50000 {
                    50 // Mid-tier premium: 50 concurrent
                } else {
                    20 // Entry-level premium: 20 concurrent
                }
            } else {
                20 // Conservative default for premium
            }
        }
        ApiTier::Public => 1, // Public is always sequential
    }
}

/// Print tier detection results
fn print_tier_info(
    api_tier: ApiTier,
    optimal_concurrency: usize,
    user: Option<&crate::users::User>,
    verbose: bool,
) {
    if !verbose {
        return;
    }

    let tier_name = match api_tier {
        ApiTier::Premium => "Premium",
        ApiTier::Public => "Public",
    };

    if let Some(user) = user {
        if let Some(quotas) = &user.attributes.quotas {
            if let Some(monthly) = &quotas.api_requests_monthly {
                println!(
                    "✅ Detected {} tier account ({}/{} monthly quota)",
                    tier_name, monthly.used, monthly.allowed
                );
            } else {
                println!("✅ Detected {} tier account", tier_name);
            }
        } else {
            println!("✅ Detected {} tier account", tier_name);
        }
    }

    if optimal_concurrency > 1 {
        println!(
            "🚀 Using {} concurrent downloads for optimal performance",
            optimal_concurrency
        );
    } else {
        println!("🔄 Using sequential downloads (public tier)");
    }
}

/// Handle manual tier and concurrency settings when user specified both
fn handle_manual_tier_and_concurrency(
    manual_tier: &str,
    manual_concurrency: Option<usize>,
) -> Option<(ApiTier, usize)> {
    if let Some(concurrency_val) = manual_concurrency {
        if manual_tier.to_lowercase() != "public" {
            let api_tier = match manual_tier.to_lowercase().as_str() {
                "premium" | "private" => ApiTier::Premium,
                _ => ApiTier::Public,
            };
            let concurrency = match api_tier {
                ApiTier::Premium => concurrency_val.clamp(1, 200), // Allow up to 200 for premium
                ApiTier::Public => 1,                              // Public is always sequential
            };
            return Some((api_tier, concurrency));
        }
    }
    None
}

/// Auto-detect tier from user API response
async fn auto_detect_tier_from_user_api(
    client: &Client,
    manual_concurrency: Option<usize>,
    verbose: bool,
) -> Result<Option<(ApiTier, usize)>, anyhow::Error> {
    if verbose {
        println!("🔍 Auto-detecting API tier and optimal concurrency...");
    }

    match client.users().get_user(client.api_key()).await {
        Ok(user_response) => {
            let user = &user_response.data;
            let api_tier = determine_tier_from_user_info(user);
            let optimal_concurrency =
                determine_optimal_concurrency(api_tier, manual_concurrency, Some(user));

            print_tier_info(api_tier, optimal_concurrency, Some(user), verbose);
            Ok(Some((api_tier, optimal_concurrency)))
        }
        Err(_) => Ok(None),
    }
}

/// Determine API tier based on user privileges and quotas
fn determine_tier_from_user_info(user: &crate::users::User) -> ApiTier {
    let is_premium = has_premium_privileges(user);
    let has_quota = has_high_quota(user);

    if is_premium || has_quota {
        ApiTier::Premium
    } else {
        ApiTier::Public
    }
}

/// Handle fallback when API detection fails
fn handle_fallback_tier_detection(
    manual_tier: &str,
    manual_concurrency: Option<usize>,
    verbose: bool,
) -> (ApiTier, usize) {
    if verbose {
        println!("⚠️  Failed to auto-detect tier, falling back to manual specification");
    }

    let api_tier = match manual_tier.to_lowercase().as_str() {
        "premium" | "private" => ApiTier::Premium,
        _ => ApiTier::Public,
    };

    let concurrency = determine_optimal_concurrency(api_tier, manual_concurrency, None);
    (api_tier, concurrency)
}

/// Auto-detect API tier and determine optimal concurrency
async fn detect_tier_and_concurrency(
    client: &Client,
    manual_tier: &str,
    manual_concurrency: Option<usize>,
    verbose: bool,
) -> Result<(ApiTier, usize)> {
    // First, check if user manually specified both tier and concurrency
    if let Some((api_tier, concurrency)) =
        handle_manual_tier_and_concurrency(manual_tier, manual_concurrency)
    {
        return Ok((api_tier, concurrency));
    }

    // Try to auto-detect tier by querying user info
    if let Some((api_tier, concurrency)) =
        auto_detect_tier_from_user_api(client, manual_concurrency, verbose).await?
    {
        return Ok((api_tier, concurrency));
    }

    // Fallback to manual tier detection if user API call fails
    let (api_tier, concurrency) =
        handle_fallback_tier_detection(manual_tier, manual_concurrency, verbose);
    Ok((api_tier, concurrency))
}
