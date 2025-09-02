use crate::cli::utils::{
    detect_input_type, format_file_size, handle_vt_error, read_hashes_from_file,
    read_hashes_from_json_export, setup_client, truncate_hash, validate_hash, InputType,
    ProgressTracker,
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

pub async fn execute(
    args: DownloadArgs,
    api_key: Option<String>,
    tier: &str,
    verbose: bool,
    dry_run: bool,
) -> Result<()> {
    let client = Arc::new(setup_client(api_key, tier)?);

    // Detect input type and parse accordingly
    let input_type = detect_input_type(&args.input)?;
    let hashes = match input_type {
        InputType::SingleHash => {
            validate_hash(&args.input)?;
            vec![args.input.clone()]
        }
        InputType::TextFile => read_hashes_from_file(&args.input)?,
        InputType::JsonExport => {
            if verbose {
                println!("Detected JSON export file, extracting file hashes...");
            }
            read_hashes_from_json_export(&args.input)?
        }
    };

    if hashes.is_empty() {
        println!("No hashes to process");
        return Ok(());
    }

    println!("Found {} hashes to process", hashes.len());

    if dry_run {
        println!("DRY RUN MODE - No files will be downloaded");
        for hash in &hashes {
            println!("Would process: {}", truncate_hash(hash, 16));
        }
        return Ok(());
    }

    // Determine what to download
    let download_files = !args.reports_only;
    let download_reports = args.reports || args.reports_only;

    // Create output directories
    if download_files {
        fs::create_dir_all(&args.output).await.with_context(|| {
            format!(
                "Failed to create output directory: {}",
                args.output.display()
            )
        })?;
    }

    if download_reports {
        fs::create_dir_all(&args.reports_dir)
            .await
            .with_context(|| {
                format!(
                    "Failed to create reports directory: {}",
                    args.reports_dir.display()
                )
            })?;

        if verbose {
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

    // Auto-detect API tier and set optimal concurrency
    let (_api_tier, optimal_concurrency) =
        detect_tier_and_concurrency(&client, tier, args.concurrency, verbose).await?;

    let concurrency = optimal_concurrency;

    if verbose && concurrency > 1 {
        println!("Using {} concurrent downloads (premium tier)", concurrency);
    }

    // Progress tracking
    let progress = if !verbose {
        Some(ProgressTracker::new(hashes.len() as u64, "Downloading"))
    } else {
        None
    };

    let successful = Arc::new(AtomicUsize::new(0));
    let failed = Arc::new(AtomicUsize::new(0));
    let skipped = Arc::new(AtomicUsize::new(0));
    let processed = Arc::new(AtomicUsize::new(0));
    let total_size = Arc::new(AtomicUsize::new(0));

    let total = hashes.len();
    let output_dir = Arc::new(args.output.clone());
    let reports_dir = Arc::new(args.reports_dir.clone());

    // Process hashes with controlled concurrency
    let results: Vec<_> = stream::iter(hashes.iter().enumerate())
        .map(|(_, hash)| {
            let client = Arc::clone(&client);
            let output_dir = Arc::clone(&output_dir);
            let reports_dir = Arc::clone(&reports_dir);
            let successful = Arc::clone(&successful);
            let failed = Arc::clone(&failed);
            let skipped = Arc::clone(&skipped);
            let processed = Arc::clone(&processed);
            let total_size = Arc::clone(&total_size);
            let progress = progress.as_ref();
            let hash = hash.clone();
            let args_clone = args.clone();

            async move {
                let current = processed.fetch_add(1, Ordering::SeqCst) + 1;
                let progress_msg = format!("[{}/{}]", current, total);

                if verbose {
                    println!("{} Processing hash: {}", progress_msg, hash);
                } else if let Some(progress) = progress {
                    progress.set_message(&format!("Processing {}", truncate_hash(&hash, 16)));
                }

                // Check if we should skip this file (resume mode)
                if args.resume {
                    let file_path = output_dir.join(format!("{}.bin", hash));
                    let report_path = reports_dir.join(format!("{}.json", hash));

                    let file_exists = download_files && file_path.exists();
                    let report_exists = download_reports && report_path.exists();

                    if (download_files && !download_reports && file_exists)
                        || (!download_files && download_reports && report_exists)
                        || (download_files && download_reports && file_exists && report_exists)
                    {
                        skipped.fetch_add(1, Ordering::SeqCst);
                        if verbose {
                            println!("  → {} already exists, skipping", truncate_hash(&hash, 16));
                        }
                        if let Some(progress) = progress {
                            progress.inc(1);
                        }
                        return Ok(());
                    }
                }

                match download_with_retry(
                    &client,
                    &hash,
                    &output_dir,
                    &reports_dir,
                    download_files,
                    download_reports,
                    &args_clone,
                )
                .await
                {
                    Ok((file_size, report_saved)) => {
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
                                truncate_hash(&hash, 16),
                                size_msg,
                                report_msg
                            );
                        }

                        if let Some(progress) = progress {
                            progress.inc(1);
                        }
                        Ok(())
                    }
                    Err(e) => {
                        failed.fetch_add(1, Ordering::SeqCst);
                        let error_msg = handle_vt_error(&e);

                        if verbose {
                            eprintln!("  ✗ {} failed: {}", truncate_hash(&hash, 16), error_msg);
                        } else {
                            eprintln!("Failed {}: {}", truncate_hash(&hash, 16), error_msg);
                        }

                        if let Some(progress) = progress {
                            progress.inc(1);
                        }

                        if args.skip_errors {
                            Ok(())
                        } else {
                            Err(anyhow::anyhow!(
                                "Failed to download {}: {}",
                                hash,
                                error_msg
                            ))
                        }
                    }
                }
            }
        })
        .buffer_unordered(concurrency)
        .collect()
        .await;

    if let Some(progress) = progress {
        progress.finish_with_message("Download completed");
    }

    // Check for errors if not skipping
    if !args.skip_errors {
        for result in results {
            if let Err(e) = result {
                eprintln!("\nStopping due to error: {}", e);
                eprintln!("Use --skip-errors to continue on failures.");
                return Err(e);
            }
        }
    }

    // Print summary
    let successful_count = successful.load(Ordering::SeqCst);
    let failed_count = failed.load(Ordering::SeqCst);
    let skipped_count = skipped.load(Ordering::SeqCst);
    let total_bytes = total_size.load(Ordering::SeqCst);

    match args.format.as_str() {
        "json" => {
            let summary = serde_json::json!({
                "total": hashes.len(),
                "successful": successful_count,
                "failed": failed_count,
                "skipped": skipped_count,
                "total_size": total_bytes,
                "total_size_formatted": format_file_size(total_bytes as u64),
                "output_directory": args.output,
                "reports_directory": if download_reports { Some(&args.reports_dir) } else { None }
            });
            println!("{}", serde_json::to_string_pretty(&summary)?);
        }
        _ => {
            println!("\n=== Download Summary ===");
            println!("Total hashes:     {}", hashes.len());
            println!("Successfully downloaded: {}", successful_count);
            println!("Failed:          {}", failed_count);
            if skipped_count > 0 {
                println!("Skipped (resume): {}", skipped_count);
            }
            if total_bytes > 0 {
                println!("Total size:      {}", format_file_size(total_bytes as u64));
            }

            if successful_count > 0 {
                if download_files {
                    println!("Files saved to:  {}", args.output.display());
                }
                if download_reports {
                    println!("Reports saved to: {}", args.reports_dir.display());
                }
            }
        }
    }

    Ok(())
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
    const BASE_DELAY: Duration = Duration::from_secs(1);

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
                // Enhanced error categorization for retries
                let should_retry = match &e {
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
                };

                if should_retry && attempt < MAX_RETRIES - 1 {
                    // Enhanced backoff strategy
                    let delay = match &e {
                        crate::Error::TooManyRequests => {
                            // Longer delay for rate limits
                            Duration::from_secs(60 * (attempt + 1) as u64)
                        }
                        crate::Error::Http(http_err)
                            if http_err.to_string().contains("timeout") =>
                        {
                            // Shorter delay for timeouts
                            BASE_DELAY * (attempt + 1)
                        }
                        _ => {
                            // Exponential backoff for other errors
                            BASE_DELAY * 2_u32.pow(attempt)
                        }
                    };

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

async fn download_file_and_report(
    client: &Client,
    hash: &str,
    output_dir: &Path,
    reports_dir: &Path,
    download_files: bool,
    download_reports: bool,
    args: &DownloadArgs,
) -> Result<(usize, bool), crate::Error> {
    let mut file_size = 0;
    let mut report_saved = false;

    // Get file info first to apply filters and check downloadability
    let file_info = if download_reports || !download_files {
        Some(client.files().get(hash).await?)
    } else {
        None
    };

    // Apply filters if file info is available
    if let Some(ref info) = file_info {
        let attributes = &info.object.attributes;

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
    }

    // Download file if requested
    if download_files {
        let is_downloadable = file_info
            .as_ref()
            .and_then(|info| info.object.attributes.downloadable)
            .unwrap_or(true);

        if is_downloadable {
            match client.files().download(hash).await {
                Ok(file_bytes) => {
                    file_size = file_bytes.len();
                    let filename = format!("{}.bin", hash);
                    let output_path = output_dir.join(&filename);

                    tokio::fs::write(&output_path, file_bytes)
                        .await
                        .map_err(|e| {
                            crate::Error::Unknown(format!("Failed to write file: {}", e))
                        })?;
                }
                Err(e) => return Err(e),
            }
        } else {
            return Err(crate::Error::Unknown("File not downloadable".to_string()));
        }
    }

    // Save report if requested
    if download_reports {
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

        report_saved = true;
    }

    Ok((file_size, report_saved))
}

/// Auto-detect API tier and determine optimal concurrency
async fn detect_tier_and_concurrency(
    client: &Client,
    manual_tier: &str,
    manual_concurrency: Option<usize>,
    verbose: bool,
) -> Result<(ApiTier, usize)> {
    // If user manually specified tier and concurrency, respect their choice
    if let Some(concurrency_val) = manual_concurrency {
        if manual_tier.to_lowercase() != "public" {
            let api_tier = match manual_tier.to_lowercase().as_str() {
                "premium" | "private" => ApiTier::Premium,
                _ => ApiTier::Public,
            };
            let concurrency = match api_tier {
                ApiTier::Premium => concurrency_val.clamp(1, 200), // Allow up to 200 for premium
                ApiTier::Public => 1, // Public is always sequential
            };
            return Ok((api_tier, concurrency));
        }
    }

    // Try to auto-detect tier by querying user info
    if verbose {
        println!("🔍 Auto-detecting API tier and optimal concurrency...");
    }

    match client.users().get_user(client.api_key()).await {
        Ok(user_response) => {
            let user = &user_response.data;

            // Check for premium features to determine tier
            let is_premium = user
                .attributes
                .privileges
                .as_ref()
                .map(|p| {
                    p.download_file.unwrap_or(false)
                        || p.intelligence.unwrap_or(false)
                        || p.private_scanning.unwrap_or(false)
                })
                .unwrap_or(false);

            // Check quotas to determine tier
            let has_high_quota = user
                .attributes
                .quotas
                .as_ref()
                .and_then(|q| q.api_requests_monthly.as_ref())
                .map(|monthly| monthly.allowed > 15000) // Public tier is typically 15k/month
                .unwrap_or(false);

            let api_tier = if is_premium || has_high_quota {
                ApiTier::Premium
            } else {
                ApiTier::Public
            };

            // Determine optimal concurrency
            let optimal_concurrency = if let Some(manual) = manual_concurrency {
                // User specified concurrency manually
                match api_tier {
                    ApiTier::Premium => manual.clamp(1, 200),
                    ApiTier::Public => 1,
                }
            } else {
                // Auto-select based on tier and quotas
                match api_tier {
                    ApiTier::Premium => {
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
                    }
                    ApiTier::Public => 1, // Public is always sequential
                }
            };

            if verbose {
                let tier_name = match api_tier {
                    ApiTier::Premium => "Premium",
                    ApiTier::Public => "Public",
                };

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

                if optimal_concurrency > 1 {
                    println!(
                        "🚀 Using {} concurrent downloads for optimal performance",
                        optimal_concurrency
                    );
                } else {
                    println!("🔄 Using sequential downloads (public tier)");
                }
            }

            Ok((api_tier, optimal_concurrency))
        }
        Err(_) => {
            // Fallback to manual tier detection if user API call fails
            if verbose {
                println!("⚠️  Failed to auto-detect tier, falling back to manual specification");
            }

            let api_tier = match manual_tier.to_lowercase().as_str() {
                "premium" | "private" => ApiTier::Premium,
                _ => ApiTier::Public,
            };

            let concurrency = match (api_tier, manual_concurrency) {
                (ApiTier::Premium, Some(c)) => c.clamp(1, 200),
                (ApiTier::Premium, None) => 20, // Conservative default for premium
                (ApiTier::Public, _) => 1,      // Public is always sequential
            };

            Ok((api_tier, concurrency))
        }
    }
}
