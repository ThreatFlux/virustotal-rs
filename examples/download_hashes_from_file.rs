use clap::Parser;
use futures::stream::{self, StreamExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use tokio::fs;
use virustotal_rs::{ApiKey, ApiTier, Client};

#[derive(Parser, Debug)]
#[command(name = "vt-download")]
#[command(about = "Download files from VirusTotal using hashes from a text file")]
struct Args {
    /// Path to text file containing hashes (one per line)
    #[arg(short, long)]
    input: PathBuf,

    /// Output directory for downloaded files
    #[arg(short, long, default_value = "./downloads")]
    output: PathBuf,

    /// API key (can also be set via VTI_API_KEY environment variable)
    #[arg(short = 'k', long)]
    api_key: Option<String>,

    /// API tier (public or premium)
    #[arg(short = 't', long, default_value = "public")]
    tier: String,

    /// Number of concurrent downloads (only for premium tier, default: 5)
    #[arg(short = 'c', long, default_value = "5")]
    concurrency: usize,

    /// Download and save JSON analysis reports
    #[arg(short = 'r', long)]
    reports: bool,

    /// Only download reports, skip binary file downloads
    #[arg(long)]
    reports_only: bool,

    /// Directory for JSON reports (default: ./reports)
    #[arg(long, default_value = "./reports")]
    reports_dir: PathBuf,

    /// Skip hashes that fail to download instead of stopping
    #[arg(short, long)]
    skip_errors: bool,

    /// Verbose output
    #[arg(short, long)]
    verbose: bool,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    // Get API key from args or environment variable
    let api_key_str = args
        .api_key
        .or_else(|| std::env::var("VTI_API_KEY").ok())
        .ok_or("API key required: use --api-key or set VTI_API_KEY environment variable")?;

    let api_key = ApiKey::new(api_key_str);

    // Parse API tier
    let api_tier = match args.tier.to_lowercase().as_str() {
        "premium" | "private" => ApiTier::Premium,
        _ => ApiTier::Public,
    };

    // Create client
    let client = Client::new(api_key, api_tier)?;

    // Read hashes from file
    let content = fs::read_to_string(&args.input).await?;
    let hashes: Vec<String> = content
        .lines()
        .map(|line| line.trim())
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .map(String::from)
        .collect();

    if hashes.is_empty() {
        eprintln!("No valid hashes found in {}", args.input.display());
        return Ok(());
    }

    println!("Found {} hashes to process", hashes.len());

    // Set reports flag based on reports_only
    let save_reports = args.reports || args.reports_only;

    // Create output directory if downloading files
    if !args.reports_only {
        fs::create_dir_all(&args.output).await?;
    }

    // Create reports directory if reports are requested
    if save_reports {
        fs::create_dir_all(&args.reports_dir).await?;
        if args.verbose {
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

    // Determine concurrency level based on tier
    let concurrency = if api_tier == ApiTier::Premium {
        args.concurrency.clamp(1, 20) // Cap at 20 concurrent downloads for safety
    } else {
        1 // Public tier should use sequential downloads due to rate limits
    };

    if args.verbose && concurrency > 1 {
        println!("Using {} concurrent downloads (premium tier)", concurrency);
    }

    // Shared counters for progress tracking
    let successful = Arc::new(AtomicUsize::new(0));
    let failed = Arc::new(AtomicUsize::new(0));
    let processed = Arc::new(AtomicUsize::new(0));

    let total = hashes.len();
    let client = Arc::new(client);
    let output_dir = Arc::new(args.output.clone());
    let reports_dir = Arc::new(args.reports_dir.clone());
    let reports_only = args.reports_only;

    // Process hashes concurrently with controlled parallelism
    let results: Vec<_> = stream::iter(hashes.iter().enumerate())
        .map(|(_index, hash)| {
            let client = Arc::clone(&client);
            let output_dir = Arc::clone(&output_dir);
            let reports_dir = Arc::clone(&reports_dir);
            let successful = Arc::clone(&successful);
            let failed = Arc::clone(&failed);
            let processed = Arc::clone(&processed);
            let hash = hash.clone();
            let verbose = args.verbose;
            let skip_errors = args.skip_errors;

            async move {
                let current = processed.fetch_add(1, Ordering::SeqCst) + 1;
                let progress = format!("[{}/{}]", current, total);

                if verbose {
                    println!("{} Downloading hash: {}", progress, hash);
                } else {
                    println!("{} Processing {}...", progress, &hash[..16.min(hash.len())]);
                }

                match download_file_and_report(
                    &client,
                    &hash,
                    &output_dir,
                    &reports_dir,
                    save_reports,
                    reports_only,
                )
                .await
                {
                    Ok((filename, report_saved)) => {
                        successful.fetch_add(1, Ordering::SeqCst);
                        if verbose {
                            let report_msg = if report_saved { " (with report)" } else { "" };
                            println!(
                                "  ✓ {} saved as: {}{}",
                                &hash[..16.min(hash.len())],
                                filename,
                                report_msg
                            );
                        } else {
                            println!("  ✓ {} downloaded", &hash[..16.min(hash.len())]);
                        }
                        Ok(())
                    }
                    Err(e) => {
                        failed.fetch_add(1, Ordering::SeqCst);
                        if verbose {
                            eprintln!("  ✗ Failed to download {}: {}", hash, e);
                        } else {
                            eprintln!("  ✗ {} failed: {}", &hash[..16.min(hash.len())], e);
                        }

                        if !skip_errors {
                            Err(format!("Failed to download {}: {}", hash, e))
                        } else {
                            Ok(())
                        }
                    }
                }
            }
        })
        .buffer_unordered(concurrency)
        .collect()
        .await;

    // Check if we should exit due to errors
    if !args.skip_errors {
        for result in results {
            if let Err(e) = result {
                eprintln!("\nStopping due to error: {}", e);
                eprintln!("Use --skip-errors to continue on failures.");
                break;
            }
        }
    }

    let successful = successful.load(Ordering::SeqCst);
    let failed = failed.load(Ordering::SeqCst);

    // Print summary
    println!("\n=== Summary ===");
    println!("Total: {}", hashes.len());
    println!("Downloaded: {}", successful);
    println!("Failed: {}", failed);

    if successful > 0 {
        println!("Files saved to: {}", args.output.display());
    }

    Ok(())
}

async fn download_file_and_report(
    client: &Client,
    hash: &str,
    output_dir: &Path,
    reports_dir: &Path,
    save_report: bool,
    reports_only: bool,
) -> Result<(String, bool), Box<dyn std::error::Error>> {
    let mut file_downloaded = false;
    let mut report_saved = false;
    let filename = format!("{}.bin", hash);

    // First, try to get file info to check if it's downloadable
    let file_info = if save_report || reports_only {
        match client.files().get(hash).await {
            Ok(info) => Some(info),
            Err(e) => {
                // If we can't even get file info, fail completely
                return Err(format!("Failed to get file info: {}", e).into());
            }
        }
    } else {
        None
    };

    // Check if file is downloadable (if we have the info)
    let is_downloadable = file_info
        .as_ref()
        .and_then(|info| info.object.attributes.downloadable)
        .unwrap_or(true); // Assume downloadable if we don't have info

    // Try to download the file if it's downloadable and not reports_only mode
    if !reports_only && is_downloadable {
        match client.files().download(hash).await {
            Ok(file_bytes) => {
                // Save file to disk
                let output_path = output_dir.join(&filename);
                match fs::write(&output_path, file_bytes).await {
                    Ok(_) => {
                        file_downloaded = true;
                    }
                    Err(e) => {
                        eprintln!("Warning: Failed to write file {}: {}", hash, e);
                    }
                }
            }
            Err(e) => {
                // Handle specific error cases
                let error_msg = e.to_string();
                if error_msg.contains("HTTP 403") || error_msg.contains("HTTP 401") {
                    eprintln!(
                        "Warning: File {} requires special permissions to download",
                        hash
                    );
                } else if error_msg.contains("HTTP 404") {
                    eprintln!("Warning: File {} not found or no longer available", hash);
                } else if error_msg.contains("error decoding response body")
                    || error_msg.contains("HTTP 502")
                    || error_msg.contains("HTTP 503")
                {
                    eprintln!(
                        "Warning: File {} temporarily unavailable (server error)",
                        hash
                    );
                } else if error_msg.contains("HTTP 400") {
                    eprintln!(
                        "Warning: Invalid request for file {} (possibly too large)",
                        hash
                    );
                } else {
                    eprintln!("Warning: Failed to download file {}: {}", hash, error_msg);
                }
            }
        }
    } else if !reports_only && !is_downloadable {
        eprintln!(
            "Warning: File {} is not downloadable (may be too large or restricted)",
            hash
        );
    }

    // Save report if requested (even if file download failed)
    if save_report {
        if let Some(file_info) = file_info {
            // Serialize the file info as pretty JSON
            let json_report =
                serde_json::to_string_pretty(&file_info).unwrap_or_else(|_| "{}".to_string());

            // Save report with hash as filename
            let report_filename = format!("{}.json", hash);
            let report_path = reports_dir.join(&report_filename);

            match fs::write(&report_path, json_report).await {
                Ok(_) => report_saved = true,
                Err(e) => {
                    eprintln!("Warning: Failed to save report for {}: {}", hash, e);
                }
            }
        } else {
            // Try to fetch report if we didn't already
            match client.files().get(hash).await {
                Ok(file_info) => {
                    let json_report = serde_json::to_string_pretty(&file_info)
                        .unwrap_or_else(|_| "{}".to_string());

                    let report_filename = format!("{}.json", hash);
                    let report_path = reports_dir.join(&report_filename);

                    match fs::write(&report_path, json_report).await {
                        Ok(_) => report_saved = true,
                        Err(e) => {
                            eprintln!("Warning: Failed to save report for {}: {}", hash, e);
                        }
                    }
                }
                Err(e) => {
                    eprintln!("Warning: Failed to fetch report for {}: {}", hash, e);
                }
            }
        }
    }

    // Return success if either file was downloaded OR report was saved
    if file_downloaded || report_saved {
        Ok((filename, report_saved))
    } else {
        Err(format!("Failed to download file or report for {}", hash).into())
    }
}
