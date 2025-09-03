use chrono::Utc;
use clap::Parser;
use elasticsearch::{http::transport::Transport, BulkParts, Elasticsearch};
use futures::stream::{self, StreamExt};
use serde_json::{json, Map, Value};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use tokio::fs;
use uuid::Uuid;
use virustotal_rs::{ApiKey, ApiTier, Client};

#[derive(Parser, Debug)]
#[command(name = "vt-es-indexer")]
#[command(
    about = "Index VirusTotal analysis reports into Elasticsearch with hierarchical structure"
)]
struct Args {
    /// Path to directory containing JSON analysis reports or text file with hashes (one per line)
    #[arg(short, long)]
    input: PathBuf,

    /// Elasticsearch URL
    #[arg(long, default_value = "http://localhost:9200")]
    es_url: String,

    /// Enable indexing to Elasticsearch
    #[arg(long)]
    index: bool,

    /// API key (can also be set via VTI_API_KEY environment variable)
    #[arg(short = 'k', long)]
    api_key: Option<String>,

    /// API tier (public or premium)
    #[arg(short = 't', long, default_value = "public")]
    tier: String,

    /// Number of concurrent downloads (only for premium tier, default: 5)
    #[arg(short = 'c', long, default_value = "5")]
    concurrency: usize,

    /// Directory for JSON reports (default: ./reports)
    #[arg(long, default_value = "./reports")]
    reports_dir: PathBuf,

    /// Skip errors and continue processing
    #[arg(short, long)]
    skip_errors: bool,

    /// Verbose output
    #[arg(short, long)]
    verbose: bool,

    /// Batch size for Elasticsearch bulk operations
    #[arg(long, default_value = "100")]
    batch_size: usize,
}

#[derive(Debug)]
struct IndexedDocument {
    index: String,
    id: String,
    body: Value,
}

#[derive(Debug)]
#[allow(dead_code)]
struct ProcessedReport {
    report_uuid: String,
    file_hash: String,
    documents: Vec<IndexedDocument>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    if !args.index {
        println!("Indexing is disabled. Use --index to enable Elasticsearch indexing.");
        return Ok(());
    }

    // Initialize Elasticsearch client
    let transport = Transport::single_node(&args.es_url)?;
    let es_client = Elasticsearch::new(transport);

    // Test Elasticsearch connection
    match es_client.ping().send().await {
        Ok(_) => {
            if args.verbose {
                println!("✓ Connected to Elasticsearch at {}", args.es_url);
            }
        }
        Err(e) => {
            eprintln!(
                "Failed to connect to Elasticsearch at {}: {}",
                args.es_url, e
            );
            return Err(e.into());
        }
    }

    // Determine if input is a directory with JSON files or a text file with hashes
    let processed_reports = if args.input.is_dir() {
        // Process existing JSON files
        process_json_directory(&args.input, &args).await?
    } else {
        // Download reports from hashes and process them
        download_and_process_hashes(&args).await?
    };

    if processed_reports.is_empty() {
        println!("No reports to process.");
        return Ok(());
    }

    println!("Found {} reports to index", processed_reports.len());

    // Create Elasticsearch indexes
    create_elasticsearch_indexes(&es_client, &args).await?;

    // Index documents in batches
    index_documents_bulk(&es_client, processed_reports, &args).await?;

    println!("✓ Indexing completed successfully");

    Ok(())
}

async fn process_json_directory(
    directory: &Path,
    args: &Args,
) -> Result<Vec<ProcessedReport>, Box<dyn std::error::Error>> {
    let mut reports = Vec::new();
    let mut entries = fs::read_dir(directory).await?;

    while let Some(entry) = entries.next_entry().await? {
        let path = entry.path();
        if path.extension().is_some_and(|ext| ext == "json") {
            if let Some(file_name) = path.file_stem().and_then(|n| n.to_str()) {
                if args.verbose {
                    println!("Processing {}", path.display());
                }

                let content = fs::read_to_string(&path).await?;
                match serde_json::from_str::<Value>(&content) {
                    Ok(json_data) => {
                        let report = process_vt_report(file_name, &json_data, args)?;
                        reports.push(report);
                    }
                    Err(e) => {
                        if args.skip_errors {
                            eprintln!("Warning: Failed to parse {}: {}", path.display(), e);
                        } else {
                            return Err(format!("Failed to parse {}: {}", path.display(), e).into());
                        }
                    }
                }
            }
        }
    }

    Ok(reports)
}

async fn download_and_process_hashes(
    args: &Args,
) -> Result<Vec<ProcessedReport>, Box<dyn std::error::Error>> {
    let api_key_str = args
        .api_key
        .clone()
        .or_else(|| std::env::var("VTI_API_KEY").ok())
        .ok_or("API key required: use --api-key or set VTI_API_KEY environment variable")?;

    let api_key = ApiKey::new(api_key_str.clone());
    let api_tier = match args.tier.to_lowercase().as_str() {
        "premium" | "private" => ApiTier::Premium,
        _ => ApiTier::Public,
    };

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
        return Ok(Vec::new());
    }

    println!("Found {} hashes to download and process", hashes.len());

    // Create reports directory
    fs::create_dir_all(&args.reports_dir).await?;

    let concurrency = if api_tier == ApiTier::Premium {
        args.concurrency.clamp(1, 20)
    } else {
        1
    };

    let processed = Arc::new(AtomicUsize::new(0));
    let total = hashes.len();
    let client = Arc::new(client);
    let reports_dir = Arc::new(args.reports_dir.clone());

    // Process hashes concurrently
    let results: Vec<_> = stream::iter(hashes.iter().enumerate())
        .map(|(_index, hash)| {
            let client = Arc::clone(&client);
            let reports_dir = Arc::clone(&reports_dir);
            let processed = Arc::clone(&processed);
            let hash = hash.clone();
            let verbose = args.verbose;
            let skip_errors = args.skip_errors;

            async move {
                let current = processed.fetch_add(1, Ordering::SeqCst) + 1;
                let progress = format!("[{}/{}]", current, total);

                if verbose {
                    println!("{} Downloading analysis for hash: {}", progress, hash);
                } else {
                    println!("{} Processing {}...", progress, &hash[..16.min(hash.len())]);
                }

                match client.files().get(&hash).await {
                    Ok(file_info) => {
                        // Save report to disk
                        let json_report = serde_json::to_string_pretty(&file_info)
                            .unwrap_or_else(|_| "{}".to_string());
                        let report_filename = format!("{}.json", hash);
                        let report_path = reports_dir.join(&report_filename);

                        if let Err(e) = fs::write(&report_path, &json_report).await {
                            eprintln!("Warning: Failed to save report for {}: {}", hash, e);
                        }

                        // Convert to JSON Value for processing
                        let file_info_json = serde_json::to_value(&file_info)?;

                        // Process the report
                        match process_vt_report(&hash, &file_info_json, args) {
                            Ok(report) => Ok(Some(report)),
                            Err(e) => {
                                if skip_errors {
                                    eprintln!("Warning: Failed to process {}: {}", hash, e);
                                    Ok(None)
                                } else {
                                    Err(e)
                                }
                            }
                        }
                    }
                    Err(e) => {
                        if skip_errors {
                            eprintln!("Warning: Failed to download {}: {}", hash, e);
                            Ok(None)
                        } else {
                            Err(format!("Failed to download {}: {}", hash, e).into())
                        }
                    }
                }
            }
        })
        .buffer_unordered(concurrency)
        .collect()
        .await;

    let mut reports = Vec::new();
    for result in results {
        match result {
            Ok(Some(report)) => reports.push(report),
            Ok(None) => {} // Skipped due to error
            Err(e) => {
                if !args.skip_errors {
                    return Err(e);
                }
            }
        }
    }

    Ok(reports)
}

fn process_vt_report(
    file_hash: &str,
    json_data: &Value,
    args: &Args,
) -> Result<ProcessedReport, Box<dyn std::error::Error>> {
    let report_uuid = Uuid::new_v4().to_string();
    let mut documents = Vec::new();

    // Extract attributes from the JSON
    let attributes = json_data
        .get("attributes")
        .ok_or("Missing attributes in VT report")?;

    // Main report document
    let mut main_report = Map::new();
    main_report.insert(
        "report_uuid".to_string(),
        Value::String(report_uuid.clone()),
    );
    main_report.insert(
        "file_hash".to_string(),
        Value::String(file_hash.to_string()),
    );
    main_report.insert(
        "file_id".to_string(),
        json_data
            .get("id")
            .cloned()
            .unwrap_or(Value::String(file_hash.to_string())),
    );
    main_report.insert(
        "file_type".to_string(),
        json_data
            .get("type")
            .cloned()
            .unwrap_or(Value::String("file".to_string())),
    );

    // Add index timestamp
    main_report.insert(
        "index_time".to_string(),
        Value::String(Utc::now().to_rfc3339()),
    );

    // Add basic file information
    if let Some(sha256) = attributes.get("sha256") {
        main_report.insert("sha256".to_string(), sha256.clone());
    }
    if let Some(sha1) = attributes.get("sha1") {
        main_report.insert("sha1".to_string(), sha1.clone());
    }
    if let Some(md5) = attributes.get("md5") {
        main_report.insert("md5".to_string(), md5.clone());
    }

    // Add similarity hashes
    if let Some(vhash) = attributes.get("vhash") {
        main_report.insert("vhash".to_string(), vhash.clone());
    }
    if let Some(tlsh) = attributes.get("tlsh") {
        main_report.insert("tlsh".to_string(), tlsh.clone());
    }
    if let Some(ssdeep) = attributes.get("ssdeep") {
        main_report.insert("ssdeep".to_string(), ssdeep.clone());
    }

    // Add file analysis details
    if let Some(magic) = attributes.get("magic") {
        main_report.insert("magic".to_string(), magic.clone());
    }
    if let Some(trid) = attributes.get("trid") {
        main_report.insert("trid".to_string(), trid.clone());
    }
    if let Some(exiftool) = attributes.get("exiftool") {
        main_report.insert("exiftool".to_string(), exiftool.clone());
    }
    if let Some(office_info) = attributes.get("office_info") {
        main_report.insert("office_info".to_string(), office_info.clone());
    }

    // Add file metadata
    if let Some(size) = attributes.get("size") {
        main_report.insert("size".to_string(), size.clone());
    }
    if let Some(names) = attributes.get("names") {
        main_report.insert("names".to_string(), names.clone());
    }
    if let Some(meaningful_name) = attributes.get("meaningful_name") {
        main_report.insert("meaningful_name".to_string(), meaningful_name.clone());
    }
    if let Some(type_description) = attributes.get("type_description") {
        main_report.insert("type_description".to_string(), type_description.clone());
    }
    if let Some(type_tag) = attributes.get("type_tag") {
        main_report.insert("type_tag".to_string(), type_tag.clone());
    }
    if let Some(type_extension) = attributes.get("type_extension") {
        main_report.insert("type_extension".to_string(), type_extension.clone());
    }

    // Add submission dates
    if let Some(first_submission_date) = attributes.get("first_submission_date") {
        main_report.insert(
            "first_submission_date".to_string(),
            first_submission_date.clone(),
        );
    }
    if let Some(last_submission_date) = attributes.get("last_submission_date") {
        main_report.insert(
            "last_submission_date".to_string(),
            last_submission_date.clone(),
        );
    }
    if let Some(last_analysis_date) = attributes.get("last_analysis_date") {
        main_report.insert("last_analysis_date".to_string(), last_analysis_date.clone());
    }
    if let Some(last_modification_date) = attributes.get("last_modification_date") {
        main_report.insert(
            "last_modification_date".to_string(),
            last_modification_date.clone(),
        );
    }

    // Add threat intelligence
    if let Some(times_submitted) = attributes.get("times_submitted") {
        main_report.insert("times_submitted".to_string(), times_submitted.clone());
    }
    if let Some(unique_sources) = attributes.get("unique_sources") {
        main_report.insert("unique_sources".to_string(), unique_sources.clone());
    }
    if let Some(reputation) = attributes.get("reputation") {
        main_report.insert("reputation".to_string(), reputation.clone());
    }
    if let Some(tags) = attributes.get("tags") {
        main_report.insert("tags".to_string(), tags.clone());
    }
    if let Some(total_votes) = attributes.get("total_votes") {
        main_report.insert("total_votes".to_string(), total_votes.clone());
    }
    if let Some(threat_severity) = attributes.get("threat_severity") {
        main_report.insert("threat_severity".to_string(), threat_severity.clone());
    }

    // Add analysis stats
    if let Some(last_analysis_stats) = attributes.get("last_analysis_stats") {
        main_report.insert(
            "last_analysis_stats".to_string(),
            last_analysis_stats.clone(),
        );
    }

    // Add special analysis fields
    if let Some(pe_info) = attributes.get("pe_info") {
        main_report.insert("pe_info".to_string(), pe_info.clone());
    }
    if let Some(androguard) = attributes.get("androguard") {
        main_report.insert("androguard".to_string(), androguard.clone());
    }
    if let Some(bundle_info) = attributes.get("bundle_info") {
        main_report.insert("bundle_info".to_string(), bundle_info.clone());
    }
    if let Some(pdf_info) = attributes.get("pdf_info") {
        main_report.insert("pdf_info".to_string(), pdf_info.clone());
    }
    if let Some(sigma_analysis_summary) = attributes.get("sigma_analysis_summary") {
        main_report.insert(
            "sigma_analysis_summary".to_string(),
            sigma_analysis_summary.clone(),
        );
    }
    if let Some(sigma_analysis_results) = attributes.get("sigma_analysis_results") {
        main_report.insert(
            "sigma_analysis_results".to_string(),
            sigma_analysis_results.clone(),
        );
    }
    if let Some(network_infrastructure) = attributes.get("network_infrastructure") {
        main_report.insert(
            "network_infrastructure".to_string(),
            network_infrastructure.clone(),
        );
    }
    if let Some(dot_net_assembly) = attributes.get("dot_net_assembly") {
        main_report.insert("dot_net_assembly".to_string(), dot_net_assembly.clone());
    }
    if let Some(macho_info) = attributes.get("macho_info") {
        main_report.insert("macho_info".to_string(), macho_info.clone());
    }
    if let Some(powershell_info) = attributes.get("powershell_info") {
        main_report.insert("powershell_info".to_string(), powershell_info.clone());
    }
    if let Some(signature_info) = attributes.get("signature_info") {
        main_report.insert("signature_info".to_string(), signature_info.clone());
    }
    if let Some(packers) = attributes.get("packers") {
        main_report.insert("packers".to_string(), packers.clone());
    }
    if let Some(detectiteasy) = attributes.get("detectiteasy") {
        main_report.insert("detectiteasy".to_string(), detectiteasy.clone());
    }
    if let Some(magika) = attributes.get("magika") {
        main_report.insert("magika".to_string(), magika.clone());
    }
    if let Some(bytehero_info) = attributes.get("bytehero_info") {
        main_report.insert("bytehero_info".to_string(), bytehero_info.clone());
    }
    if let Some(popular_threat_classification) = attributes.get("popular_threat_classification") {
        main_report.insert(
            "popular_threat_classification".to_string(),
            popular_threat_classification.clone(),
        );
    }
    if let Some(crowdsourced_ids_results) = attributes.get("crowdsourced_ids_results") {
        main_report.insert(
            "crowdsourced_ids_results".to_string(),
            crowdsourced_ids_results.clone(),
        );
    }
    if let Some(type_tags) = attributes.get("type_tags") {
        main_report.insert("type_tags".to_string(), type_tags.clone());
    }
    if let Some(permhash) = attributes.get("permhash") {
        main_report.insert("permhash".to_string(), permhash.clone());
    }
    if let Some(symhash) = attributes.get("symhash") {
        main_report.insert("symhash".to_string(), symhash.clone());
    }
    if let Some(first_seen_itw_date) = attributes.get("first_seen_itw_date") {
        main_report.insert(
            "first_seen_itw_date".to_string(),
            first_seen_itw_date.clone(),
        );
    }
    if let Some(last_seen_itw_date) = attributes.get("last_seen_itw_date") {
        main_report.insert("last_seen_itw_date".to_string(), last_seen_itw_date.clone());
    }
    if let Some(creation_date) = attributes.get("creation_date") {
        main_report.insert("creation_date".to_string(), creation_date.clone());
    }
    if let Some(downloadable) = attributes.get("downloadable") {
        main_report.insert("downloadable".to_string(), downloadable.clone());
    }
    if let Some(available_tools) = attributes.get("available_tools") {
        main_report.insert("available_tools".to_string(), available_tools.clone());
    }

    documents.push(IndexedDocument {
        index: "vt_reports".to_string(),
        id: report_uuid.clone(),
        body: Value::Object(main_report),
    });

    // Process last_analysis_results (antivirus scan results)
    if let Some(analysis_results) = attributes
        .get("last_analysis_results")
        .and_then(|v| v.as_object())
    {
        for (engine_name, engine_result) in analysis_results {
            if let Some(engine_data) = engine_result.as_object() {
                let mut analysis_doc = Map::new();
                analysis_doc.insert(
                    "report_uuid".to_string(),
                    Value::String(report_uuid.clone()),
                );
                analysis_doc.insert(
                    "file_hash".to_string(),
                    Value::String(file_hash.to_string()),
                );
                analysis_doc.insert(
                    "engine_name".to_string(),
                    Value::String(engine_name.clone()),
                );
                analysis_doc.insert(
                    "index_time".to_string(),
                    Value::String(Utc::now().to_rfc3339()),
                );

                for (key, value) in engine_data {
                    analysis_doc.insert(key.clone(), value.clone());
                }

                documents.push(IndexedDocument {
                    index: "vt_analysis_results".to_string(),
                    id: format!("{}_{}", report_uuid, engine_name),
                    body: Value::Object(analysis_doc),
                });
            }
        }
    }

    // Process sandbox verdicts if available
    if let Some(sandbox_verdicts) = attributes
        .get("sandbox_verdicts")
        .and_then(|v| v.as_object())
    {
        for (sandbox_name, verdict) in sandbox_verdicts {
            let mut sandbox_doc = Map::new();
            sandbox_doc.insert(
                "report_uuid".to_string(),
                Value::String(report_uuid.clone()),
            );
            sandbox_doc.insert(
                "file_hash".to_string(),
                Value::String(file_hash.to_string()),
            );
            sandbox_doc.insert(
                "sandbox_name".to_string(),
                Value::String(sandbox_name.clone()),
            );
            sandbox_doc.insert(
                "index_time".to_string(),
                Value::String(Utc::now().to_rfc3339()),
            );
            sandbox_doc.insert("verdict".to_string(), verdict.clone());

            documents.push(IndexedDocument {
                index: "vt_sandbox_verdicts".to_string(),
                id: format!("{}_{}", report_uuid, sandbox_name),
                body: Value::Object(sandbox_doc),
            });
        }
    }

    // Process sigma analysis results for behavioral data
    if let Some(sigma_results) = attributes
        .get("sigma_analysis_results")
        .and_then(|v| v.as_array())
    {
        for (index, sigma_result) in sigma_results.iter().enumerate() {
            if let Some(sigma_obj) = sigma_result.as_object() {
                let mut behavior_doc = Map::new();
                behavior_doc.insert(
                    "report_uuid".to_string(),
                    Value::String(report_uuid.clone()),
                );
                behavior_doc.insert(
                    "file_hash".to_string(),
                    Value::String(file_hash.to_string()),
                );
                behavior_doc.insert(
                    "index_time".to_string(),
                    Value::String(Utc::now().to_rfc3339()),
                );
                behavior_doc.insert(
                    "analysis_type".to_string(),
                    Value::String("sigma".to_string()),
                );

                // Extract rule information
                if let Some(rule_id) = sigma_obj.get("rule_id") {
                    behavior_doc.insert("rule_id".to_string(), rule_id.clone());
                }
                if let Some(rule_title) = sigma_obj.get("rule_title") {
                    behavior_doc.insert("rule_title".to_string(), rule_title.clone());
                }
                if let Some(rule_description) = sigma_obj.get("rule_description") {
                    behavior_doc.insert("rule_description".to_string(), rule_description.clone());
                }
                if let Some(rule_level) = sigma_obj.get("rule_level") {
                    behavior_doc.insert("severity".to_string(), rule_level.clone());
                }
                if let Some(rule_author) = sigma_obj.get("rule_author") {
                    behavior_doc.insert("rule_author".to_string(), rule_author.clone());
                }
                if let Some(rule_source) = sigma_obj.get("rule_source") {
                    behavior_doc.insert("rule_source".to_string(), rule_source.clone());
                }

                // Process match data for behavioral details
                if let Some(matches) = sigma_obj.get("rule_matches").and_then(|v| v.as_array()) {
                    let mut behavioral_events = Vec::new();

                    for match_item in matches {
                        if let Some(match_obj) = match_item.as_object() {
                            let mut event = Map::new();

                            // Extract process information
                            if let Some(process_info) = match_obj.get("Process") {
                                event.insert("process_info".to_string(), process_info.clone());

                                // Extract specific process details
                                if let Some(process_obj) = process_info.as_object() {
                                    if let Some(image) = process_obj.get("Image") {
                                        event.insert("process_path".to_string(), image.clone());
                                    }
                                    if let Some(command_line) = process_obj.get("CommandLine") {
                                        event.insert(
                                            "command_line".to_string(),
                                            command_line.clone(),
                                        );
                                    }
                                    if let Some(pid) = process_obj.get("ProcessId") {
                                        event.insert("process_id".to_string(), pid.clone());
                                    }
                                    if let Some(parent_image) = process_obj.get("ParentImage") {
                                        event.insert(
                                            "parent_process".to_string(),
                                            parent_image.clone(),
                                        );
                                    }
                                }
                            }

                            // Extract file operation information
                            if let Some(file_info) = match_obj.get("File") {
                                event.insert("file_info".to_string(), file_info.clone());

                                if let Some(file_obj) = file_info.as_object() {
                                    if let Some(target_filename) = file_obj.get("TargetFilename") {
                                        event.insert(
                                            "target_file".to_string(),
                                            target_filename.clone(),
                                        );
                                    }
                                    if let Some(creation_time) = file_obj.get("CreationUtcTime") {
                                        event.insert(
                                            "file_creation_time".to_string(),
                                            creation_time.clone(),
                                        );
                                    }
                                }
                            }

                            // Extract network information
                            if let Some(network_info) = match_obj.get("Network") {
                                event.insert("network_info".to_string(), network_info.clone());

                                if let Some(network_obj) = network_info.as_object() {
                                    if let Some(dest_ip) = network_obj.get("DestinationIp") {
                                        event.insert("destination_ip".to_string(), dest_ip.clone());
                                    }
                                    if let Some(dest_port) = network_obj.get("DestinationPort") {
                                        event.insert(
                                            "destination_port".to_string(),
                                            dest_port.clone(),
                                        );
                                    }
                                    if let Some(protocol) = network_obj.get("Protocol") {
                                        event.insert("protocol".to_string(), protocol.clone());
                                    }
                                }
                            }

                            // Extract registry information
                            if let Some(registry_info) = match_obj.get("Registry") {
                                event.insert("registry_info".to_string(), registry_info.clone());

                                if let Some(registry_obj) = registry_info.as_object() {
                                    if let Some(target_object) = registry_obj.get("TargetObject") {
                                        event.insert(
                                            "registry_key".to_string(),
                                            target_object.clone(),
                                        );
                                    }
                                    if let Some(details) = registry_obj.get("Details") {
                                        event.insert("registry_value".to_string(), details.clone());
                                    }
                                }
                            }

                            // Extract image loaded information
                            if let Some(image_loaded) = match_obj.get("ImageLoaded") {
                                event.insert("loaded_image".to_string(), image_loaded.clone());
                            }
                            if let Some(signature_status) = match_obj.get("SignatureStatus") {
                                event.insert(
                                    "signature_status".to_string(),
                                    signature_status.clone(),
                                );
                            }
                            if let Some(signed) = match_obj.get("Signed") {
                                event.insert("signed".to_string(), signed.clone());
                            }

                            behavioral_events.push(Value::Object(event));
                        }
                    }

                    behavior_doc.insert(
                        "behavioral_events".to_string(),
                        Value::Array(behavioral_events),
                    );
                    behavior_doc.insert(
                        "event_count".to_string(),
                        Value::Number(matches.len().into()),
                    );
                }

                // Store full sigma result for reference
                behavior_doc.insert("raw_sigma_result".to_string(), sigma_result.clone());

                documents.push(IndexedDocument {
                    index: "vt_sandbox_behaviors".to_string(),
                    id: format!("{}_sigma_{}", report_uuid, index),
                    body: Value::Object(behavior_doc),
                });
            }
        }
    }

    // Process crowdsourced data (YARA rules, IDS, etc.)
    if let Some(crowdsourced_yara_results) = attributes
        .get("crowdsourced_yara_results")
        .and_then(|v| v.as_array())
    {
        for (index, yara_result) in crowdsourced_yara_results.iter().enumerate() {
            let mut yara_doc = Map::new();
            yara_doc.insert(
                "report_uuid".to_string(),
                Value::String(report_uuid.clone()),
            );
            yara_doc.insert(
                "file_hash".to_string(),
                Value::String(file_hash.to_string()),
            );
            yara_doc.insert("data_type".to_string(), Value::String("yara".to_string()));
            yara_doc.insert(
                "index_time".to_string(),
                Value::String(Utc::now().to_rfc3339()),
            );
            yara_doc.insert("data".to_string(), yara_result.clone());

            documents.push(IndexedDocument {
                index: "vt_crowdsourced_data".to_string(),
                id: format!("{}_yara_{}", report_uuid, index),
                body: Value::Object(yara_doc),
            });
        }
    }

    if let Some(crowdsourced_ids_results) = attributes
        .get("crowdsourced_ids_results")
        .and_then(|v| v.as_array())
    {
        for (index, ids_result) in crowdsourced_ids_results.iter().enumerate() {
            let mut ids_doc = Map::new();
            ids_doc.insert(
                "report_uuid".to_string(),
                Value::String(report_uuid.clone()),
            );
            ids_doc.insert(
                "file_hash".to_string(),
                Value::String(file_hash.to_string()),
            );
            ids_doc.insert("data_type".to_string(), Value::String("ids".to_string()));
            ids_doc.insert(
                "index_time".to_string(),
                Value::String(Utc::now().to_rfc3339()),
            );
            ids_doc.insert("data".to_string(), ids_result.clone());

            documents.push(IndexedDocument {
                index: "vt_crowdsourced_data".to_string(),
                id: format!("{}_ids_{}", report_uuid, index),
                body: Value::Object(ids_doc),
            });
        }
    }

    // Process file relationships if available
    if let Some(links) = json_data.get("links") {
        let mut relationships_doc = Map::new();
        relationships_doc.insert(
            "report_uuid".to_string(),
            Value::String(report_uuid.clone()),
        );
        relationships_doc.insert(
            "file_hash".to_string(),
            Value::String(file_hash.to_string()),
        );
        relationships_doc.insert(
            "index_time".to_string(),
            Value::String(Utc::now().to_rfc3339()),
        );
        relationships_doc.insert("links".to_string(), links.clone());

        documents.push(IndexedDocument {
            index: "vt_relationships".to_string(),
            id: format!("{}_links", report_uuid),
            body: Value::Object(relationships_doc),
        });
    }

    if args.verbose {
        println!(
            "  Generated {} documents for hash {}",
            documents.len(),
            &file_hash[..16.min(file_hash.len())]
        );
    }

    Ok(ProcessedReport {
        report_uuid,
        file_hash: file_hash.to_string(),
        documents,
    })
}

async fn create_elasticsearch_indexes(
    client: &Elasticsearch,
    args: &Args,
) -> Result<(), Box<dyn std::error::Error>> {
    let indexes = vec![
        ("vt_reports", get_main_index_mapping()),
        ("vt_analysis_results", get_analysis_results_mapping()),
        ("vt_sandbox_verdicts", get_sandbox_verdicts_mapping()),
        ("vt_sandbox_behaviors", get_sandbox_behaviors_mapping()),
        ("vt_crowdsourced_data", get_crowdsourced_data_mapping()),
        ("vt_relationships", get_relationships_mapping()),
    ];

    for (index_name, mapping) in indexes {
        // Check if index exists
        let response = client
            .indices()
            .exists(elasticsearch::indices::IndicesExistsParts::Index(&[
                index_name,
            ]))
            .send()
            .await;

        match response {
            Ok(response) => {
                if response.status_code().as_u16() == 404 {
                    // Index doesn't exist, create it
                    if args.verbose {
                        println!("Creating index: {}", index_name);
                    }

                    let create_response = client
                        .indices()
                        .create(elasticsearch::indices::IndicesCreateParts::Index(
                            index_name,
                        ))
                        .body(mapping)
                        .send()
                        .await?;

                    if !create_response.status_code().is_success() {
                        return Err(format!(
                            "Failed to create index {}: {}",
                            index_name,
                            create_response.status_code()
                        )
                        .into());
                    }
                } else if args.verbose {
                    println!("Index {} already exists", index_name);
                }
            }
            Err(e) => {
                return Err(
                    format!("Failed to check if index {} exists: {}", index_name, e).into(),
                );
            }
        }
    }

    Ok(())
}

async fn index_documents_bulk(
    client: &Elasticsearch,
    reports: Vec<ProcessedReport>,
    args: &Args,
) -> Result<(), Box<dyn std::error::Error>> {
    let total_docs: usize = reports.iter().map(|r| r.documents.len()).sum();
    println!(
        "Indexing {} documents from {} reports",
        total_docs,
        reports.len()
    );

    // Flatten all documents
    let mut all_documents = Vec::new();
    for report in reports {
        for doc in report.documents {
            all_documents.push(doc);
        }
    }

    // Process in batches
    let mut indexed = 0;
    for batch in all_documents.chunks(args.batch_size) {
        let mut bulk_body = Vec::new();

        for doc in batch {
            // Action header
            let action = serde_json::json!({
                "index": {
                    "_index": doc.index,
                    "_id": doc.id
                }
            });
            bulk_body.push(serde_json::to_string(&action)?);
            bulk_body.push(serde_json::to_string(&doc.body)?);
        }

        let bulk_body_str = bulk_body.join("\n") + "\n";

        let response = client
            .bulk(BulkParts::None)
            .body(vec![bulk_body_str])
            .send()
            .await?;

        if !response.status_code().is_success() {
            return Err(format!("Bulk indexing failed: {}", response.status_code()).into());
        }

        // Check for errors in the response
        let response_body: Value = response.json().await?;
        if let Some(errors) = response_body.get("errors") {
            if errors.as_bool() == Some(true) {
                eprintln!("Some documents failed to index: {}", response_body);
                if !args.skip_errors {
                    return Err("Bulk indexing had errors".into());
                }
            }
        }

        indexed += batch.len();
        if args.verbose {
            println!("Indexed {}/{} documents", indexed, total_docs);
        }
    }

    println!("✓ Successfully indexed {} documents", indexed);
    Ok(())
}

fn get_main_index_mapping() -> Value {
    let mut properties = serde_json::Map::new();

    // Basic fields
    properties.insert("report_uuid".to_string(), json!({"type": "keyword"}));
    properties.insert("file_hash".to_string(), json!({"type": "keyword"}));
    properties.insert("file_id".to_string(), json!({"type": "keyword"}));
    properties.insert("file_type".to_string(), json!({"type": "keyword"}));
    properties.insert("sha256".to_string(), json!({"type": "keyword"}));
    properties.insert("sha1".to_string(), json!({"type": "keyword"}));
    properties.insert("md5".to_string(), json!({"type": "keyword"}));
    properties.insert("vhash".to_string(), json!({"type": "keyword"}));
    properties.insert("tlsh".to_string(), json!({"type": "keyword"}));
    properties.insert("ssdeep".to_string(), json!({"type": "keyword"}));
    properties.insert("permhash".to_string(), json!({"type": "keyword"}));
    properties.insert("symhash".to_string(), json!({"type": "keyword"}));

    // Text fields
    properties.insert("magic".to_string(), json!({"type": "text"}));
    properties.insert("magika".to_string(), json!({"type": "text"}));
    properties.insert("bytehero_info".to_string(), json!({"type": "text"}));
    properties.insert(
        "meaningful_name".to_string(),
        json!({"type": "text", "fields": {"keyword": {"type": "keyword"}}}),
    );
    properties.insert("type_description".to_string(), json!({"type": "text"}));

    // Numeric fields
    properties.insert("size".to_string(), json!({"type": "long"}));
    properties.insert("times_submitted".to_string(), json!({"type": "integer"}));
    properties.insert("unique_sources".to_string(), json!({"type": "integer"}));
    properties.insert("reputation".to_string(), json!({"type": "integer"}));

    // Keyword fields
    properties.insert("names".to_string(), json!({"type": "keyword"}));
    properties.insert("type_tag".to_string(), json!({"type": "keyword"}));
    properties.insert("type_extension".to_string(), json!({"type": "keyword"}));
    properties.insert("tags".to_string(), json!({"type": "keyword"}));
    properties.insert("type_tags".to_string(), json!({"type": "keyword"}));
    properties.insert("available_tools".to_string(), json!({"type": "keyword"}));

    // Date fields
    properties.insert("index_time".to_string(), json!({"type": "date"}));
    properties.insert(
        "first_submission_date".to_string(),
        json!({"type": "date", "format": "epoch_second"}),
    );
    properties.insert(
        "last_submission_date".to_string(),
        json!({"type": "date", "format": "epoch_second"}),
    );
    properties.insert(
        "last_analysis_date".to_string(),
        json!({"type": "date", "format": "epoch_second"}),
    );
    properties.insert(
        "last_modification_date".to_string(),
        json!({"type": "date", "format": "epoch_second"}),
    );
    properties.insert(
        "first_seen_itw_date".to_string(),
        json!({"type": "date", "format": "epoch_second"}),
    );
    properties.insert(
        "last_seen_itw_date".to_string(),
        json!({"type": "date", "format": "epoch_second"}),
    );
    properties.insert(
        "creation_date".to_string(),
        json!({"type": "date", "format": "epoch_second"}),
    );

    // Boolean fields
    properties.insert("downloadable".to_string(), json!({"type": "boolean"}));

    // Nested objects for stats
    properties.insert(
        "last_analysis_stats".to_string(),
        json!({
            "properties": {
                "harmless": {"type": "integer"},
                "malicious": {"type": "integer"},
                "suspicious": {"type": "integer"},
                "undetected": {"type": "integer"},
                "timeout": {"type": "integer"},
                "confirmed-timeout": {"type": "integer"},
                "failure": {"type": "integer"},
                "type-unsupported": {"type": "integer"}
            }
        }),
    );

    properties.insert(
        "total_votes".to_string(),
        json!({
            "properties": {
                "harmless": {"type": "integer"},
                "malicious": {"type": "integer"}
            }
        }),
    );

    // Object fields for complex data
    let object_fields = vec![
        "threat_severity",
        "trid",
        "exiftool",
        "office_info",
        "pe_info",
        "androguard",
        "bundle_info",
        "pdf_info",
        "sigma_analysis_summary",
        "network_infrastructure",
        "dot_net_assembly",
        "macho_info",
        "powershell_info",
        "signature_info",
        "packers",
        "detectiteasy",
        "popular_threat_classification",
        "sigma_analysis_results",
        "crowdsourced_ids_results",
    ];

    for field in object_fields {
        properties.insert(field.to_string(), json!({"type": "object"}));
    }

    json!({
        "mappings": {
            "properties": properties
        }
    })
}

fn get_analysis_results_mapping() -> Value {
    serde_json::json!({
        "mappings": {
            "properties": {
                "report_uuid": { "type": "keyword" },
                "file_hash": { "type": "keyword" },
                "engine_name": { "type": "keyword" },
                "category": { "type": "keyword" },
                "result": { "type": "text", "fields": { "keyword": { "type": "keyword" } } },
                "method": { "type": "keyword" },
                "engine_version": { "type": "keyword" },
                "engine_update": { "type": "keyword" },
                "index_time": { "type": "date" }
            }
        }
    })
}

fn get_sandbox_verdicts_mapping() -> Value {
    serde_json::json!({
        "mappings": {
            "properties": {
                "report_uuid": { "type": "keyword" },
                "file_hash": { "type": "keyword" },
                "sandbox_name": { "type": "keyword" },
                "index_time": { "type": "date" },
                "verdict": { "type": "object", "enabled": true }
            }
        }
    })
}

fn get_crowdsourced_data_mapping() -> Value {
    serde_json::json!({
        "mappings": {
            "properties": {
                "report_uuid": { "type": "keyword" },
                "file_hash": { "type": "keyword" },
                "data_type": { "type": "keyword" },
                "index_time": { "type": "date" },
                "data": { "type": "object", "enabled": true }
            }
        }
    })
}

fn get_sandbox_behaviors_mapping() -> Value {
    serde_json::json!({
        "mappings": {
            "properties": {
                "report_uuid": { "type": "keyword" },
                "file_hash": { "type": "keyword" },
                "index_time": { "type": "date" },
                "analysis_type": { "type": "keyword" },
                "rule_id": { "type": "keyword" },
                "rule_title": { "type": "text", "fields": { "keyword": { "type": "keyword" } } },
                "rule_description": { "type": "text" },
                "severity": { "type": "keyword" },
                "rule_author": { "type": "keyword" },
                "rule_source": { "type": "keyword" },
                "event_count": { "type": "integer" },
                "behavioral_events": {
                    "type": "nested",
                    "properties": {
                        "process_info": { "type": "object", "enabled": true },
                        "process_path": { "type": "keyword" },
                        "command_line": { "type": "text", "fields": { "keyword": { "type": "keyword" } } },
                        "process_id": { "type": "keyword" },
                        "parent_process": { "type": "keyword" },
                        "file_info": { "type": "object", "enabled": true },
                        "target_file": { "type": "keyword" },
                        "file_creation_time": { "type": "date" },
                        "network_info": { "type": "object", "enabled": true },
                        "destination_ip": { "type": "ip" },
                        "destination_port": { "type": "integer" },
                        "protocol": { "type": "keyword" },
                        "registry_info": { "type": "object", "enabled": true },
                        "registry_key": { "type": "keyword" },
                        "registry_value": { "type": "text", "fields": { "keyword": { "type": "keyword" } } },
                        "loaded_image": { "type": "keyword" },
                        "signature_status": { "type": "keyword" },
                        "signed": { "type": "boolean" }
                    }
                },
                "raw_sigma_result": { "type": "object", "enabled": true }
            }
        }
    })
}

fn get_relationships_mapping() -> Value {
    serde_json::json!({
        "mappings": {
            "properties": {
                "report_uuid": { "type": "keyword" },
                "file_hash": { "type": "keyword" },
                "index_time": { "type": "date" },
                "links": { "type": "object", "enabled": true }
            }
        }
    })
}
