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

#[derive(Debug)]
struct DownloadParams {
    reports_dir: Arc<PathBuf>,
    processed: Arc<AtomicUsize>,
    total: usize,
    verbose: bool,
    skip_errors: bool,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    // Validate arguments and check if indexing is enabled
    if !validate_arguments(&args) {
        return Ok(());
    }

    // Initialize and test Elasticsearch client
    let es_client = initialize_elasticsearch_client(&args).await?;

    // Process reports from input source
    let processed_reports = match process_reports_from_input(&args).await? {
        Some(reports) => reports,
        None => return Ok(()), // No reports to process, exit gracefully
    };

    // Coordinate the final indexing process
    coordinate_indexing(&es_client, processed_reports, &args).await?;

    println!("✓ Indexing completed successfully");
    Ok(())
}

/// Validates command-line arguments and checks if indexing is enabled
/// Returns true if should continue processing, false if should exit early
fn validate_arguments(args: &Args) -> bool {
    if !args.index {
        println!("Indexing is disabled. Use --index to enable Elasticsearch indexing.");
        return false;
    }
    true
}

/// Initializes Elasticsearch client and tests the connection
async fn initialize_elasticsearch_client(
    args: &Args,
) -> Result<Elasticsearch, Box<dyn std::error::Error>> {
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

    Ok(es_client)
}

/// Processes reports from the input source (directory or hash file)
/// Returns None if no reports found (early exit), Some(reports) if reports found
async fn process_reports_from_input(
    args: &Args,
) -> Result<Option<Vec<ProcessedReport>>, Box<dyn std::error::Error>> {
    // Determine if input is a directory with JSON files or a text file with hashes
    let processed_reports = if args.input.is_dir() {
        // Process existing JSON files
        process_json_directory(&args.input, args).await?
    } else {
        // Download reports from hashes and process them
        download_and_process_hashes(args).await?
    };

    if processed_reports.is_empty() {
        println!("No reports to process.");
        return Ok(None);
    }

    println!("Found {} reports to index", processed_reports.len());
    Ok(Some(processed_reports))
}

/// Coordinates the final indexing process by creating indexes and bulk indexing documents
async fn coordinate_indexing(
    es_client: &Elasticsearch,
    processed_reports: Vec<ProcessedReport>,
    args: &Args,
) -> Result<(), Box<dyn std::error::Error>> {
    // Create Elasticsearch indexes
    create_elasticsearch_indexes(es_client, args).await?;

    // Index documents in batches
    index_documents_bulk(es_client, processed_reports, args).await?;

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

/// Initialize VirusTotal API client with provided credentials and tier
fn initialize_vt_client(args: &Args) -> Result<(Client, ApiTier), Box<dyn std::error::Error>> {
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
    Ok((client, api_tier))
}

/// Read and parse hashes from input file, filtering out empty lines and comments
async fn read_hashes_from_file(
    input_path: &Path,
) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    let content = fs::read_to_string(input_path).await?;
    let hashes: Vec<String> = content
        .lines()
        .map(|line| line.trim())
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .map(String::from)
        .collect();

    Ok(hashes)
}

/// Download and process a single hash, returning the processed report
async fn download_and_process_single_hash(
    hash: String,
    client: Arc<Client>,
    params: &DownloadParams,
    args: &Args,
) -> Result<Option<ProcessedReport>, Box<dyn std::error::Error>> {
    let current = params.processed.fetch_add(1, Ordering::SeqCst) + 1;
    let progress = format!("[{}/{}]", current, params.total);

    if params.verbose {
        println!("{} Downloading analysis for hash: {}", progress, hash);
    } else {
        println!("{} Processing {}...", progress, &hash[..16.min(hash.len())]);
    }

    match client.files().get(&hash).await {
        Ok(file_info) => {
            // Save report to disk
            let json_report =
                serde_json::to_string_pretty(&file_info).unwrap_or_else(|_| "{}".to_string());
            let report_filename = format!("{}.json", hash);
            let report_path = params.reports_dir.join(&report_filename);

            if let Err(e) = fs::write(&report_path, &json_report).await {
                eprintln!("Warning: Failed to save report for {}: {}", hash, e);
            }

            // Convert to JSON Value for processing
            let file_info_json = serde_json::to_value(&file_info)?;

            // Process the report
            match process_vt_report(&hash, &file_info_json, args) {
                Ok(report) => Ok(Some(report)),
                Err(e) => {
                    if params.skip_errors {
                        eprintln!("Warning: Failed to process {}: {}", hash, e);
                        Ok(None)
                    } else {
                        Err(e)
                    }
                }
            }
        }
        Err(e) => {
            if params.skip_errors {
                eprintln!("Warning: Failed to download {}: {}", hash, e);
                Ok(None)
            } else {
                Err(format!("Failed to download {}: {}", hash, e).into())
            }
        }
    }
}

/// Collect and validate results from concurrent download operations
fn collect_download_results(
    results: Vec<Result<Option<ProcessedReport>, Box<dyn std::error::Error>>>,
    skip_errors: bool,
) -> Result<Vec<ProcessedReport>, Box<dyn std::error::Error>> {
    let mut reports = Vec::new();
    for result in results {
        match result {
            Ok(Some(report)) => reports.push(report),
            Ok(None) => {} // Skipped due to error
            Err(e) => {
                if !skip_errors {
                    return Err(e);
                }
            }
        }
    }
    Ok(reports)
}

async fn download_and_process_hashes(
    args: &Args,
) -> Result<Vec<ProcessedReport>, Box<dyn std::error::Error>> {
    // Initialize VirusTotal client
    let (client, api_tier) = initialize_vt_client(args)?;

    // Read hashes from file
    let hashes = read_hashes_from_file(&args.input).await?;
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

    let download_params = DownloadParams {
        reports_dir: Arc::clone(&reports_dir),
        processed: Arc::clone(&processed),
        total,
        verbose: args.verbose,
        skip_errors: args.skip_errors,
    };

    // Process hashes concurrently
    let results: Vec<_> = stream::iter(hashes.iter().enumerate())
        .map(|(_index, hash)| {
            download_and_process_single_hash(
                hash.clone(),
                Arc::clone(&client),
                &download_params,
                args,
            )
        })
        .buffer_unordered(concurrency)
        .collect()
        .await;

    // Collect and validate results
    collect_download_results(results, args.skip_errors)
}

/// Creates the main report document with basic file information and metadata
fn create_main_report_document(
    report_uuid: &str,
    file_hash: &str,
    json_data: &Value,
    attributes: &Value,
) -> IndexedDocument {
    let mut main_report = Map::new();

    // Add core identifiers
    main_report.insert(
        "report_uuid".to_string(),
        Value::String(report_uuid.to_string()),
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
    main_report.insert(
        "index_time".to_string(),
        Value::String(Utc::now().to_rfc3339()),
    );

    // Process basic file attributes using helper
    process_basic_file_attributes(&mut main_report, attributes);
    process_file_analysis_attributes(&mut main_report, attributes);
    process_temporal_attributes(&mut main_report, attributes);
    process_threat_intelligence_attributes(&mut main_report, attributes);
    process_specialized_analysis_attributes(&mut main_report, attributes);

    IndexedDocument {
        index: "vt_reports".to_string(),
        id: report_uuid.to_string(),
        body: Value::Object(main_report),
    }
}

/// Processes basic file attributes (hashes, size, names, etc.)
fn process_basic_file_attributes(main_report: &mut Map<String, Value>, attributes: &Value) {
    let basic_fields = vec![
        "sha256",
        "sha1",
        "md5",
        "vhash",
        "tlsh",
        "ssdeep",
        "permhash",
        "symhash",
        "size",
        "names",
        "meaningful_name",
        "type_description",
        "type_tag",
        "type_extension",
        "type_tags",
        "downloadable",
        "available_tools",
    ];

    for field in basic_fields {
        if let Some(value) = attributes.get(field) {
            main_report.insert(field.to_string(), value.clone());
        }
    }
}

/// Processes file analysis attributes (magic, trid, exiftool, etc.)
fn process_file_analysis_attributes(main_report: &mut Map<String, Value>, attributes: &Value) {
    let analysis_fields = vec![
        "magic",
        "trid",
        "exiftool",
        "office_info",
        "pe_info",
        "androguard",
        "bundle_info",
        "pdf_info",
        "network_infrastructure",
        "dot_net_assembly",
        "macho_info",
        "powershell_info",
        "signature_info",
        "packers",
        "detectiteasy",
        "magika",
        "bytehero_info",
    ];

    for field in analysis_fields {
        if let Some(value) = attributes.get(field) {
            main_report.insert(field.to_string(), value.clone());
        }
    }
}

/// Processes temporal attributes (submission dates, analysis dates, etc.)
fn process_temporal_attributes(main_report: &mut Map<String, Value>, attributes: &Value) {
    let temporal_fields = vec![
        "first_submission_date",
        "last_submission_date",
        "last_analysis_date",
        "last_modification_date",
        "first_seen_itw_date",
        "last_seen_itw_date",
        "creation_date",
    ];

    for field in temporal_fields {
        if let Some(value) = attributes.get(field) {
            main_report.insert(field.to_string(), value.clone());
        }
    }
}

/// Processes threat intelligence attributes (reputation, votes, tags, etc.)
fn process_threat_intelligence_attributes(
    main_report: &mut Map<String, Value>,
    attributes: &Value,
) {
    let intel_fields = vec![
        "times_submitted",
        "unique_sources",
        "reputation",
        "tags",
        "total_votes",
        "threat_severity",
        "last_analysis_stats",
        "popular_threat_classification",
    ];

    for field in intel_fields {
        if let Some(value) = attributes.get(field) {
            main_report.insert(field.to_string(), value.clone());
        }
    }
}

/// Processes specialized analysis attributes (sigma, crowdsourced data, etc.)
fn process_specialized_analysis_attributes(
    main_report: &mut Map<String, Value>,
    attributes: &Value,
) {
    let specialized_fields = vec![
        "sigma_analysis_summary",
        "sigma_analysis_results",
        "crowdsourced_ids_results",
    ];

    for field in specialized_fields {
        if let Some(value) = attributes.get(field) {
            main_report.insert(field.to_string(), value.clone());
        }
    }
}

/// Processes antivirus analysis results into separate documents
fn process_analysis_results(
    documents: &mut Vec<IndexedDocument>,
    report_uuid: &str,
    file_hash: &str,
    attributes: &Value,
) {
    if let Some(analysis_results) = attributes
        .get("last_analysis_results")
        .and_then(|v| v.as_object())
    {
        for (engine_name, engine_result) in analysis_results {
            if let Some(engine_data) = engine_result.as_object() {
                let mut analysis_doc = create_base_document(report_uuid, file_hash);
                analysis_doc.insert(
                    "engine_name".to_string(),
                    Value::String(engine_name.clone()),
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
}

/// Processes sandbox verdicts into separate documents
fn process_sandbox_verdicts(
    documents: &mut Vec<IndexedDocument>,
    report_uuid: &str,
    file_hash: &str,
    attributes: &Value,
) {
    if let Some(sandbox_verdicts) = attributes
        .get("sandbox_verdicts")
        .and_then(|v| v.as_object())
    {
        for (sandbox_name, verdict) in sandbox_verdicts {
            let mut sandbox_doc = create_base_document(report_uuid, file_hash);
            sandbox_doc.insert(
                "sandbox_name".to_string(),
                Value::String(sandbox_name.clone()),
            );
            sandbox_doc.insert("verdict".to_string(), verdict.clone());

            documents.push(IndexedDocument {
                index: "vt_sandbox_verdicts".to_string(),
                id: format!("{}_{}", report_uuid, sandbox_name),
                body: Value::Object(sandbox_doc),
            });
        }
    }
}

/// Processes sigma analysis results for behavioral data
fn process_sigma_analysis(
    documents: &mut Vec<IndexedDocument>,
    report_uuid: &str,
    file_hash: &str,
    attributes: &Value,
) {
    if let Some(sigma_results) = attributes
        .get("sigma_analysis_results")
        .and_then(|v| v.as_array())
    {
        for (index, sigma_result) in sigma_results.iter().enumerate() {
            if let Some(sigma_obj) = sigma_result.as_object() {
                let mut behavior_doc = create_base_document(report_uuid, file_hash);
                behavior_doc.insert(
                    "analysis_type".to_string(),
                    Value::String("sigma".to_string()),
                );

                process_sigma_rule_info(&mut behavior_doc, sigma_obj);
                process_sigma_behavioral_events(&mut behavior_doc, sigma_obj);
                behavior_doc.insert("raw_sigma_result".to_string(), sigma_result.clone());

                documents.push(IndexedDocument {
                    index: "vt_sandbox_behaviors".to_string(),
                    id: format!("{}_sigma_{}", report_uuid, index),
                    body: Value::Object(behavior_doc),
                });
            }
        }
    }
}

/// Processes sigma rule information
fn process_sigma_rule_info(
    behavior_doc: &mut Map<String, Value>,
    sigma_obj: &serde_json::Map<String, Value>,
) {
    let rule_fields = vec![
        ("rule_id", "rule_id"),
        ("rule_title", "rule_title"),
        ("rule_description", "rule_description"),
        ("rule_level", "severity"),
        ("rule_author", "rule_author"),
        ("rule_source", "rule_source"),
    ];

    for (source_field, target_field) in rule_fields {
        if let Some(value) = sigma_obj.get(source_field) {
            behavior_doc.insert(target_field.to_string(), value.clone());
        }
    }
}

/// Processes sigma behavioral events for detailed analysis
fn process_sigma_behavioral_events(
    behavior_doc: &mut Map<String, Value>,
    sigma_obj: &serde_json::Map<String, Value>,
) {
    if let Some(matches) = sigma_obj.get("rule_matches").and_then(|v| v.as_array()) {
        let mut behavioral_events = Vec::new();

        for match_item in matches {
            if let Some(match_obj) = match_item.as_object() {
                let mut event = Map::new();
                process_sigma_event_details(&mut event, match_obj);
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
}

/// Processes individual sigma event details (process, file, network, registry info)
fn process_sigma_event_details(
    event: &mut Map<String, Value>,
    match_obj: &serde_json::Map<String, Value>,
) {
    process_sigma_process_info(event, match_obj);
    process_sigma_file_info(event, match_obj);
    process_sigma_network_info(event, match_obj);
    process_sigma_registry_info(event, match_obj);
    process_sigma_misc_info(event, match_obj);
}

/// Processes process information from sigma events
fn process_sigma_process_info(
    event: &mut Map<String, Value>,
    match_obj: &serde_json::Map<String, Value>,
) {
    if let Some(process_info) = match_obj.get("Process") {
        event.insert("process_info".to_string(), process_info.clone());

        if let Some(process_obj) = process_info.as_object() {
            let process_fields = vec![
                ("Image", "process_path"),
                ("CommandLine", "command_line"),
                ("ProcessId", "process_id"),
                ("ParentImage", "parent_process"),
            ];

            for (source, target) in process_fields {
                if let Some(value) = process_obj.get(source) {
                    event.insert(target.to_string(), value.clone());
                }
            }
        }
    }
}

/// Processes file information from sigma events
fn process_sigma_file_info(
    event: &mut Map<String, Value>,
    match_obj: &serde_json::Map<String, Value>,
) {
    if let Some(file_info) = match_obj.get("File") {
        event.insert("file_info".to_string(), file_info.clone());

        if let Some(file_obj) = file_info.as_object() {
            if let Some(target_filename) = file_obj.get("TargetFilename") {
                event.insert("target_file".to_string(), target_filename.clone());
            }
            if let Some(creation_time) = file_obj.get("CreationUtcTime") {
                event.insert("file_creation_time".to_string(), creation_time.clone());
            }
        }
    }
}

/// Processes network information from sigma events
fn process_sigma_network_info(
    event: &mut Map<String, Value>,
    match_obj: &serde_json::Map<String, Value>,
) {
    if let Some(network_info) = match_obj.get("Network") {
        event.insert("network_info".to_string(), network_info.clone());

        if let Some(network_obj) = network_info.as_object() {
            let network_fields = vec![
                ("DestinationIp", "destination_ip"),
                ("DestinationPort", "destination_port"),
                ("Protocol", "protocol"),
            ];

            for (source, target) in network_fields {
                if let Some(value) = network_obj.get(source) {
                    event.insert(target.to_string(), value.clone());
                }
            }
        }
    }
}

/// Processes registry information from sigma events
fn process_sigma_registry_info(
    event: &mut Map<String, Value>,
    match_obj: &serde_json::Map<String, Value>,
) {
    if let Some(registry_info) = match_obj.get("Registry") {
        event.insert("registry_info".to_string(), registry_info.clone());

        if let Some(registry_obj) = registry_info.as_object() {
            if let Some(target_object) = registry_obj.get("TargetObject") {
                event.insert("registry_key".to_string(), target_object.clone());
            }
            if let Some(details) = registry_obj.get("Details") {
                event.insert("registry_value".to_string(), details.clone());
            }
        }
    }
}

/// Processes miscellaneous sigma event information
fn process_sigma_misc_info(
    event: &mut Map<String, Value>,
    match_obj: &serde_json::Map<String, Value>,
) {
    let misc_fields = vec![
        ("ImageLoaded", "loaded_image"),
        ("SignatureStatus", "signature_status"),
        ("Signed", "signed"),
    ];

    for (source, target) in misc_fields {
        if let Some(value) = match_obj.get(source) {
            event.insert(target.to_string(), value.clone());
        }
    }
}

/// Processes crowdsourced data (YARA rules and IDS results)
fn process_crowdsourced_data(
    documents: &mut Vec<IndexedDocument>,
    report_uuid: &str,
    file_hash: &str,
    attributes: &Value,
) {
    process_yara_results(documents, report_uuid, file_hash, attributes);
    process_ids_results(documents, report_uuid, file_hash, attributes);
}

/// Processes YARA results
fn process_yara_results(
    documents: &mut Vec<IndexedDocument>,
    report_uuid: &str,
    file_hash: &str,
    attributes: &Value,
) {
    if let Some(crowdsourced_yara_results) = attributes
        .get("crowdsourced_yara_results")
        .and_then(|v| v.as_array())
    {
        for (index, yara_result) in crowdsourced_yara_results.iter().enumerate() {
            let mut yara_doc = create_base_document(report_uuid, file_hash);
            yara_doc.insert("data_type".to_string(), Value::String("yara".to_string()));
            yara_doc.insert("data".to_string(), yara_result.clone());

            documents.push(IndexedDocument {
                index: "vt_crowdsourced_data".to_string(),
                id: format!("{}_yara_{}", report_uuid, index),
                body: Value::Object(yara_doc),
            });
        }
    }
}

/// Processes IDS results
fn process_ids_results(
    documents: &mut Vec<IndexedDocument>,
    report_uuid: &str,
    file_hash: &str,
    attributes: &Value,
) {
    if let Some(crowdsourced_ids_results) = attributes
        .get("crowdsourced_ids_results")
        .and_then(|v| v.as_array())
    {
        for (index, ids_result) in crowdsourced_ids_results.iter().enumerate() {
            let mut ids_doc = create_base_document(report_uuid, file_hash);
            ids_doc.insert("data_type".to_string(), Value::String("ids".to_string()));
            ids_doc.insert("data".to_string(), ids_result.clone());

            documents.push(IndexedDocument {
                index: "vt_crowdsourced_data".to_string(),
                id: format!("{}_ids_{}", report_uuid, index),
                body: Value::Object(ids_doc),
            });
        }
    }
}

/// Processes file relationships
fn process_relationships(
    documents: &mut Vec<IndexedDocument>,
    report_uuid: &str,
    file_hash: &str,
    json_data: &Value,
) {
    if let Some(links) = json_data.get("links") {
        let mut relationships_doc = create_base_document(report_uuid, file_hash);
        relationships_doc.insert("links".to_string(), links.clone());

        documents.push(IndexedDocument {
            index: "vt_relationships".to_string(),
            id: format!("{}_links", report_uuid),
            body: Value::Object(relationships_doc),
        });
    }
}

/// Creates a base document with common fields
fn create_base_document(report_uuid: &str, file_hash: &str) -> Map<String, Value> {
    let mut doc = Map::new();
    doc.insert(
        "report_uuid".to_string(),
        Value::String(report_uuid.to_string()),
    );
    doc.insert(
        "file_hash".to_string(),
        Value::String(file_hash.to_string()),
    );
    doc.insert(
        "index_time".to_string(),
        Value::String(Utc::now().to_rfc3339()),
    );
    doc
}

/// Main function to process a VirusTotal report into Elasticsearch documents
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

    // Create main report document
    let main_document = create_main_report_document(&report_uuid, file_hash, json_data, attributes);
    documents.push(main_document);

    // Process different aspects of the report using helper functions
    process_analysis_results(&mut documents, &report_uuid, file_hash, attributes);
    process_sandbox_verdicts(&mut documents, &report_uuid, file_hash, attributes);
    process_sigma_analysis(&mut documents, &report_uuid, file_hash, attributes);
    process_crowdsourced_data(&mut documents, &report_uuid, file_hash, attributes);
    process_relationships(&mut documents, &report_uuid, file_hash, json_data);

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
    let indexes = get_index_definitions();

    for (index_name, mapping) in indexes {
        create_index_if_not_exists(client, index_name, mapping, args).await?;
    }

    Ok(())
}

fn get_index_definitions() -> Vec<(&'static str, Value)> {
    vec![
        ("vt_reports", get_main_index_mapping()),
        ("vt_analysis_results", get_analysis_results_mapping()),
        ("vt_sandbox_verdicts", get_sandbox_verdicts_mapping()),
        ("vt_sandbox_behaviors", get_sandbox_behaviors_mapping()),
        ("vt_crowdsourced_data", get_crowdsourced_data_mapping()),
        ("vt_relationships", get_relationships_mapping()),
    ]
}

async fn create_index_if_not_exists(
    client: &Elasticsearch,
    index_name: &str,
    mapping: Value,
    args: &Args,
) -> Result<(), Box<dyn std::error::Error>> {
    let exists_response = check_index_exists(client, index_name).await;

    match exists_response {
        Ok(response) => {
            if response.status_code().as_u16() == 404 {
                create_new_index(client, index_name, mapping, args).await?
            } else if args.verbose {
                println!("Index {} already exists", index_name);
            }
        }
        Err(e) => {
            return Err(format!("Failed to check if index {} exists: {}", index_name, e).into());
        }
    }

    Ok(())
}

async fn check_index_exists(
    client: &Elasticsearch,
    index_name: &str,
) -> Result<elasticsearch::http::response::Response, elasticsearch::Error> {
    client
        .indices()
        .exists(elasticsearch::indices::IndicesExistsParts::Index(&[
            index_name,
        ]))
        .send()
        .await
}

async fn create_new_index(
    client: &Elasticsearch,
    index_name: &str,
    mapping: Value,
    args: &Args,
) -> Result<(), Box<dyn std::error::Error>> {
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

    Ok(())
}

async fn index_documents_bulk(
    client: &Elasticsearch,
    reports: Vec<ProcessedReport>,
    args: &Args,
) -> Result<(), Box<dyn std::error::Error>> {
    let all_documents = flatten_report_documents(reports);
    let total_docs = all_documents.len();

    println!("Indexing {} documents from reports", total_docs);

    let mut indexed = 0;
    for batch in all_documents.chunks(args.batch_size) {
        indexed += process_document_batch(client, batch, args).await?;

        if args.verbose {
            println!("Indexed {}/{} documents", indexed, total_docs);
        }
    }

    println!("✓ Successfully indexed {} documents", indexed);
    Ok(())
}

fn flatten_report_documents(reports: Vec<ProcessedReport>) -> Vec<IndexedDocument> {
    let mut all_documents = Vec::new();
    for report in reports {
        for doc in report.documents {
            all_documents.push(doc);
        }
    }
    all_documents
}

async fn process_document_batch(
    client: &Elasticsearch,
    batch: &[IndexedDocument],
    args: &Args,
) -> Result<usize, Box<dyn std::error::Error>> {
    let bulk_body = prepare_bulk_request_body(batch)?;
    let response = execute_bulk_request(client, bulk_body).await?;
    handle_bulk_response(response, args).await?;
    Ok(batch.len())
}

fn prepare_bulk_request_body(
    batch: &[IndexedDocument],
) -> Result<String, Box<dyn std::error::Error>> {
    let mut bulk_body = Vec::new();

    for doc in batch {
        let action = serde_json::json!({
            "index": {
                "_index": doc.index,
                "_id": doc.id
            }
        });
        bulk_body.push(serde_json::to_string(&action)?);
        bulk_body.push(serde_json::to_string(&doc.body)?);
    }

    Ok(bulk_body.join("\n") + "\n")
}

async fn execute_bulk_request(
    client: &Elasticsearch,
    bulk_body: String,
) -> Result<elasticsearch::http::response::Response, Box<dyn std::error::Error>> {
    let response = client
        .bulk(BulkParts::None)
        .body(vec![bulk_body])
        .send()
        .await?;

    if !response.status_code().is_success() {
        return Err(format!("Bulk indexing failed: {}", response.status_code()).into());
    }

    Ok(response)
}

async fn handle_bulk_response(
    response: elasticsearch::http::response::Response,
    args: &Args,
) -> Result<(), Box<dyn std::error::Error>> {
    let response_body: Value = response.json().await?;

    if let Some(errors) = response_body.get("errors") {
        if errors.as_bool() == Some(true) {
            eprintln!("Some documents failed to index: {}", response_body);
            if !args.skip_errors {
                return Err("Bulk indexing had errors".into());
            }
        }
    }

    Ok(())
}

/// Helper function to add basic identifier and hash fields to properties
fn add_basic_mapping_fields(properties: &mut serde_json::Map<String, Value>) {
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
}

/// Helper function to add text fields for analysis descriptions
fn add_text_mapping_fields(properties: &mut serde_json::Map<String, Value>) {
    properties.insert("magic".to_string(), json!({"type": "text"}));
    properties.insert("magika".to_string(), json!({"type": "text"}));
    properties.insert("bytehero_info".to_string(), json!({"type": "text"}));
    properties.insert(
        "meaningful_name".to_string(),
        json!({"type": "text", "fields": {"keyword": {"type": "keyword"}}}),
    );
    properties.insert("type_description".to_string(), json!({"type": "text"}));
}

/// Helper function to add numeric fields for statistics and metrics
fn add_numeric_mapping_fields(properties: &mut serde_json::Map<String, Value>) {
    properties.insert("size".to_string(), json!({"type": "long"}));
    properties.insert("times_submitted".to_string(), json!({"type": "integer"}));
    properties.insert("unique_sources".to_string(), json!({"type": "integer"}));
    properties.insert("reputation".to_string(), json!({"type": "integer"}));
}

/// Helper function to add keyword fields for categorization and tagging
fn add_keyword_mapping_fields(properties: &mut serde_json::Map<String, Value>) {
    properties.insert("names".to_string(), json!({"type": "keyword"}));
    properties.insert("type_tag".to_string(), json!({"type": "keyword"}));
    properties.insert("type_extension".to_string(), json!({"type": "keyword"}));
    properties.insert("tags".to_string(), json!({"type": "keyword"}));
    properties.insert("type_tags".to_string(), json!({"type": "keyword"}));
    properties.insert("available_tools".to_string(), json!({"type": "keyword"}));
}

/// Helper function to add date fields for temporal analysis
fn add_date_mapping_fields(properties: &mut serde_json::Map<String, Value>) {
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
}

/// Helper function to add boolean fields
fn add_boolean_mapping_fields(properties: &mut serde_json::Map<String, Value>) {
    properties.insert("downloadable".to_string(), json!({"type": "boolean"}));
}

/// Helper function to add nested objects for analysis statistics
fn add_stats_mapping_fields(properties: &mut serde_json::Map<String, Value>) {
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
}

/// Helper function to add object fields for complex nested data structures
fn add_object_mapping_fields(properties: &mut serde_json::Map<String, Value>) {
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
}

/// Creates the main Elasticsearch index mapping by combining all field types
fn get_main_index_mapping() -> Value {
    let mut properties = serde_json::Map::new();

    // Add different categories of fields using helper functions
    add_basic_mapping_fields(&mut properties);
    add_text_mapping_fields(&mut properties);
    add_numeric_mapping_fields(&mut properties);
    add_keyword_mapping_fields(&mut properties);
    add_date_mapping_fields(&mut properties);
    add_boolean_mapping_fields(&mut properties);
    add_stats_mapping_fields(&mut properties);
    add_object_mapping_fields(&mut properties);

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
