use crate::cli::utils::{handle_vt_error, read_hashes_from_file, setup_client_arc, ProgressTracker};
use crate::{ApiTier, Client};
use anyhow::{Context, Result};
use chrono::Utc;
use clap::Args;
use futures::stream::{self, StreamExt};
use serde_json::{json, Map, Value};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use tokio::fs;
use uuid::Uuid;

// Note: elasticsearch dependency needs to be added to Cargo.toml
use elasticsearch::{http::transport::Transport, BulkParts, Elasticsearch};

#[derive(Args, Debug)]
pub struct IndexArgs {
    /// Path to directory containing JSON reports or text file with hashes
    #[arg(short, long)]
    pub input: String,

    /// Elasticsearch URL
    #[arg(long, default_value = "http://localhost:9200")]
    pub es_url: String,

    /// Elasticsearch username
    #[arg(long)]
    pub es_username: Option<String>,

    /// Elasticsearch password
    #[arg(long)]
    pub es_password: Option<String>,

    /// Index name prefix
    #[arg(long, default_value = "vt")]
    pub index_prefix: String,

    /// Batch size for Elasticsearch bulk operations
    #[arg(long, default_value = "100")]
    pub batch_size: usize,

    /// Directory for JSON reports when downloading from hashes
    #[arg(long, default_value = "./reports")]
    pub reports_dir: PathBuf,

    /// Number of concurrent downloads when processing hashes
    #[arg(short = 'c', long, default_value = "5")]
    pub concurrency: usize,

    /// Skip errors and continue processing
    #[arg(short, long)]
    pub skip_errors: bool,

    /// Only create indexes, don't index documents
    #[arg(long)]
    pub create_indexes_only: bool,

    /// Skip index creation if they already exist
    #[arg(long)]
    pub skip_index_creation: bool,

    /// Delete existing indexes before creating new ones
    #[arg(long)]
    pub recreate_indexes: bool,

    /// Test Elasticsearch connection only
    #[arg(long)]
    pub test_connection: bool,
}

#[derive(Debug)]
struct IndexedDocument {
    index: String,
    id: String,
    body: Value,
}

#[derive(Debug)]
struct ProcessedReport {
    report_uuid: String,
    file_hash: String,
    documents: Vec<IndexedDocument>,
}

pub async fn execute(
    args: IndexArgs,
    api_key: Option<String>,
    tier: &str,
    verbose: bool,
    dry_run: bool,
) -> Result<()> {
    // Initialize Elasticsearch client
    let transport =
        Transport::single_node(&args.es_url).context("Failed to create Elasticsearch transport")?;
    let es_client = Elasticsearch::new(transport);

    // Test connection
    match es_client.ping().send().await {
        Ok(_) => {
            if verbose {
                println!("✓ Connected to Elasticsearch at {}", args.es_url);
            }
        }
        Err(e) => {
            return Err(anyhow::anyhow!(
                "Failed to connect to Elasticsearch at {}: {}",
                args.es_url,
                e
            ));
        }
    }

    if args.test_connection {
        println!("✓ Elasticsearch connection test successful");
        return Ok(());
    }

    if dry_run {
        println!("DRY RUN MODE - No documents will be indexed");
    }

    // Create indexes if requested
    if !args.skip_index_creation || args.create_indexes_only {
        create_elasticsearch_indexes(&es_client, &args, verbose, dry_run).await?;
    }

    if args.create_indexes_only {
        return Ok(());
    }

    // Determine input type and process
    let processed_reports = if Path::new(&args.input).is_dir() {
        // Process existing JSON files
        process_json_directory(&args.input, &args, verbose).await?
    } else if Path::new(&args.input).is_file() {
        // Check if it's a JSON file or hash list
        if args.input.ends_with(".json") {
            // Single JSON file
            process_single_json_file(&args.input, &args).await?
        } else {
            // Hash file - download reports first
            download_and_process_hashes(&args, api_key, tier, verbose).await?
        }
    } else {
        return Err(anyhow::anyhow!("Input path does not exist: {}", args.input));
    };

    if processed_reports.is_empty() {
        println!("No reports to index");
        return Ok(());
    }

    let total_docs: usize = processed_reports.iter().map(|r| r.documents.len()).sum();
    println!(
        "Found {} reports containing {} documents to index",
        processed_reports.len(),
        total_docs
    );

    if !dry_run {
        // Index documents
        index_documents_bulk(&es_client, processed_reports, &args, verbose).await?;
        println!("✓ Indexing completed successfully");
    } else {
        println!("Would index {} documents", total_docs);
    }

    Ok(())
}

async fn process_json_directory(
    directory: &str,
    args: &IndexArgs,
    verbose: bool,
) -> Result<Vec<ProcessedReport>> {
    let dir_path = Path::new(directory);
    let mut entries = fs::read_dir(dir_path)
        .await
        .with_context(|| format!("Failed to read directory: {}", directory))?;

    let mut reports = Vec::new();
    while let Some(entry) = entries.next_entry().await? {
        let path = entry.path();
        if is_json_file(&path) {
            if let Some(processed_report) = process_directory_entry(&path, args, verbose).await? {
                reports.push(processed_report);
            }
        }
    }

    Ok(reports)
}

fn is_json_file(path: &Path) -> bool {
    path.extension().map_or(false, |ext| ext == "json")
}

async fn process_directory_entry(
    path: &Path,
    args: &IndexArgs,
    verbose: bool,
) -> Result<Option<ProcessedReport>> {
    let file_name = match path.file_stem().and_then(|n| n.to_str()) {
        Some(name) => name,
        None => return Ok(None),
    };

    if verbose {
        println!("Processing {}", path.display());
    }

    handle_json_file_processing(path, file_name, args).await
}

async fn handle_json_file_processing(
    path: &Path,
    file_name: &str,
    args: &IndexArgs,
) -> Result<Option<ProcessedReport>> {
    match process_json_file(path, file_name, args).await {
        Ok(report) => Ok(Some(report)),
        Err(e) => {
            if args.skip_errors {
                eprintln!("Warning: Failed to process {}: {}", path.display(), e);
                Ok(None)
            } else {
                Err(e).with_context(|| format!("Failed to process {}", path.display()))
            }
        }
    }
}

async fn process_single_json_file(
    file_path: &str,
    args: &IndexArgs,
) -> Result<Vec<ProcessedReport>> {
    let path = Path::new(file_path);
    let file_name = path
        .file_stem()
        .and_then(|n| n.to_str())
        .ok_or_else(|| anyhow::anyhow!("Invalid file name: {}", file_path))?;

    let report = process_json_file(path, file_name, args).await?;
    Ok(vec![report])
}

async fn process_json_file(
    path: &Path,
    file_name: &str,
    args: &IndexArgs,
) -> Result<ProcessedReport> {
    let content = fs::read_to_string(path)
        .await
        .with_context(|| format!("Failed to read file: {}", path.display()))?;

    let json_data: Value = serde_json::from_str(&content)
        .with_context(|| format!("Failed to parse JSON: {}", path.display()))?;

    process_vt_report(file_name, &json_data)
}

async fn download_and_process_hashes(
    args: &IndexArgs,
    api_key: Option<String>,
    tier: &str,
    verbose: bool,
) -> Result<Vec<ProcessedReport>> {
    let client = setup_client_arc(api_key, tier)?;
    let hashes = read_hashes_from_file(&args.input)?;

    if hashes.is_empty() {
        return Ok(Vec::new());
    }

    println!("Found {} hashes to download and process", hashes.len());
    fs::create_dir_all(&args.reports_dir).await?;

    let download_config = prepare_download_configuration(args, tier, verbose, hashes.len())?;
    let results = execute_concurrent_downloads(hashes, client, args, download_config).await;
    
    finalize_download_results(results, args)
}

struct DownloadConfiguration {
    concurrency: usize,
    progress: Option<ProgressTracker>,
    total: usize,
    reports_dir: Arc<PathBuf>,
}

fn prepare_download_configuration(
    args: &IndexArgs,
    tier: &str,
    verbose: bool,
    hash_count: usize,
) -> Result<DownloadConfiguration> {
    let api_tier = match tier.to_lowercase().as_str() {
        "premium" | "private" => ApiTier::Premium,
        _ => ApiTier::Public,
    };

    let concurrency = if api_tier == ApiTier::Premium {
        args.concurrency.clamp(1, 20)
    } else {
        1
    };

    let progress = if !verbose {
        Some(ProgressTracker::new(
            hash_count as u64,
            "Downloading reports",
        ))
    } else {
        None
    };

    Ok(DownloadConfiguration {
        concurrency,
        progress,
        total: hash_count,
        reports_dir: Arc::new(args.reports_dir.clone()),
    })
}

async fn execute_concurrent_downloads(
    hashes: Vec<String>,
    client: Arc<Client>,
    args: &IndexArgs,
    config: DownloadConfiguration,
) -> Vec<Result<Option<ProcessedReport>>> {
    let processed = Arc::new(AtomicUsize::new(0));

    let results: Vec<_> = stream::iter(hashes.iter().enumerate())
        .map(|(_index, hash)| {
            process_single_hash(
                hash.clone(),
                Arc::clone(&client),
                Arc::clone(&config.reports_dir),
                Arc::clone(&processed),
                config.total,
                args.skip_errors,
                config.progress.as_ref(),
            )
        })
        .buffer_unordered(config.concurrency)
        .collect()
        .await;

    if let Some(progress) = config.progress {
        progress.finish_with_message("Download completed");
    }

    results
}

async fn process_single_hash(
    hash: String,
    client: Arc<Client>,
    reports_dir: Arc<PathBuf>,
    processed: Arc<AtomicUsize>,
    total: usize,
    skip_errors: bool,
    progress: Option<&ProgressTracker>,
) -> Result<Option<ProcessedReport>> {
    let current = processed.fetch_add(1, Ordering::SeqCst) + 1;
    update_progress_display(current, total, &hash, progress);

    match client.files().get(&hash).await {
        Ok(file_info) => {
            handle_successful_download(file_info, &hash, &reports_dir, skip_errors).await
        }
        Err(e) => {
            handle_download_error(e, &hash, skip_errors)
        }
    }
}

fn update_progress_display(
    current: usize,
    total: usize,
    hash: &str,
    progress: Option<&ProgressTracker>,
) {
    if let Some(progress) = progress {
        progress.inc(1);
    } else {
        println!(
            "[{}/{}] Downloading analysis for hash: {}",
            current, total, hash
        );
    }
}

async fn handle_successful_download(
    file_info: serde_json::Value,
    hash: &str,
    reports_dir: &Arc<PathBuf>,
    skip_errors: bool,
) -> Result<Option<ProcessedReport>> {
    if let Err(e) = save_report_to_disk(&file_info, hash, reports_dir).await {
        return handle_save_error(e, hash, skip_errors);
    }

    let file_info_json = serde_json::to_value(&file_info)
        .map_err(|e| anyhow::anyhow!("Failed to serialize file info: {}", e))?;

    process_downloaded_report(&file_info_json, hash, skip_errors)
}

async fn save_report_to_disk(
    file_info: &serde_json::Value,
    hash: &str,
    reports_dir: &Arc<PathBuf>,
) -> Result<()> {
    let json_report = serde_json::to_string_pretty(file_info)
        .unwrap_or_else(|_| "{}".to_string());
    let report_filename = format!("{}.json", hash);
    let report_path = reports_dir.join(&report_filename);

    fs::write(&report_path, &json_report).await
        .map_err(|e| anyhow::anyhow!("Failed to save report for {}: {}", hash, e))
}

fn handle_save_error(
    error: anyhow::Error,
    hash: &str,
    skip_errors: bool,
) -> Result<Option<ProcessedReport>> {
    if skip_errors {
        eprintln!("Warning: {}", error);
        Ok(None)
    } else {
        Err(error)
    }
}

fn process_downloaded_report(
    file_info_json: &serde_json::Value,
    hash: &str,
    skip_errors: bool,
) -> Result<Option<ProcessedReport>> {
    match process_vt_report(hash, file_info_json) {
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

fn handle_download_error(
    error: crate::Error,
    hash: &str,
    skip_errors: bool,
) -> Result<Option<ProcessedReport>> {
    let error_msg = handle_vt_error(&error);
    if skip_errors {
        eprintln!("Warning: Failed to download {}: {}", hash, error_msg);
        Ok(None)
    } else {
        Err(anyhow::anyhow!(
            "Failed to download {}: {}",
            hash,
            error_msg
        ))
    }
}

fn finalize_download_results(
    results: Vec<Result<Option<ProcessedReport>>>,
    args: &IndexArgs,
) -> Result<Vec<ProcessedReport>> {
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

fn process_vt_report(file_hash: &str, json_data: &Value) -> Result<ProcessedReport> {
    let report_uuid = Uuid::new_v4().to_string();
    let attributes = extract_attributes(json_data)?;
    
    let mut documents = Vec::new();
    documents.push(create_main_report_document(&report_uuid, file_hash, json_data, attributes)?);
    add_analysis_results(&mut documents, &report_uuid, file_hash, attributes);
    add_sandbox_verdicts(&mut documents, &report_uuid, file_hash, attributes);
    add_crowdsourced_data(&mut documents, &report_uuid, file_hash, attributes);

    Ok(ProcessedReport {
        report_uuid,
        file_hash: file_hash.to_string(),
        documents,
    })
}

fn extract_attributes(json_data: &Value) -> Result<&Value> {
    json_data
        .get("attributes")
        .ok_or_else(|| anyhow::anyhow!("Missing attributes in VT report"))
}

fn create_main_report_document(
    report_uuid: &str,
    file_hash: &str,
    json_data: &Value,
    attributes: &Value,
) -> Result<IndexedDocument> {
    let mut main_report = create_base_document_fields(report_uuid, file_hash);
    add_file_metadata(&mut main_report, json_data);
    add_basic_file_fields(&mut main_report, attributes);

    Ok(IndexedDocument {
        index: format!("{}_reports", "vt"),
        id: report_uuid.to_string(),
        body: Value::Object(main_report),
    })
}

fn create_base_document_fields(report_uuid: &str, file_hash: &str) -> Map<String, Value> {
    let mut doc = Map::new();
    doc.insert("report_uuid".to_string(), Value::String(report_uuid.to_string()));
    doc.insert("file_hash".to_string(), Value::String(file_hash.to_string()));
    doc.insert("index_time".to_string(), Value::String(Utc::now().to_rfc3339()));
    doc
}

fn add_file_metadata(main_report: &mut Map<String, Value>, json_data: &Value) {
    main_report.insert(
        "file_id".to_string(),
        json_data
            .get("id")
            .cloned()
            .unwrap_or(Value::String("unknown".to_string())),
    );
    main_report.insert(
        "file_type".to_string(),
        json_data
            .get("type")
            .cloned()
            .unwrap_or(Value::String("file".to_string())),
    );
}

fn add_basic_file_fields(main_report: &mut Map<String, Value>, attributes: &Value) {
    let basic_fields = get_basic_field_list();
    for field in &basic_fields {
        if let Some(value) = attributes.get(*field) {
            main_report.insert(field.to_string(), value.clone());
        }
    }
}

fn get_basic_field_list() -> [&'static str; 43] {
    [
        "sha256", "sha1", "md5", "vhash", "tlsh", "ssdeep", "permhash", "symhash",
        "magic", "magika", "meaningful_name", "type_description", "type_tag",
        "type_extension", "size", "names", "times_submitted", "unique_sources",
        "reputation", "tags", "type_tags", "first_submission_date", "last_submission_date",
        "last_analysis_date", "last_modification_date", "first_seen_itw_date",
        "last_seen_itw_date", "creation_date", "downloadable", "available_tools",
        "last_analysis_stats", "total_votes", "threat_severity", "trid", "exiftool",
        "office_info", "pe_info", "androguard", "bundle_info", "pdf_info",
        "sigma_analysis_summary", "sigma_analysis_results", "network_infrastructure",
    ]
}

fn add_analysis_results(
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
                let analysis_doc = create_analysis_document(report_uuid, file_hash, engine_name, engine_data);
                documents.push(analysis_doc);
            }
        }
    }
}

fn create_analysis_document(
    report_uuid: &str,
    file_hash: &str,
    engine_name: &str,
    engine_data: &Map<String, Value>,
) -> IndexedDocument {
    let mut analysis_doc = create_base_document_fields(report_uuid, file_hash);
    analysis_doc.insert("engine_name".to_string(), Value::String(engine_name.to_string()));
    
    for (key, value) in engine_data {
        analysis_doc.insert(key.clone(), value.clone());
    }

    IndexedDocument {
        index: format!("{}_analysis_results", "vt"),
        id: format!("{}_{}", report_uuid, engine_name),
        body: Value::Object(analysis_doc),
    }
}

fn add_sandbox_verdicts(
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
            let sandbox_doc = create_sandbox_document(report_uuid, file_hash, sandbox_name, verdict);
            documents.push(sandbox_doc);
        }
    }
}

fn create_sandbox_document(
    report_uuid: &str,
    file_hash: &str,
    sandbox_name: &str,
    verdict: &Value,
) -> IndexedDocument {
    let mut sandbox_doc = create_base_document_fields(report_uuid, file_hash);
    sandbox_doc.insert("sandbox_name".to_string(), Value::String(sandbox_name.to_string()));
    sandbox_doc.insert("verdict".to_string(), verdict.clone());

    IndexedDocument {
        index: format!("{}_sandbox_verdicts", "vt"),
        id: format!("{}_{}", report_uuid, sandbox_name),
        body: Value::Object(sandbox_doc),
    }
}

fn add_crowdsourced_data(
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
            let yara_doc = create_yara_document(report_uuid, file_hash, index, yara_result);
            documents.push(yara_doc);
        }
    }
}

fn create_yara_document(
    report_uuid: &str,
    file_hash: &str,
    index: usize,
    yara_result: &Value,
) -> IndexedDocument {
    let mut yara_doc = create_base_document_fields(report_uuid, file_hash);
    yara_doc.insert("data_type".to_string(), Value::String("yara".to_string()));
    yara_doc.insert("data".to_string(), yara_result.clone());

    IndexedDocument {
        index: format!("{}_crowdsourced_data", "vt"),
        id: format!("{}_yara_{}", report_uuid, index),
        body: Value::Object(yara_doc),
    }
}

async fn create_elasticsearch_indexes(
    client: &Elasticsearch,
    args: &IndexArgs,
    verbose: bool,
    dry_run: bool,
) -> Result<()> {
    let indexes = get_index_definitions();

    for (index_suffix, mapping) in indexes {
        let index_name = format!("{}_{}", args.index_prefix, index_suffix);
        process_single_index(client, &index_name, mapping, args, verbose, dry_run).await?;
    }

    Ok(())
}

fn get_index_definitions() -> Vec<(&'static str, Value)> {
    vec![
        ("reports", get_main_index_mapping()),
        ("analysis_results", get_analysis_results_mapping()),
        ("sandbox_verdicts", get_sandbox_verdicts_mapping()),
        ("crowdsourced_data", get_crowdsourced_data_mapping()),
        ("relationships", get_relationships_mapping()),
    ]
}

async fn process_single_index(
    client: &Elasticsearch,
    index_name: &str,
    mapping: Value,
    args: &IndexArgs,
    verbose: bool,
    dry_run: bool,
) -> Result<()> {
    if dry_run {
        println!("Would create/verify index: {}", index_name);
        return Ok(());
    }

    let index_exists = check_index_exists(client, index_name).await?;
    handle_index_creation(client, index_name, mapping, index_exists, args, verbose).await
}

async fn check_index_exists(client: &Elasticsearch, index_name: &str) -> Result<bool> {
    let response = client
        .indices()
        .exists(elasticsearch::indices::IndicesExistsParts::Index(&[index_name]))
        .send()
        .await;

    match response {
        Ok(response) => Ok(response.status_code().as_u16() != 404),
        Err(e) => Err(anyhow::anyhow!(
            "Failed to check if index {} exists: {}",
            index_name,
            e
        )),
    }
}

async fn handle_index_creation(
    client: &Elasticsearch,
    index_name: &str,
    mapping: Value,
    index_exists: bool,
    args: &IndexArgs,
    verbose: bool,
) -> Result<()> {
    if should_delete_existing_index(args, index_exists) {
        delete_existing_index(client, index_name, verbose).await?;
    }

    if should_create_index(index_exists, args) {
        create_new_index(client, index_name, mapping, verbose).await?;
    } else if verbose && index_exists {
        println!("Index {} already exists", index_name);
    }

    Ok(())
}

fn should_delete_existing_index(args: &IndexArgs, index_exists: bool) -> bool {
    args.recreate_indexes && index_exists
}

async fn delete_existing_index(
    client: &Elasticsearch,
    index_name: &str,
    verbose: bool,
) -> Result<()> {
    if verbose {
        println!("Deleting existing index: {}", index_name);
    }
    client
        .indices()
        .delete(elasticsearch::indices::IndicesDeleteParts::Index(&[index_name]))
        .send()
        .await?;
    Ok(())
}

fn should_create_index(index_exists: bool, args: &IndexArgs) -> bool {
    !index_exists || args.recreate_indexes
}

async fn create_new_index(
    client: &Elasticsearch,
    index_name: &str,
    mapping: Value,
    verbose: bool,
) -> Result<()> {
    if verbose {
        println!("Creating index: {}", index_name);
    }

    let create_response = client
        .indices()
        .create(elasticsearch::indices::IndicesCreateParts::Index(index_name))
        .body(mapping)
        .send()
        .await?;

    if !create_response.status_code().is_success() {
        return Err(anyhow::anyhow!(
            "Failed to create index {}: {}",
            index_name,
            create_response.status_code()
        ));
    }

    Ok(())
}

async fn index_documents_bulk(
    client: &Elasticsearch,
    reports: Vec<ProcessedReport>,
    args: &IndexArgs,
    verbose: bool,
) -> Result<()> {
    let all_documents = prepare_documents_for_indexing(reports, args);
    let total_docs = all_documents.len();
    
    print_indexing_summary(total_docs, &all_documents);
    let progress = create_indexing_progress(total_docs, verbose);

    process_documents_in_batches(client, all_documents, args, verbose, &progress).await?;
    finish_indexing_progress(progress);
    
    Ok(())
}

fn prepare_documents_for_indexing(
    reports: Vec<ProcessedReport>,
    args: &IndexArgs,
) -> Vec<IndexedDocument> {
    let mut all_documents = Vec::new();
    for report in reports {
        for mut doc in report.documents {
            doc.index = format!(
                "{}_{}",
                args.index_prefix,
                doc.index.strip_prefix("vt_").unwrap_or(&doc.index)
            );
            all_documents.push(doc);
        }
    }
    all_documents
}

fn print_indexing_summary(total_docs: usize, all_documents: &[IndexedDocument]) {
    let report_count = all_documents.len() / if total_docs > 0 { total_docs / all_documents.len().max(1) } else { 1 };
    println!("Indexing {} documents from {} reports", total_docs, report_count);
}

fn create_indexing_progress(total_docs: usize, verbose: bool) -> Option<ProgressTracker> {
    if !verbose {
        Some(ProgressTracker::new(total_docs as u64, "Indexing documents"))
    } else {
        None
    }
}

async fn process_documents_in_batches(
    client: &Elasticsearch,
    all_documents: Vec<IndexedDocument>,
    args: &IndexArgs,
    verbose: bool,
    progress: &Option<ProgressTracker>,
) -> Result<()> {
    let mut indexed = 0;
    let total_docs = all_documents.len();

    for batch in all_documents.chunks(args.batch_size) {
        process_single_batch(client, batch, args).await?;
        indexed += batch.len();
        
        update_batch_progress(indexed, total_docs, batch.len(), verbose, progress);
    }
    
    Ok(())
}

async fn process_single_batch(
    client: &Elasticsearch,
    batch: &[IndexedDocument],
    args: &IndexArgs,
) -> Result<()> {
    let bulk_body_str = create_bulk_request_body(batch)?;
    let response = send_bulk_request(client, bulk_body_str).await?;
    handle_bulk_response(response, args).await
}

fn create_bulk_request_body(batch: &[IndexedDocument]) -> Result<String> {
    let mut bulk_body = Vec::new();

    for doc in batch {
        let action = json!({
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

async fn send_bulk_request(
    client: &Elasticsearch,
    bulk_body_str: String,
) -> Result<elasticsearch::http::response::Response> {
    let response = client
        .bulk(BulkParts::None)
        .body(vec![bulk_body_str])
        .send()
        .await?;

    if !response.status_code().is_success() {
        return Err(anyhow::anyhow!(
            "Bulk indexing failed: {}",
            response.status_code()
        ));
    }

    Ok(response)
}

async fn handle_bulk_response(
    response: elasticsearch::http::response::Response,
    args: &IndexArgs,
) -> Result<()> {
    let response_body: Value = response.json().await?;
    if let Some(errors) = response_body.get("errors") {
        if errors.as_bool() == Some(true) {
            eprintln!("Some documents failed to index: {}", response_body);
            if !args.skip_errors {
                return Err(anyhow::anyhow!("Bulk indexing had errors"));
            }
        }
    }
    Ok(())
}

fn update_batch_progress(
    indexed: usize,
    total_docs: usize,
    batch_size: usize,
    verbose: bool,
    progress: &Option<ProgressTracker>,
) {
    if verbose {
        println!("Indexed {}/{} documents", indexed, total_docs);
    }
    if let Some(ref progress) = progress {
        progress.inc(batch_size as u64);
    }
}

fn finish_indexing_progress(progress: Option<ProgressTracker>) {
    if let Some(progress) = progress {
        progress.finish_with_message("Indexing completed");
    }
}

// Index mapping functions (shortened versions from the original)
fn get_main_index_mapping() -> Value {
    json!({
        "mappings": {
            "properties": {
                "report_uuid": {"type": "keyword"},
                "file_hash": {"type": "keyword"},
                "file_id": {"type": "keyword"},
                "file_type": {"type": "keyword"},
                "sha256": {"type": "keyword"},
                "sha1": {"type": "keyword"},
                "md5": {"type": "keyword"},
                "size": {"type": "long"},
                "index_time": {"type": "date"},
                "last_analysis_stats": {
                    "properties": {
                        "harmless": {"type": "integer"},
                        "malicious": {"type": "integer"},
                        "suspicious": {"type": "integer"},
                        "undetected": {"type": "integer"}
                    }
                }
            }
        }
    })
}

fn get_analysis_results_mapping() -> Value {
    json!({
        "mappings": {
            "properties": {
                "report_uuid": {"type": "keyword"},
                "file_hash": {"type": "keyword"},
                "engine_name": {"type": "keyword"},
                "category": {"type": "keyword"},
                "result": {"type": "text", "fields": {"keyword": {"type": "keyword"}}},
                "index_time": {"type": "date"}
            }
        }
    })
}

fn get_sandbox_verdicts_mapping() -> Value {
    json!({
        "mappings": {
            "properties": {
                "report_uuid": {"type": "keyword"},
                "file_hash": {"type": "keyword"},
                "sandbox_name": {"type": "keyword"},
                "index_time": {"type": "date"},
                "verdict": {"type": "object", "enabled": true}
            }
        }
    })
}

fn get_crowdsourced_data_mapping() -> Value {
    json!({
        "mappings": {
            "properties": {
                "report_uuid": {"type": "keyword"},
                "file_hash": {"type": "keyword"},
                "data_type": {"type": "keyword"},
                "index_time": {"type": "date"},
                "data": {"type": "object", "enabled": true}
            }
        }
    })
}

fn get_relationships_mapping() -> Value {
    json!({
        "mappings": {
            "properties": {
                "report_uuid": {"type": "keyword"},
                "file_hash": {"type": "keyword"},
                "index_time": {"type": "date"},
                "links": {"type": "object", "enabled": true}
            }
        }
    })
}
