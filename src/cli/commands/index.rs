use crate::cli::utils::{handle_vt_error, read_hashes_from_file, setup_client, ProgressTracker};
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
    let mut reports = Vec::new();
    let mut entries = fs::read_dir(dir_path)
        .await
        .with_context(|| format!("Failed to read directory: {}", directory))?;

    while let Some(entry) = entries.next_entry().await? {
        let path = entry.path();
        if path.extension().map_or(false, |ext| ext == "json") {
            if let Some(file_name) = path.file_stem().and_then(|n| n.to_str()) {
                if verbose {
                    println!("Processing {}", path.display());
                }

                match process_json_file(&path, file_name, args).await {
                    Ok(report) => reports.push(report),
                    Err(e) => {
                        if args.skip_errors {
                            eprintln!("Warning: Failed to process {}: {}", path.display(), e);
                        } else {
                            return Err(e)
                                .with_context(|| format!("Failed to process {}", path.display()));
                        }
                    }
                }
            }
        }
    }

    Ok(reports)
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
    let client = Arc::new(setup_client(api_key, tier)?);
    let hashes = read_hashes_from_file(&args.input)?;

    if hashes.is_empty() {
        return Ok(Vec::new());
    }

    println!("Found {} hashes to download and process", hashes.len());

    // Create reports directory
    fs::create_dir_all(&args.reports_dir).await?;

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
            hashes.len() as u64,
            "Downloading reports",
        ))
    } else {
        None
    };

    let processed = Arc::new(AtomicUsize::new(0));
    let total = hashes.len();
    let reports_dir = Arc::new(args.reports_dir.clone());

    // Process hashes concurrently
    let results: Vec<_> = stream::iter(hashes.iter().enumerate())
        .map(|(_index, hash)| {
            let client = Arc::clone(&client);
            let reports_dir = Arc::clone(&reports_dir);
            let processed = Arc::clone(&processed);
            let hash = hash.clone();
            let skip_errors = args.skip_errors;
            let progress = progress.as_ref();

            async move {
                let current = processed.fetch_add(1, Ordering::SeqCst) + 1;

                if verbose {
                    println!(
                        "[{}/{}] Downloading analysis for hash: {}",
                        current, total, hash
                    );
                } else if let Some(progress) = progress {
                    progress.inc(1);
                }

                match client.files().get(&hash).await {
                    Ok(file_info) => {
                        // Save report to disk
                        let json_report = serde_json::to_string_pretty(&file_info)
                            .unwrap_or_else(|_| "{}".to_string());
                        let report_filename = format!("{}.json", hash);
                        let report_path = reports_dir.join(&report_filename);

                        if let Err(e) = fs::write(&report_path, &json_report).await {
                            if !skip_errors {
                                return Err(anyhow::anyhow!(
                                    "Failed to save report for {}: {}",
                                    hash,
                                    e
                                ));
                            }
                            eprintln!("Warning: Failed to save report for {}: {}", hash, e);
                        }

                        // Process the report
                        let file_info_json = serde_json::to_value(&file_info)
                            .map_err(|e| anyhow::anyhow!("Failed to serialize file info: {}", e))?;

                        match process_vt_report(&hash, &file_info_json) {
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
                        let error_msg = handle_vt_error(&e);
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
                }
            }
        })
        .buffer_unordered(concurrency)
        .collect()
        .await;

    if let Some(progress) = progress {
        progress.finish_with_message("Download completed");
    }

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
    let mut documents = Vec::new();

    // Extract attributes from the JSON
    let attributes = json_data
        .get("attributes")
        .ok_or_else(|| anyhow::anyhow!("Missing attributes in VT report"))?;

    // Create main report document
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
    main_report.insert(
        "index_time".to_string(),
        Value::String(Utc::now().to_rfc3339()),
    );

    // Add basic file information
    let basic_fields = [
        "sha256",
        "sha1",
        "md5",
        "vhash",
        "tlsh",
        "ssdeep",
        "permhash",
        "symhash",
        "magic",
        "magika",
        "meaningful_name",
        "type_description",
        "type_tag",
        "type_extension",
        "size",
        "names",
        "times_submitted",
        "unique_sources",
        "reputation",
        "tags",
        "type_tags",
        "first_submission_date",
        "last_submission_date",
        "last_analysis_date",
        "last_modification_date",
        "first_seen_itw_date",
        "last_seen_itw_date",
        "creation_date",
        "downloadable",
        "available_tools",
        "last_analysis_stats",
        "total_votes",
        "threat_severity",
        "trid",
        "exiftool",
        "office_info",
        "pe_info",
        "androguard",
        "bundle_info",
        "pdf_info",
        "sigma_analysis_summary",
        "sigma_analysis_results",
        "network_infrastructure",
        "dot_net_assembly",
        "macho_info",
        "powershell_info",
        "signature_info",
        "packers",
        "detectiteasy",
        "bytehero_info",
        "popular_threat_classification",
        "crowdsourced_ids_results",
    ];

    for field in &basic_fields {
        if let Some(value) = attributes.get(*field) {
            main_report.insert(field.to_string(), value.clone());
        }
    }

    documents.push(IndexedDocument {
        index: format!("{}_reports", "vt"), // Using hardcoded prefix for now
        id: report_uuid.clone(),
        body: Value::Object(main_report),
    });

    // Process antivirus scan results
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
                    index: format!("{}_analysis_results", "vt"),
                    id: format!("{}_{}", report_uuid, engine_name),
                    body: Value::Object(analysis_doc),
                });
            }
        }
    }

    // Process sandbox verdicts
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
                index: format!("{}_sandbox_verdicts", "vt"),
                id: format!("{}_{}", report_uuid, sandbox_name),
                body: Value::Object(sandbox_doc),
            });
        }
    }

    // Process crowdsourced data
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
                index: format!("{}_crowdsourced_data", "vt"),
                id: format!("{}_yara_{}", report_uuid, index),
                body: Value::Object(yara_doc),
            });
        }
    }

    Ok(ProcessedReport {
        report_uuid,
        file_hash: file_hash.to_string(),
        documents,
    })
}

async fn create_elasticsearch_indexes(
    client: &Elasticsearch,
    args: &IndexArgs,
    verbose: bool,
    dry_run: bool,
) -> Result<()> {
    let indexes = vec![
        ("reports", get_main_index_mapping()),
        ("analysis_results", get_analysis_results_mapping()),
        ("sandbox_verdicts", get_sandbox_verdicts_mapping()),
        ("crowdsourced_data", get_crowdsourced_data_mapping()),
        ("relationships", get_relationships_mapping()),
    ];

    for (index_suffix, mapping) in indexes {
        let index_name = format!("{}_{}", args.index_prefix, index_suffix);

        if dry_run {
            println!("Would create/verify index: {}", index_name);
            continue;
        }

        // Check if index exists
        let response = client
            .indices()
            .exists(elasticsearch::indices::IndicesExistsParts::Index(&[
                &index_name,
            ]))
            .send()
            .await;

        match response {
            Ok(response) => {
                let index_exists = response.status_code().as_u16() != 404;

                if args.recreate_indexes && index_exists {
                    if verbose {
                        println!("Deleting existing index: {}", index_name);
                    }
                    client
                        .indices()
                        .delete(elasticsearch::indices::IndicesDeleteParts::Index(&[
                            &index_name,
                        ]))
                        .send()
                        .await?;
                }

                if !index_exists || args.recreate_indexes {
                    if verbose {
                        println!("Creating index: {}", index_name);
                    }

                    let create_response = client
                        .indices()
                        .create(elasticsearch::indices::IndicesCreateParts::Index(
                            &index_name,
                        ))
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
                } else if verbose {
                    println!("Index {} already exists", index_name);
                }
            }
            Err(e) => {
                return Err(anyhow::anyhow!(
                    "Failed to check if index {} exists: {}",
                    index_name,
                    e
                ));
            }
        }
    }

    Ok(())
}

async fn index_documents_bulk(
    client: &Elasticsearch,
    reports: Vec<ProcessedReport>,
    args: &IndexArgs,
    verbose: bool,
) -> Result<()> {
    let total_docs: usize = reports.iter().map(|r| r.documents.len()).sum();
    println!(
        "Indexing {} documents from {} reports",
        total_docs,
        reports.len()
    );

    // Flatten all documents
    let mut all_documents = Vec::new();
    for report in reports {
        for mut doc in report.documents {
            // Add index prefix to document index
            doc.index = format!(
                "{}_{}",
                args.index_prefix,
                doc.index.strip_prefix("vt_").unwrap_or(&doc.index)
            );
            all_documents.push(doc);
        }
    }

    let progress = if !verbose {
        Some(ProgressTracker::new(
            total_docs as u64,
            "Indexing documents",
        ))
    } else {
        None
    };

    // Process in batches
    let mut indexed = 0;
    for batch in all_documents.chunks(args.batch_size) {
        let mut bulk_body = Vec::new();

        for doc in batch {
            // Action header
            let action = json!({
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
            return Err(anyhow::anyhow!(
                "Bulk indexing failed: {}",
                response.status_code()
            ));
        }

        // Check for errors in the response
        let response_body: Value = response.json().await?;
        if let Some(errors) = response_body.get("errors") {
            if errors.as_bool() == Some(true) {
                eprintln!("Some documents failed to index: {}", response_body);
                if !args.skip_errors {
                    return Err(anyhow::anyhow!("Bulk indexing had errors"));
                }
            }
        }

        indexed += batch.len();
        if verbose {
            println!("Indexed {}/{} documents", indexed, total_docs);
        }
        if let Some(ref progress) = progress {
            progress.inc(batch.len() as u64);
        }
    }

    if let Some(progress) = progress {
        progress.finish_with_message(&format!("Indexed {} documents", indexed));
    }

    Ok(())
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
