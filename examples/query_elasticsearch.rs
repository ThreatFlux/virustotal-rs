use clap::Parser;
use elasticsearch::{http::transport::Transport, Elasticsearch, SearchParts};
use serde_json::{json, Value};

#[derive(Parser, Debug)]
#[command(name = "vt-es-query")]
#[command(about = "Query VirusTotal data indexed in Elasticsearch")]
struct Args {
    /// Elasticsearch URL
    #[arg(long, default_value = "http://localhost:9200")]
    es_url: String,

    /// Query type to execute
    #[arg(short, long, default_value = "summary")]
    query: String,

    /// Optional search term or file hash
    #[arg(short, long)]
    term: Option<String>,

    /// Pretty print JSON output
    #[arg(short, long)]
    pretty: bool,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    // Initialize Elasticsearch client
    let transport = Transport::single_node(&args.es_url)?;
    let client = Elasticsearch::new(transport);

    // Test connection
    match client.ping().send().await {
        Ok(_) => {
            println!("✓ Connected to Elasticsearch at {}", args.es_url);
        }
        Err(e) => {
            eprintln!(
                "Failed to connect to Elasticsearch at {}: {}",
                args.es_url, e
            );
            return Err(e.into());
        }
    }

    match args.query.as_str() {
        "summary" => query_summary(&client).await?,
        "malicious" => query_malicious_files(&client).await?,
        "engines" => query_engine_stats(&client).await?,
        "hash" => {
            if let Some(hash) = args.term {
                query_by_hash(&client, &hash).await?;
            } else {
                eprintln!("Hash query requires --term parameter");
            }
        }
        "yara" => query_yara_matches(&client).await?,
        _ => {
            eprintln!("Unknown query type: {}", args.query);
            eprintln!("Available queries: summary, malicious, engines, hash, yara");
        }
    }

    Ok(())
}

async fn query_summary(client: &Elasticsearch) -> Result<(), Box<dyn std::error::Error>> {
    println!("\n=== Index Summary ===");

    let indices = vec![
        "vt_reports",
        "vt_analysis_results",
        "vt_sandbox_verdicts",
        "vt_crowdsourced_data",
        "vt_relationships",
    ];

    for index in indices {
        let response = client
            .count(elasticsearch::CountParts::Index(&[index]))
            .send()
            .await?;

        let body: Value = response.json().await?;
        let count = body.get("count").and_then(|c| c.as_u64()).unwrap_or(0);
        println!("{:<25} {:>10} documents", index, count);
    }

    Ok(())
}

async fn query_malicious_files(client: &Elasticsearch) -> Result<(), Box<dyn std::error::Error>> {
    println!("\n=== Files with Malicious Detections ===");

    let query = json!({
        "query": {
            "range": {
                "last_analysis_stats.malicious": {
                    "gt": 0
                }
            }
        },
        "sort": [
            {
                "last_analysis_stats.malicious": {
                    "order": "desc"
                }
            }
        ],
        "size": 10
    });

    let response = client
        .search(SearchParts::Index(&["vt_reports"]))
        .body(query)
        .send()
        .await?;

    let body: Value = response.json().await?;
    if let Some(hits) = body
        .get("hits")
        .and_then(|h| h.get("hits"))
        .and_then(|h| h.as_array())
    {
        for hit in hits {
            if let Some(source) = hit.get("_source") {
                let hash = source
                    .get("file_hash")
                    .and_then(|h| h.as_str())
                    .unwrap_or("unknown");
                let malicious = source
                    .get("last_analysis_stats")
                    .and_then(|s| s.get("malicious"))
                    .and_then(|m| m.as_u64())
                    .unwrap_or(0);
                let name = source
                    .get("meaningful_name")
                    .and_then(|n| n.as_str())
                    .unwrap_or("unknown");

                println!(
                    "Hash: {} | Detections: {} | Name: {}",
                    &hash[..16],
                    malicious,
                    name
                );
            }
        }
    }

    Ok(())
}

async fn query_engine_stats(client: &Elasticsearch) -> Result<(), Box<dyn std::error::Error>> {
    println!("\n=== Top Detecting Engines ===");

    let query = json!({
        "query": {
            "term": {
                "category": "malicious"
            }
        },
        "aggs": {
            "engines": {
                "terms": {
                    "field": "engine_name",
                    "size": 15
                }
            }
        },
        "size": 0
    });

    let response = client
        .search(SearchParts::Index(&["vt_analysis_results"]))
        .body(query)
        .send()
        .await?;

    let body: Value = response.json().await?;
    if let Some(aggs) = body.get("aggregations") {
        if let Some(engines) = aggs
            .get("engines")
            .and_then(|e| e.get("buckets"))
            .and_then(|b| b.as_array())
        {
            for bucket in engines {
                let engine = bucket
                    .get("key")
                    .and_then(|k| k.as_str())
                    .unwrap_or("unknown");
                let count = bucket
                    .get("doc_count")
                    .and_then(|c| c.as_u64())
                    .unwrap_or(0);
                println!("{:<20} {:>6} malicious detections", engine, count);
            }
        }
    }

    Ok(())
}

async fn query_by_hash(
    client: &Elasticsearch,
    hash: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    println!("\n=== Analysis for Hash: {} ===", hash);

    // First get the main report
    let query = json!({
        "query": {
            "term": {
                "file_hash": hash
            }
        }
    });

    let response = client
        .search(SearchParts::Index(&["vt_reports"]))
        .body(query.clone())
        .send()
        .await?;

    let body: Value = response.json().await?;
    if let Some(hits) = body
        .get("hits")
        .and_then(|h| h.get("hits"))
        .and_then(|h| h.as_array())
    {
        if let Some(hit) = hits.first() {
            if let Some(source) = hit.get("_source") {
                let report_uuid = source
                    .get("report_uuid")
                    .and_then(|u| u.as_str())
                    .unwrap_or("unknown");

                println!("Report UUID: {}", report_uuid);
                if let Some(stats) = source.get("last_analysis_stats") {
                    println!("Detection Stats:");
                    println!(
                        "  Malicious: {}",
                        stats.get("malicious").and_then(|m| m.as_u64()).unwrap_or(0)
                    );
                    println!(
                        "  Suspicious: {}",
                        stats
                            .get("suspicious")
                            .and_then(|s| s.as_u64())
                            .unwrap_or(0)
                    );
                    println!(
                        "  Harmless: {}",
                        stats.get("harmless").and_then(|h| h.as_u64()).unwrap_or(0)
                    );
                    println!(
                        "  Undetected: {}",
                        stats
                            .get("undetected")
                            .and_then(|u| u.as_u64())
                            .unwrap_or(0)
                    );
                }

                // Get malicious detections
                let malicious_query = json!({
                    "query": {
                        "bool": {
                            "must": [
                                {"term": {"report_uuid": report_uuid}},
                                {"term": {"category": "malicious"}}
                            ]
                        }
                    },
                    "size": 20
                });

                let mal_response = client
                    .search(SearchParts::Index(&["vt_analysis_results"]))
                    .body(malicious_query)
                    .send()
                    .await?;

                let mal_body: Value = mal_response.json().await?;
                if let Some(mal_hits) = mal_body
                    .get("hits")
                    .and_then(|h| h.get("hits"))
                    .and_then(|h| h.as_array())
                {
                    if !mal_hits.is_empty() {
                        println!("\nMalicious Detections:");
                        for hit in mal_hits {
                            if let Some(source) = hit.get("_source") {
                                let engine = source
                                    .get("engine_name")
                                    .and_then(|e| e.as_str())
                                    .unwrap_or("unknown");
                                let result = source
                                    .get("result")
                                    .and_then(|r| r.as_str())
                                    .unwrap_or("unknown");
                                println!("  {}: {}", engine, result);
                            }
                        }
                    }
                }
            }
        } else {
            println!("No report found for hash: {}", hash);
        }
    }

    Ok(())
}

async fn query_yara_matches(client: &Elasticsearch) -> Result<(), Box<dyn std::error::Error>> {
    println!("\n=== Files with YARA Rule Matches ===");

    let query = json!({
        "query": {
            "bool": {
                "must": [
                    {"term": {"data_type": "yara"}},
                    {"exists": {"field": "data"}}
                ]
            }
        },
        "size": 10
    });

    let response = client
        .search(SearchParts::Index(&["vt_crowdsourced_data"]))
        .body(query)
        .send()
        .await?;

    let body: Value = response.json().await?;
    if let Some(hits) = body
        .get("hits")
        .and_then(|h| h.get("hits"))
        .and_then(|h| h.as_array())
    {
        for hit in hits {
            if let Some(source) = hit.get("_source") {
                let hash = source
                    .get("file_hash")
                    .and_then(|h| h.as_str())
                    .unwrap_or("unknown");
                let data = source.get("data");

                println!(
                    "Hash: {} | YARA Data: {}",
                    &hash[..16],
                    if data.is_some() { "Available" } else { "None" }
                );
            }
        }
    }

    Ok(())
}
