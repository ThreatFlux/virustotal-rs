pub mod commands;
pub mod config;
pub mod utils;

use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(name = "vt-cli")]
#[command(about = "A comprehensive CLI tool for the VirusTotal Rust SDK")]
#[command(version)]
pub struct Cli {
    /// API key (can also be set via VTI_API_KEY environment variable)
    #[arg(short = 'k', long, global = true)]
    pub api_key: Option<String>,

    /// API tier (public or premium)
    #[arg(short = 't', long, default_value = "public", global = true)]
    pub tier: String,

    /// Verbose output
    #[arg(short, long, global = true)]
    pub verbose: bool,

    /// Configuration file path
    #[arg(short = 'c', long, global = true)]
    pub config: Option<PathBuf>,

    /// Disable colored output
    #[arg(long, global = true)]
    pub no_color: bool,

    /// Enable dry-run mode (show what would be done without executing)
    #[arg(long, global = true)]
    pub dry_run: bool,

    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Download files and/or reports from VirusTotal
    Download(commands::download::DownloadArgs),
    // /// Index reports to Elasticsearch
    // Index(commands::index::IndexArgs),
    // /// Get report for a hash
    // Report(commands::report::ReportArgs),
    // /// Search VirusTotal for files
    // Search(commands::search::SearchArgs),
    // /// Submit files for scanning
    // Scan(commands::scan::ScanArgs),
    // /// Configuration management
    // Config(commands::config::ConfigArgs),
}

impl Cli {
    pub fn new() -> Self {
        Self::parse()
    }
}

impl Default for Cli {
    fn default() -> Self {
        Self::new()
    }
}
