use crate::cli::config::{init_config, load_config, Config};
use anyhow::{Context, Result};
use clap::{Args, Subcommand};
use std::path::PathBuf;

#[derive(Args, Debug)]
pub struct ConfigArgs {
    #[command(subcommand)]
    pub command: ConfigCommands,
}

#[derive(Subcommand, Debug)]
pub enum ConfigCommands {
    /// Initialize configuration file with defaults
    Init,
    /// Show current configuration
    Show,
    /// Set configuration value
    Set(SetArgs),
    /// Get configuration value
    Get(GetArgs),
    /// Show configuration file path
    Path,
}

#[derive(Args, Debug)]
pub struct SetArgs {
    /// Configuration key (e.g., api_key, tier, elasticsearch.url)
    pub key: String,
    /// Configuration value
    pub value: String,
}

#[derive(Args, Debug)]
pub struct GetArgs {
    /// Configuration key to retrieve
    pub key: String,
}

pub async fn execute(
    args: ConfigArgs,
    config_path: Option<PathBuf>,
    verbose: bool,
    dry_run: bool,
) -> Result<()> {
    match args.command {
        ConfigCommands::Init => handle_init(verbose, dry_run),
        ConfigCommands::Show => handle_show(config_path).await,
        ConfigCommands::Set(set_args) => handle_set(set_args, config_path, dry_run).await,
        ConfigCommands::Get(get_args) => handle_get(get_args, config_path).await,
        ConfigCommands::Path => handle_path(config_path, verbose),
    }
}

fn handle_init(verbose: bool, dry_run: bool) -> Result<()> {
    if dry_run {
        println!("DRY RUN MODE - Would initialize config file");
        return Ok(());
    }

    match init_config() {
        Ok(path) => {
            println!("✓ Configuration file created at: {}", path.display());
            if verbose {
                println!("Edit this file to customize your settings.");
            }
            Ok(())
        }
        Err(e) => {
            eprintln!("Failed to create configuration file: {}", e);
            Err(e)
        }
    }
}

async fn handle_show(config_path: Option<PathBuf>) -> Result<()> {
    let config = load_config(config_path).context("Failed to load configuration")?;
    println!("Current configuration:");
    println!("{}", toml::to_string_pretty(&config)?);
    Ok(())
}

async fn handle_set(set_args: SetArgs, config_path: Option<PathBuf>, dry_run: bool) -> Result<()> {
    if dry_run {
        println!(
            "DRY RUN MODE - Would set {} = {}",
            set_args.key, set_args.value
        );
        return Ok(());
    }

    let config_file_path = get_config_file_path(config_path)?;
    let mut config = load_or_create_config(&config_file_path)?;
    
    set_config_value(&mut config, &set_args.key, &set_args.value)?;
    save_config_and_confirm(&config, &config_file_path, &set_args)?;
    
    Ok(())
}

fn get_config_file_path(config_path: Option<PathBuf>) -> Result<PathBuf> {
    match config_path {
        Some(p) => Ok(p),
        None => Config::default_path(),
    }
}

fn load_or_create_config(config_file_path: &PathBuf) -> Result<Config> {
    if config_file_path.exists() {
        load_config(Some(config_file_path.clone()))
    } else {
        Ok(Config::new())
    }
}

fn save_config_and_confirm(config: &Config, config_file_path: &PathBuf, set_args: &SetArgs) -> Result<()> {
    config.save_to_file(config_file_path).with_context(|| {
        format!(
            "Failed to save configuration to {}",
            config_file_path.display()
        )
    })?;

    println!(
        "✓ Configuration updated: {} = {}",
        set_args.key, set_args.value
    );
    Ok(())
}

async fn handle_get(get_args: GetArgs, config_path: Option<PathBuf>) -> Result<()> {
    let config = load_config(config_path).context("Failed to load configuration")?;

    match get_config_value(&config, &get_args.key) {
        Some(value) => {
            println!("{}", value);
            Ok(())
        }
        None => {
            eprintln!("Configuration key not found: {}", get_args.key);
            std::process::exit(1);
        }
    }
}

fn handle_path(config_path: Option<PathBuf>, verbose: bool) -> Result<()> {
    let path = match config_path {
        Some(p) => p,
        None => Config::default_path()?,
    };

    println!("{}", path.display());

    if verbose {
        if path.exists() {
            println!("(file exists)");
        } else {
            println!("(file does not exist - run 'vt-cli config init' to create)");
        }
    }
    Ok(())
}

fn set_config_value(config: &mut Config, key: &str, value: &str) -> Result<()> {
    if key.starts_with("elasticsearch.") {
        set_elasticsearch_config(config, key, value)
    } else if key.starts_with("output.") {
        set_output_config(config, key, value)
    } else if key.starts_with("rate_limiting.") {
        set_rate_limiting_config(config, key, value)
    } else {
        set_general_config(config, key, value)
    }
}

fn set_general_config(config: &mut Config, key: &str, value: &str) -> Result<()> {
    match key {
        "api_key" => {
            config.api_key = Some(value.to_string());
            Ok(())
        }
        "tier" => {
            config.tier = Some(value.to_string());
            Ok(())
        }
        _ => Err(anyhow::anyhow!("Unknown configuration key: {}", key)),
    }
}

fn set_elasticsearch_config(config: &mut Config, key: &str, value: &str) -> Result<()> {
    if config.elasticsearch.is_none() {
        config.elasticsearch = Some(Default::default());
    }
    let elasticsearch = config.elasticsearch.as_mut().unwrap();

    match key {
        "elasticsearch.url" => {
            elasticsearch.url = value.to_string();
        }
        "elasticsearch.username" => {
            elasticsearch.username = Some(value.to_string());
        }
        "elasticsearch.password" => {
            elasticsearch.password = Some(value.to_string());
        }
        "elasticsearch.index_prefix" => {
            elasticsearch.index_prefix = Some(value.to_string());
        }
        "elasticsearch.batch_size" => {
            let batch_size: usize = value
                .parse()
                .context("batch_size must be a positive integer")?;
            elasticsearch.batch_size = Some(batch_size);
        }
        _ => return Err(anyhow::anyhow!("Unknown elasticsearch configuration key: {}", key)),
    }

    Ok(())
}

fn set_output_config(config: &mut Config, key: &str, value: &str) -> Result<()> {
    if config.output.is_none() {
        config.output = Some(Default::default());
    }
    let output = config.output.as_mut().unwrap();

    match key {
        "output.format" => {
            output.format = Some(value.to_string());
        }
        "output.directory" => {
            output.directory = Some(PathBuf::from(value));
        }
        "output.colored" => {
            let colored: bool = value.parse().context("colored must be true or false")?;
            output.colored = Some(colored);
        }
        "output.verbose" => {
            let verbose: bool = value.parse().context("verbose must be true or false")?;
            output.verbose = Some(verbose);
        }
        _ => return Err(anyhow::anyhow!("Unknown output configuration key: {}", key)),
    }

    Ok(())
}

fn set_rate_limiting_config(config: &mut Config, key: &str, value: &str) -> Result<()> {
    if config.rate_limiting.is_none() {
        config.rate_limiting = Some(Default::default());
    }
    let rate_limiting = config.rate_limiting.as_mut().unwrap();

    match key {
        "rate_limiting.concurrency" => {
            let concurrency: usize = value
                .parse()
                .context("concurrency must be a positive integer")?;
            rate_limiting.concurrency = Some(concurrency);
        }
        "rate_limiting.delay_ms" => {
            let delay: u64 = value
                .parse()
                .context("delay_ms must be a positive integer")?;
            rate_limiting.delay_ms = Some(delay);
        }
        "rate_limiting.retry_attempts" => {
            let retry_attempts: u32 = value
                .parse()
                .context("retry_attempts must be a positive integer")?;
            rate_limiting.retry_attempts = Some(retry_attempts);
        }
        _ => return Err(anyhow::anyhow!("Unknown rate_limiting configuration key: {}", key)),
    }

    Ok(())
}

fn get_config_value(config: &Config, key: &str) -> Option<String> {
    match key {
        "api_key" => config.api_key.clone(),
        "tier" => config.tier.clone(),

        "elasticsearch.url" => config.elasticsearch.as_ref()?.url.clone().into(),
        "elasticsearch.username" => config.elasticsearch.as_ref()?.username.clone(),
        "elasticsearch.password" => config.elasticsearch.as_ref()?.password.clone(),
        "elasticsearch.index_prefix" => config.elasticsearch.as_ref()?.index_prefix.clone(),
        "elasticsearch.batch_size" => config
            .elasticsearch
            .as_ref()?
            .batch_size
            .map(|b| b.to_string()),

        "output.format" => config.output.as_ref()?.format.clone(),
        "output.directory" => config
            .output
            .as_ref()?
            .directory
            .as_ref()
            .map(|d| d.to_string_lossy().to_string()),
        "output.colored" => config.output.as_ref()?.colored.map(|c| c.to_string()),
        "output.verbose" => config.output.as_ref()?.verbose.map(|v| v.to_string()),

        "rate_limiting.concurrency" => config
            .rate_limiting
            .as_ref()?
            .concurrency
            .map(|c| c.to_string()),
        "rate_limiting.delay_ms" => config
            .rate_limiting
            .as_ref()?
            .delay_ms
            .map(|d| d.to_string()),
        "rate_limiting.retry_attempts" => config
            .rate_limiting
            .as_ref()?
            .retry_attempts
            .map(|r| r.to_string()),

        _ => None,
    }
}

// Implement Default for config structs
impl Default for crate::cli::config::ElasticsearchConfig {
    fn default() -> Self {
        Self {
            url: "http://localhost:9200".to_string(),
            username: None,
            password: None,
            index_prefix: Some("vt".to_string()),
            batch_size: Some(100),
        }
    }
}

impl Default for crate::cli::config::OutputConfig {
    fn default() -> Self {
        Self {
            format: Some("json".to_string()),
            directory: Some(PathBuf::from("./output")),
            colored: Some(true),
            verbose: Some(false),
        }
    }
}

impl Default for crate::cli::config::RateLimitConfig {
    fn default() -> Self {
        Self {
            concurrency: Some(5),
            delay_ms: Some(100),
            retry_attempts: Some(3),
        }
    }
}
