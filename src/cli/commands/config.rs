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
        ConfigCommands::Init => {
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
                }
                Err(e) => {
                    eprintln!("Failed to create configuration file: {}", e);
                    return Err(e);
                }
            }
        }

        ConfigCommands::Show => {
            let config = load_config(config_path).context("Failed to load configuration")?;

            println!("Current configuration:");
            println!("{}", toml::to_string_pretty(&config)?);
        }

        ConfigCommands::Set(set_args) => {
            if dry_run {
                println!(
                    "DRY RUN MODE - Would set {} = {}",
                    set_args.key, set_args.value
                );
                return Ok(());
            }

            let config_file_path = match config_path {
                Some(p) => p,
                None => Config::default_path()?,
            };

            let mut config = if config_file_path.exists() {
                load_config(Some(config_file_path.clone()))?
            } else {
                Config::new()
            };

            set_config_value(&mut config, &set_args.key, &set_args.value)?;

            config.save_to_file(&config_file_path).with_context(|| {
                format!(
                    "Failed to save configuration to {}",
                    config_file_path.display()
                )
            })?;

            println!(
                "✓ Configuration updated: {} = {}",
                set_args.key, set_args.value
            );
        }

        ConfigCommands::Get(get_args) => {
            let config = load_config(config_path).context("Failed to load configuration")?;

            match get_config_value(&config, &get_args.key) {
                Some(value) => println!("{}", value),
                None => {
                    eprintln!("Configuration key not found: {}", get_args.key);
                    std::process::exit(1);
                }
            }
        }

        ConfigCommands::Path => {
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
        }
    }

    Ok(())
}

fn set_config_value(config: &mut Config, key: &str, value: &str) -> Result<()> {
    match key {
        "api_key" => config.api_key = Some(value.to_string()),
        "tier" => config.tier = Some(value.to_string()),

        "elasticsearch.url" => {
            if config.elasticsearch.is_none() {
                config.elasticsearch = Some(Default::default());
            }
            config.elasticsearch.as_mut().unwrap().url = value.to_string();
        }
        "elasticsearch.username" => {
            if config.elasticsearch.is_none() {
                config.elasticsearch = Some(Default::default());
            }
            config.elasticsearch.as_mut().unwrap().username = Some(value.to_string());
        }
        "elasticsearch.password" => {
            if config.elasticsearch.is_none() {
                config.elasticsearch = Some(Default::default());
            }
            config.elasticsearch.as_mut().unwrap().password = Some(value.to_string());
        }
        "elasticsearch.index_prefix" => {
            if config.elasticsearch.is_none() {
                config.elasticsearch = Some(Default::default());
            }
            config.elasticsearch.as_mut().unwrap().index_prefix = Some(value.to_string());
        }
        "elasticsearch.batch_size" => {
            let batch_size: usize = value
                .parse()
                .context("batch_size must be a positive integer")?;
            if config.elasticsearch.is_none() {
                config.elasticsearch = Some(Default::default());
            }
            config.elasticsearch.as_mut().unwrap().batch_size = Some(batch_size);
        }

        "output.format" => {
            if config.output.is_none() {
                config.output = Some(Default::default());
            }
            config.output.as_mut().unwrap().format = Some(value.to_string());
        }
        "output.directory" => {
            if config.output.is_none() {
                config.output = Some(Default::default());
            }
            config.output.as_mut().unwrap().directory = Some(PathBuf::from(value));
        }
        "output.colored" => {
            let colored: bool = value.parse().context("colored must be true or false")?;
            if config.output.is_none() {
                config.output = Some(Default::default());
            }
            config.output.as_mut().unwrap().colored = Some(colored);
        }
        "output.verbose" => {
            let verbose: bool = value.parse().context("verbose must be true or false")?;
            if config.output.is_none() {
                config.output = Some(Default::default());
            }
            config.output.as_mut().unwrap().verbose = Some(verbose);
        }

        "rate_limiting.concurrency" => {
            let concurrency: usize = value
                .parse()
                .context("concurrency must be a positive integer")?;
            if config.rate_limiting.is_none() {
                config.rate_limiting = Some(Default::default());
            }
            config.rate_limiting.as_mut().unwrap().concurrency = Some(concurrency);
        }
        "rate_limiting.delay_ms" => {
            let delay: u64 = value
                .parse()
                .context("delay_ms must be a positive integer")?;
            if config.rate_limiting.is_none() {
                config.rate_limiting = Some(Default::default());
            }
            config.rate_limiting.as_mut().unwrap().delay_ms = Some(delay);
        }
        "rate_limiting.retry_attempts" => {
            let retry_attempts: u32 = value
                .parse()
                .context("retry_attempts must be a positive integer")?;
            if config.rate_limiting.is_none() {
                config.rate_limiting = Some(Default::default());
            }
            config.rate_limiting.as_mut().unwrap().retry_attempts = Some(retry_attempts);
        }

        _ => {
            return Err(anyhow::anyhow!("Unknown configuration key: {}", key));
        }
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
