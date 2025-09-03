use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub api_key: Option<String>,
    pub tier: Option<String>,
    pub elasticsearch: Option<ElasticsearchConfig>,
    pub output: Option<OutputConfig>,
    pub rate_limiting: Option<RateLimitConfig>,
    pub defaults: Option<HashMap<String, String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ElasticsearchConfig {
    pub url: String,
    pub username: Option<String>,
    pub password: Option<String>,
    pub index_prefix: Option<String>,
    pub batch_size: Option<usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutputConfig {
    pub format: Option<String>,
    pub directory: Option<PathBuf>,
    pub colored: Option<bool>,
    pub verbose: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitConfig {
    pub concurrency: Option<usize>,
    pub delay_ms: Option<u64>,
    pub retry_attempts: Option<u32>,
}

impl Config {
    pub fn new() -> Self {
        Self {
            api_key: None,
            tier: None,
            elasticsearch: None,
            output: None,
            rate_limiting: None,
            defaults: None,
        }
    }

    pub fn load_from_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        let content = fs::read_to_string(&path)
            .with_context(|| format!("Failed to read config file: {}", path.as_ref().display()))?;

        let config: Config = toml::from_str(&content)
            .with_context(|| format!("Failed to parse config file: {}", path.as_ref().display()))?;

        Ok(config)
    }

    pub fn save_to_file<P: AsRef<Path>>(&self, path: P) -> Result<()> {
        let content = toml::to_string_pretty(self).context("Failed to serialize config")?;

        if let Some(parent) = path.as_ref().parent() {
            fs::create_dir_all(parent).with_context(|| {
                format!("Failed to create config directory: {}", parent.display())
            })?;
        }

        fs::write(&path, content)
            .with_context(|| format!("Failed to write config file: {}", path.as_ref().display()))?;

        Ok(())
    }

    pub fn default_path() -> Result<PathBuf> {
        let config_dir = dirs::config_dir()
            .context("Failed to determine config directory")?
            .join("vt-cli");

        Ok(config_dir.join("config.toml"))
    }

    pub fn merge_with_env_and_args(&mut self, api_key: Option<String>, tier: Option<String>) {
        // Environment variables take precedence over config file
        if let Ok(env_api_key) = std::env::var("VTI_API_KEY") {
            self.api_key = Some(env_api_key);
        }

        if let Ok(env_tier) = std::env::var("VTI_TIER") {
            self.tier = Some(env_tier);
        }

        // Command line arguments take highest precedence
        if let Some(key) = api_key {
            self.api_key = Some(key);
        }

        if let Some(t) = tier {
            self.tier = Some(t);
        }
    }

    pub fn get_api_key(&self) -> Option<&str> {
        self.api_key.as_deref()
    }

    pub fn get_tier(&self) -> &str {
        self.tier.as_deref().unwrap_or("public")
    }

    pub fn get_elasticsearch_url(&self) -> &str {
        self.elasticsearch
            .as_ref()
            .map(|es| es.url.as_str())
            .unwrap_or("http://localhost:9200")
    }

    pub fn get_batch_size(&self) -> usize {
        self.elasticsearch
            .as_ref()
            .and_then(|es| es.batch_size)
            .unwrap_or(100)
    }

    pub fn get_concurrency(&self) -> usize {
        self.rate_limiting
            .as_ref()
            .and_then(|rl| rl.concurrency)
            .unwrap_or(5)
    }

    pub fn is_colored(&self) -> bool {
        self.output
            .as_ref()
            .and_then(|out| out.colored)
            .unwrap_or(true)
    }
}

impl Default for Config {
    fn default() -> Self {
        Self::new()
    }
}

pub fn load_config(config_path: Option<PathBuf>) -> Result<Config> {
    let path = match config_path {
        Some(p) => p,
        None => {
            let default_path = Config::default_path()?;
            if !default_path.exists() {
                return Ok(Config::new());
            }
            default_path
        }
    };

    Config::load_from_file(path)
}

pub fn init_config() -> Result<PathBuf> {
    let path = Config::default_path()?;

    if path.exists() {
        return Err(anyhow::anyhow!(
            "Config file already exists at: {}",
            path.display()
        ));
    }

    let config = Config {
        api_key: None,
        tier: Some("public".to_string()),
        elasticsearch: Some(ElasticsearchConfig {
            url: "http://localhost:9200".to_string(),
            username: None,
            password: None,
            index_prefix: Some("vt".to_string()),
            batch_size: Some(100),
        }),
        output: Some(OutputConfig {
            format: Some("json".to_string()),
            directory: Some(PathBuf::from("./output")),
            colored: Some(true),
            verbose: Some(false),
        }),
        rate_limiting: Some(RateLimitConfig {
            concurrency: Some(5),
            delay_ms: Some(100),
            retry_attempts: Some(3),
        }),
        defaults: None,
    };

    config.save_to_file(&path)?;
    Ok(path)
}
