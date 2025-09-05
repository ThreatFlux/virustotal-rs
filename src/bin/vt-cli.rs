use anyhow::Result;
use virustotal_rs::cli::{
    commands::{download, user /*, index, report, search, scan, config*/},
    // config::load_config,
    Cli,
    Commands,
};
use virustotal_rs::{ApiKey, ApiTier, Client};

#[cfg(feature = "mcp")]
use virustotal_rs::cli::commands::mcp;

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::new();

    // Execute the appropriate command
    match &cli.command {
        Commands::Download(args) => {
            download::execute(
                args.clone(),
                cli.api_key.clone(),
                &cli.tier,
                cli.verbose,
                cli.dry_run,
            )
            .await?;
        }
        Commands::User(cmd) => {
            // Get API key from CLI arg or environment variable
            let api_key = cli
                .api_key
                .clone()
                .or_else(|| std::env::var("VTI_API_KEY").ok())
                .ok_or_else(|| {
                    anyhow::anyhow!("API key required. Use --api-key or set VTI_API_KEY")
                })?;

            // Determine API tier
            let tier = match cli.tier.to_lowercase().as_str() {
                "premium" | "private" => ApiTier::Premium,
                _ => ApiTier::Public,
            };

            // Create VT client
            let client = Client::new(ApiKey::new(api_key), tier).expect("Failed to create client");

            // Execute user command
            user::execute(&client, cmd.clone())
                .await
                .map_err(|e| anyhow::anyhow!("User command failed: {}", e))?;
        }
        #[cfg(feature = "mcp")]
        Commands::Mcp(cmd) => {
            // Execute MCP command
            mcp::execute(cmd.clone(), cli.verbose)
                .await
                .map_err(|e| anyhow::anyhow!("MCP command failed: {}", e))?;
        }
    }

    Ok(())
}
