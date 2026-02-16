use anyhow::Result;
use virustotal_rs::cli::{
    commands::{download, user /*, index, report, search, scan, config*/},
    utils::setup_client_with_encryption,
    // config::load_config,
    Cli,
    Commands,
};

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
            // Create VT client with encryption support
            let client =
                setup_client_with_encryption(cli.api_key.clone(), &cli.tier, cli.insecure)?;

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
