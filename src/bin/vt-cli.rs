use anyhow::Result;
use virustotal_rs::cli::{
    // config::load_config,
    Cli,
    Commands,
    commands::{download /*, index, report, search, scan, config*/},
};

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
    }

    Ok(())
}
