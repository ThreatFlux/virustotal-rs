use virustotal_rs::{ApiTier, ClientBuilder};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let api_key = std::env::var("VIRUSTOTAL_API_KEY")?;
    let hash = std::env::var("VT_FILE_HASH")
        .unwrap_or_else(|_| "44d88612fea8a8f36de82e1278abb02f".to_owned());

    let client = ClientBuilder::new()
        .api_key(api_key)
        .tier(ApiTier::Public)
        .build()?;

    let report = client.files().get(&hash).await?;
    println!(
        "{}: {:?}",
        report.object.id, report.object.attributes.type_description
    );

    Ok(())
}
