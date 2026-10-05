//! Offline regressions based on the documented VirusTotal API v3 wire contracts.

use virustotal_rs::{ApiTier, Client, ClientBuilder};
use wiremock::MockServer;

#[path = "current_api/analyses.rs"]
mod analyses;
#[path = "current_api/search_urls.rs"]
mod search_urls;

fn client(server: &MockServer) -> Client {
    ClientBuilder::new()
        .api_key("offline-fixture")
        .tier(ApiTier::Premium)
        .base_url(format!("{}/api/v3/", server.uri()))
        .build()
        .unwrap()
}
