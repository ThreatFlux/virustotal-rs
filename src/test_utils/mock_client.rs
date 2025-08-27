#[cfg(test)]
use crate::auth::ApiTier;
#[cfg(test)]
use crate::client::{Client, ClientBuilder};
#[cfg(test)]
use crate::error::Result;
#[cfg(test)]
use std::time::Duration;
#[cfg(test)]
use wiremock::MockServer;

#[cfg(test)]
use super::constants::constants;

#[cfg(test)]
/// Mock API client for testing without real API calls
pub struct MockApiClient {
    mock_server: MockServer,
    client: Client,
}

#[cfg(test)]
impl MockApiClient {
    /// Create a new mock API client
    pub async fn new() -> Result<Self> {
        let mock_server = MockServer::start().await;
        let client = ClientBuilder::new()
            .api_key(constants::TEST_API_KEY)
            .tier(ApiTier::Premium)
            .base_url(mock_server.uri())
            .timeout(Duration::from_secs(30))
            .build()?;

        Ok(Self {
            mock_server,
            client,
        })
    }

    /// Create a mock client with custom API key
    pub async fn with_api_key(api_key: &str) -> Result<Self> {
        let mock_server = MockServer::start().await;
        let client = ClientBuilder::new()
            .api_key(api_key)
            .tier(ApiTier::Premium)
            .base_url(mock_server.uri())
            .timeout(Duration::from_secs(30))
            .build()?;

        Ok(Self {
            mock_server,
            client,
        })
    }

    /// Create a public tier mock client
    pub async fn with_public_tier() -> Result<Self> {
        let mock_server = MockServer::start().await;
        let client = ClientBuilder::new()
            .api_key(constants::TEST_API_KEY)
            .tier(ApiTier::Public)
            .base_url(mock_server.uri())
            .timeout(Duration::from_secs(30))
            .build()?;

        Ok(Self {
            mock_server,
            client,
        })
    }

    /// Get reference to the mock server
    pub fn mock_server(&self) -> &MockServer {
        &self.mock_server
    }

    /// Get reference to the client
    pub fn client(&self) -> &Client {
        &self.client
    }
}
