use crate::auth::{ApiKey, ApiTier};
use crate::error::{ApiErrorResponse, Error, Result};
use crate::rate_limit::RateLimiter;
use reqwest::{Client as ReqwestClient, Method, RequestBuilder, Response};
use serde::{de::DeserializeOwned, Serialize};
use std::time::Duration;
use url::Url;

const BASE_URL: &str = "https://www.virustotal.com/api/v3/";
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Clone)]
pub struct Client {
    http_client: ReqwestClient,
    api_key: ApiKey,
    rate_limiter: RateLimiter,
    base_url: Url,
}

impl Client {
    pub fn new(api_key: ApiKey, tier: ApiTier) -> Result<Self> {
        let http_client = ReqwestClient::builder()
            .timeout(DEFAULT_TIMEOUT)
            .user_agent(format!("virustotal-rs/{}", env!("CARGO_PKG_VERSION")))
            .build()
            .map_err(Error::Http)?;

        let base_url = Url::parse(BASE_URL).expect("Invalid base URL");
        let rate_limiter = RateLimiter::new(tier);

        Ok(Self {
            http_client,
            api_key,
            rate_limiter,
            base_url,
        })
    }

    pub fn http_client(&self) -> &ReqwestClient {
        &self.http_client
    }

    pub fn api_key(&self) -> &str {
        self.api_key.as_str()
    }

    pub fn base_url(&self) -> &str {
        self.base_url.as_str()
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Result<Self> {
        self.http_client = ReqwestClient::builder()
            .timeout(timeout)
            .user_agent(format!("virustotal-rs/{}", env!("CARGO_PKG_VERSION")))
            .build()
            .map_err(Error::Http)?;
        Ok(self)
    }

    pub fn with_base_url(mut self, base_url: &str) -> Result<Self> {
        self.base_url = Url::parse(base_url)
            .map_err(|e| Error::BadRequest(format!("Invalid base URL: {}", e)))?;
        Ok(self)
    }

    pub async fn get<T>(&self, endpoint: &str) -> Result<T>
    where
        T: DeserializeOwned,
    {
        let response = self.request(Method::GET, endpoint, None::<()>).await?;
        self.parse_response(response).await
    }

    pub async fn post<B, T>(&self, endpoint: &str, body: &B) -> Result<T>
    where
        B: Serialize,
        T: DeserializeOwned,
    {
        let response = self.request(Method::POST, endpoint, Some(body)).await?;
        self.parse_response(response).await
    }

    pub async fn post_form<T>(
        &self,
        endpoint: &str,
        form: &std::collections::HashMap<&str, &str>,
    ) -> Result<T>
    where
        T: DeserializeOwned,
    {
        self.rate_limiter.check_rate_limit().await?;

        let url = self
            .base_url
            .join(endpoint)
            .map_err(|e| Error::BadRequest(format!("Invalid endpoint: {}", e)))?;

        let request = self
            .http_client
            .request(Method::POST, url)
            .header("x-apikey", self.api_key.as_str())
            .header("Accept", "application/json")
            .form(form);

        let response = request.send().await.map_err(Error::Http)?;
        self.parse_response(response).await
    }

    pub async fn put<B, T>(&self, endpoint: &str, body: &B) -> Result<T>
    where
        B: Serialize,
        T: DeserializeOwned,
    {
        let response = self.request(Method::PUT, endpoint, Some(body)).await?;
        self.parse_response(response).await
    }

    pub async fn delete(&self, endpoint: &str) -> Result<()> {
        let response = self.request(Method::DELETE, endpoint, None::<()>).await?;
        if response.status().is_success() {
            Ok(())
        } else {
            self.handle_error_response(response).await
        }
    }

    pub async fn delete_with_header(
        &self,
        endpoint: &str,
        header_name: &str,
        header_value: &str,
    ) -> Result<()> {
        self.rate_limiter.check_rate_limit().await?;

        let url = self
            .base_url
            .join(endpoint)
            .map_err(|e| Error::BadRequest(format!("Invalid endpoint: {}", e)))?;

        let request = self
            .http_client
            .request(Method::DELETE, url)
            .header("x-apikey", self.api_key.as_str())
            .header("Accept", "application/json")
            .header(header_name, header_value);

        let response = request.send().await.map_err(Error::Http)?;

        if response.status().is_success() {
            Ok(())
        } else {
            self.handle_error_response(response).await
        }
    }

    pub async fn patch<B, T>(&self, endpoint: &str, body: &B) -> Result<T>
    where
        B: Serialize,
        T: DeserializeOwned,
    {
        let response = self.request(Method::PATCH, endpoint, Some(body)).await?;
        self.parse_response(response).await
    }

    pub async fn delete_with_body<B>(&self, endpoint: &str, body: &B) -> Result<()>
    where
        B: Serialize,
    {
        let response = self.request(Method::DELETE, endpoint, Some(body)).await?;
        if response.status().is_success() {
            Ok(())
        } else {
            self.handle_error_response(response).await
        }
    }

    pub async fn get_raw(&self, endpoint: &str) -> Result<String> {
        let response = self.request_raw(Method::GET, endpoint).await?;
        if response.status().is_success() {
            response.text().await.map_err(Error::Http)
        } else {
            self.handle_error_response(response).await
        }
    }

    pub async fn get_bytes(&self, endpoint: &str) -> Result<Vec<u8>> {
        let response = self.request_raw(Method::GET, endpoint).await?;
        if response.status().is_success() {
            response
                .bytes()
                .await
                .map_err(Error::Http)
                .map(|b| b.to_vec())
        } else {
            self.handle_error_response(response).await
        }
    }

    pub async fn post_multipart<T>(
        &self,
        endpoint: &str,
        form: reqwest::multipart::Form,
    ) -> Result<T>
    where
        T: DeserializeOwned,
    {
        self.rate_limiter.check_rate_limit().await?;

        let url = self
            .base_url
            .join(endpoint)
            .map_err(|e| Error::BadRequest(format!("Invalid endpoint: {}", e)))?;

        let request = self
            .http_client
            .request(Method::POST, url)
            .header("x-apikey", self.api_key.as_str())
            .header("Accept", "application/json")
            .multipart(form);

        let response = request.send().await.map_err(Error::Http)?;
        self.parse_response(response).await
    }

    async fn request<B>(&self, method: Method, endpoint: &str, body: Option<B>) -> Result<Response>
    where
        B: Serialize,
    {
        self.rate_limiter.check_rate_limit().await?;

        let url = self
            .base_url
            .join(endpoint)
            .map_err(|e| Error::BadRequest(format!("Invalid endpoint: {}", e)))?;

        let mut request = self.build_request(method, url);

        if let Some(body) = body {
            request = request.json(&body);
        }

        let response = request.send().await.map_err(Error::Http)?;
        Ok(response)
    }

    async fn request_raw(&self, method: Method, endpoint: &str) -> Result<Response> {
        self.rate_limiter.check_rate_limit().await?;

        let url = self
            .base_url
            .join(endpoint)
            .map_err(|e| Error::BadRequest(format!("Invalid endpoint: {}", e)))?;

        let request = self.build_request_raw(method, url);
        let response = request.send().await.map_err(Error::Http)?;
        Ok(response)
    }

    fn build_request(&self, method: Method, url: Url) -> RequestBuilder {
        self.http_client
            .request(method, url)
            .header("x-apikey", self.api_key.as_str())
            .header("Accept", "application/json")
    }

    fn build_request_raw(&self, method: Method, url: Url) -> RequestBuilder {
        self.http_client
            .request(method, url)
            .header("x-apikey", self.api_key.as_str())
    }

    async fn parse_response<T>(&self, response: Response) -> Result<T>
    where
        T: DeserializeOwned,
    {
        let status = response.status();

        if status.is_success() {
            let text = response.text().await.map_err(Error::Http)?;
            serde_json::from_str(&text).map_err(Error::Json)
        } else {
            self.handle_error_response(response).await
        }
    }

    async fn handle_error_response<T>(&self, response: Response) -> Result<T> {
        let status = response.status();
        let text = response.text().await.map_err(Error::Http)?;

        if let Ok(error_response) = serde_json::from_str::<ApiErrorResponse>(&text) {
            Err(Error::from_response(status, error_response.error))
        } else {
            Err(Error::Unknown(format!(
                "HTTP {}: {}",
                status,
                text.chars().take(200).collect::<String>()
            )))
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ApiResponse<T> {
    pub data: T,
}

#[derive(Debug, Clone)]
pub struct ClientBuilder {
    api_key: Option<ApiKey>,
    tier: ApiTier,
    timeout: Option<Duration>,
    base_url: Option<String>,
}

impl ClientBuilder {
    pub fn new() -> Self {
        Self {
            api_key: None,
            tier: ApiTier::Public,
            timeout: None,
            base_url: None,
        }
    }

    pub fn api_key(mut self, key: impl Into<ApiKey>) -> Self {
        self.api_key = Some(key.into());
        self
    }

    pub fn tier(mut self, tier: ApiTier) -> Self {
        self.tier = tier;
        self
    }

    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }

    pub fn base_url(mut self, url: impl Into<String>) -> Self {
        self.base_url = Some(url.into());
        self
    }

    pub fn build(self) -> Result<Client> {
        let api_key = self
            .api_key
            .ok_or_else(|| Error::BadRequest("API key is required".to_string()))?;

        let mut client = Client::new(api_key, self.tier)?;

        if let Some(timeout) = self.timeout {
            client = client.with_timeout(timeout)?;
        }

        if let Some(base_url) = self.base_url {
            client = client.with_base_url(&base_url)?;
        }

        Ok(client)
    }
}

impl Default for ClientBuilder {
    fn default() -> Self {
        Self::new()
    }
}

use serde::Deserialize;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_client_builder() {
        let result = ClientBuilder::new()
            .api_key("test_key")
            .tier(ApiTier::Premium)
            .timeout(Duration::from_secs(60))
            .build();

        assert!(result.is_ok());
    }

    #[test]
    fn test_client_builder_missing_api_key() {
        let result = ClientBuilder::new().build();
        assert!(result.is_err());
    }
}
