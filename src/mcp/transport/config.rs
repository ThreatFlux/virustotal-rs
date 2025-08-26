#[cfg(feature = "mcp-oauth")]
use super::http::run_http_server_with_oauth;
use super::{
    http::{run_http_server, run_http_server_with_config},
    stdio::run_stdio_server,
};
#[cfg(feature = "mcp-jwt")]
use crate::mcp::auth::{JwtConfig, JwtManager};
#[cfg(feature = "mcp-oauth")]
use crate::mcp::oauth::OAuthConfig;
use crate::mcp::McpResult;
use std::net::SocketAddr;

/// Configuration for the MCP server
#[derive(Debug, Clone)]
pub struct ServerConfig {
    /// API key for `VirusTotal`
    pub api_key: String,
    /// API tier (Public, Premium, etc.)
    pub api_tier: crate::ApiTier,
    /// Server address for HTTP mode (optional)
    pub http_addr: Option<SocketAddr>,
    /// Enable debug logging
    pub debug: bool,
    /// JWT authentication configuration (optional)
    #[cfg(feature = "mcp-jwt")]
    pub jwt_config: Option<JwtConfig>,
    /// OAuth 2.1 authentication configuration (optional)
    #[cfg(feature = "mcp-oauth")]
    pub oauth_config: Option<OAuthConfig>,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            api_key: String::new(),
            api_tier: crate::ApiTier::Public,
            http_addr: None,
            debug: false,
            #[cfg(feature = "mcp-jwt")]
            jwt_config: None,
            #[cfg(feature = "mcp-oauth")]
            oauth_config: None,
        }
    }
}

impl ServerConfig {
    /// Create a new server configuration
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the API key
    pub fn api_key(mut self, key: impl Into<String>) -> Self {
        self.api_key = key.into();
        self
    }

    /// Set the API tier
    pub fn api_tier(mut self, tier: crate::ApiTier) -> Self {
        self.api_tier = tier;
        self
    }

    /// Set HTTP server address (enables HTTP mode)
    pub fn http_addr(mut self, addr: SocketAddr) -> Self {
        self.http_addr = Some(addr);
        self
    }

    /// Enable debug logging
    pub fn debug(mut self, enabled: bool) -> Self {
        self.debug = enabled;
        self
    }

    /// Enable JWT authentication with configuration
    #[cfg(feature = "mcp-jwt")]
    pub fn with_jwt(mut self, config: JwtConfig) -> Self {
        self.jwt_config = Some(config);
        self
    }

    /// Enable JWT authentication with default configuration
    #[cfg(feature = "mcp-jwt")]
    pub fn enable_jwt(mut self) -> Self {
        self.jwt_config = Some(JwtConfig::default());
        self
    }

    /// Enable JWT authentication with custom secret
    #[cfg(feature = "mcp-jwt")]
    pub fn with_jwt_secret(mut self, secret: impl Into<String>) -> Self {
        self.jwt_config = Some(JwtConfig::new(secret));
        self
    }

    /// Enable OAuth 2.1 authentication with configuration
    #[cfg(feature = "mcp-oauth")]
    pub fn with_oauth(mut self, config: OAuthConfig) -> Self {
        self.oauth_config = Some(config);
        self
    }

    /// Enable OAuth 2.1 authentication with default configuration
    #[cfg(feature = "mcp-oauth")]
    pub fn enable_oauth(mut self) -> Self {
        self.oauth_config = Some(OAuthConfig::default());
        self
    }

    /// Enable OAuth 2.1 authentication with custom client configuration
    #[cfg(feature = "mcp-oauth")]
    pub fn with_oauth_client(
        mut self,
        client_id: impl Into<String>,
        auth_server_url: impl Into<String>,
    ) -> Self {
        self.oauth_config = Some(OAuthConfig::new(client_id, auth_server_url));
        self
    }

    /// Build and run the MCP server
    pub async fn run(self) -> McpResult<()> {
        // Initialize logging
        self.init_logging();

        // Create `VirusTotal` client
        let client = crate::ClientBuilder::new()
            .api_key(self.api_key)
            .tier(self.api_tier)
            .build()
            .map_err(crate::mcp::convert_vt_error)?;

        // Run server in appropriate mode
        match self.http_addr {
            Some(addr) => {
                // Check for OAuth configuration first (takes precedence)
                #[cfg(feature = "mcp-oauth")]
                {
                    if let Some(oauth_config) = self.oauth_config {
                        tracing::info!("OAuth 2.1 Authentication enabled");
                        tracing::info!("Authorization endpoint: /oauth/authorize");
                        tracing::info!("Token endpoint: /oauth/token");
                        tracing::info!("Callback endpoint: /oauth/callback");
                        tracing::info!("Metadata endpoint: /oauth/metadata");
                        return run_http_server_with_oauth(client, addr, oauth_config).await;
                    }
                }

                // Check for JWT configuration
                #[cfg(feature = "mcp-jwt")]
                {
                    if let Some(jwt_config) = self.jwt_config {
                        // Print JWT configuration info
                        let jwt_manager = JwtManager::new(jwt_config.clone());
                        if let Ok(admin_token) = jwt_manager.generate_admin_token("admin") {
                            tracing::info!("JWT Authentication enabled");
                            tracing::info!("Sample admin credentials: admin/admin123");
                            tracing::info!("Sample user credentials: user/user123");
                            tracing::info!("Sample admin token: {}", admin_token);
                            tracing::info!("Use POST /auth/token to authenticate");
                        }
                        return run_http_server_with_config(client, addr, Some(jwt_config)).await;
                    }
                }

                // No authentication - basic server
                run_http_server(client, addr).await
            }
            None => run_stdio_server(client).await,
        }
    }

    /// Initialize tracing/logging
    fn init_logging(&self) {
        use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

        let level = if self.debug {
            tracing::Level::DEBUG
        } else {
            tracing::Level::INFO
        };

        tracing_subscriber::registry()
            .with(
                tracing_subscriber::fmt::layer()
                    .with_target(false)
                    .with_thread_ids(true)
                    .with_level(true)
                    .with_ansi(true),
            )
            .with(EnvFilter::from_default_env().add_directive(level.into()))
            .init();
    }
}

/// Helper function to create and run a server with minimal configuration
pub async fn run_server_simple(api_key: String, stdio: bool) -> McpResult<()> {
    let config = ServerConfig::new()
        .api_key(api_key)
        .api_tier(crate::ApiTier::Public)
        .debug(false);

    let config = if !stdio {
        // Default to localhost:3000 for HTTP mode
        config.http_addr("127.0.0.1:3000".parse().unwrap())
    } else {
        config
    };

    config.run().await
}

/// Helper function to run server with environment variables
pub async fn run_server_from_env() -> McpResult<()> {
    let api_key = std::env::var("VIRUSTOTAL_API_KEY")
        .map_err(|_| anyhow::anyhow!("VIRUSTOTAL_API_KEY environment variable is required"))?;

    let api_tier = match std::env::var("VIRUSTOTAL_API_TIER").as_deref() {
        Ok("Premium") => crate::ApiTier::Premium,
        _ => crate::ApiTier::Public,
    };

    let debug = std::env::var("DEBUG").is_ok();

    let mut config = ServerConfig::new()
        .api_key(api_key)
        .api_tier(api_tier)
        .debug(debug);

    // Check for HTTP mode
    if let Ok(addr_str) = std::env::var("HTTP_ADDR") {
        let addr: SocketAddr = addr_str
            .parse()
            .map_err(|e| anyhow::anyhow!("Invalid HTTP_ADDR: {}", e))?;
        config = config.http_addr(addr);
    }

    // Check for OAuth configuration (takes precedence)
    #[cfg(feature = "mcp-oauth")]
    {
        if std::env::var("ENABLE_OAUTH").is_ok() {
            let client_id = std::env::var("OAUTH_CLIENT_ID")
                .unwrap_or_else(|_| "virustotal-mcp-client".to_string());
            let auth_server_url = std::env::var("OAUTH_AUTH_SERVER_URL")
                .unwrap_or_else(|_| "http://localhost:8080".to_string());

            let mut oauth_config = OAuthConfig::new(client_id, auth_server_url);

            if let Ok(client_secret) = std::env::var("OAUTH_CLIENT_SECRET") {
                oauth_config = oauth_config.with_client_secret(client_secret);
            }

            if let Ok(redirect_uri) = std::env::var("OAUTH_REDIRECT_URI") {
                oauth_config = oauth_config.with_redirect_uri(redirect_uri);
            }

            if let Ok(scopes_str) = std::env::var("OAUTH_SCOPES") {
                let scopes: Vec<String> = scopes_str
                    .split(',')
                    .map(|s| s.trim().to_string())
                    .collect();
                oauth_config = oauth_config.with_scopes(scopes);
            }

            config = config.with_oauth(oauth_config);
        }
    }

    // Check for JWT configuration
    #[cfg(feature = "mcp-jwt")]
    {
        if std::env::var("ENABLE_JWT").is_ok() {
            let jwt_config = if let Ok(secret) = std::env::var("JWT_SECRET") {
                JwtConfig::new(secret)
            } else {
                JwtConfig::default()
            };

            let jwt_config = if let Ok(expiry_str) = std::env::var("JWT_EXPIRY_SECONDS") {
                if let Ok(expiry) = expiry_str.parse::<u64>() {
                    jwt_config.with_expiration(expiry)
                } else {
                    jwt_config
                }
            } else {
                jwt_config
            };

            config = config.with_jwt(jwt_config);
        }
    }

    config.run().await
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn test_server_config_builder() {
        let config = ServerConfig::new()
            .api_key("test_key")
            .api_tier(crate::ApiTier::Premium)
            .http_addr(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 3000))
            .debug(true);

        assert_eq!(config.api_key, "test_key");
        assert_eq!(config.api_tier, crate::ApiTier::Premium);
        assert_eq!(
            config.http_addr,
            Some(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 3000))
        );
        assert!(config.debug);
    }

    #[test]
    fn test_default_config() {
        let config = ServerConfig::default();
        assert!(config.api_key.is_empty());
        assert_eq!(config.api_tier, crate::ApiTier::Public);
        assert!(config.http_addr.is_none());
        assert!(!config.debug);
    }
}
