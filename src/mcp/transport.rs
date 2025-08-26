//! Transport layer implementations for MCP server
//!
//! This module provides both STDIO and HTTP transport modes for the MCP server,
//! allowing it to be used locally or remotely. Supports optional JWT authentication
//! for HTTP mode.

use crate::mcp::server::VtMcpServer;
use crate::mcp::McpResult;
use crate::Client;
use serde_json::{json, Value as JsonValue};
use std::net::SocketAddr;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader as TokioBufReader};

#[cfg(feature = "mcp-jwt")]
use crate::mcp::auth::{JwtAuthLayer, JwtClaims, JwtConfig, JwtManager};

#[cfg(feature = "mcp-oauth")]
use crate::mcp::oauth::{
    AuthServerMetadata, CallbackParams, OAuthClaims, OAuthConfig, OAuthError, OAuthState,
};
#[cfg(feature = "mcp-oauth")]
use axum::extract::Query;

#[cfg(any(feature = "mcp-jwt", feature = "mcp-oauth"))]
use tower_http::cors::CorsLayer;

#[cfg(feature = "mcp-jwt")]
type MaybeJwtConfig = JwtConfig;
#[cfg(not(feature = "mcp-jwt"))]
type MaybeJwtConfig = ();

#[cfg(feature = "mcp-oauth")]
type MaybeOAuthConfig = OAuthConfig;
#[cfg(not(feature = "mcp-oauth"))]
type MaybeOAuthConfig = ();

/// Simple STDIO MCP server
pub async fn run_stdio_server(client: Client) -> McpResult<()> {
    tracing::info!("Starting `VirusTotal` MCP server with STDIO transport");

    let server = VtMcpServer::new(client);
    let stdin = tokio::io::stdin();
    let mut stdout = tokio::io::stdout();
    let mut reader = TokioBufReader::new(stdin);
    let mut line = String::new();

    // Send initial server info
    let init_response = json!({
        "jsonrpc": "2.0",
        "result": {
            "capabilities": server.get_server_capabilities(),
            "serverInfo": server.get_server_info()
        }
    });
    stdout
        .write_all(format!("{}\n", init_response).as_bytes())
        .await?;
    stdout.flush().await?;

    loop {
        line.clear();
        match reader.read_line(&mut line).await {
            Ok(0) => break, // EOF
            Ok(_) => {
                if let Ok(request) = serde_json::from_str::<JsonValue>(line.trim()) {
                    let response = handle_request(&server, request).await;
                    stdout
                        .write_all(format!("{}\n", response).as_bytes())
                        .await?;
                    stdout.flush().await?;
                }
            }
            Err(e) => {
                tracing::error!("Error reading from stdin: {}", e);
                break;
            }
        }
    }

    Ok(())
}

/// Simple HTTP MCP server
pub async fn run_http_server(client: Client, addr: SocketAddr) -> McpResult<()> {
    run_http_server_with_config(client, addr, None).await
}

/// HTTP MCP server with optional authentication
pub async fn run_http_server_with_config(
    client: Client,
    addr: SocketAddr,
    jwt_config: Option<MaybeJwtConfig>,
) -> McpResult<()> {
    run_http_server_with_auth(client, addr, jwt_config, None).await
}

/// HTTP MCP server with OAuth authentication
#[cfg(feature = "mcp-oauth")]
pub async fn run_http_server_with_oauth(
    client: Client,
    addr: SocketAddr,
    oauth_config: OAuthConfig,
) -> McpResult<()> {
    run_http_server_with_auth(client, addr, None, Some(oauth_config)).await
}

/// HTTP MCP server with both JWT and OAuth support
async fn run_http_server_with_auth(
    client: Client,
    addr: SocketAddr,
    jwt_config: Option<MaybeJwtConfig>,
    oauth_config: Option<MaybeOAuthConfig>,
) -> McpResult<()> {
    tracing::info!(
        "Starting `VirusTotal` MCP server with HTTP transport on {}",
        addr
    );

    #[cfg(not(feature = "mcp-jwt"))]
    let _ = jwt_config;
    #[cfg(not(feature = "mcp-oauth"))]
    let _ = oauth_config;

    let server = VtMcpServer::new(client);

    #[cfg(feature = "axum")]
    {
        #[cfg(feature = "mcp-oauth")]
        use axum::routing::get;
        use axum::routing::post;

        // Handle OAuth authentication if configured
        #[cfg(feature = "mcp-oauth")]
        {
            if let Some(config) = oauth_config {
                tracing::info!("Enabling OAuth 2.1 authentication for HTTP server");
                let oauth_state = OAuthState::new(config)?;

                let app = base_router(post(handle_http_request_oauth))
                    .route("/oauth/authorize", get(oauth_authorize))
                    .route("/oauth/callback", get(oauth_callback))
                    .route("/oauth/token", post(oauth_token))
                    .route("/oauth/metadata", get(oauth_metadata))
                    .with_state((server, oauth_state))
                    .layer(CorsLayer::permissive());

                tracing::info!(
                    "OAuth 2.1 authentication enabled. Use /oauth/authorize to start flow"
                );

                return serve_router(app, addr).await;
            }
        }

        // Handle JWT authentication if configured
        #[cfg(feature = "mcp-jwt")]
        {
            if let Some(config) = jwt_config.clone() {
                tracing::info!("Enabling JWT authentication for HTTP server");
                let jwt_manager = JwtManager::new(config.clone());

                // Create router with JWT state
                let app = base_router(post(handle_http_request_jwt))
                    .route("/auth/token", post(generate_token))
                    .route("/auth/refresh", post(refresh_token))
                    .with_state((server, jwt_manager.clone()))
                    .layer(JwtAuthLayer::new(jwt_manager))
                    .layer(CorsLayer::permissive());

                tracing::info!("JWT authentication enabled. Use /auth/token to get access tokens");

                return serve_router(app, addr).await;
            }
        }

        // No authentication - basic server
        let app = base_router(post(handle_http_request)).with_state(server);

        serve_router(app, addr).await?;
    }

    #[cfg(not(feature = "axum"))]
    {
        return Err(anyhow::anyhow!(
            "HTTP server requires axum feature to be enabled"
        ));
    }

    Ok(())
}

#[cfg(feature = "axum")]
fn base_router<S>(root: axum::routing::MethodRouter<S>) -> axum::Router<S>
where
    S: Clone + Send + Sync + 'static,
{
    use axum::{routing::get, Router};
    Router::new()
        .route("/", root)
        .route("/health", get(health_check))
}

#[cfg(feature = "axum")]
async fn serve_router(app: axum::Router, addr: SocketAddr) -> McpResult<()> {
    let listener = tokio::net::TcpListener::bind(addr).await?;
    tracing::info!("HTTP server listening on {}", addr);
    Ok(axum::serve(listener, app.into_make_service()).await?)
}

#[cfg(feature = "axum")]
async fn process_request(server: &VtMcpServer, request: JsonValue) -> JsonValue {
    handle_request(server, request).await
}

#[cfg(feature = "axum")]
async fn handle_http_request(
    axum::extract::State(server): axum::extract::State<VtMcpServer>,
    axum::Json(request): axum::Json<JsonValue>,
) -> Result<axum::Json<JsonValue>, axum::http::StatusCode> {
    Ok(axum::Json(process_request(&server, request).await))
}

#[cfg(all(feature = "axum", feature = "mcp-jwt"))]
async fn handle_http_request_jwt(
    axum::extract::State((server, _)): axum::extract::State<(VtMcpServer, JwtManager)>,
    _claims: JwtClaims,
    axum::Json(request): axum::Json<JsonValue>,
) -> Result<axum::Json<JsonValue>, axum::http::StatusCode> {
    Ok(axum::Json(process_request(&server, request).await))
}

#[cfg(all(feature = "axum", feature = "mcp-oauth"))]
async fn handle_http_request_oauth(
    axum::extract::State((server, _)): axum::extract::State<(VtMcpServer, OAuthState)>,
    _claims: OAuthClaims,
    axum::Json(request): axum::Json<JsonValue>,
) -> Result<axum::Json<JsonValue>, axum::http::StatusCode> {
    Ok(axum::Json(process_request(&server, request).await))
}

#[cfg(feature = "axum")]
async fn health_check() -> &'static str {
    "`VirusTotal` MCP Server is healthy"
}

#[cfg(all(feature = "axum", feature = "mcp-jwt"))]
async fn generate_token(
    axum::extract::State((_, jwt_manager)): axum::extract::State<(VtMcpServer, JwtManager)>,
    axum::Json(request): axum::Json<TokenRequest>,
) -> Result<axum::Json<TokenResponse>, axum::http::StatusCode> {
    // Validate credentials (in production, check against database)
    if request.username == "admin" && request.password == "admin123" {
        match jwt_manager.generate_admin_token(&request.username) {
            Ok(token) => {
                tracing::info!("Generated admin token for user: {}", request.username);
                Ok(axum::Json(TokenResponse {
                    access_token: token,
                    token_type: "Bearer".to_string(),
                    expires_in: 86400, // 24 hours
                }))
            }
            Err(e) => {
                tracing::error!("Failed to generate token: {}", e);
                Err(axum::http::StatusCode::INTERNAL_SERVER_ERROR)
            }
        }
    } else if request.username == "user" && request.password == "user123" {
        match jwt_manager.generate_readonly_token(&request.username) {
            Ok(token) => {
                tracing::info!("Generated readonly token for user: {}", request.username);
                Ok(axum::Json(TokenResponse {
                    access_token: token,
                    token_type: "Bearer".to_string(),
                    expires_in: 86400, // 24 hours
                }))
            }
            Err(e) => {
                tracing::error!("Failed to generate token: {}", e);
                Err(axum::http::StatusCode::INTERNAL_SERVER_ERROR)
            }
        }
    } else {
        tracing::warn!("Invalid credentials for user: {}", request.username);
        Err(axum::http::StatusCode::UNAUTHORIZED)
    }
}

#[cfg(all(feature = "axum", feature = "mcp-jwt"))]
async fn refresh_token(
    axum::extract::State((_, jwt_manager)): axum::extract::State<(VtMcpServer, JwtManager)>,
    jwt_claims: JwtClaims,
) -> Result<axum::Json<TokenResponse>, axum::http::StatusCode> {
    // Generate a new token with the same permissions
    match jwt_manager.generate_token_with_permissions(
        &jwt_claims.0.sub,
        &jwt_claims.0.role,
        jwt_claims.0.permissions,
    ) {
        Ok(token) => {
            tracing::info!("Refreshed token for user: {}", jwt_claims.0.sub);
            Ok(axum::Json(TokenResponse {
                access_token: token,
                token_type: "Bearer".to_string(),
                expires_in: 86400, // 24 hours
            }))
        }
        Err(e) => {
            tracing::error!("Failed to refresh token: {}", e);
            Err(axum::http::StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

#[cfg(all(feature = "axum", feature = "mcp-jwt"))]
#[derive(serde::Deserialize)]
struct TokenRequest {
    username: String,
    password: String,
}

#[cfg(all(feature = "axum", feature = "mcp-jwt"))]
#[derive(serde::Serialize)]
struct TokenResponse {
    access_token: String,
    token_type: String,
    expires_in: u64,
}

// OAuth 2.1 endpoint handlers
#[cfg(all(feature = "axum", feature = "mcp-oauth"))]
async fn oauth_authorize(
    axum::extract::State((_, oauth_state)): axum::extract::State<(VtMcpServer, OAuthState)>,
) -> Result<axum::response::Redirect, OAuthError> {
    match oauth_state.start_authorization() {
        Ok((auth_url, _session_id)) => {
            tracing::info!("Starting OAuth authorization flow");
            Ok(axum::response::Redirect::to(&auth_url))
        }
        Err(e) => {
            tracing::error!("Failed to start OAuth authorization: {}", e);
            Err(OAuthError::AuthorizationFailed(e.to_string()))
        }
    }
}

#[cfg(all(feature = "axum", feature = "mcp-oauth"))]
async fn oauth_callback(
    axum::extract::State((_, oauth_state)): axum::extract::State<(VtMcpServer, OAuthState)>,
    Query(params): Query<CallbackParams>,
) -> Result<axum::Json<OAuthTokenResponse>, OAuthError> {
    if let Some(error) = params.error {
        tracing::warn!("OAuth callback error: {}", error);
        return Err(OAuthError::AuthorizationFailed(
            params.error_description.unwrap_or(error),
        ));
    }

    let code = params
        .code
        .ok_or_else(|| OAuthError::AuthorizationFailed("Missing authorization code".to_string()))?;

    let state = params
        .state
        .ok_or_else(|| OAuthError::AuthorizationFailed("Missing state parameter".to_string()))?;

    let session_id = params
        .session_id
        .ok_or_else(|| OAuthError::AuthorizationFailed("Missing session ID".to_string()))?;

    match oauth_state.handle_callback(code, state, session_id).await {
        Ok(credentials) => {
            tracing::info!("OAuth callback successful");
            Ok(axum::Json(OAuthTokenResponse {
                access_token: credentials.access_token,
                token_type: credentials.token_type,
                expires_in: credentials.expires_in,
                refresh_token: credentials.refresh_token,
                scope: credentials.scope,
            }))
        }
        Err(e) => {
            tracing::error!("OAuth callback failed: {}", e);
            Err(OAuthError::AuthorizationFailed(e.to_string()))
        }
    }
}

#[cfg(all(feature = "axum", feature = "mcp-oauth"))]
async fn oauth_token(
    axum::extract::State((_, oauth_state)): axum::extract::State<(VtMcpServer, OAuthState)>,
    axum::Json(request): axum::Json<OAuthTokenRequest>,
) -> Result<axum::Json<OAuthTokenResponse>, OAuthError> {
    match request.grant_type.as_str() {
        "refresh_token" => {
            if let Some(_refresh_token) = request.refresh_token {
                match oauth_state.refresh_token().await {
                    Ok(credentials) => {
                        tracing::info!("OAuth token refresh successful");
                        Ok(axum::Json(OAuthTokenResponse {
                            access_token: credentials.access_token,
                            token_type: credentials.token_type,
                            expires_in: credentials.expires_in,
                            refresh_token: credentials.refresh_token,
                            scope: credentials.scope,
                        }))
                    }
                    Err(e) => {
                        tracing::error!("OAuth token refresh failed: {}", e);
                        Err(OAuthError::TokenRefreshFailed(e.to_string()))
                    }
                }
            } else {
                Err(OAuthError::AuthorizationFailed(
                    "Missing refresh token".to_string(),
                ))
            }
        }
        _ => Err(OAuthError::AuthorizationFailed(format!(
            "Unsupported grant type: {}",
            request.grant_type
        ))),
    }
}

#[cfg(all(feature = "axum", feature = "mcp-oauth"))]
async fn oauth_metadata() -> axum::Json<AuthServerMetadata> {
    axum::Json(AuthServerMetadata {
        issuer: "http://localhost:3000".to_string(),
        authorization_endpoint: "http://localhost:3000/oauth/authorize".to_string(),
        token_endpoint: "http://localhost:3000/oauth/token".to_string(),
        scopes_supported: vec![
            "mcp".to_string(),
            "profile".to_string(),
            "vt:scan".to_string(),
            "vt:search".to_string(),
        ],
        response_types_supported: vec!["code".to_string()],
        grant_types_supported: vec![
            "authorization_code".to_string(),
            "refresh_token".to_string(),
        ],
        code_challenge_methods_supported: vec!["S256".to_string()],
    })
}

#[cfg(all(feature = "axum", feature = "mcp-oauth"))]
#[derive(serde::Deserialize)]
#[allow(dead_code)] // Fields may be used in future OAuth implementations
struct OAuthTokenRequest {
    grant_type: String,
    code: Option<String>,
    redirect_uri: Option<String>,
    client_id: Option<String>,
    code_verifier: Option<String>,
    refresh_token: Option<String>,
}

#[cfg(all(feature = "axum", feature = "mcp-oauth"))]
#[derive(serde::Serialize)]
struct OAuthTokenResponse {
    access_token: String,
    token_type: String,
    expires_in: Option<u64>,
    refresh_token: Option<String>,
    scope: Option<String>,
}

/// Handle an MCP request
async fn handle_request(server: &VtMcpServer, request: JsonValue) -> JsonValue {
    let id = request.get("id").cloned().unwrap_or(json!(null));

    if let Some(method) = request.get("method").and_then(|v| v.as_str()) {
        match method {
            "tools/list" => {
                json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "result": {
                        "tools": server.list_tools()
                    }
                })
            }
            "tools/call" => {
                if let Some(params) = request.get("params") {
                    if let (Some(name), Some(arguments)) = (
                        params.get("name").and_then(|v| v.as_str()),
                        params.get("arguments"),
                    ) {
                        match server.handle_tool_call(name, arguments).await {
                            Ok(result) => {
                                json!({
                                    "jsonrpc": "2.0",
                                    "id": id,
                                    "result": {
                                        "content": [{
                                            "type": "text",
                                            "text": serde_json::to_string_pretty(&result).unwrap_or_else(|_| result.to_string())
                                        }]
                                    }
                                })
                            }
                            Err(error) => {
                                json!({
                                    "jsonrpc": "2.0",
                                    "id": id,
                                    "error": {
                                        "code": -1,
                                        "message": error.to_string()
                                    }
                                })
                            }
                        }
                    } else {
                        json!({
                            "jsonrpc": "2.0",
                            "id": id,
                            "error": {
                                "code": -32602,
                                "message": "Invalid params"
                            }
                        })
                    }
                } else {
                    json!({
                        "jsonrpc": "2.0",
                        "id": id,
                        "error": {
                            "code": -32602,
                            "message": "Missing params"
                        }
                    })
                }
            }
            "initialize" => {
                json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "result": {
                        "protocolVersion": "2024-11-05",
                        "capabilities": server.get_server_capabilities(),
                        "serverInfo": server.get_server_info()
                    }
                })
            }
            _ => {
                json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "error": {
                        "code": -32601,
                        "message": format!("Method not found: {}", method)
                    }
                })
            }
        }
    } else {
        json!({
            "jsonrpc": "2.0",
            "id": id,
            "error": {
                "code": -32600,
                "message": "Invalid request"
            }
        })
    }
}

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
