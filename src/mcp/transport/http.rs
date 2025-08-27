use crate::mcp::server::VtMcpServer;
use crate::mcp::McpResult;
use crate::Client;
use serde_json::Value as JsonValue;
use std::net::SocketAddr;

#[cfg(feature = "mcp-jwt")]
use crate::mcp::auth::{JwtAuthLayer, JwtClaims, JwtConfig, JwtManager};
#[cfg(feature = "mcp-oauth")]
use crate::mcp::oauth::{OAuthClaims, OAuthConfig, OAuthError, OAuthState};
#[cfg(any(feature = "mcp-jwt", feature = "mcp-oauth"))]
use tower_http::cors::CorsLayer;

#[cfg(feature = "axum")]
use axum::{
    routing::{get, post},
    Router,
};

use super::common::handle_request;

#[cfg(feature = "mcp-jwt")]
type MaybeJwtConfig = JwtConfig;
#[cfg(not(feature = "mcp-jwt"))]
type MaybeJwtConfig = ();
#[cfg(feature = "mcp-oauth")]
type MaybeOAuthConfig = OAuthConfig;
#[cfg(not(feature = "mcp-oauth"))]
type MaybeOAuthConfig = ();

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
        if let Some(config) = oauth_config {
            tracing::info!("Enabling OAuth 2.1 authentication for HTTP server");
            let oauth_state = OAuthState::new(config)?;
            let app = oauth_router(server, oauth_state);
            return serve_router(app, addr).await;
        }

        #[cfg(feature = "mcp-jwt")]
        if let Some(config) = jwt_config.clone() {
            tracing::info!("Enabling JWT authentication for HTTP server");
            let jwt_manager = JwtManager::new(config.clone());
            let app = jwt_router(server, jwt_manager.clone());
            return serve_router(app, addr).await;
        }

        let app = plain_router(server);
        serve_router(app, addr).await?;
    }

    #[cfg(not(feature = "axum"))]
    {
        return Err(anyhow::anyhow!(
            "HTTP server requires axum feature to be enabled",
        ));
    }

    Ok(())
}
#[cfg(feature = "axum")]
fn base_router<S>(root: axum::routing::MethodRouter<S>) -> Router<S>
where
    S: Clone + Send + Sync + 'static,
{
    Router::new()
        .route("/", root)
        .route("/health", get(health_check))
}

#[cfg(all(feature = "axum", feature = "mcp-oauth"))]
fn oauth_router(server: VtMcpServer, oauth_state: OAuthState) -> axum::Router {
    base_router(post(handle_http_request_oauth))
        .route("/oauth/authorize", get(oauth_authorize))
        .with_state((server, oauth_state))
        .layer(CorsLayer::permissive())
}

#[cfg(all(feature = "axum", feature = "mcp-jwt"))]
fn jwt_router(server: VtMcpServer, jwt_manager: JwtManager) -> axum::Router {
    base_router(post(handle_http_request_jwt))
        .route("/auth/token", post(generate_token))
        .route("/auth/refresh", post(refresh_token))
        .with_state((server, jwt_manager.clone()))
        .layer(JwtAuthLayer::new(jwt_manager))
        .layer(CorsLayer::permissive())
}

#[cfg(feature = "axum")]
fn plain_router(server: VtMcpServer) -> axum::Router {
    base_router(post(handle_http_request)).with_state(server)
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
    if request.username == "admin" && request.password == "admin123" {
        issue_token(&jwt_manager, &request.username, "admin", |m, u| {
            m.generate_admin_token(u)
        })
    } else if request.username == "user" && request.password == "user123" {
        issue_token(&jwt_manager, &request.username, "readonly", |m, u| {
            m.generate_readonly_token(u)
        })
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
    match jwt_manager.generate_token_with_permissions(
        &jwt_claims.0.sub,
        &jwt_claims.0.role,
        jwt_claims.0.permissions,
    ) {
        Ok(token) => {
            tracing::info!("Refreshed token for user: {}", jwt_claims.0.sub);
            Ok(token_response(token))
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

#[cfg(all(feature = "axum", feature = "mcp-jwt"))]
fn token_response(token: String) -> axum::Json<TokenResponse> {
    axum::Json(TokenResponse {
        access_token: token,
        token_type: "Bearer".to_string(),
        expires_in: 86400,
    })
}

#[cfg(all(feature = "axum", feature = "mcp-jwt"))]
fn issue_token<F>(
    jwt_manager: &JwtManager,
    username: &str,
    role: &str,
    generate: F,
) -> Result<axum::Json<TokenResponse>, axum::http::StatusCode>
where
    F: Fn(&JwtManager, &str) -> anyhow::Result<String>,
{
    match generate(jwt_manager, username) {
        Ok(token) => {
            tracing::info!("Generated {} token for user: {}", role, username);
            Ok(token_response(token))
        }
        Err(e) => {
            tracing::error!("Failed to generate token: {}", e);
            Err(axum::http::StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
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
