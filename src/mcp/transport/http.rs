use crate::Client;
use crate::mcp::McpResult;
use crate::mcp::server::VtMcpServer;
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
    Router,
    routing::{get, post},
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
    return configure_and_serve(server, addr, jwt_config, oauth_config).await;

    #[cfg(not(feature = "axum"))]
    Err(anyhow::anyhow!(
        "HTTP server requires axum feature to be enabled",
    ))
}
#[cfg(feature = "axum")]
/// Select the configured authentication router and start the HTTP listener.
async fn configure_and_serve(
    server: VtMcpServer,
    addr: SocketAddr,
    _jwt_config: Option<MaybeJwtConfig>,
    _oauth_config: Option<MaybeOAuthConfig>,
) -> McpResult<()> {
    #[cfg(feature = "mcp-oauth")]
    if let Some(config) = _oauth_config {
        tracing::info!("Enabling OAuth 2.1 authentication for HTTP server");
        validate_oauth_http_callback(&config)?;
        let oauth_state = OAuthState::new(config)?;
        let app = oauth_router(server, oauth_state);
        return serve_router(app, addr).await;
    }

    #[cfg(feature = "mcp-jwt")]
    if let Some(config) = _jwt_config.clone() {
        tracing::info!("Enabling JWT authentication for HTTP server");
        let jwt_manager = JwtManager::new(config.clone());
        let app = jwt_router(server, jwt_manager.clone());
        return serve_router(app, addr).await;
    }

    let app = plain_router(server);
    serve_router(app, addr).await
}

/// Apply HTTP-router callback restrictions without limiting standalone OAuth library clients.
#[cfg(all(feature = "axum", feature = "mcp-oauth"))]
fn validate_oauth_http_callback(config: &OAuthConfig) -> McpResult<()> {
    let callback = url::Url::parse(&config.redirect_uri)?;
    if !matches!(callback.scheme(), "http" | "https")
        || callback.fragment().is_some()
        || matches!(callback.path(), "/" | "/health" | "/oauth/authorize")
    {
        anyhow::bail!("HTTP OAuth redirect URI must identify a dedicated HTTP callback path");
    }
    Ok(())
}

#[cfg(feature = "axum")]
/// Construct the shared health and MCP routes for the selected authentication state.
fn base_router<S>(root: axum::routing::MethodRouter<S>) -> Router<S>
where
    S: Clone + Send + Sync + 'static,
{
    configure_core_routes(root)
}

#[cfg(feature = "axum")]
/// Expose health without authentication while delegating MCP authentication to its handler.
fn configure_core_routes<S>(root: axum::routing::MethodRouter<S>) -> Router<S>
where
    S: Clone + Send + Sync + 'static,
{
    Router::new()
        .route("/", root)
        .route("/health", get(health_check))
}

#[cfg(all(feature = "axum", feature = "mcp-oauth"))]
/// Construct the HTTP router with OAuth state and its authorization endpoints.
fn oauth_router(server: VtMcpServer, oauth_state: OAuthState) -> axum::Router {
    configure_oauth_routes(server, oauth_state)
}

#[cfg(all(feature = "axum", feature = "mcp-oauth"))]
/// Register the configured callback path and install state for OAuth claims extraction.
fn configure_oauth_routes(server: VtMcpServer, oauth_state: OAuthState) -> axum::Router {
    base_router(post(handle_http_request_oauth))
        .route("/oauth/authorize", get(oauth_authorize))
        .route(oauth_state.callback_path(), get(oauth_callback))
        .layer(axum::Extension(oauth_state.clone()))
        .with_state((server, oauth_state))
        .layer(CorsLayer::permissive())
}

#[cfg(all(feature = "axum", feature = "mcp-jwt"))]
/// Construct the JWT-authenticated MCP router.
fn jwt_router(server: VtMcpServer, jwt_manager: JwtManager) -> axum::Router {
    configure_jwt_routes(server, jwt_manager)
}

#[cfg(all(feature = "axum", feature = "mcp-jwt"))]
/// Register token endpoints and install JWT validation middleware.
fn configure_jwt_routes(server: VtMcpServer, jwt_manager: JwtManager) -> axum::Router {
    base_router(post(handle_http_request_jwt))
        .route("/auth/token", post(generate_token))
        .route("/auth/refresh", post(refresh_token))
        .with_state((server, jwt_manager.clone()))
        .layer(JwtAuthLayer::new(jwt_manager))
        .layer(CorsLayer::permissive())
}

#[cfg(feature = "axum")]
/// Construct the explicitly unauthenticated MCP router.
fn plain_router(server: VtMcpServer) -> axum::Router {
    configure_plain_routes(server)
}

#[cfg(feature = "axum")]
/// Register MCP requests without optional authentication middleware.
fn configure_plain_routes(server: VtMcpServer) -> axum::Router {
    base_router(post(handle_http_request)).with_state(server)
}

#[cfg(feature = "axum")]
/// Bind the selected socket and serve until shutdown or a listener error.
async fn serve_router(app: axum::Router, addr: SocketAddr) -> McpResult<()> {
    let listener = tokio::net::TcpListener::bind(addr).await?;
    tracing::info!("HTTP server listening on {}", addr);
    Ok(axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await?)
}

#[cfg(feature = "axum")]
/// Dispatch one decoded JSON-RPC request to the MCP server.
async fn process_request(server: &VtMcpServer, request: JsonValue) -> JsonValue {
    handle_request(server, request).await
}

#[cfg(feature = "axum")]
/// Process JSON-RPC for the unauthenticated transport.
async fn handle_http_request(
    axum::extract::State(server): axum::extract::State<VtMcpServer>,
    axum::Json(request): axum::Json<JsonValue>,
) -> Result<axum::Json<JsonValue>, axum::http::StatusCode> {
    Ok(axum::Json(process_request(&server, request).await))
}

#[cfg(all(feature = "axum", feature = "mcp-jwt"))]
/// Process JSON-RPC only after the JWT claims extractor succeeds.
async fn handle_http_request_jwt(
    axum::extract::State((server, _)): axum::extract::State<(VtMcpServer, JwtManager)>,
    _claims: JwtClaims,
    axum::Json(request): axum::Json<JsonValue>,
) -> Result<axum::Json<JsonValue>, axum::http::StatusCode> {
    Ok(axum::Json(process_request(&server, request).await))
}

#[cfg(all(feature = "axum", feature = "mcp-oauth"))]
/// Process JSON-RPC only after the OAuth bearer-token extractor succeeds.
async fn handle_http_request_oauth(
    axum::extract::State((server, _)): axum::extract::State<(VtMcpServer, OAuthState)>,
    _claims: OAuthClaims,
    axum::Json(request): axum::Json<JsonValue>,
) -> Result<axum::Json<JsonValue>, axum::http::StatusCode> {
    Ok(axum::Json(process_request(&server, request).await))
}

#[cfg(feature = "axum")]
/// Return a lightweight liveness response without upstream API traffic.
async fn health_check() -> &'static str {
    "`VirusTotal` MCP Server is healthy"
}

#[cfg(all(feature = "axum", feature = "mcp-jwt"))]
/// Issue a token only for explicitly configured credentials and an allowed role.
async fn generate_token(
    axum::extract::State((_, jwt_manager)): axum::extract::State<(VtMcpServer, JwtManager)>,
    axum::Json(request): axum::Json<TokenRequest>,
) -> Result<axum::Json<TokenResponse>, axum::http::StatusCode> {
    let expected_user = std::env::var("MCP_AUTH_USERNAME").ok();
    let expected_password = std::env::var("MCP_AUTH_PASSWORD").ok();
    if !password_credentials_match(
        &request,
        expected_user.as_deref(),
        expected_password.as_deref(),
    ) {
        return Err(axum::http::StatusCode::UNAUTHORIZED);
    }
    match std::env::var("MCP_AUTH_ROLE")
        .as_deref()
        .unwrap_or("readonly")
    {
        "admin" => issue_token(&jwt_manager, &request.username, "admin", |m, u| {
            m.generate_admin_token(u)
        }),
        "readonly" => issue_token(&jwt_manager, &request.username, "readonly", |m, u| {
            m.generate_readonly_token(u)
        }),
        _ => Err(axum::http::StatusCode::INTERNAL_SERVER_ERROR),
    }
}

#[cfg(all(feature = "axum", feature = "mcp-jwt"))]
/// Hash both credential pairs to fixed widths before constant-time comparison.
fn password_credentials_match(
    request: &TokenRequest,
    username: Option<&str>,
    password: Option<&str>,
) -> bool {
    use sha2::{Digest, Sha256};
    use subtle::ConstantTimeEq;

    let (Some(username), Some(password)) = (username, password) else {
        return false;
    };
    if username.is_empty() || password.is_empty() {
        return false;
    }
    bool::from(
        Sha256::digest(request.username.as_bytes()).ct_eq(&Sha256::digest(username.as_bytes()))
            & Sha256::digest(request.password.as_bytes())
                .ct_eq(&Sha256::digest(password.as_bytes())),
    )
}

#[cfg(all(feature = "axum", feature = "mcp-jwt"))]
/// Refresh the authenticated JWT while preserving its subject, role, and permissions.
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
/// Wrap a newly issued JWT in the existing response schema.
fn token_response(token: String) -> axum::Json<TokenResponse> {
    axum::Json(TokenResponse {
        access_token: token,
        token_type: "Bearer".to_string(),
        expires_in: 86400,
    })
}

#[cfg(all(feature = "axum", feature = "mcp-jwt"))]
/// Generate the configured role's token without writing it to logs.
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
/// Start PKCE authorization and bind the pending session to the initiating browser.
async fn oauth_authorize(
    axum::extract::ConnectInfo(peer): axum::extract::ConnectInfo<SocketAddr>,
    axum::extract::State((_, oauth_state)): axum::extract::State<(VtMcpServer, OAuthState)>,
) -> Result<axum::response::Response, OAuthError> {
    use axum::response::IntoResponse;

    if !oauth_state.allow_authorization(peer.ip()) {
        return Ok((
            axum::http::StatusCode::TOO_MANY_REQUESTS,
            [(axum::http::header::RETRY_AFTER, "2")],
            axum::Json(serde_json::json!({"error": "Too many authorization requests"})),
        )
            .into_response());
    }
    let (auth_url, session_id) = oauth_state.start_authorization().map_err(|_| {
        OAuthError::AuthorizationFailed("Could not start authorization".to_string())
    })?;
    let mut response = axum::response::Redirect::to(&auth_url).into_response();
    set_oauth_response_headers(&mut response, &oauth_state.session_cookie(&session_id))?;
    Ok(response)
}

/// Complete a browser-bound, single-use authorization code exchange.
#[cfg(all(feature = "axum", feature = "mcp-oauth"))]
async fn oauth_callback(
    axum::extract::State((_, oauth_state)): axum::extract::State<(VtMcpServer, OAuthState)>,
    axum::extract::Query(params): axum::extract::Query<crate::mcp::oauth::CallbackParams>,
    headers: axum::http::HeaderMap,
) -> Result<axum::response::Response, OAuthError> {
    use axum::response::IntoResponse;

    let invalid = || OAuthError::AuthorizationFailed("Invalid authorization callback".to_string());
    if params.error.is_some() {
        return Err(invalid());
    }
    let code = params
        .code
        .filter(|value| !value.is_empty())
        .ok_or_else(invalid)?;
    let state = params
        .state
        .filter(|value| !value.is_empty())
        .ok_or_else(invalid)?;
    let session_id = headers
        .get(axum::http::header::COOKIE)
        .and_then(|value| value.to_str().ok())
        .and_then(|cookies| {
            cookies
                .split(';')
                .find_map(|cookie| cookie.trim().strip_prefix("mcp_oauth_session="))
        })
        .filter(|value| uuid::Uuid::parse_str(value).is_ok())
        .ok_or_else(invalid)?;
    let credentials = oauth_state
        .handle_callback(code, state, session_id.to_string())
        .await
        .map_err(|_| {
            OAuthError::AuthorizationFailed("Authorization callback failed".to_string())
        })?;
    let mut response = axum::Json(credentials).into_response();
    set_oauth_response_headers(&mut response, &oauth_state.clear_session_cookie())?;
    Ok(response)
}

/// Prevent caching and referrer leakage of authorization responses and bind the session cookie.
#[cfg(all(feature = "axum", feature = "mcp-oauth"))]
fn set_oauth_response_headers(
    response: &mut axum::response::Response,
    cookie: &str,
) -> Result<(), OAuthError> {
    use axum::http::{HeaderValue, header};

    let cookie = HeaderValue::from_str(cookie).map_err(|_| {
        OAuthError::AuthorizationFailed("Invalid callback cookie configuration".to_string())
    })?;
    let headers = response.headers_mut();
    headers.insert(header::SET_COOKIE, cookie);
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    Ok(())
}

#[cfg(all(test, feature = "axum", feature = "mcp-jwt"))]
mod password_auth_tests {
    use super::{TokenRequest, password_credentials_match};

    #[test]
    /// Reject demo logins and absent or empty issuer credentials.
    fn password_login_has_no_demo_or_empty_credential_fallback() {
        let request = TokenRequest {
            username: "admin".to_string(),
            password: "admin123".to_string(),
        };
        assert!(!password_credentials_match(&request, None, None));
        assert!(!password_credentials_match(&request, Some(""), Some("")));
        assert!(!password_credentials_match(
            &request,
            Some("fixture-user"),
            Some("fixture-password"),
        ));
    }

    #[test]
    /// Accept the configured pair and reject differing usernames and passwords.
    fn password_login_accepts_only_the_configured_credentials() {
        let request = TokenRequest {
            username: "fixture-user".to_string(),
            password: "fixture-password".to_string(),
        };
        assert!(password_credentials_match(
            &request,
            Some("fixture-user"),
            Some("fixture-password"),
        ));
        assert!(!password_credentials_match(
            &request,
            Some("fixture-user"),
            Some("incorrect-password"),
        ));
        assert!(!password_credentials_match(
            &request,
            Some("incorrect-user"),
            Some("fixture-password"),
        ));
    }
}

#[cfg(all(test, feature = "mcp-oauth"))]
mod oauth_http_tests {
    use super::*;
    use axum::{
        body::{Body, to_bytes},
        http::{Request, StatusCode, header},
    };
    use tower::ServiceExt;
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{method, path},
    };

    /// Send a fixture HTTP request through the actual OAuth router and claims extractor.
    async fn send(
        app: &Router,
        uri: &str,
        cookie: Option<&str>,
        token: Option<&str>,
    ) -> axum::response::Response {
        let mut builder = Request::builder()
            .uri(uri)
            .extension(axum::extract::ConnectInfo(
                "127.0.0.1:12345".parse::<SocketAddr>().unwrap(),
            ));
        if let Some(cookie) = cookie {
            builder = builder.header(header::COOKIE, cookie);
        }
        if let Some(token) = token {
            builder = builder
                .method("POST")
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .header(header::CONTENT_TYPE, "application/json");
        }
        let body = if token.is_some() {
            r#"{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}"#
        } else {
            ""
        };
        app.clone()
            .oneshot(builder.body(Body::from(body)).unwrap())
            .await
            .unwrap()
    }

    type AuthorizationQuery = std::collections::HashMap<String, String>;

    /// Construct the actual HTTP router for an isolated identity provider.
    fn router_for_provider(provider: &MockServer) -> Router {
        let config = OAuthConfig::new("fixture-client", provider.uri())
            .with_redirect_uri("http://127.0.0.1:8080/custom/callback?tenant=fixture");
        let state = OAuthState::new(config).unwrap();
        let server = VtMcpServer::new(
            crate::ClientBuilder::new()
                .api_key("fixture-api-key")
                .build()
                .unwrap(),
        );
        oauth_router(server, state)
    }

    /// Run an isolated provider expecting exactly one authorization-code exchange.
    async fn fixture() -> (Router, MockServer) {
        let provider = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/oauth/token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "access_token": "fixture-access-token", "token_type": "Bearer", "expires_in": 3600
            })))
            .expect(1)
            .mount(&provider)
            .await;
        (router_for_provider(&provider), provider)
    }

    /// Start authorization and retain the browser cookie and identity-provider query.
    async fn begin(app: &Router) -> (String, AuthorizationQuery) {
        let auth = send(app, "/oauth/authorize", None, None).await;
        assert_eq!(auth.status(), StatusCode::SEE_OTHER);
        assert_eq!(auth.headers()[header::CACHE_CONTROL], "no-store");
        let cookie = auth.headers()[header::SET_COOKIE]
            .to_str()
            .unwrap()
            .split(';')
            .next()
            .unwrap()
            .to_string();
        let location = url::Url::parse(auth.headers()[header::LOCATION].to_str().unwrap()).unwrap();
        (cookie, location.query_pairs().into_owned().collect())
    }

    /// Reject missing browser binding, incorrect state, provider errors, and invalid tokens.
    async fn assert_invalid_callbacks(app: &Router, callback: &str, cookie: &str) {
        for (uri, binding) in [
            (callback, None),
            (
                "/custom/callback?code=fixture-code&state=wrong",
                Some(cookie),
            ),
            ("/custom/callback?error=access_denied", Some(cookie)),
        ] {
            assert_eq!(
                send(app, uri, binding, None).await.status(),
                StatusCode::BAD_REQUEST
            );
        }
        assert_eq!(
            send(app, "/", None, Some("invalid-token")).await.status(),
            StatusCode::UNAUTHORIZED
        );
    }

    /// Require a successful non-cacheable callback to authorize the MCP tools list.
    async fn assert_authorized_callback(app: &Router, callback: &str, cookie: &str) {
        let response = send(app, callback, Some(cookie), None).await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
        assert_eq!(response.headers()[header::REFERRER_POLICY], "no-referrer");
        assert!(
            response.headers()[header::SET_COOKIE]
                .to_str()
                .unwrap()
                .contains("Max-Age=0")
        );
        let credentials: serde_json::Value =
            serde_json::from_slice(&to_bytes(response.into_body(), 8192).await.unwrap()).unwrap();
        let authorized = send(app, "/", None, credentials["access_token"].as_str()).await;
        assert_eq!(authorized.status(), StatusCode::OK);
        let result: serde_json::Value =
            serde_json::from_slice(&to_bytes(authorized.into_body(), 65536).await.unwrap())
                .unwrap();
        assert!(
            result["result"]["tools"]
                .as_array()
                .is_some_and(|tools| !tools.is_empty())
        );
    }

    /// Prove the provider received the original redirect URI and correct PKCE verifier.
    async fn assert_pkce(provider: &MockServer, query: &AuthorizationQuery) {
        let requests = provider.received_requests().await.unwrap();
        let form: AuthorizationQuery = url::form_urlencoded::parse(&requests[0].body)
            .into_owned()
            .collect();
        assert_eq!(form["grant_type"], "authorization_code");
        assert_eq!(form["redirect_uri"], query["redirect_uri"]);
        use base64::Engine;
        use sha2::{Digest, Sha256};
        let challenge = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(Sha256::digest(form["code_verifier"].as_bytes()));
        assert_eq!(challenge, query["code_challenge"]);
    }

    /// Complete token exchange while requiring cookie, CSRF, PKCE, and one-time session binding.
    #[tokio::test]
    async fn oauth_callback_authenticates_and_rejects_unbound_or_replayed_callbacks() {
        let (app, provider) = fixture().await;
        let (cookie, query) = begin(&app).await;
        let callback = format!(
            "/custom/callback?code=fixture-code&state={}",
            query["state"]
        );
        assert_invalid_callbacks(&app, &callback, &cookie).await;
        assert_authorized_callback(&app, &callback, &cookie).await;
        assert_eq!(
            send(&app, &callback, Some(&cookie), None).await.status(),
            StatusCode::BAD_REQUEST
        );
        assert_pkce(&provider, &query).await;
    }
    /// Completing another browser login must not revoke an existing client's valid bearer token.
    #[tokio::test]
    async fn oauth_clients_remain_authorized_after_another_client_logs_in() {
        use wiremock::matchers::body_string_contains;
        let provider = MockServer::start().await;
        let app = router_for_provider(&provider);
        let clients = [
            ("first-client", "fixture-first-token"),
            ("second-client", "fixture-second-token"),
        ];
        for (code, token) in clients {
            Mock::given(method("POST"))
                .and(path("/oauth/token"))
                .and(body_string_contains(format!("code={code}")))
                .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "access_token": token, "token_type": "Bearer", "expires_in": 3600
                })))
                .expect(1)
                .mount(&provider)
                .await;
            let (cookie, query) = begin(&app).await;
            let callback = format!("/custom/callback?code={code}&state={}", query["state"]);
            assert_eq!(
                send(&app, &callback, Some(&cookie), None).await.status(),
                StatusCode::OK
            );
        }
        for (_, token) in clients {
            assert_eq!(
                send(&app, "/", None, Some(token)).await.status(),
                StatusCode::OK
            );
        }
    }
    /// A spoofed forwarding header cannot bypass peer quotas or consume another peer's budget.
    #[tokio::test]
    async fn anonymous_authorization_flood_is_limited_without_starving_other_peers() {
        let provider = MockServer::start().await;
        let app = router_for_provider(&provider);
        let mut limited = false;
        for index in 0..100 {
            let request = Request::builder()
                .uri("/oauth/authorize")
                .header("x-forwarded-for", format!("192.0.2.{index}"))
                .extension(axum::extract::ConnectInfo(
                    "127.0.0.1:12345".parse::<SocketAddr>().unwrap(),
                ))
                .body(Body::empty())
                .unwrap();
            let response = app.clone().oneshot(request).await.unwrap();
            if response.status() == StatusCode::TOO_MANY_REQUESTS {
                assert_eq!(response.headers()[header::RETRY_AFTER], "2");
                limited = true;
                break;
            }
            assert_eq!(response.status(), StatusCode::SEE_OTHER);
        }
        assert!(limited, "anonymous requests bypassed the per-peer budget");
        let other = Request::builder()
            .uri("/oauth/authorize")
            .extension(axum::extract::ConnectInfo(
                "192.0.2.200:12345".parse::<SocketAddr>().unwrap(),
            ))
            .body(Body::empty())
            .unwrap();
        assert_eq!(
            app.oneshot(other).await.unwrap().status(),
            StatusCode::SEE_OTHER
        );
    }
}
