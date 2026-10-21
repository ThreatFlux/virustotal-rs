//! OAuth 2.1 authentication implementation for MCP server
//!
//! This module provides OAuth 2.1 authorization flow support with PKCE,
//! automatic token refresh, and authorization server metadata discovery
//! following the MCP 2025-03-26 Authorization Specification.

use anyhow::{Result as AnyhowResult, anyhow};
use axum::{
    extract::FromRequestParts,
    http::request::Parts,
    response::{IntoResponse, Response},
};
use oauth2::{
    AuthUrl, AuthorizationCode, ClientId, ClientSecret, CsrfToken, EmptyExtraTokenFields,
    EndpointNotSet, EndpointSet, PkceCodeChallenge, PkceCodeVerifier, RedirectUrl, RefreshToken,
    Scope, StandardTokenResponse, TokenResponse, TokenUrl, basic::BasicClient,
};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    sync::{Arc, RwLock},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use uuid::Uuid;

/// OAuth 2.1 configuration
#[derive(Debug, Clone)]
pub struct OAuthConfig {
    /// OAuth client ID
    pub client_id: String,
    /// OAuth client secret (optional for public clients)
    pub client_secret: Option<String>,
    /// Authorization server base URL
    pub auth_server_url: String,
    /// Authorization endpoint path
    pub auth_endpoint: String,
    /// Token endpoint path
    pub token_endpoint: String,
    /// Redirect URI for authorization callback
    pub redirect_uri: String,
    /// OAuth scopes to request
    pub scopes: Vec<String>,
    /// Whether to use PKCE (recommended)
    pub use_pkce: bool,
    /// Token refresh threshold (refresh when token expires within this duration)
    pub refresh_threshold: Duration,
}

impl Default for OAuthConfig {
    /// Initialize the established local defaults without enabling optional authentication.
    fn default() -> Self {
        Self {
            client_id: "virustotal-mcp-client".to_string(),
            client_secret: None, // Public client
            auth_server_url: "http://localhost:8080".to_string(),
            auth_endpoint: "/oauth/authorize".to_string(),
            token_endpoint: "/oauth/token".to_string(),
            redirect_uri: "http://localhost:3001/auth/callback".to_string(),
            scopes: vec!["mcp".to_string(), "profile".to_string()],
            use_pkce: true,
            refresh_threshold: Duration::from_secs(300), // 5 minutes
        }
    }
}

impl OAuthConfig {
    /// Create a new OAuth configuration
    pub fn new(client_id: impl Into<String>, auth_server_url: impl Into<String>) -> Self {
        Self {
            client_id: client_id.into(),
            auth_server_url: auth_server_url.into(),
            ..Default::default()
        }
    }

    /// Set client secret
    pub fn with_client_secret(mut self, secret: impl Into<String>) -> Self {
        self.client_secret = Some(secret.into());
        self
    }

    /// Set redirect URI
    pub fn with_redirect_uri(mut self, uri: impl Into<String>) -> Self {
        self.redirect_uri = uri.into();
        self
    }

    /// Set OAuth scopes
    pub fn with_scopes(mut self, scopes: Vec<String>) -> Self {
        self.scopes = scopes;
        self
    }

    /// Disable PKCE (not recommended)
    pub fn without_pkce(mut self) -> Self {
        self.use_pkce = false;
        self
    }

    /// Set custom endpoints
    pub fn with_endpoints(
        mut self,
        auth_endpoint: impl Into<String>,
        token_endpoint: impl Into<String>,
    ) -> Self {
        self.auth_endpoint = auth_endpoint.into();
        self.token_endpoint = token_endpoint.into();
        self
    }

    /// Parse scopes from a comma-separated string
    pub fn parse_scopes(scopes_str: &str) -> Vec<String> {
        scopes_str
            .split(',')
            .map(|s| s.trim().to_string())
            .collect()
    }

    /// Read scopes from the `OAUTH_SCOPES` environment variable if present
    pub fn scopes_from_env() -> Option<Vec<String>> {
        std::env::var("OAUTH_SCOPES")
            .ok()
            .map(|s| Self::parse_scopes(&s))
    }
}

/// OAuth credentials (access token + metadata)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuthCredentials {
    pub access_token: String,
    pub token_type: String,
    pub expires_in: Option<u64>,
    pub refresh_token: Option<String>,
    pub scope: Option<String>,
    pub issued_at: u64,
}

impl OAuthCredentials {
    /// Check if the token is expired or will expire soon
    pub fn needs_refresh(&self, threshold: Duration) -> bool {
        if let Some(expires_in) = self.expires_in {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            let expires_at = self.issued_at + expires_in;
            let threshold_secs = threshold.as_secs();

            now + threshold_secs >= expires_at
        } else {
            false // No expiration info, assume valid
        }
    }

    /// Check if token is definitely expired
    pub fn is_expired(&self) -> bool {
        if let Some(expires_in) = self.expires_in {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            let expires_at = self.issued_at + expires_in;

            now >= expires_at
        } else {
            false
        }
    }
}

/// OAuth authorization session state
#[derive(Debug, Clone)]
pub struct OAuthSession {
    pub session_id: String,
    pub pkce_verifier: Option<String>,
    pub csrf_token: String,
    pub original_scopes: Vec<String>,
    pub created_at: SystemTime,
}

/// OAuth state manager
#[derive(Clone)]
pub struct OAuthState {
    config: OAuthConfig,
    client: BasicClient<EndpointSet, EndpointNotSet, EndpointNotSet, EndpointNotSet, EndpointSet>,
    sessions: Arc<RwLock<HashMap<String, OAuthSession>>>,
    credentials: Arc<RwLock<Option<OAuthCredentials>>>,
    callback_path: String,
    secure_cookie: bool,
}

impl OAuthState {
    /// Create a new OAuth state manager
    pub fn new(config: OAuthConfig) -> AnyhowResult<Self> {
        let auth_url = AuthUrl::new(format!(
            "{}{}",
            config.auth_server_url, config.auth_endpoint
        ))
        .map_err(|e| anyhow!("Invalid auth URL: {}", e))?;

        let token_url = TokenUrl::new(format!(
            "{}{}",
            config.auth_server_url, config.token_endpoint
        ))
        .map_err(|e| anyhow!("Invalid token URL: {}", e))?;

        let redirect_url = RedirectUrl::new(config.redirect_uri.clone())
            .map_err(|e| anyhow!("Invalid redirect URL: {}", e))?;

        let callback = url::Url::parse(&config.redirect_uri)?;
        let callback_path = callback.path().to_string();
        let secure_cookie = callback.scheme() == "https";

        let mut client = BasicClient::new(ClientId::new(config.client_id.clone()));
        if let Some(secret) = config.client_secret.as_ref() {
            client = client.set_client_secret(ClientSecret::new(secret.clone()));
        }
        let client = client
            .set_auth_uri(auth_url)
            .set_token_uri(token_url)
            .set_redirect_uri(redirect_url);

        Ok(Self {
            config,
            client,
            sessions: Arc::new(RwLock::new(HashMap::new())),
            credentials: Arc::new(RwLock::new(None)),
            callback_path,
            secure_cookie,
        })
    }

    /// Start OAuth authorization flow
    pub fn start_authorization(&self) -> AnyhowResult<(String, String)> {
        let session_id = Uuid::new_v4().to_string();
        let csrf_token = Uuid::new_v4().to_string();

        let mut auth_request = self
            .client
            .authorize_url(|| CsrfToken::new(csrf_token.clone()));

        // Add scopes
        for scope in &self.config.scopes {
            auth_request = auth_request.add_scope(Scope::new(scope.clone()));
        }

        let pkce_verifier = if self.config.use_pkce {
            let (challenge, verifier) = PkceCodeChallenge::new_random_sha256();
            auth_request = auth_request.set_pkce_challenge(challenge);
            Some(verifier.secret().to_string())
        } else {
            None
        };

        let (auth_url, _csrf_token) = auth_request.url();

        // Store session
        let session = OAuthSession {
            session_id: session_id.clone(),
            pkce_verifier,
            csrf_token: csrf_token.clone(),
            original_scopes: self.config.scopes.clone(),
            created_at: SystemTime::now(),
        };

        {
            let mut sessions = self.sessions.write().unwrap();
            sessions.retain(|_, session| Self::session_is_current(session));
            if sessions.len() >= 1024 {
                return Err(anyhow!("Too many pending authorization sessions"));
            }
            sessions.insert(session_id.clone(), session);
        }

        Ok((auth_url.to_string(), session_id))
    }

    /// Handle OAuth callback
    pub async fn handle_callback(
        &self,
        code: String,
        state: String,
        session_id: String,
    ) -> AnyhowResult<OAuthCredentials> {
        let session = self.take_session(&session_id, &state)?;

        let credentials = self.exchange_code(&session, code).await?;
        self.store_credentials(credentials.clone());
        Ok(credentials)
    }

    /// Return the configured redirect URI path for registration on the HTTP router.
    pub fn callback_path(&self) -> &str {
        &self.callback_path
    }

    /// Bind authorization to the initiating browser using an HTTP-only session cookie.
    pub fn session_cookie(&self, session_id: &str) -> String {
        let secure = if self.secure_cookie { "; Secure" } else { "" };
        format!(
            "mcp_oauth_session={session_id}; Path={}; HttpOnly; SameSite=Lax; Max-Age=600{secure}",
            self.callback_path
        )
    }

    /// Clear the browser binding after a successful token exchange.
    pub fn clear_session_cookie(&self) -> String {
        self.session_cookie("").replace("Max-Age=600", "Max-Age=0")
    }

    /// Reject expired sessions, including timestamps unexpectedly in the future.
    fn session_is_current(session: &OAuthSession) -> bool {
        session
            .created_at
            .elapsed()
            .is_ok_and(|age| age < Duration::from_secs(600))
    }

    /// Validate and consume the session atomically before starting a token exchange.
    fn take_session(&self, session_id: &str, state: &str) -> AnyhowResult<OAuthSession> {
        let mut sessions = self.sessions.write().unwrap();
        let session = sessions
            .get(session_id)
            .ok_or_else(|| anyhow!("Invalid session ID"))?;
        if !Self::session_is_current(session) {
            sessions.remove(session_id);
            return Err(anyhow!("Authorization session expired"));
        }
        Self::validate_csrf(session, state)?;
        sessions
            .remove(session_id)
            .ok_or_else(|| anyhow!("Invalid session ID"))
    }

    /// Require the callback state to match the pending authorization session.
    fn validate_csrf(session: &OAuthSession, state: &str) -> AnyhowResult<()> {
        if session.csrf_token != state {
            Err(anyhow!("CSRF token mismatch"))
        } else {
            Ok(())
        }
    }

    /// Exchange a one-time authorization code with its original PKCE verifier.
    async fn exchange_code(
        &self,
        session: &OAuthSession,
        code: String,
    ) -> AnyhowResult<OAuthCredentials> {
        let mut token_request = self.client.exchange_code(AuthorizationCode::new(code));
        if let Some(verifier) = &session.pkce_verifier {
            token_request =
                token_request.set_pkce_verifier(PkceCodeVerifier::new(verifier.clone()));
        }

        let http_client = oauth2::reqwest::Client::builder()
            .redirect(oauth2::reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(20))
            .build()?;
        let token_response: StandardTokenResponse<
            EmptyExtraTokenFields,
            oauth2::basic::BasicTokenType,
        > = token_request
            .request_async(&http_client)
            .await
            .map_err(|e| anyhow!("Token exchange failed: {}", e))?;

        Ok(Self::build_credentials(token_response))
    }

    /// Preserve token metadata and issuance time for bearer validation and refresh.
    fn build_credentials(
        token_response: StandardTokenResponse<EmptyExtraTokenFields, oauth2::basic::BasicTokenType>,
    ) -> OAuthCredentials {
        let issued_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        OAuthCredentials {
            access_token: token_response.access_token().secret().to_string(),
            token_type: "Bearer".to_string(),
            expires_in: token_response.expires_in().map(|d| d.as_secs()),
            refresh_token: token_response
                .refresh_token()
                .map(|t| t.secret().to_string()),
            scope: token_response.scopes().map(|scopes| {
                scopes
                    .iter()
                    .map(|s| s.as_str())
                    .collect::<Vec<_>>()
                    .join(" ")
            }),
            issued_at,
        }
    }

    /// Replace the current credentials under the shared state lock.
    fn store_credentials(&self, credentials: OAuthCredentials) {
        let mut creds = self.credentials.write().unwrap();
        *creds = Some(credentials);
    }

    /// Get current credentials
    pub fn get_credentials(&self) -> Option<OAuthCredentials> {
        let creds = self.credentials.read().unwrap();
        creds.clone()
    }

    /// Refresh access token
    pub async fn refresh_token(&self) -> AnyhowResult<OAuthCredentials> {
        let refresh_token = {
            let creds = self.credentials.read().unwrap();
            creds
                .as_ref()
                .and_then(|c| c.refresh_token.clone())
                .ok_or_else(|| anyhow!("No refresh token available"))?
        };

        let token_response = self
            .client
            .exchange_refresh_token(&RefreshToken::new(refresh_token))
            .request_async(&oauth2::reqwest::Client::new())
            .await
            .map_err(|e| anyhow!("Token refresh failed: {}", e))?;
        let mut credentials = Self::build_credentials(token_response);
        if credentials.refresh_token.is_none() {
            let creds = self.credentials.read().unwrap();
            credentials.refresh_token = creds.as_ref().and_then(|c| c.refresh_token.clone());
        }
        self.store_credentials(credentials.clone());

        Ok(credentials)
    }

    /// Get valid access token (refresh if needed)
    pub async fn get_access_token(&self) -> AnyhowResult<String> {
        let (needs_refresh, token) = {
            let creds = self.credentials.read().unwrap();
            let c = creds
                .as_ref()
                .ok_or_else(|| anyhow!("No credentials available"))?;
            (
                c.needs_refresh(self.config.refresh_threshold),
                c.access_token.clone(),
            )
        };

        if needs_refresh {
            tracing::info!("Access token needs refresh, refreshing...");
            let refreshed = self.refresh_token().await?;
            Ok(refreshed.access_token)
        } else {
            Ok(token)
        }
    }
}

/// OAuth authentication error
#[derive(Debug)]
pub enum OAuthError {
    InvalidToken(String),
    MissingToken,
    ExpiredToken,
    AuthorizationFailed(String),
    TokenRefreshFailed(String),
}

impl std::fmt::Display for OAuthError {
    /// Format the OAuth error without changing its classification.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OAuthError::InvalidToken(msg) => write!(f, "Invalid OAuth token: {}", msg),
            OAuthError::MissingToken => write!(f, "Missing OAuth access token"),
            OAuthError::ExpiredToken => write!(f, "OAuth token has expired"),
            OAuthError::AuthorizationFailed(msg) => {
                write!(f, "OAuth authorization failed: {}", msg)
            }
            OAuthError::TokenRefreshFailed(msg) => write!(f, "Token refresh failed: {}", msg),
        }
    }
}

impl std::error::Error for OAuthError {}

impl IntoResponse for OAuthError {
    /// Map OAuth failures to the corresponding HTTP status and JSON error.
    fn into_response(self) -> Response {
        let (status, error_message) = match self {
            OAuthError::InvalidToken(_) => (axum::http::StatusCode::UNAUTHORIZED, self.to_string()),
            OAuthError::MissingToken => (axum::http::StatusCode::UNAUTHORIZED, self.to_string()),
            OAuthError::ExpiredToken => (axum::http::StatusCode::UNAUTHORIZED, self.to_string()),
            OAuthError::AuthorizationFailed(_) => {
                (axum::http::StatusCode::BAD_REQUEST, self.to_string())
            }
            OAuthError::TokenRefreshFailed(_) => (
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                self.to_string(),
            ),
        };

        let body = serde_json::json!({
            "error": error_message
        });

        (status, axum::Json(body)).into_response()
    }
}

/// Extractor for OAuth credentials from HTTP requests
pub struct OAuthClaims(pub OAuthCredentials);

impl<S> FromRequestParts<S> for OAuthClaims
where
    S: Send + Sync,
{
    type Rejection = OAuthError;

    /// Validate a bearer token against the installed OAuth state and expiration.
    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        // Try to extract Bearer token from Authorization header
        let auth_header = parts
            .headers
            .get("authorization")
            .and_then(|h| h.to_str().ok())
            .and_then(|h| h.strip_prefix("Bearer "))
            .ok_or(OAuthError::MissingToken)?;

        // Get OAuth state from extensions
        let oauth_state = parts
            .extensions
            .get::<OAuthState>()
            .ok_or_else(|| OAuthError::InvalidToken("OAuth not configured".to_string()))?;

        // Validate token by checking current credentials
        let credentials = oauth_state
            .get_credentials()
            .ok_or(OAuthError::InvalidToken("No valid credentials".to_string()))?;

        if credentials.access_token != auth_header {
            return Err(OAuthError::InvalidToken("Token mismatch".to_string()));
        }

        if credentials.is_expired() {
            return Err(OAuthError::ExpiredToken);
        }

        Ok(OAuthClaims(credentials))
    }
}

/// OAuth callback parameters
#[derive(Debug, Deserialize)]
pub struct CallbackParams {
    pub code: Option<String>,
    pub state: Option<String>,
    pub error: Option<String>,
    pub error_description: Option<String>,
    pub session_id: Option<String>,
}

/// Authorization server metadata (simplified)
#[derive(Debug, Serialize, Deserialize)]
pub struct AuthServerMetadata {
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub scopes_supported: Vec<String>,
    pub response_types_supported: Vec<String>,
    pub grant_types_supported: Vec<String>,
    pub code_challenge_methods_supported: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    /// Verify OAuth builder methods preserve client, scope, redirect, and endpoint settings.
    fn test_oauth_config_builder() {
        let config = OAuthConfig::new("test-client", "https://auth.example.com")
            .with_client_secret("secret123")
            .with_redirect_uri("https://app.example.com/callback")
            .with_scopes(vec!["read".to_string(), "write".to_string()])
            .with_endpoints("/auth", "/token");

        assert_eq!(config.client_id, "test-client");
        assert_eq!(config.client_secret, Some("secret123".to_string()));
        assert_eq!(config.auth_server_url, "https://auth.example.com");
        assert_eq!(config.redirect_uri, "https://app.example.com/callback");
        assert_eq!(config.scopes, vec!["read", "write"]);
        assert_eq!(config.auth_endpoint, "/auth");
        assert_eq!(config.token_endpoint, "/token");
    }

    #[test]
    /// Distinguish expired credentials from tokens approaching their refresh threshold.
    fn test_oauth_credentials_expiration() {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Token that expires in 1 hour
        let credentials = OAuthCredentials {
            access_token: "test-token".to_string(),
            token_type: "Bearer".to_string(),
            expires_in: Some(3600),
            refresh_token: Some("refresh-token".to_string()),
            scope: Some("mcp profile".to_string()),
            issued_at: now,
        };

        // Should not be expired or need refresh yet
        assert!(!credentials.is_expired());
        assert!(!credentials.needs_refresh(Duration::from_secs(300)));

        // But should need refresh with large threshold
        assert!(credentials.needs_refresh(Duration::from_secs(3700)));
    }

    #[tokio::test]
    /// Require authorization URLs to contain a browser session, redirect URI, and PKCE challenge.
    async fn test_oauth_state_creation() {
        let config = OAuthConfig::default();
        let state = OAuthState::new(config).unwrap();

        // Should be able to start authorization
        let (auth_url, session_id) = state.start_authorization().unwrap();
        assert!(!auth_url.is_empty());
        assert!(!session_id.is_empty());
        assert!(auth_url.contains("client_id"));
        assert!(auth_url.contains("redirect_uri"));
        assert!(auth_url.contains("code_challenge")); // PKCE
    }
    /// Expired browser sessions fail before any network exchange and are removed.
    #[tokio::test]
    async fn expired_authorization_session_cannot_exchange_a_code() {
        let state = OAuthState::new(OAuthConfig::default()).unwrap();
        let (_, session_id) = state.start_authorization().unwrap();
        let csrf = {
            let mut sessions = state.sessions.write().unwrap();
            let session = sessions.get_mut(&session_id).unwrap();
            session.created_at = SystemTime::now() - Duration::from_secs(601);
            session.csrf_token.clone()
        };
        assert!(
            state
                .handle_callback("fixture-code".into(), csrf, session_id.clone())
                .await
                .is_err()
        );
        assert!(!state.sessions.read().unwrap().contains_key(&session_id));
    }
    /// Keep registered query parameters and native-app redirect schemes compatible with the library API.
    #[test]
    fn authorization_preserves_existing_redirect_uri_forms() {
        for uri in [
            "https://app.example.com/callback?tenant=fixture",
            "fixture-app:/callback?tenant=fixture",
        ] {
            let state = OAuthState::new(OAuthConfig::default().with_redirect_uri(uri)).unwrap();
            let (location, _) = state.start_authorization().unwrap();
            let location = url::Url::parse(&location).unwrap();
            let redirect = location
                .query_pairs()
                .find(|(key, _)| key == "redirect_uri")
                .unwrap()
                .1;
            assert_eq!(redirect, uri);
        }
    }
}
