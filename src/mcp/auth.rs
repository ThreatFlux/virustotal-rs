use anyhow::{anyhow, Result as AnyhowResult};
use axum::{
    async_trait,
    extract::FromRequestParts,
    http::request::Parts,
    response::{IntoResponse, Response},
    RequestPartsExt,
};
use axum_extra::{
    headers::{authorization::Bearer, Authorization},
    TypedHeader,
};
use base64::Engine;
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use std::fmt;
use uuid::Uuid;

/// JWT authentication configuration
#[derive(Debug, Clone)]
pub struct JwtConfig {
    /// Secret key for signing/verifying JWTs
    pub secret: String,
    /// Token expiration time in seconds (default: 24 hours)
    pub expiration_seconds: u64,
    /// JWT issuer (default: "virustotal-mcp")
    pub issuer: String,
    /// JWT audience (default: "virustotal-mcp-client")
    pub audience: String,
}

impl Default for JwtConfig {
    fn default() -> Self {
        Self {
            secret: Self::generate_secret(),
            expiration_seconds: 24 * 60 * 60, // 24 hours
            issuer: "virustotal-mcp".to_string(),
            audience: "virustotal-mcp-client".to_string(),
        }
    }
}

impl JwtConfig {
    /// Create a new JWT config with a custom secret
    pub fn new(secret: impl Into<String>) -> Self {
        Self {
            secret: secret.into(),
            ..Default::default()
        }
    }

    /// Generate a random secret key
    pub fn generate_secret() -> String {
        use sha2::{Digest, Sha256};
        let uuid = Uuid::new_v4();
        let mut hasher = Sha256::new();
        hasher.update(uuid.as_bytes());
        hasher.update(b"virustotal-mcp-secret");
        base64::engine::general_purpose::STANDARD.encode(hasher.finalize())
    }

    /// Set expiration time in seconds
    pub fn with_expiration(mut self, seconds: u64) -> Self {
        self.expiration_seconds = seconds;
        self
    }

    /// Set issuer
    pub fn with_issuer(mut self, issuer: impl Into<String>) -> Self {
        self.issuer = issuer.into();
        self
    }

    /// Set audience
    pub fn with_audience(mut self, audience: impl Into<String>) -> Self {
        self.audience = audience.into();
        self
    }
}

/// JWT claims structure
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Claims {
    /// Subject (user ID)
    pub sub: String,
    /// Issuer
    pub iss: String,
    /// Audience
    pub aud: String,
    /// Issued at (timestamp)
    pub iat: usize,
    /// Expiration time (timestamp)
    pub exp: usize,
    /// JWT ID (unique identifier)
    pub jti: String,
    /// User role (e.g., "admin", "user")
    pub role: String,
    /// Custom permissions
    pub permissions: Vec<String>,
}

impl Claims {
    /// Create new claims for a user
    pub fn new(user_id: impl Into<String>, role: impl Into<String>, config: &JwtConfig) -> Self {
        let now = chrono::Utc::now().timestamp() as usize;
        let exp = now + config.expiration_seconds as usize;

        Self {
            sub: user_id.into(),
            iss: config.issuer.clone(),
            aud: config.audience.clone(),
            iat: now,
            exp,
            jti: Uuid::new_v4().to_string(),
            role: role.into(),
            permissions: vec!["mcp:access".to_string()],
        }
    }

    /// Add a permission to the claims
    pub fn with_permission(mut self, permission: impl Into<String>) -> Self {
        self.permissions.push(permission.into());
        self
    }

    /// Check if the user has a specific permission
    pub fn has_permission(&self, permission: &str) -> bool {
        self.permissions.contains(&permission.to_string())
    }

    /// Check if the token is expired
    pub fn is_expired(&self) -> bool {
        let now = chrono::Utc::now().timestamp() as usize;
        self.exp < now
    }
}

/// JWT token manager for encoding and decoding tokens
#[derive(Clone)]
pub struct JwtManager {
    config: JwtConfig,
    encoding_key: EncodingKey,
    decoding_key: DecodingKey,
    validation: Validation,
}

impl std::fmt::Debug for JwtManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("JwtManager")
            .field("config", &self.config)
            .field("encoding_key", &"[REDACTED]")
            .field("decoding_key", &"[REDACTED]")
            .field("validation", &self.validation)
            .finish()
    }
}

impl JwtManager {
    /// Create a new JWT manager
    pub fn new(config: JwtConfig) -> Self {
        let encoding_key = EncodingKey::from_secret(config.secret.as_bytes());
        let decoding_key = DecodingKey::from_secret(config.secret.as_bytes());

        let mut validation = Validation::new(Algorithm::HS256);
        validation.set_issuer(&[&config.issuer]);
        validation.set_audience(&[&config.audience]);

        Self {
            config,
            encoding_key,
            decoding_key,
            validation,
        }
    }

    /// Generate a JWT token for a user
    pub fn generate_token(
        &self,
        user_id: impl Into<String>,
        role: impl Into<String>,
    ) -> AnyhowResult<String> {
        let claims = Claims::new(user_id, role, &self.config);
        let header = Header::new(Algorithm::HS256);

        encode(&header, &claims, &self.encoding_key)
            .map_err(|e| anyhow!("Failed to encode JWT: {}", e))
    }

    /// Generate a token with custom permissions
    pub fn generate_token_with_permissions(
        &self,
        user_id: impl Into<String>,
        role: impl Into<String>,
        permissions: Vec<String>,
    ) -> AnyhowResult<String> {
        let mut claims = Claims::new(user_id, role, &self.config);
        claims.permissions = permissions;
        let header = Header::new(Algorithm::HS256);

        encode(&header, &claims, &self.encoding_key)
            .map_err(|e| anyhow!("Failed to encode JWT: {}", e))
    }

    /// Validate and decode a JWT token
    pub fn validate_token(&self, token: &str) -> AnyhowResult<Claims> {
        let token_data = decode::<Claims>(token, &self.decoding_key, &self.validation)
            .map_err(|e| anyhow!("Failed to decode JWT: {}", e))?;

        let claims = token_data.claims;

        // Additional validation
        if claims.is_expired() {
            return Err(anyhow!("Token has expired"));
        }

        Ok(claims)
    }

    /// Create an admin token with full permissions
    pub fn generate_admin_token(&self, admin_id: impl Into<String>) -> AnyhowResult<String> {
        self.generate_token_with_permissions(
            admin_id,
            "admin",
            vec![
                "mcp:access".to_string(),
                "mcp:admin".to_string(),
                "vt:scan".to_string(),
                "vt:search".to_string(),
                "vt:download".to_string(),
            ],
        )
    }

    /// Create a read-only token
    pub fn generate_readonly_token(&self, user_id: impl Into<String>) -> AnyhowResult<String> {
        self.generate_token_with_permissions(
            user_id,
            "readonly",
            vec!["mcp:access".to_string(), "vt:search".to_string()],
        )
    }
}

/// JWT authentication error
#[derive(Debug)]
pub enum AuthError {
    InvalidToken(String),
    MissingToken,
    ExpiredToken,
    InsufficientPermissions,
}

impl fmt::Display for AuthError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AuthError::InvalidToken(msg) => write!(f, "Invalid token: {}", msg),
            AuthError::MissingToken => write!(f, "Missing authorization token"),
            AuthError::ExpiredToken => write!(f, "Token has expired"),
            AuthError::InsufficientPermissions => write!(f, "Insufficient permissions"),
        }
    }
}

impl std::error::Error for AuthError {}

impl IntoResponse for AuthError {
    fn into_response(self) -> Response {
        let (status, error_message) = match self {
            AuthError::InvalidToken(_) => (axum::http::StatusCode::UNAUTHORIZED, self.to_string()),
            AuthError::MissingToken => (axum::http::StatusCode::UNAUTHORIZED, self.to_string()),
            AuthError::ExpiredToken => (axum::http::StatusCode::UNAUTHORIZED, self.to_string()),
            AuthError::InsufficientPermissions => {
                (axum::http::StatusCode::FORBIDDEN, self.to_string())
            }
        };

        let body = serde_json::json!({
            "error": error_message
        });

        (status, axum::Json(body)).into_response()
    }
}

/// Extractor for JWT claims from HTTP requests
pub struct JwtClaims(pub Claims);

#[async_trait]
impl<S> FromRequestParts<S> for JwtClaims
where
    S: Send + Sync,
{
    type Rejection = AuthError;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        // Try to extract the Authorization header
        let TypedHeader(Authorization(bearer)) = parts
            .extract::<TypedHeader<Authorization<Bearer>>>()
            .await
            .map_err(|_| AuthError::MissingToken)?;

        // Get the JWT manager from extensions
        let jwt_manager = parts
            .extensions
            .get::<JwtManager>()
            .ok_or(AuthError::InvalidToken(
                "JWT manager not configured".to_string(),
            ))?;

        // Validate the token
        let claims = jwt_manager
            .validate_token(bearer.token())
            .map_err(|e| AuthError::InvalidToken(e.to_string()))?;

        Ok(JwtClaims(claims))
    }
}

/// Middleware layer for JWT authentication
#[derive(Clone)]
pub struct JwtAuthLayer {
    jwt_manager: JwtManager,
}

impl JwtAuthLayer {
    pub fn new(jwt_manager: JwtManager) -> Self {
        Self { jwt_manager }
    }
}

impl<S> tower::Layer<S> for JwtAuthLayer {
    type Service = JwtAuthMiddleware<S>;

    fn layer(&self, inner: S) -> Self::Service {
        JwtAuthMiddleware {
            inner,
            jwt_manager: self.jwt_manager.clone(),
        }
    }
}

/// Middleware service for JWT authentication
#[derive(Clone)]
pub struct JwtAuthMiddleware<S> {
    inner: S,
    jwt_manager: JwtManager,
}

impl<S> tower::Service<axum::http::Request<axum::body::Body>> for JwtAuthMiddleware<S>
where
    S: tower::Service<axum::http::Request<axum::body::Body>, Response = axum::response::Response>
        + Send
        + Clone
        + 'static,
    S::Future: Send + 'static,
    S::Error: Send + 'static,
{
    type Response = axum::response::Response;
    type Error = S::Error;
    type Future = std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<Self::Response, Self::Error>> + Send>,
    >;

    fn poll_ready(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, mut req: axum::http::Request<axum::body::Body>) -> Self::Future {
        let jwt_manager = self.jwt_manager.clone();
        let mut inner = self.inner.clone();

        Box::pin(async move {
            // Insert JWT manager into request extensions
            req.extensions_mut().insert(jwt_manager);

            // Call the inner service
            inner.call(req).await
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_jwt_config_default() {
        let config = JwtConfig::default();
        assert!(!config.secret.is_empty());
        assert_eq!(config.expiration_seconds, 24 * 60 * 60);
        assert_eq!(config.issuer, "virustotal-mcp");
        assert_eq!(config.audience, "virustotal-mcp-client");
    }

    #[test]
    fn test_jwt_config_builder() {
        let config = JwtConfig::new("test-secret")
            .with_expiration(3600)
            .with_issuer("test-issuer")
            .with_audience("test-audience");

        assert_eq!(config.secret, "test-secret");
        assert_eq!(config.expiration_seconds, 3600);
        assert_eq!(config.issuer, "test-issuer");
        assert_eq!(config.audience, "test-audience");
    }

    #[test]
    fn test_claims_creation() {
        let config = JwtConfig::default();
        let claims = Claims::new("user123", "admin", &config);

        assert_eq!(claims.sub, "user123");
        assert_eq!(claims.role, "admin");
        assert_eq!(claims.iss, config.issuer);
        assert_eq!(claims.aud, config.audience);
        assert!(claims.has_permission("mcp:access"));
    }

    #[test]
    fn test_jwt_token_generation_and_validation() {
        let config = JwtConfig::new("test-secret");
        let manager = JwtManager::new(config);

        // Generate a token
        let token = manager.generate_token("user123", "admin").unwrap();
        assert!(!token.is_empty());

        // Validate the token
        let claims = manager.validate_token(&token).unwrap();
        assert_eq!(claims.sub, "user123");
        assert_eq!(claims.role, "admin");
        assert!(claims.has_permission("mcp:access"));
    }

    #[test]
    fn test_admin_token_permissions() {
        let config = JwtConfig::new("test-secret");
        let manager = JwtManager::new(config);

        let token = manager.generate_admin_token("admin123").unwrap();
        let claims = manager.validate_token(&token).unwrap();

        assert_eq!(claims.sub, "admin123");
        assert_eq!(claims.role, "admin");
        assert!(claims.has_permission("mcp:access"));
        assert!(claims.has_permission("mcp:admin"));
        assert!(claims.has_permission("vt:scan"));
        assert!(claims.has_permission("vt:search"));
        assert!(claims.has_permission("vt:download"));
    }

    #[test]
    fn test_readonly_token_permissions() {
        let config = JwtConfig::new("test-secret");
        let manager = JwtManager::new(config);

        let token = manager.generate_readonly_token("user123").unwrap();
        let claims = manager.validate_token(&token).unwrap();

        assert_eq!(claims.sub, "user123");
        assert_eq!(claims.role, "readonly");
        assert!(claims.has_permission("mcp:access"));
        assert!(claims.has_permission("vt:search"));
        assert!(!claims.has_permission("vt:scan"));
        assert!(!claims.has_permission("mcp:admin"));
    }

    #[test]
    fn test_invalid_token() {
        let config = JwtConfig::new("test-secret");
        let manager = JwtManager::new(config);

        let result = manager.validate_token("invalid-token");
        assert!(result.is_err());
    }

    #[test]
    fn test_token_with_wrong_secret() {
        let config1 = JwtConfig::new("secret1");
        let manager1 = JwtManager::new(config1);

        let config2 = JwtConfig::new("secret2");
        let manager2 = JwtManager::new(config2);

        let token = manager1.generate_token("user123", "admin").unwrap();
        let result = manager2.validate_token(&token);
        assert!(result.is_err());
    }
}
