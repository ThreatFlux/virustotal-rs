//! Private OAuth2 protocol from the verified public 5.0.0 archive.
//! See third_party/oauth2 for original authors, licenses and source custody.

/// Basic OAuth2 implementation with no extensions
/// ([RFC 6749](https://tools.ietf.org/html/rfc6749)).
pub mod basic;

mod client;

mod code;

/// HTTP client backed by the [curl](https://crates.io/crates/curl) crate.
/// Requires "curl" feature.
#[cfg(all(any(), not(target_arch = "wasm32")))]
mod curl_client;

#[cfg(all(any(), target_arch = "wasm32"))]
compile_error!(
    "wasm32 is not supported with the `curl` feature. Use the `reqwest` backend or a custom backend for wasm32 support"
);

/// Device Authorization Flow OAuth2 implementation
/// ([RFC 8628](https://tools.ietf.org/html/rfc8628)).
mod devicecode;

mod endpoint;

mod error;

/// Helper methods used by OAuth2 implementations/extensions.
pub mod helpers;

mod introspection;

/// HTTP client backed by the [reqwest](https://crates.io/crates/reqwest) crate.
/// Requires "reqwest" feature.
#[cfg(any(feature = "mcp-oauth", any()))]
mod reqwest_client;

/// OAuth 2.0 Token Revocation implementation
/// ([RFC 7009](https://tools.ietf.org/html/rfc7009)).
mod revocation;

#[cfg(test)]
mod tests;

mod token;

mod types;

/// HTTP client backed by the [ureq](https://crates.io/crates/ureq) crate.
/// Requires "ureq" feature.
#[cfg(any())]
mod ureq_client;

pub use crate::mcp::oauth_protocol::client::{
    Client, EndpointMaybeSet, EndpointNotSet, EndpointSet, EndpointState,
};
pub use crate::mcp::oauth_protocol::code::AuthorizationRequest;
#[cfg(all(any(), not(target_arch = "wasm32")))]
pub use crate::mcp::oauth_protocol::curl_client::CurlHttpClient;
pub use crate::mcp::oauth_protocol::devicecode::{
    DeviceAccessTokenRequest, DeviceAuthorizationRequest, DeviceAuthorizationResponse,
    DeviceCodeErrorResponse, DeviceCodeErrorResponseType, EmptyExtraDeviceAuthorizationFields,
    ExtraDeviceAuthorizationFields, StandardDeviceAuthorizationResponse,
};
pub use crate::mcp::oauth_protocol::endpoint::{
    AsyncHttpClient, HttpRequest, HttpResponse, SyncHttpClient,
};
pub use crate::mcp::oauth_protocol::error::{
    ErrorResponse, ErrorResponseType, RequestTokenError, StandardErrorResponse,
};
pub use crate::mcp::oauth_protocol::introspection::{
    IntrospectionRequest, StandardTokenIntrospectionResponse, TokenIntrospectionResponse,
};
pub use crate::mcp::oauth_protocol::revocation::{
    RevocableToken, RevocationErrorResponseType, RevocationRequest, StandardRevocableToken,
};
pub use crate::mcp::oauth_protocol::token::{
    ClientCredentialsTokenRequest, CodeTokenRequest, EmptyExtraTokenFields, ExtraTokenFields,
    PasswordTokenRequest, RefreshTokenRequest, StandardTokenResponse, TokenResponse, TokenType,
};
pub use crate::mcp::oauth_protocol::types::{
    AccessToken, AuthUrl, AuthorizationCode, ClientId, ClientSecret, CsrfToken,
    DeviceAuthorizationUrl, DeviceCode, EndUserVerificationUrl, IntrospectionUrl,
    PkceCodeChallenge, PkceCodeChallengeMethod, PkceCodeVerifier, RedirectUrl, RefreshToken,
    ResourceOwnerPassword, ResourceOwnerUsername, ResponseType, RevocationUrl, Scope, TokenUrl,
    UserCode, VerificationUriComplete,
};
use std::error::Error;

/// Public re-exports of types used for HTTP client interfaces.
pub use http;
pub use url;

#[cfg(all(any(), not(target_arch = "wasm32")))]
pub use ::curl;

#[cfg(any(feature = "mcp-oauth", any()))]
pub use ::reqwest;

#[cfg(any())]
pub use ::ureq;

const CONTENT_TYPE_JSON: &str = "application/json";
const CONTENT_TYPE_FORMENCODED: &str = "application/x-www-form-urlencoded";

/// There was a problem configuring the request.
#[non_exhaustive]
#[derive(Debug, thiserror::Error)]
pub enum ConfigurationError {
    /// The endpoint URL is not set.
    #[error("No {0} endpoint URL specified")]
    MissingUrl(&'static str),
    /// The endpoint URL to be contacted MUST be HTTPS.
    #[error("Scheme for {0} endpoint URL must be HTTPS")]
    InsecureUrl(&'static str),
}

/// Indicates whether requests to the authorization server should use basic authentication or
/// include the parameters in the request body for requests in which either is valid.
///
/// The default AuthType is *BasicAuth*, following the recommendation of
/// [Section 2.3.1 of RFC 6749](https://tools.ietf.org/html/rfc6749#section-2.3.1).
#[derive(Clone, Debug)]
#[non_exhaustive]
pub enum AuthType {
    /// The client_id and client_secret (if set) will be included as part of the request body.
    RequestBody,
    /// The client_id and client_secret will be included using the basic auth authentication scheme.
    BasicAuth,
}

/// Error type returned by built-in HTTP clients when requests fail.
#[non_exhaustive]
#[derive(Debug, thiserror::Error)]
pub enum HttpClientError<RE>
where
    RE: Error + 'static,
{
    /// Error returned by reqwest crate.
    #[error("client error")]
    Reqwest(#[from] Box<RE>),
    /// Non-reqwest HTTP error.
    #[error("HTTP error")]
    Http(#[from] http::Error),
    /// I/O error.
    #[error("I/O error")]
    Io(#[from] std::io::Error),
    /// Other error.
    #[error("{}", _0)]
    Other(String),
}

#[cfg(test)]
mod maintained_time_tests;
