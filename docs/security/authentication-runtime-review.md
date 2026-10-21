# MCP container authentication compatibility

The maintained container compiles all existing MCP, JWT, OAuth and CLI features. During restoration of a runnable container, inspection found that `mcp_server` called the plain HTTP transport even when JWT/OAuth environment settings were supplied. HTTP startup now uses the existing environment configuration path while retaining the established default address and stdio behavior.

The old JWT token endpoint accepted built-in `admin/admin123` and `user/user123` logins. Those fallbacks are removed. Password token issuance now requires explicitly configured `MCP_AUTH_USERNAME` and `MCP_AUTH_PASSWORD`; missing/empty settings fail authentication. Comparisons hash both sides with SHA-256 before using the `subtle` constant-time API, so differing credential lengths do not trigger a slice-length early exit. `MCP_AUTH_ROLE` accepts `readonly` (default) or `admin`; other values fail closed. Applications can continue presenting correctly signed external JWTs without enabling a password token issuer.

When `ENABLE_JWT` is set, startup requires a nonempty `JWT_SECRET`. This provides explicit deployment signing-key configuration. The library's `JwtConfig::default` generates a fresh random key; it was not a known fixed default secret and is not described as one. Store real credentials in local environment/secrets facilities, never in Git. Passwords used by regression fixtures are fabricated test values.

Compatibility: deployments that relied on the demo logins must configure credentials and a signing secret. Deployments that previously set authentication variables without enforcement will now enforce the requested mode. `ENABLE_OAUTH` retains the library's OAuth configuration and takes precedence when both modes are requested, as in the existing library server builder. No authentication mode is silently dropped at build time.

Focused validation covers missing-secret startup rejection, rejection of absent/incorrect credentials and demo fallbacks, successful configured token issuance, unauthenticated MCP rejection, accepted valid JWT requests, and OAuth authorization redirect behavior. The mock checks do not call VirusTotal or an identity provider with real credentials.

A requested JWT or OAuth mode also fails startup when the corresponding Cargo feature was not compiled. The focused feature-matrix test passes explicit booleans into the same startup validator, avoiding global environment mutation in parallel Rust tests. OAuth fixture coverage now completes a PKCE authorization-code exchange against an isolated identity provider, then uses the returned bearer token for a real MCP request. It rejects missing browser cookies, incorrect state, invalid bearer tokens, expired sessions, and callback replay. No real provider credentials are used.

HTTP configuration preserves the binary’s existing `Premium` and lowercase `premium` tier spellings. A pure parser regression test covers both and the public-tier default, so routing through the shared environment helper does not silently downgrade an existing deployment.

The real MCP `get_file_report` tool also fetches a synthetic file report over HTTPS through a local CONNECT fixture using the SDK’s existing proxy support. The proxy permits only the expected hostname, serves fabricated data itself, and never forwards traffic to VirusTotal. The fixture verifies the fabricated API-key header, successful parsed report, unknown-issuer rejection and hostname rejection with certificate-specific logs. Default production URLs and certificate validation remain unchanged.

A final real-container audit found two additional defects: startup diagnostics polluted the stdio JSON-RPC stream, and the shared authenticated startup helper minted and logged a valid sample admin JWT using the configured signing key. Both are fixed: diagnostics go to stderr, startup never mints/logs credentials or tokens, and the container test rejects any non-JSON stdout or JWT/demo-credential leakage in logs. For older deployments using that authenticated helper, previously logged tokens require signing-key rotation to revoke; removing the logging does not invalidate existing tokens. No production credentials were accessed during this review.

OAuth registers the callback path from `OAUTH_REDIRECT_URI`. Set that variable to the externally reachable HTTP(S) callback URI registered with your identity provider; the library default remains `http://localhost:3001/auth/callback`. The authorization response binds the random session ID in an HttpOnly, SameSite=Lax cookie scoped to that callback path (Secure for HTTPS). Sessions expire after ten minutes and are consumed atomically before token exchange. Successful callback responses return the provider credentials as JSON, clear the cookie, and use `Cache-Control: no-store` and `Referrer-Policy: no-referrer`. The HTTP router installs the shared OAuth state for bearer claims validation. Token exchange uses a bounded client that refuses redirects.

Container verification subprocesses have explicit timeouts. Cleanup failures remain fatal after successful validation; if validation already failed, cleanup diagnostics are reported without replacing the primary exception. The image contains no built-in healthcheck executable: deployment orchestrators should probe the unauthenticated `/health` endpoint externally, as the container smoke tests do.

The SHA-256 outputs used for credential comparison are transient, fixed-width inputs to `subtle::ConstantTimeEq`; they are never persisted, transmitted, or used as stored password verifiers. CodeQL alerts [218](https://github.com/ThreatFlux/virustotal-rs/security/code-scanning/218) and [219](https://github.com/ThreatFlux/virustotal-rs/security/code-scanning/219) classified this normalization as password-storage hashing. Both were reviewed and dismissed as false positives with that specific rationale; the query remains enabled.

OAuth HTTP bearer validation indexes credentials by each client's access token. A later browser login cannot replace another client's authentication state. Expired entries are reclaimed on issuance; a full active-client registry rejects additional issuance rather than evicting a valid client. The existing single-client library accessors retain their latest-credential behavior for compatibility. Router and real-binary regressions authorize both independent tokens after the second login, and test capacity/expiry behavior.

TLS negative fixtures first require a JSON-RPC error and zero upstream API requests, then verify the certificate-specific diagnostic emitted by the TLS backend at ERROR level. The serialized JSON-RPC message contains only the generic request failure; the underlying logs distinguish `UnknownIssuer` and the invalid hostname. Both platform runs in [container verification 39640122746](https://github.com/ThreatFlux/virustotal-rs/actions/runs/39640122746) passed these assertions. A direct fixture inspection also confirmed the two backend diagnostics; changing the assertion to accept only the generic JSON-RPC error would lose that certificate-specific evidence.

Anonymous `/oauth/authorize` requests are limited to a burst of 30 and a sustained 30 per minute per TCP peer (IPv6 /64, with IPv4-mapped addresses normalized). The server supplies connection metadata directly, ignores forwarding headers for this decision, returns HTTP 429 with `Retry-After: 2` when throttled, and reclaims inactive rate-limit state. One peer therefore cannot fill the 1,024 pending slots within their ten-minute lifetime. Behind a reverse proxy, the budget applies to that proxy's peer address; normal authenticated MCP requests are unaffected. A regression floods one peer while rotating spoofed forwarding headers and verifies that an independent peer can still authorize.

Unrecognized `SERVER_MODE` values now fail before starting a listener; an unset value still selects HTTP. JWT issuance and refresh responses advertise the configured lifetime used in their signed `exp` claims. For OAuth providers that omit `expires_in`, HTTP authentication records receive a one-hour server-side lifetime, returned in the callback response and enforced/reclaimed by the client registry. The legacy single-client library metadata retains the provider's original expiration information. Regressions cover both JWT response paths, absent OAuth expiry, registry reclamation, and invalid transport startup.

OAuth callback token grants must include every requested scope; an omitted scope inherits the
requested set, while an explicit reduction is rejected before storing credentials. Refresh grants
use the same rule. Public HTTP callback hosts require HTTPS; plaintext redirects are restricted to
loopback IP addresses and `localhost`. Standalone OAuth clients retain custom redirect schemes.

Authorization and token endpoints also require HTTPS outside explicit loopback hosts, including
standalone OAuth clients; validation uses both effective endpoint URLs before any authorization
traffic. Token issuance and refresh use a timeout and refuse redirects. `SSL_CERT_FILE` may supply
an explicit PEM CA bundle for private identity providers; peer and hostname verification remain
enabled, and an invalid or empty bundle fails closed. The container identity-provider fixture now
uses TLS with a temporary CA: an untrusted-provider exchange must fail without transmitting a code,
while an explicitly trusted provider completes the existing PKCE, callback, multi-client and rate
limit checks. No plaintext host-gateway exception or certificate-verification bypass is introduced.

Empty comma-separated scope entries and blank builder entries are excluded from authorization and
grant validation, without accepting a grant missing any nonempty requested scope. Keyed limiter
cleanup runs at most once per 30 seconds rather than scanning the map on every anonymous request;
the per-peer quota and public unwind-safety traits remain unchanged.

Environment-backed OAuth startup requires explicit nonempty `OAUTH_AUTH_SERVER_URL` and
`OAUTH_REDIRECT_URI` values. Missing settings fail before listening, rather than inheriting
standalone-library defaults that can point authorization back at the MCP endpoint or target a
different callback port. Explicit builder configuration retains its existing library defaults.
