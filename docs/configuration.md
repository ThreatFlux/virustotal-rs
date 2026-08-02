# Configuration and runtime behavior

This guide documents behavior implemented on the current `main` branch. Published releases can differ; use the version selector on [docs.rs](https://docs.rs/virustotal-rs) when working from crates.io.

## Credentials

VirusTotal API v3 authenticates with an API key in the `x-apikey` header. Keep the key out of source control, logs, panic messages, issue reports, and shell history. VirusTotal's [authentication guide](https://docs.virustotal.com/reference/authentication) treats the key as carrying all of the user's privileges.

The core `ClientBuilder` accepts a key explicitly and does not read the environment:

```rust,no_run
use virustotal_rs::{ApiTier, ClientBuilder};

let client = ClientBuilder::new()
    .api_key(std::env::var("VIRUSTOTAL_API_KEY")?)
    .tier(ApiTier::Public)
    .build()?;
# Ok::<(), Box<dyn std::error::Error>>(())
```

Environment helpers and binaries use these variables:

| Consumer | Variable order or requirement |
| --- | --- |
| `ClientUtils::from_common_env()` | First present: `VIRUSTOTAL_API_KEY`, `VT_API_KEY`, `VTI_API_KEY` |
| `ClientUtils::from_private_env()` | First present: `VT_PRIVATE_API_KEY`, `VIRUSTOTAL_PRIVATE_API_KEY` |
| `vt-cli` | `--api-key`, then `VTI_API_KEY` |
| `mcp_server` | Requires `VIRUSTOTAL_API_KEY`; optional `VIRUSTOTAL_API_TIER` |

Use `VIRUSTOTAL_API_KEY` for new library integrations. The additional names exist for compatibility with existing applications and examples.

## Client builders

`ClientBuilder` is the recommended production entry point.

| Setting | Default | Applied by `ClientBuilder` | Applied by `EnhancedClientBuilder` |
| --- | --- | --- | --- |
| API key | Required | Yes | Yes |
| API tier | `Public` | Yes | Yes |
| Timeout | 30 seconds | Yes | Yes |
| Base URL | `https://www.virustotal.com/api/v3/` | Yes | Yes |
| Retry configuration | No automatic retries | Not available | **Stored, but not applied by `build()`** |
| Custom rate limiter | Tier-derived core limiter | Not available | **Stored, but not applied by `build()`** |
| Custom headers | `Accept` and `x-apikey` per request | Not available | **Stored, but not applied by `build()`** |
| Custom user agent | `virustotal-rs/<crate-version>` | Not available | **Stored, but not applied by `build()`** |

The compatibility setters remain callable so existing source continues to compile, but calling `retry_config`, `advanced_retry_config`, `rate_limiter`, `header`, `headers`, or `user_agent` on `EnhancedClientBuilder` does not change the returned `Client` today. Do not rely on those settings until an implementation change is documented and released.

`with_tier_detection()` is applied, but it guesses from API-key format and length. It is not an account lookup and cannot establish actual privileges. Prefer `.tier(ApiTier::Public)` or `.tier(ApiTier::Premium)` explicitly.

## Base URL and timeout

The default timeout covers each HTTP request and is 30 seconds. Both builders accept a `Duration` override.

The base URL is joined with relative endpoint paths. A custom URL should therefore:

- use HTTPS;
- point to a trusted service;
- include the required API version path; and
- end with `/` so URL joining preserves the final path segment.

The SDK sends `x-apikey` to the configured base URL. Never use an untrusted proxy or an accidental non-production host with a real key.

## Rate limits and quotas

Each core `Client` owns an in-memory limiter selected by `ApiTier`:

- `Public` allows 4 requests per minute and tracks up to 500 requests over a 24-hour period beginning when that limiter is created.
- `Premium` has no client-side throttle.

The limiter is not shared between clients, processes, containers, or hosts, and its daily window is not synchronized to VirusTotal's reset schedule. It is a guardrail, not a distributed quota manager. VirusTotal's server-side [per-minute, daily, and monthly quotas](https://docs.virustotal.com/docs/consumption-quotas-handled) remain authoritative and can return `TooManyRequests` or `QuotaExceeded`.

## Retries and errors

Core client methods make one HTTP attempt. They do not retry automatically.

`RetryUtils::retry_request` is an opt-in helper that retries SDK errors classified as `TooManyRequests`, `TransientError`, or `DeadlineExceeded` according to a `RetryConfig`. Apply it only when replaying the operation is safe. Reads are usually better candidates than uploads, scans, comments, votes, or lifecycle mutations.

```rust,no_run
use std::time::Duration;
use virustotal_rs::{RetryConfig, client_utils::RetryUtils};
# use virustotal_rs::{ApiTier, ClientBuilder};
# async fn example() -> Result<(), Box<dyn std::error::Error>> {
# let client = ClientBuilder::new().api_key("redacted").tier(ApiTier::Public).build()?;

let config = RetryConfig::new(3, Duration::from_secs(1));
let report = RetryUtils::retry_request(
    || client.files().get("44d88612fea8a8f36de82e1278abb02f"),
    &config,
)
.await?;
# let _ = report;
# Ok(())
# }
```

Match typed `Error` variants when an application needs different handling for authentication, authorization, quota, validation, transport, or parsing failures. Avoid retrying non-retryable 4xx errors.

## Data handling

Public file/URL submission and private scanning have different visibility and licensing properties. Confirm the destination and account entitlement before uploading files or submitting URLs. Review VirusTotal's [getting-started guidance](https://docs.virustotal.com/reference/getting-started) and [Private Scanning documentation](https://docs.virustotal.com/docs/private-scanning); the SDK cannot determine whether content is safe or authorized to share.
