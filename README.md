<div align="center">

# virustotal-rs

[![CI](https://github.com/ThreatFlux/virustotal-rs/actions/workflows/ci.yml/badge.svg)](https://github.com/ThreatFlux/virustotal-rs/actions/workflows/ci.yml)
[![Security](https://github.com/ThreatFlux/virustotal-rs/actions/workflows/security.yml/badge.svg)](https://github.com/ThreatFlux/virustotal-rs/actions/workflows/security.yml)
[![Crates.io](https://img.shields.io/crates/v/virustotal-rs.svg)](https://crates.io/crates/virustotal-rs)
[![Documentation](https://docs.rs/virustotal-rs/badge.svg)](https://docs.rs/virustotal-rs)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](#license)
[![Rust](https://img.shields.io/badge/rust-1.97.1%2B-orange.svg)](https://www.rust-lang.org)

**Async Rust SDK for the VirusTotal API v3, with optional CLI and MCP server support.**

[Quick start](#quick-start) · [API coverage](docs/api-coverage.md) · [Configuration](docs/configuration.md) · [Examples](#examples) · [Contributing](CONTRIBUTING.md)

</div>

> [!IMPORTANT]
> This is an independent, community-maintained project. It is not affiliated with, endorsed by, or maintained by VirusTotal or Google.

## Why virustotal-rs?

- Async API v3 client built on `reqwest`, `tokio`, and strongly typed resource models.
- Resource clients for files, URLs, domains, IP addresses, comments, votes, search, collections, graphs, hunting, feeds, and private APIs.
- No default features: the core SDK stays small unless you opt into the CLI or MCP server.
- Typed API, transport, parsing, authentication, quota, and local rate-limit errors.
- Maintained feature-matrix, MSRV, examples, rustdoc, security, and cross-platform CI checks.

See the [source-derived API coverage guide](docs/api-coverage.md) for the complete resource-client inventory and account-access notes.

## Installation

Add the latest published release and a Tokio runtime:

```bash
cargo add virustotal-rs
cargo add tokio --features macros,rt-multi-thread
```

Enable an optional component only when you need it:

```bash
cargo add virustotal-rs --features cli
cargo add virustotal-rs --features mcp
```

The `main` branch can be ahead of the newest crates.io release. To test unreleased code explicitly:

```bash
cargo add virustotal-rs --git https://github.com/ThreatFlux/virustotal-rs.git
```

The current development MSRV is Rust 1.97.1. <!-- docs-msrv:1.97.1 -->

## Quick start

After adding the dependencies above, save the following complete, read-only
program as `src/main.rs` in your application:

<!-- quickstart:start -->
```rust
use virustotal_rs::{ApiTier, ClientBuilder};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let api_key = std::env::var("VIRUSTOTAL_API_KEY")?;
    let hash = std::env::var("VT_FILE_HASH")
        .unwrap_or_else(|_| "44d88612fea8a8f36de82e1278abb02f".to_owned());

    let client = ClientBuilder::new()
        .api_key(api_key)
        .tier(ApiTier::Public)
        .build()?;

    let report = client.files().get(&hash).await?;
    println!(
        "{}: {:?}",
        report.object.id, report.object.attributes.type_description
    );

    Ok(())
}
```
<!-- quickstart:end -->

Set a [VirusTotal API key](https://docs.virustotal.com/reference/authentication),
then run the consumer application:

```bash
export VIRUSTOTAL_API_KEY="your-api-key"
cargo run
```

From a clone of this repository, run the synchronized example with:

```bash
cargo run --example quickstart
```

`VT_FILE_HASH` is optional; the application and example otherwise look up the
standard EICAR test-file hash.

Use `ApiTier::Premium` only when your account has the corresponding privileges. The tier controls this SDK's local throttling; it does not grant VirusTotal access or override account quotas.

## Feature flags

The contract check keeps this table aligned with `Cargo.toml`.

<!-- feature-flags:start -->
| Feature | Default | Purpose |
| --- | --- | --- |
| `default` | Yes | Empty feature set; core async SDK only |
| `cli` | No | Enables the `vt-cli` download workflow and its dependencies |
| `mcp` | No | Enables the MCP server runtime and transports |
| `mcp-jwt` | No | Adds JWT authentication and enables `mcp` |
| `mcp-oauth` | No | Adds OAuth 2.1 authentication and enables `mcp` |
<!-- feature-flags:end -->

## Operational expectations

- The client sends the API key in the `x-apikey` header over HTTPS, matching [VirusTotal authentication guidance](https://docs.virustotal.com/reference/authentication). Never log, commit, or expose the key.
- `ApiTier::Public` enforces an in-process limit of 4 requests per minute and 500 requests per client day. `ApiTier::Premium` disables that local limiter, but VirusTotal's [account quotas](https://docs.virustotal.com/docs/consumption-quotas-handled) remain authoritative.
- Core client requests use a 30-second timeout and are not retried automatically. Use `RetryUtils::retry_request` deliberately for idempotent operations.
- A custom base URL receives your API key. Configure only a trusted HTTPS endpoint whose base path ends in `/`, such as the default `https://www.virustotal.com/api/v3/`.
- Uploads, URL submissions, comments, votes, and lifecycle APIs mutate remote state. Review the example before running it and confirm that your use complies with the [VirusTotal API terms and access rules](https://docs.virustotal.com/reference/getting-started).
- Private scanning and advanced intelligence APIs require separate account privileges. Consult VirusTotal's [private scanning documentation](https://docs.virustotal.com/docs/private-scanning) before sending sensitive content.

Read [configuration and runtime behavior](docs/configuration.md) before deploying the SDK.

## Examples

All examples are compile-checked by CI. Many integration examples call live endpoints or mutate remote state, so inspect them before execution.

| Start here | What it demonstrates | Access |
| --- | --- | --- |
| [`quickstart.rs`](examples/quickstart.rs) | Build a public-tier client and fetch one file report | API key |
| [`test_file.rs`](examples/test_file.rs) | Detailed file metadata and analysis output | API key |
| [`test_urls.rs`](examples/test_urls.rs) | URL scan, report, relationships, comments, and votes | API key; mutates state |
| [`test_collections.rs`](examples/test_collections.rs) | Collection lifecycle and indicators | Privilege-dependent; mutates state |
| [`test_livehunt.rs`](examples/test_livehunt.rs) | Livehunt rulesets, notifications, and permissions | Premium/privileged |
| [`test_private_files.rs`](examples/test_private_files.rs) | Private-file operations | Private Scanning license |
| [`mcp_stdio_server.rs`](examples/mcp_stdio_server.rs) | Embedded MCP server over stdio | `mcp` feature |

The [`examples/`](examples/) directory contains additional focused coverage for graphs, feeds, behaviors, Retrohunt, Sigma, YARA, users, groups, private URLs, and iterator utilities.

## Optional binaries

### CLI

The `vt-cli` binary is currently focused on download workflows and uses `VTI_API_KEY` (or `--api-key`):

```bash
cargo run --locked --features cli --bin vt-cli -- --help
cargo run --locked --features cli --bin vt-cli -- download --help
```

### MCP server

The MCP server uses `VIRUSTOTAL_API_KEY`. HTTP is the default transport; set `SERVER_MODE=stdio` for stdio:

```bash
VIRUSTOTAL_API_KEY="your-api-key" \
  cargo run --locked --features mcp --bin mcp_server

SERVER_MODE=stdio VIRUSTOTAL_API_KEY="your-api-key" \
  cargo run --locked --features mcp --bin mcp_server
```

Use `mcp-jwt` or `mcp-oauth` instead of `mcp` to compile the corresponding authentication layer.

## Documentation

- [API reference](https://docs.rs/virustotal-rs)
- [API coverage](docs/api-coverage.md)
- [Configuration and runtime behavior](docs/configuration.md)
- [Architecture](docs/ARCHITECTURE.md)
- [Changelog](CHANGELOG.md)
- [VirusTotal API v3 reference](https://docs.virustotal.com/reference/overview)

## Development

```bash
make docs-contract
make fmt-check
make clippy
make test
make ci-local
```

The repository pins Rust 1.97.1 in `rust-toolchain.toml`. See [CONTRIBUTING.md](CONTRIBUTING.md) for the validation matrix and pull-request expectations.

## Support and security

- Use [GitHub issues](https://github.com/ThreatFlux/virustotal-rs/issues) for reproducible SDK bugs and feature requests.
- Use [GitHub Discussions](https://github.com/ThreatFlux/virustotal-rs/discussions) for usage questions when available.
- Report vulnerabilities privately according to [SECURITY.md](SECURITY.md).
- For API access, quota, policy, or service issues, contact VirusTotal through its official support channels.

## License

Licensed under either the [MIT License](LICENSE) or the
[Apache License 2.0](LICENSE-APACHE), at your option.

---

<div align="center">

Built and maintained by [ThreatFlux](https://github.com/ThreatFlux)

</div>
