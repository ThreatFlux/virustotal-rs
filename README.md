<div align="center">

# virustotal-rs

[![CI](https://github.com/ThreatFlux/virustotal-rs/actions/workflows/ci.yml/badge.svg)](https://github.com/ThreatFlux/virustotal-rs/actions/workflows/ci.yml)
[![Security](https://github.com/ThreatFlux/virustotal-rs/actions/workflows/security.yml/badge.svg)](https://github.com/ThreatFlux/virustotal-rs/actions/workflows/security.yml)
[![Crates.io](https://img.shields.io/crates/v/virustotal-rs.svg)](https://crates.io/crates/virustotal-rs)
[![Documentation](https://docs.rs/virustotal-rs/badge.svg)](https://docs.rs/virustotal-rs)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-1.94%2B-orange.svg)](https://www.rust-lang.org)

**Async Rust SDK for the VirusTotal API v3, with optional CLI and MCP server support.**

[Quick Start](#quick-start) · [Feature Flags](#feature-flags) · [Development](#development) · [Docs](docs/) · [Contributing](CONTRIBUTING.md)

</div>

## Table of Contents

- [Features](#features)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Feature Flags](#feature-flags)
- [CLI and MCP Binaries](#cli-and-mcp-binaries)
- [Development](#development)
- [Release Automation](#release-automation)
- [Documentation](#documentation)
- [Contributing](#contributing)
- [Security](#security)
- [License](#license)

## Features

- Async VirusTotal API v3 client built on `reqwest` and `tokio`
- Coverage for files, URLs, domains, IP addresses, comments, votes, search, collections, graphs, Livehunt, Retrohunt, private files, and private URLs
- Optional Model Context Protocol server with plain MCP, JWT, and OAuth feature sets
- Optional CLI binary for download-oriented workflows
- Typed errors, rate limiting, validation helpers, iterators, and display utilities
- Cross-platform CI, security scanning, CodeQL, docs deployment, and automated release tagging

## Installation

```toml
[dependencies]
virustotal-rs = "0.4.4"
```

Optional feature flags:

```toml
[dependencies]
virustotal-rs = { version = "0.4.4", features = ["mcp"] }
virustotal-rs = { version = "0.4.4", features = ["mcp-jwt"] }
virustotal-rs = { version = "0.4.4", features = ["mcp-oauth"] }
virustotal-rs = { version = "0.4.4", features = ["cli"] }
```

## Quick Start

```rust
use virustotal_rs::{ApiTier, ClientBuilder};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = ClientBuilder::new()
        .api_key(std::env::var("VIRUSTOTAL_API_KEY")?)
        .tier(ApiTier::Public)
        .build()?;

    let file = client.files().get("44d88612fea8a8f36de82e1278abb02f").await?;
    println!("file type: {:?}", file.object.attributes.type_description);

    let analysis = client.urls().scan("https://example.com").await?;
    println!("analysis id: {}", analysis.data.id);

    Ok(())
}
```

The preferred environment variable is `VIRUSTOTAL_API_KEY`, but helper utilities also accept `VT_API_KEY` and `VTI_API_KEY`.

## Feature Flags

| Feature | Purpose |
|---------|---------|
| `cli` | Enables the `vt-cli` binary and related optional dependencies |
| `mcp` | Enables the MCP server runtime and transport layers |
| `mcp-jwt` | Adds JWT authentication support on top of `mcp` |
| `mcp-oauth` | Adds OAuth 2.1 authentication support on top of `mcp` |

## CLI and MCP Binaries

### `vt-cli`

The CLI is currently focused on download workflows.

```bash
cargo run --locked --features cli --bin vt-cli -- --help
cargo run --locked --features cli --bin vt-cli -- download --help
```

### `mcp_server`

Start the MCP server over HTTP:

```bash
VIRUSTOTAL_API_KEY=your_key \
cargo run --locked --features mcp --bin mcp_server
```

Start it over stdio:

```bash
SERVER_MODE=stdio VIRUSTOTAL_API_KEY=your_key \
cargo run --locked --features mcp --bin mcp_server
```

Optional auth layers:

```bash
cargo run --locked --features mcp-jwt --bin mcp_server
cargo run --locked --features mcp-oauth --bin mcp_server
```

## Development

### Baseline

- Rust `1.94.0`
- `rust-toolchain.toml` pins the maintained local toolchain
- `Makefile` targets mirror the main CI checks

### Common Commands

```bash
make fmt
make clippy
make test
make ci-local
make validate
```

### Examples and Integration-Style Runs

```bash
export VIRUSTOTAL_API_KEY=your_api_key
make examples
```

Examples that exercise premium endpoints may require a premium VirusTotal account.

## Release Automation

The repository follows [Conventional Commits](https://www.conventionalcommits.org/).

- `CI` and `Security` run on pushes and pull requests
- `auto-release.yml` bumps the version on `main` when there are releasable `feat`, `fix`, or breaking commits
- `release.yml` builds `vt-cli` and `mcp_server`, creates the GitHub Release, and publishes the crate when a registry token is configured

Maintainer runbook: [docs/RELEASING.md](docs/RELEASING.md)

## Documentation

- API docs: [docs.rs/virustotal-rs](https://docs.rs/virustotal-rs)
- Maintainer docs: [docs/README.md](docs/README.md)
- Architecture overview: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)
- Changelog: [CHANGELOG.md](CHANGELOG.md)

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for setup, validation, and pull request expectations.

## Security

See [SECURITY.md](SECURITY.md) for vulnerability reporting guidance.

## License

Licensed under [MIT OR Apache-2.0](LICENSE).

---

<div align="center">

Built and maintained by [ThreatFlux](https://github.com/ThreatFlux)

</div>
