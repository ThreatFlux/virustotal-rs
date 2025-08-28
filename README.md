# VirusTotal Rust SDK 🦀

[![Crates.io](https://img.shields.io/crates/v/virustotal-rs.svg)](https://crates.io/crates/virustotal-rs)
[![Documentation](https://docs.rs/virustotal-rs/badge.svg)](https://docs.rs/virustotal-rs)
[![Build Status](https://github.com/threatflux/virustotal-rs/workflows/CI/badge.svg)](https://github.com/threatflux/virustotal-rs/actions)
[![Security Audit](https://github.com/threatflux/virustotal-rs/workflows/Security/badge.svg)](https://github.com/threatflux/virustotal-rs/actions)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](LICENSE)

A comprehensive, async Rust SDK for the VirusTotal API v3 with advanced features including **Model Context Protocol (MCP) server** for AI/LLM integrations.

## ✨ Features

### 🔧 Core SDK Features
- **Full VirusTotal API v3 Coverage**: All endpoints including files, URLs, domains, IPs, analyses, and more
- **Public & Premium API Support**: Built-in tier handling with appropriate rate limiting
- **Robust Rate Limiting**: 
  - Public API: 4 req/min, 500/day
  - Premium API: Configurable based on your plan
- **Comprehensive Error Handling**: Strongly-typed errors matching VirusTotal API responses
- **Async/Await**: Built on Tokio for high-performance async operations
- **Type Safety**: Strong Rust types throughout the API surface
- **Retry Logic**: Automatic retry for transient failures
- **Request/Response Validation**: Built-in validation and sanitization

### 🤖 MCP (Model Context Protocol) Integration
- **AI/LLM Ready**: Native MCP server for Language Model integrations
- **Multiple Transport Protocols**: HTTP and stdio support
- **Authentication Options**:
  - JWT authentication (`mcp-jwt` feature)
  - OAuth 2.1 support (`mcp-oauth` feature)
- **Real-time Threat Intelligence**: Provides structured threat data to AI models
- **Docker Container**: Ready-to-deploy containerized MCP server

### 🚀 DevOps & Automation
- **Automated Releases**: Auto-increment versioning based on conventional commits
- **Multi-Platform Builds**: Linux, Windows, macOS support
- **Continuous Integration**: Comprehensive CI/CD with testing, security audits, and documentation
- **Container Registry**: Automatic Docker image publishing to GHCR

## 📦 Installation

### As a Rust Dependency

Add to your `Cargo.toml`:

```toml
[dependencies]
virustotal-rs = "0.1.0"

# For MCP server functionality
virustotal-rs = { version = "0.1.0", features = ["mcp"] }

# For MCP with JWT authentication
virustotal-rs = { version = "0.1.0", features = ["mcp-jwt"] }

# For MCP with OAuth 2.1 authentication
virustotal-rs = { version = "0.1.0", features = ["mcp-oauth"] }
```

### Docker Container (MCP Server)

```bash
# Pull the latest MCP server image (Docker Hub)
docker pull threatflux/virustotal-rs-mcp:latest

# Or from GitHub Container Registry
docker pull ghcr.io/threatflux/virustotal-rs-mcp:latest

# Run with your VirusTotal API key
docker run -e VIRUSTOTAL_API_KEY=your_api_key -p 8080:8080 \
  threatflux/virustotal-rs-mcp:latest
```

### Pre-built Binaries

Download from [GitHub Releases](https://github.com/threatflux/virustotal-rs/releases) for:
- Linux (x86_64)
- Windows (x86_64) 
- macOS (x86_64, ARM64)

## 🚀 Quick Start

### Basic SDK Usage

```rust
use virustotal_rs::{ClientBuilder, ApiTier};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create a client for Public API
    let client = ClientBuilder::new()
        .api_key("your-api-key")
        .tier(ApiTier::Public)
        .build()?;

    // Get file information
    let file_hash = "44d88612fea8a8f36de82e1278abb02f";
    let file_info = client.files().get_file_info(file_hash).await?;
    
    println!("File reputation: {:?}", file_info.data.attributes.reputation);
    
    // Get URL analysis
    let url_id = client.urls().scan_url("https://example.com").await?;
    let analysis = client.analyses().get_analysis(&url_id.data.id).await?;
    
    println!("URL analysis status: {:?}", analysis.data.attributes.status);

    Ok(())
}
```

### MCP Server Usage

#### HTTP Server Mode

```bash
# Start MCP HTTP server
VIRUSTOTAL_API_KEY=your_key cargo run --bin mcp_server --features mcp

# Or using Docker
docker run -e VIRUSTOTAL_API_KEY=your_key -p 8080:8080 \
  threatflux/virustotal-rs-mcp:latest

# Connect with MCP Inspector
npx @modelcontextprotocol/inspector http://localhost:8080
```

#### Stdio Server Mode (for direct MCP client integration)

```bash
SERVER_MODE=stdio VIRUSTOTAL_API_KEY=your_key cargo run --bin mcp_server --features mcp
```

#### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `VIRUSTOTAL_API_KEY` | **Required** VirusTotal API key | - |
| `SERVER_MODE` | Server mode: `http` or `stdio` | `http` |
| `HTTP_ADDR` | HTTP server address | `127.0.0.1:8080` |
| `VIRUSTOTAL_API_TIER` | API tier: `Public` or `Premium` | `Public` |
| `LOG_LEVEL` | Log level: `error`, `warn`, `info`, `debug`, `trace` | `info` |

## 📚 API Coverage

### Supported Endpoints

| Category | Endpoints | Status |
|----------|-----------|--------|
| **Files** | Upload, scan, get info, comments, votes, relationships | ✅ Complete |
| **URLs** | Scan, get info, comments, votes | ✅ Complete |
| **Domains** | Get info, comments, votes, relationships | ✅ Complete |
| **IP Addresses** | Get info, comments, votes, relationships | ✅ Complete |
| **Analyses** | Get analysis results, comments | ✅ Complete |
| **Comments** | CRUD operations, votes | ✅ Complete |
| **Collections** | IOC collections management | ✅ Complete |
| **Livehunt** | Real-time hunting rules (Premium) | ✅ Complete |
| **Retrohunt** | Historical hunting jobs (Premium) | ✅ Complete |
| **Intelligence** | VT Intelligence searches (Premium) | ✅ Complete |
| **Graphs** | Relationship graphs (Premium) | ✅ Complete |
| **Private Scanning** | Private file/URL analysis (Premium) | ✅ Complete |

### Error Handling

All VirusTotal API errors are mapped to strongly-typed Rust errors:

```rust
use virustotal_rs::Error;

match client.files().get_file_info("invalid-hash").await {
    Ok(file) => println!("File info: {:?}", file),
    Err(Error::NotFound) => println!("File not found in VirusTotal"),
    Err(Error::QuotaExceeded(msg)) => println!("API quota exceeded: {}", msg),
    Err(Error::RateLimit(msg)) => println!("Rate limited: {}", msg),
    Err(e) if e.is_retryable() => {
        println!("Retryable error (will auto-retry): {}", e);
    },
    Err(e) => println!("Permanent error: {}", e),
}
```

## 🏗️ Development

### Prerequisites

- **Rust** 1.82.0 or later
- **VirusTotal API Key** (get from [VirusTotal](https://www.virustotal.com/gui/join-us))

### Building from Source

```bash
# Clone the repository
git clone https://github.com/threatflux/virustotal-rs.git
cd virustotal-rs

# Build with all features
cargo build --all-features

# Run tests (requires VT_API_KEY environment variable)
export VT_API_KEY=your_api_key
cargo test --all-features

# Build the MCP server
cargo build --bin mcp_server --features mcp
```

### Development Commands

The project includes a comprehensive Makefile for development:

```bash
# Quick development workflow
make dev                # format + build + test

# Full validation (used in CI)
make all               # format + lint + build + test + doc + security

# Individual commands
make fmt               # Format code
make clippy            # Run linting
make test              # Run all tests
make doc               # Generate documentation
make security          # Security audits
make examples          # Run examples (requires VT_API_KEY)
```

### Running Examples

```bash
# Set your API key
export VIRUSTOTAL_API_KEY=your_api_key

# Run basic examples
cargo run --example test_file --all-features
cargo run --example test_url --all-features

# Run MCP server examples
cargo run --example mcp_http_server --features mcp
cargo run --example mcp_stdio_server --features mcp

# Run with JWT authentication
cargo run --example mcp_http_server_jwt --features mcp-jwt
```

## 🤝 MCP (Model Context Protocol) Integration

### What is MCP?

The Model Context Protocol (MCP) enables AI models to securely access external data sources. This SDK includes a full MCP server implementation that provides threat intelligence tools to Language Models.

### Available MCP Tools

| Tool | Description | Parameters |
|------|-------------|------------|
| `vt_file_scan` | Analyze files by hash/upload | `hash` or `file_path` |
| `vt_url_scan` | Analyze URLs | `url` |
| `vt_domain_info` | Get domain information | `domain` |
| `vt_ip_info` | Get IP address information | `ip_address` |
| `vt_search` | VirusTotal Intelligence search (Premium) | `query` |
| `vt_livehunt` | Manage hunting rules (Premium) | `rule_content` |

### Authentication Options

#### JWT Authentication (Recommended for Production)

```bash
# Generate JWT configuration
cargo run --example jwt_token_generator --features mcp-jwt

# Start server with JWT
JWT_SECRET=your_secret cargo run --bin mcp_server --features mcp-jwt
```

#### OAuth 2.1 Authentication

```bash
# Configure OAuth settings
export OAUTH_CLIENT_ID=your_client_id
export OAUTH_CLIENT_SECRET=your_secret

# Start server with OAuth
cargo run --bin mcp_server --features mcp-oauth
```

### Docker Deployment

```bash
# Build custom image
docker build -t my-vt-mcp-server .

# Run with custom configuration
docker run -d \
  --name vt-mcp-server \
  -e VIRUSTOTAL_API_KEY=your_key \
  -e VIRUSTOTAL_API_TIER=Premium \
  -e LOG_LEVEL=info \
  -p 8080:8080 \
  --restart unless-stopped \
  threatflux/virustotal-rs-mcp:latest

# Health check
curl http://localhost:8080/health
```

## 🔄 Automated Releases

This project uses an advanced automated release system:

### Release Process

1. **Automatic Triggering**: Every push to `main` after CI passes
2. **Smart Version Bumping**: 
   - 🔴 **Major**: Commits with `BREAKING CHANGE` or `!:`
   - 🟡 **Minor**: Commits with `feat:` or `feature:`
   - 🟢 **Patch**: All other changes (default)
3. **Multi-Platform Release**:
   - 📦 **Crates.io**: Rust package registry
   - 🐳 **Docker Hub**: Public container registry
   - 🐳 **GHCR**: GitHub container registry
   - 📋 **GitHub**: Release with binaries and changelog
   - 📚 **Docs**: Updated documentation site

### Manual Release

```bash
# Trigger manual release via GitHub Actions
gh workflow run auto-release.yml -f version_type=minor
```

### Version Bumping Examples

```bash
# Patch release (0.1.0 → 0.1.1)
git commit -m "fix: resolve rate limiting edge case"

# Minor release (0.1.0 → 0.2.0)  
git commit -m "feat: add new MCP authentication method"

# Major release (0.1.0 → 1.0.0)
git commit -m "feat!: redesign API structure

BREAKING CHANGE: Client initialization now requires explicit tier"
```

## 🔒 Security

### Security Features

- **Input Validation**: All inputs are validated and sanitized
- **Rate Limiting**: Prevents API abuse and quota exhaustion
- **Authentication**: Secure API key handling
- **TLS**: All connections use HTTPS/TLS
- **Container Security**: Non-root user, minimal attack surface

### Security Auditing

Regular security audits are performed automatically:

```bash
# Run security audit locally
make security

# Or individually
cargo audit              # Known vulnerabilities
cargo deny check         # License and source verification
```

### Reporting Security Issues

Please report security vulnerabilities via [GitHub Security Advisories](https://github.com/threatflux/virustotal-rs/security/advisories).

## 📊 Performance

### Benchmarks

| Operation | Public API | Premium API | Notes |
|-----------|------------|-------------|-------|
| File Hash Lookup | ~200ms | ~150ms | Cached results faster |
| URL Scan | ~500ms | ~400ms | Depends on URL complexity |
| Domain Info | ~300ms | ~250ms | WHOIS data included |
| Batch Operations | 4/min | No limit* | *Based on your plan |

### Optimization Tips

```rust
// Use connection pooling for multiple requests
let client = ClientBuilder::new()
    .api_key("key")
    .tier(ApiTier::Premium)
    .timeout(Duration::from_secs(30))
    .build()?;

// Batch requests when possible
let hashes = vec!["hash1", "hash2", "hash3"];
let futures: Vec<_> = hashes.iter()
    .map(|hash| client.files().get_file_info(hash))
    .collect();

let results = futures::future::join_all(futures).await;
```

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guidelines](CONTRIBUTING.md) for details.

### Development Setup

1. **Fork and Clone**
```bash
git clone https://github.com/your-username/virustotal-rs.git
cd virustotal-rs
```

2. **Set up Environment**
```bash
# Install Rust toolchain
rustup install stable
rustup default stable

# Install development tools
make install-tools

# Set API key for testing
export VIRUSTOTAL_API_KEY=your_test_key
```

3. **Run Tests**
```bash
make test
make examples  # Integration tests
```

4. **Submit PR**
- Write tests for new features
- Update documentation
- Follow conventional commit format
- Ensure CI passes

## 📋 Changelog

See [CHANGELOG.md](CHANGELOG.md) for detailed release notes.

## 📄 License

This project is dual-licensed under either:

- **MIT License** ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)
- **Apache License, Version 2.0** ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)

at your option.

## 🙏 Acknowledgments

- **VirusTotal** for providing the comprehensive threat intelligence API
- **Rust Community** for excellent async ecosystem and tooling
- **MCP Contributors** for the Model Context Protocol specification
- **Security Researchers** who help make threat intelligence accessible

## 📞 Support

- **Documentation**: [docs.rs/virustotal-rs](https://docs.rs/virustotal-rs)
- **Issues**: [GitHub Issues](https://github.com/threatflux/virustotal-rs/issues)
- **Discussions**: [GitHub Discussions](https://github.com/threatflux/virustotal-rs/discussions)
- **Security**: [Security Advisories](https://github.com/threatflux/virustotal-rs/security)

---

**Built with ❤️ by the ThreatFlux team**# CI Status Check
