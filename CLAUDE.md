# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Development Commands

### Quick Start
- `make help` - Show all available make targets
- `make dev` - Quick development workflow (format, build, test)
- `make all` - Complete validation (format, lint, build, test, doc, security)
- `make ci` - Simulate CI checks

### Makefile Targets
The project includes a comprehensive Makefile with the following key targets:
- `make install-tools` - Install required cargo tools (audit, deny, llvm-cov, etc.)
- `make fmt` - Format code
- `make clippy` - Run linting with all features
- `make build` - Build with all features in release mode
- `make test` - Run all tests with all features
- `make doc` - Generate documentation
- `make security` - Run security audit, deny checks, and outdated dependency check
- `make coverage` - Generate test coverage report
- `make examples` - Run examples (requires VT_API_KEY environment variable)
- `make validate` - Full validation including feature combination tests

### Direct Cargo Commands
- `cargo build --all-features` - Build with all optional features
- `cargo test --all-features` - Run tests with all features
- `cargo run --example test_all_features` - Demonstrate all SDK features
- `cargo run --example <example_name>` - Run specific example
- `cargo clippy --all-features -- -D warnings` - Strict linting
- `cargo deny check` - Check dependencies against security advisories

### Feature-specific Commands
- `cargo build --features mcp` - Build with MCP (Model Context Protocol) support
- `cargo build --features mcp-jwt` - Build with MCP JWT authentication
- `cargo build --features mcp-oauth` - Build with MCP OAuth 2.1 authentication

## Architecture Overview

This is a Rust SDK for the VirusTotal API v3 that provides comprehensive threat intelligence capabilities.

### Core Components

**Client Architecture**: The `Client` struct in `src/client.rs` is the main entry point, built using `ClientBuilder`. It handles HTTP requests, rate limiting, and authentication. All API modules receive a reference to this client.

**Rate Limiting**: Built-in rate limiting in `src/rate_limit.rs` using the `governor` crate. Public API tier: 4 req/min, 500/day. Premium tier: configurable limits.

**Authentication**: API key-based authentication (`src/auth.rs`) with support for Public and Premium tier configurations.

**Error Handling**: Comprehensive error types in `src/error.rs` that map VirusTotal API errors to strongly-typed Rust errors with retry logic.

### API Module Structure

Each VirusTotal API endpoint has its own module:
- `files.rs` - File analysis and scanning
- `urls.rs` - URL analysis and scanning  
- `domains.rs` - Domain information and analysis
- `ip_addresses.rs` - IP address analysis
- `analysis.rs` - Analysis results and reports
- `comments.rs` - Community comments and votes
- `collections.rs` - IOC collections management
- `livehunt.rs` - Real-time hunting rules
- `retrohunt.rs` - Historical hunting jobs
- `private_files.rs` - Private scanning API (Premium)
- `private_urls.rs` - Private URL scanning (Premium)

### Optional Features

**MCP Integration** (`src/mcp/`): Model Context Protocol server implementation that can run as HTTP or stdio server, providing threat intelligence tools to AI models. Includes JWT and OAuth 2.1 authentication options.

**Testing**: Comprehensive test suite in `src/tests/` with mock data and integration tests. Examples in `examples/` directory demonstrate real API usage.

### Key Patterns

- All API clients follow the same pattern: `client.{module_name}()` returns a module-specific client
- Async/await throughout using Tokio runtime
- Strong typing with serde for JSON serialization/deserialization
- Builder pattern for configuration (ClientBuilder, request builders)
- Error types implement `is_retryable()` for retry logic
- Rate limiting is transparent to the caller

### Dependencies

Uses `reqwest` for HTTP, `tokio` for async runtime, `serde` for JSON, `governor` for rate limiting, and optional dependencies for MCP features including `axum`, `jsonwebtoken`, and `oauth2`.