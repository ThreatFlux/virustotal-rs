# Documentation

This directory holds user and maintainer documentation for `virustotal-rs`.

| File | Audience | Purpose |
|------|----------|---------|
| [`api-coverage.md`](api-coverage.md) | SDK users | Source-derived resource-client inventory and account-access boundaries |
| [`configuration.md`](configuration.md) | SDK users | Credentials, builders, timeouts, rate limits, retries, errors, and data handling |
| [`ARCHITECTURE.md`](ARCHITECTURE.md) | Contributors | High-level component map for the SDK, CLI, and MCP modules |
| [`RELEASING.md`](RELEASING.md) | Maintainers | Release automation and manual fallback checklist |
| [`../examples/quickstart.rs`](../examples/quickstart.rs) | New users | Executable, read-only client example mirrored in the root README |
| [`../CHANGELOG.md`](../CHANGELOG.md) | Users | Version history and unreleased changes |
| [`../CONTRIBUTING.md`](../CONTRIBUTING.md) | Contributors | Setup, validation, and PR expectations |
| [`../SECURITY.md`](../SECURITY.md) | Security researchers | Vulnerability reporting process |

Run `make docs-contract` after changing `Cargo.toml`, the README quickstart, feature documentation, or these guides. CI also compiles every example and treats rustdoc warnings as errors.
