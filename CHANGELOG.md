# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- Modernized GitHub Actions to current SHA-pinned stable releases and removed deprecated release patterns.
- Rolled up April 2026 Dependabot security and maintenance updates for `openssl`, `rustls-webpki`, `rand`, and the release/docs/security GitHub Actions workflows.
- Updated direct dependencies and aligned local tooling with the maintained Rust 1.95.0 baseline.
- Reworked repository documentation to match ThreatFlux project standards and reflect the actual SDK, CLI, and MCP surfaces.
