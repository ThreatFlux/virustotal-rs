# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- Reworked end-user documentation around verified installation, API coverage, configuration, account boundaries, and operational safety.
- Added an executable quickstart and a CI-enforced documentation contract for MSRV, features, local links, and mirrored code.
- Clarified that compatibility settings on `EnhancedClientBuilder` for retries, custom limiters, headers, and user agents are not currently applied to the built client.

## [0.4.7] - 2026-08-01

### Changed

- Modernized GitHub Actions to current SHA-pinned stable releases and removed deprecated release patterns.
- Rolled up April 2026 Dependabot security and maintenance updates for `openssl`, `rustls-webpki`, `rand`, and the release/docs/security GitHub Actions workflows.
- Updated direct dependencies and aligned local tooling with the maintained Rust 1.97.1 baseline.
- Refreshed the Cargo lockfile to the latest compatible dependency releases.
- Updated the CI, release, documentation, and security workflows to current action releases.
- Reworked repository documentation to match ThreatFlux project standards and reflect the actual SDK, CLI, and MCP surfaces.
