# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.5.1] - 2026-10-06

This is the first crates.io release since 0.4.7: v0.5.0 was published on GitHub only, so 0.5.1 also carries every 0.5.0 change listed below.

### Maintenance

- Publish to crates.io through trusted publishing (OIDC) instead of a stored registry token, and add dry-run modes to the release workflows.
- Build release binaries for Linux (x86_64 glibc and musl, arm64), macOS (arm64, x86_64), and Windows with SHA-256 checksums and a CycloneDX SBOM.
- Use this changelog's section for the version as the GitHub Release notes.
- Stop the `test_users_groups` example from printing the first characters of the API key.

## [0.5.0] - 2026-10-05

### Added

- Current public analysis reports with nullable engine verdicts, preserved extension fields, item relationships, and bounded completion polling.
- Extensible heterogeneous search pages and iterators, with encoded intelligence-search cursors and explicit page limits.
- Single-object URL network-location and last-serving-IP relationship helpers.
- Configurable positive page/item bounds on core and enhanced collection iterators.

### Fixed

- Decode `in-progress` analyses, empty queued statistics, and search results according to their object discriminator.
- Preserve query filters and encode opaque cursors during pagination; continue through empty pages, reject zero page sizes, and report cursor cycles or exhausted bounds.
- Apply enhanced custom headers and user agents across every HTTP request format and preserve them when changing timeout.
- Redact API-key debug output and mark credential headers sensitive; reject conflicting credential and routing headers.

### Maintenance

- Update development Rust to the latest stable 1.99.0 while preserving consumer MSRV 1.97.1.
- Refresh stable crates, locked transitive dependencies, SHA-pinned GitHub Actions, and pinned local/hosted development tools.
- Replace the alpha-only Elasticsearch Rust client in optional CLI examples with stable reqwest REST operations, including authentication, encoded paths, NDJSON, and HTTP-status checks.

### Changed

- Reworked end-user documentation around verified installation, API coverage, configuration, account boundaries, and operational safety.
- Added an executable quickstart and a CI-enforced documentation contract for MSRV, features, local links, and mirrored code.
- Clarified that compatibility retry and custom-limiter settings on `EnhancedClientBuilder` remain standalone utilities.

## [0.4.7] - 2026-08-01

### Changed

- Modernized GitHub Actions to current SHA-pinned stable releases and removed deprecated release patterns.
- Rolled up April 2026 Dependabot security and maintenance updates for `openssl`, `rustls-webpki`, `rand`, and the release/docs/security GitHub Actions workflows.
- Updated direct dependencies and aligned local tooling with the maintained Rust 1.97.1 baseline.
- Refreshed the Cargo lockfile to the latest compatible dependency releases.
- Updated the CI, release, documentation, and security workflows to current action releases.
- Reworked repository documentation to match ThreatFlux project standards and reflect the actual SDK, CLI, and MCP surfaces.
