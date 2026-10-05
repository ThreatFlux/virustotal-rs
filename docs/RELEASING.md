# Releasing

## Automated Release Path

Routine releases are driven by [Conventional Commits](https://www.conventionalcommits.org/).

When either the `CI` or `Security` workflow finishes on `main`, or when triggered
manually, `auto-release.yml` calls the pinned ThreatFlux reusable release workflow:

1. Looks at commits since the last tag
2. Chooses a patch, minor, or major bump
3. Verifies the latest `CI` and `Security` runs for the target `main` commit succeeded
4. Updates `Cargo.toml` and `Cargo.lock`
5. Commits the version bump
6. Creates and pushes a new `v*` tag
7. Dispatches `release.yml` with the new version

The explicit dispatch also runs with `GITHUB_TOKEN`, whose tag pushes do not
trigger another workflow. `release.yml` also accepts maintainer-created tags and:

1. Validates the manifest version
2. Builds `vt-cli` and `mcp_server` on Linux, macOS, and Windows
3. Publishes the crate when a registry token is configured
4. Creates or updates the GitHub Release with packaged artifacts

There is one versioning owner: the reusable auto-release workflow. Implementation
PRs leave the current package version in place and use Conventional Commits to
select the next release. Do not add a second automatic versioning path or publish
a crate while validating an implementation. `cargo publish --dry-run` verifies
packaging without uploading it.

## Compatibility for the October 2026 refresh

Development and hosted stable checks use Rust 1.99.0; the consumer MSRV remains
1.97.1 and has a separate CI job. `jsonwebtoken` 11, `dirs` 7, and `tower-http` 0.7
are internal to the existing optional integrations: their changed nominal types
are not exposed through this SDK's public parameters or fields.

The Elasticsearch crate only publishes alpha releases. The `cli` feature now uses
the existing stable `reqwest` dependency for the report examples' REST operations.
`cli::elasticsearch::ElasticsearchClient` supports Basic authentication, index
management, search, count, and exact newline-delimited bulk bodies. URLs with
embedded credentials are rejected; use the separate `--es-username` and
`--es-password` example options. Redirects are disabled and non-successful HTTP
statuses are errors. Bulk callers still inspect the JSON `errors` field, because
individual operations can fail within an HTTP 200 response. The compiled CLI
continues to expose its existing Download command. The former implicit
`elasticsearch` Cargo feature remains as an empty compatibility alias.

## Manual Release

Use this when you need a hotfix, a prerelease, or a release from a specific ref.

### Pre-flight

1. Ensure the branch is green:
   ```bash
   make ci-local
   ```
2. Update [CHANGELOG.md](../CHANGELOG.md).
3. Bump the version in `Cargo.toml`.
4. Commit the release prep:
   ```bash
   git add Cargo.toml Cargo.lock CHANGELOG.md
   git commit -m "chore: release vX.Y.Z"
   ```

### Trigger the workflow

```bash
gh workflow run release.yml \
  -f version=X.Y.Z \
  -f source_ref=main \
  -f prerelease=false
```

## Required Secrets

| Secret | Purpose |
|--------|---------|
| `GITHUB_TOKEN` | Git tags, release creation, artifact publishing |
| `CARGO_REGISTRY_TOKEN` or `CRATES_IO_TOKEN` | crates.io publishing |

## Rollback

1. Delete the GitHub Release if it was created.
2. Delete the tag:
   ```bash
   git push --delete origin vX.Y.Z
   ```
3. Yank the crate from crates.io if it was published:
   ```bash
   cargo yank --version X.Y.Z
   ```
4. Fix the issue and publish the next patch release.
