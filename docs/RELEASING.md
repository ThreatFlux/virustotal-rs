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

The release commit and tag are pushed as the `threatflux-automation` GitHub App
(organization variable `TF_AUTOMATION_APP_ID` and secret
`TF_AUTOMATION_APP_PRIVATE_KEY`). Unlike a `GITHUB_TOKEN` push, an App push
starts workflows: the tag starts `release.yml` through its `push: tags` trigger,
and the release commit gets the usual `main` checks. The reusable workflow
dispatches `release.yml` itself only when no App is configured and it releases
with `GITHUB_TOKEN`; if the App token cannot be minted, the run fails instead.

`release.yml` also accepts maintainer-created tags and:

1. Validates that the tag matches the `Cargo.toml` version, and never moves an existing tag
2. Builds `vt-cli` and `mcp_server` for Linux (x86_64 glibc and musl, arm64),
   macOS (arm64, x86_64), and Windows (x86_64), each with a SHA-256 checksum
3. Generates a CycloneDX SBOM
4. Creates the GitHub Release (keeping notes that already exist) and uploads the
   archives, checksums, and SBOM
5. Publishes the crate to crates.io through
   [trusted publishing](https://crates.io/docs/trusted-publishing)

### crates.io trusted publishing

crates.io trusts the `ThreatFlux/virustotal-rs` repository, the `release.yml`
workflow, and the `crates-io` environment. The publish job requests an OIDC token
(`id-token: write`), and `rust-lang/crates-io-auth-action` exchanges it for a
short-lived publish token that is revoked when the job ends. No registry token is
stored in the repository or the organization. Renaming `release.yml` or the
publish job's environment breaks publishing until the trusted publisher on
crates.io is updated to match.

The publish job checks crates.io first and skips a version that is already
published, so a re-run after a partial failure is safe. A publish failure fails
the workflow run. Prereleases (a version with a suffix such as `1.2.3-rc.1`, or
the `prerelease` input) are not published.

### Dry runs

Both workflows can be rehearsed from the Actions tab or the CLI without
creating a commit, tag, release, or crates.io version:

```bash
# Report the version auto-release would cut next
gh workflow run auto-release.yml -f version_bump=auto -f dry_run=true

# Build every target, generate the SBOM, and run `cargo publish --dry-run`
gh workflow run release.yml -f version=X.Y.Z -f dry_run=true
```

A release dry run warns instead of failing when `version` differs from
`Cargo.toml`; it packages and verifies the `Cargo.toml` version.

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
  -f prerelease=false
```

`release.yml` builds the commit it runs on: the pushed tag, or the head of the
branch or tag chosen with `--ref` (default: `main`). To release from a release
branch, dispatch on that branch with `--ref`. A dispatch tags that commit unless
the tag already exists, in which case the tag must point at the same commit.

## Credentials

| Credential | Purpose |
|------------|---------|
| `GITHUB_TOKEN` | Release tag, GitHub Release, and release assets |
| crates.io trusted publishing (OIDC) | crates.io publishing; no stored secret |

## Rollback

Published tags, GitHub Releases, and crates.io versions are not deleted or
moved; a bad release is superseded.

1. Yank the crate version if it must not be used:
   ```bash
   cargo yank --version X.Y.Z
   ```
2. Mark the GitHub Release as a prerelease or edit its notes to point at the fix.
3. Fix the issue and publish the next patch release.
