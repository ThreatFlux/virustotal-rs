# Releasing

## Automated Release Path

Routine releases are driven by [Conventional Commits](https://www.conventionalcommits.org/).

When both `CI` and `Security` succeed on `main`, `auto-release.yml`:

1. Looks at commits since the last tag
2. Chooses a patch, minor, or major bump
3. Updates `Cargo.toml` and `Cargo.lock`
4. Commits the version bump
5. Creates and pushes a new `v*` tag

That tag triggers `release.yml`, which:

1. Validates the manifest version
2. Builds `vt-cli` and `mcp_server` on Linux, macOS, and Windows
3. Publishes the crate when a registry token is configured
4. Creates or updates the GitHub Release with packaged artifacts

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
