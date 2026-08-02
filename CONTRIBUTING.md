# Contributing to virustotal-rs

`virustotal-rs` is a Rust SDK for the VirusTotal API v3 with optional CLI and MCP server support. Contributions should improve the public library surface, documentation, workflow reliability, or the optional operational tooling without regressing API compatibility.

## Getting Started

1. Fork the repository.
2. Clone your fork.
3. Create a topic branch: `git checkout -b feat/your-change`.
4. Make your changes.
5. Run the local validation targets before opening a pull request.

## Development Setup

```bash
make install-tools
make docs-contract
make ci-local
```

For integration-style examples, export either `VIRUSTOTAL_API_KEY` or `VT_API_KEY`.

## Commit Guidelines

We use [Conventional Commits](https://www.conventionalcommits.org/):

- `feat`: new functionality
- `fix`: bug fix
- `docs`: documentation-only change
- `refactor`: internal refactor
- `test`: tests added or updated
- `chore`: maintenance work

The automated release workflow only cuts a release for `feat`, `fix`, or breaking changes, so commit prefixes matter.

## Pull Request Checklist

- [ ] `cargo fmt --all` is clean
- [ ] `cargo clippy --all-features --all-targets -- -D warnings` passes
- [ ] `cargo test --all-features` passes
- [ ] `make docs-contract` passes
- [ ] Docs were updated when behavior or public APIs changed
- [ ] `CHANGELOG.md` was updated for user-facing changes

## Documentation

- Keep [README.md](README.md) accurate for end users.
- Keep [docs/api-coverage.md](docs/api-coverage.md) aligned with `Client` resource accessors.
- Keep [docs/configuration.md](docs/configuration.md) aligned with implemented builder and runtime behavior.
- Keep [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) accurate when module boundaries change.
- Keep [docs/RELEASING.md](docs/RELEASING.md) accurate when release automation changes.
- Keep the marked README quickstart byte-for-byte aligned with [examples/quickstart.rs](examples/quickstart.rs). Run `python3 scripts/check_docs.py` for fast feedback.

## Security Issues

Do not open public issues for security vulnerabilities. Follow [SECURITY.md](SECURITY.md).
