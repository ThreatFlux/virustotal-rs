.PHONY: all clean build test fmt clippy doc audit security coverage bench check install-tools help \
         fmt-check test-no-features test-mcp-features build-examples test-doc doc-check doc-links \
         deny outdated security-geiger security-supply-chain semver-check feature-test feature-test-full \
         msrv msrv-install security-enhanced ci-local validate analyze examples release-prep dev

# Default target
all: install-tools fmt clippy build test test-no-features test-mcp-features build-examples test-doc doc-check doc-links audit security
	@echo "✅ All checks passed!"

# CI simulation - matches GitHub Actions CI workflow
ci: fmt-check clippy build test test-no-features test-mcp-features build-examples test-doc doc-check
	@echo "✅ CI checks passed!"

# Install required tools
install-tools:
	@echo "📦 Installing required tools..."
	@command -v cargo-audit >/dev/null 2>&1 || cargo install cargo-audit
	@command -v cargo-outdated >/dev/null 2>&1 || cargo install cargo-outdated
	@command -v cargo-deny >/dev/null 2>&1 || cargo install cargo-deny
	@command -v cargo-llvm-cov >/dev/null 2>&1 || cargo install cargo-llvm-cov
	@command -v cargo-hack >/dev/null 2>&1 || cargo install cargo-hack
	@command -v cargo-deadlinks >/dev/null 2>&1 || cargo install cargo-deadlinks
	@command -v cargo-geiger >/dev/null 2>&1 || cargo install cargo-geiger --locked
	@command -v cargo-supply-chain >/dev/null 2>&1 || cargo install cargo-supply-chain --locked
	@command -v cargo-semver-checks >/dev/null 2>&1 || cargo install cargo-semver-checks --locked
	@echo "✅ Tools installed"

# Format code
fmt:
	@echo "🎨 Formatting code..."
	@cargo fmt
	@echo "✅ Code formatted"

# Check formatting without modifying
fmt-check:
	@echo "🔍 Checking code format..."
	@cargo fmt -- --check
	@echo "✅ Format check passed"

# Run clippy linter
clippy:
	@echo "📎 Running clippy..."
	@cargo clippy --all-features --all-targets -- -D warnings
	@echo "✅ Clippy passed"

# Build the project
build:
	@echo "🔨 Building project..."
	@cargo build --all-features --release
	@echo "✅ Build successful"

# Run tests
test:
	@echo "🧪 Running tests..."
	@cargo test --all-features
	@echo "✅ Tests passed"

# Test without features
test-no-features:
	@echo "🧪 Running tests without features..."
	@cargo test --no-default-features
	@echo "✅ Tests without features passed"

# Test with individual MCP features
test-mcp-features:
	@echo "🧪 Testing MCP features..."
	@cargo test --features mcp
	@cargo test --features mcp-jwt
	@cargo test --features mcp-oauth
	@echo "✅ MCP feature tests passed"

# Build examples
build-examples:
	@echo "🔨 Building examples..."
	@cargo build --examples --all-features
	@echo "✅ Examples built successfully"

# Test documentation examples
test-doc:
	@echo "📚 Testing documentation examples..."
	@cargo test --doc --all-features
	@echo "✅ Doc tests passed"

# Generate documentation
doc:
	@echo "📖 Generating documentation..."
	@cargo doc --all-features --no-deps
	@echo "✅ Documentation generated"

# Check documentation with warnings as errors
doc-check:
	@echo "📖 Checking documentation..."
	@echo '<style>.sidebar { width: 250px; } .content { margin-left: 250px; }</style>' > docs-header.html
	@RUSTDOCFLAGS="-D warnings --html-in-header docs-header.html" cargo doc --all-features --no-deps --document-private-items
	@echo "✅ Documentation check passed"

# Run security audit
audit:
	@echo "🔒 Running security audit..."
	@cargo audit
	@echo "✅ Security audit passed"

# Check with cargo-deny
deny:
	@echo "🚫 Running cargo-deny checks..."
	@cargo deny check
	@echo "✅ Cargo deny checks passed"

# Check outdated dependencies
outdated:
	@echo "📊 Checking for outdated dependencies..."
	@cargo outdated || true
	@echo "✅ Outdated check complete"

# Security analysis with cargo-geiger (unsafe code detection)
security-geiger:
	@echo "🔍 Analyzing unsafe code usage..."
	@cargo geiger --output-format GitHubMarkdown > unsafe-report.md || echo "⚠️ Geiger analysis completed with warnings"
	@echo "✅ Unsafe code analysis complete (see unsafe-report.md)"

# Supply chain security analysis
security-supply-chain:
	@echo "🔗 Analyzing supply chain security..."
	@cargo supply-chain crates > supply-chain-report.txt 2>&1 || echo "⚠️ Supply chain analysis completed with warnings"
	@echo "✅ Supply chain analysis complete (see supply-chain-report.txt)"

# Check documentation links
doc-links:
	@echo "🔗 Checking documentation links..."
	@cargo doc --all-features --no-deps --document-private-items
	@cargo deadlinks --dir target/doc || echo "⚠️ Some documentation links may be broken"
	@echo "✅ Documentation link check complete"

# Semantic versioning checks
semver-check:
	@echo "📋 Checking semantic versioning..."
	@cargo semver-checks check-release || echo "⚠️ Semver check completed with warnings"
	@echo "✅ Semantic versioning check complete"

# Combined security checks
security: audit deny outdated security-geiger security-supply-chain
	@echo "✅ All security checks complete"

# Generate test coverage
coverage:
	@echo "📊 Generating test coverage..."
	@cargo llvm-cov --all-features --html
	@echo "✅ Coverage report generated at target/llvm-cov/html/index.html"

# Run benchmarks
bench:
	@echo "⚡ Running benchmarks..."
	@cargo bench --all-features || true
	@echo "✅ Benchmarks complete"

# Check MSRV (Minimum Supported Rust Version)
msrv:
	@echo "🦀 Checking MSRV (1.82.0)..."
	@if rustup toolchain list | grep -q "1.82.0"; then \
		cargo +1.82.0 check --all-features; \
	else \
		echo "⚠️  MSRV toolchain 1.82.0 not installed. Installing..."; \
		rustup toolchain install 1.82.0 --component rustfmt,clippy; \
		cargo +1.82.0 check --all-features; \
	fi
	@echo "✅ MSRV check complete"

# Install MSRV toolchain if not present
msrv-install:
	@echo "🦀 Installing MSRV toolchain (1.82.0)..."
	@rustup toolchain install 1.82.0 --component rustfmt,clippy
	@echo "✅ MSRV toolchain installed"

# Test feature combinations
feature-test:
	@echo "🔀 Testing feature combinations..."
	@cargo hack check --feature-powerset --depth 2 --all-targets
	@echo "✅ Feature combination tests passed"

# Test feature combinations with tests
feature-test-full:
	@echo "🔀 Testing feature combinations (with tests)..."
	@cargo hack test --feature-powerset --depth 2
	@echo "✅ Full feature combination tests passed"

# Quick check (faster than full build)
check:
	@echo "⚡ Quick check..."
	@cargo check --all-features
	@echo "✅ Check passed"

# Clean build artifacts
clean:
	@echo "🧹 Cleaning build artifacts..."
	@cargo clean
	@echo "✅ Clean complete"

# Run examples (requires VT_API_KEY)
examples:
	@echo "🎯 Running examples..."
	@if [ -z "$$VT_API_KEY" ]; then \
		echo "⚠️  VT_API_KEY not set, skipping examples"; \
	else \
		cargo run --example test_file && \
		echo "✅ Examples ran successfully"; \
	fi


# Release preparation
release-prep: fmt test doc audit security
	@echo "📦 Checking Cargo.toml version..."
	@grep "^version" Cargo.toml
	@echo "✅ Ready for release!"

# Development workflow - format, build, and test
dev: fmt build test
	@echo "✅ Development checks passed!"

# Enhanced security analysis (matches CI/CD security workflow)
security-enhanced: security security-supply-chain security-geiger semver-check
	@echo "✅ Enhanced security analysis complete!"

# CI-equivalent validation (matches GitHub Actions CI workflow)
ci-local: fmt-check clippy build test test-no-features test-mcp-features build-examples test-doc doc-check doc-links feature-test
	@echo "✅ Local CI validation complete!"

# Full validation (everything - matches all CI/CD workflows)
validate: all coverage feature-test-full security-enhanced
	@echo "🎉 Full validation complete!"

# Complete analysis (all tools, all checks)
analyze: validate security-enhanced doc-links semver-check
	@echo "🎯 Complete analysis finished!"

# Help target
help:
	@echo "VirusTotal Rust SDK - Makefile targets"
	@echo ""
	@echo "🎯 Main targets:"
	@echo "  make all          - Run all standard checks (format, lint, build, test, doc, security)"
	@echo "  make dev          - Quick development check (format, build, test)"
	@echo "  make ci-local     - Simulate full CI checks locally"
	@echo "  make validate     - Full validation including coverage and feature tests"
	@echo "  make analyze      - Complete analysis (all tools, all checks)"
	@echo ""
	@echo "🔨 Individual targets:"
	@echo "  make fmt          - Format code"
	@echo "  make fmt-check    - Check formatting without modifying"
	@echo "  make clippy       - Run clippy linter"
	@echo "  make build        - Build the project"
	@echo "  make test         - Run tests"
	@echo "  make test-doc     - Test documentation examples"
	@echo "  make doc          - Generate documentation"
	@echo "  make doc-check    - Check documentation with strict warnings"
	@echo "  make doc-links    - Check documentation links"
	@echo ""
	@echo "🔒 Security targets:"
	@echo "  make security     - Run all security checks"
	@echo "  make audit        - Run security audit"
	@echo "  make deny         - Run cargo-deny checks"
	@echo "  make security-geiger       - Analyze unsafe code usage"
	@echo "  make security-supply-chain - Supply chain analysis"
	@echo "  make semver-check - Check semantic versioning"
	@echo ""
	@echo "🧪 Testing targets:"
	@echo "  make test-no-features      - Test without features"
	@echo "  make test-mcp-features     - Test MCP features"
	@echo "  make feature-test          - Test feature combinations (check only)"
	@echo "  make feature-test-full     - Test feature combinations (with tests)"
	@echo "  make coverage              - Generate test coverage report"
	@echo ""
	@echo "🛠️  Utility targets:"
	@echo "  make msrv         - Check minimum supported Rust version"
	@echo "  make msrv-install - Install MSRV toolchain"
	@echo "  make outdated     - Check for outdated dependencies"
	@echo "  make bench        - Run benchmarks"
	@echo "  make clean        - Clean build artifacts"
	@echo "  make examples     - Run example programs (requires VT_API_KEY)"
	@echo ""
	@echo "📦 Tool installation:"
	@echo "  make install-tools - Install required cargo tools"
	@echo ""
	@echo "🌍 Environment variables:"
	@echo "  VT_API_KEY        - VirusTotal API key for running examples"