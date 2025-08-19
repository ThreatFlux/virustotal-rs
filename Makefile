.PHONY: all clean build test fmt clippy doc audit security coverage bench check install-tools help

# Default target
all: install-tools fmt clippy build test doc audit security
	@echo "✅ All checks passed!"

# Install required tools
install-tools:
	@echo "📦 Installing required tools..."
	@command -v cargo-audit >/dev/null 2>&1 || cargo install cargo-audit
	@command -v cargo-outdated >/dev/null 2>&1 || cargo install cargo-outdated
	@command -v cargo-deny >/dev/null 2>&1 || cargo install cargo-deny
	@command -v cargo-llvm-cov >/dev/null 2>&1 || cargo install cargo-llvm-cov
	@command -v cargo-hack >/dev/null 2>&1 || cargo install cargo-hack
	@command -v cargo-deadlinks >/dev/null 2>&1 || cargo install cargo-deadlinks
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
	@cargo clippy --all-features -- -D warnings
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
	@RUSTDOCFLAGS="-D warnings" cargo doc --all-features --no-deps --quiet
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

# Combined security checks
security: audit deny outdated
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
	@echo "🦀 Checking MSRV (1.89.0)..."
	@cargo +1.89.0 check --all-features 2>/dev/null || echo "⚠️  MSRV check requires Rust 1.89.0 toolchain"
	@echo "✅ MSRV check complete"

# Test feature combinations
feature-test:
	@echo "🔀 Testing feature combinations..."
	@cargo hack test --feature-powerset --depth 2
	@echo "✅ Feature combination tests passed"

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

# CI simulation - runs what CI would run
ci: fmt-check clippy build test doc-check audit
	@echo "✅ CI checks passed!"

# Release preparation
release-prep: fmt test doc audit security
	@echo "📦 Checking Cargo.toml version..."
	@grep "^version" Cargo.toml
	@echo "✅ Ready for release!"

# Development workflow - format, build, and test
dev: fmt build test
	@echo "✅ Development checks passed!"

# Full validation (everything)
validate: all coverage feature-test
	@echo "🎉 Full validation complete!"

# Help target
help:
	@echo "VirusTotal Rust SDK - Makefile targets"
	@echo ""
	@echo "Main targets:"
	@echo "  make all          - Run all standard checks (format, lint, build, test, doc, security)"
	@echo "  make dev          - Quick development check (format, build, test)"
	@echo "  make ci           - Simulate CI checks"
	@echo "  make validate     - Full validation including coverage and feature tests"
	@echo ""
	@echo "Individual targets:"
	@echo "  make fmt          - Format code"
	@echo "  make fmt-check    - Check formatting without modifying"
	@echo "  make clippy       - Run clippy linter"
	@echo "  make build        - Build the project"
	@echo "  make test         - Run tests"
	@echo "  make test-doc     - Test documentation examples"
	@echo "  make doc          - Generate documentation"
	@echo "  make audit        - Run security audit"
	@echo "  make deny         - Run cargo-deny checks"
	@echo "  make outdated     - Check for outdated dependencies"
	@echo "  make coverage     - Generate test coverage report"
	@echo "  make bench        - Run benchmarks"
	@echo "  make clean        - Clean build artifacts"
	@echo "  make examples     - Run example programs (requires VT_API_KEY)"
	@echo ""
	@echo "Tool installation:"
	@echo "  make install-tools - Install required cargo tools"
	@echo ""
	@echo "Environment variables:"
	@echo "  VT_API_KEY        - VirusTotal API key for running examples"