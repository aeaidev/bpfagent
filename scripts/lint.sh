#!/bin/bash
# Lint BPF Agent
# Runs Clippy and other static analysis checks

set -e

echo "🔍 Linting Code"
echo "==============="

# Check for unused imports and dead code
echo "📌 Running Clippy..."
cargo clippy --all --tests -- \
    -D warnings \
    -D clippy::all \
    -W clippy::pedantic \
    2>&1 | tee clippy_output.log || {
    echo ""
    echo "❌ Clippy found issues (see clippy_output.log)"
    exit 1
}

# Security audit
echo ""
echo "🔐 Running security audit..."
if command -v cargo-audit &> /dev/null; then
    cargo audit || echo "⚠️  Security advisories found"
else
    echo "⚠️  cargo-audit not installed (cargo install cargo-audit)"
fi

# Check for outdated dependencies
echo ""
echo "📦 Checking dependencies..."
if command -v cargo-outdated &> /dev/null; then
    cargo outdated || true
else
    echo "⚠️  cargo-outdated not installed (cargo install cargo-outdated)"
fi

echo ""
echo "✅ Linting complete!"
