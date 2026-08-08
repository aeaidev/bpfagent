#!/bin/bash
# Test BPF Agent
# Runs unit tests, integration tests, and checks

set -e

echo "🧪 Testing BPF Agent"
echo "==================="

# Run clippy checks
echo "🔍 Running Clippy..."
cargo clippy --all -- -D warnings

# Run format check
echo "📝 Checking code formatting..."
cargo fmt --all -- --check

# Run tests
echo "🧪 Running tests..."
cargo test --all --lib --verbose

# Run integration tests (if they exist)
if [ -d "bpfagent/tests" ]; then
    echo "🧪 Running integration tests..."
    cargo test --test '*' --verbose
fi

# Run documentation tests
echo "📚 Running doc tests..."
cargo test --doc

echo ""
echo "✅ All tests passed!"
