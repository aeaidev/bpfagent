#!/bin/bash
# Format checking for BPF Agent
# Checks code formatting without modifying files

set -e

echo "📝 Checking Code Format"
echo "======================="

if cargo fmt --all -- --check; then
    echo "✅ All code is properly formatted"
    exit 0
else
    echo "❌ Code formatting issues found"
    echo ""
    echo "Run the following to auto-fix:"
    echo "  cargo fmt --all"
    exit 1
fi
