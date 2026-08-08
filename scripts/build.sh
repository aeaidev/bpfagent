#!/bin/bash
# Build BPF Agent
# Builds the application in release mode for x86_64 and optionally ARM64

set -e

echo "🔨 Building BPF Agent"
echo "===================="

# Parse arguments
BUILD_MODE="${1:-release}"
TARGET="${2:-x86_64-unknown-linux-gnu}"

case "$BUILD_MODE" in
    debug)
        echo "📦 Building debug version for $TARGET..."
        cargo build --package bpfagent --target "$TARGET"
        echo "✅ Debug build complete: target/$TARGET/debug/bpfagent"
        ;;
    release)
        echo "📦 Building release version for $TARGET..."
        cargo build --package bpfagent --release --target "$TARGET"
        echo "✅ Release build complete: target/$TARGET/release/bpfagent"
        ;;
    all)
        echo "📦 Building all targets..."
        cargo build --package bpfagent --release
        echo "📦 Building for ARM64..."
        cargo build --package bpfagent --release --target aarch64-unknown-linux-gnu 2>/dev/null || \
            echo "⚠️  ARM64 build skipped (target not installed)"
        echo "✅ All builds complete"
        ;;
    *)
        echo "❌ Unknown build mode: $BUILD_MODE"
        echo "Usage: $0 {debug|release|all} [target]"
        exit 1
        ;;
esac
