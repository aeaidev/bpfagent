#!/bin/bash
# Release BPF Agent
# Builds release binaries for multiple targets

set -e

VERSION="${1:-}"
if [ -z "$VERSION" ]; then
    echo "Usage: $0 <version> [targets...]"
    echo "Example: $0 1.2.3 x86_64 aarch64"
    exit 1
fi

TARGETS="${@:2}"
if [ -z "$TARGETS" ]; then
    TARGETS="x86_64-unknown-linux-gnu aarch64-unknown-linux-musl"
fi

BUILD_DIR="dist/bpfagent-${VERSION}"
mkdir -p "$BUILD_DIR"

echo "🚀 Building Release ${VERSION}"
echo "=============================="

for target in $TARGETS; do
    echo ""
    echo "📦 Building for $target..."
    
    # Check if target is installed
    if ! rustup target list | grep -q "^$target (installed)"; then
        echo "Installing target $target..."
        rustup target add "$target"
    fi
    
    # Build
    cargo build --package bpfagent --release --target "$target" || {
        echo "⚠️  Build failed for $target, skipping"
        continue
    }
    
    # Copy binary
    binary_path="target/$target/release/bpfagent"
    if [ -f "$binary_path" ]; then
        cp "$binary_path" "$BUILD_DIR/bpfagent-${target}"
        echo "✅ Built: $BUILD_DIR/bpfagent-${target}"
    fi
done

# Create checksums
echo ""
echo "📝 Creating checksums..."
cd "$BUILD_DIR"
sha256sum bpfagent-* > SHA256SUMS
cd - > /dev/null

echo ""
echo "✅ Release build complete!"
echo "📁 Binaries: $BUILD_DIR/"
ls -lh "$BUILD_DIR"
