#!/bin/bash
# BPF Agent Development Setup
# Installs required dependencies and toolchains

set -e

echo "🔧 BPF Agent Development Setup"
echo "==============================="

# Check if running on Linux
if [[ ! "$OSTYPE" =~ linux ]]; then
    echo "❌ This script only runs on Linux"
    exit 1
fi

# Check for sudo/root
if [[ $EUID -ne 0 ]]; then
    echo "⚠️  Some steps require root. Re-run with sudo if needed."
fi

# Install system dependencies
echo "📦 Installing system dependencies..."
if command -v apt-get &> /dev/null; then
    sudo apt-get update
    sudo apt-get install -y \
        build-essential \
        llvm \
        clang \
        libelf-dev \
        libz-dev \
        pkg-config \
        git
elif command -v yum &> /dev/null; then
    sudo yum groupinstall -y "Development Tools"
    sudo yum install -y \
        llvm-devel \
        clang \
        elfutils-libelf-devel \
        zlib-devel \
        pkg-config \
        git
else
    echo "⚠️  Package manager not found. Please install development tools manually."
fi

# Install Rust
if ! command -v rustc &> /dev/null; then
    echo "🦀 Installing Rust..."
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
    source $HOME/.cargo/env
else
    echo "✅ Rust already installed"
fi

# Install Rust toolchains
echo "🔨 Installing Rust toolchains..."
rustup toolchain install stable
rustup toolchain install nightly --component rust-src
rustup default stable

# Install bpf-linker
if ! command -v bpf-linker &> /dev/null; then
    echo "📌 Installing bpf-linker..."
    cargo install bpf-linker
else
    echo "✅ bpf-linker already installed"
fi

# Install additional tools
echo "🛠️  Installing development tools..."
cargo install cargo-watch
cargo install cargo-expand

echo ""
echo "✅ Development setup complete!"
echo ""
echo "Next steps:"
echo "  1. cd /home/igor/projects/bpfagent"
echo "  2. cargo build --release"
echo "  3. cargo test"
echo ""
