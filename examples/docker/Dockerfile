# Dockerfile for bpfagent
#
# This Dockerfile builds a containerized bpfagent application.
# Note: eBPF programs require a host with kernel BPF support (Linux 5.8+)
# and typically need to run with privileged access.
#
# Build: docker build -t bpfagent:latest .
# Run: docker run --privileged --cap-add SYS_ADMIN --cap-add SYS_RESOURCE \
#      --net host -v /sys:/sys bpfagent:latest

FROM rust:latest AS builder

WORKDIR /build

# Install build dependencies
RUN apt-get update && apt-get install -y \
    clang \
    llvm \
    libelf-dev \
    libssl-dev \
    pkg-config \
    && rm -rf /var/lib/apt/lists/*

# Install Rust eBPF toolchain
RUN rustup target add x86_64-unknown-linux-musl && \
    rustup target add bpfel-unknown-none && \
    cargo install cargo-bpf

# Copy project files
COPY . .

# Build the application
RUN cd bpfagent && cargo build --release

# Runtime image
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl3 \
    && rm -rf /var/lib/apt/lists/*

# Copy binary from builder
COPY --from=builder /build/bpfagent/target/release/bpfagent /usr/local/bin/

# Create configuration directory
RUN mkdir -p /etc/bpfagent

# Copy example configuration
COPY config/bpfagent.conf.example /etc/bpfagent/bpfagent.conf

# Expose metrics port
EXPOSE 9101

# Run as unprivileged user (for non-eBPF operations)
# For actual eBPF tracing, run with --privileged
USER nobody

ENTRYPOINT ["bpfagent"]
CMD ["--config-file", "/etc/bpfagent/bpfagent.conf", "--metrics-port", "9101"]
