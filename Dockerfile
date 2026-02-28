# Multi-stage build for TrustChain node.
# Build: docker build -t trustchain-node .
# Run:   docker run -p 8200:8200/udp -p 8201:8201 -p 8202:8202 trustchain-node

# --- Builder stage ---
FROM rust:1.82-bookworm AS builder

WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY trustchain-core/ trustchain-core/
COPY trustchain-transport/ trustchain-transport/
COPY trustchain-node/ trustchain-node/
COPY proto/ proto/

# Install protobuf compiler for tonic-build.
RUN apt-get update && apt-get install -y protobuf-compiler && rm -rf /var/lib/apt/lists/*

RUN cargo build --release --bin trustchain-node

# --- Runtime stage ---
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*

COPY --from=builder /build/target/release/trustchain-node /usr/local/bin/trustchain-node

# Install default config (paths set to /data for persistent volume).
RUN mkdir -p /etc/trustchain /data
COPY deploy/docker-node.toml /etc/trustchain/node.toml

# QUIC (UDP), gRPC (TCP), HTTP REST (TCP).
EXPOSE 8200/udp
EXPOSE 8201/tcp
EXPOSE 8202/tcp

# Persistent volume for identity key and SQLite database.
# Mount: docker run -v trustchain-data:/data ...
VOLUME /data

ENV RUST_LOG=info

ENTRYPOINT ["trustchain-node"]
CMD ["run", "--config", "/etc/trustchain/node.toml"]
