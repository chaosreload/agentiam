# ── Stage 1: Builder ─────────────────────────────────────────────
FROM rust:1.89-slim-bookworm AS builder

WORKDIR /build

# Dependency layer cache: copy manifests first, fetch deps
COPY Cargo.toml Cargo.lock ./
RUN mkdir src && echo "fn main() {}" > src/main.rs && echo "" > src/lib.rs \
    && cargo fetch --locked \
    && rm -rf src

# Build the real source
COPY src ./src
RUN cargo build --release --locked \
    && strip target/release/agentiam-server \
    && strip target/release/agentiam-bootstrap

# ── Stage 2: Runtime ─────────────────────────────────────────────
FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates wget \
    && rm -rf /var/lib/apt/lists/*

RUN groupadd -g 10001 agentiam \
    && useradd -u 10001 -g agentiam -s /bin/false -M agentiam

COPY --from=builder /build/target/release/agentiam-server /usr/local/bin/agentiam-server
COPY --from=builder /build/target/release/agentiam-bootstrap /usr/local/bin/agentiam-bootstrap

# Copy Cedar schema + policies so the image is self-contained
COPY schemas/ /var/lib/agentiam/schemas/
COPY policies/ /var/lib/agentiam/policies/

WORKDIR /var/lib/agentiam
RUN chown -R agentiam:agentiam /var/lib/agentiam

USER agentiam

ENV AGENTIAM_PORT=8080 \
    AGENTIAM_DB_PATH="sqlite:/var/lib/agentiam/agentiam.db?mode=rwc" \
    AGENTIAM_SCHEMA_FILE="/var/lib/agentiam/schemas/agentiam.cedarschema" \
    AGENTIAM_POLICY_DIR="/var/lib/agentiam/policies"

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD wget -qO- http://localhost:8080/health || exit 1

ENTRYPOINT ["/usr/local/bin/agentiam-server"]
