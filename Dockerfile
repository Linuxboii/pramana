# syntax=docker/dockerfile:1
# Pramāṇa — one image: demo issuer + two verifiers + the web app with the WASM wallet.
#   docker build -t pramana .
#   docker run -p 8080:8080 -v pramana-data:/data pramana

# ---------------------------------------------------------------- Rust: server + WASM
FROM rust:1-bookworm AS rust
ARG WASM_BINDGEN_VERSION=0.2.130
RUN rustup target add wasm32-unknown-unknown \
 && cargo install wasm-bindgen-cli --version ${WASM_BINDGEN_VERSION} --locked
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY crates crates
COPY test-vectors test-vectors
RUN cargo build --release --locked -p pramana-demo -p pramana-issuer -p pramana-sakshi
RUN cargo build --release --locked -p pramana-wasm --target wasm32-unknown-unknown \
 && wasm-bindgen --target web --out-dir /wasm --out-name pramana \
      target/wasm32-unknown-unknown/release/pramana_wasm.wasm

# ---------------------------------------------------------------- Web app
FROM node:22-bookworm-slim AS web
WORKDIR /web
COPY web/package.json web/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY web/ ./
COPY --from=rust /wasm ./src/wasm
RUN npm run build

# ---------------------------------------------------------------- Runtime
FROM debian:bookworm-slim
RUN useradd --system --uid 10001 --home /data pramana \
 && mkdir -p /data /app \
 && chown pramana /data
COPY --from=rust /src/target/release/pramana-demo /src/target/release/pramana-issuer /src/target/release/pramana-sakshi /usr/local/bin/
COPY --from=web /web/dist /app/web
ENV PRAMANA_ADDR=0.0.0.0:8080 \
    PRAMANA_WEB_DIR=/app/web \
    PRAMANA_ISSUER_KEY_FILE=/data/issuer.key \
    RUST_LOG=info,tower_http=warn
USER pramana
WORKDIR /data
EXPOSE 8080
VOLUME ["/data"]
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 CMD ["pramana-demo", "--healthcheck"]
CMD ["pramana-demo"]
