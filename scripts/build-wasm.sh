#!/usr/bin/env sh
# Build the wallet WebAssembly into web/src/wasm.
# Uses wasm-pack if available, otherwise cargo + wasm-bindgen-cli (pinned to Cargo.lock).
set -eu
cd "$(dirname "$0")/.."
if command -v wasm-pack >/dev/null 2>&1; then
  wasm-pack build crates/pramana-wasm --release --target web --out-dir ../../web/src/wasm --out-name pramana
else
  VERSION=$(awk '/^name = "wasm-bindgen"$/{getline; gsub(/version = |"/,""); print; exit}' Cargo.lock)
  command -v wasm-bindgen >/dev/null 2>&1 || cargo install wasm-bindgen-cli --version "$VERSION" --locked
  rustup target add wasm32-unknown-unknown
  cargo build --release --locked -p pramana-wasm --target wasm32-unknown-unknown
  wasm-bindgen --target web --out-dir web/src/wasm --out-name pramana target/wasm32-unknown-unknown/release/pramana_wasm.wasm
fi
echo "wasm built into web/src/wasm"
