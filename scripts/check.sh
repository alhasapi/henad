#!/usr/bin/env bash
# Local CI for Henad. No remote services: run this before every commit.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

if [[ ! -d node_modules ]]; then
  echo "==> installing npm dependencies"
  npm ci
fi

echo "==> frontend: typecheck + build"
npm run build

echo "==> rust: format"
cargo fmt --manifest-path src-tauri/Cargo.toml --all -- --check

echo "==> rust: clippy"
cargo clippy --manifest-path src-tauri/Cargo.toml --all-targets -- -D warnings

echo "==> rust: tests"
cargo test --manifest-path src-tauri/Cargo.toml --all-targets

echo
echo "PASS: henad checks are green"
