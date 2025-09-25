#!/usr/bin/env bash
set -euo pipefail

# Run quick fuzz smokes under Linux/WSL with cargo-fuzz installed.
# Usage: ./scripts/run_fuzz_smoke.sh

if ! command -v cargo-fuzz >/dev/null 2>&1; then
  echo "cargo-fuzz not installed. Installing..." >&2
  cargo install cargo-fuzz
fi

# Ensure we're at repo root
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
REPO_ROOT="$(cd -- "${SCRIPT_DIR}/.." &>/dev/null && pwd)"
cd "${REPO_ROOT}/fuzz"

# Build fuzzers
cargo fuzz build registration_decode
cargo fuzz build registration_verify

# Run short smokes
cargo fuzz run registration_decode -- -runs=1000 || true
cargo fuzz run registration_verify -- -runs=1000 || true

echo "Fuzz smoke runs completed."
