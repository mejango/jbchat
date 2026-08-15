#!/bin/sh
set -eu

cd "$(dirname "$0")/.."

cargo fmt --check
cargo check --workspace --all-targets --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
sh scripts/audit-features.sh

