#!/usr/bin/env bash
# Verify this bundle offline. Needs: a Rust toolchain and the pcp-zk crate source
# (set PCP_ZK_CRATE, default: the directory above this bundle). No network after the
# crates are fetched, no node, no money. Prints OK and exits 0 if the proof verifies.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
CRATE="${PCP_ZK_CRATE:-$(cd "$HERE/.." && pwd)}"
cargo build --release --quiet --manifest-path "$CRATE/Cargo.toml" --bin pcp-zk
"$CRATE/target/release/pcp-zk" verify --dir "$HERE" --puzzle "$HERE/givens.txt" \
  --payment-hash 64671770057fae33fcf10fb65523964c20e13659e75326e0a13f088d60b60dbc \
  --binding 1405bbaefc37ee45baa8aa69dbbdac2ce62afcf081825c590cc7e0f76cbe6610 \
  --vk-fingerprint d8fb5e70076e3d0c8617de14c44bc5c37594032acd910b11ff42663fa3a8d2e4
