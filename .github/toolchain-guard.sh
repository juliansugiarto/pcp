#!/usr/bin/env bash
# Records the runner image and the Rust toolchain into out/toolchain.txt, and
# fails if rustc is not the version pinned in rust-toolchain.toml (design note
# 31, Fable review 32). The guard is for anything that overrides the file:
# a RUSTUP_TOOLCHAIN variable, a toolchain action, a `+toolchain` default.
# Usage: bash .github/toolchain-guard.sh [DIR]   (DIR: where cargo will run;
# its nearest rust-toolchain.toml is the pin; default: the repository root)
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
dir="${1:-$root}"
mkdir -p "$root/out"
f="$dir"
while [ ! -f "$f/rust-toolchain.toml" ] && [ "$f" != / ]; do f="$(dirname "$f")"; done
[ -f "$f/rust-toolchain.toml" ] || { echo "no rust-toolchain.toml above $dir"; exit 1; }
want=$(grep -E '^channel *=' "$f/rust-toolchain.toml" | grep -oE '[0-9]+\.[0-9]+\.[0-9]+')
[ -n "$want" ] || { echo "rust-toolchain.toml in $f pins no version"; exit 1; }
got=$(cd "$dir" && rustc -V)
{
  echo "pin: $want ($f/rust-toolchain.toml)"
  echo "rustc: $got"
  echo "cargo: $(cd "$dir" && cargo -V)"
  echo "RUSTUP_TOOLCHAIN: ${RUSTUP_TOOLCHAIN:-unset}"
  echo "ImageOS: ${ImageOS:-unknown}  ImageVersion: ${ImageVersion:-unknown}"
  if [ -f /etc/os-release ]; then . /etc/os-release; echo "os: ${PRETTY_NAME:-unknown}"; fi
  if command -v sw_vers >/dev/null; then echo "macos: $(sw_vers -productVersion) build $(sw_vers -buildVersion)"; fi
  echo "kernel: $(uname -srm)"
} | tee -a "$root/out/toolchain.txt"
case "$got" in
  "rustc $want "*) echo "toolchain pin: ok" | tee -a "$root/out/toolchain.txt" ;;
  *) echo "toolchain pin: FAILED, rustc is not the pinned $want" | tee -a "$root/out/toolchain.txt"; exit 1 ;;
esac
