# What this repository trusts, and how it is pinned

Everything that runs in CI or in a sale window comes from somewhere. This file lists each external piece, how it is pinned, and where the pin came from, so that a replaced release or a re-pointed tag fails loudly instead of running. Written 22 October 2026, after that week's incidents: LiteLLM's releases on PyPI, Docker Hub and GHCR carried an infostealer, and the OVHcloud CLI's GitHub release was replaced by a backdoored build for about 94 minutes on 19 October.

| Piece | Pinned how | Source of the pin | What a substitution would do |
|---|---|---|---|
| Rust crates (`pcp`, `pcp-risc0`, `pcp-zk`, `pcp/fuzz`, the guest) | `Cargo.lock` committed; every CI `cargo build/test/run/clippy` uses `--locked` | the lockfiles in this repository | the build fails instead of resolving another version |
| RustSec advisories | `cargo audit` on `pcp` (two-process) and `pcp-risc0` (verify-buyer); reviewed exceptions in `pcp-risc0/.cargo/audit.toml`, each with its reason; the verify-only buyer must contain none of those crates | advisory database at run time | a new advisory fails CI |
| GitHub Actions | commit SHA (`actions/checkout` v4.4.0 `11d5960a…`, `actions/cache` v4.3.0 `0057852b…`, `actions/upload-artifact` v4.6.2 `ea165f8d…`) | `git ls-remote` of each action's tags, 22 October 2026 | a moved tag is ignored |
| LND images | `lightninglabs/lnd:v0.21.4-beta@sha256:04d06edc…627d`, `v0.19.3-beta@sha256:b175f136…3aaa` | the `RepoDigests` that `.github/lnd-regtest/up.sh` logged in CI on 22 October 2026 (`ci-results-lnd/lnd/20261022T0806*`) | Docker refuses an image with another digest |
| bitcoind image (regtest) | `polarlightning/bitcoind:28.0@sha256:ff435d75…d010` | same | same |
| cloudflared (sale window) | version 2026.10.3, file SHA-256 `053b80b0…bab0`, also compared with the digest GitHub records for the release asset | two CI downloads on 22 October 2026 (`ci-results-lnd/window/*/cloudflared-version.txt`) | the window does not open |
| bore-cli, cargo-audit, cargo-fuzz | `cargo install --locked --version` (0.6.0, 0.22.2, 0.13.1) | crates.io | another version is not installed |
| RISC Zero toolchain | `rzup install` of rust 1.97.0, cpp 2024.1.5, r0vm 3.0.6, cargo-risczero 3.0.6, checked with `rzup show`; the installer script's hash is recorded | the versions CI used on 22 October 2026 | the build stops if r0vm is not 3.0.6 |
| The zkVM guest | its image id, `cc6e7b82…e328`, pinned in `pcp-risc0/verify/src/lib.rs` and checked against every Docker build | `pcp-risc0/IMAGE-ID.md` | a different guest is refused by every buyer and fails `real-sale` |

## Not pinned yet

- The `rzup` binary the installer fetches, and the toolchain archives rzup downloads. (The installer script itself is now checked against the hash every recorded run fetched (22 October 2026), `5699878a…41bf`.) The pinned image id catches a tampered guest build; it does not catch a tampered `r0vm` or `cargo-risczero` on the seller's machine.
- The guest builder image `risczero/risc0-guest-builder:r0.1.97.0` is pinned by tag, not digest (`pcp-risc0/methods/build.rs`); the digest behind the tag is now recorded by `risc0-image-id` (`guest-builder-digest.txt`). The image id is the compensating check.
- The host Rust toolchain (`rust-toolchain.toml` says `stable`) and the runner image (`ubuntu-latest`).
- nginx in the HTTPS test comes from Ubuntu's signed apt archive.
