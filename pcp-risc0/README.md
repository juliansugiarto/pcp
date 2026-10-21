# pcp-risc0: RISC Zero proof backend for PCP/0

> **This folder is not built by the `pcp` crate.** It is built and run by the `bench` CI workflow. On 21 October 2026 the guest was compiled and run for the first time, and all three jobs completed a full sale with real STARK proofs over the simulated rail. Measured costs are in [`COSTS.md`](COSTS.md). The guest is also built reproducibly in Docker (two separate CI builds gave the same image id), and with that guest a sale with a real proof settled over two real LND nodes on regtest (`real-sale` workflow, run 39627526488). For the steps to run it, see [`../pcp/RUN.md`](../pcp/RUN.md).

## Contents

| File | Contents |
|---|---|
| `methods/guest/src/main.rs` | The zkVM guest. Reads the input, calls `pcp::statement::evaluate`, then commits the public journal. |
| `methods/build.rs` | `risc0_build::embed_methods()`: builds the guest and generates `PCP_GUEST_ELF` and `PCP_GUEST_ID`. |
| `host/src/main.rs` | `Risc0Backend` (an implementation of `ProofBackend`), plus a sudoku sale demo and a cost table row. |

The layout follows the `cargo risczero new` template from risc0 version 3.0.6 (crates.io, 17 July 2026), read directly from the source of the `cargo-risczero` crate on crates.io.

## One source of truth

The relation being proven exists in only one place: `pcp/src/statement.rs`. The insecure dev backend in the `pcp` crate calls the same function in the open. The guest here calls it inside the zkVM. The guest depends on `pcp` with `default-features = false`, so only `encoding`, `crypto`, `job` and `statement` are pulled in (no_std + alloc, and the only dependencies are `sha2` and `chacha20poly1305`).

The journal is `canonical_bytes("statement", ...)`, so `SHA256(journal) = statement_hash`. Test vectors 14 to 17 in Appendix A of `SPEC.md` cover the guest input and this journal.

## Local proving only

The guest input contains the result `R` and the key `k`. A remote proving service would see the goods being sold before they are paid for. Therefore:

- `risc0-zkvm` is used with `default-features = false, features = ["prove"]`. The `bonsai` feature is not compiled in.
- The host uses `LocalProver` directly, not `default_prover()` (which follows the `RISC0_PROVER` and `BONSAI_API_KEY` variables).
- Dev mode is explicitly turned off (`with_dev_mode(false)`), and fake receipts are rejected both when creating and when checking proofs.
- Receipts are of the succinct kind (STARK, no trusted setup). Not Groth16.

## `backend_id` and image id

`backend_id` has the form `risc0-zkvm-3-succinct/<image id hex>`. `offer_id` commits to `backend_id`, so an offer names the exact guest binary. The buyer checks the receipt against the image id they built themselves. So that a seller and a buyer on different machines get the same image id, build the guest with Docker: `RISC0_USE_DOCKER=1 cargo build --release` (`methods/build.rs` maps the variable to risc0-build's Docker option, using the builder image `risczero/risc0-guest-builder:r0.1.88.0`). Two separate CI jobs built it this way on 21 October 2026 and got the same image id, `abe2df2125017d6785cab6fe7103c0ecf3fc130e34d9f7efa0359c8ffe06d941`. Without Docker, the image id depends on the local toolchain.

## What has and has not been checked

| Part | Status |
|---|---|
| `pcp::statement` (relation, encoding, vectors) | Tested in the `pcp` crate, including the `--no-default-features` (no_std) build. |
| Guest (`methods/guest`) | **Compiled and run in CI** (rzup, risc0 3.0.6), 21 October 2026. Reproducible image id from the Docker build: `abe2df21…d941` (two separate CI builds agree). The native build in the cost table had `6dc846c4…e8ea`. |
| `methods/build.rs` | **Run in CI** with the real guest. |
| Host (`host/src/main.rs`) | **Passes type checking** (`cargo check` and `cargo clippy`, no warnings, with and without `--features lnd`) against risc0-zkvm 3.0.6 from crates.io. **Linked and run in CI:** sudoku n=4, sudoku n=9 and the test-suite job each ended `SETTLED`. |
| Sale over LND with real proofs | **Run in CI** (`real-sale`, run 39627526488, 21 October 2026): with the Docker-built guest, a 9x9 sudoku sale and a test-suite sale settled over two LND v0.21.4 nodes on regtest. |
| Accelerated SHA-256 patch | Only a comment in `methods/guest/Cargo.toml`. Not yet tried. |

### Type checking

The command used in the writing environment (Linux x86_64, Rust 1.97):

```bash
DOCS_RS=1 RISC0_SKIP_BUILD_KERNELS=1 RISC0_SKIP_BUILD=1 RUSTUP_TOOLCHAIN=stable \
  cargo check -p pcp-risc0-host --features lnd
```

These four variables are only for type checking on a machine with no network access to RISC Zero: `RISC0_SKIP_BUILD` skips the guest (its ELF is empty), `RISC0_SKIP_BUILD_KERNELS` skips the prover's C++ kernels, and `DOCS_RS` stops `risc0-circuit-recursion` from downloading artifacts from S3 (that download is blocked), and `RUSTUP_TOOLCHAIN=stable` makes the check use the ordinary stable toolchain instead of the RISC Zero toolchain, which is not installed there. A binary produced this way **cannot** create proofs. On a Mac, do not set any of these variables.

The `Cargo.lock` in this folder is the result of version resolution during that type check.

## Running

See [`../pcp/RUN.md`](../pcp/RUN.md). In short, from this folder (a virtual workspace, so name the package with `-p`):

```bash
export RISC0_USE_DOCKER=1   # reproducible image id; needs Docker
cargo run --release -p pcp-risc0-host -- --job sudoku4 --execute-only   # count cycles, no proof
cargo run --release -p pcp-risc0-host -- --job sudoku9                  # real proof, simulated Lightning
cargo run --release -p pcp-risc0-host --features lnd -- --job sudoku9 --rail lnd   # real proof, two regtest LND nodes
```

The last line of a successful run's output starts with `cost-row,` and contains the numbers for the cost table.

MIT license, same as the repository.
