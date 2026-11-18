# The PCP/0 guest image id

```
b5b5a8f7a6290a0b46146ed3dd75030684187d2d47c7711cfd7f815bd8e4ab8c
```

This is the RISC Zero image id of the PCP/0 guest (`methods/guest/`), built reproducibly in Docker with risc0-zkvm 3.1.0 and the RISC Zero builder image `r0.1.97.0` (pinned by tag and digest in `methods/build.rs`). Two independent Docker builds in CI on 18 November 2026 gave this id (`risc0-image-id/20261118T032523Z-docker-2` and `real-sale/20261118T033549Z` on branch `ci-results-lnd`). The id before it, `cc6e7b82…e328`, was the same guest source built against risc0-zkvm 3.0.6; RISC Zero 3.1.0 corrected the recursion and rv32im circuits, and receipts of the two versions do not verify under each other's verifier, so that id is retired. A receipt valid for this id says: the PCP/0 statement core ran to completion (exit code 0) on some input and wrote the journal shown. The buyer compares that journal with the statement it expects, so the receipt means "this ciphertext decrypts, under the key whose hash is the invoice's payment hash, to a result that passes the job's check" (SPEC 7.2).

An offer names its guest in `backend_id`: `risc0-zkvm-3.1-succinct/<image id>`. The name carries the RISC Zero minor version because a circuit fix upstream can change the verifier without changing the guest; a buyer on another version then refuses the offer instead of a proof. A buyer pinned to this id refuses any other (`backend_not_accepted`) before anything is proven or paid.

## Where it is pinned

- `verify/src/lib.rs`, `PINNED_IMAGE_ID`: the default of the verify-only buyer `pcp-buy-risc0`.
- The `real-sale` workflow reads it from there and fails if the guest it builds in Docker has another id.

## Checking it yourself

You do not have to trust this file. Build the guest yourself and compare:

```bash
# needs Docker and the RISC Zero toolchain (rzup)
cd pcp-risc0
RISC0_USE_DOCKER=1 cargo build --release -p methods
RISC0_USE_DOCKER=1 cargo run --release -p pcp-risc0-host -- --job sudoku9 --execute-only
# prints: guest image id <id>
```

The `risc0-image-id` workflow does this twice on separate runners and publishes both ids (branch `ci-results-lnd`, folder `risc0-image-id/`). Not yet pinned: the builder image by digest (only by tag) and the toolchain version (`rust-toolchain.toml` says `stable`).

## When it changes

Any change to the code compiled into the guest changes the id: `pcp/src/job/`, `encoding`, `crypto`, `statement`, `lib.rs`, the guest itself, its `Cargo.lock`, the risc0-zkvm version it links, or the builder. Even a change that only moves lines does, because panic locations (file, line, column) are embedded in the guest binary. A new id means a new release: update `PINNED_IMAGE_ID`, this file and every document that quotes the id, in the same commit.

## A buyer without the RISC Zero toolchain

`verify/` (crate `pcp-risc0-verify`, binary `pcp-buy-risc0`) verifies receipts with risc0-zkvm built without its `client`, `prove` and `bonsai` features: no guest build, no rzup, no Docker, no prover. It accepts only succinct receipts (one STARK) of at most 512 KiB: composite receipts nest without limit and could overflow the buyer's stack while decoding, and Groth16 receipts rest on a trusted setup (SPEC T9). It takes `pcp-buy`'s options. Today this is what the `real-sale` workflow runs, against an LND node on regtest:

```bash
cd pcp-risc0 && cargo build --release -p pcp-risc0-verify --features lnd,http
./target/release/pcp-buy-risc0 --state <buyer dir> --seller-url https://<seller> --rail lnd
```

`../pcp/RUN-SIGNET.md` walks through the rest: an LND node on signet, a channel, a macaroon that can only pay, and `pcp-setup --buyer-only` for the buyer's principal, agent key and mandate.

With `--image-id HEX` the buyer pins another id instead. Take that id only from a guest you built or a release you trust, never from the seller's offer: the offer names the guest the seller wants you to accept.
