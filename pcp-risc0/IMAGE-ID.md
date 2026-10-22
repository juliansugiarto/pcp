# The PCP/0 guest image id

```
cc6e7b82fb2da7bba9aa051331c0662ad123ac9821820c0daa34f4e942d0e328
```

This is the RISC Zero image id of the PCP/0 guest (`methods/guest/`), built reproducibly in Docker with risc0-zkvm 3.0.6 and the RISC Zero builder image `r0.1.97.0` (pinned by tag in `methods/build.rs`). A receipt valid for this id says: the PCP/0 statement core ran to completion (exit code 0) on some input and wrote the journal shown. The buyer compares that journal with the statement it expects, so the receipt means "this ciphertext decrypts, under the key whose hash is the invoice's payment hash, to a result that passes the job's check" (SPEC 7.2).

An offer names its guest in `backend_id`: `risc0-zkvm-3-succinct/<image id>`. A buyer pinned to this id refuses any other (`backend_not_accepted`) before anything is proven or paid.

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

Any change to the code compiled into the guest changes the id: `pcp/src/job/`, `encoding`, `crypto`, `statement`, `lib.rs`, the guest itself, its `Cargo.lock`, or the builder. Even a change that only moves lines does, because panic locations (file, line, column) are embedded in the guest binary. A new id means a new release: update `PINNED_IMAGE_ID`, this file and every document that quotes the id, in the same commit.

## A buyer without the RISC Zero toolchain

`verify/` (crate `pcp-risc0-verify`, binary `pcp-buy-risc0`) verifies receipts with risc0-zkvm built without its `client`, `prove` and `bonsai` features: no guest build, no rzup, no Docker, no prover. It accepts only succinct receipts (one STARK) of at most 512 KiB: composite receipts nest without limit and could overflow the buyer's stack while decoding, and Groth16 receipts rest on a trusted setup (SPEC T9). It takes `pcp-buy`'s options. Today this is what the `real-sale` workflow runs, against an LND node on regtest:

```bash
cd pcp && cargo build --features lnd --bin pcp-setup && cd ..
cd pcp-risc0 && cargo build --release -p pcp-risc0-verify --features lnd,http && cd ..
export PCP_LND_REST_URL=https://127.0.0.1:8081           # your LND node's REST address
export PCP_LND_TLS_CERT=/path/to/tls.cert
export PCP_LND_MACAROON=/path/to/admin.macaroon         # regtest; least rights beyond it
# pcp-setup makes a principal, an agent key and a mandate (and a seller pair for tests)
PCP_BUYER_LND_REST_URL=$PCP_LND_REST_URL PCP_BUYER_LND_TLS_CERT=$PCP_LND_TLS_CERT \
PCP_BUYER_LND_MACAROON=$PCP_LND_MACAROON \
  ./pcp/target/debug/pcp-setup --root run --buyer-node from-env:PCP_BUYER_LND_ --seller-node unused
./pcp-risc0/target/release/pcp-buy-risc0 --state run/buyer --seller-url https://<seller> --rail lnd
```

A setup for a buyer alone, and the signet seller's address, come with the signet runbook. See `../pcp/RUN.md` for the regtest network.

With `--image-id HEX` the buyer pins another id instead. Take that id only from a guest you built or a release you trust, never from the seller's offer: the offer names the guest the seller wants you to accept.
