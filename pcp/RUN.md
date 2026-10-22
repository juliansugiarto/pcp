# Running PCP

This file covers what has been shown to work: the tests, the halo2 CLI, the RISC Zero guest built reproducibly, and sales over two LND nodes on regtest. Each step below is what a CI workflow ran on 21 October 2026; the workflow is named so you can compare. Nothing here has run on signet or mainnet. Regtest sats only. Do not use with real money.

Commands start from the repository root unless a `cd` says otherwise.

## 0. What you need

- Rust stable, with access to crates.io.
- Python 3 with the `cryptography` package, for `pcp/tools/vectors.py` (`pip install cryptography`).
- For the RISC Zero guest: Docker, and the RISC Zero toolchain (section 3).
- For the LND sales: Docker, `jq` and `openssl` (section 4).

## 1. The `pcp` crate

```bash
cd pcp
cargo test                       # protocol, mandate and threat tests, simulated rail
cargo test --features lnd        # adds the LND rail; tests that need real nodes are ignored here
cargo run --bin demo             # four principals and four agents: two sales and a refusal
python3 tools/vectors.py         # recomputes SPEC Appendix A vectors 1 to 17 in Python
```

`tools/vectors.py` prints one `PASS` or `FAIL` line per vector and exits nonzero if any vector differs from the table in `SPEC.md`.

### Two processes

A buyer and a seller as separate processes, each with its own state directory, on the TEST-ONLY simulated network file (dev proof backend, no zero knowledge):

```bash
cd pcp && cargo build --bins
R=/tmp/pcp-run
./target/debug/pcp-setup --root $R --seller-node seller --buyer-node buyer --sim $R/sim.json
./target/debug/pcp-sell --state $R/seller --inbox $R/seller-inbox --peer-inbox $R/buyer-inbox \
  --rail sim:$R/sim.json:seller --allow-sim &
./target/debug/pcp-buy --state $R/buyer --inbox $R/buyer-inbox --peer-inbox $R/seller-inbox \
  --rail sim:$R/sim.json:buyer --allow-sim
./target/debug/pcp-audit --state $R/buyer --expect-state Delivered
./target/debug/pcp-audit --state $R/seller --expect-settled 1
```

Kill either process at any time and start it again with the same arguments: it resumes from its state directory. `PCP_CRASH_AT=<point>` aborts at a named point (the list is `CRASH_POINTS` in `src/node/mod.rs`). `tools/crash-matrix.sh OUT` runs every point; with `RAIL=lnd` and the `PCP_{BUYER,SELLER}_LND_*` variables of section 4 it runs against two LND nodes (build with `--features lnd`).

A state directory holds the agent key and, for the seller, `k`; for the buyer, the result. Treat it like a Lightning node's macaroons. `pcp-setup` keeps the principals' keys outside the agents' directories, as a principal would.

## 2. The halo2 CLI (`pcp-zk`)

```bash
cd pcp-zk
cargo test --release -- --test-threads=1   # a few minutes on 2 CPUs
scripts/cli-e2e.sh                         # needs cargo, python3, sha256sum (shasum on macOS)
cargo run --release -- vk-fingerprint
```

`cli-e2e.sh` runs one honest sale, 9 lies or tampers that must fail, and decryption with the right and the wrong key. It ends with `all cases as expected`. The fingerprint for the current circuit is `d8fb5e70076e3d0c8617de14c44bc5c37594032acd910b11ff42663fa3a8d2e4`; the `bench` workflow got the same value on Linux x86_64 and macOS arm64. Usage of `prove`, `verify` and `decrypt` is in `pcp-zk/README.md`.

## 3. The RISC Zero guest, built reproducibly

Install the toolchain as CI does:

```bash
curl -L https://risczero.com/install | bash
rzup install
rzup show        # CI recorded cargo-risczero 3.0.6 and r0vm 3.0.6
```

Build the guest in Docker, then the host. `pcp-risc0/` is a virtual workspace, so every cargo command there names the package with `-p`:

```bash
cd pcp-risc0
export RISC0_USE_DOCKER=1
cargo build --release -p methods
cargo build --release -p pcp-risc0-host --features lnd   # --features lnd only for section 4
./target/release/pcp-risc0 --job sudoku9 --execute-only
```

The first line of the last command must be:

```text
guest image id cc6e7b82fb2da7bba9aa051331c0662ad123ac9821820c0daa34f4e942d0e328
```

Two separate CI builds (`risc0-image-id` workflow) and the `real-sale` workflow got this value. With `RISC0_USE_DOCKER=1`, `methods/build.rs` builds the guest in the Docker image `risczero/risc0-guest-builder:r0.1.97.0` (set in `build.rs`; risc0-build 3.0.6's own default, `r0.1.88.0`, gives a different image id and a guest that pads to 2^18 cycles), with the repository root as the build context and `methods/guest/Cargo.lock` locked. Keep the variable exported for every cargo command in this folder: `build.rs` rebuilds the guest when it changes, and a build without it is native, with an image id that depends on your local toolchain.

A sale with a real proof over the simulated Lightning rail:

```bash
./target/release/pcp-risc0 --job sudoku9      # or sudoku4, testsuite
```

A successful run prints `SETTLED.`, the result, and a last line starting with `cost-row,`. With the reproducible guest, proving the 9x9 sudoku took 62 to 102 s and about 1.4 GiB of memory on 4-vCPU CI runners (`pcp-risc0/COSTS.md`). In CI the simulated-rail sales ran with a native build of the guest (`bench` workflow); the reproducible guest ran the LND sales of section 4 (`real-sale` workflow).

## 4. Two LND nodes on regtest

This is what `.github/workflows/lnd-regtest.yml` and `.github/workflows/real-sale.yml` do, with the same pinned images.

### Start the network

```bash
export LND_IMAGE=lightninglabs/lnd:v0.21.4-beta   # lnd-regtest also runs v0.19.3-beta
export BTC_IMAGE=polarlightning/bitcoind:28.0
bash .github/lnd-regtest/up.sh
```

`up.sh` starts, in a Docker network called `pcpnet`:

- `bitcoind` on regtest;
- `alice`, the buyer principal's LND node, REST on `127.0.0.1:8081`;
- `bob`, the seller principal's LND node, REST on `127.0.0.1:8082`.

It funds alice, opens a 1,000,000 sat channel from alice to bob, pays one 1-sat warm-up invoice so the channel is known to forward, and copies each node's `tls.cert` and `admin.macaroon` to `creds/alice/` and `creds/bob/` (set `CREDS` to use another folder). It prints `ready` at the end. The channel is direct: no hop between buyer and seller.

`admin.macaroon` is for regtest only. Beyond regtest, give each role a macaroon with the least rights it needs (seller: invoices; buyer: offchain), as `pcp/src/rail/lnd.rs` says.

### Point the binaries at the nodes

Both `lnd_sale` and `pcp-risc0 --rail lnd` read the same six variables. The macaroon and the certificate are file paths:

```bash
export PCP_BUYER_LND_REST_URL=https://127.0.0.1:8081
export PCP_BUYER_LND_TLS_CERT=$PWD/creds/alice/tls.cert
export PCP_BUYER_LND_MACAROON=$PWD/creds/alice/admin.macaroon
export PCP_SELLER_LND_REST_URL=https://127.0.0.1:8082
export PCP_SELLER_LND_TLS_CERT=$PWD/creds/bob/tls.cert
export PCP_SELLER_LND_MACAROON=$PWD/creds/bob/admin.macaroon
```

### The rail alone (`lnd-regtest` workflow)

```bash
(cd pcp && cargo build --features lnd --bin lnd_sale)
./pcp/target/debug/lnd_sale
(cd pcp && cargo test --features lnd --test lnd_regtest -- --ignored --test-threads=1)
```

`lnd_sale` sells a 9x9 sudoku for 1,000 sat with the INSECURE dev proof backend: it tests the Lightning rail, not the proof. It ends with `SETTLED over LND: 1000000 msat, preimage …`. In CI the 4 ignored tests (a hold invoice reads back with the requested terms, a reused payment hash is refused, the buyer's node refuses a presented invoice with other terms, a cancelled hold invoice refunds the buyer) passed on LND v0.19.3 and v0.21.4.

### A real proof over real Lightning (`real-sale` workflow)

After section 3 (built with `--features lnd`, `RISC0_USE_DOCKER=1`):

```bash
./pcp-risc0/target/release/pcp-risc0 --job sudoku9 --rail lnd
./pcp-risc0/target/release/pcp-risc0 --job testsuite --rail lnd
```

Each run prints `offer accepted: 1000000 msat, backend risc0-zkvm-3-succinct/cc6e7b82…, rail lightning-bolt11/0`, then `SETTLED.` and a `cost-row,` line. The seller's channel balance rises by 1,000 sat per sale:

```bash
docker exec bob lncli --network=regtest channelbalance
```

In CI (run 39627526488, LND v0.21.4) both sales settled, and SHA-256 of the revealed preimage equalled the invoice's payment hash.

### Timelocks on LND

BOLT11 timelocks are in blocks. The LND rail converts seconds to blocks at 600 s per block. LND refuses a hold invoice whose final CLTV delta is below its minimum (24 blocks in v0.21, 18 in v0.19), so the rail asks for at least `LND_MIN_FINAL_CLTV` = 24 blocks, and the seller's `min_htlc_secs` is at least 24 × 600 = 14,400 s. A buyer whose `htlc_secs` (the longest lock it accepts) is below the seller's `min_htlc_secs` refuses the invoice with `HtlcLockTooLong` (SPEC section 9, V8). So on this rail the buyer's `htlc_secs` must be at least 14,400 s.

`lnd_sale` and `pcp-risc0 --rail lnd` use the Lightning presets in `pcp::protocol`:

```rust
BuyerPolicy::lightning()          // rail lightning-bolt11/0; htlc_secs = (24 + 2 * 80 + 20) * 600 = 122,400 s (204 blocks)
SellerConfig::lightning(price)    // min_htlc_secs = 24 * 600 (24 blocks); settle_margin_secs = 14 * 600 (14 blocks); offer TTL 900 s
```

The buyer's 204-block limit leaves room for the seller's 24-block final CLTV plus two routing hops at LND's default per-hop delta (`bitcoin.timelockdelta`, 80). The seller's 14-block settle margin is above LND's own hold-expiry cancel (`invoices.holdexpirydelta`, 12), so the seller never tries to settle an HTLC its node is about to cancel; when it decides not to settle, it cancels the HTLC so the buyer is refunded at once. The CI runs of 21 October 2026 before these presets used a 40-block buyer limit, a 24-block final CLTV and a 1-block margin. Only the direct alice to bob channel has been tested; a route through an intermediate node has not.

### Stop and clean up

```bash
docker rm -f alice bob bitcoind
docker network rm pcpnet
rm -rf creds
```

Run this before starting `up.sh` again: it creates the network and the containers by name and stops if they already exist.
