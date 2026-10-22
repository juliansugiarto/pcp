# PCP: proof-contingent payment

> Verified exchange: pay only if it is proven, under a mandate you sign, settled where nobody can freeze it.

**Status: v0, a prototype for learning and discussion. Not audited. The RISC Zero backend has produced real proofs in CI, and the LND rail has settled a full sale between two real LND nodes on regtest (LND v0.19.3 and v0.21.4), both on 21 October 2026. On the same day the two ran together: a sale with a real RISC Zero proof settled over real LND nodes on regtest. Do not use with real money.** For how to run it yourself, see [`RUN.md`](RUN.md).

## What PCP is

PCP (*proof-contingent payment*) is a way to pay for a piece of work where the payment happens only if there is proof that the work is correct. The buyer and the seller do not need to know each other, trust each other, or be able to sue each other. There is no joint account (escrow), no platform, no court.

The exchange is atomic. The buyer cannot get the result without paying, and the seller cannot get the money without handing over the result.

Buyers and sellers can be humans, or they can be programs (agents). But every agent acts for a principal: a human, or an organisation controlled by a human. The principal signs a mandate for its agent. Money flows to the principal, and every receipt also reaches the principal.

## How it works

1. The seller does the task and gets a result `R`.
2. The seller picks a random key `k`, encrypts the result into `C`, and computes `H = SHA256(k)`.
3. The seller produces a proof that `C` contains a result that passes the check, locked with a key whose hash is `H`.
4. The buyer checks the proof themselves, offline, **before** paying.
5. The buyer pays a Lightning invoice with `payment_hash = H`. To receive the money, the seller must reveal `k`. Once `k` is revealed, the buyer can open `C` and get `R`.

This is a modern form of ZKCP, first done in practice on Bitcoin in February 2016 by selling a sudoku solution.

## Why mandates

An agent without a human principal is exactly the future people do not want. Such an agent cannot be stopped, nobody is responsible for it, and it can fund itself. A payment path without an operator will be the path it uses, unless the defaults refuse it.

So in PCP every agent carries a mandate signed by its principal. It contains: the kinds of work allowed, a total limit (cap), a per-transaction limit, the principal's Lightning node, and an expiry date. The buyer refuses a seller that has no valid mandate, and the seller refuses a buyer that has no valid mandate or whose cap is used up.

The cap and closing the channel are the stop button. A principal who funds its agent's channel with N sat has already limited that agent to N sat, without asking anyone's permission. Closing the channel stops it. Payments to the seller go to the principal's node, not the agent's node, so the agent cannot fund itself.

The limits must be stated plainly. A mandate only proves that a key gave permission. A mandate does not prove that the holder of the key is a human, and it does not prove their legal identity. There is no privileged issuer: any key may be a principal, and mandates are checked offline with no third party.

Operating without a mandate is only possible by modifying the client. This project does not ship that and does not document it. None of these rules can be enforced on a modified client. These rules are defaults, enforced by counterparties refusing.

## Why it cannot be taken over

Settlement happens on Bitcoin, through ordinary Lightning HTLCs. The payment condition is a script and a proof. There is no operator role that can be bought, regulated, or shut down.

An imitation version with stablecoins can be built, but that version always carries two extra roles: an issuer that can freeze funds, and a facilitator that routes transactions and can be ordered to do KYC. PCP on Bitcoin has neither of these roles.

## What v0 does

- The complete `PCP/0` specification in [`SPEC.md`](SPEC.md): message formats, canonical encoding, verification order, the proof backend interface, the threat list, and test vectors for a second implementation.
- A Rust crate `pcp` with two job classes:
  - `SudokuJob`: checks a 4x4 or 9x9 sudoku solution, the classic 2016 demo.
  - `TestSuiteJob`: "a patch that passes the tests". The result is a function body in a small expression language, which is then tested against the buyer's list of `(x, expected result)` pairs.
- Buyer and seller state machines that follow the verification order in the specification, with one error type for each threat.
- Ed25519 mandates signed by the principal, checked in both directions: job scope, total cap, per-transaction limit, expiry. An agent may not be its own principal.
- Payment to the principal: the seller's invoice must pay the principal's node named in the mandate.
- Receipts and refusals for the principal: every transaction, including refused ones, is logged, signed by the agent, and can be exported as JSON lines. The principal can re-check all of it offline.
- A registry of reviewed and tested job classes. Unregistered classes are refused by default. Registered means reviewed and tested, not safe.
- A per-transaction value limit in the default buyer policy (10,000 sat), because PCP is meant for small, repeatable jobs.
- A simulated HTLC ledger: principal-owned nodes, create invoice, pay (funds locked), settle with preimage, expiry and refund.
- The statement core (`src/statement.rs`): the relation being proven, as one pure function with no `std`, no randomness, no I/O. The dev backend calls it in the open, and the RISC Zero guest calls it inside the zkVM. Its journal is the preimage of `statement_hash`. Test vectors 14 to 17 cover this part.
- The `Rail` trait (`src/rail.rs`): create invoice, pay, settle with preimage, look up status. The simulated ledger implements it, and the buyer and seller state machines talk only through this trait.
- The LND rail (`src/rail/lnd.rs`, feature `lnd`, off by default): hold invoices through the LND REST API. Run against real LND v0.19.3 and v0.21.4 nodes on regtest by the `lnd-regtest` CI workflow: a full sale settles, and `tests/lnd_regtest.rs` (ignored by default) checks a reused hash, a presented invoice with other terms, and a cancelled hold invoice.
- `src/sale.rs`: one sale from start to finish on any backend and rail, with timing measurements for the cost table.
- Buyer and seller as two processes (`src/node/`, binaries `pcp-sell`, `pcp-buy`, `pcp-audit`): each has its own state directory, saves its state after every step, and resumes after a restart. They talk over a directory of JSON messages or over HTTP (SPEC 5.5, feature `http`: `pcp-sell --listen`, `pcp-buy --seller-url`; the seller serves on loopback behind a TLS proxy, the buyer refuses `http://` unless told it is a test). The seller proves only after the buyer's signed Accept (SPEC 5.1a). `tools/crash-matrix.sh` kills each side at 19 named points (before and after each save), restarts it, and checks both state directories with `pcp-audit`, the exit codes and the money moved. On 22 October 2026 it passed every case on the simulated network (23, `two-process` workflow) and on two real LND nodes, v0.21.4 and v0.19.3 (24 each, `lnd-regtest`), including one where the buyer's node is stopped while the buyer waits on a payment it made. In `real-sale`, the same two processes sold a 9x9 sudoku with a real RISC Zero proof over LND, once cleanly and once with the seller killed after invoicing. The same matrix over loopback HTTP passed every case too, at commit 70b1c39: 23 on the simulated network, 24 on each LND version.
- A demo with four principals and four agents, and 91 tests (99 with `--features lnd`, 97 with `--features http`, plus 4 real-node tests that run against LND regtest in CI).

## What v0 does not do yet

- **Zero knowledge runs outside this crate.** The RISC Zero backend is in [`../pcp-risc0/`](../pcp-risc0/), outside this crate's build. It was first run in CI on 21 October 2026. Proving a 9x9 sudoku with the reproducible (Docker-built) guest, the one a buyer can check, takes 62 to 102 s on a 4-vCPU CI runner (runner speed varies) and about 1.4 GiB of memory; the receipt is 224 KB and verifies in about 0.02 s (see `../pcp-risc0/COSTS.md`). Inside this crate's own tests, the only backend, `InsecureDevTransparentBackend`, puts the witness (result and key) inside a seal whose key is written in the source code. Its verification still checks the full relation, so the protocol flow is tested. But anyone who reads the code can open that seal and get the result without paying. The buyer refuses this backend unless it is explicitly allowed for testing.
- **Real Lightning only on regtest.** The LND rail has settled sales between two real regtest nodes in CI, including a sale with a real RISC Zero proof (21 October 2026, see `../pcp-risc0/COSTS.md`). It has never run on signet or mainnet.
- There is no "data matches schema" job class yet, although its shape is the same as the two existing classes.
- **Two processes, but not yet between strangers.** The HTTP binding has run only on loopback in CI, never behind a real TLS proxy or across the internet, and one state directory holds one purchase. Timelocks are still expressed in seconds, not blocks, and a sale has not yet been routed through an intermediate Lightning node.

## Running

Requires stable Rust and access to crates.io to download dependencies.

```bash
cd pcp
cargo build
cargo test
cargo run --bin demo
cargo test --features lnd                  # LND rail, no network
cargo build --no-default-features          # statement core only, no_std (what the zkVM guest uses)
python3 tools/vectors.py                   # SPEC Appendix A vectors 1 to 17 in Python (needs `cryptography`)
tools/crash-matrix.sh /tmp/matrix          # two processes, killed and restarted at every point (simulated network)
```

With RISC Zero proofs and two regtest LND nodes: see [`RUN.md`](RUN.md).

Every agent in the demo works under its principal's mandate. Demo 1 sells a 9x9 sudoku solution between two agents. Demo 2 sells a patch: the seller's first candidate fails one test and cannot be sold, then the second candidate passes and is sold. Demo 3 shows a refusal: the same buyer agent asks again, its cap is almost used up, and the seller refuses.

Money always moves between principals' nodes. At the end, each principal's log is printed and re-checked: receipts, refusals with their reason codes, and agent signatures.

The tests cover the normal path of both jobs and every threat: a ciphertext containing a wrong result, a mismatched invoice hash, a wrong preimage, a buyer who does not pay, expired invoices and HTLCs, and a proof replayed to another buyer. The mandate tests cover a missing mandate, a wrong signature, expiry, mismatched scope, a cap exceeded across transactions, the per-transaction limit, a payee that is not the principal's node, the principal log, an unregistered job class, and payment to oneself.

## Folder contents

| File | Contents |
|---|---|
| `SPEC.md` | PCP/0 specification (English) |
| `src/job/` | Job classes: sudoku and test suite |
| `src/statement.rs` | Statement core: the relation being proven, guest input, journal, test vectors |
| `src/proof.rs` | Statement, proof bundle, backend interface, the INSECURE dev backend |
| `src/lightning.rs` | Simulated HTLC ledger, principal-owned nodes |
| `src/rail.rs`, `src/rail/lnd.rs` | `Rail` trait; LND rail (feature `lnd`) |
| `src/sale.rs` | One complete sale on any backend and rail |
| `src/bin/lnd_sale.rs` | Sudoku sale over two LND nodes (feature `lnd`) |
| `RUN.md` | How to run the tests, the halo2 CLI, the RISC Zero guest, and a sale over two LND nodes on regtest |
| `tools/vectors.py` | Recomputes the SPEC Appendix A vectors in Python and compares them with the SPEC |
| `src/mandate.rs` | Keys, mandates, agents, principal log, metrics |
| `src/registry.rs` | Registry of reviewed job classes |
| `src/protocol.rs` | Messages, buyer and seller state machines, receipts, error list |
| `src/tests.rs` | Threat tests, mandate tests, and conformance vectors |
| `tests/public_api.rs` | Full-flow tests through the public API |
| `src/bin/demo.rs` | Demo |

## Legal note

This section is not part of the protocol. It was section 13 of `SPEC.md`.

- **The authors publish code and the specification. That is all.** Publishing open-source protocol code is the only activity of this project.
- **Nobody in this project operates** a custodial wallet, a Lightning hub, LSP or router that forwards others' payments for a fee, a relay, matching service, facilitator or escrow that touches others' funds, a rupiah on-ramp or off-ramp, or any mixing service. Liability follows operation and fees, not authorship; the project stays on the authorship side.
- **Indonesia:** any transaction with a payment purpose inside Indonesia must use rupiah (UU No. 7 Tahun 2011 tentang Mata Uang, Art. 21(1), with criminal penalties in Art. 33(1)), and payment-system providers may not process virtual-currency payments. Domestic payment in BTC is therefore unlawful, and PCP MUST NOT be offered or marketed for domestic payment in Indonesia.
- **First users are cross-border:** foreign agents paying foreign agents; developers paid from abroad for exported, verified work (whether Art. 21(2)'s international-trade exemption covers crypto consideration for exported services is untested; income is taxable); open-source bounties funded from abroad. The only lawful domestic form is decoupled and non-atomic: the proof gates key release while rupiah moves over a licensed rail.
- This section is a summary of the project's position, not legal advice.

## Next steps

1. **Signet.** The RISC Zero backend and the LND rail have run together on regtest (see `../pcp-risc0/COSTS.md`). Next: a sale between two LND nodes on signet. Also check whether LND macaroon constraints or LNC budgets are enough as a budgeted credential for agents.
2. **More cost measurements.** Apple Silicon with the Metal GPU prover has not been measured (see `../pcp-risc0/COSTS.md`).
3. **A second implementation** that passes the vectors in Appendix A of the specification. `tools/vectors.py` recomputes the vectors (encoding, cipher, mandate signature); it is not a second implementation of the protocol.
