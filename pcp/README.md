# PCP: proof-contingent payment

> Verified exchange: pay only if it is proven, under a mandate you sign, settled where nobody can freeze it.

**Status: v0, a prototype for learning and discussion. Not audited. The RISC Zero backend has produced real proofs in CI, and the LND rail has settled a full sale between two real LND nodes on regtest (LND v0.19.3 and v0.21.4), both on 21 October 2026. The two have not yet run together in one sale: the LND sale used the insecure dev proof backend. Do not use with real money.** For how to run the first real instance, see [`RUN-ON-MAC.md`](RUN-ON-MAC.md) (Indonesian; an English version is not yet written).

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
- A demo with four principals and four agents, and 61 tests (68 with `--features lnd`).

## What v0 does not do yet

- **Zero knowledge runs outside this crate.** The RISC Zero backend is in [`../pcp-risc0/`](../pcp-risc0/), outside this crate's build. It was first run in CI on 21 October 2026 (64.6 s to prove a 9x9 sudoku on 4 vCPU, receipt 224 KB; see `../pcp-risc0/COSTS.md`). Inside this crate's own tests, the only backend, `InsecureDevTransparentBackend`, puts the witness (result and key) inside a seal whose key is written in the source code. Its verification still checks the full relation, so the protocol flow is tested. But anyone who reads the code can open that seal and get the result without paying. The buyer refuses this backend unless it is explicitly allowed for testing.
- **Real Lightning only on regtest.** The LND rail has settled sales between two real regtest nodes in CI, but never on signet or mainnet, and never together with a real (non-dev) proof.
- There is no "data matches schema" job class yet, although its shape is the same as the two existing classes.

## Running

Requires stable Rust and access to crates.io to download dependencies.

```bash
cd pcp
cargo build
cargo test
cargo run --bin demo
cargo test --features lnd                  # LND rail, no network
cargo build --no-default-features          # statement core only, no_std (what the zkVM guest uses)
```

With RISC Zero proofs and two regtest LND nodes: see [`RUN-ON-MAC.md`](RUN-ON-MAC.md) (Indonesian; an English version is not yet written).

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
| `RUN-ON-MAC.md` | Steps to run real proofs and regtest Lightning on a Mac (Indonesian; an English version is not yet written) |
| `src/mandate.rs` | Keys, mandates, agents, principal log, metrics |
| `src/registry.rs` | Registry of reviewed job classes |
| `src/protocol.rs` | Messages, buyer and seller state machines, receipts, error list |
| `src/tests.rs` | Threat tests, mandate tests, and conformance vectors |
| `tests/public_api.rs` | Full-flow tests through the public API |
| `src/bin/demo.rs` | Demo |

## Legal limits

This project only publishes code and a specification. Nobody in this project runs a custodial wallet, a Lightning hub or router, a relay, escrow, a matching service, or rupiah on-ramps and off-ramps.

In Indonesia, transactions whose purpose is payment must use rupiah (Law 7/2011 on Currency, Article 21). Paying with BTC domestically is against the law. Therefore PCP must not be offered for domestic payments.

The first users are cross-border: agents abroad paying agents abroad, developers paid from abroad for exported, verified work, and open source bounties funded from abroad. This section is the project's position, not legal advice.

## Next steps

1. **Run the zkVM backend.** The RISC Zero guest and host skeleton already exists in `../pcp-risc0/`. The next step is to compile and run it on a Mac (section 2 of `RUN-ON-MAC.md`, in Indonesian). STARK proofs need no trusted setup, so the 2017 CRS attack does not apply.
2. **Run real Lightning.** The LND rail exists behind the `lnd` feature. Next step: two LND nodes on regtest with Polar (section 4 of `RUN-ON-MAC.md`, in Indonesian), then signet. Also check whether LND macaroon constraints or LNC budgets are enough as a budgeted credential for agents.
3. **A measured cost table.** For each job class: cycle count, proving time, cost in USD and satoshi, and the ratio of proof cost to job price. Numbers that actually came out, not estimates.
4. **A second implementation** that passes the vectors in Appendix A of the specification.
