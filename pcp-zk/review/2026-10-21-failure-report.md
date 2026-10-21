# Failure report: an unsound SHA-256 gadget in a ZKCP circuit, caught before anyone paid

*21 October 2026. Julian Sugiarto.*

This is a failure report. It covers a proof-contingent payment circuit (ZKCP over Lightning) that used the halo2 Table16 SHA-256 gadget. An internal read-only review found that a seller could forge the payment hash. We reproduced the forgery, removed the gadget, and wrote a replacement. This post covers what broke, how we found it, what replaced it, and what the replacement has and has not been checked for.

No real money was ever involved. The circuit was never published as safe to use.

## The statement

A seller sells a sudoku solution `R` for a puzzle the buyer chose. Before paying, the buyer receives a ciphertext `C`, a Lightning payment hash `H`, and a proof that the seller knows `k` and `R` with:

1. `R` is a valid solution consistent with the puzzle's givens;
2. `C = Enc_k(R)`, using a Poseidon keystream derived from `k`;
3. `SHA256(k) = H`;
4. the proof is bound to this offer.

The buyer pays a BOLT 11 invoice with payment hash `H`. Settling it reveals `k` as the preimage. The buyer then decrypts `C`. Condition 3 is the only thing tying the payment to the key. The HTLC enforces `SHA256(preimage) = payment_hash` and nothing else, so one SHA-256 compression has to be inside the circuit.

Proof system: halo2_proofs 0.3.5, IPA over Pasta. It is transparent, with no trusted setup, so the CRS attack of Campanelli et al. (CCS 2017) has nothing to poison.

## What broke

We vendored the Table16 SHA-256 gadget from halo2_gadgets 0.5.0 and patched three small things we had noticed. A reviewer who had not written the code then read all of it, read-only, and found four independent ways to forge `H`:

| ID | Gap |
|---|---|
| C-1 | Round constants `K_t` are assigned into an advice column with nothing tying them to constants |
| C-2 | The carries of the modular additions are not range-checked |
| C-3 | Message schedule words `W_16..W_63` are not linked to the schedule computation |
| C-4 | The final-round state words feeding the digest are free |

The attack: the seller issues an invoice with `H = SHA256(p)`. It encrypts under a different key `k != p`, and proves with a witness that forces the in-circuit digest to `H`. The proof verifies, the buyer pays and learns `p`, and decryption fails. The verifying key never changes. Only the prover's witness generator changes, and the seller controls that code.

We reproduced C-1 and C-4 with MockProver: tests that shift `K_63`, or the round-63 value of `a_final`, still satisfy every constraint.

## The part we got wrong before the review

On 2026-09-29, upstream removed this gadget in halo2_gadgets 0.6.0. The changelog says it was removed "due to multiple soundness vulnerabilities". It also says the carry issue was "confirmed exploitable, allowing a malicious prover to forge arbitrary SHA-256 digests" ([zcash/halo2#964](https://github.com/zcash/halo2/pull/964)). We knew the module was gone from 0.6.0. We read "unstable" as "API may change" and did not read why it was removed.

Upstream names three issues: missing carry range checks (our C-2), missing copy constraints on final-round outputs (our C-4), and missing booleanity on schedule decomposition bits. Our C-1 and C-3 are not in that PR, not in the 0.6.0 changelog, and not in the one fork removal we found, which gave "no remaining consumers" as its reason (searched 21 Oct 2026). We added C-1 and C-3 to the public record in a comment on zcash/halo2#964 on the day this report was published, so that forks still carrying the 0.5.0 code can see them.

The same bug class has bitten audited code. CVE-2026-54496: Zcash's variable-base scalar multiplication gadget assigned the base point with `assign_advice` where `copy_advice` was needed, so a prover could choose any base. It sat in production from May 2022 until an audit found it in May 2026, and the fix needed a hard fork ([GHSA-ww9q-8r59-xv46](https://osv.dev/vulnerability/GHSA-ww9q-8r59-xv46)). Every advice cell needs exactly one owner, whoever wrote the gadget.

The lesson for anyone vendoring crypto gadgets: read the changelog and the removal notes, not just the version number. In a cryptographic crate, "unstable" can mean "unsound".

## The replacement

The replacement is a bit-level SHA-256 chip. It was written so that a reviewer can check it cell by cell, not so that it is small. The design rule: every advice cell has exactly one owner, either a gate enabled on its own row or a copy constraint from an owned cell.

- Every 32-bit word is 32 boolean cells plus a packed cell on the same row, tied by a packing gate.
- There is one row per round. The round gate reads the previous four rows by rotation (a sliding window). The schedule gate reads `W[t-2], W[t-7], W[t-15], W[t-16]` the same way.
- `K_t` and the IV are in a fixed column, so the prover cannot choose them.
- Each carry is constrained by the exact product `∏(c - i)` over its range: 0..5 for E, 0..6 for A, 0..3 for the schedule, boolean in the digest.
- Key words enter the schedule, each `W_t` enters its round, and the final state enters the digest, all by copy constraint.

Tests:

- 19 malicious witnesses are rejected: a non-boolean bit, a packed value that disagrees with its bits, a wrong IV word, a shifted carry in each of the four carry columns, shifted W, A, E, digest and padding words, and SHA key bits that differ from the Poseidon key.
- 14 compensated forgeries are rejected, each by exactly the constraint that owns the tampered cell. In each one the trace downstream of the tampered cell is recomputed and `H` is set to the forged digest, so only one constraint can catch it. They were written by the independent reviewer (section 5).
- In-circuit SHA-256 equals the `sha2` crate for 24 keys.
- 7 MockProver tests and 6 real-proof tests pass.
- A 14-case CLI end-to-end run passes. It includes a seller who lies consistently: their public file agrees with a forged `H`, binding or puzzle, so only the proof can reject it.

Costs on 2 CPUs:

| | Table16 (unsound) | Replacement |
|---|---|---|
| `k` | 17 | 13 |
| Prove | 143.6 s, 4.29 GB peak | 7.8 s, 0.57 GB peak |
| Verify | 0.98 s | 0.057 s |
| Proof | 5,088 bytes | 15,936 bytes |
| Advice columns | 10 | 80 |

Table16's 2^16-row spread table was what forced `k = 17`. Without it `k` drops to 13. The proof grows because IPA proof size scales with the column count.

## What the replacement has and has not been checked for

A second reviewer, again someone who had not written the chip, checked it against a 16-item checklist. Two tools did the checking, not reading alone. The first was a recorder that replays the circuit's assignments without MockProver. The second was the set of 14 compensated forgeries above.

- Every advice cell has exactly one owner.
- 23,128 (gate, row, cell) rotation triples land on cells assigned by the same region.
- The five selectors are on exactly 16, 48, 4, 64 and 8 contiguous rows.
- Exactly 104 copy constraints touch SHA columns, all of them intended.
- Items 1 to 15 pass. Item 16, automated under-constraint detection, was not run.

The review found no soundness issue in the chip. It did find one in our tests, and that one matters. The 19 original malicious witnesses left the rest of the honest trace in place, so the rejection could come from any downstream constraint. None of them targeted the `W_t` copy, the final-state copy or a field-solved carry: the exact classes that broke Table16. We checked this by mutation testing:

- with the `W_t` copy into the round replaced by a fresh cell, every original test still passed;
- with the E-carry range check removed, every original test still passed;
- in both cases only the compensated forgeries failed, with "ACCEPTED with H != SHA256(k)".

If you test a circuit with tampered witnesses, recompute everything downstream of the tamper and forge the public output. Otherwise your tests show that the circuit is consistent, not that each constraint is needed.

The review is `pcp-zk/review/2026-10-21-newchip-review.md`. The tests are `pcp-zk/src/review_tests.rs` (compensated forgeries, layout and ownership) and `pcp-zk/src/adversarial.rs` (the original 19 tampers).

It has not been audited by anyone outside this project. We do not consider one project's own review enough for a hash circuit that guards money. For that reason this chip is published as a target to break, not as the backend anyone should pay through. The backend meant for payments is a zkVM (RISC Zero): there SHA-256 is part of circuits maintained by a team that does this full time, and our guest code is plain Rust calling `sha2`. That backend has been written but not yet run; its cost table will come from CI. The halo2 chip is labelled "reviewed and tested by us, not audited". A buyer has to allow it explicitly.

## Two bounties

No reward is funded yet. Both bounties are open now as challenges, and the results will be credited publicly. The break-this bundle is in `pcp-zk/bundle-v1/`; funding, donation addresses and full terms will be added there. Claims: open an issue in this repository, or ask there for a private channel. Timestamp your claim first (for example with OpenTimestamps), because the first timestamp wins.

1. **Privacy:** produce the grid `R` committed to in the bundle (`pcp-zk/bundle-v1/`) (a salted SHA-256 commitment is published) from `(givens, C, H, π)` alone. The bounty instance uses an **empty grid** as the givens, so `R` is one of about 6.7 x 10^21 valid grids and cannot be computed from the puzzle. On a well-posed sudoku this bounty would be meaningless: a solver gets `R` from the givens in milliseconds. Our own first draft of this bounty made exactly that mistake.
2. **Soundness:** produce a proof that verifies against the published verifying key for any `(givens, C, H, binding)` where `H != SHA256(k)` for the `k` that decrypts `C`, or where the decryption of `C` is not a valid solution.

The second bounty is the lesson of this report. Our first plan offered only the first.
