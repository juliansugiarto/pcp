# In-house SHA-256 chip: notes for the next reviewer

File: `src/sha256.rs`. Call site: `src/circuit.rs` (`ShaChip::digest`). This
chip replaces the removed Table16 gadget. It is new and UNAUDITED. These notes
give the invariants a reviewer should check, the cell-ownership table, and the
region-safety argument for the sliding-window rotations.

## Shape

- `k = 13` (8192 rows); `k = 12` does not fit (Poseidon + sudoku). Measured in
  COSTS.md.
- Max gate degree: **8** (reported by `cargo run --release --example stats`).
  It comes from the `A[t]` carry range polynomial `prod_{i=0}^{6}(acar - i)`
  (degree 7) times its selector. Poseidon's degree-6 S-box already fixes the
  halo2 extended-domain factor at 8, so this degree costs nothing; a lower SHA
  degree would not shrink it.
- 80 advice columns: 64 of them are the SHA bit columns (`abit[0..32]`,
  `ebit[0..32]`). The bit columns have NO `enable_equality`; they are read only
  by gates via fixed rotations, so they add no permutation polynomials. Only a
  handful of columns are in the permutation argument (`aval`, `eval`, `wc`, the
  5 Poseidon/sudoku work columns, instance).

## Layout (three regions, shared columns)

| region | rows | selector | count |
|---|---|---|---|
| message schedule | `W_0..W_7` (key), `W_8..W_15` (padding) | `q_sched_word` | 16 |
| message schedule | `W_16..W_63` | `q_sched` | 48 |
| compression | IV seed rows (A=IV3..IV0, E=IV7..IV4) | `q_init` | 4 |
| compression | rounds `t=0..63` at row `t+4` | `q_round` | 64 |
| digest | `H_0..H_7` feed-forward | `q_digest` | 8 |

These exact counts are pinned by the test
`adversarial::selector_enable_counts_match_the_layout` (normalised by the
floor planner's pass count).

A/E recurrence: row `r` of the compression region holds `A[r-4]` and `E[r-4]`.
Round row `t+4` reads `A[t-1..t-4]` / `E[t-1..t-4]` at rotations `-1..-4`, so
the 4 IV-seed rows are the lookback for the first rounds. Final state:
`a=A[63]@row67, b=A[62], c=A[61], d=A[60]; e=E[63], f=E[62], g=E[61], h=E[60]`.
`H[m] = (final + IV[m]) mod 2^32`.

## Cell ownership (every advice cell has exactly one owner)

Owner = the gate whose constraints determine the cell, or the copy/constant it
is assigned from. Unassigned cells are never read by an enabled gate.

| column | schedule given (0..15) | schedule computed (16..63) | IV seed (0..3) | round (4..67) | digest (0..7) |
|---|---|---|---|---|---|
| `abit[0..32]` | `q_sched_word` bool | `q_sched` bool | `q_init` bool | `q_round` bool | `q_digest` bool |
| `ebit[0..32]` | unassigned (not read) | unassigned (not read) | `q_init` bool | `q_round` bool | unassigned (not read) |
| `aval` | i<8: copy from `k_cells`; i in 8..16: `assign_advice_from_constant` (padding); pack tied by `q_sched_word` | `q_sched` W-addition; pack tied | `assign_advice_from_constant` (IV); pack tied by `q_init` | `q_round` A-addition; pack tied | `q_digest` addition; pack tied |
| `eval` | unassigned | unassigned | `assign_advice_from_constant` (IV); pack by `q_init` | `q_round` E-addition; pack tied | unassigned |
| `s0` | unassigned | `q_sched` (lower_sigma0) | unassigned | `q_round` (Sigma0) | unassigned |
| `s1` | unassigned | `q_sched` (lower_sigma1) | unassigned | `q_round` (Sigma1) | unassigned |
| `chc` | unassigned | unassigned | unassigned | `q_round` (Ch) | unassigned |
| `majc` | unassigned | unassigned | unassigned | `q_round` (Maj) | unassigned |
| `wc` | unassigned | unassigned | unassigned | copy of `W_t` (`w_cells[t]`) | copy of operand `A/E` |
| `acar` | unassigned | `q_sched` carry (addition + range 0..3) | unassigned | `q_round` A-carry (addition + range 0..6) | `q_digest` carry (addition + bool) |
| `ecar` | unassigned | unassigned | unassigned | `q_round` E-carry (addition + range 0..5) | unassigned |
| `kcol` (fixed) | 0 | 0 | 0 | `K_t` (`assign_fixed`) | `IV[m]` (`assign_fixed`) |

Notes:
- `aval` for `W_0..W_7` is a copy constraint to the caller's `k_cells` (the same
  cells `circuit.rs` packs into `k_hi`/`k_lo` for Poseidon). The pack gate then
  forces `abit` to be the bit decomposition of that shared cell, which is why a
  SHA key word cannot differ from the Poseidon key word (tested).
- `ebit` on schedule and digest rows is left unassigned on purpose: no gate on
  those rows reads `ebit` at any rotation, so it needs no booleanity. It
  defaults to 0 and never enters a constraint.
- `kcol` and the IV/padding constants are FIXED (or constrain-to-constant);
  the prover cannot choose them. They are checked by a known-answer test
  (`round_constants_and_iv_are_the_fips_known_answer`), not by a (vacuous)
  witness tamper.

## Booleanity coverage

Every bit cell that is READ is covered by exactly one booleanity gate on its
row kind: `q_sched_word` (given `abit`), `q_sched` (computed `abit`), `q_init`
(seed `abit`+`ebit`), `q_round` (round `abit`+`ebit`), `q_digest` (digest
`abit`). No bit cell is covered by two gates (each row kind has exactly one
selector that owns its bits).

## Region safety for the sliding-window rotations

The round gate reads rotations `-1..-4`; the schedule gate reads `-2,-7,-15,
-16`. Each reference must (a) land on an assigned cell and (b) stay inside the
same region, because the three regions share the `abit/aval/s0/s1/acar`
columns.

`SimpleFloorPlanner` lays each region in a contiguous block of rows and assigns
regions in call order (schedule, then compression, then digest). Within a
region, a gate enabled at internal offset `o` reads offset `o-n` for a rotation
`-n`; this stays `>= 0` (inside the region) because:
- schedule: `q_sched` is enabled only at offsets `>= 16`, and its deepest
  lookback is `-16`, so `o-16 >= 0`;
- compression: `q_round` is enabled only at offsets `>= 4` (the 4 IV-seed rows
  precede it), and its deepest lookback is `-4`, so `o-4 >= 0`;
- digest: `q_digest` reads only the current row.

So no rotation crosses a region boundary into another region's rows, and every
referenced offset is assigned (schedule rows assign `abit`/`aval`; seed and
round rows assign `abit`/`ebit`/`aval`/`eval`). `MockProver` additionally fails
on any enabled gate that reads an unassigned cell, and the honest and
adversarial suites pass, which exercises this end to end.

## What the tests cover

- `trace_matches_sha2_reference`: the pure-Rust witness equals `sha2` (40 keys).
- `in_circuit_sha256_equals_sha2_for_many_keys`: the full circuit's digest
  equals `sha2` for 20 random + 4 edge keys (all-zero, all-0xff, two alternating
  patterns), and a single flipped `H` bit is rejected.
- `instance_endianness_known_answer_and_negative`: honest `H` passes; reversing
  the 4 bytes of one output word fails.
- `round_constants_and_iv_are_the_fips_known_answer`: `K` and `IV` are the FIPS
  180-4 tables.
- `selector_enable_counts_match_the_layout`: 4/64/16/48/8 enables.
- `every_sha_constraint_rejects_a_tampered_witness`: 19 advice-cell tampers (the original text said 21; corrected after the review in `2026-10-21-newchip-review.md`, finding L-2),
  each rejected (non-boolean bit; packed != bits; wrong IV seed bits; tampered
  A/E/schedule/digest carry; tampered `W_t` for `t>=16`; tampered inter-round
  state; tampered final words; tampered digest word; tampered padding bits; SHA
  key word != Poseidon key word).

Thread-local hooks require `--test-threads=1` (already documented in README and
COSTS).

## Still open (needs a human)

- A review of this chip by someone outside the project (these notes are the author's own; the review inside the project, by a separate AI reviewer, is `2026-10-21-newchip-review.md`).
- A second implementation of the suite for cross-conformance vectors.
- A full audit before any money relies on it.
- Spot-checked but not proven: that the per-bit polynomials for Sigma/sigma/Ch/
  Maj use the correct rotation index maps for all 32 bit positions (the `sha2`
  known-answer over 44 keys is strong evidence, not a proof).
