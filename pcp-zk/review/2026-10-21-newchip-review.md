# Soundness review: the bit-level SHA-256 chip in pcp-zk

Date: 2026-10-21. Reviewer: a separate AI model session (Claude) that did not write the code, inside the project; not an outside party. Read-only on the repo.
Repo: `/home/claude/somnus`, branch `main`, HEAD `13eac4e`. The commit named in the brief, `c7581ec`, is the one that introduced the chip; `git diff --stat c7581ec HEAD -- pcp-zk/` touches only `README.md`, the old review, and `scripts/cli-e2e.sh`, so the sources reviewed (`pcp-zk/src/*.rs`) are byte-identical in both commits.
Crate: `pcp-zk` (halo2_proofs 0.3.5, IPA/Pasta, `k = 13`). Files: `src/sha256.rs` (960 lines), `src/circuit.rs`, `src/adversarial.rs`, `src/lib.rs`, `src/bin/pcp-zk.rs`, `tests/mock.rs`, `scripts/cli-e2e.sh`.
Checklist: `2026-10-21-reviewer-checklist.md` (section 1.2), items 1 to 16.
Line numbers below refer to the repo files unless marked `(copy)`, which is my scratch copy at `/tmp/claude-0/-home-claude/050e7634-91f2-5c3c-9f3e-28ef8a7e1e06/scratchpad/review-crate/`.

Method: I read all of `sha256.rs`, `circuit.rs`, `adversarial.rs`, `lib.rs`, the CLI, the mock and prove tests, and the halo2_proofs 0.3.5 registry source for the parts my conclusions depend on (`dev.rs` MockProver `verify` and `Assignment` impl, `floor_planner/single_pass.rs` region placement, `prover.rs` `WitnessCollection`, `circuit.rs` `query_fixed`). I then wrote two tests in a scratch copy of the crate: an `Assignment` recorder that re-derives the layout without MockProver, and a set of 14 *compensated* exploit attempts (malicious witness with everything downstream recomputed and `H` set to the forged digest). I also ran the author's `--lib` and `--test mock` suites and one real `create_proof`/`verify_proof` round in the copy.

---

## 1. Summary verdict

**Sound as far as reviewed. No Critical, High or Medium soundness finding in the chip.** Every advice cell the chip assigns has exactly one owner (section 4), every rotation of every enabled gate lands on a cell assigned by the same region (23,128 (gate, row, cell) triples checked mechanically), the five selectors are on exactly 16 / 48 / 4 / 64 / 8 distinct contiguous rows, the only copy constraints touching SHA columns are the 104 intended ones, the carries are range-checked with the exact product polynomial, `K_t` and the IV addends are in a fixed column, and the IV seed and padding words are constant-pinned. Fourteen compensated forgery attempts (seller-side `H != SHA256(k)` through the key copy, free `W_t` into a round, free digest operand, field-solved carries at every carry column, free IV, and an owned intermediate) were each rejected by MockProver, and each by exactly the one constraint class that is supposed to own the tampered cell, nothing else (section 5).

Findings are confined to the *test suite* and documentation (one Medium on test strength, three Low). The chip remains unaudited by anyone outside this project; this review does not change the author's own "reviewed, adversarially tested, not audited" label, and it does not cover halo2_proofs 0.3.5 or halo2_gadgets 0.5.0 Poseidon themselves.

---

## 2. Findings

### M-1 (Medium, test strength): the adversarial tampers are uncompensated, so the suite never shows that a copy constraint or a carry range is the *sole* defence

`src/adversarial.rs:48-85` (`tamper_cases`), `:87-103`.

Each tamper changes one cell and leaves the rest of the honest trace and the honest instance `H` in place. The rejection can then come from any downstream constraint or from the instance mismatch, not from the constraint the case is named after. Examples:

- "tampered final A[63]" (`:73`) is rejected by the round-63 A equation *and* by the digest gate (the tampered `A[63]` is copied into the digest operand while `H` stays honest). A chip in which the digest operand was a fresh cell (Table16's C-4) would still reject this case.
- "tampered W_16" (`:67`) is rejected by the schedule equation at 16, by the four later schedule rows that read `W_16`, and by the round-16 equation. A chip in which `W_t` entered the round as a fresh cell (Table16's C-3) would still reject this case.
- "SHA key != Poseidon key (word 0)" (`:82`) shifts the key *bits* under a copied `aval`, so it is rejected by the packing constraint; it never tests that the `aval` cell itself is tied to the Poseidon key cell.
- No case targets the `wc` copy of `W_t` into the rounds, the `wc` copy of the final state into the digest rows, or the constant copies of the IV seed, which are precisely the three classes that broke Table16.
- The carry cases add 1 to an integer carry; they do not try the field-solved carry `(sum - out) * 2^-32 mod p` that C-2 is about.

Failure scenario (hypothetical, not the current code): a future refactor replaces `w_cells[t].copy_advice(..)` at `sha256.rs:818` with a plain `assign_advice` of the same value. Every current adversarial test still passes, the honest tests still pass, and `W_t` is free, i.e. C-3 again.

Suggested fix: add the compensated tests in section 5.2 to the repo (`Attack` hook in `poc_hook`, `compute_trace_attacked`, post-copy overwrite of the copied cell). They assert the failure *kind* (permutation vs. a specific constraint index) so each case proves which constraint owns the cell.

### L-1 (Low, test strength): `selector_enable_counts_match_the_layout` counts `.enable()` calls, not selector rows

`src/adversarial.rs:136-157`; the counter is `poc_hook::count` called next to each `enable` (`sha256.rs:742,753,757,796,808,854`). Two `enable`s on the same row, or an `enable` on the wrong row, keep the counts unchanged. Checklist item 2 asks for a walk over the *assigned* selectors. The recorder test in section 5.1 does that: distinct rows per selector, contiguity, and `q_sched` immediately after `q_sched_word`, `q_round` immediately after `q_init`.

### L-2 (Low, documentation): "21 adversarial tampers" is 19

`tamper_cases()` has 19 entries (`adversarial.rs:51-83`). `review/2026-10-21-sha-chip-notes.md:119`, `README.md:6` and `COSTS.md` (test-duration table) say 21.

### L-3 (Low, documentation): the checklist's item 12 refers to code that is not in the commit

Item 12 mentions four placeholder assignments into `chc`/`majc` at row 0 of the compression region. The committed `sha256.rs` has none (`grep placeholder` finds nothing; the recorder finds 0 advice cells assigned more than once). Same for item 7's `tamper_fixed` hook: there is no fixed-column tamper in the committed code. Both items pass; the checklist was written against an earlier draft and should be updated so the next reader does not look for them.

### Informational

- I-1 Unassigned cells: `ebit[*]` on schedule and digest rows; `s0`, `s1`, `acar` on schedule rows 0..15; `wc`, `chc`, `majc`, `ecar`, `kcol` on the four seed rows. No enabled gate reads any of them at any rotation (recorder, 23,128 checks). In the real prover they are zero (`prover.rs:273` initialises every advice column with `empty_lagrange_assigned`). Harmless.
- I-2 `tamper_pack` treats `PackDelta` and `WordDelta` identically (`sha256.rs:874-880`); the difference is only in `assign_bits`. Fine, just a reading hazard.
- I-3 The author's tamper `Bit(5, 2)` writes the raw field value 2 (`sha256.rs:902`); good, it is a true non-boolean, not a flipped bit.
- I-4 `lib.rs:268` `assert!(blinding_rows() > 0)` is still the tautology the previous review called L-1. Harmless.

---

## 3. The 16-item checklist

| # | Item | Verdict | Evidence |
|---|---|---|---|
| 1 | Every referenced cell assigned on every selected row | **PASS** | Hand-transcribed rotation sets per gate (`sha256.rs:471-487, 490-577, 580-591, 594-654, 657-674`) checked by the recorder against the cells each region assigned: 23,128 triples, all in-region (section 5.1). Independently, halo2 0.3.5 MockProver `verify` reports `CellNotAssigned` for any queried cell not assigned *by the same region* (`dev.rs:580-640`, `r.cells.contains(..)`), and the honest tests pass. |
| 2 | Selector coverage 4 / 64 / 16 / 48 / 8 | **PASS** | Recorder: distinct rows `q_sched_word` 0..=15, `q_sched` 16..=63, `q_init` 64..=67, `q_round` 68..=131, `q_digest` 132..=139 (absolute rows); contiguous; pairwise disjoint. The author's test counts calls, not rows (L-1). |
| 3 | Negative rotations stay inside the region; no wrap-around | **PASS** | `SingleChipLayouter` places a region at `max` of the next free row of every column its shape uses (`single_pass.rs:95-106`), and the three SHA regions share `abit`, `aval`, `s0`, `s1`, `acar`, so they are laid out in call order: schedule rows 0..63, compression 64..131, digest 132..139 (recorder). Deepest lookback: schedule `-16` from offset 16, round `-4` from offset 4; recorder asserts `row + rot >= first row of region` for every triple. The earliest selected row with a negative rotation is absolute row 16, so nothing reaches domain row 0 or wraps. |
| 4 | Booleanity on every witnessed bit column, every row where it is read | **PASS** | Ownership table (section 4): every `abit` cell in all three regions and every `ebit` cell in the compression region has exactly one owning selector whose gate contains `b(1-b)` at `Rotation::cur()` (`sha256.rs:479-480, 500-501, 586, 602, 663`). Rotations `-1..-3` (round) and `-2`, `-15` (schedule) land on rows owned by `q_init`/`q_round` or `q_sched_word`/`q_sched` respectively (recorder). |
| 5 | Packing identity on the same row as the bits | **PASS** | `aval - sum(abit 2^i)` and `eval - sum(ebit 2^i)` at `cur` in all five gates (`sha256.rs:484-485, 507-508, 589, 605-606, 666-667`). Rows read at `aval@-4`, `-7`, `-16` and `eval@-4` are all owned by a gate with the pack constraint (section 4). |
| 6 | Carry ranges exact; the field cannot help | **PASS** | `range_poly` is the exact product `prod_{i=0}^{hi}(x-i)` (`sha256.rs:365-371`). `hi`: E carry 5 for 6 addends (`:573`), A carry 6 for 7 addends (`:574`), schedule 3 for 4 addends (`:651`), digest boolean for 2 addends (`:672`). All addends are `< 2^32` (packed-with-bits cells, per-bit boolean polynomials times `2^j`, fixed `K_t`, copied `W_t`), so the honest sum is `< 7 * 2^32 << p` and `(out, carry)` is unique over the integers. Five field-solved-carry attacks (one per carry column, section 5.2) were each rejected by exactly the range constraint (`Constraint 72/73 in gate 1`, `36 in gate 3`, `34 in gate 4`). |
| 7 | Fixed column identical at keygen and proving | **PASS** | `kcol` is assigned unconditionally with `Value::known` at `sha256.rs:816` and `:856`, inside the region, on the selected row. The real prover's `WitnessCollection` ignores `assign_fixed`, `enable_selector` and `copy` (`prover.rs:160-245`); fixed values and the permutation come from the proving key, and the verifier rebuilds the VK from `SaleCircuit::default()` (`lib.rs:190-192`). There is no `tamper_fixed` hook in the committed code. |
| 8 | No witness-dependent control flow on selectors or fixed cells | **PASS** | All branches in `digest()` are on the loop index (`sha256.rs:738, 744, 755`), never on a `Value`. In `circuit.rs` the only value-dependent code is the inverse witness (`:357-359`), which affects a witness value only. The test hooks read a thread-local, not the witness, and are compile-time `None` outside `cfg(test)` (`sha256.rs:174-178`). |
| 9 | Equality columns and the only cross-region links | **PASS** | `enable_equality` on `aval`, `eval`, `wc`, `work[0..5]` (`sha256.rs:450-455`), `a9` and `instance` (`circuit.rs:119,130`); bit columns and `s0/s1/chc/majc/acar/ecar` have none, so they cannot be copy endpoints. Recorder enumerates every copy touching a SHA column: key cell -> `aval` 8; constants -> `aval` 12 (8 padding + 4 A seed); constants -> `eval` 4; `aval` -> `wc` 68 (64 `W_t` into rounds + 4 `A[63..60]` into digest); `eval` -> `wc` 4; `aval` -> instance 8. Total 104, nothing else. |
| 10 | Instance endianness and layout | **PASS** | `lib.rs:43-46` `words()` = big-endian u32 per 4 bytes; `instance()` order givens, C, H, binding = `ROW_*` (`circuit.rs:58-62`); `constrain_instance` at `ROW_PAYMENT_HASH + i` (`circuit.rs:273-275`); digest word `m` is `final_words[m] + IV[m]` with `final_words = A[63],A[62],A[61],A[60],E[63..60]` (`sha256.rs:307-316, 838-847`). KAT: the circuit tests use key `[0x11;32]` with `suite::payment_hash`, which `suite.rs:142-149` pins to SPEC vector 2 `02d449a3...`; `trace_matches_sha2_reference` (40 keys) and `in_circuit_sha256_equals_sha2_for_many_keys` (24 keys, plus a flipped-bit negative); byte-reversed-word negative at `adversarial.rs:159-175`. |
| 11 | Adversarial suite tests what it claims | **PASS with M-1, L-1, L-2** | All 19 tampers are advice-cell tampers; no fixed-column tamper; `clear()` in every test; `--test-threads=1` documented (README:140). But the tampers are uncompensated (M-1) and the selector test counts calls (L-1). |
| 12 | Dead cells / placeholder assignments | **PASS** | None in the commit (L-3). Recorder: 0 advice cells assigned more than once in the whole circuit. |
| 13 | Degree and proof-system limits | **PASS** | `cargo run --release --example stats` (copy): `degree 8 blinding_factors 10`, 80 advice, 9 fixed, 13 selectors, 1 instance. Max comes from `q_round * range_poly(acar, 6)` (1 + 7). Keygen and a real proof succeed (section 5.3). |
| 14 | Column count vs memory, re-tuned `k` | **PASS (re-measured)** | `K = 13` (`circuit.rs:56`). One CLI `prove` in the copy: prove 7.503 s, peak RSS 570 MB, proof 15,936 bytes; `tests/prove.rs` honest round 14.88 s including params and keygen (section 5.3). Matches `COSTS.md`. The 2^16-row Table16 lookup is gone; the floor is Poseidon + sudoku (author: k = 12 does not fit; not re-checked). |
| 15 | CLI verify takes the buyer's own puzzle, `H`, binding; only `C` from the seller | **PASS (read and executed)** | `bin/pcp-zk.rs` `verify`: `--puzzle`, `--payment-hash`, `--binding` are all `need()`ed (required); `PublicInputs` is rebuilt from them with `ciphertext: seller.ciphertext` only; the seller file must additionally agree on givens, `H`, binding or the result is FAIL; `pcp_zk::verify` runs against the buyer-built inputs. `scripts/cli-e2e.sh` run in the copy: 14/14 cases as expected, including "wrong puzzle" and "consistent lie: other puzzle" (a seller `public.json` with different givens that agrees with the buyer's `--puzzle`: FAIL because the proof does not verify against those givens). |
| 16 | Tooling (Picus etc.) | **NOT CHECKED** | Only crates.io was reachable and the brief marked this optional. No under-constrained-circuit detector was run. |

---

## 4. Ownership table

Produced mechanically by the recorder test (`review_tests::layout_selectors_rotations_and_ownership`, section 5.1) and cross-checked against the gate source. "Owner" = the gate enabled on that row whose constraint determines the cell at `Rotation::cur()`, plus `+copy` when the cell is also an endpoint of a permutation copy. Every SHA advice cell has exactly one owner; the test asserts `own.len() == 1` for each cell.

Absolute rows: schedule 0..=63, compression 64..=131 (seed 64..=67, rounds 68..=131), digest 132..=139. Column indices: `abit` 0..31, `ebit` 32..63, `aval` 64, `eval` 65, `s0` 66, `s1` 67, `chc` 68, `majc` 69, `wc` 70, `acar` 71, `ecar` 72, `work` 73..77; fixed `kcol` 0, `constants` 1.

| column | schedule given (rows 0..15) | schedule computed (16..63) | IV seed (64..67) | round (68..131) | digest (132..139) |
|---|---|---|---|---|---|
| `abit[0..32]` | `q_sched_word`: bool + pack (512 cells) | `q_sched`: bool + pack (1536) | `q_init`: bool + pack (128) | `q_round`: bool + pack (2048) | `q_digest`: bool + pack (256) |
| `ebit[0..32]` | unassigned, never read | unassigned, never read | `q_init`: bool + pack (128) | `q_round`: bool + pack (2048) | unassigned, never read |
| `aval` | `q_sched_word` pack **+copy** from key cell (`work[2]`, rows 0..7) or from `constants` (rows 8..15) (16) | `q_sched` W-equation + pack **+copy** out to round `wc` (48) | `q_init` pack **+copy** from `constants` (4) | `q_round` A-equation + pack (60); rows 128..131 also **+copy** out to digest `wc` (4) | `q_digest` feed-forward equation + pack **+copy** out to instance (8) |
| `eval` | unassigned | unassigned | `q_init` pack **+copy** from `constants` (4) | `q_round` E-equation + pack (60); rows 128..131 **+copy** out to digest `wc` (4) | unassigned |
| `s0` | unassigned, never read | `q_sched` sigma0 equation (48) | unassigned | `q_round` Sigma0 equation (64) | unassigned |
| `s1` | unassigned, never read | `q_sched` sigma1 equation (48) | unassigned | `q_round` Sigma1 equation (64) | unassigned |
| `chc` | unassigned | unassigned | unassigned, never read | `q_round` Ch equation (64) | unassigned |
| `majc` | unassigned | unassigned | unassigned, never read | `q_round` Maj equation (64) | unassigned |
| `wc` | unassigned | unassigned | unassigned, never read | `q_round` reads it; **copy** of schedule `aval` row t (64) | `q_digest` reads it; **copy** of round `aval`/`eval` rows 128..131 (8) |
| `acar` | unassigned, never read | `q_sched` equation + `range_poly(.,3)` (48) | unassigned | `q_round` A-equation + `range_poly(.,6)` (64) | `q_digest` equation + boolean (8) |
| `ecar` | unassigned | unassigned | unassigned, never read | `q_round` E-equation + `range_poly(.,5)` (64) | unassigned |
| `kcol` (fixed) | 0 (not read) | 0 (not read) | 0 (not read) | `K_t`, `assign_fixed` (64) | `IV[m]`, `assign_fixed` (8) |

Rotation reads (all in-region, all landing on owned cells): round gate at row r reads `abit`/`ebit` at r-1..r-3 (seed or round rows, bool+pack) and `aval`/`eval` at r-4 (seed or round rows, pack); schedule gate at row i reads `abit` at i-2 and i-15 (given or computed schedule rows, bool) and `aval` at i-7 and i-16 (pack).

Why this suffices: by induction over rows, every cell is a function of the key cells and the constants. Schedule rows 0..15 are determined by the key cells/constants (pack + booleanity make the bits unique); each later schedule row, each round row and each digest row is `out + carry * 2^32 = S` with `S` determined by earlier owned cells, `out < 2^32` by its bits and `carry` in its exact range, which has a unique integer solution. The digest cells are therefore a function of the key cells, and that function agrees with SHA-256 on 24 keys through MockProver and matches FIPS 180-4 by reading (rotation sets 2/13/22, 6/11/25, 7/18/shr3, 17/19/shr10 at `sha256.rs:516, 527, 615-621, 633-639`; `rotr(n,j) = (j+n) mod 32` with LSB-first bits is bit j of `x >>> n`; `Ch(E[t-1],E[t-2],E[t-3])`, `Maj(A[t-1],A[t-2],A[t-3])`, `d = A[t-4]`, `h = E[t-4]`, seed rows `A[-4..-1] = IV3..IV0`, `E[-4..-1] = IV7..IV4`).

---

## 5. Extra tests written and their results

All in the scratch copy. Source changes to the copy that are *not* test code: `ShaConfig` fields, `SaleConfig::{sha,a}` and `Trace` made `pub(crate)`; `Trace` gained four attack-bookkeeping fields; `assign_carry` takes `Value<Fp>`; the attack hook is consulted after each `copy_advice` / `assign_advice_from_constant`. None of this changes `configure`.

### 5.1 `review_tests::layout_selectors_rotations_and_ownership` (0.03 s, no MockProver)

Implements `halo2_proofs::plonk::Assignment<Fp>` as a recorder (regions, cells, selector rows, copies), runs `SimpleFloorPlanner::synthesize` on `SaleCircuit::default()`, then asserts: selector row counts and contiguity; every rotation of every enabled SHA gate is assigned in the same region; no advice cell assigned twice; every SHA advice cell has exactly one owner; the exact multiset of copies touching SHA columns. Output:

```
selector rows: sched_word 0..=15 sched 16..=63 init 64..=67 round 68..=131 digest 132..=139
rotation checks: 23128 (gate,row,cell) triples all assigned in-region
--- ownership table (region, column) -> owner: cell count ---
sha compression        abit[*]  {"q_init": 128, "q_round": 2048}
sha compression        acar     {"q_round": 64}
sha compression        aval     {"q_init+copy": 4, "q_round": 60, "q_round+copy": 4}
sha compression        chc      {"q_round": 64}
sha compression        ebit[*]  {"q_init": 128, "q_round": 2048}
sha compression        ecar     {"q_round": 64}
sha compression        eval     {"q_init+copy": 4, "q_round": 60, "q_round+copy": 4}
sha compression        majc     {"q_round": 64}
sha compression        s0       {"q_round": 64}
sha compression        s1       {"q_round": 64}
sha compression        wc       {"q_round+copy": 64}
sha digest             abit[*]  {"q_digest": 256}
sha digest             acar     {"q_digest": 8}
sha digest             aval     {"q_digest+copy": 8}
sha digest             wc       {"q_digest+copy": 8}
sha message schedule   abit[*]  {"q_sched": 1536, "q_sched_word": 512}
sha message schedule   acar     {"q_sched": 48}
sha message schedule   aval     {"q_sched+copy": 48, "q_sched_word+copy": 16}
sha message schedule   s0       {"q_sched": 48}
sha message schedule   s1       {"q_sched": 48}
--- copy constraints touching SHA columns ---
("aval", "instance"): 8
("aval", "work[2]=k cell"): 8
("constants(fixed)", "aval"): 12
("constants(fixed)", "eval"): 4
("wc", "aval"): 68
("wc", "eval"): 4
region 'key words': rows 0..=63
region 'sha message schedule': rows 0..=63
region 'sha compression': rows 64..=131
region 'sha digest': rows 132..=139
test review_tests::layout_selectors_rotations_and_ownership ... ok
```

### 5.2 `review_tests::compensated_attacks_are_rejected` (21 s, 15 MockProver runs at k = 13)

For each attack the trace is recomputed with the tamper and everything downstream of it, the instance `H` is the forged digest (asserted `!= sha2(key)`), the circuit is run, and the set of MockProver failure kinds is asserted to contain only the one constraint class under test. Result: every attack rejected, every rejection by exactly the expected class. The `S0Shift` case is an ownership probe (the digest is unchanged) and is expected to fail only on the `s0` equation.

```
SELLER: SHA on k' != Poseidon k (W_0 copy): rejected by {"Permutation(Column('Advice', 70))": 1, "Permutation(Column('Advice', 75))": 1}
SELLER: W_7 copy: rejected by {"Permutation(Column('Advice', 70))": 1, "Permutation(Column('Advice', 75))": 1}
C-3: round 20 consumes W_20+1: rejected by {"Permutation(Column('Advice', 64))": 1, "Permutation(Column('Advice', 70))": 1}
C-3: round 3 consumes key word W_3+d: rejected by {"Permutation(Column('Advice', 64))": 1, "Permutation(Column('Advice', 70))": 1}
C-4: digest operand A[63]+1: rejected by {"Permutation(Column('Advice', 64))": 1, "Permutation(Column('Advice', 70))": 1}
C-4: digest operand E[60]+5: rejected by {"Permutation(Column('Advice', 65))": 1, "Permutation(Column('Advice', 70))": 1}
C-2: E[63] shifted, carry solved in field: rejected by {"Constraint 72 in gate 1 ('sha: round')": 1}
C-2: A[63] shifted, carry solved in field: rejected by {"Constraint 73 in gate 1 ('sha: round')": 1}
C-2: A[0] shifted, carry in field: rejected by {"Constraint 73 in gate 1 ('sha: round')": 1}
C-2: W_40 shifted, schedule carry in field: rejected by {"Constraint 36 in gate 3 ('sha: schedule word')": 1}
C-2: H[3] shifted, digest carry in field: rejected by {"Constraint 34 in gate 4 ('sha: digest')": 1}
s0 += 2^32 with acar += 1 (A equation holds): rejected by {"Constraint 66 in gate 1 ('sha: round')": 1}
free-IV: seed d=IV3+1 overwritten after constant copy: rejected by {"Permutation(Column('Advice', 64))": 1, "Permutation(Column('Fixed', 1))": 1}
free-IV: seed a=IV0+2^31: rejected by {"Permutation(Column('Advice', 64))": 1, "Permutation(Column('Fixed', 1))": 1}
test review_tests::compensated_attacks_are_rejected ... ok
```

(Column 70 = `wc`, 64 = `aval`, 65 = `eval`, 75 = `work[2]` = the key-word cell, Fixed 1 = the `constants` column. Constraint 72/73 = `range_poly(ecar,5)` / `range_poly(acar,6)`, 66 = the `s0` equation, 36 = schedule `range_poly(carry,3)`, 34 = digest `carry(carry-1)`.)

Note on method: the copied cell is overwritten *after* `copy_advice`, so the permutation constraint stays in the circuit (as at keygen) and only the value differs. Removing the `copy_advice` call instead would change the circuit and make MockProver accept vacuously, which is the trap checklist item 11 warns about.

### 5.3 Author's suites, re-run in the copy

See the end of this section for the log (`cargo test --release --lib -- --test-threads=1`, `--test mock`, and `--test prove valid_sale_verifies_and_buyer_decrypts_after_payment`).

```
cargo test --release --lib -- --test-threads=1      (copy; includes the two review tests)
  11 passed; 0 failed; finished in 123.73s
  (adversarial: every_sha_constraint_rejects_a_tampered_witness, in_circuit_sha256_equals_sha2_for_many_keys,
   instance_endianness_known_answer_and_negative, round_constants_and_iv_are_the_fips_known_answer,
   selector_enable_counts_match_the_layout; review_tests: both; sha256/suite unit tests)
cargo test --release --test mock -- --test-threads=1
  7 passed; 0 failed; finished in 31.13s
cargo test --release --test prove valid_sale_verifies_and_buyer_decrypts_after_payment -- --test-threads=1
  1 passed; finished in 14.88s   (params from scratch + keygen + create_proof + verify_proof + decrypt)
bash scripts/cli-e2e.sh <scratch>/e2e      (item 15; builds the bin in the copy)
  14/14 cases as expected: honest OK; wrong H / binding / puzzle FAIL; consistent lies (other H,
  other binding, other puzzle) FAIL; tampered C, flipped proof byte, truncated proof FAIL;
  decrypt with k OK and grid equals the solution; decrypt with wrong key exit 2.  real 0m16s
pcp-zk prove (one more run, for item 14):
  params cached 0.135 s / keygen vk+pk 1.378 s, 90.7 MB / prove 7.503 s, peak RSS 570 MB / proof 15936 bytes
```

These agree with `COSTS.md` (7.8 s, 572 MB, 15936 bytes). So item 14 is re-measured after all; the "memory not re-measured" note in section 3 is superseded by this run (`VmHWM` of the CLI process, 570,376 KiB).

### 5.4 Code to add to the repo

Full files are at:
- `/tmp/claude-0/-home-claude/050e7634-91f2-5c3c-9f3e-28ef8a7e1e06/scratchpad/review-crate/src/review_tests.rs` (both tests)
- `/tmp/claude-0/-home-claude/050e7634-91f2-5c3c-9f3e-28ef8a7e1e06/scratchpad/review-crate/src/sha256.rs` (the `Attack` hook, `compute_trace_attacked`, and the post-copy overwrites; diff against the repo with `diff -u /home/claude/somnus/pcp-zk/src/sha256.rs <copy>/src/sha256.rs`)

To integrate: declare `#[cfg(test)] mod review_tests;` in `lib.rs`, make the `ShaConfig` fields, `SaleConfig::{sha, a}` and `Trace` `pub(crate)`, and port the `Attack` hook. The recorder test needs no hook at all and could replace `selector_enable_counts_match_the_layout`.

---

## 6. What I did not check

- halo2_proofs 0.3.5 itself (IPA, permutation argument, selector compression, lookup argument) and halo2_gadgets 0.5.0 Pow5 Poseidon: assumed sound. The Poseidon leg of the statement (`kk`, keystream) and the sudoku gates were read once (they match the previous review's "Verified OK") but were not the focus and got no new tests.
- Zero knowledge: not in scope; the blinding argument is the previous review's.
- Under-constrained-circuit tooling (item 16): not run.
- The per-bit rotation index maps were checked by reading the four `rotr` sets and by the 24-key MockProver agreement with `sha2`; a wrong index at any single bit position would disagree with `sha2` on a random key with probability about 1/2 per round, so 24 keys x 64 rounds makes an undetected error vanishingly unlikely, but this is statistical evidence, not a proof over all 2^32 inputs.
- Completeness over all keys (that an honest prover never fails): the carry `hi` values are the exact maxima, so completeness holds by the same counting as soundness; tested on 24 + 40 keys only.

---

## Appendix A: `src/review_tests.rs` (add to the repo as is)

```rust
//! Independent-review tests for the SHA-256 chip (not part of the repo).
//!
//! 1. `layout_selectors_rotations_and_ownership`: an `Assignment` recorder
//!    (no MockProver) that re-derives the layout, counts selector ROWS (not
//!    `.enable` calls), checks every rotation of every gate against the cells
//!    the same region assigned, enumerates every copy constraint, and prints
//!    the ownership table.
//! 2. `compensated_attacks_are_rejected`: MockProver with a malicious witness
//!    where everything downstream of the tampered cell is recomputed and the
//!    instance H is the forged digest, so only the one constraint under test
//!    can reject. Acceptance = unsound.

use std::collections::{BTreeMap, BTreeSet, HashMap};

use halo2_proofs::{
    circuit::{SimpleFloorPlanner, Value},
    dev::{MockProver, VerifyFailure},
    pasta::Fp,
    plonk::{
        Any, Assigned, Assignment, Circuit, Column, ConstraintSystem, Error, Fixed, FloorPlanner,
        Instance, Selector,
    },
};

use crate::{
    circuit::{SaleCircuit, K},
    sha256::{self, poc_hook, poc_hook::Attack},
    suite, PublicInputs,
};

// ---------------------------------------------------------------------------
// Recorder

#[derive(Default)]
struct Region {
    name: String,
    cells: BTreeSet<(Column<Any>, usize)>,
    selectors: BTreeMap<usize, BTreeSet<usize>>, // selector index -> rows
}

#[derive(Default)]
struct Rec {
    regions: Vec<Region>,
    cur: Option<Region>,
    sel_index: HashMap<Selector, usize>,
    advice_count: HashMap<(Column<Any>, usize), usize>, // (col,row) -> times assigned
    copies: Vec<((Column<Any>, usize), (Column<Any>, usize))>,
}

impl Rec {
    fn sel(&mut self, s: &Selector) -> usize {
        // Selector(index, _) is pub(crate); recover the index from Debug.
        let d = format!("{:?}", s);
        let n: usize = d.trim_start_matches("Selector(").split(',').next().unwrap().parse().unwrap();
        self.sel_index.insert(*s, n);
        n
    }
}

impl Assignment<Fp> for Rec {
    fn enter_region<NR, N>(&mut self, name: N)
    where
        NR: Into<String>,
        N: FnOnce() -> NR,
    {
        assert!(self.cur.is_none());
        self.cur = Some(Region { name: name().into(), ..Default::default() });
    }
    fn exit_region(&mut self) {
        self.regions.push(self.cur.take().unwrap());
    }
    fn enable_selector<A, AR>(&mut self, _: A, s: &Selector, row: usize) -> Result<(), Error>
    where
        A: FnOnce() -> AR,
        AR: Into<String>,
    {
        let i = self.sel(s);
        self.cur.as_mut().unwrap().selectors.entry(i).or_default().insert(row);
        Ok(())
    }
    fn query_instance(&self, _: Column<Instance>, _: usize) -> Result<Value<Fp>, Error> {
        Ok(Value::unknown())
    }
    fn assign_advice<V, VR, A, AR>(
        &mut self,
        _: A,
        column: Column<halo2_proofs::plonk::Advice>,
        row: usize,
        _: V,
    ) -> Result<(), Error>
    where
        V: FnOnce() -> Value<VR>,
        VR: Into<Assigned<Fp>>,
        A: FnOnce() -> AR,
        AR: Into<String>,
    {
        *self.advice_count.entry((column.into(), row)).or_default() += 1;
        if let Some(r) = self.cur.as_mut() {
            r.cells.insert((column.into(), row));
        }
        Ok(())
    }
    fn assign_fixed<V, VR, A, AR>(
        &mut self,
        _: A,
        column: Column<Fixed>,
        row: usize,
        _: V,
    ) -> Result<(), Error>
    where
        V: FnOnce() -> Value<VR>,
        VR: Into<Assigned<Fp>>,
        A: FnOnce() -> AR,
        AR: Into<String>,
    {
        if let Some(r) = self.cur.as_mut() {
            r.cells.insert((column.into(), row));
        }
        Ok(())
    }
    fn copy(&mut self, lc: Column<Any>, lr: usize, rc: Column<Any>, rr: usize) -> Result<(), Error> {
        self.copies.push(((lc, lr), (rc, rr)));
        Ok(())
    }
    fn fill_from_row(&mut self, _: Column<Fixed>, _: usize, _: Value<Assigned<Fp>>) -> Result<(), Error> {
        Ok(())
    }
    fn push_namespace<NR, N>(&mut self, _: N)
    where
        NR: Into<String>,
        N: FnOnce() -> NR,
    {
    }
    fn pop_namespace(&mut self, _: Option<String>) {}
}

fn sample() -> ([u8; 81], [u8; 81]) {
    let p = suite::parse_grid(include_str!("../examples/puzzle.txt")).unwrap();
    let s = suite::parse_grid(include_str!("../examples/solution.txt")).unwrap();
    (p, s)
}

#[test]
fn layout_selectors_rotations_and_ownership() {
    poc_hook::clear();
    let mut cs = ConstraintSystem::<Fp>::default();
    let cfg = SaleCircuit::configure(&mut cs);
    let sha = cfg.sha.clone();
    let mut rec = Rec::default();
    // The real floor planner uses cs.constants[0]; that is the SHA `constants`
    // column (first `enable_constant` call in `configure`).
    SimpleFloorPlanner::synthesize(&mut rec, &SaleCircuit::default(), cfg.clone(), vec![sha.constants])
        .unwrap();

    let sidx = |s: Selector| -> usize {
        let d = format!("{:?}", s);
        d.trim_start_matches("Selector(").split(',').next().unwrap().parse().unwrap()
    };
    let q_init = sidx(sha.q_init);
    let q_round = sidx(sha.q_round);
    let q_sw = sidx(sha.q_sched_word);
    let q_s = sidx(sha.q_sched);
    let q_dig = sidx(sha.q_digest);

    // ---- selector row sets, globally (distinct rows) ----
    let mut rows: BTreeMap<usize, BTreeSet<usize>> = BTreeMap::new();
    for r in &rec.regions {
        for (s, rs) in &r.selectors {
            rows.entry(*s).or_default().extend(rs.iter().copied());
        }
    }
    let count = |s: usize| rows.get(&s).map(|r| r.len()).unwrap_or(0);
    assert_eq!(count(q_init), 4, "q_init rows");
    assert_eq!(count(q_round), 64, "q_round rows");
    assert_eq!(count(q_sw), 16, "q_sched_word rows");
    assert_eq!(count(q_s), 48, "q_sched rows");
    assert_eq!(count(q_dig), 8, "q_digest rows");
    // contiguity and ordering
    let contiguous = |s: usize| {
        let r = &rows[&s];
        let (a, b) = (*r.iter().next().unwrap(), *r.iter().last().unwrap());
        assert_eq!(b - a + 1, r.len(), "selector {s} rows not contiguous");
        (a, b)
    };
    let (sw0, sw1) = contiguous(q_sw);
    let (s0, s1) = contiguous(q_s);
    let (i0, i1) = contiguous(q_init);
    let (r0, r1) = contiguous(q_round);
    let (d0, d1) = contiguous(q_dig);
    assert_eq!(s0, sw1 + 1, "q_sched follows q_sched_word");
    assert_eq!(r0, i1 + 1, "q_round follows q_init");
    println!("selector rows: sched_word {sw0}..={sw1} sched {s0}..={s1} init {i0}..={i1} round {r0}..={r1} digest {d0}..={d1}");
    // No selector row shared between two SHA selectors.
    for (a, b) in [(q_init, q_round), (q_sw, q_s), (q_init, q_sw), (q_round, q_s), (q_dig, q_round), (q_dig, q_s)] {
        assert!(rows[&a].is_disjoint(&rows[&b]));
    }

    // ---- per-gate rotation sets (transcribed from ShaChip::configure) ----
    let adv = |c: Column<halo2_proofs::plonk::Advice>| -> Column<Any> { c.into() };
    let fix = |c: Column<Fixed>| -> Column<Any> { c.into() };
    let mut gates: Vec<(&str, usize, Vec<(Column<Any>, i32)>)> = Vec::new();
    {
        let mut v = Vec::new();
        for i in 0..32 {
            v.push((adv(sha.abit[i]), 0));
            v.push((adv(sha.ebit[i]), 0));
        }
        v.push((adv(sha.aval), 0));
        v.push((adv(sha.eval), 0));
        gates.push(("iv seed", q_init, v));
    }
    {
        let mut v = Vec::new();
        for i in 0..32 {
            for rot in [0, -1, -2, -3] {
                v.push((adv(sha.abit[i]), rot));
                v.push((adv(sha.ebit[i]), rot));
            }
        }
        for c in [sha.aval, sha.eval] {
            v.push((adv(c), 0));
            v.push((adv(c), -4));
        }
        for c in [sha.s0, sha.s1, sha.chc, sha.majc, sha.wc, sha.ecar, sha.acar] {
            v.push((adv(c), 0));
        }
        v.push((fix(sha.kcol), 0));
        gates.push(("round", q_round, v));
    }
    {
        let mut v = Vec::new();
        for i in 0..32 {
            v.push((adv(sha.abit[i]), 0));
        }
        v.push((adv(sha.aval), 0));
        gates.push(("schedule given", q_sw, v));
    }
    {
        let mut v = Vec::new();
        for i in 0..32 {
            for rot in [0, -15, -2] {
                v.push((adv(sha.abit[i]), rot));
            }
        }
        for rot in [0, -16, -7] {
            v.push((adv(sha.aval), rot));
        }
        for c in [sha.s0, sha.s1, sha.acar] {
            v.push((adv(c), 0));
        }
        gates.push(("schedule word", q_s, v));
    }
    {
        let mut v = Vec::new();
        for i in 0..32 {
            v.push((adv(sha.abit[i]), 0));
        }
        for c in [sha.aval, sha.wc, sha.acar] {
            v.push((adv(c), 0));
        }
        v.push((fix(sha.kcol), 0));
        gates.push(("digest", q_dig, v));
    }

    // ---- every rotation of every enabled gate lands on a cell assigned by
    //      the SAME region (items 1 and 3) ----
    let mut checked = 0usize;
    for r in &rec.regions {
        for (gname, s, cells) in &gates {
            if let Some(srows) = r.selectors.get(s) {
                let first = *r.cells.iter().map(|(_, row)| row).min().unwrap();
                for &row in srows {
                    for (col, rot) in cells {
                        let target = row as i64 + *rot as i64;
                        assert!(target >= first as i64, "gate {gname} at row {row} reaches above region '{}' (first row {first})", r.name);
                        assert!(r.cells.contains(&(*col, target as usize)), "gate {gname} at row {row}: {:?}@{rot} (row {target}) not assigned in region '{}'", col, r.name);
                        checked += 1;
                    }
                }
            }
        }
    }
    println!("rotation checks: {checked} (gate,row,cell) triples all assigned in-region");

    // ---- no advice cell assigned twice (item 12) ----
    let dups: Vec<_> = rec.advice_count.iter().filter(|(_, n)| **n > 1).collect();
    assert!(dups.is_empty(), "cells assigned more than once: {dups:?}");

    // ---- ownership table: every assigned SHA advice cell has a gate at
    //      rotation 0 that constrains it (bool/pack/equation/range) or is a
    //      copy endpoint (wc). ----
    let sha_cols: Vec<(String, Column<Any>)> = {
        let mut v = Vec::new();
        for i in 0..32 {
            v.push((format!("abit[{i}]"), adv(sha.abit[i])));
        }
        for i in 0..32 {
            v.push((format!("ebit[{i}]"), adv(sha.ebit[i])));
        }
        for (n, c) in [("aval", sha.aval), ("eval", sha.eval), ("s0", sha.s0), ("s1", sha.s1), ("chc", sha.chc), ("majc", sha.majc), ("wc", sha.wc), ("acar", sha.acar), ("ecar", sha.ecar)] {
            v.push((n.to_string(), adv(c)));
        }
        v
    };
    // owner selectors per column
    let owners: HashMap<Column<Any>, Vec<usize>> = sha_cols
        .iter()
        .map(|(n, c)| {
            let v = if n.starts_with("abit") {
                vec![q_init, q_round, q_sw, q_s, q_dig]
            } else if n.starts_with("ebit") || n == "eval" || n == "ecar" || n == "chc" || n == "majc" {
                if n.starts_with("ebit") || n == "eval" { vec![q_init, q_round] } else { vec![q_round] }
            } else if n == "aval" {
                vec![q_init, q_round, q_sw, q_s, q_dig]
            } else if n == "s0" || n == "s1" {
                vec![q_round, q_s]
            } else if n == "acar" {
                vec![q_round, q_s, q_dig]
            } else if n == "wc" {
                vec![q_round, q_dig]
            } else {
                unreachable!()
            };
            (*c, v)
        })
        .collect();
    let copy_endpoints: BTreeSet<(Column<Any>, usize)> =
        rec.copies.iter().flat_map(|(a, b)| [*a, *b]).collect();
    let mut table: BTreeMap<(String, String), BTreeMap<String, usize>> = BTreeMap::new();
    let selname = |s: usize| -> &'static str {
        if s == q_init { "q_init" } else if s == q_round { "q_round" } else if s == q_sw { "q_sched_word" } else if s == q_s { "q_sched" } else if s == q_dig { "q_digest" } else { "OTHER" }
    };
    for r in &rec.regions {
        for (n, c) in &sha_cols {
            for (col, row) in r.cells.iter().filter(|(col, _)| col == c) {
                let own: Vec<usize> = owners[c].iter().copied().filter(|s| r.selectors.get(s).map(|rs| rs.contains(row)).unwrap_or(false)).collect();
                assert!(own.len() == 1, "cell {n}@{row} in '{}' has {} owning gates: {:?}", r.name, own.len(), own);
                let is_copy = copy_endpoints.contains(&(*col, *row));
                if n == "wc" {
                    assert!(is_copy, "wc@{row} must be a copy endpoint");
                }
                let kind = format!("{}{}", selname(own[0]), if is_copy { "+copy" } else { "" });
                let key = (r.name.clone(), if n.starts_with("abit") { "abit[*]".into() } else if n.starts_with("ebit") { "ebit[*]".into() } else { n.clone() });
                *table.entry(key).or_default().entry(kind).or_default() += 1;
            }
        }
    }
    println!("--- ownership table (region, column) -> owner: cell count ---");
    for ((reg, col), kinds) in &table {
        println!("{reg:22} {col:8} {:?}", kinds);
    }

    // ---- copies: classify every copy constraint touching a SHA column ----
    let name_of = |c: &Column<Any>| -> String {
        for (n, cc) in &sha_cols {
            if cc == c {
                return n.clone();
            }
        }
        if *c == fix(sha.constants) {
            return "constants(fixed)".into();
        }
        if c.column_type() == &Any::Instance {
            return "instance".into();
        }
        if *c == adv(cfg.a[2]) {
            return "work[2]=k cell".into();
        }
        format!("{:?}", c)
    };
    let mut classes: BTreeMap<(String, String), usize> = BTreeMap::new();
    for (a, b) in &rec.copies {
        let touches = sha_cols.iter().any(|(_, c)| c == &a.0 || c == &b.0);
        if touches {
            *classes.entry((name_of(&a.0), name_of(&b.0))).or_default() += 1;
        }
    }
    println!("--- copy constraints touching SHA columns ---");
    for (k, n) in &classes {
        println!("{:?}: {n}", k);
    }
    let get = |x: &str, y: &str| classes.get(&(x.to_string(), y.to_string())).copied().unwrap_or(0) + classes.get(&(y.to_string(), x.to_string())).copied().unwrap_or(0);
    assert_eq!(get("work[2]=k cell", "aval"), 8, "key -> W_0..7");
    assert_eq!(get("constants(fixed)", "aval"), 12, "padding (8) + A seed (4)");
    assert_eq!(get("constants(fixed)", "eval"), 4, "E seed");
    assert_eq!(get("aval", "wc"), 68, "W_t -> round (64) + A[63..60] -> digest (4)");
    assert_eq!(get("eval", "wc"), 4, "E[63..60] -> digest");
    assert_eq!(get("aval", "instance"), 8, "digest -> H");
    let total: usize = classes.values().sum();
    assert_eq!(total, 8 + 12 + 4 + 68 + 4 + 8, "no other copy touches a SHA column");

    // Region row ranges for the report.
    for r in &rec.regions {
        if r.name.starts_with("sha") || r.name == "key words" {
            let lo = r.cells.iter().map(|(_, row)| *row).min().unwrap();
            let hi = r.cells.iter().map(|(_, row)| *row).max().unwrap();
            println!("region '{}': rows {lo}..={hi}", r.name);
        }
    }
}

// ---------------------------------------------------------------------------
// Compensated attacks

fn key_words(key: &[u8; 32]) -> [u32; 8] {
    core::array::from_fn(|i| u32::from_be_bytes(key[4 * i..4 * i + 4].try_into().unwrap()))
}

fn classify(fails: &[VerifyFailure]) -> BTreeMap<String, usize> {
    let mut m = BTreeMap::new();
    for f in fails {
        let k = match f {
            VerifyFailure::Permutation { column, .. } => format!("Permutation({column})"),
            VerifyFailure::ConstraintNotSatisfied { constraint, .. } => format!("{constraint}"),
            VerifyFailure::CellNotAssigned { .. } => "CellNotAssigned".into(),
            VerifyFailure::InstanceCellNotAssigned { .. } => "InstanceCellNotAssigned".into(),
            VerifyFailure::ConstraintPoisoned { .. } => "ConstraintPoisoned".into(),
            VerifyFailure::Lookup { .. } => "Lookup".into(),
        };
        *m.entry(k).or_default() += 1;
    }
    m
}

#[test]
fn compensated_attacks_are_rejected() {
    use sha2::{Digest, Sha256};
    let (p, s) = sample();
    let key = [0x11u8; 32];
    let kw = key_words(&key);
    let honest: [u8; 32] = Sha256::digest(key).into();

    // (attack, name, the only failure kinds allowed, as substrings of the Display form)
    let cases: Vec<(Attack, &str, Vec<&str>)> = vec![
        (Attack::KeyWord { i: 0, delta: 1 }, "SELLER: SHA on k' != Poseidon k (W_0 copy)", vec!["Permutation"]),
        (Attack::KeyWord { i: 7, delta: 0x8000_0000 }, "SELLER: W_7 copy", vec!["Permutation"]),
        (Attack::RoundW { t: 20, delta: 1 }, "C-3: round 20 consumes W_20+1", vec!["Permutation"]),
        (Attack::RoundW { t: 3, delta: 0xffff }, "C-3: round 3 consumes key word W_3+d", vec!["Permutation"]),
        (Attack::DigestOperand { m: 0, delta: 1 }, "C-4: digest operand A[63]+1", vec!["Permutation"]),
        (Attack::DigestOperand { m: 7, delta: 5 }, "C-4: digest operand E[60]+5", vec!["Permutation"]),
        (Attack::RoundEFieldCarry { t: 63, delta: 1 }, "C-2: E[63] shifted, carry solved in field", vec!["Constraint 72 in gate 1"]),
        (Attack::RoundAFieldCarry { t: 63, delta: 1 }, "C-2: A[63] shifted, carry solved in field", vec!["Constraint 73 in gate 1"]),
        (Attack::RoundAFieldCarry { t: 0, delta: 0x1234 }, "C-2: A[0] shifted, carry in field", vec!["Constraint 73 in gate 1"]),
        (Attack::SchedFieldCarry { i: 40, delta: 1 }, "C-2: W_40 shifted, schedule carry in field", vec!["Constraint 36 in gate 3"]),
        (Attack::DigestFieldCarry { m: 3, delta: 1 }, "C-2: H[3] shifted, digest carry in field", vec!["Constraint 34 in gate 4"]),
        (Attack::S0Shift { t: 10 }, "s0 += 2^32 with acar += 1 (A equation holds)", vec!["Constraint 66 in gate 1", "Constraint 73 in gate 1"]),
        (Attack::SeedA { r: 0, delta: 1 }, "free-IV: seed d=IV3+1 overwritten after constant copy", vec!["Permutation"]),
        (Attack::SeedA { r: 3, delta: 0x8000_0000 }, "free-IV: seed a=IV0+2^31", vec!["Permutation"]),
    ];

    poc_hook::clear();
    let base = PublicInputs {
        givens: p,
        ciphertext: suite::encrypt(&s, &key),
        payment_hash: honest,
        binding: [0x22; 32],
    };
    assert!(MockProver::run(K, &SaleCircuit::new(s, key), vec![base.instance()]).unwrap().verify().is_ok());

    let mut report = String::new();
    for (atk, name, expect) in cases {
        // forged digest = what the attacked trace produces
        let tr = sha256::compute_trace_attacked(kw, atk);
        let mut forged = [0u8; 32];
        for m in 0..8 {
            forged[4 * m..4 * m + 4].copy_from_slice(&tr.digest[m].to_be_bytes());
        }
        if matches!(atk, Attack::S0Shift { .. }) {
            // ownership probe, not a forgery: the digest is unchanged
            assert_eq!(forged, honest);
        } else {
            assert_ne!(forged, honest, "{name}: attack must change the digest to be meaningful");
        }
        let public = PublicInputs { payment_hash: forged, ..base.clone() };
        poc_hook::set_attack(atk);
        let res = MockProver::run(K, &SaleCircuit::new(s, key), vec![public.instance()]).unwrap().verify();
        poc_hook::clear();
        match res {
            Ok(()) => panic!("CRITICAL: attack '{name}' ({atk:?}) ACCEPTED with H != SHA256(k)"),
            Err(fails) => {
                let c = classify(&fails);
                report.push_str(&format!("{name}: rejected by {:?}\n", c));
                for k in c.keys() {
                    assert!(expect.iter().any(|e| k.contains(e)), "{name}: unexpected failure kind {k} (expected only {expect:?}); all: {c:?}");
                }
            }
        }
    }
    println!("--- compensated attacks ---\n{report}");
}
```

## Appendix B: diff of `src/sha256.rs`, `src/circuit.rs`, `src/lib.rs` for the `Attack` hook (test-only semantics; `configure` untouched)

```diff
--- /home/claude/somnus/pcp-zk/src/sha256.rs	2026-10-21 08:50:05.829320015 +0700
+++ review-crate/src/sha256.rs	2026-10-21 09:32:21.634669405 +0700
@@ -60,6 +60,7 @@
 //! column (part of the verifying key, not prover advice). The IV seed words
 //! and the padding words are pinned with `assign_advice_from_constant`.
 
+use ff::Field as _ReviewField;
 use halo2_proofs::{
     circuit::{AssignedCell, Layouter, Value},
     pasta::Fp,
@@ -184,6 +185,59 @@
     #[cfg(test)]
     pub fn clear() {
         TAMPER.with(|c| c.set((TAG_NONE, 0, Tamper::None)));
+        ATTACK.with(|c| c.set(Attack::None));
+    }
+
+    // ---- REVIEW ADDITION: compensated attacks -------------------------------
+    // Unlike `Tamper`, an `Attack` recomputes the whole trace downstream of the
+    // tampered cell, so every gate except the one under test is satisfied and
+    // the instance H is set to the forged digest. If MockProver accepts, the
+    // chip is unsound.
+    #[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
+    pub enum Attack {
+        #[default]
+        None,
+        /// Round `t` consumes `W_t + delta` (the `wc` cell is overwritten after
+        /// `copy_advice`); the schedule cell keeps the honest W_t. C-3 class.
+        RoundW { t: usize, delta: u32 },
+        /// Digest row `m` consumes `operand + delta` (overwritten after copy).
+        /// C-4 class.
+        DigestOperand { m: usize, delta: u32 },
+        /// `E[t] := E[t] + delta` with the E carry solved in the field. C-2.
+        RoundEFieldCarry { t: usize, delta: u32 },
+        /// `A[t] := A[t] + delta` with the A carry solved in the field. C-2.
+        RoundAFieldCarry { t: usize, delta: u32 },
+        /// `W_i := W_i + delta` (i >= 16) with the schedule carry in the field.
+        SchedFieldCarry { i: usize, delta: u32 },
+        /// `H[m] := H[m] + delta` with the digest carry in the field.
+        DigestFieldCarry { m: usize, delta: u32 },
+        /// `s0 += 2^32`, `acar += 1` at round t: the A equation still holds.
+        S0Shift { t: usize },
+        /// Seed row r: `aval` overwritten (after the constant copy) with
+        /// `IV + delta`, bits consistent, trace propagated. Free-IV class.
+        SeedA { r: usize, delta: u32 },
+        /// Schedule row i < 8: `aval` overwritten (after the key copy) with
+        /// `k_i + delta`; SHA runs on the forged key, Poseidon on the real one.
+        /// This is the seller attack: H != SHA256(k).
+        KeyWord { i: usize, delta: u32 },
+    }
+
+    #[cfg(test)]
+    thread_local! {
+        static ATTACK: std::cell::Cell<Attack> = const { std::cell::Cell::new(Attack::None) };
+    }
+    #[cfg(test)]
+    pub fn attack() -> Attack {
+        ATTACK.with(|c| c.get())
+    }
+    #[cfg(not(test))]
+    #[inline(always)]
+    pub fn attack() -> Attack {
+        Attack::None
+    }
+    #[cfg(test)]
+    pub fn set_attack(a: Attack) {
+        ATTACK.with(|c| c.set(a));
     }
 }
 
@@ -217,7 +271,7 @@
 /// assignment is a direct table lookup. `w[0..8]` are filled by the caller
 /// from the key; the rest is derived.
 #[derive(Clone, Debug)]
-struct Trace {
+pub(crate) struct Trace {
     w: [u32; 64],
     wcar: [u64; 64],   // schedule carries (only 16..64 meaningful)
     a_seq: [u32; 68],  // row r holds A[r-4]; rows 0..4 are the IV seed
@@ -228,13 +282,31 @@
     majv: [u32; 68],   // Maj(A[t-1],A[t-2],A[t-3])
     acar: [u64; 68],   // A[t] carry
     ecar: [u64; 68],   // E[t] carry
-    digest: [u32; 8],
+    pub(crate) digest: [u32; 8],
     digest_car: [u64; 8],
+    // REVIEW ADDITION (attack bookkeeping; honest values when no attack):
+    w_in: [u32; 64],       // the W consumed by round t (== w[t] honestly)
+    operand: [u32; 8],     // the operand consumed by digest row m
+    carry_fp: Option<(u32, u32, Fp)>, // (tag, index, field value) carry override
+    s0_shift_row: Option<usize>,      // row where s0 += 2^32 and acar += 1
+}
+
+fn inv232() -> Fp {
+    Fp::from(1u64 << 32).invert().unwrap()
 }
 
 fn compute_trace(key_words: [u32; 8]) -> Trace {
+    compute_trace_attacked(key_words, poc_hook::Attack::None)
+}
+
+pub(crate) fn compute_trace_attacked(key_words: [u32; 8], atk: poc_hook::Attack) -> Trace {
+    use poc_hook::Attack;
+    let mut carry_fp = None;
     let mut w = [0u32; 64];
     w[..8].copy_from_slice(&key_words);
+    if let Attack::KeyWord { i, delta } = atk {
+        w[i] = w[i].wrapping_add(delta);
+    }
     w[8..16].copy_from_slice(&PADDING);
     let mut wcar = [0u64; 64];
     for i in 16..64 {
@@ -243,7 +315,23 @@
         let sum = w[i - 16] as u64 + w[i - 7] as u64 + s0 as u64 + s1 as u64;
         w[i] = sum as u32;
         wcar[i] = sum >> 32;
+        if let Attack::SchedFieldCarry { i: ai, delta } = atk {
+            if ai == i {
+                let forged = w[i].wrapping_add(delta);
+                w[i] = forged;
+                carry_fp = Some((
+                    poc_hook::TAG_SCHED_CARRY,
+                    i as u32,
+                    (Fp::from(sum) - Fp::from(forged as u64)) * inv232(),
+                ));
+            }
+        }
+    }
+    let mut w_in = w;
+    if let Attack::RoundW { t, delta } = atk {
+        w_in[t] = w[t].wrapping_add(delta);
     }
+    let mut s0_shift_row = None;
 
     // Seed: row0=A[-4]=d=IV3, row1=A[-3]=IV2, row2=A[-2]=IV1, row3=A[-1]=a=IV0.
     let mut a_seq = [0u32; 68];
@@ -256,6 +344,9 @@
     e_seq[1] = IV[6];
     e_seq[2] = IV[5];
     e_seq[3] = IV[4];
+    if let Attack::SeedA { r, delta } = atk {
+        a_seq[r] = a_seq[r].wrapping_add(delta);
+    }
 
     let mut s0 = [0u32; 68];
     let mut s1 = [0u32; 68];
@@ -287,19 +378,46 @@
             + s1v as u64
             + chvv as u64
             + ROUND_CONSTANTS[t] as u64
-            + w[t] as u64;
+            + w_in[t] as u64;
         e_seq[r] = sum_e as u32;
         ecar[r] = sum_e >> 32;
+        if let Attack::RoundEFieldCarry { t: at, delta } = atk {
+            if at == t {
+                let forged = e_seq[r].wrapping_add(delta);
+                e_seq[r] = forged;
+                carry_fp = Some((
+                    poc_hook::TAG_ROUND_ECAR,
+                    t as u32,
+                    (Fp::from(sum_e) - Fp::from(forged as u64)) * inv232(),
+                ));
+            }
+        }
         // A[t] = h + Sigma1 + Ch + K + W + Sigma0 + Maj
         let sum_a = e4 as u64
             + s1v as u64
             + chvv as u64
             + ROUND_CONSTANTS[t] as u64
-            + w[t] as u64
+            + w_in[t] as u64
             + s0v as u64
             + majvv as u64;
         a_seq[r] = sum_a as u32;
         acar[r] = sum_a >> 32;
+        if let Attack::RoundAFieldCarry { t: at, delta } = atk {
+            if at == t {
+                let forged = a_seq[r].wrapping_add(delta);
+                a_seq[r] = forged;
+                carry_fp = Some((
+                    poc_hook::TAG_ROUND_ACAR,
+                    t as u32,
+                    (Fp::from(sum_a) - Fp::from(forged as u64)) * inv232(),
+                ));
+            }
+        }
+        if let Attack::S0Shift { t: at } = atk {
+            if at == t {
+                s0_shift_row = Some(r);
+            }
+        }
     }
 
     // Digest: H = final working vars + IV.
@@ -307,15 +425,34 @@
     let final_words = [
         a_seq[67], a_seq[66], a_seq[65], a_seq[64], e_seq[67], e_seq[66], e_seq[65], e_seq[64],
     ];
+    let mut operand = final_words;
+    if let Attack::DigestOperand { m, delta } = atk {
+        operand[m] = operand[m].wrapping_add(delta);
+    }
     let mut digest = [0u32; 8];
     let mut digest_car = [0u64; 8];
     for m in 0..8 {
-        let sum = final_words[m] as u64 + IV[m] as u64;
+        let sum = operand[m] as u64 + IV[m] as u64;
         digest[m] = sum as u32;
         digest_car[m] = sum >> 32;
+        if let Attack::DigestFieldCarry { m: am, delta } = atk {
+            if am == m {
+                let forged = digest[m].wrapping_add(delta);
+                digest[m] = forged;
+                carry_fp = Some((
+                    poc_hook::TAG_DIGEST_CARRY,
+                    m as u32,
+                    (Fp::from(sum) - Fp::from(forged as u64)) * inv232(),
+                ));
+            }
+        }
     }
 
     Trace {
+        w_in,
+        operand,
+        carry_fp,
+        s0_shift_row,
         w,
         wcar,
         a_seq,
@@ -376,42 +513,42 @@
 #[derive(Clone, Debug)]
 pub struct ShaConfig {
     /// A bits (compression) / W bits (schedule). Little-endian, one col per bit.
-    abit: [Column<Advice>; 32],
+    pub(crate) abit: [Column<Advice>; 32],
     /// E bits (compression only).
-    ebit: [Column<Advice>; 32],
+    pub(crate) ebit: [Column<Advice>; 32],
     /// A packed (compression) / W packed (schedule). Equality-enabled.
-    aval: Column<Advice>,
+    pub(crate) aval: Column<Advice>,
     /// E packed (compression). Equality-enabled.
-    eval: Column<Advice>,
+    pub(crate) eval: Column<Advice>,
     /// Sigma0 / lower-sigma0 packed.
-    s0: Column<Advice>,
+    pub(crate) s0: Column<Advice>,
     /// Sigma1 / lower-sigma1 packed.
-    s1: Column<Advice>,
+    pub(crate) s1: Column<Advice>,
     /// Ch packed.
-    chc: Column<Advice>,
+    pub(crate) chc: Column<Advice>,
     /// Maj packed.
-    majc: Column<Advice>,
+    pub(crate) majc: Column<Advice>,
     /// Message word copied into a round (and operand copied into a digest row).
     /// Equality-enabled.
-    wc: Column<Advice>,
+    pub(crate) wc: Column<Advice>,
     /// A-side carry (compression) / schedule carry / digest carry.
-    acar: Column<Advice>,
+    pub(crate) acar: Column<Advice>,
     /// E-side carry (compression).
-    ecar: Column<Advice>,
+    pub(crate) ecar: Column<Advice>,
     /// Round constant `K_t` (rounds) / IV addend (digest). Fixed.
-    kcol: Column<Fixed>,
+    pub(crate) kcol: Column<Fixed>,
     /// A fixed column enabled for constants (IV seed, padding words).
     #[allow(dead_code)]
-    constants: Column<Fixed>,
+    pub(crate) constants: Column<Fixed>,
     /// Advice columns exposed for the parent circuit to reuse for Poseidon and
     /// the sudoku gates (disjoint rows; every gate is selector-guarded).
     pub work: [Column<Advice>; 5],
 
-    q_init: Selector,          // IV seed rows: booleanity + pack
-    q_round: Selector,         // compression rounds
-    q_sched_word: Selector,    // schedule given words W_0..W_15: booleanity + pack
-    q_sched: Selector,         // schedule computed words W_16..W_63
-    q_digest: Selector,        // feed-forward + output
+    pub(crate) q_init: Selector,          // IV seed rows: booleanity + pack
+    pub(crate) q_round: Selector,         // compression rounds
+    pub(crate) q_sched_word: Selector,    // schedule given words W_0..W_15: booleanity + pack
+    pub(crate) q_sched: Selector,         // schedule computed words W_16..W_63
+    pub(crate) q_digest: Selector,        // feed-forward + output
 }
 
 /// The auditable SHA-256 chip.
@@ -723,7 +860,8 @@
             }
             acc
         };
-        let trace: Value<Trace> = kw.map(compute_trace);
+        let atk = poc_hook::attack();
+        let trace: Value<Trace> = kw.map(move |k| compute_trace_attacked(k, atk));
 
         // ---- message schedule ----
         let w_cells = layouter.assign_region(
@@ -737,7 +875,15 @@
 
                     if i < 8 {
                         // W_i = key word: copy the caller's cell into `aval`.
-                        let cell = key_cells[i].copy_advice(|| "W=key", &mut region, cfg.aval, i)?;
+                        let mut cell = key_cells[i].copy_advice(|| "W=key", &mut region, cfg.aval, i)?;
+                        if let poc_hook::Attack::KeyWord { i: ai, .. } = atk {
+                            if ai == i {
+                                // REVIEW ATTACK: overwrite the copied cell's value.
+                                cell = region.assign_advice(|| "ATTACK key", cfg.aval, i, || {
+                                    trace.clone().map(|t| Fp::from(t.w[i] as u64))
+                                })?;
+                            }
+                        }
                         cfg.q_sched_word.enable(&mut region, i)?;
                         poc_hook::count(poc_hook::SEL_SCHED_WORD);
                         w_cells.push(cell);
@@ -765,7 +911,7 @@
                             &mut region,
                             cfg.acar,
                             i,
-                            trace.clone().map(|t| t.wcar[i]),
+                            trace.clone().map(|t| t.carry(poc_hook::TAG_SCHED_CARRY, i as u32, t.wcar[i])),
                             poc_hook::TAG_SCHED_CARRY,
                             i as u32,
                         )?;
@@ -794,10 +940,18 @@
                 for r in 0..4usize {
                     cfg.q_init.enable(&mut region, r)?;
                     poc_hook::count(poc_hook::SEL_INIT);
-                    assign_bits(&mut region, &cfg.abit, r, Value::known(a_seed[r]), poc_hook::TAG_SEED_A, r as u32)?;
+                    assign_bits(&mut region, &cfg.abit, r, trace.clone().map(|t| t.a_seq[r]), poc_hook::TAG_SEED_A, r as u32)?;
                     assign_bits(&mut region, &cfg.ebit, r, Value::known(e_seed[r]), poc_hook::TAG_SEED_E, r as u32)?;
                     region.assign_advice_from_constant(|| "A seed", cfg.aval, r, Fp::from(a_seed[r] as u64))?;
                     region.assign_advice_from_constant(|| "E seed", cfg.eval, r, Fp::from(e_seed[r] as u64))?;
+                    if let poc_hook::Attack::SeedA { r: ar, .. } = atk {
+                        if ar == r {
+                            // REVIEW ATTACK: overwrite the constant-copied cell's value.
+                            region.assign_advice(|| "ATTACK seed", cfg.aval, r, || {
+                                trace.clone().map(|t| Fp::from(t.a_seq[r] as u64))
+                            })?;
+                        }
+                    }
                 }
                 // Round cells, indexed by `t` in 0..64 (A[t] at a_cells[t]).
                 let mut a_cells: Vec<Cell> = Vec::with_capacity(64);
@@ -807,7 +961,10 @@
                     cfg.q_round.enable(&mut region, r)?;
                     poc_hook::count(poc_hook::SEL_ROUND);
                     // intermediates
-                    region.assign_advice(|| "s0", cfg.s0, r, || trace.clone().map(|tr| Fp::from(tr.s0[r] as u64)))?;
+                    region.assign_advice(|| "s0", cfg.s0, r, || trace.clone().map(|tr| {
+                        let shift = if tr.s0_shift_row == Some(r) { Fp::from(1u64 << 32) } else { Fp::zero() };
+                        Fp::from(tr.s0[r] as u64) + shift
+                    }))?;
                     region.assign_advice(|| "s1", cfg.s1, r, || trace.clone().map(|tr| Fp::from(tr.s1[r] as u64)))?;
                     region.assign_advice(|| "ch", cfg.chc, r, || trace.clone().map(|tr| Fp::from(tr.chv[r] as u64)))?;
                     region.assign_advice(|| "maj", cfg.majc, r, || trace.clone().map(|tr| Fp::from(tr.majv[r] as u64)))?;
@@ -816,9 +973,20 @@
                     region.assign_fixed(|| "K", cfg.kcol, r, || Value::known(Fp::from(ROUND_CONSTANTS[t] as u64)))?;
                     // W_t copied in
                     w_cells[t].copy_advice(|| "W", &mut region, cfg.wc, r)?;
+                    if let poc_hook::Attack::RoundW { t: at, .. } = atk {
+                        if at == t {
+                            // REVIEW ATTACK: overwrite the copied W_t value.
+                            region.assign_advice(|| "ATTACK wc", cfg.wc, r, || {
+                                trace.clone().map(|tr| Fp::from(tr.w_in[t] as u64))
+                            })?;
+                        }
+                    }
                     // carries
-                    assign_carry(&mut region, cfg.ecar, r, trace.clone().map(|tr| tr.ecar[r]), poc_hook::TAG_ROUND_ECAR, t as u32)?;
-                    assign_carry(&mut region, cfg.acar, r, trace.clone().map(|tr| tr.acar[r]), poc_hook::TAG_ROUND_ACAR, t as u32)?;
+                    assign_carry(&mut region, cfg.ecar, r, trace.clone().map(|tr| tr.carry(poc_hook::TAG_ROUND_ECAR, t as u32, tr.ecar[r])), poc_hook::TAG_ROUND_ECAR, t as u32)?;
+                    assign_carry(&mut region, cfg.acar, r, trace.clone().map(|tr| {
+                        let extra = if tr.s0_shift_row == Some(r) { 1 } else { 0 };
+                        tr.carry(poc_hook::TAG_ROUND_ACAR, t as u32, tr.acar[r] + extra)
+                    }), poc_hook::TAG_ROUND_ACAR, t as u32)?;
                     // A[t], E[t] words + bits
                     let av: Value<u32> = trace.clone().map(|tr| tr.a_seq[r]);
                     let ev: Value<u32> = trace.clone().map(|tr| tr.e_seq[r]);
@@ -853,8 +1021,16 @@
                     cfg.q_digest.enable(&mut region, m)?;
                     poc_hook::count(poc_hook::SEL_DIGEST);
                     operands[m].copy_advice(|| "operand", &mut region, cfg.wc, m)?;
+                    if let poc_hook::Attack::DigestOperand { m: am, .. } = atk {
+                        if am == m {
+                            // REVIEW ATTACK: overwrite the copied operand value.
+                            region.assign_advice(|| "ATTACK operand", cfg.wc, m, || {
+                                trace.clone().map(|t| Fp::from(t.operand[m] as u64))
+                            })?;
+                        }
+                    }
                     region.assign_fixed(|| "IV", cfg.kcol, m, || Value::known(Fp::from(IV[m] as u64)))?;
-                    assign_carry(&mut region, cfg.acar, m, trace.clone().map(|t| t.digest_car[m]), poc_hook::TAG_DIGEST_CARRY, m as u32)?;
+                    assign_carry(&mut region, cfg.acar, m, trace.clone().map(|t| t.carry(poc_hook::TAG_DIGEST_CARRY, m as u32, t.digest_car[m])), poc_hook::TAG_DIGEST_CARRY, m as u32)?;
                     let hv: Value<u32> = trace.clone().map(|t| t.digest[m]);
                     assign_bits(&mut region, &cfg.abit, m, hv, poc_hook::TAG_DIGEST, m as u32)?;
                     let cell = assign_val(&mut region, cfg.aval, m, hv, poc_hook::TAG_DIGEST, m as u32)?;
@@ -878,13 +1054,24 @@
         _ => x,
     }
 }
-fn tamper_carry(c: u64, tag: u32, index: u32) -> u64 {
+fn tamper_carry(c: Fp, tag: u32, index: u32) -> Fp {
     match poc_hook::get(tag, index) {
-        poc_hook::Tamper::CarryDelta(d) => c.wrapping_add(d),
+        poc_hook::Tamper::CarryDelta(d) => c + Fp::from(d),
         _ => c,
     }
 }
 
+impl Trace {
+    /// The carry to assign: the attack's field override if it targets this
+    /// (tag, index), else the honest integer carry.
+    fn carry(&self, tag: u32, index: u32, honest: u64) -> Fp {
+        match self.carry_fp {
+            Some((t, i, v)) if t == tag && i == index => v,
+            _ => Fp::from(honest),
+        }
+    }
+}
+
 /// The 32 bit-cell field values for `word` at `offset`, honouring a tamper:
 /// `WordDelta` shifts the whole word before decomposing (bits stay boolean and
 /// consistent with the shifted word), while `Bit` overrides one bit cell with
@@ -925,12 +1112,12 @@
     region: &mut halo2_proofs::circuit::Region<'_, Fp>,
     col: Column<Advice>,
     offset: usize,
-    carry: Value<u64>,
+    carry: Value<Fp>,
     tag: u32,
     index: u32,
 ) -> Result<(), Error> {
     region.assign_advice(|| "carry", col, offset, || {
-        carry.map(|c| Fp::from(tamper_carry(c, tag, index)))
+        carry.map(|c| tamper_carry(c, tag, index))
     })?;
     Ok(())
 }
--- /home/claude/somnus/pcp-zk/src/circuit.rs	2026-10-21 08:58:40.087716266 +0700
+++ review-crate/src/circuit.rs	2026-10-21 09:32:15.349324170 +0700
@@ -65,11 +65,11 @@
 
 #[derive(Clone, Debug)]
 pub struct SaleConfig {
-    sha: ShaConfig,
+    pub(crate) sha: ShaConfig,
     poseidon: Pow5Config<Fp, 3, 2>,
     /// Nibble column (looked up in `nib_table` where `q_nib` is on).
     rc: Column<Advice>,
-    a: [Column<Advice>; 5],
+    pub(crate) a: [Column<Advice>; 5],
     instance: Column<Instance>,
     nib_table: TableColumn,
     q_nib: Selector,
--- /home/claude/somnus/pcp-zk/src/lib.rs	2026-10-21 08:41:57.241349514 +0700
+++ review-crate/src/lib.rs	2026-10-21 09:27:52.683321757 +0700
@@ -10,6 +10,8 @@
 
 #[cfg(test)]
 mod adversarial;
+#[cfg(test)]
+mod review_tests;
 
 use halo2_proofs::{
     pasta::{EqAffine, Fp},
```

---

## Follow-up by the maintainer (2026-10-21, after this review)

Line numbers in this review refer to `sha256.rs` before the follow-up below. After it, `w_cells[t].copy_advice` moved from line 818 to line 975.

What was done, and checked independently of the reviewer:

1. **M-1 fixed.** The `Attack` hook (Appendix B) and `src/review_tests.rs` (Appendix A) are now in the repo unchanged. The only edits: the doc header of `review_tests.rs`, the `ff::Field` import renamed to `_`, and `compute_trace` gated to `#[cfg(test)]` to clear a dead-code warning. Every attack path is dead outside `cfg(test)`: `poc_hook::attack()` returns `Attack::None` there.
2. **M-1 confirmed by mutation testing.** Two bugs were put back into the chip on purpose, then removed:
   - Mutant 1 (C-3 class): `w_cells[t].copy_advice` was replaced by a plain `assign_advice` of the same value. Result: all 19 old tampers, the other lib tests and all 7 MockProver tests passed. `compensated_attacks_are_rejected` failed with "CRITICAL: attack 'C-3: round 20 consumes W_20+1' ACCEPTED with H != SHA256(k)", and `layout_selectors_rotations_and_ownership` also failed.
   - Mutant 2 (C-2 class): `range_poly(ecarry, 5)` was replaced by a constraint that is always zero, so the constraint indices did not move. Result: everything passed except `compensated_attacks_are_rejected`, which failed with "CRITICAL: attack 'C-2: E[63] shifted, carry solved in field' ACCEPTED".
   - The restored chip is byte-identical to the pre-mutation backup (`grep -c MUTANT` = 0).
3. **Verifying key unchanged.** A proof produced by the binary before this follow-up still verifies (`OK`) with the binary after it.
4. **Suites after the follow-up:**
   - `--lib`: 11/11 (126 s);
   - `--test mock`: 7/7 (31 s);
   - `--test prove`: 6/6 (40 s);
   - `scripts/cli-e2e.sh`: 14/14 as expected;
   - release build with no warnings.
5. **L-1:** a note in `selector_enable_counts_match_the_layout` points to the row-exact recorder test. The old test is kept as a cheap second check.
6. **L-2:** "21" is corrected to 19 in `README.md`, `COSTS.md`, `review/2026-10-21-sha-chip-notes.md`, the round 8 report and the failure-report draft. I counted the 19 entries in `tamper_cases()` myself.
7. **L-3:** checklist items 7 (`tamper_fixed`) and 12 (`chc`/`majc` placeholders) describe an earlier draft of the chip. Both are vacuous for the committed code. The checklist itself, Fable's round 6 note, is left as written; this paragraph is the correction.
8. **I-4** (blinding tautology in `lib.rs`) is left as is. It is harmless and already documented.

Status is unchanged: **reviewed and adversarially tested inside this project, not audited.** Two outside requirements remain before the halo2 chip is offered to anyone with money: an outside review, and the soundness bounty in `RELEASE-CHECKLIST.md` item 4.
