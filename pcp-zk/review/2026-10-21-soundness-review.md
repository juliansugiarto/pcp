# pcp-zk soundness review (read-only)

Reviewer: a separate AI model session (Claude) that did not write the code, inside the project; not an outside party.

Scope: /home/claude/somnus/pcp-zk (halo2_proofs 0.3.5 IPA/Pasta, halo2_gadgets 0.5.0).
Method: I read every source file and the upstream registry copy of halo2_gadgets 0.5.0
(`diff -r` of `src/sha256` against
`~/.cargo/registry/src/*/halo2_gadgets-0.5.0/src/sha256`). The only differences are the
marked "PCP-ZK patch" hunks. Everything listed under C-1 to C-4 below is therefore unmodified
upstream code. I did not build or run anything.

## Verdict

**Do not use this circuit. It is unsound.** The in-circuit SHA-256 (vendored Table16) has at
least four independent gaps. Each one alone lets a prover produce a verifying proof that
`H = SHA256(k)` for a `k` whose real SHA-256 is not `H`. That breaks the ZKCP guarantee
(SPEC T3, "money with no delivery"):

1. The seller issues a BOLT11 invoice with `payment_hash = H = SHA256(p)`.
2. The seller encrypts the real solution under a different key `k != p`, and proves the
   statement with a witness that forces the SHA-256 output to `H`.
3. The buyer's verify returns OK, and the buyer checks V6 `invoice.payment_hash = H`.
4. The buyer pays and receives `p`. Decryption with `p` fails, and the seller keeps the money.

The verifying key and constraint system stay the same. Only the prover's witness generator
changes, and the attacker controls that code.

The PCP-ZK code in `circuit.rs`, `suite.rs` and `lib.rs` is essentially correct. See "Verified
OK" below.

---

## Critical

### C-1 SHA-256 round constants K_t are free advice witnesses
`src/sha256/table16/compression/compression_util.rs:748-755` (`assign_h_prime`)

`k_lo` and `k_hi` are assigned with `AssignedBits::<16>::assign_bits(region, .., a_6, ..,
Value::known(k_lo))`. `a_6` is an **advice** column (`extras[2]`), and nothing ties these cells
to a constant. The `s_h_prime` gate (`compression.rs:747-748`, `compression_gates.rs:358-364`)
reads them as ordinary advice.

- **Exploit.** In each round the prover picks any K_t'. That makes H' an arbitrary 32-bit
  value, and through it E_new and A_new (one degree of freedom per round). Free K_t at rounds
  56..63 is enough to hit all 8 target output words:
  - Use K_56..K_59 to set A_56..A_59 to the values the targets force.
  - Use K_60..K_63 to set E_60..E_63.
  - A_60..A_63 then follow.
- **Fix.** Put K_t in a fixed column (`assign_fixed`) and enable equality if it is copied.
  Alternatively, keep it in advice but `constrain_constant` both halves.

### C-2 Compression carries are not range-constrained
`compression_gates.rs:364, 388, 410`; witnesses at `compression_util.rs:782-787, 829-834, 883-888`

`s_h_prime`, `s_a_new` and `s_e_new` check `sum - carry*2^32 - out = 0` with **no range check
on `carry`**. The message-schedule `s_word` gate does check its carry (`schedule_gates.rs:32`,
`range_check(carry,0,3)`); the compression gates do not.

- **Exploit.** For any target `out` in [0, 2^32), set
  `carry = (sum - out) * 2^-32 mod p`. Next round's decomposition only checks
  `out < 2^32`, which the target satisfies. Choosing A_new and E_new at rounds 60..63 sets the
  whole final state, so `state + IV` equals any H.
- **Fix.** Range-check the carries: `h_prime_carry` in 0..5 (6 addends), `a_new_carry` in 0..2,
  `e_new_carry` in 0..1. Also range-check `h_prime_lo` and `h_prime_hi` to 16 bits
  (`compression_util.rs:793-796` assigns them with no lookup). Otherwise `h'` can be off by a
  multiple of 2^32 that the next carries absorb.

### C-3 Message schedule words W_16..W_63 are never tied to the `s_word` result
`message_schedule/subregion2.rs:253-268`, `message_schedule/subregion3.rs:169-184`

- **What happens.** The `s_word` gate writes `W_i = σ1 + W_{i-7} + σ0 + W_{i-16}` into
  `a_5` at row `get_word_row(i-16)+1`.
- **What is actually used.** `assign_word_and_halves(region, word, i)` then assigns a
  **separate** `W_i` cell at `get_word_row(i)`, plus its halves.
- **What links them.** Those separate cells are what get decomposed, what feed later σ
  computations, and what feed the compression (`w_halves`). No `constrain_equal` links them to
  the `s_word` output. `grep` finds no `constrain_equal` anywhere in `table16/`.
- **Consequence.** W_16..W_63 are free 32-bit witnesses. One degree of freedom per round gives
  full control of the output, as in C-1.
- **Fix.** `region.constrain_equal(s_word_out.cell(), w_i.cell())`, or assign W_i once and reuse
  the cell.

### C-4 Final-round A and E are fresh, unlinked witnesses
`compression/subregion_main.rs:104-112`

In round 63, `a_final` and `e_final` come from
`assign_word_halves_dense(.., a_new_val)` and `assign_word_halves_dense(.., e_new_val)`. These
are **new cells**, with no copy constraint from `a_new_dense` or `e_new_dense` (the `s_a_new` and
`s_e_new` outputs). In rounds < 63 the link exists through `copy_advice` at lines 72-86.

- **Consequence.** The digest words 0 (A) and 4 (E) are arbitrary. The feed-forward in
  `circuit.rs` checks only `out = s + IV - carry*2^32`, which an arbitrary `s` satisfies.
- **Exploit.** This is the simplest one. Add a delta to `a_new_val` at the `a_final` assignment
  and set `H[0]` to match. No other change is needed.
- **Fix.** Copy-constrain `a_new_dense` and `e_new_dense` into the digest rows, and
  range-check them (16-bit lookups), because in round 63 no next-round decomposition does it.

## High

### H-1 1-bit message-schedule pieces are not boolean-constrained
`schedule_gates.rs:81-112` (`s_decompose_2`), `:290-297` and `:356-363` (σ v2)

Pieces `e` and `f` of W_14..W_48 (bits 17 and 18) have no `x*(1-x)` check. `e` can absorb any
residue in `decompose_check`, so the other pieces, and therefore σ0 and σ1, are not
determined by W. This is moot until C-3 is fixed, but it matters after the fix. In particular,
W_14 and W_15 are fixed padding words, and their σ values could still be forged.

**Fix.** Add `range_check(e,0,1)` and `range_check(f,0,1)`.

### H-2 The CLI verifier trusts the seller's `public.json` for `givens` and `H`, and `--binding` is optional
`src/bin/pcp-zk.rs:87-111`

The buyer step shown in the README is `verify --dir sale --binding ..`. It loads `givens`, `C`,
`H` and `binding` from the seller's file. It only optionally compares `binding`, and it never
compares `givens` with the buyer's puzzle or `H` with the invoice.

- **Exploit.** A seller ships a proof for a puzzle the seller chose (for example, all blank)
  and gets OK.
- **Why the binding check does not cover this.** The binding check compares two opaque bytes.
  The CLI does not recompute `statement_hash` from `public.json`.

`lib::verify` is fine when the caller builds `PublicInputs` itself, as README:138 describes for
the ProofBackend. The CLI does not.

**Fix.** Make `verify` take `--puzzle`, `--payment-hash` and a required `--binding`, and build
`PublicInputs` from those. Take only `C` from the seller.

## Medium

### M-1 Tests cannot detect any of C-1 to C-4
`tests/mock.rs:41-61`, `tests/prove.rs`

Every SHA test uses the honest witness generator, so these tests show completeness, not
soundness. The README's claim (lines 79-87, 94) that the gadget was patched to standard SHA-256
is therefore incomplete, and the security argument (lines 62 and 71) depends on it.

**Fix.** Add adversarial MockProver tests behind a `cfg(test)` perturbation hook in the
vendored gadget. Each one should be expected to FAIL after the fixes and currently PASSES:
- C-4: `a_final = a_new + 1`, `H[0]` adjusted.
- C-1: `K_63 += 1`, `H` set to what the circuit computes.
- C-2: `e_new` at round 63 shifted by delta, with the carry solved in the field.
- C-3: `W_20 ^= 1` in `assign_word_and_halves`.

## Low / Info

- **L-1** `lib.rs:265`: `assert!(blinding_rows() > 0)` is a tautology. halo2 0.3
  `blinding_factors()` is always at least 4 (`max(3, q) + 1`). It is harmless but proves nothing.
  ZK itself is unconditional in halo2 0.3, so the claim holds.
- **I-1** For given cells, `s_j = c_j - g_j` is public. Under the Poseidon-PRF assumption this
  leaks nothing about the other `s_j`. It is worth one line in the README.
- **I-2** `params_cached` regenerates params on a hash mismatch and only prints a note. This is
  fine because `Params::new(K)` is deterministic and the dependencies are pinned with `=`.
- **I-3** The Table16 spread lookup is unselected over `a_0..a_2`. It is safe because no other
  chip uses those columns and `(0,0,0)` is in the table.

---

## Verified OK (by reading)

### 1. SHA-256 patches
- The IV dense halves of all 8 words are pinned with `constrain_constant`
  (`subregion_initial.rs:45-52`).
- The IV spread forms are tied to the dense forms by `s_decompose_abcd` and
  `s_decompose_efgh`.
- The patch adds a constants column (`table16.rs:314-315`).
- Digest cells are returned constrained (`s_digest`: `word = lo + 2^16 hi`).
- Feed-forward (`circuit.rs:161-172, 308-334`): `out = s + IV - carry*2^32`, with the carry
  boolean, the IV from a fixed column, and `out` decomposed into 8 lookup-checked nibbles
  (`q_dec` plus `q_nib`). This is correct mod 2^32. It is only as good as `s`, which is
  broken by C-1 to C-4.
- Message words 0..7 are `constrain_equal` to the nibble-checked k cells, and words 8..15 to the
  constants `0x80000000, 0 x6, 256`. That is the correct single-block padding for a 32-byte
  message (`circuit.rs:288-307`).
- `comp.message` is `w[0..16]`, which `s_decompose_0` ties to the halves used by the
  compression.
- Digest cells `a..h` go to instance rows 162..169. `lib.rs::words` encodes `H` as 8
  big-endian u32 words, which matches SHA-256 byte order.

### 2. Binding of k
- The same `k_cells` feed the SHA message (`circuit.rs:302`) and the packing
  (`circuit.rs:275`).
- Each word is less than 2^32 because of the nibble lookups.
- `k_hi = w0·2^96 + w1·2^64 + w2·2^32 + w3` is less than 2^128, which is less than `p`, so the
  representation is unique.
- This equals `suite::key_halves`, which reads the 16 bytes as a big-endian u128.

### 3. Poseidon
- Both sides use Pow5Chip / `P128Pow5T3` / `ConstantLength<3>` and `ConstantLength<2>`, matching
  the out-of-circuit `halo2_gadgets::poseidon::primitives`.
- `TAG_KK` and `j` are `assign_advice_from_constant`.
- Padding goes through `rc_b`, which has equality enabled, plus `constrain_equal`.
- The capacity element comes from a constant.
- `kk` is copy-constrained into every keystream hash.

### 4. Cells
- `r-1 ∈ [0,15]` and `9-r ∈ [0,15]` both apply to the same `r` in the same gate row. Over F_p
  this forces `r ∈ {1..9}`: `r = 1+x` with `x ≤ 15`, and `8-x ≥ 0` forces `x ≤ 8`. There is no
  wraparound because `p` is large.
- `g` is copied from the instance column, and the gate is `g(r-g) = 0`.
- The 27 groups (rows, columns, boxes) are correct.
- 36 pairs each give 972 inverse-witness gates, using copies of the same `r` cells.

### 5. Encryption
- `c` is copied from instance rows 81..161.
- `s` is copied from the Poseidon outputs.
- `r` is the same cell used by the range, givens and distinctness constraints.

### 6. Binding public input
- The 8 binding words are copied into advice (equality-enabled), so they take part in the
  permutation argument.
- halo2 0.3.5 `verify_proof` recomputes the instance commitments and absorbs them into the
  transcript (`verifier.rs:87-115`).

### 7. Selectors
- Every selector is enabled unconditionally in `synthesize`, so the verifying key computed
  from `SaleCircuit::default()` is identical.
- No gate depends on a selector the prover controls.
- Shared columns are safe because all gates are selector-guarded and regions do not overlap.
- No unconstrained cell exists in the PCP-ZK code. The unconstrained cells are all in Table16
  (C-1 to C-4).

### 8. Zero knowledge
- Blinding is unconditional in halo2 0.3: 11 blinding rows plus a random vanishing polynomial.
- The public inputs contain only `givens`, `C`, `H` and the binding.

### 9. lib.rs
- The verifying key is rebuilt from the circuit (`keygen_vk(SaleCircuit::default())`).
- Params come from `Params::new(17)`, and the cache is pinned by SHA-256.
- `instance()` order (`givens`, `C`, `H` words, binding words) matches the `ROW_*` constants.
- Non-canonical `C` encodings and trailing proof bytes are rejected.

## Not verifiable by reading alone
- Whether more Table16 gaps exist beyond C-1 to C-4 and H-1. Given four critical gaps in
  upstream "unstable" code, assume more. My review of the σ/Ch/Maj spread algebra was a spot
  check, not a proof.
- Proof that the PoCs pass MockProver. This needs a run.
- The soundness and ZK of halo2_proofs 0.3.5 itself and the Poseidon parameters. Those are
  assumed.

## Recommendation
Treat the vendored SHA-256 as untrusted. Either:

- **(a) Fix it.** Fix C-1 to C-4 and H-1 and the h' range check, add the adversarial tests in
  M-1, and get an independent audit of the whole gadget.
- **(b) Replace it.** Use a SHA-256 circuit that has a published audit, even if that means
  changing the proof-system stack.

In either case, also fix H-2 before any buyer relies on the CLI.

---

## Addendum (2026-10-21, after the review): upstream had already declared this gadget unsound

On 2026-09-29, three weeks before this crate vendored it, upstream removed the Table16 gadget
in halo2_gadgets 0.6.0. The changelog gives the reason: "removed due to multiple soundness
vulnerabilities". It also says the carry range check issue "has been confirmed exploitable,
allowing a malicious prover to forge arbitrary SHA-256 digests". Sources:
https://github.com/zcash/halo2/pull/964 and the halo2_gadgets 0.6.0 CHANGELOG.

The upstream PR names three issues:

- missing carry range checks in `s_h_prime`, `s_a_new` and `s_e_new` (matches C-2 here);
- missing copy constraints on the final-round outputs (matches C-4);
- missing boolean constraints on the schedule decomposition bits (overlaps H-1).

C-1 (`K_t` held in free advice) and C-3 (`W_16..63` not linked) are not named in that PR.
Unverified: whether they are known elsewhere.

Process lesson: the removal was known when the gadget was vendored, but its stated reason was
not read. For every cryptographic dependency, read the changelog and the removal or
deprecation notes before vendoring. "Unstable" in a crypto crate can mean unsound, not only
"API may change".
