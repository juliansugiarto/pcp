# pcp-zk: real zero-knowledge proofs for the PCP/0 sudoku sale

> **STATUS: NOT SAFE (NOT AUDITED). DO NOT USE WITH REAL MONEY.**
> A review on 21 October 2026, done inside the project by a separate AI reviewer (a Claude model session) that did not write the code, found four critical flaws in the upstream SHA-256 Table16 gadget (halo2_gadgets 0.5.0): the round constants `K_t` are free, the compression carries are unbounded, the message words `W_16..W_63` are unconstrained, and `a_final`/`e_final` are unconstrained. The flaws were shown to be real (see `review/2026-10-21-poc.md`: with the old gadget, a malicious witness makes the circuit accept an `H` that is not `SHA256(k)`).
>
> What has been fixed: the Table16 gadget was removed entirely and replaced with a simple, auditable SHA-256 chip written in-house (`src/sha256.rs`). Every 32-bit word is decomposed into boolean bits, `K_t` and the IV are in fixed columns, all carries are bounded, the message schedule words and the state between rounds are bound through gates and copy constraints, and there are no free cells. Every constraint class is tested with 19 malicious witnesses and 14 compensated attacks (the trace after the corrupted cell is recomputed and `H` is replaced with a fake digest, so only the constraint under test can reject it), all of which must be rejected, and the in-circuit SHA is matched against `sha2` for 24 keys. The `verify` CLI was also fixed: the buyer must supply their own puzzle, `H`, and binding, the circuit is rebuilt from those, and the result is FAIL if the seller's `public.json` does not match.
>
> What is NOT done yet: this SHA-256 chip is NEW and NOT AUDITED. It was reviewed inside the project by a separate AI reviewer that did not write the code; it has not been audited by any outside party. The tests only show that an honest witness passes and a number of malicious witnesses fail, not that there are no other flaws. Before anyone may trust it, it needs: (1) a review of this new SHA-256 chip by someone outside the project, (2) a second implementation of the whole suite for cross-conformance vectors, and (3) a full audit. Do not consider this safe.


Status: experiment. Not audited. Do not use with real money.

This folder is its own Cargo project, separate from `../pcp`. It contains a halo2 circuit, a prover and a verifier as a CLI, and tests. It builds and runs with crates from crates.io only, on stable Rust.

## What is proven

The seller proves the following statement without revealing their secrets.

Public data (known to the buyer before paying):

- `givens`: the 81 puzzle cells, 0 meaning empty.
- `C`: the ciphertext, 81 field elements.
- `H`: the Lightning payment hash, 32 bytes.
- `binding`: 32 bytes that bind the proof to one offer (`statement_hash` from SPEC.md section 3.2 is recommended).

Secret data (known only to the seller):

- `R`: the solution, 81 cells with values 1 to 9.
- `k`: a 32-byte key.

The relation guaranteed by the proof:

1. `R` is a valid 9x9 sudoku solution: every cell has a value in 1..9, every row, column, and 3x3 box is a permutation of 1..9, and every number given in `givens` is unchanged.
2. `H = SHA256(k)`, standard SHA-256, so `H` can be used directly as the `payment_hash` of a BOLT11 invoice.
3. `C = Enc_k(R)` under the `zk-poseidon-ctr/0` suite below.

Uniqueness within each group is not checked with a sum of 45 and a product of 9!, because that is not enough. The counterexample is `{1,2,4,4,4,5,7,9,9}`: its sum is 45 and its product is 362880, but it is not a permutation (this is in the tests). This circuit uses range checks (`r - 1` and `9 - r` both in 0..15 through a lookup table) and pairwise inequality: for 27 groups and 36 pairs per group, `(r_a - r_b) * inv = 1` with `inv` as a witness. Nine mutually distinct values in 1..9 must be a permutation of 1..9.

## Proof system

halo2_proofs 0.3.5 (Zcash), IPA commitments over the Pasta curves, Blake2b transcript. The system is transparent: the parameters `Params::new(13)` are derived by hash-to-curve, and there is no trusted setup and no CRS that anyone can choose. The verifier computes the verifying key itself from the circuit definition and never accepts it from the seller. So the CCS 2017 attack on pay-to-sudoku (the buyer creates a malicious CRS) does not apply here.

Zero knowledge: halo2 0.3 has no switch for ZK. Blinding is always on. Every advice column gets random rows from the prover's RNG, and a random polynomial is added to the vanishing argument. The code checks this (`blinding_rows() > 0` before every proving run), and the test `zero_knowledge_blinding_is_on` fails if two proofs for the same statement turn out to be identical, which is what happens if blinding is off.

## Cipher suite `zk-poseidon-ctr/0`

ChaCha20-Poly1305 from the current specification is too expensive inside a circuit. This backend uses a separate suite:

```
k      32 bytes from a CSPRNG, fresh for every offer
H      SHA256(k)
k_hi   first 16 bytes of k, big-endian, as a field element (< 2^128)
k_lo   last 16 bytes of k, big-endian, as a field element
kk     Poseidon_3(TAG_KK, k_hi, k_lo)     keystream key, TAG_KK = "pcpzk/kk"
s_j    Poseidon_2(kk, j)   for j = 0..80
c_j    r_j + s_j  (mod p)                 addition in the field
```

`p` is the Pallas base field modulus (about 2^254). Poseidon here is `P128Pow5T3` from `halo2_gadgets::poseidon` in halo2_gadgets 0.5.0 (width 3, rate 2, Orchard parameters) in `ConstantLength<L>` mode. The input length goes into the capacity element, so key derivation (3 inputs) and the keystream (2 inputs) are domain-separated, in addition to the `TAG_KK` tag.

halo2_gadgets 0.5.0 is the version whose Table16 SHA-256 gadget was found forgeable (see the status note above). This crate uses it only for Poseidon; it does not use its SHA-256 gadget.

Decryption by the buyer after paying: `r_j = c_j - s_j`, and the result must be an integer in 1..9.

The ciphertext holds 81 field elements of 32 bytes each (2592 bytes total), encoded as canonical little-endian. Non-canonical encodings are rejected.

Requirements this suite meets:

1. `k` is 32 bytes from a CSPRNG, fresh for every offer. `H = SHA256(k)` is exactly one SHA-256 inside the circuit.
2. The keystream key `kk` is derived from `k` with a domain-separated hash; it is not `k` itself.
3. One keystream element per cell, encryption by addition in the field, not XOR.
4. Keystream elements are uniform in the field because they come directly out of Poseidon, with no biased bit reduction. `kk` is bound to `k` inside the circuit: the words of `k` that go into SHA-256 are the same cells that are packed into `k_hi` and `k_lo` for Poseidon. So the buyer's decryption with the `k` from the payment must match what was proven.
5. ZK is on and is checked in the code and the tests.
6. The offer binding is a public input.
7. Sudoku constraints: givens, range 1..9, permutation per group.

### Security argument in plain words

Before paying, the buyer sees `C`, `H`, and the proof. The proof reveals nothing except that the statement is true (zero knowledge). `H` does not reveal `k` because SHA-256 is preimage resistant and `k` has 256 bits of entropy. Each `c_j` is `r_j` plus `s_j`, and `s_j` is a Poseidon output under the secret key `kk`, so it looks like a uniform random element of the field. Adding a uniform element to `r_j` gives a uniform element, so `c_j` gives no information about `r_j` as long as `kk` stays secret. The assumptions are standard: Poseidon with the key in its input acts as a PRF, and knowing `SHA256(k)` does not help compute `Poseidon(TAG_KK, k)`, because the two are unrelated hash functions.

After paying, the buyer gets `k` as the payment preimage, computes `kk` and `s_j`, and then gets `r_j`. The proof guarantees that this result is a valid solution, because the same `k` goes into SHA-256 (which must produce `H`) and into Poseidon (which produces the keystream).

A fresh key per offer: keystream reuse cannot happen in normal use, for three reasons. First, the seller API `sell()` and the CLI `prove` draw `k` themselves from the operating system's CSPRNG for every offer, and do not accept `k` from outside (`prove_with_key` is for tests only). Second, the same `k` means the same `H`, and a Lightning node rejects a second invoice with a payment hash that already exists, while a buyer following SPEC.md (T5) rejects any `H` it has seen before. Third, after the first sale `k` is public to every hop on the payment route, so a seller who reuses `k` harms themselves. If it is reused anyway, the two ciphertexts leak the difference `r - r'`, which is why this rule is mandatory.

A note on the difference from `chacha20poly1305-k/0`: the old suite binds `C` to `offer_id` through AEAD associated data. In this suite the binding is done by the proof: `binding` is a public input and goes into the Fiat-Shamir transcript, and `C` itself is also a public input. A proof for one offer does not pass verification under another binding (covered in the tests).

## SHA-256 inside the circuit

The upstream Table16 gadget has been removed entirely (no upstream code remains, so there is no longer a license note). Its replacement is an in-house SHA-256 chip in `src/sha256.rs`, for one compression of a 64-byte block: the first 32 bytes are the key words, and the rest is the fixed padding for a 256-bit message.

The design is deliberately simple so that it can be audited line by line:

1. Every 32-bit word is stored as 32 boolean advice cells in one row (one column per bit, little-endian) plus one packed value cell. One gate enforces `b*(1-b)=0` for every bit and `packed = sum of b_i * 2^i`.
2. Rotations and shifts are just re-indexing of the bit cells through fixed rotations inside the gate. `Sigma0/1`, `sigma0/1`, `Ch`, `Maj` are written as packed sums taken directly from per-bit polynomials (`XOR = x+y-2xy`, `XOR3`, `Ch = ef + (1-e)g`, `Maj = ab+ac+bc-2abc`); because every per-bit term is proven boolean, these functions need no extra bit columns or range checks.
3. Addition mod 2^32: the sum of the packed inputs = packed output + carry * 2^32, with the output fully decomposed into bits (so it is in `[0, 2^32)`) and the carry constrained to exactly its range through a product polynomial (schedule 0..3, `E[t]` 0..5, `A[t]` 0..6, feed-forward 0..1). Because each term is < 2^32 and there are few terms, the honest sum is < 2^36 < p, so the equation holds over the integers and the pair (output, carry) is unique.
4. The IV and the 64 `K_t` are in fixed columns (part of the verifying key, not prover advice). The padding words are pinned to constants. `W_0..W_7` are copy-constrained to the same `k` word cells that are packed for Poseidon, so the key in SHA must be the same as the key in Poseidon. `W_16..W_63` are computed inside the circuit and read by the rounds through rotations/copies.
5. The state between rounds uses the standard recurrence: each round produces only two new words, `A[t]` and `E[t]`, one row each, so the history `A[t-1..t-4]` and `E[t-1..t-4]` is read through fixed rotations. There are no free cells: the only copies between regions are the key words to `W_0..W_7`, the message words to the rounds, and the 8 digest words to the `H` instance cells.
6. Output = IV + final state (feed-forward, with the carry constrained to boolean), copied to the `H` instance cells in the same order and endianness as before.

This chip no longer uses a 2^16 lookup table, so `k` dropped from 17 to 13 (see COSTS.md).

## What is safe and what is not yet

Done:

- Real ZK proofs, transparent, built and verified on Linux x86_64 and macOS arm64 (`scripts/cli-e2e.sh` in the `bench` workflow, 21 October 2026).
- The in-circuit `H` is the same as standard `sha2::Sha256` (tested with 24 keys, including extreme keys: all zeros, all 0xff, two alternating bit patterns), and matches vector 2 from SPEC.md.
- Every constraint class of the SHA-256 chip is rejected by 19 malicious-witness tests (non-boolean bit, packed value that does not match its bits, altered carry, altered schedule/state/final/padding word, SHA key different from the Poseidon key). The endianness of `H` and the number of selectors are also pinned by tests.
- 14 compensated attacks from the reviewer (a separate AI reviewer inside the project that did not write the chip; `src/review_tests.rs`) test the `W_t` copy into the rounds, the state copy into the digest, the IV constant copy, the key copy into the schedule, and carries solved in the field. Mutation test on 2026-10-21: if the `W_t` copy or the E carry range check is removed, the 19 older tests and 7 MockProver tests still pass, and only the compensated tests fail. That is why these tests are required.
- The reviewer's layout test (`layout_selectors_rotations_and_ownership`) records the assignment without MockProver: it counts selector rows, checks that every rotation of every gate lands on a cell assigned by the same region, and lists all copy constraints.
- A proof with a wrong solution does not pass verification; an altered `C`, `H`, givens, or binding does not pass; the proof and the public inputs do not contain `R` or `k` (checked byte by byte in the tests).

Not yet:

- The new SHA-256 chip in `src/sha256.rs` is NOT AUDITED. It is our own code. Tests can only show that an honest witness passes and 33 cheating witnesses fail, not that there is no other way to cheat. Notes for reviewers (cell ownership table, region boundary argument, booleanity coverage) are in `review/2026-10-21-sha-chip-notes.md`.
- Our own circuit (key packing, encryption, uniqueness) is not audited either.
- halo2_proofs 0.3.5 and Poseidon `P128Pow5T3` are used in Zcash Orchard, but the usage here is different and is not covered by that audit.
- Pasta security is about 126 bits (discrete logarithm), not 128.
- The `zk-poseidon-ctr/0` suite is newly proposed here and has not been reviewed by anyone else.
- There are no conformance vectors yet from a second implementation (for example in Python) for this suite.

## Usage

```
cargo build --release
B=target/release/pcp-zk

# seller: k is drawn fresh from the CSPRNG and written only to the secret file
$B prove --puzzle examples/puzzle.txt --solution examples/solution.txt \
         --binding <64 hex> --out sale --secret seller-k.hex

# buyer: checks before paying. The buyer MUST supply the puzzle, H
# (from the invoice they are about to pay), and their own binding; only C
# is taken from the seller's public.json. OK or FAIL.
$B verify --dir sale --puzzle examples/puzzle.txt \
          --payment-hash <64 hex H> --binding <64 hex>

# buyer after paying: k is obtained as the preimage
$B decrypt --dir sale --key $(cat seller-k.hex)
```

`sale/` contains only `proof.bin` and `public.json`.

Tests: `cargo test --release -- --test-threads=1`. The `--lib` tests include the SHA reference test, the suite tests, and the adversarial tests (malicious witnesses rejected + honest SHA equal to `sha2`). The `mock` tests use the halo2 MockProver; the `prove` tests create real proofs. `--test-threads=1` is required: the adversarial tests use a thread-local hook, and two parallel provers raise memory use. With the new SHA chip, the full test run finishes in a few minutes (not tens of minutes as with the Table16 version).

A "break this" bundle for strangers: `scripts/make-bundle.sh BUNDLE_DIR SECRETS_DIR [LABEL]`. It produces the puzzle as an empty grid, `public.json`, `proof.bin`, `BUNDLE.md` (the exact claim, the values, two bounties), `verify.sh`, and `SHA256SUMS`. `R`, `k`, and the commitment salt are written only to `SECRETS_DIR`, and the script refuses if that folder is inside a git repo. An empty grid is used because for an ordinary sudoku `R` can be computed from the puzzle, which would make the privacy bounty meaningless. A privacy bounty claim is checked with `scripts/check-bounty-claim.py SECRETS_DIR CLAIM_FILE`. Test on 2026-10-21 from a fresh copy of the public repository files, with no target and no cache: `verify.sh` printed OK in 57.6 seconds including the build and parameters (the verification itself took 0.064 seconds). A wrong fingerprint, a tampered proof, and a mismatched `SHA256SUMS` all fail.

`pcp-zk vk-fingerprint` prints the SHA-256 of the verifying key representation that halo2 also hashes into the transcript. Its value for the current circuit (2026-10-21) is `d8fb5e70076e3d0c8617de14c44bc5c37594032acd910b11ff42663fa3a8d2e4`, and it changes if even one constraint changes (tested by changing the E carry range). `verify --vk-fingerprint HEX` returns FAIL if your build is not the circuit the bundle names. The value is the same on macOS arm64 and on Linux x86_64 (`bench` workflow, 21 October 2026; raw output in the `ci-results` branch under `bench/pcp-zk-macos-latest-20261021T100324Z/` and `bench/pcp-zk-ubuntu-latest-20261021T100231Z/`).

End-to-end CLI test: `scripts/cli-e2e.sh [DIR]`. This script runs one honest sale, then 3 buyer inputs that do not match `public.json`, 6 consistent lies and tamperings that only the proof can catch (a different H, a different binding, a different puzzle, an altered ciphertext, one proof byte flipped, a truncated proof), and 2 decryptions (correct key and wrong key). `H = SHA256(k)` is also checked outside the circuit with Python's `hashlib`. Result on 2026-10-21: 14 of 14 as expected.

The transparent parameters are generated in about 5 seconds (k=13) and then stored in `target/params-k13.bin` (or at the `PCP_ZK_PARAMS` path). This cache adds no trust: the file is used only if its SHA-256 equals `PARAMS_SHA256` in the code, and anyone can regenerate the same parameters from scratch.

Cost summary on a 2-CPU Linux machine: proving about 8 seconds with peak memory of 0.57 GB, verification 0.06 seconds, proof 15936 bytes. Details are in `COSTS.md`.

## Plan for connecting to the `ProofBackend` trait in pcp

This backend will become a separate crate that depends on `pcp` and implements its trait, so that halo2 does not enter the `pcp` build.

- `backend_id()`: `halo2-ipa-pasta/pcp-sudoku9-zk-poseidon-ctr/0` (constant `BACKEND_ID`). Because `offer_id` binds `backend_id` and `enc_scheme`, the buyer knows exactly which circuit is verified.
- `is_secure()`: must be `false` as long as the new SHA-256 chip and this suite are not audited. The buyer must require explicit permission through policy, as with the current dev backend.
- `prove(job, statement, ciphertext, witness)`: only for `pcp/sudoku/v0` with `n = 9`. `givens = witness.input`, `R = witness.R`, `k = witness.k`, `binding = statement_hash`. `C` is the 81 field elements concatenated (2592 bytes), and `statement.ciphertext_hash = tagged_hash("ciphertext", [C])` as usual. `bundle.proof` holds the halo2 proof bytes.
- `verify(job, expected_statement, bundle)`: the verifier builds the public inputs from its own state: `givens` from the input it sent (already matched against `input_commitment`), `C` from the bundle after step V3, `H = statement.payment_hash`, and `binding = statement_hash` as it computed it itself. Then it computes the parameters and the verifying key itself and calls `pcp_zk::verify`.
- `enc_scheme` in the offer changes to `zk-poseidon-ctr/0`, and step P4 (decryption) uses `suite::decrypt`.
- Before that, SPEC.md needs a new section for this suite and conformance vectors.

## Files

- `src/circuit.rs`: the circuit.
- `src/suite.rs`: the cipher suite outside the circuit (encryption, decryption, sudoku check).
- `src/lib.rs`: setup, prove, verify, file formats.
- `src/sha256.rs`: the in-house SHA-256 chip (one compression of a 64-byte block).
- `src/bin/pcp-zk.rs`: CLI.
- `src/adversarial.rs`: malicious-witness tests + honest SHA (library tests).
- `tests/mock.rs`, `tests/prove.rs`: MockProver tests and real-proof tests.
- `review/`: soundness review, PoC, and notes on the new SHA chip.
- `COSTS.md`: measurements.
