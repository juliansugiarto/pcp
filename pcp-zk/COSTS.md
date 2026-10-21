# pcp-zk costs (measured in this container)

Machine: 2 CPUs, 8 GB RAM (cgroup limit about 6.3 GB), Linux, rustc 1.97.0 stable, `cargo build --release`. Measured on 2026-10-21 with the new in-house SHA-256 gadget (Table16 has been removed), one proving process at a time. Times are wall-clock times. Peak memory is the process `VmHWM` (read from `/proc/self/status`).

The major change since the Table16 version: the 2^16-row lookup is gone, so `k` dropped from 17 to 13. Proving is much faster and uses much less memory. The price is a larger proof, because the new circuit uses many advice columns (80) for the 64 SHA bit columns, and IPA proof size grows with the number of columns.

## Results

| Step | Who | Time | Peak memory |
|---|---|---|---|
| Transparent parameters `Params::new(13)`, from scratch | once per machine | 4.6 s | 5 MB |
| Parameters from cache (SHA-256 hash matched) | every process | 0.14 s | 5 MB |
| `keygen_vk` (the verifier computes the key itself) | buyer, once per circuit version | 0.81 s | 21 MB |
| `keygen_vk` + `keygen_pk` | seller, once per circuit version | 1.38 s | 91 MB |
| **Proving** (witness + `create_proof`) | seller, per sale | **7.8 s** | **572 MB** (process peak, including keygen) |
| **Verification** (`verify_proof`) | buyer, per sale | **0.057 s** | 22 MB (including vk) |

Sizes:

| Item | Size |
|---|---|
| Proof (`proof.bin`) | **15936 bytes** (up from 5088; a result of the 80 advice columns) |
| Public inputs (`public.json`) | 6217 bytes (ciphertext 81 x 32 bytes = 2592 bytes, written as hex) |
| Cached parameters (`target/params-k13.bin`) | 524356 bytes (0.5 MB), SHA-256 `76ebe6b7...bb876` (pinned in `PARAMS_SHA256`) |

Total for one sale through the CLI with no cache at all: the seller takes about 14 seconds (parameters + keygen + proof), the buyer under 1 second (parameters from cache + vk + verification). With cached parameters and keys, the per-sale cost is only proving (about 8 seconds) and verification (about 0.06 seconds).

## Circuit shape

- `k = 13` (8192 rows). `k = 12` is not enough (the sudoku inequality gates and the 83 Poseidon permutations exceed 4096 rows). The lower bound is now set by Poseidon and sudoku, no longer by the SHA lookup table.
- 80 advice columns, 9 fixed columns, 13 selectors, 1 instance column (178 values), 1 lookup argument (nibble table 0..15), maximum gate degree 8, 10 blinding rows. Print these again with `cargo run --release --example stats`.
- Of the 80 advice columns, 64 are SHA-256 bit columns (32 for the A/W sequence, 32 for the E sequence). These bit columns do not take part in the permutation argument (no `enable_equality`); they are only read by gates through rotations, so they add no permutation polynomials. Only a few columns take part in the permutation (the A/E packed values, the copied W words, the Poseidon and sudoku working columns, the instance).
- SHA contents: 64 message schedule rows, 68 compression rows (4 IV seed rows + 64 rounds), 8 feed-forward/digest rows. Each round computes Sigma0, Sigma1, Ch, Maj as packed sums taken directly from the operand bits (fixed rotations -1..-4), then two additions mod 2^32 with carries constrained through a product polynomial.
- Other contents: 83 Poseidon permutations (2 for `kk`, 81 for the keystream), 81 encryption rows (two rows per cell for the range check), 972 pairwise inequality rows, 8 `k` words with nibble decomposition (used by Poseidon and copied to `W_0..W_7`).

## Where the memory goes

halo2_proofs 0.3 stores every advice/fixed/permutation column in the extended domain (a factor of 8 because of the highest degree, from the Poseidon S-box and the carry checks). With `k = 13` (8192 rows) the extended domain is only 65536 rows per column, much smaller than in the `k = 17` version (1,048,576 rows), even though the advice columns went up from 10 to 80. That is why the proving peak dropped from 4.29 GB to 0.57 GB. This machine (about 6.3 GB usable under its cgroup limit) now has plenty of room, and even two parallel provers should fit (about 1.2 GB), but the `prove` tests are still run one at a time to be safe.

## Test durations (`cargo test --release -- --test-threads=1`)

| Test | Contents | Time |
|---|---|---|
| `--lib` (except `adversarial`) | 1 SHA reference test, 3 suite tests | <1 s |
| `--lib adversarial` | 19 malicious witnesses rejected + honest SHA equal to `sha2` for 24 keys | 103 s |
| `--lib review_tests` | 14 compensated attacks + layout and cell ownership test (from the independent reviewer) | 21 s |
| `--test mock` | 7 MockProver tests | 32 s |
| `--test prove` | 6 tests with real proofs (5 proofs created) | 46 s |

## Rough comparison

A 16 KB proof and 0.06-second verification are still a good fit for a buyer who checks before paying. Proving at 8 seconds and 0.57 GB is the seller's cost per sale, down sharply from the previous version. The threefold increase in proof size is a consequence of the simple, easy-to-audit SHA bit-column design; if proof size becomes a problem, the bits can be packed more densely at the cost of a more complicated circuit.
