# pcp-risc0 costs (first real run)

Measured on 21 October 2026 by the `bench` workflow on a GitHub-hosted runner. The machine had 4 vCPU (x86_64), 16 GB RAM, Ubuntu 24.04 and no GPU. The toolchain was risc0 3.0.6, installed with `rzup` (cargo-risczero 3.0.6, r0vm 3.0.6). This was the first time the guest was compiled and run anywhere. The guest in this first table was built natively, without Docker (image id `6dc846c4…e8ea`), so its image id is not reproducible on another machine; the reproducible guest is measured in the next section. Raw output is in the `ci-results` branch under `bench/risc0-20261021T103355Z/`.

Each run is a full sale over the simulated Lightning rail:
1. the seller proves locally;
2. the buyer verifies before paying;
3. the payment settles;
4. the buyer decrypts and re-checks the result.

All three runs ended with `SETTLED`.

Native (non-reproducible) build:

| Job | User cycles | Total cycles | Segments | Prove (s) | Verify (s) | Receipt (bytes) | Peak memory |
|---|---|---|---|---|---|---|---|
| `pcp/sudoku/v0` n=4 | 64,913 | 131,072 | 1 | 65.1 | 0.013 | 223,748 | 1.41 GB |
| `pcp/sudoku/v0` n=9 | 88,629 | 131,072 | 1 | 64.6 | 0.012 | 223,748 | 1.41 GB |
| `pcp/testsuite-toyexpr/v0` | 106,885 | 262,144 | 1 | 101.0 | 0.012 | 223,770 | 2.35 GB |

Execute-only runs, which count cycles without proving, took about 0.02 s per job.

## Current reproducible guest (builder r0.1.97.0, 21 October 2026)

`methods/build.rs` pins the Docker builder `risczero/risc0-guest-builder:r0.1.97.0` (Rust 1.97, the same toolchain rzup installs). With risc0-build 3.0.6's default builder `r0.1.88.0` (Rust 1.88), the same source needed about 10,300 more cycles, and the 9x9 sudoku padded to 2^18. Two independent Docker builds give image id `cc6e7b82fb2da7bba9aa051331c0662ad123ac9821820c0daa34f4e942d0e328` and the same guest ELF SHA-256. The guest source and the journal (261 bytes) are unchanged.

Two real sales over LND v0.21.4 regtest (`real-sale` workflow) with this guest, both `SETTLED`:

| Result folder (`ci-results-lnd`) | `pcp/sudoku/v0` n=9: user / total cycles | Prove | Verify | Peak RSS | `pcp/testsuite-toyexpr/v0` (2^18) prove | Peak RSS |
|---|---|---|---|---|---|---|
| `real-sale/20261021T170434Z` | 88,606 / 131,072 | 62.0 s | 0.012 s | 1,424 MiB | 97.3 s | 2,359 MiB |
| `real-sale/20261021T173907Z` | 88,606 / 131,072 | 102.4 s | 0.019 s | 1,428 MiB | 158.9 s | 2,359 MiB |

The receipt stays 223,748 bytes. The second folder is the run whose expected image id was already `cc6e7b82…` (`match: yes`); the first ran the same guest before that check was updated.

Both runs used the same guest; the second runner was about 1.6 times slower on both jobs. GitHub-hosted runners vary that much, so compare times only within one run. Within one run, the 2^17 sudoku took 0.64 times as long as the 2^18 test-suite job (62.0 / 97.3 and 102.4 / 158.9), and peak memory fell from 2,359 MiB to about 1,425 MiB. An earlier note here expected "151 s to about 65 s"; that compared different runners. The like-for-like gain is about 1.55 times, not 2.3.

How close 88,606 user cycles are to the 2^17 limit (user plus paging cycles) is not measured; a guest change that adds a few thousand cycles could push it back to 2^18. `--execute-only` now prints the padded total, so this can be checked without proving.

## A real sale: real proof, real Lightning (21 October 2026) (first guest, builder r0.1.88.0)

The `real-sale` workflow (run 39627526488) used the reproducible Docker-built guest, image id `abe2df2125017d6785cab6fe7103c0ecf3fc130e34d9f7efa0359c8ffe06d941`. It ran two sales over two LND v0.21.4 nodes on regtest, with the backend `risc0-zkvm-3-succinct/abe2df21…d941` and the rail `lightning-bolt11/0`. Both ended `SETTLED`. The seller's balance rose by exactly 1,000 sat per sale, and SHA-256 of the revealed preimage equals the invoice's payment hash.

| Job | User cycles | Total cycles | Prove (s) | Verify (s) | Receipt (bytes) | Peak memory | Buyer has `k` after paying |
|---|---|---|---|---|---|---|---|
| `pcp/sudoku/v0` n=9 | 98,941 | 262,144 | 150.6 | 0.018 | 223,748 | 2.36 GB | 0.53 s |
| `pcp/testsuite-toyexpr/v0` | 114,019 | 262,144 | 149.7 | 0.018 | 223,770 | 2.36 GB | 1.03 s |

**Correction.** An earlier version of this file said the Docker-built guest would stay inside one 2^17 segment, "so the proving cost should not change much". That was wrong. The Docker guest's 9x9 sudoku pads to 2^18 total cycles, and proving takes about 2.3 times as long (150.6 s against 64.6 s) with 1.7 times the memory. The reproducible guest is the one a stranger can check, so these are the numbers that count for real sales. The guest in the section above is back under 2^17 cycles; in the runs measured, that cut proving time to about 0.64 of the 2^18 time, not to half.

The timelocks held with room to spare. The seller proves before it invoices, so proving time does not eat into the invoice or the HTLC. It does count against the 600-second offer lifetime: 151 s used, 449 s left. Since 21 October the seller refuses to invoice on an expired offer, and the buyer refuses to pay on one.

## Reading the numbers

- **Proving time follows the padded cycle count, not the job.** In the native build, sudoku n=4 and n=9 both pad to 2^17 cycles, so they cost the same, and the test-suite job crosses into 2^18 and costs about 1.6 times as much. With the first reproducible guest (builder r0.1.88.0) the 9x9 sudoku padded to 2^18 (98,941 user cycles) and cost the same as the test-suite job; with the current one (r0.1.97.0) it is back at 2^17 (88,606).
- **The receipt is a succinct STARK of about 224 KB.** It is transparent: no trusted setup and no Groth16 wrapper. That is 14 times larger than the halo2 proof (15,936 bytes), and verifying it is faster (0.012 s native, 0.018 s reproducible, against 0.057 s).
- **Proving is slower than halo2 on the same statement:** 62 to 102 s on a 4-vCPU runner with the current reproducible guest, against 7.8 s on 2 CPUs. In exchange, the SHA-256 here is RISC Zero's own circuit rather than one this project wrote, and the guest is plain Rust.
- **What one proof costs a seller** is the proving time multiplied by the price of the machine's time. On a rented 4-vCPU machine, 62 to 102 s with the current reproducible guest is 1/58 to 1/35 of an hour. Fill in a real hourly rate and the BTC price on the day before putting this next to a sale price.

## Not yet measured

- Apple Silicon with the Metal GPU prover. It is expected to be much faster than this CPU-only runner, but that has not been measured.
