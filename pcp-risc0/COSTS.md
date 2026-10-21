# pcp-risc0 costs (first real run)

Measured on 21 October 2026 by the `bench` workflow on a GitHub-hosted runner. The machine had 4 vCPU (x86_64), 16 GB RAM, Ubuntu 24.04 and no GPU. The toolchain was risc0 3.0.6, installed with `rzup` (cargo-risczero 3.0.6, r0vm 3.0.6). This was the first time the guest was compiled and run anywhere. Raw output is in the `ci-results` branch under `bench/risc0-20261021T103355Z/`.

Each run is a full sale over the simulated Lightning rail:
1. the seller proves locally;
2. the buyer verifies before paying;
3. the payment settles;
4. the buyer decrypts and re-checks the result.

All three runs ended with `SETTLED`.

| Job | User cycles | Total cycles | Segments | Prove (s) | Verify (s) | Receipt (bytes) | Peak memory |
|---|---|---|---|---|---|---|---|
| `pcp/sudoku/v0` n=4 | 64,913 | 131,072 | 1 | 65.1 | 0.013 | 223,748 | 1.41 GB |
| `pcp/sudoku/v0` n=9 | 88,629 | 131,072 | 1 | 64.6 | 0.012 | 223,748 | 1.41 GB |
| `pcp/testsuite-toyexpr/v0` | 106,885 | 262,144 | 1 | 101.0 | 0.012 | 223,770 | 2.35 GB |

Execute-only runs, which count cycles without proving, took about 0.02 s per job.

## Reading the numbers

- **Proving time follows the padded cycle count, not the job.** Sudoku n=4 and n=9 both pad to 2^17 cycles, so they cost the same. The test-suite job crosses into 2^18 and costs about 1.6 times as much. The 9x9 sudoku uses only 68% of its 2^17 segment, so there is headroom before the next step up.
- **The receipt is a succinct STARK of about 224 KB.** It is transparent: no trusted setup and no Groth16 wrapper. That is 14 times larger than the halo2 proof (15,936 bytes), and verifying it is faster (0.012 s against 0.057 s).
- **Proving is slower than halo2 on the same statement:** 64.6 s on 4 vCPU against 7.8 s on 2 CPUs. In exchange, the SHA-256 here is RISC Zero's own circuit rather than one this project wrote, and the guest is plain Rust.
- **What one proof costs a seller** is the proving time multiplied by the price of the machine's time. On a rented 4-vCPU machine, 65 s is about 1/55 of an hour. Fill in a real hourly rate and the BTC price on the day before putting this next to a sale price.

## Not yet measured

- Apple Silicon with the Metal GPU prover. It is expected to be much faster than this CPU-only runner, but that has not been measured.
- A reproducible image id. This build did not use `RISC0_USE_DOCKER=1`, so the image id `6dc846c4…e8ea` comes from this runner's toolchain. A buyer on another machine can only match it after a Docker build. That is required before any sale to a stranger.
- The LND rail with real nodes.
