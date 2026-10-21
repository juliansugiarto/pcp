# pcp

**Pay for work only when it's proven correct.**

Hi, I'm Julian. This repo is my attempt at something I think the internet is still missing: a way to pay someone for a result only if they can prove, before you pay, that the result is right. No escrow, no platform in the middle, nobody who can freeze the payment. The money moves over Lightning, and the proof is zero-knowledge, so you learn that the answer is correct without seeing it until you've paid.

The idea isn't mine. Greg Maxwell described it in 2011 as the zero-knowledge contingent payment, and a sudoku solution was sold this way live at Financial Cryptography 2016. A year later Campanelli et al. showed that the trusted-setup version could be broken by a buyer who poisons the setup. Everything here uses transparent proof systems, so that attack has nothing to poison.

What I'm adding:
- a written protocol;
- a mandate that a human signs, so software agents can buy and sell on someone's behalf without spending without limits;
- honest numbers about what it costs.

The design is written up in the whitepaper: [`WHITEPAPER.md`](WHITEPAPER.md) ([PDF](whitepaper.pdf)).

> **Please don't use this with real money yet.** It's experimental, and nobody outside the project has audited it.

## What's in here

| Folder | What it is | Where it stands |
|---|---|---|
| `pcp/` | The protocol (`pcp/SPEC.md`) and a Rust implementation: mandates, offers, statements, and a Lightning rail (simulated, plus LND behind `--features lnd`) | Tests pass. A full sale has settled between two real LND nodes on regtest in CI |
| `pcp-zk/` | A transparent zero-knowledge proof (halo2, IPA over Pasta) for selling a sudoku solution, with a SHA-256 chip I wrote myself | Works. Reviewed inside the project by a separate AI reviewer that did not write the code; **not audited** by any outside party. Treat it as something to break, not something to pay through |
| `pcp-risc0/` | The same statement as a RISC Zero zkVM program. This is the backend meant for real payments | Runs: a sale with a real proof has settled over real LND nodes on regtest. Proving the 9x9 sudoku with the reproducible guest takes 151 s on 4 vCPU; the receipt is 224 KB and verifies in 0.018 s. See `pcp-risc0/COSTS.md` |
| `spec/`, `verifier/`, `tests/` | witnessed-record, an earlier design for publicly recountable signed records that I've put on hold | Parked |

## Try it

```
cd pcp-zk
cargo test --release -- --test-threads=1   # 24 tests, a few minutes on 2 CPUs
scripts/cli-e2e.sh                          # an honest sale, 9 lies or tampers that must fail, decrypt with right and wrong key
```

On a 2-CPU machine: proving takes 7.8 s and 0.57 GB, verifying takes 0.057 s, and the proof is 15,936 bytes. The full breakdown is in `pcp-zk/COSTS.md`.

To build the RISC Zero guest reproducibly and run a sale over two LND nodes on regtest, see `pcp/RUN.md`.

## The embarrassing part (worth reading first)

The first SHA-256 gadget I used turned out to be forgeable. A seller could have proven a false payment hash and been paid for nothing. A review inside the project, by a separate AI reviewer (a Claude model session) that did not write the code, caught it before any money was involved. Then I found that upstream had already removed that gadget three weeks earlier, for exactly this reason, and I simply hadn't read why.

The whole story is in `pcp-zk/review/2026-10-21-failure-report.md`: how it was found, the exploits, the replacement, and what has and hasn't been checked since. The other files in `pcp-zk/review/` are the reviews, the proof of concept and the reviewer checklist. Section 12 of `pcp/SPEC.md` lists the honest limits, including that the system as a whole is not quantum-resistant.

## Break it

Two challenges are open. There's no money behind them yet, but anyone who succeeds gets credited publicly.

1. **Soundness:** make `pcp-zk verify` accept a proof for any (givens, C, H, binding) where H is not the SHA-256 of a key that decrypts C to a valid grid consistent with the givens.
2. **Privacy:** recover the hidden grid of the break-this bundle in `pcp-zk/bundle-v1/` (an empty puzzle, so the answer cannot be solved for) from its public data alone. Its `BUNDLE.md` has the exact claim and the values; `./verify.sh` checks the proof.

Found something? Open an issue, or ask there for a private channel. Please timestamp your finding first.

## Fund the bounties

Donations go to the bounty fund for the two challenges above. Lightning, as a reusable BOLT12 offer (pay it from a wallet that supports BOLT12, for example Phoenix):

```
lno1zrxq8pjw7qjlm68mtp7e3yvxee4y5xrgjhhyf2fxhlphpckrvevh50u0q2jc9vhm8vl7me3zyzc5k0slwlv8msva9prweneujggq52w8vs99gqszscfw45da9ka0fcevnalar09mtyljd9ht6geglszsq0xugxhpuzqqqvlln9nv4qhm266r9nga8jqf7jcpkfl4jzp9dwlsk93k58t5j2m3dxv4wxnfmgwf8nswkaqyenng5prdjv7eqdlsmv8x2l5xnnkyya34967sl4scm7ysjx3702tgjxfekmzcf5gjgqqsqq79ml8ejgkdpr4y0xs2d67euc
```

Bitcoin on-chain:

```
bc1qt48zk92qrrzmdf4kx8argtga6wnxhs2julnctg
```

<sub>Also accepted: ETH and BNB Chain `0xaA7c8810888eeCC0946AAaa8625D5Ce2dDC4E2F9`, Solana `GM6y46HGzvJiQy5mWeyRUccDaK9bbmMmSLAxkUPrpS2p`, Tron `TRkwRyx3uhiExgAd7NbisUsgrRvn9Wi9h2`.</sub>

MIT license. Written by Julian Sugiarto.
