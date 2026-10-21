# pcp

**Pay for work only when it's proven correct.**

Hi, I'm Julian. This repo is my attempt at something I think the internet is still missing: a way to pay someone for a result only if they can prove, before you pay, that the result is right. No escrow, no platform in the middle, nobody who can freeze the payment. The money moves over Lightning, and the proof is zero-knowledge, so you learn that the answer is correct without seeing it until you've paid.

The idea isn't mine. Greg Maxwell described it in 2011 as the zero-knowledge contingent payment, and a sudoku solution was sold this way live at Financial Cryptography 2016. A year later Campanelli et al. showed that the trusted-setup version could be broken by a buyer who poisons the setup. Everything here uses transparent proof systems, so that attack has nothing to poison.

What I'm adding:
- a written protocol;
- a mandate that a human signs, so software agents can buy and sell on someone's behalf without spending without limits;
- honest numbers about what it costs.

> **Please don't use this with real money yet.** It's experimental, and nobody outside the project has audited it.

## What's in here

| Folder | What it is | Where it stands |
|---|---|---|
| `pcp/` | The protocol (`pcp/SPEC.md`) and a Rust implementation: mandates, offers, statements, and a Lightning rail (simulated, plus LND behind `--features lnd`) | Tests pass. Not yet run against a real LND node |
| `pcp-zk/` | A transparent zero-knowledge proof (halo2, IPA over Pasta) for selling a sudoku solution, with a SHA-256 chip I wrote myself | Works, and was reviewed inside the project. **Not audited.** Treat it as something to break, not something to pay through |
| `pcp-risc0/` | The same statement as a RISC Zero zkVM program. This is the backend meant for real payments | Written but not yet run. CI will produce its cost table |
| `spec/`, `verifier/`, `tests/` | witnessed-record, an earlier design for publicly recountable signed records that I've put on hold | Parked |

## Try it

```
cd pcp-zk
cargo test --release -- --test-threads=1   # 24 tests, a few minutes on 2 CPUs
scripts/cli-e2e.sh                          # an honest sale, 9 lies or tampers that must fail, decrypt with right and wrong key
```

On a 2-CPU machine: proving takes 7.8 s and 0.57 GB, verifying takes 0.057 s, and the proof is 15,936 bytes. The full breakdown is in `pcp-zk/COSTS.md`.

## The embarrassing part (worth reading first)

The first SHA-256 gadget I used turned out to be forgeable. A seller could have proven a false payment hash and been paid for nothing. An internal review caught it before any money was involved. Then I found that upstream had already removed that gadget three weeks earlier, for exactly this reason, and I simply hadn't read why.

The whole story is in `pcp-zk/review/2026-10-21-failure-report.md`: how it was found, the exploits, the replacement, and what has and hasn't been checked since. The other files in `pcp-zk/review/` are the reviews, the proof of concept and the reviewer checklist. Section 12 of `pcp/SPEC.md` lists the honest limits, including that the system as a whole is not quantum-resistant.

## Break it

Two challenges are open. There's no money behind them yet, but anyone who succeeds gets credited publicly.

1. **Soundness:** make `pcp-zk verify` accept a proof for any (givens, C, H, binding) where H is not the SHA-256 of a key that decrypts C to a valid grid consistent with the givens.
2. **Privacy:** recover the hidden grid of the break-this bundle in `pcp-zk/bundle-v1/` (an empty puzzle, so the answer cannot be solved for) from its public data alone. Its `BUNDLE.md` has the exact claim and the values; `./verify.sh` checks the proof.

Found something? Open an issue, or ask there for a private channel. Please timestamp your finding first.

MIT license. Written by Julian Sugiarto, with help from contributors.
