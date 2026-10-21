# pcp-zk break-this bundle (v1)

**Experimental, not audited. Do not use where money depends on it.**

## The claim, exactly

This bundle contains a transparent zero-knowledge proof, made with halo2_proofs 0.3.5 (IPA over the Pasta curves, no trusted setup), for one statement: the prover knows a valid 9x9 sudoku grid R consistent with the published givens and a 32-byte key k such that the published C is the encryption of R under a Poseidon-derived keystream from k, and the published H equals SHA-256(k), bound to the published 32-byte binding value. A verifier rebuilds the verifying key from the circuit source and checks the proof against the givens, H and binding it supplies itself; it takes only C from the bundle. The proof is 15,936 bytes and verified in 0.057 s on a 2-CPU Linux container; proving took 7.8 s and 0.57 GB there, at k = 13. The SHA-256 chip inside the circuit is our own. It replaces the halo2_gadgets 0.5.0 Table16 gadget, which a read-only review inside this project found forgeable in four independent ways (two reproduced with MockProver), three weeks after upstream had removed it for three overlapping reasons; the failure report is included. The replacement has been checked, inside this project and by a reviewer who did not write it, for: exactly one owning constraint or copy for every advice cell of the SHA chip (mechanically, 23,128 rotation reads), exact carry ranges, round constants and IV in fixed columns, 14 compensated forgery attempts each rejected by the intended constraint, agreement with the sha2 crate on 24 keys, and two deliberate re-insertions of Table16-class bugs that only the compensated tests caught. It has not been audited by anyone outside this project; halo2_proofs, the upstream Poseidon chip and the sudoku gates are assumed or lightly checked rather than reviewed to the same depth; zero-knowledge rests on halo2's default blinding and one test that two proofs of the same statement differ, with no further analysis; no Lightning payment has been made with it; no one outside the project has run it. It is not the backend the protocol defaults to, and it must not be used where money depends on it. Two bounties are open: produce a proof that verifies under the published verifying key for any (givens, C, H, binding) where H is not SHA-256 of the key that decrypts C, or where the decryption of C is not a valid grid; and produce the grid R committed to in this bundle from (givens, C, H, proof) alone, where the givens are an empty grid so that R is not computable from the puzzle. If either succeeds, this bundle is withdrawn and the report updated.

## Values

| | |
|---|---|
| givens | empty grid (81 zeros), `givens.txt` |
| H (payment hash) | `64671770057fae33fcf10fb65523964c20e13659e75326e0a13f088d60b60dbc` |
| binding | `1405bbaefc37ee45baa8aa69dbbdac2ce62afcf081825c590cc7e0f76cbe6610` = SHA-256("pcp-zk/bounty-bundle/v1") |
| verifying-key fingerprint | `d8fb5e70076e3d0c8617de14c44bc5c37594032acd910b11ff42663fa3a8d2e4` (`pcp-zk vk-fingerprint`) |
| transparent params (k = 13) SHA-256 | `76ebe6b75b5281cb1dcc2eb04888968573758672b521522f62abedf6366bb876` |
| commitment to R | `47eca0ccb400e35c78cb3300e8fc7df0d572aa5191c52ddedbed3013a3441d87` = SHA-256("pcp-zk/bounty-R/v0" ‖ R as 81 ASCII digits, row by row ‖ 32-byte salt) |

## Verify

```
./verify.sh        # prints OK; set PCP_ZK_CRATE if the crate is not the parent directory
```

Or by hand: `pcp-zk verify --dir . --puzzle givens.txt --payment-hash <H> --binding <binding> --vk-fingerprint <fingerprint>`. The fingerprint check fails if your build of the circuit is not the one this bundle names.

## Bounties

Reward: none funded yet; anyone who succeeds is credited publicly. Donations to the bounty fund: Lightning BOLT12 offer `lno1zrxq8pjw7qjlm68mtp7e3yvxee4y5xrgjhhyf2fxhlphpckrvevh50u0q2jc9vhm8vl7me3zyzc5k0slwlv8msva9prweneujggq52w8vs99gqszscfw45da9ka0fcevnalar09mtyljd9ht6geglszsq0xugxhpuzqqqvlln9nv4qhm266r9nga8jqf7jcpkfl4jzp9dwlsk93k58t5j2m3dxv4wxnfmgwf8nswkaqyenng5prdjv7eqdlsmv8x2l5xnnkyya34967sl4scm7ysjx3702tgjxfekmzcf5gjgqqsqq79ml8ejgkdpr4y0xs2d67euc`. Bitcoin on-chain: `bc1qt48zk92qrrzmdf4kx8argtga6wnxhs2julnctg`. Other currencies: see the repository README. Full terms will follow. Author: Julian Sugiarto. Contact: open an issue at https://github.com/juliansugiarto/pcp/issues, or ask there for a private channel. Timestamp your finding first.

1. **Soundness.** Send a tuple (givens, C, H, binding), a proof that `pcp-zk verify` accepts for that tuple under the verifying key with the fingerprint above, and a 32-byte p with SHA-256(p) = H such that `pcp-zk decrypt --key p` does not yield a valid grid consistent with the givens. Any tuple counts, not only this bundle's.
2. **Privacy.** Send the 81 digits of the R committed to above, derived from this bundle's givens, C, H and proof alone. The owner checks it against the commitment with the salt, then publishes the salt and R.

If either bounty is claimed, this bundle is withdrawn and the failure report is updated.

## Files

`givens.txt`, `public.json` (C, H, binding, suite and backend ids), `proof.bin`, `verify.sh`, this file, `SHA256SUMS`.
