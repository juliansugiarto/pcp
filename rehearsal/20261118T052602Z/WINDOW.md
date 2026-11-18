# PCP sale window

| | |
|---|---|
| Seller URL | `https://travis-coalition-senior-delayed.trycloudflare.com` |
| Lightning node | `02634b148723d8e0fc973a8c72f8c36d43832d4547e5cb005455c395208dc4e051@bore.pub:30802` (signet) |
| Price | 1000 sat per sale (signet test coins) |
| Job | `sudoku9`, the default puzzle of `pcp-buy-risc0` |
| Guest image id | `b5b5a8f7a6290a0b46146ed3dd75030684187d2d47c7711cfd7f815bd8e4ab8c` |
| Opens | 2026-11-18T04:44:28Z |
| Closes | 2026-11-18T06:44:28Z (channels are closed at the end) |
| Software | commit `dca1522d96f183438e6a65eee189fe30c31ce180` |

A short test of this software on signet. Signet coins have no value.
Invited principals only (0); other requests are refused before any work.

Open a direct channel of 25,000 sat to the node (LND's minimum is 20,000), then follow pcp/RUN-SIGNET.md.
Cloudflare terminates TLS and sees the request, the offer and the encrypted result, never the key.
