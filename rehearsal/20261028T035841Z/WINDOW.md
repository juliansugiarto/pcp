# PCP sale window

| | |
|---|---|
| Seller URL | `https://separately-need-communist-journal.trycloudflare.com` |
| Lightning node | `026c623b935890c816a953e218b4809e4ccd68413c25a4a4b126bb1b9153f4ee3e@bore.pub:27541` (signet) |
| Price | 1000 sat per sale (signet test coins) |
| Job | `sudoku9`, the default puzzle of `pcp-buy-risc0` |
| Guest image id | `cc6e7b82fb2da7bba9aa051331c0662ad123ac9821820c0daa34f4e942d0e328` |
| Opens | 2026-10-28T03:11:24Z |
| Closes | 2026-10-28T05:11:24Z (channels are closed at the end) |
| Software | commit `8a0dd35b274b0d7ec6d26b056b22c6c7600209e8` |

A short test of this software on signet. Signet coins have no value.
Invited principals only (0); other requests are refused before any work.

Open a direct channel of 25,000 sat to the node (LND's minimum is 20,000), then follow pcp/RUN-SIGNET.md.
Cloudflare terminates TLS and sees the request, the offer and the encrypted result, never the key.
