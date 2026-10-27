# PCP sale window

| | |
|---|---|
| Seller URL | `https://receiver-conversion-aspects-breed.trycloudflare.com` |
| Lightning node | `023cf4d219098f636c2472f05a6653951b9167461d5f78ac90ac3853d56143e7f7@bore.pub:32514` (signet) |
| Price | 1000 sat per sale (signet test coins) |
| Job | `sudoku9`, the default puzzle of `pcp-buy-risc0` |
| Guest image id | `cc6e7b82fb2da7bba9aa051331c0662ad123ac9821820c0daa34f4e942d0e328` |
| Opens | 2026-10-27T09:44:11Z |
| Closes | 2026-10-27T11:44:11Z (channels are closed at the end) |
| Software | commit `08955b2619d06e59930c96179f313b6e0442e9d0` |

A short test of this software on signet. Signet coins have no value.
Invited principals only (0); other requests are refused before any work.

Open a direct channel of at least 20,000 sat to the node, then follow pcp/RUN-SIGNET.md.
Cloudflare terminates TLS and sees the request, the offer and the encrypted result, never the key.
