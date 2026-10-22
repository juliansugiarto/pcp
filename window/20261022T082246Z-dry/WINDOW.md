# PCP sale window

| | |
|---|---|
| Seller URL | `https://aging-scenarios-permissions-passion.trycloudflare.com` |
| Lightning node | `03ad244a2b47ca498f8c5723a1758775e0f7ff3616cfa089b8159541efbd79746a@bore.pub:65120` (signet) |
| Price | 1000 sat per sale (signet test coins) |
| Job | `sudoku9`, the default puzzle of `pcp-buy-risc0` |
| Guest image id | `cc6e7b82fb2da7bba9aa051331c0662ad123ac9821820c0daa34f4e942d0e328` |
| Opens | 2026-10-22T08:11:33Z |
| Closes | 2026-10-22T08:21:33Z (channels are closed at the end) |
| Software | commit `7975f384e907b87ff7bb9bc824ffb76ef0b42222` |

A short test of this software on signet. Signet coins have no value.

Open a direct channel of at least 20,000 sat to the node, then follow pcp/RUN-SIGNET.md.
Cloudflare terminates TLS and sees the request, the offer and the encrypted result, never the key.
