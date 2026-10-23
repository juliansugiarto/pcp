# PCP sale window

| | |
|---|---|
| Seller URL | `https://types-process-clothing-request.trycloudflare.com` |
| Lightning node | `030e631c859d2885e93ff65d70f767cc8afc87437c727a7c6bcd555d178ed20d7b@bore.pub:46489` (signet) |
| Price | 1000 sat per sale (signet test coins) |
| Job | `sudoku9`, the default puzzle of `pcp-buy-risc0` |
| Guest image id | `cc6e7b82fb2da7bba9aa051331c0662ad123ac9821820c0daa34f4e942d0e328` |
| Opens | 2026-10-23T16:27:00Z |
| Closes | 2026-10-23T16:37:00Z (channels are closed at the end) |
| Software | commit `68e99baa8700770cbac507291bd9eed1e9bdbed7` |

A short test of this software on signet. Signet coins have no value.
Invited principals only (0); other requests are refused before any work.

Open a direct channel of at least 20,000 sat to the node, then follow pcp/RUN-SIGNET.md.
Cloudflare terminates TLS and sees the request, the offer and the encrypted result, never the key.
