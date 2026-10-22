# PCP sale window

| | |
|---|---|
| Seller URL | `https://sbjct-total-multiple-wing.trycloudflare.com` |
| Lightning node | `02cf42124604b279e28ffdc94a79c4f1db465599bab6ed0c037a01babee7717b3f@bore.pub:11390` (signet) |
| Price | 1000 sat per sale (signet test coins) |
| Job | `sudoku9`, the default puzzle of `pcp-buy-risc0` |
| Guest image id | `cc6e7b82fb2da7bba9aa051331c0662ad123ac9821820c0daa34f4e942d0e328` |
| Opens | 2026-10-22T08:31:17Z |
| Closes | 2026-10-22T08:41:17Z (channels are closed at the end) |
| Software | commit `271ff96b4a01b2cd13544dada7c5e444a9ad7fc5` |

A short test of this software on signet. Signet coins have no value.

Open a direct channel of at least 20,000 sat to the node, then follow pcp/RUN-SIGNET.md.
Cloudflare terminates TLS and sees the request, the offer and the encrypted result, never the key.
