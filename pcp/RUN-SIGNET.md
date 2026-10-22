# Buying from a PCP sale window on signet

A sale window is a PCP seller that runs for a few announced hours on Bitcoin's signet test network. It sells one thing: the solution of a 9x9 sudoku, encrypted, with a RISC Zero proof that the ciphertext decrypts to a valid solution under the key that settles your payment. You check the proof before you pay. You pay a Lightning hold invoice; settling it gives you the key.

A short test of this software. Signet coins have no value. Not audited. One seller, one proof at a time.

**What others see.** The window's HTTPS endpoint is a Cloudflare quick tunnel: Cloudflare terminates TLS and sees your request, the offer and the encrypted result, never the key. The Lightning port goes through bore, a plain TCP relay; Lightning's own transport is encrypted and authenticated, so bore sees only ciphertext. The node is fresh for every window and closes its channels at the end.

Plan on about an hour: most of it is building, syncing and three channel confirmations (signet blocks come about every 10 minutes).

## 1. Is a window open?

Read `WINDOW.md` on the `window` branch of this repository. It gives the seller URL, the node (`pubkey@bore.pub:port`), the price, the guest image id, the closing time and the commit of the software. If it says closed, no window is open.

## 2. Build the buyer

Rust stable and git. No RISC Zero toolchain, no Docker for this step.

```bash
git clone https://github.com/juliansugiarto/pcp && cd pcp
git checkout <commit from WINDOW.md>
(cd pcp-risc0 && cargo build --release -p pcp-risc0-verify --features lnd,http)
(cd pcp && cargo build --release --features lnd --bin pcp-setup --bin pcp-audit)
grep -A1 'PINNED_IMAGE_ID' pcp-risc0/verify/src/lib.rs
```

The id printed last must equal the guest image id in `WINDOW.md`. `pcp-risc0/IMAGE-ID.md` explains what it is and how to rebuild the guest yourself and compare. The verify-only buyer took 76 s to build on a 4-vCPU CI runner.

## 3. An LND node on signet

Any LND you control on signet works. With Docker:

```bash
docker run -d --name buyer-lnd -p 127.0.0.1:8080:8080 --entrypoint lnd lightninglabs/lnd:v0.21.4-beta \
  --bitcoin.signet --bitcoin.node=neutrino --restlisten=0.0.0.0:8080 --tlsextradomain=localhost
docker exec -it buyer-lnd lncli --network=signet create     # write the seed down
# after every restart of the container: docker exec -it buyer-lnd lncli --network=signet unlock
docker exec buyer-lnd lncli --network=signet getinfo | grep synced_to_chain   # wait for true
docker exec buyer-lnd lncli --network=signet newaddress p2wkh
```

Neutrino synced signet in 172 s on a CI runner. Send the address some signet coins from a signet faucet (search "signet faucet"; most ask you to solve a captcha). 70,000 sat is enough: 50,000 for the channel, the on-chain fee, and the 10,000 sat LND keeps in reserve for anchor channels.

## 4. A channel to the window's node

```bash
docker exec buyer-lnd lncli --network=signet connect <pubkey>@bore.pub:<port>
docker exec buyer-lnd lncli --network=signet openchannel --node_key <pubkey> --local_amt 50000
docker exec buyer-lnd lncli --network=signet listchannels | grep '"active"'   # after 3 blocks: true
```

The channel must be direct: the window's node has no other channels, so your channel is the only way to reach it.

## 5. A macaroon that can only pay

```bash
docker exec buyer-lnd lncli --network=signet bakemacaroon --save_to /root/buyer.macaroon \
  info:read offchain:read offchain:write
docker cp buyer-lnd:/root/buyer.macaroon . && docker cp buyer-lnd:/root/.lnd/tls.cert .
export PCP_LND_REST_URL=https://127.0.0.1:8080 PCP_LND_TLS_CERT=$PWD/tls.cert PCP_LND_MACAROON=$PWD/buyer.macaroon
```

## 6. Your buyer agent and its limits

```bash
PCP_BUYER_LND_REST_URL=$PCP_LND_REST_URL PCP_BUYER_LND_TLS_CERT=$PCP_LND_TLS_CERT \
PCP_BUYER_LND_MACAROON=$PCP_LND_MACAROON \
  ./pcp/target/release/pcp-setup --root pcp-run --buyer-node from-env:PCP_BUYER_LND_ --buyer-only
```

This makes you a principal key (`pcp-run/buyer-principal.key`, kept outside the agent's directory), an agent key and a mandate: at most 10,000 sat per deal and 50,000 sat in total, for a week. The agent cannot spend beyond it.

## 7. Buy

```bash
./pcp-risc0/target/release/pcp-buy-risc0 --state pcp-run/buyer --seller-url <URL from WINDOW.md> --rail lnd
```

What happens, in order: your agent sends a signed request; the seller answers with an offer naming the guest image id, which your buyer checks against its pinned id; your agent accepts; the seller proves (about 100 s; meanwhile the buyer asks again every few seconds and gets `202`); your buyer verifies the proof and the invoice offline, before any payment; it pays; the seller settles; your buyer decrypts the result and checks it again. It prints the solved grid and exits 0.

The default limit is 2,000 sat per purchase (`--max-price-msat`). If the buyer is stopped, run the same command again: it resumes from `pcp-run/buyer`.

One state directory holds one purchase. Once it ends (delivered, refunded or aborted), running the command again only prints the outcome. For another purchase make a new agent: `pcp-setup --root pcp-run2 --buyer-node from-env:PCP_BUYER_LND_ --buyer-only`, then `--state pcp-run2/buyer`.

Check your log afterwards:

```bash
./pcp/target/release/pcp-audit --state pcp-run/buyer --expect-state Delivered
```

## 8. Afterwards

The window closes its channels when it ends. If it could not close yours cooperatively it force-closes, and your side of the channel comes back to your wallet on chain; as the one who opened the channel, you pay its closing fee. You can also close it yourself: `lncli closechannel`.

## What you risk, and what to keep private

- Your payment is a hold invoice. If the seller never settles it (it stopped, or the window ended mid-sale), the payment stays locked in your channel until its HTLC times out and then returns to you (exit code 10). Over a direct channel that is the invoice's final delta, 24 blocks (about 4 hours on signet); the buyer accepts no lock longer than 204 blocks.
- The buyer pays only after it has verified the proof and the invoice. It never pays an offer that names another guest or has expired.
- `pcp-run/buyer` holds your agent key and the result; `pcp-run/buyer-principal.key` is your principal key. Keep both private.

## When something goes wrong

| You see | Meaning |
|---|---|
| `202` or `HTTP 503 (will ask again)` | The seller is proving or busy. Normal; the buyer keeps asking |
| `offer refused: backend_not_accepted` | The offer names another guest than your pinned id. Do not pass `--image-id` from the offer |
| `refused_by_counterparty.seller_busy` | Another buyer is being served. Try again in a few minutes |
| `price_too_high` | The price is above `--max-price-msat` |
| `certificate verify failed` | The URL is wrong or not the window's. Use the URL from `WINDOW.md` exactly |
| `no_answer` | No offer came: the window is closed or unreachable |
| A payment that does not leave | No active direct channel to the window's node, or too little in it |
| `unknown option` | A typo in an option name; options are refused rather than ignored |
| `HTTP 404 ... 1 of 3 before giving up` | The URL path is wrong, or the tunnel is changing. Three such answers in a row stop the buyer; run it again with the URL from `WINDOW.md` |

Exit codes: 0 delivered, 10 refunded (the payment timed out and came back), 11 aborted (refused or gave up), 1 stopped by an error, 2 a usage error (a missing or unknown option).
