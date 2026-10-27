#!/usr/bin/env bash
# The rehearsal's pass/fail checks (design note 30, Fable review 32), over
# files the workflow wrote. Each check prints PASS or FAIL; exit 1 if any
# fails. Kept apart from the workflow so each check can be shown to fail on
# planted inputs (red runs).
# Usage: check.sh OUT_DIR SELLER_LOG BUYER_LOG
#   OUT_DIR holds buyer-exit.txt, close.json (the buyer's closedchannels
#   entry for the channel), balance-before.txt, balance-after.txt,
#   open-fee.txt, buyer-peer.txt (the buyer's listpeers entry for the
#   seller), bore-ip.txt, window-ref-before.txt, window-ref-after.txt, price.txt.
set -uo pipefail
o=$1; slog=$2; blog=$3
fails=0
say() { printf '%-28s %s\n' "$1" "$2" | tee -a "$o/checks.txt"; [ "${2%% *}" = PASS ] || fails=$((fails + 1)); }
: > "$o/checks.txt"
# 1. The buyer exited 0 (delivered and checked).
[ "$(cat "$o/buyer-exit.txt" 2>/dev/null)" = 0 ] && say buyer-exit PASS || say buyer-exit "FAIL ($(cat "$o/buyer-exit.txt" 2>/dev/null))"
# 2. One deal on each side, for the same payment hash.
hashes() { python3 -c '
import json, sys
hs = [json.loads(l)["deal"]["receipt"]["payment_hash"] for l in open(sys.argv[1]) if l.strip() and "deal" in json.loads(l)]
print(" ".join(hs))' "$1" 2>/dev/null; }
sh=$(hashes "$slog"); bh=$(hashes "$blog")
echo "seller deals: $sh" > "$o/receipts.txt"; echo "buyer deals: $bh" >> "$o/receipts.txt"
[ -n "$sh" ] && [ "$sh" = "$bh" ] && [ "$(wc -w <<<"$sh")" = 1 ] && say receipts PASS || say receipts "FAIL (seller [$sh] buyer [$bh])"
# 3. The channel closed cooperatively and the close confirmed.
ct=$(jq -r '.close_type // empty' "$o/close.json" 2>/dev/null)
[ "$ct" = COOPERATIVE_CLOSE ] && say cooperative-close PASS || say cooperative-close "FAIL (${ct:-no close})"
# 4. The sats came back: loss = before - after = price + the funding fee
#    (recorded exactly from listchaintxns) + the cooperative close fee the
#    funder pays (about 9,700 sat at 50 sat/vB, static on neutrino, whatever
#    the channel size); 15,000 covers the close and rounding.
before=$(cat "$o/balance-before.txt" 2>/dev/null); after=$(cat "$o/balance-after.txt" 2>/dev/null)
price=$(cat "$o/price.txt" 2>/dev/null); fee_open=$(cat "$o/open-fee.txt" 2>/dev/null)
if [[ "$before" =~ ^[0-9]+$ && "$after" =~ ^[0-9]+$ && "$price" =~ ^[0-9]+$ && "$fee_open" =~ ^[0-9]+$ ]]; then
  loss=$((before - after))
  [ "$loss" -ge "$price" ] && [ "$loss" -le $((price + fee_open + 15000)) ] && say sats-returned "PASS (loss $loss sat, funding fee $fee_open)" || say sats-returned "FAIL (before $before after $after loss $loss price $price funding fee $fee_open)"
else
  say sats-returned "FAIL (balances or funding fee missing)"
fi
# 5. The buyer reached the seller over the public path: its own peer entry
#    for the seller is outbound, to bore.pub's address, not loopback or a
#    private range. (The seller's entry for the buyer always shows the local
#    bore client, so it proves nothing.)
addr=$(jq -r '.address // empty' "$o/buyer-peer.txt" 2>/dev/null)
inbound=$(jq -r '.inbound' "$o/buyer-peer.txt" 2>/dev/null)
host=${addr%:*}
case "$addr" in
  "" ) say public-path "FAIL (seller not a peer of the buyer)" ;;
  127.*|172.1[6-9].*|172.2[0-9].*|172.3[01].*|10.*|192.168.*|"[::1]"*|localhost*) say public-path "FAIL ($addr)" ;;
  *) if [ "$inbound" = false ] && { [ ! -s "$o/bore-ip.txt" ] || grep -qxF "$host" "$o/bore-ip.txt"; }; then
       say public-path "PASS ($addr, outbound)"
     else
       say public-path "FAIL ($addr inbound=$inbound, bore.pub $(tr '\n' ' ' < "$o/bore-ip.txt" 2>/dev/null))"
     fi ;;
esac
# 6. Nothing announced.
[ -n "$(cat "$o/window-ref-before.txt" 2>/dev/null)" ] && cmp -s "$o/window-ref-before.txt" "$o/window-ref-after.txt" \
  && say nothing-announced PASS || say nothing-announced FAIL
exit $((fails > 0))
