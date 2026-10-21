#!/usr/bin/env bash
# Record balances and, after a sale, the LND state of that sale's payment:
# bob's (seller) last non-warm-up invoice, looked up by its payment hash,
# the decoded BOLT11, and alice's (buyer) payment to the same hash.
# Usage: sale-state.sh <label>. Output: $OUT/state-<label>.txt. Never fails.
set -uo pipefail
OUT=${OUT:-out}
label=${1:?label}
f="$OUT/state-$label.txt"
btc() { docker exec bitcoind bitcoin-cli -regtest -rpcuser=pcp -rpcpassword=pcp "$@"; }
lnc() { local n=$1; shift; docker exec "$n" lncli --network=regtest "$@"; }

{
  echo "== $label at $(date -u +%FT%TZ), block height $(btc getblockcount)"
  for n in alice bob; do
    echo "== $n channelbalance"
    lnc "$n" channelbalance | jq -c '{local_balance, remote_balance}'
    echo "== $n walletbalance"
    lnc "$n" walletbalance | jq -c '{confirmed_balance, unconfirmed_balance}'
  done
  inv=$(lnc bob listinvoices --max_invoices 100 | jq -c '[.invoices[] | select(.memo != "warmup")] | last')
  if [ -n "$inv" ] && [ "$inv" != "null" ]; then
    hash=$(jq -r .r_hash <<<"$inv")
    echo "== sale payment hash $hash"
    echo "== bob lookupinvoice"
    lnc bob lookupinvoice "$hash" | jq '{state, is_keysend, value_msat, amt_paid_msat, creation_date, settle_date, expiry, cltv_expiry, description_hash, r_preimage, htlcs: [.htlcs[] | {state, amt_msat, accept_height, resolve_height, expiry_height}]}'
    echo "== alice decodepayreq"
    lnc alice decodepayreq "$(jq -r .payment_request <<<"$inv")" | jq -c .
    echo "== alice payment to this hash"
    lnc alice listpayments --include_incomplete | jq --arg h "$hash" '[.payments[] | select(.payment_hash == $h) | {status, value_msat, fee_msat, payment_preimage, creation_time_ns, failure_reason, htlcs: [.htlcs[] | {status, attempt_time_ns, resolve_time_ns, route: {total_time_lock: .route.total_time_lock}}]}]'
    pre=$(lnc alice listpayments --include_incomplete | jq -r --arg h "$hash" '[.payments[] | select(.payment_hash == $h)] | last | .payment_preimage // empty')
    if [ -n "$pre" ] && [ "$pre" != "0000000000000000000000000000000000000000000000000000000000000000" ]; then
      echo "== sha256(preimage) = $(printf '%s' "$pre" | xxd -r -p | sha256sum | cut -c1-64) (hash $hash)"
    fi
  else
    echo "== no sale invoice yet"
  fi
} > "$f" 2>&1
cat "$f"
exit 0
