#!/usr/bin/env bash
# The rehearsal buyer's LND on signet (neutrino), restored every run from
# one extended private key kept as the Actions secret REHEARSAL_BUYER_XPRV
# (design note 30, Fable review 32). The owner funded it once; the coins and
# the cooperative-close outputs come back through recovery in every run.
#
# Starts container `buyer` (REST on 127.0.0.1:8081, P2P 9736 not published),
# initialises the wallet from the key (never `--noseedbackup`, which would
# create another wallet), waits for chain sync AND wallet recovery, bakes the
# pay-only macaroon into creds-buyer/, and writes the public facts (node key,
# balances, a receiving address) to $OUT/buyer-wallet.txt.
# Usage: LND_IMAGE=... REHEARSAL_BUYER_XPRV=... bash buyer-wallet.sh
set -euo pipefail
: "${REHEARSAL_BUYER_XPRV:?the Actions secret REHEARSAL_BUYER_XPRV is not set}"
: "${LND_IMAGE:?}"
OUT=${OUT:-out}
mkdir -p "$OUT" creds-buyer
case "$REHEARSAL_BUYER_XPRV" in tprv*) ;; *) echo "REHEARSAL_BUYER_XPRV is not a tprv key (signet uses testnet version bytes)"; exit 1 ;; esac
# The key was made after this time; recovery scans from here.
birthday=$(date -u -d 2026-10-20T00:00:00Z +%s)
t0=$(date +%s)
docker run -d --name buyer -p 127.0.0.1:8081:8080 --entrypoint lnd "$LND_IMAGE" \
  --bitcoin.signet --bitcoin.node=neutrino --alias=pcp-rehearsal-buyer --debuglevel=info \
  --listen=0.0.0.0:9736 --restlisten=0.0.0.0:8080 --rpclisten=127.0.0.1:10009 \
  --tlsextradomain=localhost >/dev/null
ln() { docker exec buyer lncli --network=signet "$@"; }
for i in $(seq 60); do
  docker cp buyer:/root/.lnd/tls.cert creds-buyer/tls.cert 2>/dev/null \
    && curl -sS -m 5 --cacert creds-buyer/tls.cert https://127.0.0.1:8081/v1/state >/dev/null 2>&1 && break
  sleep 2
done
# The wallet password protects the wallet file inside this throwaway container only.
pw=$(head -c 24 /dev/urandom | base64 | tr -d '/+=')
umask 077
jq -n --arg pw "$(printf %s "$pw" | base64)" --arg k "$REHEARSAL_BUYER_XPRV" --arg b "$birthday" \
  '{wallet_password: $pw, extended_master_key: $k, extended_master_key_birthday_timestamp: $b, recovery_window: 250}' > creds-buyer/init.json
code=$(curl -sS -m 300 --cacert creds-buyer/tls.cert -X POST https://127.0.0.1:8081/v1/initwallet \
  -d @creds-buyer/init.json -o creds-buyer/init-response.json -w '%{http_code}' || echo 000)
rm -f creds-buyer/init.json
[ "$code" = 200 ] || { echo "initwallet: HTTP $code: $(jq -r '.message // empty' creds-buyer/init-response.json 2>/dev/null | head -c 200)"; exit 1; }
rm -f creds-buyer/init-response.json   # holds the admin macaroon
synced=""; recovered=""
for i in $(seq 240); do
  synced=$(ln getinfo 2>/dev/null | jq -r .synced_to_chain || true)
  recovered=$(ln getrecoveryinfo 2>/dev/null | jq -r .recovery_finished || true)
  [ "$synced" = true ] && [ "$recovered" = true ] && break
  sleep 5
done
[ "$synced" = true ] && [ "$recovered" = true ] || { echo "buyer LND: synced=$synced recovered=$recovered after 20 minutes"; exit 1; }
ln bakemacaroon --save_to /root/buyer.macaroon info:read offchain:read offchain:write >/dev/null
docker cp buyer:/root/buyer.macaroon creds-buyer/buyer.macaroon
info=$(ln getinfo); bal=$(ln walletbalance); addr=$(ln newaddress p2wkh | jq -r .address)
{
  echo "buyer node: $(jq -r .identity_pubkey <<<"$info")"
  echo "block height: $(jq -r .block_height <<<"$info")"
  echo "ready after: $(( $(date +%s) - t0 )) s (sync and recovery)"
  echo "confirmed_sat: $(jq -r .confirmed_balance <<<"$bal")"
  echo "unconfirmed_sat: $(jq -r .unconfirmed_balance <<<"$bal")"
  echo "receive address: $addr"
} | tee "$OUT/buyer-wallet.txt"
