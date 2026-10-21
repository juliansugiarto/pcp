#!/usr/bin/env bash
# Start bitcoind (regtest) and two LND nodes in Docker, fund alice, open a
# channel alice -> bob and wait until it is active on both sides.
# alice = buyer principal's node (REST on 127.0.0.1:8081)
# bob   = seller principal's node (REST on 127.0.0.1:8082)
# Credentials are copied to $CREDS/{alice,bob}/{tls.cert,admin.macaroon}.
set -euo pipefail

: "${LND_IMAGE:?}" "${BTC_IMAGE:?}"
CREDS=${CREDS:-creds}

log() { echo "[$(date -u +%H:%M:%S)] $*"; }
btc() { docker exec bitcoind bitcoin-cli -regtest -rpcuser=pcp -rpcpassword=pcp "$@"; }
lnc() { local n=$1; shift; docker exec "$n" lncli --network=regtest "$@"; }
mine() { btc generatetoaddress "$1" "$MINER" >/dev/null; }

docker pull -q "$BTC_IMAGE"
docker pull -q "$LND_IMAGE"
log "bitcoind image $BTC_IMAGE $(docker image inspect --format '{{index .RepoDigests 0}}' "$BTC_IMAGE")"
log "lnd image      $LND_IMAGE $(docker image inspect --format '{{index .RepoDigests 0}}' "$LND_IMAGE")"

docker network create pcpnet >/dev/null
docker run -d --name bitcoind --network pcpnet --entrypoint bitcoind "$BTC_IMAGE" \
  -regtest -server -txindex -printtoconsole \
  -rpcuser=pcp -rpcpassword=pcp -rpcbind=0.0.0.0 -rpcallowip=0.0.0.0/0 \
  -zmqpubrawblock=tcp://0.0.0.0:28332 -zmqpubrawtx=tcp://0.0.0.0:28333 \
  -fallbackfee=0.0002 >/dev/null
for _ in $(seq 60); do btc getblockchaininfo >/dev/null 2>&1 && break; sleep 1; done
log "bitcoind $(btc getnetworkinfo | jq -r .subversion)"

start_lnd() {
  docker run -d --name "$1" --network pcpnet -p "127.0.0.1:$2:8080" --entrypoint lnd "$LND_IMAGE" \
    --noseedbackup --alias="$1" --debuglevel=info \
    --bitcoin.regtest --bitcoin.node=bitcoind \
    --bitcoind.rpchost=bitcoind:18443 --bitcoind.rpcuser=pcp --bitcoind.rpcpass=pcp \
    --bitcoind.zmqpubrawblock=tcp://bitcoind:28332 --bitcoind.zmqpubrawtx=tcp://bitcoind:28333 \
    --listen=0.0.0.0:9735 --rpclisten=0.0.0.0:10009 --restlisten=0.0.0.0:8080 \
    --tlsextradomain="$1" --trickledelay=1000 >/dev/null
}
start_lnd alice 8081
start_lnd bob 8082

btc createwallet miner >/dev/null
MINER=$(btc -rpcwallet=miner getnewaddress)
mine 101

wait_synced() {
  for _ in $(seq 120); do
    if [ "$(lnc "$1" getinfo 2>/dev/null | jq -r .synced_to_chain)" = "true" ]; then return 0; fi
    sleep 1
  done
  echo "$1 did not sync"; docker logs --tail 80 "$1"; return 1
}
wait_synced alice
wait_synced bob
log "lnd $(lnc alice getinfo | jq -r .version)"

ALICE_ADDR=$(lnc alice newaddress p2wkh | jq -r .address)
btc -rpcwallet=miner sendtoaddress "$ALICE_ADDR" 1 >/dev/null
mine 6
for _ in $(seq 60); do
  [ "$(lnc alice walletbalance | jq -r .confirmed_balance)" != "0" ] && break; sleep 1
done
log "alice wallet $(lnc alice walletbalance | jq -c '{confirmed_balance}')"

BOB_PK=$(lnc bob getinfo | jq -r .identity_pubkey)
ALICE_PK=$(lnc alice getinfo | jq -r .identity_pubkey)
log "alice $ALICE_PK"
log "bob   $BOB_PK"
lnc alice connect "$BOB_PK@bob:9735" >/dev/null
for _ in $(seq 30); do
  [ "$(lnc alice listpeers | jq '.peers | length')" -ge 1 ] && break; sleep 1
done
lnc alice openchannel --node_key="$BOB_PK" --local_amt=1000000 | jq -c .
mine 6
active() { lnc "$1" listchannels --active_only | jq '.channels | length'; }
for _ in $(seq 120); do
  if [ "$(active alice)" -ge 1 ] && [ "$(active bob)" -ge 1 ]; then break; fi
  sleep 1
done
[ "$(active alice)" -ge 1 ] && [ "$(active bob)" -ge 1 ] || { echo "channel not active"; exit 1; }
wait_synced alice
wait_synced bob
log "channel active; height $(btc getblockcount)"

# A channel can be listed active a moment before its link forwards: the
# first run's sale payment, sent within a second, failed with
# FAILURE_REASON_INSUFFICIENT_BALANCE and no HTLC. So pay one ordinary 1-sat
# invoice first and wait until it settles.
ready=""
for _ in $(seq 30); do
  inv=$(lnc bob addinvoice --amt 1 --memo warmup)
  lnc alice payinvoice --force --pay_req="$(jq -r .payment_request <<<"$inv")" --timeout 20s >/dev/null 2>&1 || true
  if [ "$(lnc bob lookupinvoice "$(jq -r .r_hash <<<"$inv")" | jq -r .state)" = "SETTLED" ]; then ready=1; break; fi
  sleep 1
done
[ -n "$ready" ] || { echo "warm-up payment never settled"; exit 1; }
log "warm-up payment settled"
lnc alice channelbalance | jq -c '{local_balance, remote_balance}'

for n in alice bob; do
  mkdir -p "$CREDS/$n"
  docker cp "$n:/root/.lnd/tls.cert" "$CREDS/$n/tls.cert"
  docker cp "$n:/root/.lnd/data/chain/bitcoin/regtest/admin.macaroon" "$CREDS/$n/admin.macaroon"
done
openssl x509 -in "$CREDS/bob/tls.cert" -noout -subject -ext subjectAltName || true
log "ready"
