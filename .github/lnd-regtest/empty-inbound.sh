#!/usr/bin/env bash
# Can a node with an empty wallet accept an inbound channel? A sale window's
# node starts with no coins and relies on the buyer opening the channel to
# it. LND keeps a reserve for anchor channels, so check it on regtest:
# start `carol` with nothing, let alice (funded by up.sh) open a channel to
# her, and wait until it is active on carol's side. Prints `active: yes`.
set -euo pipefail

: "${LND_IMAGE:?}"
log() { echo "[$(date -u +%H:%M:%S)] $*"; }
btc() { docker exec bitcoind bitcoin-cli -regtest -rpcuser=pcp -rpcpassword=pcp "$@"; }
lnc() { local n=$1; shift; docker exec "$n" lncli --network=regtest "$@"; }

docker run -d --name carol --network pcpnet --entrypoint lnd "$LND_IMAGE" \
  --noseedbackup --alias=carol --debuglevel=info \
  --bitcoin.regtest --bitcoin.node=bitcoind \
  --bitcoind.rpchost=bitcoind:18443 --bitcoind.rpcuser=pcp --bitcoind.rpcpass=pcp \
  --bitcoind.zmqpubrawblock=tcp://bitcoind:28332 --bitcoind.zmqpubrawtx=tcp://bitcoind:28333 \
  --listen=0.0.0.0:9735 --rpclisten=0.0.0.0:10009 --restlisten=0.0.0.0:8080 >/dev/null
for _ in $(seq 120); do
  [ "$(lnc carol getinfo 2>/dev/null | jq -r .synced_to_chain)" = true ] && break
  sleep 1
done
CAROL=$(lnc carol getinfo | jq -r .identity_pubkey)
log "carol $CAROL, wallet: $(lnc carol walletbalance | jq -c '{total_balance}')"

lnc alice connect "$CAROL@carol:9735" >/dev/null
open=$(lnc alice openchannel --node_key "$CAROL" --local_amt 100000 2>&1) || true
echo "openchannel: $(echo "$open" | tr '\n' ' ' | cut -c1-300)"
MINER=$(btc -rpcwallet=miner getnewaddress)
btc generatetoaddress 6 "$MINER" >/dev/null
for _ in $(seq 60); do
  n=$(lnc carol listchannels --active_only | jq '.channels | length')
  [ "$n" -ge 1 ] && break
  sleep 1
done
lnc carol listchannels | jq -c '[.channels[] | {active, capacity, local_balance, commitment_type}]'
echo "active: $([ "${n:-0}" -ge 1 ] && echo yes || echo no)"
[ "${n:-0}" -ge 1 ]
