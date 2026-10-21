#!/usr/bin/env bash
# After the sale: record what the two nodes say, as raw LND REST JSON, so
# the adapter's assumptions can be checked against real output.
set -uo pipefail
CREDS=${CREDS:-creds}
OUT=${OUT:-out}
mkdir -p "$OUT/rest"

rest() { # node port path [curl args...]
  local n=$1 port=$2 path=$3; shift 3
  curl -sS --cacert "$CREDS/$n/tls.cert" \
    -H "Grpc-Metadata-macaroon: $(xxd -p -c 10000 "$CREDS/$n/admin.macaroon")" \
    "https://127.0.0.1:$port$path" "$@"
}
lnc() { local n=$1; shift; docker exec "$n" lncli --network=regtest "$@"; }

for n in alice bob; do
  { echo "== $n channelbalance"; lnc "$n" channelbalance; echo "== $n listchannels"; lnc "$n" listchannels; } \
    > "$OUT/$n-state.txt" 2>&1
done

if [ -f "$CREDS/bob/admin.macaroon" ]; then
  rest bob 8082 /v1/invoices > "$OUT/rest/bob-v1-invoices.json"
  rest alice 8081 "/v1/payments?include_incomplete=true" > "$OUT/rest/alice-v1-payments.json"
  rest bob 8082 /v1/getinfo > "$OUT/rest/bob-v1-getinfo.json"
  last=$(jq -r '.invoices | last' "$OUT/rest/bob-v1-invoices.json")
  if [ "$last" != "null" ]; then
    bolt11=$(jq -r '.invoices | last | .payment_request' "$OUT/rest/bob-v1-invoices.json")
    hash_hex=$(jq -r '.invoices | last | .r_hash' "$OUT/rest/bob-v1-invoices.json" | base64 -d | xxd -p -c 64)
    rest alice 8081 "/v1/payreq/$bolt11" > "$OUT/rest/alice-v1-payreq.json"
    rest bob 8082 "/v1/invoice/$hash_hex" > "$OUT/rest/bob-v1-invoice-by-hash.json"
  fi
  # How LND answers a lookup for an invoice it does not have (the adapter
  # maps HTTP 404 to "no HTLC").
  rest bob 8082 "/v1/invoice/$(printf '%064d' 0)" -w '\nHTTP %{http_code}\n' > "$OUT/rest/bob-v1-invoice-unknown.txt"
fi

for c in bitcoind alice bob; do docker logs --tail 400 "$c" > "$OUT/docker-$c.log" 2>&1 || true; done
ls -la "$OUT" "$OUT/rest"
