#!/usr/bin/env bash
# Record LND's raw REST behaviour for the calls the adapter makes, by hand
# with curl: AddHoldInvoice, the SendPaymentV2 stream (first lines, then the
# stream is dropped), LookupInvoice while held, SettleInvoice, and
# ListPayments after settlement. Output: $OUT/rest/probe-*.
set -uo pipefail
CREDS=${CREDS:-creds}
OUT=${OUT:-out}
mkdir -p "$OUT/rest"

mac() { xxd -p -c 10000 "$CREDS/$1/admin.macaroon"; }
rest() { # node port method path [body]
  local n=$1 port=$2 m=$3 path=$4 body=${5:-}
  curl -sS --cacert "$CREDS/$n/tls.cert" -H "Grpc-Metadata-macaroon: $(mac "$n")" \
    -X "$m" ${body:+-d "$body"} "https://127.0.0.1:$port$path"
}

k_hex=$(openssl rand -hex 32)
h_hex=$(printf '%s' "$k_hex" | xxd -r -p | sha256sum | cut -c1-64)
k_b64=$(printf '%s' "$k_hex" | xxd -r -p | base64 -w0)
h_b64=$(printf '%s' "$h_hex" | xxd -r -p | base64 -w0)
echo "k=$k_hex H=$h_hex"

rest bob 8082 POST /v2/invoices/hodl \
  "{\"hash\":\"$h_b64\",\"value_msat\":\"1000000\",\"expiry\":\"600\",\"cltv_expiry\":\"18\"}" \
  | tee "$OUT/rest/probe-1-hodl.json"; echo
pr=$(jq -r .payment_request "$OUT/rest/probe-1-hodl.json")

# The stream, for 6 seconds (the invoice is held, so it does not end).
curl -sS -N --max-time 6 --cacert "$CREDS/alice/tls.cert" -H "Grpc-Metadata-macaroon: $(mac alice)" \
  -X POST -d "{\"payment_request\":\"$pr\",\"timeout_seconds\":60,\"fee_limit_sat\":\"10\",\"cltv_limit\":40}" \
  https://127.0.0.1:8081/v2/router/send > "$OUT/rest/probe-2-send-stream.jsonl"
echo "stream lines: $(wc -l < "$OUT/rest/probe-2-send-stream.jsonl")"
jq -c '.result | {status, htlcs: [.htlcs[]? | {status, attempt_time_ns, total_time_lock: .route.total_time_lock}]}' \
  "$OUT/rest/probe-2-send-stream.jsonl"

sleep 1
rest bob 8082 GET "/v1/invoice/$h_hex" > "$OUT/rest/probe-3-invoice-held.json"
jq -c '{state, htlcs: [.htlcs[] | {state, amt_msat, expiry_height, accept_height}]}' "$OUT/rest/probe-3-invoice-held.json"
rest alice 8081 GET "/v1/payments?include_incomplete=true&reversed=true&max_payments=5" > "$OUT/rest/probe-4-payments-inflight.json"
jq -c --arg h "$h_hex" '.payments[] | select(.payment_hash==$h) | {status, payment_preimage, nhtlcs: (.htlcs|length)}' "$OUT/rest/probe-4-payments-inflight.json"

rest bob 8082 POST /v2/invoices/settle "{\"preimage\":\"$k_b64\"}" | tee "$OUT/rest/probe-5-settle.json"; echo
sleep 2
rest alice 8081 GET "/v1/payments?include_incomplete=true&reversed=true&max_payments=5" > "$OUT/rest/probe-6-payments-settled.json"
jq -c --arg h "$h_hex" '.payments[] | select(.payment_hash==$h) | {status, payment_preimage, nhtlcs: (.htlcs|length), htlc_resolve: [.htlcs[]?.resolve_time_ns]}' "$OUT/rest/probe-6-payments-settled.json"
rest bob 8082 GET "/v1/invoice/$h_hex" | jq -c '{state, settled, amt_paid_msat, htlcs: [.htlcs[] | {state, amt_msat}]}'
