#!/usr/bin/env bash
# Two-process PCP sales, killed and restarted at every named crash point.
#
#   pcp/tools/crash-matrix.sh OUT [CASE...]
#
# Rail: the TEST-ONLY simulated network file by default. With RAIL=lnd the
# buyer and seller use two LND nodes, configured by
# PCP_{BUYER,SELLER}_LND_{REST_URL,MACAROON,TLS_CERT} (see
# .github/workflows/lnd-regtest.yml). Build with --features lnd.
#
# For each case: set up a fresh buyer and seller, run both as separate
# processes with separate state directories, abort one of them at the
# named point (PCP_CRASH_AT), restart it once without the crash point, and
# wait for both to finish. A case passes only if:
#   - the process really died at its point (exit 134 first);
#   - both processes then exit as expected (buyer 0 when delivered, seller 0);
#   - pcp-audit passes on both state directories (log verifies, one receipt
#     per settled payment hash and none otherwise, the cap equals what the
#     log sold or paid, the refusals expected);
#   - on the simulated network, the buyer paid exactly the price if and
#     only if delivered, and the seller received it;
#   - the seller's k appears in no file outside the two state directories
#     and the simulated network file (which holds k after settlement, as a
#     node does).
#
# CASE names: clean, repeat-accept, tampered-accept, buyer-gone,
# buyer-node-down (LND only, needs BUYER_NODE_STOP and BUYER_NODE_START
# commands), and every crash point (seller:offer:pre ...). Default: all.
# Prints one line per case and writes OUT/summary.txt. Exit 0 only if every
# case passed. Needs bash, timeout and python3.

set -u
OUT=${1:?usage: crash-matrix.sh OUT [CASE...]}
shift
command -v python3 >/dev/null || { echo "crash-matrix.sh needs python3"; exit 2; }
BIN=${BIN:-$(cd "$(dirname "$0")/.." && pwd)/target/debug}
RAIL=${RAIL:-sim}
TIMEOUT=${TIMEOUT:-120}
# The seller and buyer programs. Any program taking pcp-sell / pcp-buy's
# options works, e.g. the RISC Zero host: SELL_BIN=.../pcp-risc0
# SELL_PRE="--role sell" (real proofs).
SELL_BIN=${SELL_BIN:-$BIN/pcp-sell}
BUY_BIN=${BUY_BIN:-$BIN/pcp-buy}
read -r -a SELL_PRE <<<"${SELL_PRE:-}"
read -r -a BUY_PRE <<<"${BUY_PRE:-}"
PRICE=1000000
FUNDS=100000000
mkdir -p "$OUT"
OUT=$(cd "$OUT" && pwd)

POINTS="seller:offer:pre seller:offer:post seller:accept:pre seller:accept:post
seller:k:pre seller:k:post seller:invoice:pre seller:invoice:post seller:settle:pre
seller:settle:post buyer:request:post buyer:offer:pre buyer:accept:post
buyer:invoice:pre buyer:paying:post buyer:pay:pre buyer:pay:post buyer:settle:pre
buyer:settle:post"
# buyer-node-down restarts the buyer's node, so it runs last.
LAST=""
[ "$RAIL" = lnd ] && [ -n "${BUYER_NODE_STOP:-}" ] && LAST=buyer-node-down
CASES=${*:-clean repeat-accept tampered-accept buyer-gone $POINTS $LAST}

# supervise MODE POINT LOG CMD...: run CMD and echo its exit codes.
#   normal:    with PCP_CRASH_AT=POINT; if it aborted (134), run it again.
#   once:      with PCP_CRASH_AT=POINT, no restart.
#   node-down: crash at POINT; restart paused just after resuming; stop the
#              buyer's node during the pause, let the buyer run without it,
#              start the node again; wait for the buyer.
supervise() {
  local mode=$1 point=$2 log=$3
  shift 3
  if [ -z "$point" ]; then
    timeout "$TIMEOUT" "$@" >>"$log" 2>&1
    echo "$?"
    return
  fi
  PCP_CRASH_AT=$point timeout "$TIMEOUT" "$@" >>"$log" 2>&1
  local c=$?
  if [ "$mode" = once ] || [ $c -ne 134 ]; then echo "$c"; return; fi
  echo "--- restarted after $point ---" >>"$log"
  if [ "$mode" = node-down ]; then
    PCP_PAUSE_AT=buyer:resumed:8 timeout "$TIMEOUT" "$@" >>"$log" 2>&1 &
    local pid=$!
    sleep 3
    echo "--- buyer node stopped ---" >>"$log"
    bash -c "$BUYER_NODE_STOP" >>"$log" 2>&1
    sleep 20
    echo "--- buyer node started ---" >>"$log"
    bash -c "$BUYER_NODE_START" >>"$log" 2>&1
    wait $pid
    echo "$c $?"
    return
  fi
  timeout "$TIMEOUT" "$@" >>"$log" 2>&1
  echo "$c $?"
}

last_code() { awk '{print $NF}' "$1"; }
first_code() { awk '{print $1}' "$1"; }

run_case() {
  local name=$1
  local dir="$OUT/${name//:/_}"
  rm -rf "$dir" && mkdir -p "$dir"
  local sim="$dir/sim.json"
  local seller_rail buyer_rail
  if [ "$RAIL" = lnd ]; then
    seller_rail=lnd; buyer_rail=lnd
    "$BIN/pcp-setup" --root "$dir" --seller-node from-env:PCP_SELLER_LND_ \
      --buyer-node from-env:PCP_BUYER_LND_ >"$dir/setup.txt" 2>&1
  else
    seller_rail="sim:$sim:seller"; buyer_rail="sim:$sim:buyer"
    "$BIN/pcp-setup" --root "$dir" --seller-node seller --buyer-node buyer \
      --sim "$sim" --buyer-funds-msat $FUNDS >"$dir/setup.txt" 2>&1
  fi
  local sp="" bp="" bmode=normal extra=() sextra=()
  local expect_state=Delivered expect_settled=1 expect_proofs=1 expect_reason=""
  local buyer_exit=0 audit_buyer=1
  # A repeat is answered, never refused: no refusal in either log.
  local brefusals=(--expect-refusals 0) srefusals=(--expect-refusals 0)
  case $name in
    # The seller works for 3 s while the buyer resends its accept.
    repeat-accept) extra=(--resend-secs 0); sextra=(--work-delay-ms 3000) ;;
    # An accept for an offer the seller never issued: no proof, no sale.
    # The buyer may resend before it reads the refusal, so the seller logs
    # at least one refusal.
    tampered-accept)
      extra=(--tamper-accept); buyer_exit=11
      expect_state=Aborted; expect_settled=0; expect_proofs=0
      expect_reason=refused_by_counterparty.offer_not_issued
      brefusals=(--expect-refusals 1); srefusals=(--min-refusals 1) ;;
    # The buyer dies holding a checked invoice and never comes back: the
    # seller must end the sale when the invoice expires.
    buyer-gone)
      bp=buyer:invoice:pre; bmode=once; buyer_exit=134; audit_buyer=0; expect_state=Gone
      sextra=(--invoice-expiry-secs 75); expect_settled=0
      srefusals=(--expect-refusals 1) ;;
    # LND only: the buyer dies right after paying; it is restarted while
    # its node is up, and its node is stopped while it runs. It must stay
    # Paying with the price held (lookups fail), then finish when the node
    # is back.
    buyer-node-down) bp=buyer:pay:pre; bmode=node-down ;;
    seller:*) sp=$name ;;
    buyer:*) bp=$name ;;
  esac
  local allow=()
  [ "$RAIL" = sim ] && allow=(--allow-sim)
  (
    if [ "$RAIL" = lnd ]; then
      export PCP_LND_REST_URL=$PCP_SELLER_LND_REST_URL PCP_LND_MACAROON=$PCP_SELLER_LND_MACAROON PCP_LND_TLS_CERT=$PCP_SELLER_LND_TLS_CERT
    fi
    supervise normal "$sp" "$dir/seller.log" "$SELL_BIN" "${SELL_PRE[@]}" --state "$dir/seller" \
      --inbox "$dir/seller-inbox" --peer-inbox "$dir/buyer-inbox" --rail "$seller_rail" \
      "${allow[@]}" "${sextra[@]}" --quiet-exit-secs 20 --deadline-secs "$TIMEOUT" >"$dir/seller.codes"
  ) &
  local spid=$!
  (
    if [ "$RAIL" = lnd ]; then
      export PCP_LND_REST_URL=$PCP_BUYER_LND_REST_URL PCP_LND_MACAROON=$PCP_BUYER_LND_MACAROON PCP_LND_TLS_CERT=$PCP_BUYER_LND_TLS_CERT
    fi
    supervise "$bmode" "$bp" "$dir/buyer.log" "$BUY_BIN" "${BUY_PRE[@]}" --state "$dir/buyer" \
      --inbox "$dir/buyer-inbox" --peer-inbox "$dir/seller-inbox" --rail "$buyer_rail" \
      "${allow[@]}" --resend-secs 1 --deadline-secs "$TIMEOUT" "${extra[@]}" >"$dir/buyer.codes"
  )
  wait $spid
  local problems=()

  # The crash point was reached, and both processes ended as expected.
  if [ -n "$sp" ] && [ "$(first_code "$dir/seller.codes")" != 134 ]; then problems+=(point-missed); fi
  if [ -n "$bp" ] && [ "$(first_code "$dir/buyer.codes")" != 134 ]; then problems+=(point-missed); fi
  [ "$(last_code "$dir/seller.codes")" = 0 ] || problems+=(seller-exit)
  [ "$(last_code "$dir/buyer.codes")" = "$buyer_exit" ] || problems+=(buyer-exit)

  # Audits.
  if [ $audit_buyer = 1 ]; then
    local bargs=(--state "$dir/buyer" --expect-state "$expect_state" "${brefusals[@]}" --out "$dir/audit-buyer.json")
    [ -n "$expect_reason" ] && bargs+=(--expect-reason "$expect_reason")
    "$BIN/pcp-audit" "${bargs[@]}" >/dev/null 2>"$dir/audit-buyer.err" || problems+=(audit-buyer)
  fi
  "$BIN/pcp-audit" --state "$dir/seller" --expect-settled "$expect_settled" \
    --expect-proofs "$expect_proofs" "${srefusals[@]}" --out "$dir/audit-seller.json" \
    >/dev/null 2>"$dir/audit-seller.err" || problems+=(audit-seller)

  # buyer-node-down: the buyer ran while its node was down and did not move.
  if [ "$bmode" = node-down ]; then
    grep -q "payment status unknown" "$dir/buyer.log" || problems+=(node-down-not-seen)
    grep -q "payment never left" "$dir/buyer.log" && problems+=(node-down-released)
  fi

  # Money on the simulated network: the price moved iff delivered.
  if [ "$RAIL" = sim ]; then
    local want_b=$FUNDS want_s=0
    if [ "$expect_state" = Delivered ]; then want_b=$((FUNDS - PRICE)); want_s=$PRICE; fi
    local got
    got=$(python3 -c 'import json,sys; b=json.load(open(sys.argv[1]))["ledger"]["balances"]; print(b["buyer"], b["seller"])' "$sim" 2>&1)
    [ "$got" = "$want_b $want_s" ] || problems+=("balance:$got")
  fi

  # The seller's k must not appear outside the two state directories and
  # the simulated network.
  local keys
  keys=$(python3 -c 'import json,sys; print(" ".join(s["key"] for s in json.load(open(sys.argv[1]))["state"]["sales"]))' "$dir/seller/state.json") \
    || problems+=(no-seller-state)
  for k in $keys; do
    if grep -rl "$k" "$dir" --exclude-dir=seller --exclude-dir=buyer --exclude=sim.json >/dev/null 2>&1; then
      problems+=(k-leak)
    fi
  done

  local status=PASS
  [ ${#problems[@]} -eq 0 ] || status=FAIL
  local line
  line=$(printf '%-22s %s  buyer exits [%s] seller exits [%s] %s' "$name" "$status" \
    "$(cat "$dir/buyer.codes")" "$(cat "$dir/seller.codes")" "${problems[*]:-}")
  echo "$line" | tee -a "$OUT/summary.txt"
  [ $status = PASS ]
}

: >"$OUT/summary.txt"
fail=0
for c in $CASES; do
  run_case "$c" || fail=1
done
echo "rail=$RAIL cases=$(echo $CASES | wc -w) failed=$(grep -c FAIL "$OUT/summary.txt")" | tee -a "$OUT/summary.txt"
exit $fail
