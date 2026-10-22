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
# named point (PCP_CRASH_AT), restart it once without the crash point,
# and wait for both to finish. Then pcp-audit checks both state
# directories, and the seller's k is searched for in every file outside
# the two state directories and the simulated network.
#
# Prints one line per case and writes OUT/summary.txt. Exit 0 only if every
# case passed. CASE names: clean, repeat-accept, tampered-accept, buyer-gone,
# buyer-node-down (LND only, needs BUYER_NODE_STOP and BUYER_NODE_START
# commands), and every crash point (seller:offer:pre ...). Default: all.

set -u
OUT=${1:?usage: crash-matrix.sh OUT [CASE...]}
shift
BIN=${BIN:-$(cd "$(dirname "$0")/.." && pwd)/target/debug}
RAIL=${RAIL:-sim}
TIMEOUT=${TIMEOUT:-120}
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

# Run "$@" with PCP_CRASH_AT=$point; if it aborted there (exit 134),
# run it again without. Echo the exit codes, e.g. "134 0".
supervise() {
  local point=$1 log=$2
  shift 2
  if [ "${NO_RESTART:-0}" = 1 ]; then
    PCP_CRASH_AT=$point timeout "$TIMEOUT" "$@" >>"$log" 2>&1
    echo "$?"
    return
  fi
  if [ "${NODE_DOWN:-0}" = 1 ]; then
    PCP_CRASH_AT=$point timeout "$TIMEOUT" "$@" >>"$log" 2>&1
    local c1=$?
    echo "--- buyer node stopped ---" >>"$log"
    bash -c "$BUYER_NODE_STOP" >>"$log" 2>&1
    timeout 20 "$@" >>"$log" 2>&1
    local c2=$?
    echo "--- buyer node started ---" >>"$log"
    bash -c "$BUYER_NODE_START" >>"$log" 2>&1
    timeout "$TIMEOUT" "$@" >>"$log" 2>&1
    echo "$c1 $c2 $?"
    return
  fi
  local codes=""
  if [ -n "$point" ]; then
    PCP_CRASH_AT=$point timeout "$TIMEOUT" "$@" >>"$log" 2>&1
    local c=$?
    codes="$c"
    if [ $c -ne 134 ]; then echo "$codes"; return; fi
    echo "--- restarted after $point ---" >>"$log"
  fi
  timeout "$TIMEOUT" "$@" >>"$log" 2>&1
  echo "$codes $?"
}

run_case() {
  local name=$1
  local dir="$OUT/${name//:/_}"
  rm -rf "$dir" && mkdir -p "$dir"
  local sim="$dir/sim.json"
  local seller_rail buyer_rail sn bn
  if [ "$RAIL" = lnd ]; then
    sn=from-env:PCP_SELLER_LND_; bn=from-env:PCP_BUYER_LND_; seller_rail=lnd; buyer_rail=lnd
    "$BIN/pcp-setup" --root "$dir" --seller-node "$sn" --buyer-node "$bn" >"$dir/setup.txt" 2>&1
  else
    sn=seller; bn=buyer
    seller_rail="sim:$sim:seller"; buyer_rail="sim:$sim:buyer"
    "$BIN/pcp-setup" --root "$dir" --seller-node "$sn" --buyer-node "$bn" --sim "$sim" >"$dir/setup.txt" 2>&1
  fi
  local sp="" bp="" extra=() sextra=() expect_state=Delivered expect_settled=1 expect_proofs=1 expect_reason=""
  # A repeat is answered, never refused: no refusal in either log.
  local expect_refusals=0
  local buyer_restarts=1 node_down=0
  case $name in
    # The buyer dies holding a checked invoice and never comes back: the
    # seller must end the sale when the invoice expires (no refusal on the
    # buyer side, which never learns).
    buyer-gone)
      bp=buyer:invoice:pre; buyer_restarts=0; sextra=(--invoice-expiry-secs 75)
      expect_settled=0; expect_refusals=1 ;;
    # LND only: the buyer dies right after paying, its node is stopped, the
    # buyer runs meanwhile and must keep the reservation (Paying), then the
    # node comes back and the sale completes.
    buyer-node-down) bp=buyer:pay:pre; node_down=1 ;;
    seller:*) sp=$name ;;
    buyer:*) bp=$name ;;
    # The seller works for 3 s while the buyer resends its accept.
    repeat-accept) extra=(--resend-secs 0); sextra=(--work-delay-ms 3000) ;;
    tampered-accept)
      extra=(--tamper-accept)
      expect_state=Aborted; expect_settled=0; expect_proofs=0; expect_refusals=1
      expect_reason=refused_by_counterparty.offer_not_issued ;;
  esac
  local allow=()
  [ "$RAIL" = sim ] && allow=(--allow-sim)
  (
    if [ "$RAIL" = lnd ]; then
      export PCP_LND_REST_URL=$PCP_SELLER_LND_REST_URL PCP_LND_MACAROON=$PCP_SELLER_LND_MACAROON PCP_LND_TLS_CERT=$PCP_SELLER_LND_TLS_CERT
    fi
    supervise "$sp" "$dir/seller.log" "$BIN/pcp-sell" --state "$dir/seller" \
      --inbox "$dir/seller-inbox" --peer-inbox "$dir/buyer-inbox" --rail "$seller_rail" \
      "${allow[@]}" "${sextra[@]}" --quiet-exit-secs 20 --deadline-secs "$TIMEOUT" >"$dir/seller.codes"
  ) &
  local spid=$!
  (
    if [ "$RAIL" = lnd ]; then
      export PCP_LND_REST_URL=$PCP_BUYER_LND_REST_URL PCP_LND_MACAROON=$PCP_BUYER_LND_MACAROON PCP_LND_TLS_CERT=$PCP_BUYER_LND_TLS_CERT
    fi
    if [ $buyer_restarts = 0 ]; then export NO_RESTART=1; fi
    if [ $node_down = 1 ]; then export NODE_DOWN=1; fi
    supervise "$bp" "$dir/buyer.log" "$BIN/pcp-buy" --state "$dir/buyer" \
      --inbox "$dir/buyer-inbox" --peer-inbox "$dir/seller-inbox" --rail "$buyer_rail" \
      "${allow[@]}" --resend-secs 1 --deadline-secs "$TIMEOUT" "${extra[@]}" >"$dir/buyer.codes"
  )
  wait $spid
  local bargs=(--state "$dir/buyer" --expect-state "$expect_state" --expect-refusals "$expect_refusals" --out "$dir/audit-buyer.json")
  [ -n "$expect_reason" ] && bargs+=(--expect-reason "$expect_reason")
  local ab=0
  if [ $buyer_restarts = 1 ]; then
    "$BIN/pcp-audit" "${bargs[@]}" >/dev/null 2>"$dir/audit-buyer.err"
    ab=$?
  fi
  if [ $node_down = 1 ]; then
    # While its node was down the buyer must have stayed in Paying.
    grep -q "payment status unknown" "$dir/buyer.log" || ab=1
  fi
  "$BIN/pcp-audit" --state "$dir/seller" --expect-settled "$expect_settled" \
    --expect-proofs "$expect_proofs" --expect-refusals "$expect_refusals" --out "$dir/audit-seller.json" >/dev/null 2>"$dir/audit-seller.err"
  local as=$?
  # The seller's k must not appear outside the two state directories (the
  # simulated network holds it after settlement, as a node would).
  local leak=0
  for k in $(python3 -c 'import json,sys; print(" ".join(s["key"] for s in json.load(open(sys.argv[1]))["state"]["sales"]))' "$dir/seller/state.json" 2>/dev/null); do
    if grep -rl "$k" "$dir" --exclude-dir=seller --exclude-dir=buyer --exclude=sim.json >/dev/null 2>&1; then
      leak=1
    fi
  done
  # A crash case counts only if the process really died at its point.
  local reached=0
  if [ -n "$sp" ]; then read -r first _ <"$dir/seller.codes"; [ "$first" = 134 ] || reached=1; fi
  if [ -n "$bp" ]; then read -r first _ <"$dir/buyer.codes"; [ "$first" = 134 ] || reached=1; fi
  local status=PASS
  [ $ab -eq 0 ] && [ $as -eq 0 ] && [ $leak -eq 0 ] && [ $reached -eq 0 ] || status=FAIL
  local line
  line=$(printf '%-22s %s  buyer exits [%s] seller exits [%s] audit buyer %s seller %s k-leak %s point-missed %s' \
    "$name" "$status" "$(cat "$dir/buyer.codes")" "$(cat "$dir/seller.codes")" "$ab" "$as" "$leak" "$reached")
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
