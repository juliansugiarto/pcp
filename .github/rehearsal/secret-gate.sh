#!/usr/bin/env bash
# Run before anything is published or uploaded (artifacts of a public
# repository can be downloaded by anyone signed in): fail if OUT_DIR holds
# the rehearsal key, any tprv string, a macaroon (hex), or an agent or
# principal key seed. `k` is not searched: the files in OUT_DIR hold it
# only after settlement (receipts), when every hop of the payment has it.
# Usage: secret-gate.sh OUT_DIR [FILE_WITH_SECRET...]
set -uo pipefail
o=$1; shift
hits=0
check() { if grep -rqF -- "$1" "$o"; then echo "secret gate: found $2 in $o"; hits=$((hits + 1)); fi; }
[ -n "${REHEARSAL_BUYER_XPRV:-}" ] && check "$REHEARSAL_BUYER_XPRV" "the rehearsal key"
if grep -rqE 'tprv[1-9A-HJ-NP-Za-km-z]{20,}' "$o"; then echo "secret gate: a tprv key in $o"; hits=$((hits + 1)); fi
for f in "$@"; do
  [ -f "$f" ] || continue
  case "$f" in
    *.macaroon) s=$(od -An -tx1 "$f" | tr -d ' \n') ;;
    *) s=$(tr -d ' \n' < "$f") ;;
  esac
  [ ${#s} -ge 32 ] && check "${s:0:64}" "the contents of $(basename "$f")"
done
[ "$hits" = 0 ] && echo "secret gate: clean" || exit 1
