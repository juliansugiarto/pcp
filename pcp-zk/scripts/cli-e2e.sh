#!/usr/bin/env bash
# End-to-end check of the pcp-zk CLI, from the seller's prove to the buyer's decrypt.
#
# Usage: pcp-zk/scripts/cli-e2e.sh [WORK_DIR]
#
# Runs one honest sale, then 3 inputs that disagree with the seller's public.json,
# 6 consistent lies and tampers that only the proof can catch, and 2 decrypts.
# Every case must give the expected result, or the script exits nonzero.
# Needs: cargo, python3, sha256sum. Proving takes about 8 s and 0.6 GB on 2 CPUs.

set -euo pipefail

# macOS ships `shasum`, not `sha256sum`.
if ! command -v sha256sum >/dev/null 2>&1; then sha256sum() { shasum -a 256 "$@"; }; fi

CRATE="$(cd "$(dirname "$0")/.." && pwd)"
W="${1:-$(mktemp -d)}"
mkdir -p "$W"
cd "$CRATE"
cargo build --release --quiet --bin pcp-zk
B="$CRATE/target/release/pcp-zk"
PUZ="$CRATE/examples/puzzle.txt"
SOL="$CRATE/examples/solution.txt"

h() { printf '%s' "$1" | sha256sum | cut -d' ' -f1; }
BIND=$(h offer-1)
fails=0
expect() { # expect NAME WANT_EXIT CMD...
  local name=$1 want=$2; shift 2
  set +e; "$@" >"$W/last.out" 2>"$W/last.err"; local got=$?; set -e
  if [ "$got" = "$want" ]; then echo "ok    $name (exit $got)"; else
    echo "WRONG $name: exit $got, expected $want"; cat "$W/last.err"; fails=$((fails+1)); fi
}
edit_json() { # edit_json DIR PYTHON_EXPR_ON_d
  python3 - "$1/public.json" "$2" <<'EOF'
import json, sys
p, expr = sys.argv[1], sys.argv[2]
d = json.load(open(p)); exec(expr); json.dump(d, open(p, "w"))
EOF
}
copy() { rm -rf "$W/$1"; cp -r "$W/out" "$W/$1"; }

# Seller
rm -rf "$W/out"
"$B" prove --puzzle "$PUZ" --solution "$SOL" --binding "$BIND" --out "$W/out" --secret "$W/k.txt"
K=$(tr -d '\n' <"$W/k.txt")
H=$(python3 -c "import hashlib;print(hashlib.sha256(bytes.fromhex('$K')).hexdigest())")
[ "$H" = "$(python3 -c "import json;print(json.load(open('$W/out/public.json'))['payment_hash'])")" ] \
  || { echo "WRONG: public.json H is not SHA256(k)"; exit 1; }
echo "ok    H = SHA256(k), checked outside the circuit with python hashlib"

BADH=$(h x); BADB=$(h offer-2)
python3 - "$PUZ" "$W/puzzle-bad.txt" <<'EOF'
import sys
s = open(sys.argv[1]).read(); out = []; done = False
for ch in s:
    if not done and ch in "123456789":
        out.append("1" if ch != "1" else "2"); done = True
    else:
        out.append(ch)
open(sys.argv[2], "w").write("".join(out))
EOF
BADG=$(python3 -c "import sys;print(''.join(c for c in open('$W/puzzle-bad.txt').read() if c.isdigit())[:81])")

# Buyer: honest
expect "verify honest sale"            0 "$B" verify --dir "$W/out" --puzzle "$PUZ" --payment-hash "$H" --binding "$BIND"
# Buyer inputs disagree with the seller's file
expect "wrong invoice H"               1 "$B" verify --dir "$W/out" --puzzle "$PUZ" --payment-hash "$BADH" --binding "$BIND"
expect "wrong offer binding"           1 "$B" verify --dir "$W/out" --puzzle "$PUZ" --payment-hash "$H" --binding "$BADB"
expect "wrong puzzle"                  1 "$B" verify --dir "$W/out" --puzzle "$W/puzzle-bad.txt" --payment-hash "$H" --binding "$BIND"
# Consistent lies: the file agrees with the buyer, so only the proof can catch them
copy a; edit_json "$W/a" "d['payment_hash']='$BADH'"
expect "consistent lie: other H"       1 "$B" verify --dir "$W/a" --puzzle "$PUZ" --payment-hash "$BADH" --binding "$BIND"
copy b; edit_json "$W/b" "d['binding']='$BADB'"
expect "consistent lie: other binding" 1 "$B" verify --dir "$W/b" --puzzle "$PUZ" --payment-hash "$H" --binding "$BADB"
copy c; edit_json "$W/c" "d['givens']='$BADG'"
expect "consistent lie: other puzzle"  1 "$B" verify --dir "$W/c" --puzzle "$W/puzzle-bad.txt" --payment-hash "$H" --binding "$BIND"
copy d; edit_json "$W/d" "c=d['ciphertext'];c[40]=c[40][:-2]+('00' if c[40][-2:]!='00' else '01')"
expect "tampered ciphertext"           1 "$B" verify --dir "$W/d" --puzzle "$PUZ" --payment-hash "$H" --binding "$BIND"
copy e; python3 -c "p='$W/e/proof.bin';b=bytearray(open(p,'rb').read());b[8000]^=1;open(p,'wb').write(b)"
expect "flipped proof byte"            1 "$B" verify --dir "$W/e" --puzzle "$PUZ" --payment-hash "$H" --binding "$BIND"
copy f; head -c 15000 "$W/out/proof.bin" >"$W/f/proof.bin"
expect "truncated proof"               1 "$B" verify --dir "$W/f" --puzzle "$PUZ" --payment-hash "$H" --binding "$BIND"
# After payment
expect "decrypt with k"                0 "$B" decrypt --dir "$W/out" --key "$K"
diff <(tr -cd '0-9' <"$W/last.out") <(tr -cd '0-9' <"$SOL") >/dev/null \
  && echo "ok    decrypted grid equals the seller's solution" \
  || { echo "WRONG decrypted grid differs"; fails=$((fails+1)); }
expect "decrypt with wrong key"        2 "$B" decrypt --dir "$W/out" --key "$BADH"

if [ "$fails" -ne 0 ]; then echo "$fails case(s) wrong"; exit 1; fi
echo "all cases as expected (work dir: $W)"
