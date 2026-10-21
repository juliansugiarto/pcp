#!/usr/bin/env bash
# Build a public "break this" bundle for the pcp-zk proof, plus the owner's secrets.
#
# Usage: pcp-zk/scripts/make-bundle.sh BUNDLE_DIR SECRETS_DIR [LABEL]
#
# BUNDLE_DIR  gets: givens.txt (an EMPTY grid), public.json (C, H, binding), proof.bin,
#             BUNDLE.md (the exact claim, the values, the two bounties), verify.sh, SHA256SUMS.
# SECRETS_DIR gets: R.txt (the encrypted grid), k.txt (the key), salt.txt (the commitment salt).
#             It must not be inside a git work tree or inside BUNDLE_DIR. Keep it offline.
#             Without it, nobody (including the owner) can check a privacy-bounty claim or
#             reveal R later.
# LABEL       names the bundle and feeds the binding value (default: v0).
#
# Why an empty grid: for a well-posed sudoku, R can be computed from the givens by any
# solver, so "recover R without k" would be claimable on day one without touching the
# proof. With an empty grid R is one of about 6.7e21 valid grids. R is drawn with a
# randomized backtracking fill from the OS CSPRNG, and a salted commitment to it is published.

set -euo pipefail

trap 'echo "make-bundle: failed at line $LINENO: $BASH_COMMAND" >&2' ERR

# macOS ships `shasum`, not `sha256sum`.
if ! command -v sha256sum >/dev/null 2>&1; then sha256sum() { shasum -a 256 "$@"; }; fi

BUNDLE="${1:?usage: make-bundle.sh BUNDLE_DIR SECRETS_DIR [LABEL]}"
SECRETS="${2:?usage: make-bundle.sh BUNDLE_DIR SECRETS_DIR [LABEL]}"
LABEL="${3:-v0}"
CRATE="$(cd "$(dirname "$0")/.." && pwd)"

for d in "$BUNDLE" "$SECRETS"; do
  if [ -e "$d" ] && [ -n "$(ls -A "$d" 2>/dev/null)" ]; then echo "refusing: $d exists and is not empty" >&2; exit 1; fi
done
mkdir -p "$BUNDLE" "$SECRETS"
BUNDLE="$(cd "$BUNDLE" && pwd)"; SECRETS="$(cd "$SECRETS" && pwd)"
case "$SECRETS/" in "$BUNDLE/"*) echo "refusing: SECRETS_DIR is inside BUNDLE_DIR" >&2; exit 1;; esac
if git -C "$SECRETS" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  echo "refusing: SECRETS_DIR is inside a git work tree; the secrets could get committed" >&2; exit 1
fi
chmod 700 "$SECRETS"

cd "$CRATE"
cargo build --release --quiet --bin pcp-zk
B="$CRATE/target/release/pcp-zk"

# 1. R: random full grid; empty givens; salted commitment.
python3 -I - "$SECRETS" "$BUNDLE" <<'EOF'
import hashlib, os, secrets, sys
sec, bun = sys.argv[1], sys.argv[2]
rng = secrets.SystemRandom()
g = [0] * 81
def ok(i, d):
    r, c = divmod(i, 9)
    br, bc = 3 * (r // 3), 3 * (c // 3)
    for j in range(9):
        if g[9 * r + j] == d or g[9 * j + c] == d:
            return False
    for rr in range(br, br + 3):
        for cc in range(bc, bc + 3):
            if g[9 * rr + cc] == d:
                return False
    return True
def fill(i=0):
    if i == 81:
        return True
    digits = list(range(1, 10)); rng.shuffle(digits)
    for d in digits:
        if ok(i, d):
            g[i] = d
            if fill(i + 1):
                return True
    g[i] = 0
    return False
assert fill()
# The backtracking fill is not uniform over grids (its min-entropy is below the
# 72.5 bits of a uniform draw). Apply a random element of the sudoku symmetry
# group: digit relabelling, row permutations within bands, band permutations,
# column permutations within stacks, stack permutations, optional transpose.
# Every element maps valid grids to valid grids and spreads probability evenly
# over each symmetry orbit.
def perm3():
    p = [0, 1, 2]; rng.shuffle(p); return p
def line_perm():
    bands = perm3()
    return [3 * b + i for b in bands for i in perm3()]
rows, cols = line_perm(), line_perm()
relabel = list(range(1, 10)); rng.shuffle(relabel)
h = [relabel[g[9 * rows[r] + cols[c]] - 1] for r in range(9) for c in range(9)]
if rng.randrange(2):
    h = [h[9 * c + r] for r in range(9) for c in range(9)]
g = h
def valid(x):
    groups = [[9 * r + c for c in range(9)] for r in range(9)]
    groups += [[9 * r + c for r in range(9)] for c in range(9)]
    groups += [[9 * (br + i) + bc + j for i in range(3) for j in range(3)] for br in (0, 3, 6) for bc in (0, 3, 6)]
    return all(sorted(x[i] for i in grp) == list(range(1, 10)) for grp in groups)
assert valid(g), "symmetry step produced an invalid grid"
rtxt ="\n".join("".join(str(d) for d in g[9 * r:9 * r + 9]) for r in range(9)) + "\n"
salt = secrets.token_bytes(32)
digits = "".join(str(d) for d in g).encode()
commit = hashlib.sha256(b"pcp-zk/bounty-R/v0" + digits + salt).hexdigest()
open(os.path.join(sec, "R.txt"), "w").write(rtxt)
open(os.path.join(sec, "salt.txt"), "w").write(salt.hex() + "\n")
open(os.path.join(bun, "givens.txt"), "w").write("000000000\n" * 9)
open(os.path.join(bun, ".r_commitment"), "w").write(commit + "\n")
EOF
chmod 600 "$SECRETS/R.txt" "$SECRETS/salt.txt"

BIND=$(printf '%s' "pcp-zk/bounty-bundle/$LABEL" | sha256sum | cut -d' ' -f1)
COMMIT=$(cat "$BUNDLE/.r_commitment"); rm "$BUNDLE/.r_commitment"

# 2. Prove. k is drawn inside `prove` from the OS CSPRNG and written only to SECRETS.
"$B" prove --puzzle "$BUNDLE/givens.txt" --solution "$SECRETS/R.txt" --binding "$BIND" \
  --out "$BUNDLE" --secret "$SECRETS/k.txt" 2>"$SECRETS/prove.log" \
  || { echo "prove failed; its log:" >&2; cat "$SECRETS/prove.log" >&2; exit 1; }
chmod 600 "$SECRETS/k.txt"
H=$(python3 -c "import json,sys;print(json.load(open(sys.argv[1]))['payment_hash'])" "$BUNDLE/public.json")
FP=$("$B" vk-fingerprint)
PARAMS=$(grep -A1 'pub const PARAMS_SHA256' src/lib.rs | grep -o '[0-9a-f]\{64\}' | head -1)
[ -n "$PARAMS" ] || { echo "could not read PARAMS_SHA256 from src/lib.rs" >&2; exit 1; }

# 3. Leak scan: neither R, k nor the salt may appear in the bundle, in any encoding we can think of.
python3 -I - "$SECRETS" "$BUNDLE" <<'EOF'
import os, sys
sec, bun = sys.argv[1], sys.argv[2]
r = "".join(c for c in open(os.path.join(sec, "R.txt")).read() if c.isdigit())
k = open(os.path.join(sec, "k.txt")).read().strip()
salt = open(os.path.join(sec, "salt.txt")).read().strip()
needles = [r.encode(), bytes(int(c) for c in r), k.encode(), bytes.fromhex(k), salt.encode(), bytes.fromhex(salt)]
for name in os.listdir(bun):
    data = open(os.path.join(bun, name), "rb").read()
    for n in needles:
        if n in data:
            sys.exit(f"LEAK: a secret appears in {name}")
print("leak scan: R, k and salt appear in no bundle file")
EOF

# 4. The buyer-side check must pass on the bundle as written.
"$B" verify --dir "$BUNDLE" --puzzle "$BUNDLE/givens.txt" --payment-hash "$H" --binding "$BIND" \
  --vk-fingerprint "$FP" >/dev/null 2>&1 || { echo "self-check: verify FAILED" >&2; exit 1; }
"$B" decrypt --dir "$BUNDLE" --key "$(tr -d '\n' <"$SECRETS/k.txt")" | tr -cd '0-9' >"$SECRETS/.dec"
cmp -s "$SECRETS/.dec" <(tr -cd '0-9' <"$SECRETS/R.txt") || { echo "self-check: decrypt != R" >&2; exit 1; }
rm "$SECRETS/.dec"
echo "self-check: verify OK, and decrypting with k gives R"

# 5. verify.sh, BUNDLE.md, SHA256SUMS.
cat >"$BUNDLE/verify.sh" <<EOF
#!/usr/bin/env bash
# Verify this bundle offline. Needs: a Rust toolchain and the pcp-zk crate source
# (set PCP_ZK_CRATE, default: the directory above this bundle). No network after the
# crates are fetched, no node, no money. Prints OK and exits 0 if the proof verifies.
set -euo pipefail
HERE="\$(cd "\$(dirname "\$0")" && pwd)"
CRATE="\${PCP_ZK_CRATE:-\$(cd "\$HERE/.." && pwd)}"
cargo build --release --quiet --manifest-path "\$CRATE/Cargo.toml" --bin pcp-zk
"\$CRATE/target/release/pcp-zk" verify --dir "\$HERE" --puzzle "\$HERE/givens.txt" \\
  --payment-hash $H \\
  --binding $BIND \\
  --vk-fingerprint $FP
EOF
chmod +x "$BUNDLE/verify.sh"

cat >"$BUNDLE/BUNDLE.md" <<EOF
# pcp-zk break-this bundle ($LABEL)

**Experimental, not audited. Do not use where money depends on it.**

## The claim, exactly

This bundle contains a transparent zero-knowledge proof, made with halo2_proofs 0.3.5 (IPA over the Pasta curves, no trusted setup), for one statement: the prover knows a valid 9x9 sudoku grid R consistent with the published givens and a 32-byte key k such that the published C is the encryption of R under a Poseidon-derived keystream from k, and the published H equals SHA-256(k), bound to the published 32-byte binding value. A verifier rebuilds the verifying key from the circuit source and checks the proof against the givens, H and binding it supplies itself; it takes only C from the bundle. The proof is 15,936 bytes and verified in 0.057 s on a 2-CPU Linux container; proving took 7.8 s and 0.57 GB there, at k = 13. The SHA-256 chip inside the circuit is our own. It replaces the halo2_gadgets 0.5.0 Table16 gadget, which a read-only review inside this project found forgeable in four independent ways (two reproduced with MockProver), three weeks after upstream had removed it for three overlapping reasons; the failure report is included. The replacement has been checked, inside this project and by a reviewer who did not write it, for: exactly one owning constraint or copy for every advice cell of the SHA chip (mechanically, 23,128 rotation reads), exact carry ranges, round constants and IV in fixed columns, 14 compensated forgery attempts each rejected by the intended constraint, agreement with the sha2 crate on 24 keys, and two deliberate re-insertions of Table16-class bugs that only the compensated tests caught. It has not been audited by anyone outside this project; halo2_proofs, the upstream Poseidon chip and the sudoku gates are assumed or lightly checked rather than reviewed to the same depth; zero-knowledge rests on halo2's default blinding and one test that two proofs of the same statement differ, with no further analysis; no Lightning payment has been made with it; no one outside the project has run it. It is not the backend the protocol defaults to, and it must not be used where money depends on it. Two bounties are open: produce a proof that verifies under the published verifying key for any (givens, C, H, binding) where H is not SHA-256 of the key that decrypts C, or where the decryption of C is not a valid grid; and produce the grid R committed to in this bundle from (givens, C, H, proof) alone, where the givens are an empty grid so that R is not computable from the puzzle. If either succeeds, this bundle is withdrawn and the report updated.

## Values

| | |
|---|---|
| givens | empty grid (81 zeros), \`givens.txt\` |
| H (payment hash) | \`$H\` |
| binding | \`$BIND\` = SHA-256("pcp-zk/bounty-bundle/$LABEL") |
| verifying-key fingerprint | \`$FP\` (\`pcp-zk vk-fingerprint\`) |
| transparent params (k = 13) SHA-256 | \`$PARAMS\` |
| commitment to R | \`$COMMIT\` = SHA-256("pcp-zk/bounty-R/v0" ‖ R as 81 ASCII digits, row by row ‖ 32-byte salt) |

## Verify

\`\`\`
./verify.sh        # prints OK; set PCP_ZK_CRATE if the crate is not the parent directory
\`\`\`

Or by hand: \`pcp-zk verify --dir . --puzzle givens.txt --payment-hash <H> --binding <binding> --vk-fingerprint <fingerprint>\`. The fingerprint check fails if your build of the circuit is not the one this bundle names.

## Bounties

Reward: [J: amount in sats, or "no reward yet; a funded bounty follows"]. Author: Julian Sugiarto. Contact: [J: channel].

1. **Soundness.** Send a tuple (givens, C, H, binding), a proof that \`pcp-zk verify\` accepts for that tuple under the verifying key with the fingerprint above, and a 32-byte p with SHA-256(p) = H such that \`pcp-zk decrypt --key p\` does not yield a valid grid consistent with the givens. Any tuple counts, not only this bundle's.
2. **Privacy.** Send the 81 digits of the R committed to above, derived from this bundle's givens, C, H and proof alone. The owner checks it against the commitment with the salt, then publishes the salt and R.

If either bounty is claimed, this bundle is withdrawn and the failure report is updated.

## Files

\`givens.txt\`, \`public.json\` (C, H, binding, suite and backend ids), \`proof.bin\`, \`verify.sh\`, this file, \`SHA256SUMS\`.
EOF

(cd "$BUNDLE" && sha256sum givens.txt public.json proof.bin verify.sh BUNDLE.md >SHA256SUMS)
cat >"$SECRETS/README.txt" <<EOF
Secrets for bundle $LABEL. Do not publish, do not commit, keep a second offline copy.
R.txt     the encrypted grid (privacy bounty answer)
k.txt     the key: SHA-256(k) = $H; decrypts the bundle's C to R
salt.txt  the salt of the R commitment $COMMIT
Check a privacy claim: python3 pcp-zk/scripts/check-bounty-claim.py $SECRETS CLAIM.txt
EOF
echo "bundle:  $BUNDLE"
echo "secrets: $SECRETS  (keep offline; not in git)"
echo "H=$H"; echo "binding=$BIND"; echo "vk=$FP"; echo "R commitment=$COMMIT"
