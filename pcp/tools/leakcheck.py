#!/usr/bin/env python3
"""Look for the secret in a RISC Zero receipt (audit item M6, minimum).

    python3 pcp/tools/leakcheck.py BUYER_STATE_JSON...

For each buyer state directory's state.json that ended Delivered, take the
proof (the serialized receipt the seller sent before payment) and search
it for what must not be in it:

- k, the key that settles the payment and decrypts the result;
- the key derived from it, enc_key = tagged_hash("enc-key", [k]);
- R, the result the buyer paid for;
- the guest input encoding is not searched as a whole (it contains the
  public statement fields), but its secret parts are the three above.

A hit means the receipt carries the goods before payment. No hit is
evidence, not proof, of zero knowledge: it rules out the plain leak (a
secret copied into the journal or the seal), not a cryptographic one.

With two or more receipts it also checks: all have the same
length (a length that depended on R would leak it), and any two differ in
most bytes (a prover with a fixed random generator would repeat itself).
Neither shows zero knowledge either; RISC Zero does not claim it (SPEC 7.2).
Exit 1 on any hit or failed check, 2 if no delivered purchase was found.
"""

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from vectors import tagged_hash  # noqa: E402  (SPEC 3.1 encoding)


def main():
    checked, hits = 0, 0
    proofs = []
    for path in sys.argv[1:]:
        try:
            st = json.load(open(path))["state"]["state"]
        except (OSError, KeyError, ValueError) as e:
            print(f"{path}: unreadable ({e})")
            continue
        d = st if isinstance(st, dict) and st.get("state") == "delivered" else None
        if not d:
            print(f"{path}: not delivered, skipped")
            continue
        proof = bytes.fromhex(d["bundle"]["proof"])
        proofs.append((path, proof))
        k = bytes.fromhex(d["receipt"]["preimage"])
        r = bytes.fromhex(d["result"])
        secrets = {"k": k, "enc_key": tagged_hash("enc-key", [k]), "R": r}
        found = [name for name, s in secrets.items() if s and s in proof]
        checked += 1
        hits += len(found)
        print(f"{path}: receipt {len(proof)} bytes, R {len(r)} bytes: "
              + (f"LEAK of {', '.join(found)}" if found else "no k, enc_key or R in the receipt"))
    if checked == 0:
        print("no delivered purchase found")
        return 2
    lengths = {len(p) for _, p in proofs}
    if len(lengths) > 1:
        print(f"receipt lengths differ: {sorted(lengths)}")
        hits += 1
    for i in range(len(proofs)):
        for j in range(i + 1, len(proofs)):
            a, b = proofs[i][1], proofs[j][1]
            n = min(len(a), len(b))
            same = sum(1 for x, y in zip(a, b) if x == y) / max(n, 1)
            print(f"{proofs[i][0]} vs {proofs[j][0]}: {same:.1%} of bytes equal")
            # The journal, the claim and the fixed header match; the seal
            # must not. Random bytes agree about 0.4% of the time.
            if same > 0.10:
                print("  too similar: is the prover's randomness fixed?")
                hits += 1
    return 1 if hits else 0


if __name__ == "__main__":
    sys.exit(main())
