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
Exit 1 on any hit, 2 if no delivered purchase was found.
"""

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from vectors import tagged_hash  # noqa: E402  (SPEC 3.1 encoding)


def main():
    checked, hits = 0, 0
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
    return 1 if hits else 0


if __name__ == "__main__":
    sys.exit(main())
