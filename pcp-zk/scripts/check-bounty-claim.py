#!/usr/bin/env python3
"""Check a privacy-bounty claim against a bundle's secrets.

Usage: python3 check-bounty-claim.py SECRETS_DIR CLAIM_FILE

CLAIM_FILE holds the claimed grid: 81 digits 1-9 in any layout (whitespace ignored).
Prints MATCH and exits 0 if it is the committed R, otherwise NO MATCH and exits 1.
It also recomputes the published commitment from R.txt and the salt, so a corrupted
secrets folder is caught rather than reported as "no match".
"""
import hashlib
import os
import sys


def digits(path):
    d = "".join(c for c in open(path).read() if not c.isspace())
    if len(d) != 81 or any(c not in "123456789" for c in d):
        sys.exit(f"{path}: expected 81 digits 1-9")
    return d


def commit(r, salt):
    return hashlib.sha256(b"pcp-zk/bounty-R/v0" + r.encode() + salt).hexdigest()


sec, claim = sys.argv[1], sys.argv[2]
salt = bytes.fromhex(open(os.path.join(sec, "salt.txt")).read().strip())
r = digits(os.path.join(sec, "R.txt"))
c = digits(claim)
print("commitment from secrets:", commit(r, salt))
if commit(c, salt) == commit(r, salt):
    print("MATCH")
    sys.exit(0)
print("NO MATCH")
sys.exit(1)
