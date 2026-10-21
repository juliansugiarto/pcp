#!/usr/bin/env python3
"""Recompute the PCP/0 conformance vectors (SPEC.md, Appendix A) from scratch.

This is a second implementation of the encoding. It follows SPEC.md and shares
no code with the Rust crate. It recomputes all 17 vectors of Appendix A and
compares each with the value printed in SPEC.md, which it reads from the
Appendix A table itself.

Needs Python 3 and the `cryptography` package (ChaCha20-Poly1305, Ed25519):

    pip install cryptography
    python3 pcp/tools/vectors.py [path/to/SPEC.md]

Prints one PASS or FAIL line per vector, and exits nonzero if any fails.
"""

import hashlib
import os
import re
import struct
import sys

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

VERSION = b"PCP/0"


# SPEC 3.1
def lp(x: bytes) -> bytes:
    return struct.pack(">I", len(x)) + x


def canonical_bytes(tag: str, fields) -> bytes:
    return lp(VERSION + b"/" + tag.encode()) + b"".join(lp(f) for f in fields)


def tagged_hash(tag: str, fields) -> bytes:
    return hashlib.sha256(canonical_bytes(tag, fields)).digest()


def u64(x: int) -> bytes:
    return struct.pack(">Q", x)


def sha256(x: bytes) -> bytes:
    return hashlib.sha256(x).digest()


# SPEC 4: chacha20poly1305-k/0
def encrypt(k: bytes, offer_id: bytes, r: bytes) -> bytes:
    enc_key = tagged_hash("enc-key", [k])
    aad = tagged_hash("enc-aad", [offer_id])
    return ChaCha20Poly1305(enc_key).encrypt(bytes(12), r, aad)


# SPEC 6.1: job classes
SUDOKU = b"pcp/sudoku/v0"
TOYEXPR = b"pcp/testsuite-toyexpr/v0"


def spec_hash(job_id: bytes, params: bytes) -> bytes:
    return tagged_hash("spec", [job_id, params])


def sudoku_spec(n: int) -> bytes:
    return spec_hash(SUDOKU, bytes([n]))


def toyexpr_spec() -> bytes:
    return spec_hash(TOYEXPR, struct.pack(">III", 4096, 4096, 64))


def encode_suite(vectors) -> bytes:
    out = struct.pack(">I", len(vectors))
    for x, expected in vectors:
        out += struct.pack(">qq", x, expected)
    return out


# SPEC 3.2 and 7.2
def journal(job_id, spec, input_commitment, offer_id, buyer_nonce, c, h) -> bytes:
    return canonical_bytes(
        "statement",
        [VERSION, job_id, spec, input_commitment, offer_id, buyer_nonce,
         tagged_hash("ciphertext", [c]), h],
    )


def ed25519(seed: bytes):
    sk = Ed25519PrivateKey.from_private_bytes(seed)
    pk = sk.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return sk, pk


def compute() -> dict:
    k = bytes([0x11]) * 32
    offer_id = bytes([0x22]) * 32
    input_commitment = bytes([0x33]) * 32
    buyer_nonce = bytes([0x44]) * 32
    h = sha256(k)
    spec4 = sudoku_spec(4)

    v = {}
    v[1] = tagged_hash("test", [b"", b"abc", u64(1)])
    v[2] = h
    v[3] = encrypt(k, offer_id, b"PCP")
    v[4] = spec4
    v[5] = sudoku_spec(9)
    v[6] = toyexpr_spec()
    v[7] = tagged_hash("input", [encode_suite([(-1, 1)])])
    v[8] = sha256(journal(SUDOKU, spec4, input_commitment, offer_id, buyer_nonce, b"C", h))
    v[9] = tagged_hash("offer", [
        VERSION, SUDOKU, spec4, input_commitment, buyer_nonce,
        u64(1_000_000), u64(600), b"seller",
        b"INSECURE-dev-transparent/0", b"chacha20poly1305-k/0", b"lightning-htlc-sim/0",
    ])

    principal_sk, principal_pk = ed25519(bytes([0x55]) * 32)
    _, agent_pk = ed25519(bytes([0x66]) * 32)
    v[10] = principal_pk
    v[11] = agent_pk
    mandate_id = tagged_hash("mandate", [
        VERSION, principal_pk, agent_pk, b"buyer", spec4,
        u64(5_000_000), u64(2_000_000), b"principal-node", u64(86_400),
        bytes([0x77]) * 32,
    ])
    v[12] = mandate_id
    v[13] = principal_sk.sign(mandate_id)

    puzzle = bytes([1, 0, 0, 4, 0, 0, 1, 0, 0, 1, 0, 0, 4, 0, 0, 1])
    result = bytes([1, 2, 3, 4, 3, 4, 1, 2, 2, 1, 4, 3, 4, 3, 2, 1])
    c = encrypt(k, offer_id, result)
    v[14] = c
    guest_input = canonical_bytes("guest-input", [spec4, puzzle, result, k, c, offer_id, buyer_nonce])
    v[15] = sha256(guest_input)
    j = journal(SUDOKU, spec4, tagged_hash("input", [puzzle]), offer_id, buyer_nonce, c, h)
    v[16] = sha256(j)
    v[17] = len(j)
    return {n: (x if isinstance(x, int) else x.hex()) for n, x in v.items()}


def spec_values(path: str) -> dict:
    """Read the `| # | Value | Result |` rows of Appendix A."""
    with open(path, encoding="utf-8") as f:
        text = f.read()
    start = text.index("## Appendix A")
    end = text.index("## Appendix B", start)
    rows = {}
    for line in text[start:end].splitlines():
        m = re.match(r"^\|\s*(\d+)\s*\|.*\|\s*`([0-9a-f]+)`\s*\|\s*$", line)
        if m:
            rows[int(m.group(1))] = m.group(2)
    return rows


def main() -> int:
    here = os.path.dirname(os.path.abspath(__file__))
    path = sys.argv[1] if len(sys.argv) > 1 else os.path.join(here, "..", "SPEC.md")
    expected = spec_values(path)
    got = compute()
    failed = 0
    passed = 0
    for n in sorted(got):
        want = expected.get(n)
        have = str(got[n])
        ok = want is not None and have == want
        failed += not ok
        passed += ok
        print(f"{'PASS' if ok else 'FAIL'} {n:2d} {have}" + ("" if ok else f" (SPEC: {want})"))
    missing = sorted(set(expected) - set(got))
    for n in missing:
        failed += 1
        print(f"FAIL {n:2d} not computed by this script")
    print(f"{passed} of {len(expected)} vectors in SPEC.md Appendix A reproduced")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
