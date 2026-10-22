#!/usr/bin/env python3
"""Check pcp0.py against SPEC.md Appendix A (conformance vectors 1-17).

Run: python3 vectors_check.py      (exit status 1 if any vector fails)
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import pcp0  # noqa: E402

EXPECTED = {
    1: "69b1f5ad126e00c4f741eab035dc593a23728edb32ee92d98dfd442272842463",
    2: "02d449a31fbb267c8f352e9968a79e3e5fc95c1bbeaa502fd6454ebde5a4bedc",
    3: "1b7e1354b4a7b7f40ad290a740585505a2001a",
    4: "977fe68aefda363451d6526e3598975c18f39fa3399a792e16650319448f36be",
    5: "0a3c3833260ed33c76cd735d4b005686f15f14b38f1aaa0422ac95e17797f5a0",
    6: "9aa91b2878399b36576180833e32dcd2b7f793b9c89dc24300cd4f1e35dcf3ea",
    7: "9e2497098d49db24713ed622b7220e02fa38b646b7e11925614d73ecfc746242",
    8: "48b2ecc5eccf1ec9f13e74019ff6a45aa7aae444a3cae5f4338f28aff28e39b8",
    9: "0e5dd77c4975f961abf06701b79ec912900f3ce5fc0cacb08856b92a5e8fc105",
    10: "c6822637c7d310ec57627be00ba259d253749f4aaf644470cffbe53a35f73242",
    11: "34b4d9043156cb6dcf0beb0a2949b7559c940d2bcb6dbe8c53a9b30278e3a746",
    12: "768febe650b08741e15fb538587b359df87bd48a6e78f7b93cfa7f7a5424c772",
    13: "60e9f0b666227078f8c10dadadd1862b9ba54be3d14ac6014a743cc5540d76f2"
        "0d2a3ae5cf030a8d20975bf99248aef53e787ee8b9473853b04d6edc5bf09a0e",
    14: "4a3f402e4c2e98b8371e2fe27c1869c35d2b11e3107848cff28e8b624e5bf554",
    15: "ee93318d136f05eeecc095c3512a667c4bae50fa81b8fb1718e29c30ce66bed9",
    16: "9119de0c3d909b092a118b655588b7e85e004e9de2d17ab297f247cd42bd3c02",
    17: "261",
}

DESC = {
    1: 'tagged_hash("test", ["", "abc", u64(1)])',
    2: "H = SHA256(k)",
    3: 'Enc_k("PCP") under offer_id',
    4: "spec_hash sudoku n=4",
    5: "spec_hash sudoku n=9",
    6: "spec_hash testsuite-toyexpr",
    7: "input_commitment of suite [(-1, 1)]",
    8: "statement_hash (C = \"C\")",
    9: "offer_id",
    10: "principal_key from seed 0x55",
    11: "agent_key from seed 0x66",
    12: "mandate_id",
    13: "principal_sig over #12",
    14: "C = Enc_k(R) for the sudoku",
    15: "SHA256(guest input)",
    16: "SHA256(journal) = statement_hash",
    17: "journal length",
}


def compute():
    k = b"\x11" * 32
    oid = b"\x22" * 32
    ic = b"\x33" * 32
    nonce = b"\x44" * 32
    got = {}
    got[1] = pcp0.tagged_hash("test", [b"", b"abc", pcp0.u64(1)]).hex()
    H = pcp0.payment_hash(k)
    got[2] = H.hex()
    got[3] = pcp0.encrypt(k, b"PCP", oid).hex()
    sh4 = pcp0.sudoku_spec_hash(4)
    got[4] = sh4.hex()
    got[5] = pcp0.sudoku_spec_hash(9).hex()
    got[6] = pcp0.toyexpr_spec_hash().hex()
    got[7] = pcp0.input_commitment(pcp0.toyexpr_input([(-1, 1)])).hex()
    got[8] = pcp0.statement_hash(
        "PCP/0", pcp0.SUDOKU_JOB_ID, sh4, ic, oid, nonce, pcp0.ciphertext_hash(b"C"), H
    ).hex()
    got[9] = pcp0.offer_id(
        "PCP/0", pcp0.SUDOKU_JOB_ID, sh4, ic, nonce, 1_000_000, 600, "seller",
        pcp0.INSECURE_DEV_BACKEND, pcp0.ENC_SCHEME, "lightning-htlc-sim/0",
    ).hex()
    pseed = b"\x55" * 32
    aseed = b"\x66" * 32
    pk = pcp0.ed25519_public_key_from_seed(pseed)
    ak = pcp0.ed25519_public_key_from_seed(aseed)
    got[10] = pk.hex()
    got[11] = ak.hex()
    mid = pcp0.mandate_id("PCP/0", pk, ak, "buyer", [sh4], 5_000_000, 2_000_000,
                          "principal-node", 86_400, b"\x77" * 32)
    got[12] = mid.hex()
    sig = pcp0.ed25519_sign(pseed, mid)
    got[13] = sig.hex()
    assert pcp0.ed25519_verify(pk, sig, mid)
    inp = bytes([1, 0, 0, 4, 0, 0, 1, 0, 0, 1, 0, 0, 4, 0, 0, 1])
    R = bytes([1, 2, 3, 4, 3, 4, 1, 2, 2, 1, 4, 3, 4, 3, 2, 1])
    assert pcp0.sudoku_check(4, inp, R), "sudoku_check rejects the vector's R"
    C = pcp0.encrypt(k, R, oid)
    got[14] = C.hex()
    assert pcp0.decrypt(k, C, oid) == R
    gi = pcp0.canonical_bytes("guest-input", [sh4, inp, R, k, C, oid, nonce])
    got[15] = pcp0.sha256(gi).hex()
    j = pcp0.journal("PCP/0", pcp0.SUDOKU_JOB_ID, sh4, pcp0.input_commitment(inp), oid, nonce,
                     pcp0.ciphertext_hash(C), H)
    got[16] = pcp0.sha256(j).hex()
    assert pcp0.sha256(j) == pcp0.statement_hash(
        "PCP/0", pcp0.SUDOKU_JOB_ID, sh4, pcp0.input_commitment(inp), oid, nonce,
        pcp0.ciphertext_hash(C), H)
    got[17] = str(len(j))
    return got


def main():
    got = compute()
    fails = 0
    for n in sorted(EXPECTED):
        ok = got[n] == EXPECTED[n]
        fails += not ok
        print("%-4s #%-2d %-40s %s" % ("PASS" if ok else "FAIL", n, DESC[n], "" if ok else "got " + got[n]))
    print("%d/%d vectors pass" % (len(EXPECTED) - fails, len(EXPECTED)))
    sys.exit(1 if fails else 0)


if __name__ == "__main__":
    main()
