#!/usr/bin/env python3
"""Make the rehearsal buyer's key: a BIP32 master private key for signet
(testnet version bytes, "tprv"), from 32 random bytes. Python standard
library only. Prints the key; store it as the Actions secret
REHEARSAL_BUYER_XPRV and nowhere else. Signet coins have no value, so a
leaked key loses the rehearsal's funding, not money (design note 30)."""
import hashlib, hmac, os

ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def b58check(payload: bytes) -> str:
    data = payload + hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    n = int.from_bytes(data, "big")
    out = ""
    while n:
        n, r = divmod(n, 58)
        out = ALPHABET[r] + out
    return "1" * (len(data) - len(data.lstrip(b"\0"))) + out


def tprv(seed: bytes) -> str:
    i = hmac.new(b"Bitcoin seed", seed, hashlib.sha512).digest()
    key, chain = i[:32], i[32:]
    k = int.from_bytes(key, "big")
    n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
    if not 0 < k < n:
        raise ValueError("invalid master key; run again")
    # version tprv, depth 0, parent fingerprint 0, child number 0
    payload = bytes.fromhex("04358394") + b"\0" + b"\0" * 4 + b"\0" * 4 + chain + b"\0" + key
    return b58check(payload)


if __name__ == "__main__":
    print(tprv(os.urandom(32)))
