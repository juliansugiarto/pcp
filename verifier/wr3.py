"""Offline verifier for Witnessed Record spec v0.3 (draft).

Changes from v0.2 (see spec/witnessed-record-v0.3.md):
- witness-cert carries `role` (saksi, ptps, pemantau, kpps, posted) and `alg` (ed25519, es256)
- ES256 (ECDSA P-256, raw r||s) witness keys next to Ed25519; org keys stay Ed25519
- envelope identity is the SHA-256 of the canonical body, so ECDSA malleability cannot add a leaf
- capture.image = {orig_sha256, deriv_sha256, deriv_params}; capture.anchors = body hashes seen in the room
- official records carry a `stage`; each station gets a recap-drift table and first_divergent_stage
- policy linter: the `official` camp is never required; mixed kpps/other camps are warned about
- station list may carry dpt; plausibility and sybil flags are evidence, never rejection
- per-station evidence bundle (bundle / verify-bundle) and a materiality-ordered disputes list

Usage:
    python -m verifier.wr3 demo OUT_DIR
    python -m verifier.wr3 verify ENVELOPES_DIR --stations S.json --policy P1.json [--policy P2.json ...] [--camp-solo]
    python -m verifier.wr3 bundle ENVELOPES_DIR --stations S.json --policy P.json [--policy ...] --station ID --out FILE
    python -m verifier.wr3 verify-bundle FILE
    python -m verifier.wr3 disputes ENVELOPES_DIR --stations S.json --policy P.json --official-stage STAGE
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from datetime import datetime
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature, encode_dss_signature
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

SPEC = "witnessed-record/0.3"
VERSION = "0.3.0-draft"
BUNDLE_FORMAT = "witnessed-record/0.3/station-bundle"
KEY_RE = re.compile(r"^[a-z0-9_.-]{1,32}$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")      # 32 bytes: sha256, Ed25519 public key
HEX130 = re.compile(r"^04[0-9a-f]{128}$")  # uncompressed SEC1 P-256 point
HEX16 = re.compile(r"^[0-9a-f]{32}$")      # 16-byte nonce
TYPES = {"org", "witness-cert", "revocation", "capture", "incident", "official"}
SIGNED_TYPES = {"org", "witness-cert", "revocation", "capture", "incident"}
ROLES = ("saksi", "ptps", "pemantau", "kpps", "posted")
ALGS = ("ed25519", "es256")
STAGES = ("capture", "tps", "ppk", "kabko", "prov", "nasional")
FLAGS = ("implausible", "same_image", "nonce_reuse", "late_enrollment")
OFFICIAL_CAMP = "official"


# ---------------------------------------------------------------- canonical bytes and signatures

def _check_keys(obj, path="body") -> None:
    if isinstance(obj, dict):
        for k, v in obj.items():
            if not isinstance(k, str) or not k.isascii():
                raise ValueError(f"{path}: non-ascii key {k!r}")
            _check_keys(v, f"{path}.{k}")
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            _check_keys(v, f"{path}[{i}]")
    elif isinstance(obj, float):
        raise ValueError(f"{path}: floats are not allowed")
    elif isinstance(obj, bool) or obj is None or isinstance(obj, (int, str)):
        return
    else:
        raise ValueError(f"{path}: unsupported type {type(obj).__name__}")


def canonical_bytes(body) -> bytes:
    """RFC 8785 (JCS) for the restricted domain used here: ascii keys, strings, integers, no floats.

    For this domain Python's sorted, compact json.dumps produces JCS-identical bytes.
    """
    _check_keys(body)
    return json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def signing_input(body: dict) -> bytes:
    return f"wr/0.3/{body['type']}\n".encode() + canonical_bytes(body)


def body_hash(body: dict) -> str:
    """Envelope identity in v0.3: the body, never the signature (ECDSA signatures are malleable)."""
    return hashlib.sha256(canonical_bytes(body)).hexdigest()


def envelope_hash(env: dict) -> str:
    return body_hash(env["body"])


def alg_of(sk) -> str:
    if isinstance(sk, Ed25519PrivateKey):
        return "ed25519"
    if isinstance(sk, ec.EllipticCurvePrivateKey) and isinstance(sk.curve, ec.SECP256R1):
        return "es256"
    raise TypeError(f"unsupported key type {type(sk).__name__}")


def pub_hex(sk) -> str:
    if alg_of(sk) == "es256":
        return sk.public_key().public_bytes(Encoding.X962, PublicFormat.UncompressedPoint).hex()
    return sk.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()


def es256_key():
    return ec.generate_private_key(ec.SECP256R1())


def sign_bytes(data: bytes, sk) -> str:
    """Ed25519 signature, or ES256 as raw r||s (64 bytes), lowercase hex."""
    if alg_of(sk) == "es256":
        r, s = decode_dss_signature(sk.sign(data, ec.ECDSA(hashes.SHA256())))
        return (r.to_bytes(32, "big") + s.to_bytes(32, "big")).hex()
    return sk.sign(data).hex()


def fingerprint(root_pubkey_hex: str) -> str:
    return hashlib.sha256(bytes.fromhex(root_pubkey_hex)).hexdigest()[:32]


def seal(body: dict, sk) -> dict:
    env = {"body": body}
    if sk is not None:
        env["sig"] = sign_bytes(signing_input(body), sk)
    return env


def verify_sig(body: dict, sig: str, pubkey_hex: str, alg: str = "ed25519") -> bool:
    try:
        raw, pk, data = bytes.fromhex(sig), bytes.fromhex(pubkey_hex), signing_input(body)
        if alg == "ed25519":
            Ed25519PublicKey.from_public_bytes(pk).verify(raw, data)
            return True
        if alg == "es256":
            if len(raw) != 64 or len(pk) != 65:
                return False
            der = encode_dss_signature(int.from_bytes(raw[:32], "big"), int.from_bytes(raw[32:], "big"))
            ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), pk).verify(der, data, ec.ECDSA(hashes.SHA256()))
            return True
        return False
    except (InvalidSignature, ValueError, TypeError):
        return False


def signer_of(body: dict) -> str | None:
    t = body.get("type")
    if t == "org":
        return body.get("root_pubkey")
    if t in ("witness-cert", "revocation"):
        return body.get("issuer")
    if t in ("capture", "incident"):
        return (body.get("witness") or {}).get("pubkey")
    return None


def parse_time(s: str) -> datetime:
    t = datetime.fromisoformat(s)
    if t.tzinfo is None:
        raise ValueError("time must carry an offset")
    return t


# ---------------------------------------------------------------- validation

def _tally_ok(t) -> bool:
    return (
        isinstance(t, dict) and t
        and all(isinstance(k, str) and KEY_RE.match(k) for k in t)
        and all(isinstance(v, int) and not isinstance(v, bool) and 0 <= v < 2**31 for v in t.values())
    )


def _hex(rx, v) -> bool:
    return isinstance(v, str) and bool(rx.match(v))


def _witness_pub_ok(v) -> bool:
    """Structural only: 64 hex (Ed25519) or 130 hex (P-256). The alg comes from the cert table."""
    return _hex(HEX64, v) or _hex(HEX130, v)


def validate(env: dict) -> list[str]:
    """Structural validation. Signatures are checked later, against the key table."""
    errs = []
    body = env.get("body") if isinstance(env, dict) else None
    if not isinstance(body, dict):
        return ["missing body"]
    try:
        canonical_bytes(body)
    except ValueError as e:
        return [str(e)]
    if body.get("spec") != SPEC:
        errs.append("bad spec")
    t = body.get("type")
    if t not in TYPES:
        return errs + [f"unknown type {t!r}"]
    if t in SIGNED_TYPES and not isinstance(env.get("sig"), str):
        errs.append("missing sig")
    need = {
        "org": {"spec", "type", "name", "root_pubkey", "contest_keys"},
        "witness-cert": {"spec", "type", "org", "contest", "pubkey", "alg", "role", "scope", "not_before", "not_after", "issuer"},
        "revocation": {"spec", "type", "org", "contest", "issuer", "issued_at", "revoked"},
        "capture": {"spec", "type", "contest", "station", "form", "tally", "image", "anchors", "captured_at", "nonce",
                    "copresence", "witness"},
        "incident": {"spec", "type", "contest", "station", "kind", "note", "ref", "witness"},
        "official": {"spec", "type", "contest", "station", "form", "stage", "tally", "source"},
    }[t]
    if set(body) != need:
        errs.append(f"{t}: keys must be exactly {sorted(need)}")
        return errs
    for k in ("contest", "station", "form", "name", "org", "scope"):
        if k in body and not isinstance(body[k], str):
            errs.append(f"{k} must be a string")
    if errs:
        return errs
    if t in ("capture", "official") and not _tally_ok(body["tally"]):
        errs.append("bad tally")
    if t == "org":
        if not _hex(HEX64, body["root_pubkey"]):
            errs.append("bad root_pubkey")
        ck = body["contest_keys"]
        if not isinstance(ck, list) or any(
            not isinstance(c, dict) or not isinstance(c.get("contest"), str) or not _hex(HEX64, c.get("pubkey")) for c in ck
        ):
            errs.append("bad contest_keys")
    if t == "capture":
        img = body["image"]
        if not (isinstance(img, dict) and set(img) == {"orig_sha256", "deriv_sha256", "deriv_params"}
                and _hex(HEX64, img["orig_sha256"])
                and (img["deriv_sha256"] == "" or _hex(HEX64, img["deriv_sha256"]))
                and isinstance(img["deriv_params"], str)):
            errs.append("bad image: need orig_sha256, deriv_sha256 (hex or empty), deriv_params")
        if not isinstance(body["anchors"], list) or any(not _hex(HEX64, a) for a in body["anchors"]):
            errs.append("bad anchors")
        if not _hex(HEX16, body["nonce"]):
            errs.append("nonce must be 16 bytes hex")
        w = body["witness"]
        if not (isinstance(w, dict) and _witness_pub_ok(w.get("pubkey"))):
            errs.append("bad witness.pubkey")
        cp = body["copresence"]
        if not isinstance(cp, list) or any(
            not isinstance(c, dict) or c.get("pubkey") == (w or {}).get("pubkey") for c in cp
        ):
            errs.append("bad copresence")
        try:
            parse_time(body["captured_at"])
        except (ValueError, TypeError):
            errs.append("bad captured_at")
    if t == "witness-cert":
        if body["role"] not in ROLES:
            errs.append(f"role must be one of {list(ROLES)}")
        if body["alg"] not in ALGS:
            errs.append(f"alg must be one of {list(ALGS)}")
        elif not _hex(HEX64 if body["alg"] == "ed25519" else HEX130, body["pubkey"]):
            errs.append(f"pubkey does not match alg {body['alg']}")
        if not _hex(HEX64, body["issuer"]):
            errs.append("bad issuer (org keys are Ed25519)")
        try:
            if parse_time(body["not_before"]) >= parse_time(body["not_after"]):
                errs.append("empty validity window")
        except (ValueError, TypeError):
            errs.append("bad validity times")
    if t == "revocation":
        rv = body["revoked"]
        if not isinstance(rv, list) or any(not isinstance(r, dict) or not _witness_pub_ok(r.get("pubkey")) for r in rv):
            errs.append("bad revoked list")
        else:
            try:
                for r in rv:
                    parse_time(r["effective"])
            except (ValueError, TypeError, KeyError):
                errs.append("bad revocation time")
    if t == "incident":
        if body["kind"] not in ("copy_refused", "no_access", "not_visible", "retraction"):
            errs.append("bad incident kind")
        if not (isinstance(body["witness"], dict) and _witness_pub_ok(body["witness"].get("pubkey"))):
            errs.append("bad witness.pubkey")
    if t == "official":
        if body["stage"] not in STAGES:
            errs.append(f"stage must be one of {list(STAGES)}")
        if not isinstance(body["source"], dict):
            errs.append("bad source")
    return errs


# ---------------------------------------------------------------- Merkle root (RFC 6962 prefixes)

def merkle_root(leaves: list[bytes]) -> str:
    if not leaves:
        return hashlib.sha256(b"").hexdigest()
    level = [hashlib.sha256(b"\x00" + x).digest() for x in leaves]
    while len(level) > 1:
        level = [
            hashlib.sha256(b"\x01" + level[i] + level[i + 1]).digest() if i + 1 < len(level) else level[i]
            for i in range(0, len(level), 2)
        ]
    return level[0].hex()


def _body_key(body: dict, h: str):
    return (body["type"], body.get("contest", ""), body.get("station", ""), signer_of(body) or "", h)


def unique_bodies(envelopes: list[dict]) -> list[dict]:
    """Group envelopes by body hash. Each item: {"body", "h", "sigs"}; sorted deterministically."""
    groups: dict[str, dict] = {}
    for env in envelopes:
        h = body_hash(env["body"])
        g = groups.setdefault(h, {"body": env["body"], "h": h, "sigs": []})
        s = env.get("sig")
        if isinstance(s, str) and s not in g["sigs"]:
            g["sigs"].append(s)
    for g in groups.values():
        g["sigs"].sort()
    return sorted(groups.values(), key=lambda g: _body_key(g["body"], g["h"]))


def input_root(envelopes: list[dict]) -> str:
    """Policy-free: one leaf per distinct canonical body, the same root for every honest mirror."""
    return merkle_root([canonical_bytes(it["body"]) for it in unique_bodies(envelopes)])


def _sig_ok(item: dict, pubkey: str, alg: str) -> bool:
    return any(verify_sig(item["body"], s, pubkey, alg) for s in item["sigs"])


# ---------------------------------------------------------------- stations and policies

def normalize_stations(stations: list) -> tuple[list[str], dict[str, int]]:
    """Station entries are strings or objects {"station": "...", "dpt": int}."""
    ids, dpt = [], {}
    for e in stations:
        if isinstance(e, str):
            ids.append(e)
        elif isinstance(e, dict) and isinstance(e.get("station"), str):
            ids.append(e["station"])
            if "dpt" in e:
                d = e["dpt"]
                if not isinstance(d, int) or isinstance(d, bool) or d < 0:
                    raise ValueError(f"bad dpt for station {e['station']!r}")
                dpt[e["station"]] = d
        else:
            raise ValueError(f"bad station entry {e!r}")
    return ids, dpt


def _station_id(entry) -> str:
    return entry if isinstance(entry, str) else entry["station"]


def policy_sha256(policy: dict) -> str:
    return hashlib.sha256(canonical_bytes(policy)).hexdigest()


def lint_policy(policy: dict, certs: dict | None = None) -> list[str]:
    """Raise if the official camp is ever required; return warnings for camps mixing kpps with other roles."""
    name = policy.get("name", "")
    if OFFICIAL_CAMP in policy.get("rule", {}).get("require_camps", []):
        raise ValueError(f"policy {name!r}: the camp {OFFICIAL_CAMP!r} may be listed but never required (require_camps)")
    warnings = []
    for camp, fps in sorted(policy.get("camps", {}).items()):
        roles = {c["role"] for c in (certs or {}).values() if c["org"] in set(fps)}
        if "kpps" in roles and len(roles) > 1:
            warnings.append(f"policy {name!r}: camp {camp!r} mixes kpps-role witnesses with roles "
                            f"{sorted(roles - {'kpps'})}")
    return warnings


# ---------------------------------------------------------------- key table

def build_key_table(items: list[dict], contest: str, rejected: dict) -> tuple[dict, dict]:
    """Every valid witness cert for the contest, from any org. Policies filter by camp afterwards."""
    contest_keys: dict[str, str] = {}  # contest pubkey -> org fp
    org_names: dict[str, str] = {}
    for it in items:
        b = it["body"]
        if b["type"] != "org":
            continue
        if not _sig_ok(it, b["root_pubkey"], "ed25519"):
            rejected["bad_signature"] += 1
            continue
        fp = fingerprint(b["root_pubkey"])
        org_names[fp] = b["name"]
        for ck in b["contest_keys"]:
            if ck["contest"] == contest:
                contest_keys[ck["pubkey"]] = fp

    revoked: dict[tuple[str, str], datetime] = {}  # (org, pubkey) -> earliest effective time
    for it in items:
        b = it["body"]
        if b["type"] != "revocation" or b["contest"] != contest:
            continue
        if contest_keys.get(b["issuer"]) != b["org"] or not _sig_ok(it, b["issuer"], "ed25519"):
            rejected["bad_signature"] += 1
            continue
        for r in b["revoked"]:
            t = parse_time(r["effective"])
            k = (b["org"], r["pubkey"])
            revoked[k] = min(t, revoked.get(k, t))

    certs: dict[str, dict] = {}
    for it in items:
        b = it["body"]
        if b["type"] != "witness-cert" or b["contest"] != contest:
            continue
        org = contest_keys.get(b["issuer"])
        if org is None or org != b["org"]:
            rejected["unknown_key"] += 1
            continue
        if not _sig_ok(it, b["issuer"], "ed25519"):
            rejected["bad_signature"] += 1
            continue
        nb = parse_time(b["not_before"])
        prev = certs.get(b["pubkey"])
        certs[b["pubkey"]] = {
            "org": org, "org_name": org_names.get(org, ""), "role": b["role"], "alg": b["alg"],
            "scope": b["scope"] or "", "not_before": nb, "not_after": parse_time(b["not_after"]),
            "revoked_at": revoked.get((org, b["pubkey"])),
            "first_not_before": min(nb, prev["first_not_before"]) if prev else nb,
        }
    return certs, org_names


# ---------------------------------------------------------------- aggregation

def _add(acc: dict, tally: dict, sign: int = 1) -> None:
    for k, v in tally.items():
        acc[k] = acc.get(k, 0) + sign * v


def _delta(official: dict, witnessed: dict) -> dict:
    return {k: official.get(k, 0) - witnessed.get(k, 0)
            for k in sorted(set(official) | set(witnessed)) if official.get(k, 0) != witnessed.get(k, 0)}


def _tkey(t: dict) -> str:
    return json.dumps(t, sort_keys=True, separators=(",", ":"))


def _connected_across_camps(supporters: list[dict], edges: set[frozenset]) -> bool:
    for i, a in enumerate(supporters):
        for b in supporters[i + 1:]:
            if a["camp"] != b["camp"] and frozenset((a["pubkey"], b["pubkey"])) in edges:
                return True
    return False


def _qualified(supporters: list[dict], rule: dict, edges: set[frozenset]) -> bool:
    camps = {s["camp"] for s in supporters}
    if len(supporters) < rule.get("min_witnesses", 2) or len(camps) < rule.get("min_camps", 2):
        return False
    if any(c not in camps for c in rule.get("require_camps", [])):
        return False
    if rule.get("require_copresence") and rule.get("min_camps", 2) >= 2:
        return _connected_across_camps(supporters, edges)
    return True


def _station_flags(verified: list[dict], dpt: dict, freeze: datetime | None) -> dict:
    """station -> flag -> sorted witness pubkeys at that station involved. Evidence only."""
    out: dict[str, dict[str, set]] = {}

    def mark(st, flag, pk):
        out.setdefault(st, {}).setdefault(flag, set()).add(pk)

    by_img: dict[tuple, list] = {}
    by_nonce: dict[str, list] = {}
    for c in verified:
        b, pk, st = c["body"], c["pubkey"], c["body"]["station"]
        if st in dpt and sum(b["tally"].values()) > dpt[st]:
            mark(st, "implausible", pk)
        if freeze is not None and c["info"]["first_not_before"] > freeze:
            mark(st, "late_enrollment", pk)
        by_img.setdefault(("orig", b["image"]["orig_sha256"]), []).append((st, pk))
        if b["image"]["deriv_sha256"]:
            by_img.setdefault(("deriv", b["image"]["deriv_sha256"]), []).append((st, pk))
        by_nonce.setdefault(b["nonce"], []).append((st, pk))
    for entries in by_img.values():
        if len({pk for _, pk in entries}) >= 2:
            for st, pk in entries:
                mark(st, "same_image", pk)
    for entries in by_nonce.values():
        if len({st for st, _ in entries}) >= 2:
            for st, pk in entries:
                mark(st, "nonce_reuse", pk)
    return {st: {f: sorted(pks) for f, pks in sorted(fl.items())} for st, fl in out.items()}


def aggregate(envelopes: list[dict], stations: list, policy: dict) -> dict:
    ids, dpt = normalize_stations(stations)
    lint_policy(policy)  # raises before any work
    rule = policy["rule"]
    contest = policy["contest"]
    freeze = parse_time(policy["freeze_at"]) if policy.get("freeze_at") else None
    camp_of = {fp: camp for camp, fps in policy["camps"].items() for fp in fps}
    rejected = {"bad_signature": 0, "unknown_key": 0, "out_of_scope": 0, "expired": 0, "revoked": 0, "self_conflict": 0}
    items = unique_bodies(envelopes)
    certs, _ = build_key_table(items, contest, rejected)
    warnings = lint_policy(policy, certs)

    # signature-valid captures from any certified key, policy-free: input for anchors and flags
    sig_ok: dict[str, bool] = {}
    verified = []
    for it in items:
        b = it["body"]
        if b["type"] != "capture" or b["contest"] != contest:
            continue
        pk = b["witness"]["pubkey"]
        info = certs.get(pk)
        if info is None:
            continue
        sig_ok[it["h"]] = _sig_ok(it, pk, info["alg"])
        if sig_ok[it["h"]]:
            verified.append({"h": it["h"], "body": b, "pubkey": pk, "info": info})
    kpps_at: dict[str, set] = {}
    for c in verified:
        if c["info"]["role"] == "kpps":
            kpps_at.setdefault(c["body"]["station"], set()).add(c["h"])
    anchored = {c["h"]: bool(set(c["body"]["anchors"]) & kpps_at.get(c["body"]["station"], set())) for c in verified}
    flags = _station_flags(verified, dpt, freeze)

    # captures accepted under this policy, per (station, form)
    by_sf: dict[tuple[str, str], list[dict]] = {}
    seen_witness: dict[tuple[str, str, str], str] = {}
    for it in items:
        b = it["body"]
        if b["type"] != "capture" or b["contest"] != contest:
            continue
        pk = b["witness"]["pubkey"]
        info = certs.get(pk)
        if info is None or info["org"] not in camp_of:
            rejected["unknown_key"] += 1
            continue
        if not sig_ok[it["h"]]:
            rejected["bad_signature"] += 1
            continue
        if info["scope"] and not b["station"].startswith(info["scope"]):
            rejected["out_of_scope"] += 1
            continue
        at = parse_time(b["captured_at"])
        if not (info["not_before"] <= at <= info["not_after"]):
            rejected["expired"] += 1
            continue
        if info["revoked_at"] is not None and at >= info["revoked_at"]:
            rejected["revoked"] += 1
            continue
        key = (b["station"], b["form"], pk)
        tally_c = _tkey(b["tally"])
        if key in seen_witness and seen_witness[key] != tally_c:
            rejected["self_conflict"] += 1
            # keep neither: a witness who told two stories counts for nothing at this station
            by_sf[(b["station"], b["form"])] = [c for c in by_sf.get((b["station"], b["form"]), []) if c["pubkey"] != pk]
            seen_witness[key] = "!conflict"
            continue
        if key in seen_witness:
            continue
        seen_witness[key] = tally_c
        by_sf.setdefault((b["station"], b["form"]), []).append({
            "h": it["h"], "pubkey": pk, "org": info["org"], "org_name": info["org_name"], "role": info["role"],
            "alg": info["alg"], "camp": camp_of[info["org"]], "tally": b["tally"], "image": b["image"],
            "nonce": b["nonce"], "copresence": b["copresence"],
        })

    officials: dict[tuple[str, str], dict[str, list[dict]]] = {}
    for it in items:
        b = it["body"]
        if b["type"] == "official" and b["contest"] == contest:
            per_stage = officials.setdefault((b["station"], b["form"]), {})
            lst = per_stage.setdefault(b["stage"], [])
            if b["tally"] not in lst:
                lst.append(b["tally"])
    for per_stage in officials.values():
        for st in per_stage:
            per_stage[st].sort(key=_tkey)

    incidents: dict[str, list[str]] = {}
    for it in items:
        b = it["body"]
        if b["type"] != "incident" or b["contest"] != contest:
            continue
        info = certs.get(b["witness"]["pubkey"])
        if info is not None and info["org"] in camp_of and _sig_ok(it, b["witness"]["pubkey"], info["alg"]):
            incidents.setdefault(b["station"], []).append(b["kind"])

    report_st = {}
    settled_tot: dict[str, int] = {}
    lo_tot: dict[str, int] = {}
    hi_tot: dict[str, int] = {}
    counts = {"settled": 0, "disputed": 0, "insufficient": 0, "missing": 0}
    diff = {"equal": 0, "differs": 0, "official_only": 0, "witnessed_only": 0, "official_conflict": 0}
    drift_counts = {s: 0 for s in STAGES}
    by_camp: dict[str, int] = {}
    by_prov: dict[str, dict] = {}
    flags_by_org: dict[str, dict] = {}

    flagged_keys = {(c["body"]["station"], c["body"]["form"]) for c in verified if c["body"]["station"] in flags}
    keys = sorted(set(by_sf) | set(officials) | flagged_keys)
    stations_seen = set()
    stations_witnessed = set()
    for st, form in keys:
        stations_seen.add(st)
        caps = by_sf.get((st, form), [])
        nonce_of = {c["pubkey"]: c["nonce"] for c in caps}
        edges = set()
        for c in caps:
            for p in c["copresence"]:
                if nonce_of.get(p.get("pubkey")) == p.get("nonce"):
                    edges.add(frozenset((c["pubkey"], p["pubkey"])))
        groups: dict[str, list[dict]] = {}
        for c in caps:
            groups.setdefault(_tkey(c["tally"]), []).append(c)
        cands = []
        for tk in sorted(groups):
            sup = groups[tk]
            cands.append({
                "tally": json.loads(tk),
                "supporters": [{"pubkey": s["pubkey"], "org": s["org"], "org_name": s["org_name"], "role": s["role"],
                                "alg": s["alg"], "camp": s["camp"], "image": s["image"],
                                "anchored_to_official": anchored.get(s["h"], False)} for s in sup],
                "qualified": _qualified(sup, rule, edges),
            })
        qual = [c for c in cands if c["qualified"]]
        if not caps:
            status = "missing"
        elif len(qual) == 1:
            status = "settled"
        elif len(qual) >= 2:
            status = "disputed"
        else:
            status = "insufficient"
        if caps:
            stations_witnessed.add(st)
        counts[status] += 1
        for camp in {s["camp"] for c in cands for s in c["supporters"]}:
            by_camp[camp] = by_camp.get(camp, 0) + 1
        prov = st.split(".")[0]
        pv = by_prov.setdefault(prov, {"settled": 0, "disputed": 0, "insufficient": 0, "missing": 0})
        pv[status] += 1

        if status == "settled":
            _add(settled_tot, qual[0]["tally"])
            _add(lo_tot, qual[0]["tally"])
            _add(hi_tot, qual[0]["tally"])
        elif status == "disputed":
            options = {k for c in qual for k in c["tally"]}
            for k in options:
                vals = [c["tally"].get(k, 0) for c in qual]
                lo_tot[k] = lo_tot.get(k, 0) + min(vals)
                hi_tot[k] = hi_tot.get(k, 0) + max(vals)

        # recap drift: the official number at every stage, against the settled witnessed tally
        witnessed = qual[0]["tally"] if status == "settled" else None
        off = officials.get((st, form), {})
        drift, first_div = [], None
        for stage in STAGES:
            if stage not in off:
                continue
            tl = off[stage]
            if len(tl) > 1:
                e = {"stage": stage, "status": "official_conflict", "tallies": tl}
            elif witnessed is None:
                e = {"stage": stage, "status": "official_only", "tally": tl[0]}
            else:
                d = _delta(tl[0], witnessed)
                e = {"stage": stage, "status": "differs" if d else "equal", "tally": tl[0]}
                if d:
                    e["delta_official_minus_witnessed"] = d
            if witnessed is not None and first_div is None and e["status"] in ("differs", "official_conflict"):
                first_div = stage
            drift.append(e)
        if first_div:
            drift_counts[first_div] += 1

        # station-level diff: against the most downstream official stage present
        off_status = None
        if drift:
            last = drift[-1]
            off_status = {k: v for k, v in last.items() if k in ("status", "stage", "delta_official_minus_witnessed")}
        elif status == "settled":
            off_status = {"status": "witnessed_only"}
        if off_status:
            diff[off_status["status"]] += 1

        st_flags = flags.get(st, {})
        for flag, pks in st_flags.items():
            for org in sorted({certs[pk]["org"] for pk in pks}):
                o = flags_by_org.setdefault(org, {"name": "", **{f: 0 for f in FLAGS}})
                o[flag] += 1
        if status != "missing" or off or st_flags:
            report_st[f"{st}/{form}"] = {
                "station": st,
                "form": form,
                "status": status,
                "candidates": [c for c in cands if c["qualified"]],
                "contested": [c for c in cands if not c["qualified"]],
                "incidents": sorted(incidents.get(st, [])),
                "official": off_status,
                "recap_drift": drift,
                "first_divergent_stage": first_div,
                "flags": sorted(st_flags),
                "flag_detail": st_flags,
            }

    for st in ids:
        if st not in stations_seen:
            counts["missing"] += 1
            by_prov.setdefault(st.split(".")[0], {"settled": 0, "disputed": 0, "insufficient": 0, "missing": 0})["missing"] += 1

    org_name = {c["org"]: c["org_name"] for c in certs.values()}
    for org, o in flags_by_org.items():
        o["name"] = org_name.get(org, "")

    ranked = sorted(lo_tot, key=lambda k: (-settled_tot.get(k, 0), k))
    ranked = [k for k in ranked if k != "invalid"]
    flip, margin = False, None
    if len(ranked) >= 2:
        leader, runner = ranked[0], ranked[1]
        margin = settled_tot.get(leader, 0) - settled_tot.get(runner, 0)
        flip = hi_tot.get(runner, 0) >= lo_tot.get(leader, 0)

    return {
        "policy": policy.get("name", ""),
        "policy_sha256": policy_sha256(policy),
        "policy_warnings": warnings,
        "totals": {"settled": dict(sorted(settled_tot.items())), "min": dict(sorted(lo_tot.items())),
                   "max": dict(sorted(hi_tot.items())), "flip": flip, "margin_settled": margin},
        "status_counts": counts,
        "coverage": {"by_province": dict(sorted(by_prov.items())), "stations_with_camp": dict(sorted(by_camp.items())),
                     "missing": sorted(set(ids) - stations_witnessed),
                     "flags_by_org": dict(sorted(flags_by_org.items()))},
        "diff_vs_official": diff,
        "first_divergent_stage_counts": {s: n for s, n in drift_counts.items() if n},
        "rejected": rejected,
        "stations": report_st,
    }


def run(envelopes: list[dict], stations: list, policies: list[dict], malformed: list[str]) -> dict:
    reports = [aggregate(envelopes, stations, p) for p in policies]
    return {
        "header": {"verifier": {"name": "somnus-wr3", "version": VERSION, "spec": SPEC},
                   "input_root": input_root(envelopes),
                   "envelopes": len(envelopes), "unique_bodies": len(unique_bodies(envelopes)),
                   "malformed": malformed,
                   "stations_sha256": hashlib.sha256(canonical_bytes(stations)).hexdigest(),
                   "policy_warnings": [w for r in reports for w in r["policy_warnings"]]},
        "by_policy": reports,
    }


def camp_solo_policies(policy: dict) -> list[dict]:
    """What each camp alone claims. Diagnostics, not results."""
    out = []
    for camp, fps in policy["camps"].items():
        out.append({**policy, "name": f"camp-solo:{camp}", "camps": {camp: fps},
                    "rule": {"min_witnesses": 1, "min_camps": 1, "require_camps": [], "require_copresence": False}})
    return out


def load_dir(d: Path) -> tuple[list[dict], list[str]]:
    envs, bad = [], []
    for p in sorted(d.rglob("*.json")):
        try:
            env = json.loads(p.read_text(encoding="utf-8"))
        except json.JSONDecodeError as e:
            bad.append(f"{p.name}: {e}")
            continue
        errs = validate(env)
        if errs:
            bad.append(f"{p.name}: {'; '.join(errs)}")
        else:
            envs.append(env)
    return envs, bad


# ---------------------------------------------------------------- disputes

def disputes(envelopes: list[dict], stations: list, policy: dict, stage: str) -> dict:
    """Stations where the settled witnessed tally differs from the official one at `stage`, by materiality."""
    if stage not in STAGES:
        raise ValueError(f"stage must be one of {list(STAGES)}")
    rep = aggregate(envelopes, stations, policy)
    rows, conflicts = [], []
    for key, r in rep["stations"].items():
        e = next((x for x in r["recap_drift"] if x["stage"] == stage), None)
        if e is None or r["status"] != "settled":
            continue
        if e["status"] == "official_conflict":
            conflicts.append(key)
        elif e["status"] == "differs":
            d = e["delta_official_minus_witnessed"]
            rows.append({"station": r["station"], "form": r["form"], "delta_official_minus_witnessed": d,
                         "abs_delta": sum(abs(v) for v in d.values())})
    rows.sort(key=lambda x: (-x["abs_delta"], x["station"], x["form"]))
    cum: dict[str, int] = {}
    cum_abs = 0
    for x in rows:
        _add(cum, x["delta_official_minus_witnessed"])
        cum_abs += x["abs_delta"]
        x["cumulative_delta"] = dict(sorted(cum.items()))
        x["cumulative_abs_delta"] = cum_abs
    return {
        "policy": rep["policy"], "policy_sha256": rep["policy_sha256"], "official_stage": stage,
        "margin_settled": rep["totals"]["margin_settled"],
        "count": len(rows), "total_abs_delta": cum_abs,
        "stations": rows, "official_conflict": sorted(conflicts),
    }


# ---------------------------------------------------------------- per-station evidence bundle

def _env_key(env: dict):
    return (_body_key(env["body"], body_hash(env["body"])), env.get("sig", ""))


def _station_rows(report: dict, station: str) -> dict:
    return {k: r for k, r in report["stations"].items() if r["station"] == station}


def _select_for_station(envelopes: list[dict], station: str) -> list[dict]:
    """Station envelopes, related captures that its flags depend on, and the signers' full chain."""
    uniq = {canonical_bytes(e): e for e in envelopes}
    envs = sorted(uniq.values(), key=_env_key)
    own = [e for e in envs if e["body"]["type"] in ("capture", "incident", "official") and e["body"]["station"] == station]
    caps = [e["body"] for e in own if e["body"]["type"] == "capture"]
    nonces = {b["nonce"] for b in caps}
    imgs = {("o", b["image"]["orig_sha256"]) for b in caps} | {("d", b["image"]["deriv_sha256"]) for b in caps
                                                                if b["image"]["deriv_sha256"]}
    related = [e for e in envs if e["body"]["type"] == "capture" and e["body"]["station"] != station and (
        e["body"]["nonce"] in nonces or ("o", e["body"]["image"]["orig_sha256"]) in imgs
        or ("d", e["body"]["image"]["deriv_sha256"]) in imgs)]
    signers = {signer_of(e["body"]) for e in own + related if e["body"]["type"] in ("capture", "incident")}
    certs = [e for e in envs if e["body"]["type"] == "witness-cert" and e["body"]["pubkey"] in signers]
    revs = [e for e in envs if e["body"]["type"] == "revocation"
            and any(r["pubkey"] in signers for r in e["body"]["revoked"])]
    issuers = {e["body"]["issuer"] for e in certs + revs}
    org_fps = {e["body"]["org"] for e in certs + revs}
    orgs = [e for e in envs if e["body"]["type"] == "org" and (
        fingerprint(e["body"]["root_pubkey"]) in org_fps or any(ck["pubkey"] in issuers for ck in e["body"]["contest_keys"]))]
    chosen = {canonical_bytes(e): e for e in own + related + certs + revs + orgs}
    return sorted(chosen.values(), key=_env_key)


def _fmt_tally(t: dict) -> str:
    return " ".join(f"{k}={v}" for k, v in sorted(t.items()))


def _fmt_delta(d: dict) -> str:
    return " ".join(f"{k}={v:+d}" for k, v in sorted(d.items()))


def render_station(entry, results: list[dict]) -> list[str]:
    """The printable table: one block per policy and form."""
    st = _station_id(entry)
    dpt = entry.get("dpt") if isinstance(entry, dict) else None
    lines = [
        f"Berkas TPS / station evidence bundle ({SPEC}, verifier {VERSION})",
        f"station: {st}",
        f"dpt: {dpt if dpt is not None else 'unknown'}",
        "vocabulary: station status is settled, disputed, insufficient or missing; a candidate tally is "
        "qualified or contested; an official stage is equal, differs, official_conflict or official_only",
        "signer columns: org/role/camp, key prefix, photo prefix",
    ]
    for res in results:
        lines.append("")
        lines.append(f"policy {res['policy']} (sha256 {res['policy_sha256'][:16]})")
        if not res["rows"]:
            lines.append("  status: missing (no capture and no official record for this station)")
        for key in sorted(res["rows"]):
            r = res["rows"][key]
            lines.append(f"  form {r['form']}: status {r['status']}")
            for label, cands in (("qualified", r["candidates"]), ("contested", r["contested"])):
                for c in cands:
                    lines.append(f"    candidate [{label}] {_fmt_tally(c['tally'])}  ({len(c['supporters'])} signers)")
                    for s in c["supporters"]:
                        who = f"{s['org_name'] or s['org'][:8]}/{s['role']}/{s['camp']}"
                        extra = "  anchored_to_official" if s["anchored_to_official"] else ""
                        lines.append(f"      {who:<36} key {s['pubkey'][:12]}  photo {s['image']['orig_sha256'][:12]}{extra}")
            if r["recap_drift"]:
                lines.append("    official by stage:")
                for e in r["recap_drift"]:
                    if e["status"] == "official_conflict":
                        lines.append(f"      {e['stage']:<9} official_conflict  " + " | ".join(_fmt_tally(t) for t in e["tallies"]))
                    else:
                        line = f"      {e['stage']:<9} {_fmt_tally(e['tally'])}  {e['status']}"
                        if "delta_official_minus_witnessed" in e:
                            line += f"  delta {_fmt_delta(e['delta_official_minus_witnessed'])}"
                        lines.append(line)
            else:
                lines.append("    official by stage: none")
            lines.append(f"    first_divergent_stage: {r['first_divergent_stage'] or 'none'}")
            off = r["official"]
            off_s = "none" if not off else off["status"] + (f" (stage {off['stage']})" if off.get("stage") else "")
            lines.append(f"    official vs witnessed: {off_s}")
            lines.append(f"    flags: {', '.join(r['flags']) if r['flags'] else 'none'}")
            lines.append(f"    incidents: {', '.join(r['incidents']) if r['incidents'] else 'none'}")
    return lines


def _bundle_results(envelopes: list[dict], stations: list, policies: list[dict], station: str) -> list[dict]:
    out = []
    for p in policies:
        rep = aggregate(envelopes, stations, p)
        out.append({"policy": rep["policy"], "policy_sha256": rep["policy_sha256"], "rows": _station_rows(rep, station)})
    return out


def bundle_digest(bundle: dict) -> str:
    return hashlib.sha256(canonical_bytes({k: v for k, v in bundle.items() if k != "bundle_sha256"})).hexdigest()


def make_bundle(envelopes: list[dict], stations: list, policies: list[dict], station: str) -> dict:
    ids, _ = normalize_stations(stations)
    if station not in ids:
        raise ValueError(f"station {station!r} is not in the station list")
    entry = next(e for e in stations if _station_id(e) == station)
    chosen = _select_for_station(envelopes, station)
    results = _bundle_results(envelopes, stations, policies, station)
    # self-check: the selected envelopes alone must reproduce the result computed from everything
    if _bundle_results(chosen, [entry], policies, station) != results:
        raise RuntimeError("bundle is not self-contained for this station")
    bundle = {
        "format": BUNDLE_FORMAT,
        "verifier": {"name": "somnus-wr3", "version": VERSION, "spec": SPEC},
        "station": entry,
        "policies": policies,
        "envelopes": chosen,
        "results": results,
        "rendering": render_station(entry, results),
    }
    bundle["bundle_sha256"] = bundle_digest(bundle)
    return bundle


def verify_bundle(bundle: dict) -> tuple[bool, list[str]]:
    """Recompute everything from the bundle alone."""
    problems = []
    try:
        if bundle.get("format") != BUNDLE_FORMAT:
            problems.append("unknown bundle format")
        if bundle.get("bundle_sha256") != bundle_digest(bundle):
            problems.append("bundle_sha256 does not match the content")
        bad = [f"envelope {i}: {'; '.join(errs)}" for i, e in enumerate(bundle["envelopes"]) if (errs := validate(e))]
        problems += bad
        if not bad:
            entry = bundle["station"]
            station = _station_id(entry)
            results = _bundle_results(bundle["envelopes"], [entry], bundle["policies"], station)
            if results != bundle["results"]:
                names = [r["policy"] for r, s in zip(results, bundle["results"]) if r != s] or ["policy list"]
                problems.append(f"recomputed station result differs for: {', '.join(names)}")
            if render_station(entry, results) != bundle["rendering"]:
                problems.append("rendering does not match the recomputed result")
    except (KeyError, TypeError, ValueError, AttributeError) as e:
        problems.append(f"bundle unreadable: {e}")
    return (not problems), problems


# ---------------------------------------------------------------- demo

def build_demo(out: Path) -> None:
    """Six stations, five orgs in four camps. Every v0 failure mode and every v0.3 flag appears once."""
    import os
    env_dir = out / "envelopes"
    env_dir.mkdir(parents=True, exist_ok=True)
    contest = "demo-2029"
    t0, t1, tc = "2029-02-14T00:00:00+07:00", "2029-02-16T00:00:00+07:00", "2029-02-14T13:00:00+07:00"
    n = 0

    def put(env):
        nonlocal n
        n += 1
        (env_dir / f"{n:03d}-{env['body']['type']}.json").write_text(json.dumps(env, indent=2))

    def make_org(name):
        root, ck = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
        put(seal({"spec": SPEC, "type": "org", "name": name, "root_pubkey": pub_hex(root),
                  "contest_keys": [{"contest": contest, "pubkey": pub_hex(ck)}]}, root))
        return fingerprint(pub_hex(root)), ck

    orgs = {name: make_org(name) for name in ["party-a", "party-a-sybil", "party-b", "watch-ngo", "kpu"]}

    def witness(org, scope="", role="saksi", alg="ed25519"):
        fp, ck = orgs[org]
        sk = es256_key() if alg == "es256" else Ed25519PrivateKey.generate()
        put(seal({"spec": SPEC, "type": "witness-cert", "org": fp, "contest": contest, "pubkey": pub_hex(sk),
                  "alg": alg, "role": role, "scope": scope, "not_before": t0, "not_after": t1,
                  "issuer": pub_hex(ck)}, ck))
        return sk

    def capture(sk, station, tally, photo=None):
        raw = os.urandom(8) if photo is None else photo
        return {"spec": SPEC, "type": "capture", "contest": contest, "station": station, "form": "c-hasil",
                "tally": tally,
                "image": {"orig_sha256": hashlib.sha256(raw).hexdigest(),
                          "deriv_sha256": hashlib.sha256(raw + b"/deriv").hexdigest(),
                          "deriv_params": "jpeg q=60 max=1600"},
                "anchors": [], "captured_at": tc, "nonce": os.urandom(16).hex(), "copresence": [],
                "witness": {"pubkey": pub_hex(sk)}}

    def room(pairs, official=()):
        """Everyone in the room scans everyone else's QR. The KPPS phone signs first; the others
        scan its QR too and record its body hash as an anchor, next to their own photo."""
        everyone = list(official) + list(pairs)
        for b, _ in everyone:
            b["copresence"] = [{"pubkey": o["witness"]["pubkey"], "nonce": o["nonce"]} for o, _ in everyone if o is not b]
        for b, sk in official:
            put(seal(b, sk))
        anchors = sorted(body_hash(b) for b, _ in official)
        for b, sk in pairs:
            b["anchors"] = anchors
            put(seal(b, sk))

    T = lambda a, b: {"a": a, "b": b, "invalid": 1}  # noqa: E731
    W = lambda org, **kw: witness(org, role="pemantau" if org == "watch-ngo" else "saksi", **kw)  # noqa: E731
    # 001 settled: party-a, party-b and the KPPS phone (ES256) agree; recap drifts at PPK
    a, b, k = W("party-a"), W("party-b"), witness("kpu", role="kpps", alg="es256")
    room([(capture(a, "32.01.001", T(120, 98)), a), (capture(b, "32.01.001", T(120, 98)), b)],
         official=[(capture(k, "32.01.001", T(120, 98)), k)])
    # 002 disputed: two qualified stories
    a1, b1, a2, n2 = W("party-a"), W("party-b"), W("party-a"), W("watch-ngo")
    room([(capture(a1, "32.01.002", T(90, 90)), a1), (capture(b1, "32.01.002", T(90, 90)), b1),
          (capture(a2, "32.01.002", T(110, 70)), a2), (capture(n2, "32.01.002", T(110, 70)), n2)])
    # 003 flooded: party-a and its sybil claim a different number from one phone (same_image); same camp
    a, b, n3, s = W("party-a"), W("party-b"), W("watch-ngo"), W("party-a-sybil")
    room([(capture(b, "32.02.003", T(50, 150)), b), (capture(n3, "32.02.003", T(50, 150)), n3),
          (capture(a, "32.02.003", T(150, 50), photo=b"one-phone"), a),
          (capture(s, "32.02.003", T(150, 50), photo=b"one-phone"), s)])
    # 004 insufficient: only one camp present, and the tally exceeds the station's dpt (implausible)
    a, s = W("party-a"), W("party-a-sybil")
    room([(capture(a, "32.02.004", T(200, 10)), a), (capture(s, "32.02.004", T(200, 10)), s)])
    # 005 scoped witness signs outside scope; plus a party-b witness: insufficient
    a, b = W("party-a", scope="32.09"), W("party-b")
    room([(capture(a, "32.02.005", T(70, 70)), a), (capture(b, "32.02.005", T(70, 70)), b)])
    # 006 missing: nobody captured. Official numbers for 001 at three stages: capture and tps agree, ppk does not
    for stage, tally in (("capture", T(120, 98)), ("tps", T(120, 98)), ("ppk", T(130, 88))):
        put({"body": {"spec": SPEC, "type": "official", "contest": contest, "station": "32.01.001", "form": "c-hasil",
                      "stage": stage, "tally": tally,
                      "source": {"url": f"https://example.invalid/{stage}/001", "sha256": "0" * 64}}})
    stations = ["32.01.001", "32.01.002", "32.02.003", {"station": "32.02.004", "dpt": 200}, "32.02.005", "32.02.006"]
    (out / "stations.json").write_text(json.dumps(stations, indent=2))

    fp = {k: v[0] for k, v in orgs.items()}
    two_camps = {"spec": SPEC, "type": "policy", "name": "two-camps", "contest": contest,
                 "camps": {"koalisi-a": [fp["party-a"], fp["party-a-sybil"]], "koalisi-b": [fp["party-b"]],
                           "nonpartisan": [fp["watch-ngo"]], OFFICIAL_CAMP: [fp["kpu"]]},
                 "freeze_at": "2029-02-14T06:00:00+07:00",
                 "rule": {"min_witnesses": 2, "min_camps": 2, "require_camps": [], "require_copresence": True}}
    naive = {**two_camps, "name": "any-2-orgs",
             "camps": {f"org:{k}": [v] for k, v in fp.items()},
             "rule": {"min_witnesses": 2, "min_camps": 2, "require_camps": [], "require_copresence": False}}
    (out / "policy-two-camps.json").write_text(json.dumps(two_camps, indent=2))
    (out / "policy-any-2-orgs.json").write_text(json.dumps(naive, indent=2))
    print(f"demo written to {out}")


# ---------------------------------------------------------------- CLI

def _load_inputs(a) -> tuple[list[dict], list[str], list, list[dict]]:
    envs, bad = load_dir(a.envelopes)
    stations = json.loads(a.stations.read_text(encoding="utf-8"))
    pols = a.policy if isinstance(a.policy, list) else [a.policy]
    policies = [json.loads(p.read_text(encoding="utf-8")) for p in pols]
    return envs, bad, stations, policies


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="wr3")
    sub = ap.add_subparsers(dest="cmd", required=True)
    d = sub.add_parser("demo")
    d.add_argument("out", type=Path)
    v = sub.add_parser("verify")
    v.add_argument("envelopes", type=Path)
    v.add_argument("--stations", type=Path, required=True)
    v.add_argument("--policy", type=Path, action="append", required=True)
    v.add_argument("--camp-solo", action="store_true", help="also report what each camp alone claims")
    b = sub.add_parser("bundle", help="write a self-contained evidence bundle for one station")
    b.add_argument("envelopes", type=Path)
    b.add_argument("--stations", type=Path, required=True)
    b.add_argument("--policy", type=Path, action="append", required=True)
    b.add_argument("--station", required=True)
    b.add_argument("--out", type=Path, required=True)
    vb = sub.add_parser("verify-bundle", help="recompute a bundle with no other input")
    vb.add_argument("file", type=Path)
    ds = sub.add_parser("disputes", help="stations where witnessed differs from official at one stage")
    ds.add_argument("envelopes", type=Path)
    ds.add_argument("--stations", type=Path, required=True)
    ds.add_argument("--policy", type=Path, required=True)
    ds.add_argument("--official-stage", required=True, choices=STAGES)
    a = ap.parse_args(argv)
    try:
        if a.cmd == "demo":
            build_demo(a.out)
            return 0
        if a.cmd == "verify-bundle":
            bundle = json.loads(a.file.read_text(encoding="utf-8"))
            ok, problems = verify_bundle(bundle)
            if ok:
                print(f"OK: bundle {bundle['bundle_sha256'][:16]} for station {_station_id(bundle['station'])} "
                      f"reproduced from its own content under {len(bundle['policies'])} policies")
                return 0
            print(f"FAILED: bundle {a.file.name} does not verify")
            for p in problems:
                print(f"  - {p}")
            return 1
        envs, bad, stations, policies = _load_inputs(a)
        if a.cmd == "verify":
            if a.camp_solo:
                policies += [s for p in policies[:1] for s in camp_solo_policies(p)]
            json.dump(run(envs, stations, policies, bad), sys.stdout, indent=2)
            print()
            return 0
        if a.cmd == "bundle":
            bundle = make_bundle(envs, stations, policies, a.station)
            a.out.write_text(json.dumps(bundle, indent=2, sort_keys=True) + "\n", encoding="utf-8")
            print(f"bundle for station {a.station} written to {a.out} (bundle_sha256 {bundle['bundle_sha256']})")
            return 0
        if a.cmd == "disputes":
            json.dump(disputes(envs, stations, policies[0], a.official_stage), sys.stdout, indent=2)
            print()
            return 0
    except (ValueError, RuntimeError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
