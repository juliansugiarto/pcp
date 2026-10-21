"""Offline verifier for Witnessed Record spec v0.2 (draft).

Changes from v0 (see spec/witnessed-record-v0.2.md):
- one capture per witness, each with its own photo; consensus is on the tally only
- conflicts are evidence and produce bounds (min/max), never deletion
- independence is a verifier policy (orgs grouped into camps), several policies side by side
- org -> witness certificate key model with scope, validity window and prospective revocation
- in-room co-presence by nonce exchange
- official numbers carried alongside and diffed per station
- one policy-free log root over every well-formed envelope

Usage:
    python -m verifier.wr2 demo OUT_DIR
    python -m verifier.wr2 verify ENVELOPES_DIR --stations STATIONS.json --policy P1.json [--policy P2.json ...]
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
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

SPEC = "witnessed-record/0.2"
VERSION = "0.2.0-draft"
KEY_RE = re.compile(r"^[a-z0-9_.-]{1,32}$")
HEX32 = re.compile(r"^[0-9a-f]{64}$")
HEX16 = re.compile(r"^[0-9a-f]{32}$")
TYPES = {"org", "witness-cert", "revocation", "capture", "incident", "official"}
SIGNED_TYPES = {"org", "witness-cert", "revocation", "capture", "incident"}


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


def canonical_bytes(body: dict) -> bytes:
    """RFC 8785 (JCS) for the restricted domain used here: ascii keys, strings, integers, no floats.

    For this domain Python's sorted, compact json.dumps produces JCS-identical bytes.
    """
    _check_keys(body)
    return json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def signing_input(body: dict) -> bytes:
    return f"wr/0.2/{body['type']}\n".encode() + canonical_bytes(body)


def envelope_hash(env: dict) -> str:
    return hashlib.sha256(canonical_bytes(env)).hexdigest()


def pub_hex(sk: Ed25519PrivateKey) -> str:
    return sk.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()


def fingerprint(root_pubkey_hex: str) -> str:
    return hashlib.sha256(bytes.fromhex(root_pubkey_hex)).hexdigest()[:32]


def seal(body: dict, sk: Ed25519PrivateKey | None) -> dict:
    env = {"body": body}
    if sk is not None:
        env["sig"] = sk.sign(signing_input(body)).hex()
    return env


def verify_sig(body: dict, sig: str, pubkey_hex: str) -> bool:
    try:
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(pubkey_hex)).verify(bytes.fromhex(sig), signing_input(body))
        return True
    except (InvalidSignature, ValueError):
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


def validate(env: dict) -> list[str]:
    """Structural validation. Signatures are checked later, against the key table."""
    errs = []
    body = env.get("body")
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
        "witness-cert": {"spec", "type", "org", "contest", "pubkey", "scope", "not_before", "not_after", "issuer"},
        "revocation": {"spec", "type", "org", "contest", "issuer", "issued_at", "revoked"},
        "capture": {"spec", "type", "contest", "station", "form", "tally", "image", "captured_at", "nonce", "copresence", "witness"},
        "incident": {"spec", "type", "contest", "station", "kind", "note", "ref", "witness"},
        "official": {"spec", "type", "contest", "station", "form", "tally", "source"},
    }[t]
    if set(body) != need:
        errs.append(f"{t}: keys must be exactly {sorted(need)}")
        return errs
    if t in ("capture", "official") and not _tally_ok(body["tally"]):
        errs.append("bad tally")
    if t == "capture":
        img = body["image"]
        if not (isinstance(img, dict) and HEX32.match(str(img.get("sha256", "")))):
            errs.append("bad image.sha256")
        if not HEX16.match(str(body["nonce"])):
            errs.append("nonce must be 16 bytes hex")
        w = body["witness"]
        if not (isinstance(w, dict) and HEX32.match(str(w.get("pubkey", "")))):
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
        try:
            if parse_time(body["not_before"]) >= parse_time(body["not_after"]):
                errs.append("empty validity window")
        except (ValueError, TypeError):
            errs.append("bad validity times")
    if t == "incident" and body["kind"] not in ("copy_refused", "no_access", "not_visible", "retraction"):
        errs.append("bad incident kind")
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


def _sort_key(env: dict):
    b = env["body"]
    return (b["type"], b.get("contest", ""), b.get("station", ""), signer_of(b) or "", envelope_hash(env))


def input_root(envelopes: list[dict]) -> str:
    """Policy-free: every well-formed envelope, same root for every honest mirror."""
    return merkle_root([canonical_bytes(e) for e in sorted(envelopes, key=_sort_key)])


# ---------------------------------------------------------------- key table

def build_key_table(envelopes: list[dict], policy: dict, rejected: dict) -> dict:
    contest = policy["contest"]
    camp_of = {fp: camp for camp, fps in policy["camps"].items() for fp in fps}
    contest_keys: dict[str, str] = {}  # contest pubkey -> org fp
    for env in envelopes:
        b = env["body"]
        if b["type"] != "org":
            continue
        if not verify_sig(b, env["sig"], b["root_pubkey"]):
            rejected["bad_signature"] += 1
            continue
        fp = fingerprint(b["root_pubkey"])
        for ck in b["contest_keys"]:
            if ck.get("contest") == contest:
                contest_keys[ck["pubkey"]] = fp

    revoked: dict[str, datetime] = {}
    for env in envelopes:
        b = env["body"]
        if b["type"] != "revocation" or b["contest"] != contest:
            continue
        if contest_keys.get(b["issuer"]) != b["org"] or not verify_sig(b, env["sig"], b["issuer"]):
            rejected["bad_signature"] += 1
            continue
        for r in b["revoked"]:
            t = parse_time(r["effective"])
            revoked[r["pubkey"]] = min(t, revoked.get(r["pubkey"], t))

    table = {}
    for env in envelopes:
        b = env["body"]
        if b["type"] != "witness-cert" or b["contest"] != contest:
            continue
        org = contest_keys.get(b["issuer"])
        if org is None or org != b["org"]:
            rejected["unknown_key"] += 1
            continue
        if not verify_sig(b, env["sig"], b["issuer"]):
            rejected["bad_signature"] += 1
            continue
        if org not in camp_of:
            continue  # org exists but this policy does not count it
        table[b["pubkey"]] = {
            "org": org, "camp": camp_of[org], "scope": b["scope"] or "",
            "not_before": parse_time(b["not_before"]), "not_after": parse_time(b["not_after"]),
            "revoked_at": revoked.get(b["pubkey"]),
        }
    return table


# ---------------------------------------------------------------- aggregation

def _add(acc: dict, tally: dict, sign: int = 1) -> None:
    for k, v in tally.items():
        acc[k] = acc.get(k, 0) + sign * v


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


def aggregate(envelopes: list[dict], stations: list[str], policy: dict) -> dict:
    rule = policy["rule"]
    contest = policy["contest"]
    rejected = {"bad_signature": 0, "unknown_key": 0, "out_of_scope": 0, "expired": 0, "revoked": 0, "self_conflict": 0}
    table = build_key_table(envelopes, policy, rejected)

    # captures per (station, form)
    by_sf: dict[tuple[str, str], list[dict]] = {}
    seen_witness: dict[tuple[str, str, str], str] = {}
    for env in envelopes:
        b = env["body"]
        if b["type"] != "capture" or b["contest"] != contest:
            continue
        pk = b["witness"]["pubkey"]
        info = table.get(pk)
        if info is None:
            rejected["unknown_key"] += 1
            continue
        if not verify_sig(b, env["sig"], pk):
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
        tally_c = json.dumps(b["tally"], sort_keys=True)
        if key in seen_witness and seen_witness[key] != tally_c:
            rejected["self_conflict"] += 1
            # keep neither: a witness who told two stories counts for nothing at this station
            by_sf[(b["station"], b["form"])] = [c for c in by_sf.get((b["station"], b["form"]), []) if c["pubkey"] != pk]
            seen_witness[key] = "!conflict"
            continue
        if seen_witness.get(key) == "!conflict" or key in seen_witness:
            continue
        seen_witness[key] = tally_c
        by_sf.setdefault((b["station"], b["form"]), []).append({
            "pubkey": pk, "org": info["org"], "camp": info["camp"],
            "tally": b["tally"], "image": b["image"]["sha256"],
            "nonce": b["nonce"], "copresence": b["copresence"],
        })

    officials: dict[tuple[str, str], list[dict]] = {}
    for env in envelopes:
        b = env["body"]
        if b["type"] == "official" and b["contest"] == contest:
            officials.setdefault((b["station"], b["form"]), []).append(b["tally"])

    incidents: dict[str, list[str]] = {}
    for env in envelopes:
        b = env["body"]
        if b["type"] == "incident" and b["contest"] == contest and b["witness"]["pubkey"] in table:
            if verify_sig(b, env["sig"], b["witness"]["pubkey"]):
                incidents.setdefault(b["station"], []).append(b["kind"])

    report_st = {}
    settled_tot: dict[str, int] = {}
    lo_tot: dict[str, int] = {}
    hi_tot: dict[str, int] = {}
    counts = {"settled": 0, "disputed": 0, "insufficient": 0, "missing": 0}
    diff = {"equal": 0, "differs": 0, "official_only": 0, "witnessed_only": 0, "official_conflict": 0}
    by_camp: dict[str, int] = {}
    by_prov: dict[str, dict] = {}

    keys = sorted(set(by_sf) | set(officials) | {(s, f) for s in stations for f in _forms(by_sf, officials, s)})
    stations_seen = set()
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
            groups.setdefault(json.dumps(c["tally"], sort_keys=True), []).append(c)
        cands = []
        for tk, sup in groups.items():
            cands.append({
                "tally": json.loads(tk),
                "supporters": [{"pubkey": s["pubkey"], "org": s["org"], "camp": s["camp"], "image": s["image"]} for s in sup],
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

        off = officials.get((st, form), [])
        off_distinct = {json.dumps(t, sort_keys=True) for t in off}
        off_status = None
        if len(off_distinct) > 1:
            off_status = {"status": "official_conflict"}
        elif off and status == "settled":
            o = off[0]
            w = qual[0]["tally"]
            delta = {k: o.get(k, 0) - w.get(k, 0) for k in set(o) | set(w) if o.get(k, 0) != w.get(k, 0)}
            off_status = {"status": "equal"} if not delta else {"status": "differs", "delta_official_minus_witnessed": delta}
        elif off and status != "settled":
            off_status = {"status": "official_only"}
        elif not off and status == "settled":
            off_status = {"status": "witnessed_only"}
        if off_status:
            diff[off_status["status"]] += 1

        if status != "missing" or off:
            report_st[f"{st}/{form}"] = {
                "status": status,
                "candidates": [c for c in cands if c["qualified"]],
                "contested": [c for c in cands if not c["qualified"]],
                "incidents": incidents.get(st, []),
                "official": off_status,
            }

    for st in stations:
        if st not in stations_seen:
            counts["missing"] += 1
            by_prov.setdefault(st.split(".")[0], {"settled": 0, "disputed": 0, "insufficient": 0, "missing": 0})["missing"] += 1

    ranked = sorted(lo_tot, key=lambda k: -settled_tot.get(k, 0))
    ranked = [k for k in ranked if k != "invalid"]
    flip, margin = False, None
    if len(ranked) >= 2:
        leader, runner = ranked[0], ranked[1]
        margin = settled_tot.get(leader, 0) - settled_tot.get(runner, 0)
        flip = hi_tot.get(runner, 0) >= lo_tot.get(leader, 0)

    return {
        "policy": policy.get("name", ""),
        "policy_sha256": hashlib.sha256(json.dumps(policy, sort_keys=True).encode()).hexdigest(),
        "totals": {"settled": dict(sorted(settled_tot.items())), "min": dict(sorted(lo_tot.items())),
                   "max": dict(sorted(hi_tot.items())), "flip": flip, "margin_settled": margin},
        "status_counts": counts,
        "coverage": {"by_province": by_prov, "stations_with_camp": dict(sorted(by_camp.items())),
                     "missing": sorted(set(stations) - stations_seen)},
        "diff_vs_official": diff,
        "rejected": rejected,
        "stations": report_st,
    }


def _forms(by_sf, officials, station):
    forms = {f for (s, f) in list(by_sf) + list(officials) if s == station}
    return forms or set()


def run(envelopes: list[dict], stations: list[str], policies: list[dict], malformed: list[str]) -> dict:
    return {
        "header": {"verifier": {"name": "somnus-wr2", "version": VERSION}, "input_root": input_root(envelopes),
                   "envelopes": len(envelopes), "malformed": malformed,
                   "stations_sha256": hashlib.sha256(json.dumps(stations).encode()).hexdigest()},
        "by_policy": [aggregate(envelopes, stations, p) for p in policies],
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


# ---------------------------------------------------------------- demo

def build_demo(out: Path) -> None:
    """Six stations, four orgs in three camps. Every v0 failure mode appears once."""
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

    orgs = {name: make_org(name) for name in ["party-a", "party-a-sybil", "party-b", "watch-ngo"]}

    def witness(org, scope=""):
        fp, ck = orgs[org]
        sk = Ed25519PrivateKey.generate()
        put(seal({"spec": SPEC, "type": "witness-cert", "org": fp, "contest": contest, "pubkey": pub_hex(sk),
                  "scope": scope, "not_before": t0, "not_after": t1, "issuer": pub_hex(ck)}, ck))
        return sk

    def capture(sk, station, tally, others=(), photo=None):
        nonce = os.urandom(16).hex()
        body = {"spec": SPEC, "type": "capture", "contest": contest, "station": station, "form": "c-hasil",
                "tally": tally, "image": {"sha256": hashlib.sha256(os.urandom(8) if photo is None else photo).hexdigest()},
                "captured_at": tc, "nonce": nonce, "copresence": [], "witness": {"pubkey": pub_hex(sk)}}
        return body

    def room(bodies_and_keys):
        """Everyone in the room scans everyone else's QR, then signs."""
        for b, _ in bodies_and_keys:
            b["copresence"] = [{"pubkey": o["witness"]["pubkey"], "nonce": o["nonce"]}
                               for o, _ in bodies_and_keys if o is not b]
        for b, sk in bodies_and_keys:
            put(seal(b, sk))

    T = lambda a, b: {"a": a, "b": b, "invalid": 1}
    # 001 settled: party-a and party-b agree, different photos, cross-scanned
    a, b = witness("party-a"), witness("party-b")
    room([(capture(a, "32.01.001", T(120, 98)), a), (capture(b, "32.01.001", T(120, 98)), b)])
    # 002 disputed: two qualified stories
    a1, b1, a2, n2 = witness("party-a"), witness("party-b"), witness("party-a"), witness("watch-ngo")
    room([(capture(a1, "32.01.002", T(90, 90)), a1), (capture(b1, "32.01.002", T(90, 90)), b1),
          (capture(a2, "32.01.002", T(110, 70)), a2), (capture(n2, "32.01.002", T(110, 70)), n2)])
    # 003 flooded: party-a and its sybil claim a different number; same camp, so it cannot qualify
    a, b, n3, s = witness("party-a"), witness("party-b"), witness("watch-ngo"), witness("party-a-sybil")
    room([(capture(b, "32.02.003", T(50, 150)), b), (capture(n3, "32.02.003", T(50, 150)), n3),
          (capture(a, "32.02.003", T(150, 50)), a), (capture(s, "32.02.003", T(150, 50)), s)])
    # 004 insufficient: only one camp present
    a, s = witness("party-a"), witness("party-a-sybil")
    room([(capture(a, "32.02.004", T(200, 10)), a), (capture(s, "32.02.004", T(200, 10)), s)])
    # 005 scoped witness signs outside scope; plus a party-b witness: insufficient
    a, b = witness("party-a", scope="32.09"), witness("party-b")
    room([(capture(a, "32.02.005", T(70, 70)), a), (capture(b, "32.02.005", T(70, 70)), b)])
    # 006 missing: nobody captured; official numbers exist for 001 and 002
    put({"body": {"spec": SPEC, "type": "official", "contest": contest, "station": "32.01.001", "form": "c-hasil",
                  "tally": T(130, 88), "source": {"url": "https://example.invalid/scan/001", "sha256": "0" * 64}}})
    stations = ["32.01.001", "32.01.002", "32.02.003", "32.02.004", "32.02.005", "32.02.006"]
    (out / "stations.json").write_text(json.dumps(stations, indent=2))

    fp = {k: v[0] for k, v in orgs.items()}
    two_camps = {"spec": SPEC, "type": "policy", "name": "two-camps", "contest": contest,
                 "camps": {"koalisi-a": [fp["party-a"], fp["party-a-sybil"]], "koalisi-b": [fp["party-b"]],
                           "nonpartisan": [fp["watch-ngo"]]},
                 "rule": {"min_witnesses": 2, "min_camps": 2, "require_camps": [], "require_copresence": True}}
    naive = {**two_camps, "name": "any-2-orgs",
             "camps": {f"org:{k}": [v] for k, v in fp.items()},
             "rule": {"min_witnesses": 2, "min_camps": 2, "require_camps": [], "require_copresence": False}}
    (out / "policy-two-camps.json").write_text(json.dumps(two_camps, indent=2))
    (out / "policy-any-2-orgs.json").write_text(json.dumps(naive, indent=2))
    print(f"demo written to {out}")


# ---------------------------------------------------------------- CLI

def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="wr2")
    sub = ap.add_subparsers(dest="cmd", required=True)
    d = sub.add_parser("demo")
    d.add_argument("out", type=Path)
    v = sub.add_parser("verify")
    v.add_argument("envelopes", type=Path)
    v.add_argument("--stations", type=Path, required=True)
    v.add_argument("--policy", type=Path, action="append", required=True)
    v.add_argument("--camp-solo", action="store_true", help="also report what each camp alone claims")
    a = ap.parse_args(argv)
    if a.cmd == "demo":
        build_demo(a.out)
        return 0
    envs, bad = load_dir(a.envelopes)
    stations = json.loads(a.stations.read_text(encoding="utf-8"))
    policies = [json.loads(p.read_text(encoding="utf-8")) for p in a.policy]
    if a.camp_solo:
        policies += [s for p in policies[:1] for s in camp_solo_policies(p)]
    json.dump(run(envs, stations, policies, bad), sys.stdout, indent=2)
    print()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
