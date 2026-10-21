"""Offline verifier for Witnessed Record spec v0 (draft).

Recompute a public total from records signed by independent witnesses,
without any network access and without trusting the official tabulator.

Usage:
    python -m verifier.wr demo OUT_DIR
    python -m verifier.wr verify RECORDS_DIR --registry REGISTRY.json [--min-witnesses 2] [--min-orgs 2]
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from dataclasses import dataclass, field
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

SPEC = "witnessed-record/0.1"
RECORD_KEYS = {"spec", "tier", "contest", "station", "tally", "image_sha256", "captured_at"}


# ---------- canonical bytes, signing, verification ----------

def canonical_bytes(record: dict) -> bytes:
    """Sorted keys, no whitespace, UTF-8. Identical input gives identical bytes."""
    return json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def validate_record(record: dict) -> list[str]:
    errors = []
    if set(record) != RECORD_KEYS:
        errors.append(f"record keys must be exactly {sorted(RECORD_KEYS)}")
    if record.get("spec") != SPEC:
        errors.append(f"unsupported spec {record.get('spec')!r}")
    if record.get("tier") not in ("witnessed", "historical"):
        errors.append("tier must be 'witnessed' or 'historical'")
    tally = record.get("tally")
    if not isinstance(tally, dict) or not tally:
        errors.append("tally must be a non-empty object")
    elif any(not isinstance(v, int) or isinstance(v, bool) or v < 0 for v in tally.values()):
        errors.append("tally values must be non-negative integers")
    h = record.get("image_sha256", "")
    if not (isinstance(h, str) and len(h) == 64 and all(c in "0123456789abcdef" for c in h)):
        errors.append("image_sha256 must be 64 lowercase hex characters")
    return errors


def pubkey_hex(private_key: Ed25519PrivateKey) -> str:
    return private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()


def sign(record: dict, private_key: Ed25519PrivateKey) -> dict:
    return {"pubkey": pubkey_hex(private_key), "sig": private_key.sign(canonical_bytes(record)).hex()}


def verify_signature(record: dict, pubkey: str, sig: str) -> bool:
    try:
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(pubkey)).verify(bytes.fromhex(sig), canonical_bytes(record))
        return True
    except (InvalidSignature, ValueError):
        return False


# ---------- Merkle root (RFC 6962 prefixes) ----------

def merkle_root(leaves: list[bytes]) -> str:
    if not leaves:
        return hashlib.sha256(b"").hexdigest()
    level = [hashlib.sha256(b"\x00" + leaf).digest() for leaf in leaves]
    while len(level) > 1:
        nxt = []
        for i in range(0, len(level), 2):
            if i + 1 < len(level):
                nxt.append(hashlib.sha256(b"\x01" + level[i] + level[i + 1]).digest())
            else:
                nxt.append(level[i])  # odd node is promoted, as in RFC 6962's split rule
        level = nxt
    return level[0].hex()


# ---------- aggregation ----------

@dataclass
class Report:
    totals: dict[str, int] = field(default_factory=dict)
    accepted: list[str] = field(default_factory=list)
    conflicts: list[str] = field(default_factory=list)
    insufficient: list[str] = field(default_factory=list)
    invalid_files: list[str] = field(default_factory=list)
    rejected_signatures: int = 0
    historical_totals: dict[str, int] = field(default_factory=dict)
    merkle_root: str = ""

    def to_dict(self) -> dict:
        seen = len(self.accepted) + len(self.conflicts) + len(self.insufficient)
        return {
            "totals": dict(sorted(self.totals.items())),
            "coverage": {"accepted": len(self.accepted), "seen": seen},
            "conflicts": sorted(self.conflicts),
            "insufficient_witnesses": sorted(self.insufficient),
            "invalid_files": sorted(self.invalid_files),
            "rejected_signatures": self.rejected_signatures,
            "historical_totals_not_mixed": dict(sorted(self.historical_totals.items())),
            "merkle_root": self.merkle_root,
        }


def aggregate(envelopes: list[dict], registry: dict, min_witnesses: int = 2, min_orgs: int = 2) -> Report:
    report = Report()
    by_station: dict[tuple[str, str], list[dict]] = {}
    historical: dict[tuple[str, str], list[dict]] = {}

    for env in envelopes:
        record = env["record"]
        key = (record["contest"], record["station"])
        if record["tier"] == "historical":
            historical.setdefault(key, []).append(record)
            continue
        valid_orgs, valid_keys = set(), set()
        for w in env.get("witnesses", []):
            pk, sig = w.get("pubkey", ""), w.get("sig", "")
            if pk in registry and pk not in valid_keys and verify_signature(record, pk, sig):
                valid_keys.add(pk)
                valid_orgs.add(registry[pk]["org"])
            else:
                report.rejected_signatures += 1
        if len(valid_keys) >= min_witnesses and len(valid_orgs) >= min_orgs:
            by_station.setdefault(key, []).append(record)
        else:
            by_station.setdefault(key, [])

    accepted_records = []
    for key in sorted(by_station):
        label = f"{key[0]}/{key[1]}"
        records = by_station[key]
        if not records:
            report.insufficient.append(label)
            continue
        distinct = {(json.dumps(r["tally"], sort_keys=True), r["image_sha256"]) for r in records}
        if len(distinct) > 1:
            report.conflicts.append(label)
            continue
        record = records[0]
        report.accepted.append(label)
        accepted_records.append(record)
        for option, n in record["tally"].items():
            report.totals[option] = report.totals.get(option, 0) + n

    for key in sorted(historical):
        for option, n in historical[key][0]["tally"].items():
            report.historical_totals[option] = report.historical_totals.get(option, 0) + n

    report.merkle_root = merkle_root([canonical_bytes(r) for r in accepted_records])
    return report


def load_dir(records_dir: Path, report_errors: list[str]) -> list[dict]:
    envelopes = []
    for path in sorted(records_dir.glob("*.json")):
        try:
            env = json.loads(path.read_text(encoding="utf-8"))
            errs = validate_record(env.get("record", {}))
            if errs:
                report_errors.append(f"{path.name}: {'; '.join(errs)}")
                continue
            envelopes.append(env)
        except (json.JSONDecodeError, AttributeError) as exc:
            report_errors.append(f"{path.name}: {exc}")
    return envelopes


# ---------- demo data ----------

def build_demo(out_dir: Path) -> None:
    """Five stations, three witness orgs. Includes one conflict, one forged signature, one historical record."""
    out_dir.mkdir(parents=True, exist_ok=True)
    rec_dir = out_dir / "records"
    rec_dir.mkdir(exist_ok=True)
    orgs = ["party-a", "party-b", "observer-c"]
    keys = {org: Ed25519PrivateKey.generate() for org in orgs}
    forger = Ed25519PrivateKey.generate()  # not in registry
    registry = {pubkey_hex(k): {"role": "witness", "org": org} for org, k in keys.items()}
    (out_dir / "registry.json").write_text(json.dumps(registry, indent=2))

    def record(station, a, b, img="photo", tier="witnessed"):
        return {
            "spec": SPEC, "tier": tier, "contest": "demo-2029", "station": station,
            "tally": {"A": a, "B": b, "invalid": 1},
            "image_sha256": hashlib.sha256(f"{img}-{station}".encode()).hexdigest(),
            "captured_at": "2029-02-14T13:00:00+07:00",
        }

    def write(name, rec, signers):
        env = {"record": rec, "witnesses": [sign(rec, k) for k in signers]}
        (rec_dir / f"{name}.json").write_text(json.dumps(env, indent=2))

    write("001", record("001", 120, 98), [keys["party-a"], keys["party-b"]])
    write("002", record("002", 80, 110), [keys["party-a"], keys["observer-c"]])
    # station 003: two accepted records disagree -> conflict
    write("003-a", record("003", 90, 90), [keys["party-a"], keys["observer-c"]])
    write("003-b", record("003", 60, 120, img="other"), [keys["party-b"], keys["observer-c"]])
    # station 004: one real witness plus a forger -> insufficient
    write("004", record("004", 200, 10), [keys["party-a"], forger])
    # station 005: re-entered from a published scan, no witnesses -> historical tier
    write("005-hist", record("005", 70, 70, tier="historical"), [])
    print(f"demo written to {out_dir}")


# ---------- CLI ----------

def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="wr", description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="cmd", required=True)
    d = sub.add_parser("demo", help="write a demo dataset")
    d.add_argument("out_dir", type=Path)
    v = sub.add_parser("verify", help="recompute totals from a folder of signed records")
    v.add_argument("records_dir", type=Path)
    v.add_argument("--registry", type=Path, required=True)
    v.add_argument("--min-witnesses", type=int, default=2)
    v.add_argument("--min-orgs", type=int, default=2)
    args = parser.parse_args(argv)

    if args.cmd == "demo":
        build_demo(args.out_dir)
        return 0

    errors: list[str] = []
    envelopes = load_dir(args.records_dir, errors)
    registry = json.loads(args.registry.read_text(encoding="utf-8"))
    report = aggregate(envelopes, registry, args.min_witnesses, args.min_orgs)
    report.invalid_files = errors
    json.dump(report.to_dict(), sys.stdout, indent=2)
    print()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
