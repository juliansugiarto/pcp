"""Conformance-style tests for spec v0.2. One test per attack or v0 failure it fixes."""

import json
import os
import tempfile
import unittest
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from verifier import wr2

C = "t-2029"
T0, T1, TC = "2029-02-14T00:00:00+07:00", "2029-02-16T00:00:00+07:00", "2029-02-14T13:00:00+07:00"


class World:
    """A tiny election world: orgs, witness certs, captures."""

    def __init__(self):
        self.envs = []
        self.orgs = {}

    def org(self, name):
        root, ck = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
        self.envs.append(wr2.seal({"spec": wr2.SPEC, "type": "org", "name": name, "root_pubkey": wr2.pub_hex(root),
                                   "contest_keys": [{"contest": C, "pubkey": wr2.pub_hex(ck)}]}, root))
        self.orgs[name] = (wr2.fingerprint(wr2.pub_hex(root)), ck)
        return self.orgs[name][0]

    def witness(self, org, scope="", nb=T0, na=T1):
        fp, ck = self.orgs[org]
        sk = Ed25519PrivateKey.generate()
        self.envs.append(wr2.seal({"spec": wr2.SPEC, "type": "witness-cert", "org": fp, "contest": C,
                                   "pubkey": wr2.pub_hex(sk), "scope": scope, "not_before": nb, "not_after": na,
                                   "issuer": wr2.pub_hex(ck)}, ck))
        return sk

    def body(self, sk, station, a, b, at=TC):
        return {"spec": wr2.SPEC, "type": "capture", "contest": C, "station": station, "form": "f",
                "tally": {"a": a, "b": b}, "image": {"sha256": os.urandom(32).hex()}, "captured_at": at,
                "nonce": os.urandom(16).hex(), "copresence": [], "witness": {"pubkey": wr2.pub_hex(sk)}}

    def room(self, *pairs, scan=True):
        if scan:
            for b, _ in pairs:
                b["copresence"] = [{"pubkey": o["witness"]["pubkey"], "nonce": o["nonce"]} for o, _ in pairs if o is not b]
        for b, sk in pairs:
            self.envs.append(wr2.seal(b, sk))

    def policy(self, camps, **rule):
        r = {"min_witnesses": 2, "min_camps": 2, "require_camps": [], "require_copresence": True}
        r.update(rule)
        return {"name": "p", "contest": C, "camps": camps, "rule": r}


def agg(w, policy, stations=("s1",)):
    for e in w.envs:
        assert not wr2.validate(e), wr2.validate(e)
    return wr2.aggregate(w.envs, list(stations), policy)


class TestV02(unittest.TestCase):
    def setUp(self):
        self.w = World()
        self.fa, self.fb, self.fn = self.w.org("A"), self.w.org("B"), self.w.org("N")
        self.camps = {"ka": [self.fa], "kb": [self.fb], "np": [self.fn]}

    def test_E1_different_photos_same_tally_is_settled(self):
        a, b = self.w.witness("A"), self.w.witness("B")
        self.w.room((self.w.body(a, "s1", 10, 5), a), (self.w.body(b, "s1", 10, 5), b))
        r = agg(self.w, self.w.policy(self.camps))
        self.assertEqual(r["stations"]["s1/f"]["status"], "settled")
        self.assertEqual(r["totals"]["settled"], {"a": 10, "b": 5})

    def test_E2_flood_from_one_camp_does_not_erase_station(self):
        a, b, n = self.w.witness("A"), self.w.witness("B"), self.w.witness("N")
        a2 = self.w.witness("A")
        self.w.room((self.w.body(b, "s1", 10, 5), b), (self.w.body(n, "s1", 10, 5), n),
                    (self.w.body(a, "s1", 99, 0), a), (self.w.body(a2, "s1", 99, 0), a2))
        r = agg(self.w, self.w.policy(self.camps))
        st = r["stations"]["s1/f"]
        self.assertEqual(st["status"], "settled")
        self.assertEqual(len(st["contested"]), 1)
        self.assertEqual(r["totals"]["settled"], {"a": 10, "b": 5})

    def test_two_qualified_stories_give_bounds_not_deletion(self):
        a, b, a2, n = (self.w.witness(x) for x in ("A", "B", "A", "N"))
        self.w.room((self.w.body(a, "s1", 10, 5), a), (self.w.body(b, "s1", 10, 5), b),
                    (self.w.body(a2, "s1", 12, 3), a2), (self.w.body(n, "s1", 12, 3), n))
        r = agg(self.w, self.w.policy(self.camps))
        self.assertEqual(r["stations"]["s1/f"]["status"], "disputed")
        self.assertEqual(r["totals"]["min"], {"a": 10, "b": 3})
        self.assertEqual(r["totals"]["max"], {"a": 12, "b": 5})

    def test_E3_input_root_is_policy_free(self):
        a, b = self.w.witness("A"), self.w.witness("B")
        self.w.room((self.w.body(a, "s1", 10, 5), a), (self.w.body(b, "s1", 10, 5), b))
        r1 = wr2.run(self.w.envs, ["s1"], [self.w.policy(self.camps)], [])
        r2 = wr2.run(list(reversed(self.w.envs)), ["s1"], [self.w.policy({"x": [self.fa]})], [])
        self.assertEqual(r1["header"]["input_root"], r2["header"]["input_root"])

    def test_sybil_org_in_same_camp_does_not_qualify(self):
        fs = self.w.org("A-sybil")
        a, s = self.w.witness("A"), self.w.witness("A-sybil")
        self.w.room((self.w.body(a, "s1", 50, 0), a), (self.w.body(s, "s1", 50, 0), s))
        honest = agg(self.w, self.w.policy({"ka": [self.fa, fs], "kb": [self.fb]}))
        naive = agg(self.w, self.w.policy({"o1": [self.fa], "o2": [fs]}, require_copresence=False))
        self.assertEqual(honest["stations"]["s1/f"]["status"], "insufficient")
        self.assertEqual(naive["stations"]["s1/f"]["status"], "settled")

    def test_replay_to_another_station_breaks_signature(self):
        a, b = self.w.witness("A"), self.w.witness("B")
        self.w.room((self.w.body(a, "s1", 10, 5), a), (self.w.body(b, "s1", 10, 5), b))
        for e in self.w.envs:
            if e["body"]["type"] == "capture":
                e["body"]["station"] = "s2"
        r = agg(self.w, self.w.policy(self.camps), stations=("s1", "s2"))
        self.assertEqual(r["rejected"]["bad_signature"], 2)
        self.assertEqual(r["status_counts"]["missing"], 2)

    def test_copresence_required(self):
        a, b = self.w.witness("A"), self.w.witness("B")
        self.w.room((self.w.body(a, "s1", 10, 5), a), (self.w.body(b, "s1", 10, 5), b), scan=False)
        self.assertEqual(agg(self.w, self.w.policy(self.camps))["stations"]["s1/f"]["status"], "insufficient")
        self.assertEqual(agg(self.w, self.w.policy(self.camps, require_copresence=False))["stations"]["s1/f"]["status"], "settled")

    def test_scope_and_validity_window(self):
        a = self.w.witness("A", scope="32.09")
        b = self.w.witness("B", nb="2029-02-15T00:00:00+07:00")
        self.w.room((self.w.body(a, "32.01.1", 10, 5), a), (self.w.body(b, "32.01.1", 10, 5), b))
        r = agg(self.w, self.w.policy(self.camps), stations=("32.01.1",))
        self.assertEqual(r["rejected"]["out_of_scope"], 1)
        self.assertEqual(r["rejected"]["expired"], 1)

    def test_revocation_is_prospective(self):
        a, b = self.w.witness("A"), self.w.witness("B")
        self.w.room((self.w.body(a, "s1", 10, 5), a), (self.w.body(b, "s1", 10, 5), b))
        fp, ck = self.w.orgs["A"]
        self.w.envs.append(wr2.seal({"spec": wr2.SPEC, "type": "revocation", "org": fp, "contest": C,
                                     "issuer": wr2.pub_hex(ck), "issued_at": "2029-02-15T00:00:00+07:00",
                                     "revoked": [{"pubkey": wr2.pub_hex(a), "effective": "2029-02-14T20:00:00+07:00"}]}, ck))
        r = agg(self.w, self.w.policy(self.camps))
        self.assertEqual(r["stations"]["s1/f"]["status"], "settled")
        self.assertEqual(r["rejected"]["revoked"], 0)

    def test_witness_telling_two_stories_counts_for_nothing(self):
        a, b, n = self.w.witness("A"), self.w.witness("B"), self.w.witness("N")
        first = self.w.body(a, "s1", 10, 5)
        self.w.room((first, a), (self.w.body(b, "s1", 10, 5), b))
        second = self.w.body(a, "s1", 11, 4)
        self.w.envs.append(wr2.seal(second, a))
        r = agg(self.w, self.w.policy(self.camps, require_copresence=False))
        self.assertEqual(r["rejected"]["self_conflict"], 1)
        self.assertEqual(r["stations"]["s1/f"]["status"], "insufficient")

    def test_official_diff(self):
        a, b = self.w.witness("A"), self.w.witness("B")
        self.w.room((self.w.body(a, "s1", 10, 5), a), (self.w.body(b, "s1", 10, 5), b))
        self.w.envs.append({"body": {"spec": wr2.SPEC, "type": "official", "contest": C, "station": "s1", "form": "f",
                                     "tally": {"a": 12, "b": 3}, "source": {"url": "x", "sha256": "0" * 64}}})
        r = agg(self.w, self.w.policy(self.camps))
        self.assertEqual(r["stations"]["s1/f"]["official"],
                         {"status": "differs", "delta_official_minus_witnessed": {"a": 2, "b": -2}})

    def test_validation_rejects_float_and_non_ascii_keys(self):
        a = self.w.witness("A")
        body = self.w.body(a, "s1", 10, 5)
        body["tally"]["é"] = 1
        with self.assertRaises(ValueError):
            wr2.seal(body, a)
        self.assertTrue(wr2.validate({"body": body, "sig": "00"}))
        with self.assertRaises(ValueError):
            wr2.canonical_bytes({"type": "capture", "x": 1.5})

    def test_demo_end_to_end(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            wr2.build_demo(out)
            envs, bad = wr2.load_dir(out / "envelopes")
            self.assertEqual(bad, [])
            stations = json.loads((out / "stations.json").read_text())
            p = json.loads((out / "policy-two-camps.json").read_text())
            r = wr2.aggregate(envs, stations, p)
            self.assertEqual(r["status_counts"], {"settled": 2, "disputed": 1, "insufficient": 2, "missing": 1})


if __name__ == "__main__":
    unittest.main()
