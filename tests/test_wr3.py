"""Conformance-style tests for spec v0.3. v0.2 tests are ported; v0.3 adds one test per change."""

import ast
import contextlib
import io
import json
import os
import tempfile
import unittest
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from verifier import wr3

C = "t-2029"
T0, T1, TC = "2029-02-14T00:00:00+07:00", "2029-02-16T00:00:00+07:00", "2029-02-14T13:00:00+07:00"
P256_N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
FORBIDDEN = ("fraud", "curang", "kecurangan")


class World:
    """A tiny election world: orgs, witness certs, captures, official records."""

    def __init__(self):
        self.envs = []
        self.orgs = {}

    def org(self, name):
        root, ck = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
        self.envs.append(wr3.seal({"spec": wr3.SPEC, "type": "org", "name": name, "root_pubkey": wr3.pub_hex(root),
                                   "contest_keys": [{"contest": C, "pubkey": wr3.pub_hex(ck)}]}, root))
        self.orgs[name] = (wr3.fingerprint(wr3.pub_hex(root)), ck)
        return self.orgs[name][0]

    def witness(self, org, scope="", nb=T0, na=T1, role="saksi", alg="ed25519"):
        fp, ck = self.orgs[org]
        sk = wr3.es256_key() if alg == "es256" else Ed25519PrivateKey.generate()
        self.envs.append(wr3.seal({"spec": wr3.SPEC, "type": "witness-cert", "org": fp, "contest": C,
                                   "pubkey": wr3.pub_hex(sk), "alg": alg, "role": role, "scope": scope,
                                   "not_before": nb, "not_after": na, "issuer": wr3.pub_hex(ck)}, ck))
        return sk

    def body(self, sk, station, a, b, at=TC, orig=None, deriv=None, nonce=None, anchors=()):
        return {"spec": wr3.SPEC, "type": "capture", "contest": C, "station": station, "form": "f",
                "tally": {"a": a, "b": b},
                "image": {"orig_sha256": orig or os.urandom(32).hex(),
                          "deriv_sha256": os.urandom(32).hex() if deriv is None else deriv,
                          "deriv_params": "jpeg q=60"},
                "anchors": list(anchors), "captured_at": at, "nonce": nonce or os.urandom(16).hex(),
                "copresence": [], "witness": {"pubkey": wr3.pub_hex(sk)}}

    def room(self, *pairs, scan=True):
        if scan:
            for b, _ in pairs:
                b["copresence"] = [{"pubkey": o["witness"]["pubkey"], "nonce": o["nonce"]} for o, _ in pairs if o is not b]
        for b, sk in pairs:
            self.envs.append(wr3.seal(b, sk))

    def official(self, station, a, b, stage="tps"):
        self.envs.append({"body": {"spec": wr3.SPEC, "type": "official", "contest": C, "station": station, "form": "f",
                                   "stage": stage, "tally": {"a": a, "b": b},
                                   "source": {"url": "x", "sha256": "0" * 64}}})

    def policy(self, camps, **rule):
        r = {"min_witnesses": 2, "min_camps": 2, "require_camps": [], "require_copresence": True}
        freeze = rule.pop("freeze_at", None)
        r.update(rule)
        p = {"name": "p", "contest": C, "camps": camps, "rule": r}
        if freeze:
            p["freeze_at"] = freeze
        return p


def agg(w, policy, stations=("s1",)):
    for e in w.envs:
        assert not wr3.validate(e), wr3.validate(e)
    return wr3.aggregate(w.envs, list(stations), policy)


def flip_s(sig_hex):
    """Re-encode an ES256 r||s signature with high/low S swapped: still valid, different bytes."""
    raw = bytes.fromhex(sig_hex)
    r, s = raw[:32], int.from_bytes(raw[32:], "big")
    return (r + (P256_N - s).to_bytes(32, "big")).hex()


class Base(unittest.TestCase):
    def setUp(self):
        self.w = World()
        self.fa, self.fb, self.fn = self.w.org("A"), self.w.org("B"), self.w.org("N")
        self.camps = {"ka": [self.fa], "kb": [self.fb], "np": [self.fn]}

    def settle(self, station="s1", a=10, b=5, **kw):
        wa, wb = self.w.witness("A"), self.w.witness("B")
        self.w.room((self.w.body(wa, station, a, b, **kw), wa), (self.w.body(wb, station, a, b), wb))
        return wa, wb


class TestPortedFromV02(Base):
    def test_E1_different_photos_same_tally_is_settled(self):
        self.settle()
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
        self.settle()
        r1 = wr3.run(self.w.envs, ["s1"], [self.w.policy(self.camps)], [])
        r2 = wr3.run(list(reversed(self.w.envs)), ["s1"], [self.w.policy({"x": [self.fa]})], [])
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
        self.settle()
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
        self.assertEqual(agg(self.w, self.w.policy(self.camps, require_copresence=False))["stations"]["s1/f"]["status"],
                         "settled")

    def test_scope_and_validity_window(self):
        a = self.w.witness("A", scope="32.09")
        b = self.w.witness("B", nb="2029-02-15T00:00:00+07:00")
        self.w.room((self.w.body(a, "32.01.1", 10, 5), a), (self.w.body(b, "32.01.1", 10, 5), b))
        r = agg(self.w, self.w.policy(self.camps), stations=("32.01.1",))
        self.assertEqual(r["rejected"]["out_of_scope"], 1)
        self.assertEqual(r["rejected"]["expired"], 1)

    def test_revocation_is_prospective(self):
        a, _ = self.settle()
        fp, ck = self.w.orgs["A"]
        self.w.envs.append(wr3.seal({"spec": wr3.SPEC, "type": "revocation", "org": fp, "contest": C,
                                     "issuer": wr3.pub_hex(ck), "issued_at": "2029-02-15T00:00:00+07:00",
                                     "revoked": [{"pubkey": wr3.pub_hex(a), "effective": "2029-02-14T20:00:00+07:00"}]}, ck))
        r = agg(self.w, self.w.policy(self.camps))
        self.assertEqual(r["stations"]["s1/f"]["status"], "settled")
        self.assertEqual(r["rejected"]["revoked"], 0)

    def test_revocation_by_another_org_has_no_effect(self):
        a, _ = self.settle()
        fp, ck = self.w.orgs["B"]  # org B tries to revoke org A's witness
        self.w.envs.append(wr3.seal({"spec": wr3.SPEC, "type": "revocation", "org": fp, "contest": C,
                                     "issuer": wr3.pub_hex(ck), "issued_at": "2029-02-14T00:00:00+07:00",
                                     "revoked": [{"pubkey": wr3.pub_hex(a), "effective": "2029-02-14T00:00:00+07:00"}]}, ck))
        r = agg(self.w, self.w.policy(self.camps))
        self.assertEqual(r["rejected"]["revoked"], 0)
        self.assertEqual(r["stations"]["s1/f"]["status"], "settled")

    def test_witness_telling_two_stories_counts_for_nothing(self):
        a, b = self.w.witness("A"), self.w.witness("B")
        self.w.room((self.w.body(a, "s1", 10, 5), a), (self.w.body(b, "s1", 10, 5), b))
        self.w.envs.append(wr3.seal(self.w.body(a, "s1", 11, 4), a))
        r = agg(self.w, self.w.policy(self.camps, require_copresence=False))
        self.assertEqual(r["rejected"]["self_conflict"], 1)
        self.assertEqual(r["stations"]["s1/f"]["status"], "insufficient")

    def test_official_diff(self):
        self.settle()
        self.w.official("s1", 12, 3)
        r = agg(self.w, self.w.policy(self.camps))
        self.assertEqual(r["stations"]["s1/f"]["official"],
                         {"status": "differs", "stage": "tps", "delta_official_minus_witnessed": {"a": 2, "b": -2}})

    def test_validation_rejects_float_and_non_ascii_keys(self):
        a = self.w.witness("A")
        body = self.w.body(a, "s1", 10, 5)
        body["tally"]["é"] = 1
        with self.assertRaises(ValueError):
            wr3.seal(body, a)
        self.assertTrue(wr3.validate({"body": body, "sig": "00"}))
        with self.assertRaises(ValueError):
            wr3.canonical_bytes({"type": "capture", "x": 1.5})

    def test_v02_envelopes_are_not_v03(self):
        a = self.w.witness("A")
        body = self.w.body(a, "s1", 10, 5)
        body["image"] = {"sha256": "0" * 64}
        self.assertTrue(wr3.validate({"body": body, "sig": "00"}))


class TestES256(Base):
    def test_es256_witness_verifies_and_counts(self):
        a, b = self.w.witness("A"), self.w.witness("B", alg="es256")
        self.w.room((self.w.body(a, "s1", 10, 5), a), (self.w.body(b, "s1", 10, 5), b))
        env = self.w.envs[-1]
        self.assertEqual(len(wr3.pub_hex(b)), 130)
        self.assertEqual(len(env["sig"]), 128)  # raw r||s, not DER
        self.assertTrue(wr3.verify_sig(env["body"], env["sig"], wr3.pub_hex(b), "es256"))
        self.assertFalse(wr3.verify_sig(env["body"], env["sig"], wr3.pub_hex(b), "ed25519"))
        r = agg(self.w, self.w.policy(self.camps))
        self.assertEqual(r["stations"]["s1/f"]["status"], "settled")
        algs = {s["alg"] for s in r["stations"]["s1/f"]["candidates"][0]["supporters"]}
        self.assertEqual(algs, {"ed25519", "es256"})

    def test_tampered_es256_capture_is_rejected(self):
        a, b = self.w.witness("A"), self.w.witness("B", alg="es256")
        self.w.room((self.w.body(a, "s1", 10, 5), a), (self.w.body(b, "s1", 10, 5), b))
        self.w.envs[-1]["body"]["tally"]["a"] = 11
        r = agg(self.w, self.w.policy(self.camps))
        self.assertEqual(r["rejected"]["bad_signature"], 1)
        self.assertEqual(r["stations"]["s1/f"]["status"], "insufficient")

    def test_pubkey_length_depends_on_alg(self):
        fp, ck = self.w.orgs["A"]
        ed, p = Ed25519PrivateKey.generate(), wr3.es256_key()

        def cert(pub, alg):
            return wr3.seal({"spec": wr3.SPEC, "type": "witness-cert", "org": fp, "contest": C, "pubkey": pub,
                             "alg": alg, "role": "saksi", "scope": "", "not_before": T0, "not_after": T1,
                             "issuer": wr3.pub_hex(ck)}, ck)

        self.assertEqual(wr3.validate(cert(wr3.pub_hex(ed), "ed25519")), [])
        self.assertEqual(wr3.validate(cert(wr3.pub_hex(p), "es256")), [])
        self.assertTrue(wr3.validate(cert(wr3.pub_hex(p), "ed25519")))
        self.assertTrue(wr3.validate(cert(wr3.pub_hex(ed), "es256")))
        self.assertTrue(wr3.validate(cert(wr3.pub_hex(ed), "rsa")))
        bad_role = cert(wr3.pub_hex(ed), "ed25519")
        bad_role["body"]["role"] = "boss"
        self.assertTrue(wr3.validate(bad_role))
        # captures accept either length structurally; the alg comes from the cert table
        for sk in (ed, p):
            self.assertEqual(wr3.validate(wr3.seal(self.w.body(sk, "s1", 1, 1), sk)), [])
        body = self.w.body(ed, "s1", 1, 1)
        body["witness"]["pubkey"] = "ab" * 40
        self.assertTrue(wr3.validate({"body": body, "sig": "00"}))

    def test_malleated_signature_adds_no_leaf_and_no_count(self):
        a, b = self.w.witness("A"), self.w.witness("B", alg="es256")
        self.w.room((self.w.body(a, "s1", 10, 5), a), (self.w.body(b, "s1", 10, 5), b))
        before = wr3.run(self.w.envs, ["s1"], [self.w.policy(self.camps, require_copresence=False)], [])
        orig = self.w.envs[-1]
        twin = {"body": json.loads(json.dumps(orig["body"])), "sig": flip_s(orig["sig"])}
        self.assertNotEqual(twin["sig"], orig["sig"])
        self.assertTrue(wr3.verify_sig(twin["body"], twin["sig"], wr3.pub_hex(b), "es256"))
        self.assertEqual(wr3.envelope_hash(twin), wr3.envelope_hash(orig))
        self.w.envs.append(twin)
        self.w.envs.append(json.loads(json.dumps(self.w.envs[-3])))  # a byte-identical Ed25519 replay too
        after = wr3.run(self.w.envs, ["s1"], [self.w.policy(self.camps, require_copresence=False)], [])
        self.assertEqual(after["header"]["input_root"], before["header"]["input_root"])
        self.assertEqual(after["header"]["unique_bodies"], before["header"]["unique_bodies"])
        self.assertEqual(after["header"]["envelopes"], before["header"]["envelopes"] + 2)
        pa, pb = before["by_policy"][0], after["by_policy"][0]
        self.assertEqual(pb["totals"], pa["totals"])
        self.assertEqual(pb["rejected"], pa["rejected"])
        self.assertEqual(len(pb["stations"]["s1/f"]["candidates"][0]["supporters"]), 2)

    def test_duplicate_body_with_one_bad_sig_still_counts_once(self):
        a, b = self.w.witness("A"), self.w.witness("B", alg="es256")
        self.w.room((self.w.body(a, "s1", 10, 5), a), (self.w.body(b, "s1", 10, 5), b))
        junk = {"body": self.w.envs[-1]["body"], "sig": "00" * 64}
        self.w.envs.insert(0, junk)
        r = agg(self.w, self.w.policy(self.camps))
        self.assertEqual(r["stations"]["s1/f"]["status"], "settled")
        self.assertEqual(r["totals"]["settled"], {"a": 10, "b": 5})


class TestAnchors(Base):
    def setUp(self):
        super().setUp()
        self.fk = self.w.org("KPU")
        self.camps["official"] = [self.fk]

    def test_anchored_to_official_is_reported_never_required(self):
        k = self.w.witness("KPU", role="kpps", alg="es256")
        kb = self.w.body(k, "s1", 10, 5)
        a, b, n = self.w.witness("A"), self.w.witness("B"), self.w.witness("N")
        ab = self.w.body(a, "s1", 10, 5)
        bb = self.w.body(b, "s1", 10, 5)
        nb = self.w.body(n, "s1", 10, 5, anchors=["ab" * 32])
        pairs = [(kb, k), (ab, a), (bb, b), (nb, n)]
        for x, _ in pairs:
            x["copresence"] = [{"pubkey": o["witness"]["pubkey"], "nonce": o["nonce"]} for o, _ in pairs if o is not x]
        h = wr3.body_hash(kb)  # after copresence is filled: the KPPS body is final, the others are not yet signed
        ab["anchors"] = [h]
        bb["anchors"] = [h, "cd" * 32]
        for x, sk in pairs:
            self.w.envs.append(wr3.seal(x, sk))
        r = agg(self.w, self.w.policy(self.camps))
        sup = {s["org"]: s for s in r["stations"]["s1/f"]["candidates"][0]["supporters"]}
        self.assertTrue(sup[self.fa]["anchored_to_official"])
        self.assertTrue(sup[self.fb]["anchored_to_official"])
        self.assertFalse(sup[self.fn]["anchored_to_official"])
        self.assertFalse(sup[self.fk]["anchored_to_official"])
        self.assertEqual(sup[self.fk]["role"], "kpps")

    def test_anchor_to_non_kpps_capture_does_not_count(self):
        a, b = self.w.witness("A"), self.w.witness("B")
        ab = self.w.body(a, "s1", 10, 5)
        self.w.room((ab, a))
        bb = self.w.body(b, "s1", 10, 5, anchors=[wr3.body_hash(ab)])
        self.w.room((bb, b))
        r = agg(self.w, self.w.policy(self.camps, require_copresence=False))
        self.assertFalse(any(s["anchored_to_official"] for s in r["stations"]["s1/f"]["candidates"][0]["supporters"]))

    def test_anchor_alone_does_not_qualify(self):
        k = self.w.witness("KPU", role="kpps", alg="es256")
        kb = self.w.body(k, "s1", 10, 5)
        self.w.room((kb, k))
        a = self.w.witness("A")
        self.w.room((self.w.body(a, "s1", 10, 5, anchors=[wr3.body_hash(kb)]), a))
        r = agg(self.w, self.w.policy(self.camps))
        self.assertEqual(r["stations"]["s1/f"]["status"], "insufficient")  # no co-presence edge

    def test_official_camp_counts_like_any_camp_and_is_droppable(self):
        k, a = self.w.witness("KPU", role="kpps", alg="es256"), self.w.witness("A")
        self.w.room((self.w.body(k, "s1", 10, 5), k), (self.w.body(a, "s1", 10, 5), a))
        with_state = agg(self.w, self.w.policy(self.camps))
        camps = {c: v for c, v in self.camps.items() if c != "official"}
        without = agg(self.w, self.w.policy(camps))
        self.assertEqual(with_state["stations"]["s1/f"]["status"], "settled")
        self.assertEqual(without["stations"]["s1/f"]["status"], "insufficient")


class TestRecapDrift(Base):
    def test_first_divergent_stage(self):
        self.settle()
        self.w.official("s1", 10, 5, "capture")
        self.w.official("s1", 10, 5, "tps")
        self.w.official("s1", 14, 1, "kabko")
        self.w.official("s1", 12, 3, "ppk")
        r = agg(self.w, self.w.policy(self.camps))["stations"]["s1/f"]
        self.assertEqual([e["stage"] for e in r["recap_drift"]], ["capture", "tps", "ppk", "kabko"])
        self.assertEqual([e["status"] for e in r["recap_drift"]], ["equal", "equal", "differs", "differs"])
        self.assertEqual(r["recap_drift"][2]["delta_official_minus_witnessed"], {"a": 2, "b": -2})
        self.assertEqual(r["first_divergent_stage"], "ppk")
        self.assertEqual(r["official"]["stage"], "kabko")

    def test_no_drift(self):
        self.settle()
        self.w.official("s1", 10, 5, "tps")
        self.w.official("s1", 10, 5, "ppk")
        r = agg(self.w, self.w.policy(self.camps))
        self.assertIsNone(r["stations"]["s1/f"]["first_divergent_stage"])
        self.assertEqual(r["diff_vs_official"]["equal"], 1)

    def test_two_tallies_at_one_stage_is_official_conflict(self):
        self.settle()
        self.w.official("s1", 10, 5, "capture")
        self.w.official("s1", 10, 5, "tps")
        self.w.official("s1", 11, 5, "tps")
        r = agg(self.w, self.w.policy(self.camps))
        st = r["stations"]["s1/f"]
        self.assertEqual(st["recap_drift"][1]["status"], "official_conflict")
        self.assertEqual(len(st["recap_drift"][1]["tallies"]), 2)
        self.assertEqual(st["first_divergent_stage"], "tps")
        self.assertEqual(r["diff_vs_official"]["official_conflict"], 1)

    def test_not_settled_gives_null(self):
        a = self.w.witness("A")
        self.w.room((self.w.body(a, "s1", 10, 5), a))
        self.w.official("s1", 12, 3, "ppk")
        st = agg(self.w, self.w.policy(self.camps))["stations"]["s1/f"]
        self.assertEqual(st["status"], "insufficient")
        self.assertIsNone(st["first_divergent_stage"])
        self.assertEqual(st["recap_drift"][0]["status"], "official_only")

    def test_bad_stage_is_malformed(self):
        self.w.official("s1", 1, 1, "kelurahan")
        self.assertTrue(wr3.validate(self.w.envs[-1]))


class TestPolicyLinter(Base):
    def test_official_never_required(self):
        p = self.w.policy({**self.camps, "official": ["00" * 16]}, require_camps=["official"])
        with self.assertRaises(ValueError):
            wr3.lint_policy(p)
        with self.assertRaises(ValueError):
            wr3.aggregate(self.w.envs, ["s1"], p)
        wr3.lint_policy(self.w.policy({**self.camps, "official": ["00" * 16]}, require_camps=["np"]))

    def test_cli_reports_linter_error(self):
        p = self.w.policy({**self.camps, "official": []}, require_camps=["official"])
        with tempfile.TemporaryDirectory() as tmp:
            t = Path(tmp)
            (t / "env").mkdir()
            (t / "s.json").write_text(json.dumps(["s1"]))
            (t / "p.json").write_text(json.dumps(p))
            err = io.StringIO()
            with contextlib.redirect_stderr(err), contextlib.redirect_stdout(io.StringIO()):
                code = wr3.main(["verify", str(t / "env"), "--stations", str(t / "s.json"), "--policy", str(t / "p.json")])
            self.assertEqual(code, 2)
            self.assertIn("never required", err.getvalue())

    def test_warns_when_camp_mixes_kpps_and_others(self):
        fk = self.w.org("KPU")
        self.w.witness("KPU", role="kpps", alg="es256")
        self.w.witness("A")
        mixed = self.w.policy({"ka": [self.fa, fk], "kb": [self.fb]})
        clean = self.w.policy({"ka": [self.fa], "official": [fk]})
        r = wr3.run(self.w.envs, ["s1"], [mixed, clean], [])
        self.assertEqual(len(r["header"]["policy_warnings"]), 1)
        self.assertIn("'ka'", r["header"]["policy_warnings"][0])


class TestFlags(Base):
    def test_station_list_accepts_objects(self):
        ids, dpt = wr3.normalize_stations(["s1", {"station": "s2", "dpt": 300}, {"station": "s3"}])
        self.assertEqual(ids, ["s1", "s2", "s3"])
        self.assertEqual(dpt, {"s2": 300})
        for bad in ([{"dpt": 3}], [{"station": "s1", "dpt": -1}], [{"station": "s1", "dpt": True}], [7]):
            with self.assertRaises(ValueError):
                wr3.normalize_stations(bad)

    def test_implausible_is_a_flag_not_a_rejection(self):
        self.settle(a=200, b=20)
        r = agg(self.w, self.w.policy(self.camps), stations=[{"station": "s1", "dpt": 210}])
        st = r["stations"]["s1/f"]
        self.assertEqual(st["status"], "settled")
        self.assertEqual(st["flags"], ["implausible"])
        self.assertEqual(len(st["flag_detail"]["implausible"]), 2)
        self.assertEqual(r["coverage"]["flags_by_org"][self.fa]["implausible"], 1)
        ok = agg(self.w, self.w.policy(self.camps), stations=[{"station": "s1", "dpt": 220}])
        self.assertEqual(ok["stations"]["s1/f"]["flags"], [])

    def test_same_image_orig_or_deriv(self):
        shared = os.urandom(32).hex()
        a, b, n = self.w.witness("A"), self.w.witness("B"), self.w.witness("N")
        self.w.room((self.w.body(a, "s1", 10, 5, orig=shared), a), (self.w.body(b, "s1", 10, 5, orig=shared), b))
        self.w.room((self.w.body(n, "s2", 1, 1, deriv=shared), n))  # orig of one == deriv of another: not the same field
        r = agg(self.w, self.w.policy(self.camps), stations=("s1", "s2"))
        self.assertEqual(r["stations"]["s1/f"]["flags"], ["same_image"])
        self.assertEqual(r["stations"]["s2/f"]["flags"], [])

        w2 = World()
        w2.org("A")
        w2.org("B")
        d = os.urandom(32).hex()
        a, b = w2.witness("A"), w2.witness("B")
        w2.room((w2.body(a, "s1", 1, 1, deriv=d), a), (w2.body(b, "s1", 1, 1, deriv=d), b))
        r2 = wr3.aggregate(w2.envs, ["s1"], w2.policy({"x": [w2.orgs["A"][0]], "y": [w2.orgs["B"][0]]}))
        self.assertEqual(r2["stations"]["s1/f"]["flags"], ["same_image"])

    def test_empty_deriv_is_not_same_image(self):
        a, b = self.w.witness("A"), self.w.witness("B")
        self.w.room((self.w.body(a, "s1", 10, 5, deriv=""), a), (self.w.body(b, "s1", 10, 5, deriv=""), b))
        self.assertEqual(agg(self.w, self.w.policy(self.camps))["stations"]["s1/f"]["flags"], [])

    def test_nonce_reuse_across_stations(self):
        nonce = os.urandom(16).hex()
        a, b = self.w.witness("A"), self.w.witness("B")
        self.w.room((self.w.body(a, "s1", 10, 5, nonce=nonce), a))
        self.w.room((self.w.body(b, "s2", 10, 5, nonce=nonce), b))
        r = agg(self.w, self.w.policy(self.camps, require_copresence=False), stations=("s1", "s2"))
        self.assertEqual(r["stations"]["s1/f"]["flags"], ["nonce_reuse"])
        self.assertEqual(r["stations"]["s2/f"]["flags"], ["nonce_reuse"])
        self.assertEqual(r["coverage"]["flags_by_org"][self.fa]["nonce_reuse"], 1)
        self.assertEqual(r["coverage"]["flags_by_org"][self.fb]["nonce_reuse"], 1)

    def test_late_enrollment(self):
        a = self.w.witness("A")
        b = self.w.witness("B", nb="2029-02-14T12:00:00+07:00")
        self.w.room((self.w.body(a, "s1", 10, 5), a), (self.w.body(b, "s1", 10, 5), b))
        r = agg(self.w, self.w.policy(self.camps, freeze_at="2029-02-14T06:00:00+07:00"))
        st = r["stations"]["s1/f"]
        self.assertEqual(st["status"], "settled")
        self.assertEqual(st["flags"], ["late_enrollment"])
        self.assertEqual(st["flag_detail"]["late_enrollment"], [wr3.pub_hex(b)])
        self.assertEqual(agg(self.w, self.w.policy(self.camps))["stations"]["s1/f"]["flags"], [])

    def test_flags_include_orgs_outside_the_policy(self):
        shared = os.urandom(32).hex()
        a, b = self.w.witness("A"), self.w.witness("B")
        self.w.room((self.w.body(a, "s1", 10, 5, orig=shared), a), (self.w.body(b, "s1", 10, 5, orig=shared), b))
        r = agg(self.w, self.w.policy({"ka": [self.fa]}))
        self.assertEqual(r["stations"]["s1/f"]["flags"], ["same_image"])
        self.assertIn(self.fb, r["coverage"]["flags_by_org"])


def run_cli(*argv):
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        code = wr3.main([str(a) for a in argv])
    return code, out.getvalue()


class TestBundleAndDisputes(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.d = Path(cls.tmp.name)
        with contextlib.redirect_stdout(io.StringIO()):
            wr3.build_demo(cls.d)
        cls.envs, bad = wr3.load_dir(cls.d / "envelopes")
        assert bad == [], bad
        cls.stations = json.loads((cls.d / "stations.json").read_text())
        cls.policies = [json.loads((cls.d / f"policy-{n}.json").read_text()) for n in ("two-camps", "any-2-orgs")]

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def test_demo_end_to_end(self):
        two, naive = (wr3.aggregate(self.envs, self.stations, p) for p in self.policies)
        self.assertEqual(two["status_counts"], {"settled": 2, "disputed": 1, "insufficient": 2, "missing": 1})
        st = two["stations"]["32.01.001/c-hasil"]
        self.assertEqual(st["first_divergent_stage"], "ppk")
        self.assertIn("official", {s["camp"] for s in st["candidates"][0]["supporters"]})
        self.assertIn("es256", {s["alg"] for s in st["candidates"][0]["supporters"]})
        self.assertEqual(sum(s["anchored_to_official"] for s in st["candidates"][0]["supporters"]), 2)
        self.assertEqual(two["stations"]["32.02.004/c-hasil"]["flags"], ["implausible"])
        self.assertEqual(two["stations"]["32.02.003/c-hasil"]["flags"], ["same_image"])
        self.assertEqual(two["policy_warnings"], [])
        self.assertEqual(naive["stations"]["32.02.004/c-hasil"]["status"], "settled")

    def bundle(self, station):
        return wr3.make_bundle(self.envs, self.stations, self.policies, station)

    def test_bundle_round_trip_every_station(self):
        for st in [wr3._station_id(e) for e in self.stations]:
            b = self.bundle(st)
            ok, problems = wr3.verify_bundle(json.loads(json.dumps(b)))
            self.assertTrue(ok, (st, problems))

    def test_bundle_is_deterministic(self):
        b1 = self.bundle("32.01.001")
        b2 = wr3.make_bundle(list(reversed(self.envs)), self.stations, self.policies, "32.01.001")
        self.assertEqual(wr3.canonical_bytes(b1), wr3.canonical_bytes(b2))
        types = {e["body"]["type"] for e in b1["envelopes"]}
        self.assertEqual(types, {"org", "witness-cert", "capture", "official"})
        self.assertEqual(len([e for e in b1["envelopes"] if e["body"]["type"] == "org"]), 3)

    def test_tampered_bundle_fails(self):
        b = self.bundle("32.01.001")
        cap = next(e for e in b["envelopes"] if e["body"]["type"] == "capture")
        cap["body"]["tally"]["a"] += 1
        ok, problems = wr3.verify_bundle(b)
        self.assertFalse(ok)
        self.assertTrue(any("bundle_sha256" in p for p in problems))
        b["bundle_sha256"] = wr3.bundle_digest(b)  # a careful forger rehashes: the signature still fails
        ok, problems = wr3.verify_bundle(b)
        self.assertFalse(ok)
        self.assertTrue(any("recomputed" in p for p in problems))

    def test_tampered_rendering_fails_even_if_rehashed(self):
        b = self.bundle("32.01.001")
        b["rendering"] = [line.replace("differs", "equal") for line in b["rendering"]]
        b["bundle_sha256"] = wr3.bundle_digest(b)
        ok, problems = wr3.verify_bundle(b)
        self.assertFalse(ok)
        self.assertTrue(any("rendering" in p for p in problems))

    def test_bundle_carries_cross_station_evidence(self):
        w = World()
        fa, fb = w.org("A"), w.org("B")
        nonce = os.urandom(16).hex()
        a, b, a2 = w.witness("A"), w.witness("B"), w.witness("A")
        w.room((w.body(a, "s1", 10, 5, nonce=nonce), a), (w.body(b, "s1", 10, 5), b))
        w.room((w.body(a2, "s2", 3, 3, nonce=nonce), a2))
        p = w.policy({"x": [fa], "y": [fb]})
        bnd = wr3.make_bundle(w.envs, ["s1", "s2"], [p], "s1")
        self.assertEqual(bnd["results"][0]["rows"]["s1/f"]["flags"], ["nonce_reuse"])
        self.assertTrue(wr3.verify_bundle(bnd)[0])

    def test_bundle_cli_and_verify_bundle_cli(self):
        out = self.d / "b.json"
        code, _ = run_cli("bundle", self.d / "envelopes", "--stations", self.d / "stations.json",
                          "--policy", self.d / "policy-two-camps.json", "--station", "32.01.001", "--out", out)
        self.assertEqual(code, 0)
        code, text = run_cli("verify-bundle", out)
        self.assertEqual(code, 0)
        self.assertTrue(text.startswith("OK"))
        b = json.loads(out.read_text())
        b["results"][0]["rows"]["32.01.001/c-hasil"]["status"] = "disputed"
        out.write_text(json.dumps(b))
        code, text = run_cli("verify-bundle", out)
        self.assertEqual(code, 1)
        self.assertTrue(text.startswith("FAILED"))

    def test_disputes_sorted_by_materiality_with_running_total(self):
        w = World()
        fa, fb = w.org("A"), w.org("B")
        for st, (oa, ob) in {"s1": (11, 4), "s2": (20, 0), "s3": (10, 5), "s4": (13, 5)}.items():
            a, b = w.witness("A"), w.witness("B")
            w.room((w.body(a, st, 10, 5), a), (w.body(b, st, 10, 5), b))
            w.official(st, oa, ob, "ppk")
            w.official(st, 10, 5, "tps")
        w.official("s5", 1, 1, "ppk")
        p = w.policy({"x": [fa], "y": [fb]})
        d = wr3.disputes(w.envs, ["s1", "s2", "s3", "s4", "s5"], p, "ppk")
        self.assertEqual([x["station"] for x in d["stations"]], ["s2", "s4", "s1"])
        self.assertEqual([x["abs_delta"] for x in d["stations"]], [15, 3, 2])
        self.assertEqual([x["cumulative_abs_delta"] for x in d["stations"]], [15, 18, 20])
        self.assertEqual(d["stations"][-1]["cumulative_delta"], {"a": 14, "b": -6})
        self.assertEqual(wr3.disputes(w.envs, ["s1"], p, "tps")["count"], 0)
        with self.assertRaises(ValueError):
            wr3.disputes(w.envs, ["s1"], p, "rt")

    def test_vocabulary_rule_on_every_output(self):
        outputs = []
        with tempfile.TemporaryDirectory() as tmp:
            t = Path(tmp)
            code, text = run_cli("demo", t)
            outputs.append(text)
            env, st = t / "envelopes", t / "stations.json"
            pols = ["--policy", t / "policy-two-camps.json", "--policy", t / "policy-any-2-orgs.json"]
            code, text = run_cli("verify", env, "--stations", st, *pols, "--camp-solo")
            self.assertEqual(code, 0)
            outputs.append(text)
            for station in [wr3._station_id(e) for e in json.loads(st.read_text())]:
                out = t / f"bundle-{station}.json"
                code, text = run_cli("bundle", env, "--stations", st, *pols, "--station", station, "--out", out)
                self.assertEqual(code, 0)
                outputs += [text, out.read_text()]
                code, text = run_cli("verify-bundle", out)
                self.assertEqual(code, 0)
                outputs.append(text)
            for stage in wr3.STAGES:
                code, text = run_cli("disputes", env, "--stations", st, "--policy", t / "policy-two-camps.json",
                                     "--official-stage", stage)
                self.assertEqual(code, 0)
                outputs.append(text)
        for text in outputs:
            low = text.lower()
            for word in FORBIDDEN:
                self.assertNotIn(word, low)

    def test_vocabulary_rule_on_string_table(self):
        src = Path(wr3.__file__).read_text(encoding="utf-8")
        for node in ast.walk(ast.parse(src)):
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                for word in FORBIDDEN:
                    self.assertNotIn(word, node.value.lower())


if __name__ == "__main__":
    unittest.main()
