import json
import tempfile
import unittest
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from verifier import wr


def make_record(station="001", a=10, b=5, tier="witnessed"):
    return {
        "spec": wr.SPEC, "tier": tier, "contest": "t", "station": station,
        "tally": {"A": a, "B": b}, "image_sha256": "a" * 64,
        "captured_at": "2029-01-01T00:00:00+07:00",
    }


class TestCanonical(unittest.TestCase):
    def test_key_order_does_not_change_bytes(self):
        r1 = make_record()
        r2 = dict(reversed(list(r1.items())))
        self.assertEqual(wr.canonical_bytes(r1), wr.canonical_bytes(r2))

    def test_validation_rejects_negative_tally(self):
        r = make_record(a=-1)
        self.assertTrue(wr.validate_record(r))


class TestAggregate(unittest.TestCase):
    def setUp(self):
        self.k1, self.k2, self.k3 = (Ed25519PrivateKey.generate() for _ in range(3))
        self.registry = {
            wr.pubkey_hex(self.k1): {"role": "w", "org": "x"},
            wr.pubkey_hex(self.k2): {"role": "w", "org": "y"},
            wr.pubkey_hex(self.k3): {"role": "w", "org": "x"},
        }

    def env(self, rec, *keys):
        return {"record": rec, "witnesses": [wr.sign(rec, k) for k in keys]}

    def test_two_orgs_accepted(self):
        rep = wr.aggregate([self.env(make_record(), self.k1, self.k2)], self.registry)
        self.assertEqual(rep.totals, {"A": 10, "B": 5})

    def test_same_org_twice_is_insufficient(self):
        rep = wr.aggregate([self.env(make_record(), self.k1, self.k3)], self.registry)
        self.assertEqual(rep.totals, {})
        self.assertEqual(rep.insufficient, ["t/001"])

    def test_tampered_tally_breaks_signatures(self):
        e = self.env(make_record(), self.k1, self.k2)
        e["record"]["tally"]["A"] = 999
        rep = wr.aggregate([e], self.registry)
        self.assertEqual(rep.totals, {})
        self.assertEqual(rep.rejected_signatures, 2)

    def test_conflict_is_excluded(self):
        e1 = self.env(make_record(a=10), self.k1, self.k2)
        e2 = self.env(make_record(a=11), self.k1, self.k2)
        rep = wr.aggregate([e1, e2], self.registry)
        self.assertEqual(rep.conflicts, ["t/001"])
        self.assertEqual(rep.totals, {})

    def test_historical_not_mixed(self):
        rep = wr.aggregate([{"record": make_record(tier="historical"), "witnesses": []}], self.registry)
        self.assertEqual(rep.totals, {})
        self.assertEqual(rep.historical_totals, {"A": 10, "B": 5})

    def test_merkle_root_is_order_independent_of_input(self):
        e1 = self.env(make_record("001"), self.k1, self.k2)
        e2 = self.env(make_record("002"), self.k1, self.k2)
        r1 = wr.aggregate([e1, e2], self.registry).merkle_root
        r2 = wr.aggregate([e2, e1], self.registry).merkle_root
        self.assertEqual(r1, r2)


class TestDemoEndToEnd(unittest.TestCase):
    def test_demo(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            wr.build_demo(out)
            errors = []
            envs = wr.load_dir(out / "records", errors)
            registry = json.loads((out / "registry.json").read_text())
            rep = wr.aggregate(envs, registry).to_dict()
            self.assertEqual(errors, [])
            self.assertEqual(rep["totals"], {"A": 200, "B": 208, "invalid": 2})
            self.assertEqual(rep["conflicts"], ["demo-2029/003"])
            self.assertEqual(rep["insufficient_witnesses"], ["demo-2029/004"])
            self.assertEqual(rep["historical_totals_not_mixed"], {"A": 70, "B": 70, "invalid": 1})


if __name__ == "__main__":
    unittest.main()
