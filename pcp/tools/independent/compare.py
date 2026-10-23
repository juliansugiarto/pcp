#!/usr/bin/env python3
"""Compare the SPEC-only buyer checks (pcp0.py) with the Rust buyer's verdicts.

Usage: python3 compare.py CORPUS.jsonl [--show N] [--dump FILE]

Each corpus line: {set, request, offer, bundle, binding, now, buyer, verdict,
changed}, and optionally r0_now (when R0 ran before ``now``).  ``set`` names
the generator (mutation, mandate, boundary, request, transport); ``buyer`` may
carry allow_unregistered_job_classes and agent_key.  ``verdict`` is the Rust
buyer's {stage, code}, stage one of request, offer, bundle, invoice, accepted;
``changed`` the case label or mutated JSON path (a list; empty when none).

Categories reported
-------------------
agree                 same stage and same code (both accept, or both refuse with
                      the same code).  Codes are compared verbatim: every code
                      pcp0.py returns is a wire code named in SPEC 5.4a / 2.1,
                      so no alias table is needed.
rust_refuses_we_accept
we_refuse_rust_accepts
same_stage_diff_code  both refuse at the same stage with different codes
diff_stage            both refuse, at different stages
ignored_proof_invalid Rust refused with ``proof_invalid`` (the opaque proof,
                      which this implementation does not check)
"""

import argparse
import collections
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import pcp0  # noqa: E402

def policy_from(buyer: dict) -> pcp0.BuyerPolicy:
    return pcp0.BuyerPolicy(
        max_price_msat=buyer["max_price_msat"],
        accepted_backend_id=buyer["accepted_backend_id"],
        allow_insecure_dev_backend=buyer["allow_insecure_dev_backend"],
        htlc_secs=buyer["htlc_secs"],
        min_invoice_remaining_secs=buyer["min_invoice_remaining_secs"],
        max_deal_msat=buyer["max_deal_msat"],
        rail=buyer["rail"],
        payout_node=buyer["payout_node"],
        allow_unregistered_job_classes=buyer.get("allow_unregistered_job_classes", False),
        agent_key=bytes.fromhex(buyer["agent_key"]) if buyer.get("agent_key") else None,
    )


def run_case(case: dict):
    buyer = pcp0.Buyer(case["request"], policy_from(case["buyer"]))
    return buyer.evaluate(case["offer"], case["bundle"], case["binding"], case["now"],
                          case.get("r0_now"))


def classify(rust_stage, rust_code, our_stage, our_code):
    if rust_stage != "accepted" and rust_code == "proof_invalid":
        return "ignored_proof_invalid"
    if rust_stage == "accepted" and our_stage == "accepted":
        return "agree"
    if rust_stage == "accepted":
        return "we_refuse_rust_accepts"
    if our_stage == "accepted":
        return "rust_refuses_we_accept"
    if rust_stage != our_stage:
        return "diff_stage"
    if rust_code == our_code:
        return "agree"
    return "same_stage_diff_code"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("corpus")
    ap.add_argument("--show", type=int, default=3, help="examples per divergence class")
    ap.add_argument("--dump", help="write every divergence as JSON lines here")
    args = ap.parse_args()

    counts = collections.Counter()
    by_set = collections.defaultdict(collections.Counter)
    by_class = collections.defaultdict(list)
    n = 0
    with open(args.corpus) as f:
        for lineno, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            case = json.loads(line)
            n += 1
            rust = case["verdict"]
            try:
                our_stage, our_code, detail = run_case(case)
            except Exception as e:  # a crash is a finding too
                our_stage, our_code, detail = "crash", type(e).__name__, str(e)
            cls = classify(rust["stage"], rust["code"], our_stage, our_code)
            counts[cls] += 1
            by_set[case.get("set", "(none)")][cls] += 1
            changed = "/".join(map(str, case.get("changed") or [])) or "(none)"
            key = (cls, changed, rust["stage"], rust["code"], our_stage, our_code)
            by_class[key].append((lineno, detail))

    print("cases: %d" % n)
    print()
    print("%-24s %6s" % ("category", "count"))
    for cls in ("agree", "rust_refuses_we_accept", "we_refuse_rust_accepts",
                "same_stage_diff_code", "diff_stage", "ignored_proof_invalid"):
        print("%-24s %6d" % (cls, counts[cls]))
    other = {k: v for k, v in counts.items() if k not in (
        "agree", "rust_refuses_we_accept", "we_refuse_rust_accepts",
        "same_stage_diff_code", "diff_stage", "ignored_proof_invalid")}
    for k, v in other.items():
        print("%-24s %6d" % (k, v))

    # Per set, so a new set cannot hide inside the old totals.
    print()
    for name in sorted(by_set):
        c = by_set[name]
        div = sum(v for k, v in c.items() if k not in ("agree", "ignored_proof_invalid"))
        print("set %-10s cases %5d  agree %5d  ignored %3d  divergent %d"
              % (name, sum(c.values()), c["agree"], c["ignored_proof_invalid"], div))

    print()
    print("Agreed refusal codes (count per code, as named by the SPEC):")
    agreed_codes = collections.Counter()
    for key, items in by_class.items():
        if key[0] == "agree" and key[2] != "accepted":
            agreed_codes[(key[2], key[3])] += len(items)
    for (stage, code), cnt in sorted(agreed_codes.items()):
        print("  %4d  %s/%s" % (cnt, stage, code))

    print()
    print("Divergences (one line per class; line numbers are 1-based in the corpus):")
    any_div = False
    for key in sorted(by_class):
        cls, changed, rs, rc, os_, oc = key
        if cls in ("agree", "ignored_proof_invalid"):
            continue
        any_div = True
        items = by_class[key]
        print("  [%s] x%d changed=%s" % (cls, len(items), changed))
        print("      rust: %s/%s   ours: %s/%s" % (rs, rc, os_, oc))
        for lineno, detail in items[: args.show]:
            print("      line %d: %s" % (lineno, detail))
    if not any_div:
        print("  none")

    if args.dump:
        with open(args.dump, "w") as out:
            for key in sorted(by_class):
                cls, changed, rs, rc, os_, oc = key
                if cls in ("agree", "ignored_proof_invalid"):
                    continue
                for lineno, detail in by_class[key]:
                    out.write(json.dumps({"class": cls, "line": lineno, "changed": changed,
                                          "rust": [rs, rc], "ours": [os_, oc], "detail": detail}) + "\n")
    # For CI: any divergence, or an empty corpus, fails.
    return 1 if any_div or n == 0 else 0


if __name__ == "__main__":
    sys.exit(main())
