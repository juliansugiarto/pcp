# Witnessed Record, spec v0.2 (draft)

Status: draft for discussion. Not audited. Do not use in a real election. Reference implementation: `verifier/wr2.py`. Threat model and rationale: in the project's private research notes (not published).

**One-line principle:** whoever counts must not be the only one who can recount.

**The scarce resource** (the role proof-of-work plays in Bitcoin) is *adversarial co-presence*: two people who want each other to lose, in the same room, at the same minute. Anything that does not meet that bar is evidence to display, never a reason to delete.

## What changed from v0, and why

| v0 | v0.2 | Reason |
|---|---|---|
| One shared record, all witnesses sign the same photo hash | One `capture` per witness, each with its own photo; consensus is on the **tally only** | Honest witnesses take different photos, so v0 marked almost every honest station as a conflict |
| A conflict deletes the station | Conflicts become **bounds** (`min`, `max`, `flip`); unqualified rival tallies are listed as `contested` | Deletion lets one colluding pair erase a province |
| A single registry file decides who is independent | Independence is a **verifier policy**: orgs grouped into **camps**, several policies reported side by side | The same choice Certificate Transparency made: the relying party decides |
| Merkle root over accepted records only | **Policy-free** root over every well-formed envelope | Honest mirrors with different trust must still agree on the input |
| One long-lived key per witness | Org root → per-contest org key → per-witness certificate with scope, validity window, prospective revocation | Limits a stolen key to one camp, one area, one day |
| Time and place unproven | In-room **co-presence** by QR nonce exchange | A capture made elsewhere, earlier, or by AI cannot contain a nonce it never saw |
| Official numbers mixed in or ignored | `official` records carried alongside, diffed per station | The diff is the product |
| No station universe | Station list pinned by policy; `missing` computed | Silence is evidence |

## 1. Encoding and signatures

- UTF-8, lowercase hex, RFC 3339 times with offset, integers in `[0, 2^31)`, **no floats**, ASCII object keys. Tally option names match `^[a-z0-9_.-]{1,32}$`.
- Canonical bytes: RFC 8785 (JCS). For the restricted domain above, sorted compact JSON is identical to JCS.
- Envelope: `{"body": {...}, "sig": "<hex>"}`. The signer's public key is inside `body`.
- Signature input is domain separated: `"wr/0.2/" + type + "\n" + canonical_bytes(body)`.
- Algorithm: Ed25519. **Open item:** Android phones guarantee hardware-backed ECDSA P-256, not Ed25519, so v0.3 should accept P-256 witness keys.

## 2. Envelope types

| Type | Signed by | Purpose |
|---|---|---|
| `org` | org root key | Name, root public key, per-contest keys |
| `witness-cert` | org contest key | Binds a witness phone key to an org, with `scope` (admin prefix) and `not_before` / `not_after` |
| `revocation` | org contest key | Revokes witness keys from an `effective` time (prospective only) |
| `capture` | witness key | What one witness saw at one station for one form |
| `incident` | witness key | `copy_refused`, `no_access`, `not_visible`, `retraction` |
| `official` | unsigned or the fetcher | The official number for a station with its source URL and hash |

Capture body:

```json
{
  "spec": "witnessed-record/0.2", "type": "capture",
  "contest": "pemilu-2029-ppwp", "station": "32.03.01.2001.001", "form": "c-hasil",
  "tally": {"01": 120, "02": 98, "invalid": 3},
  "image": {"sha256": "<hex>"},
  "captured_at": "2029-02-14T13:05:00+07:00",
  "nonce": "<16 bytes hex>",
  "copresence": [{"pubkey": "<hex>", "nonce": "<hex>"}],
  "witness": {"pubkey": "<hex>"}
}
```

**Open item from the field research:** the capturing phone should sign both the original photo hash and the hash of a compressed copy made at capture time. Then no zero-knowledge edit proof is needed, unless someone *other* than the signer edits the image.

## 3. Policy

```json
{
  "name": "two-camps", "contest": "pemilu-2029-ppwp",
  "camps": {"koalisi-a": ["<fp>"], "koalisi-b": ["<fp>"], "nonpartisan": ["<fp>"]},
  "rule": {"min_witnesses": 2, "min_camps": 2, "require_camps": [], "require_copresence": true}
}
```

A policy is an argument, not an authority. Every report carries the policy hash. Suggested set: `any-2-orgs` (v0 behaviour, for comparison), `two-camps`, `nonpartisan-plus-one`, and `camp-solo:<X>` (what one camp alone claims; a diagnostic, not a result).

## 4. Aggregation, per policy

1. **Key table** from org manifests, witness certs, and revocations. Only orgs named in the policy count.
2. **Validate captures:** signature, key in table, station within scope, time within window, not revoked from before the capture. A witness who signs two different tallies for the same station counts for nothing there (`self_conflict`).
3. **Co-presence graph** per station: an edge between W1 and W2 if W1 lists W2's nonce *and* W2's own capture declares that nonce.
4. **Candidates:** group captures by tally. A candidate is *qualified* if its supporters meet the rule, and if co-presence is required, at least two supporters from different camps are linked by an edge.
5. **Status:** `settled` (one qualified), `disputed` (two or more qualified), `insufficient` (captures but none qualified), `missing` (none).
6. **Totals:** `settled`; `min` and `max` adding the range over qualified candidates at disputed stations; `flip` if the runner-up's max reaches the leader's min.
7. **Coverage** by province and by camp, plus the missing list.
8. **Diff vs official:** `equal`, `differs` (with the delta), `official_only`, `witnessed_only`, `official_conflict`.
9. **Header:** verifier version, policy-free `input_root`, station-list hash.

## 5. The attack that could kill the mission

**Independence that is not.** Parties cannot afford witnesses at every one of ~823,000 stations, post-election coalitions turn "two parties" into one interest, and the officials in the room are not adversaries of the dominant camp. Under an honest two-camp policy, most stations could come out `insufficient`.

It is survivable only if a non-party witness class exists at most stations. Candidates: Bawaslu's polling-station supervisor (one per station by law), accredited observers, and a `posted` tier of citizens photographing the copy that must be publicly posted (UU 7/2017 pasal 391). If none of these is in place by the 2028 pilot, stop.

## 6. Not yet implemented

- Signed tree heads, inclusion and consistency proofs (RFC 6962), and revocation that relies on them.
- Skew table: the winner distribution at stations an org captured, compared to all stations.
- `posted` tier and its policy.
- P-256 keys, original-plus-copy image hashes, compact binary encoding for SMS (~120 bytes).
- A conformance directory with one folder per attack (today these are unit tests in `tests/test_wr2.py`).
- The capture app with QR co-presence. This is the real product.
